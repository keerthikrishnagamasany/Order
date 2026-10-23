/**
 * The Web Bot Auth verifier.
 *
 * Outcome is one of three (draft-ietf-webbotauth-httpsig-protocol, Appendix C.1):
 *   "verified"   — a signature validated against a resolved key for this agent.
 *   "unverified" — well-formed but the key could not be resolved (e.g. directory
 *                  fetch failed). NOT a hostile signal; just "we don't know".
 *   "invalid"    — malformed, expired, wrong tag, or the signature did not validate.
 *
 * Key resolution is injected (a KeyResolver), so the verifier itself does no network
 * I/O and is deterministic and testable. A directory-fetching resolver can be supplied
 * in production; its lookups MUST be keyed on the (directory-URL, keyid) pair per the
 * draft, and MUST apply the size / latency / redirect / private-address limits it calls for.
 */

import { createPublicKey, verify as edVerify, type JsonWebKey } from "node:crypto";
import { buildSignatureBase, type MessageContext } from "./base.js";
import { parseSignature, parseSignatureAgent, parseSignatureInput } from "./structured.js";
import { ed25519Thumbprint, thumbprintMatches, type JwkOkp } from "./thumbprint.js";
import { isHttpsOrigin } from "./netguard.js";

export type VerifyStatus = "verified" | "unverified" | "invalid";

export interface VerifyResult {
  status: VerifyStatus;
  /** The Signature-Agent directory URL, when parseable. */
  agent?: string;
  /** The keyid from Signature-Input, when parseable. */
  keyid?: string;
  /** Human-readable reason, for logs. */
  reason: string;
}

export interface RequestHeaders {
  signatureInput?: string | undefined;
  signature?: string | undefined;
  signatureAgent?: string | undefined;
}

/** Resolve a public key for an (agent directory URL, keyid) pair. */
export interface KeyResolver {
  resolve(agentUrl: string, keyid: string): Promise<JwkOkp | null> | JwkOkp | null;
}

/** A static, no-network resolver. Keys are indexed by (agent URL, JWK thumbprint). */
export class StaticKeyResolver implements KeyResolver {
  private readonly keys = new Map<string, JwkOkp>();

  add(agentUrl: string, jwk: JwkOkp): this {
    this.keys.set(`${agentUrl}|${ed25519Thumbprint(jwk)}`, jwk);
    return this;
  }

  resolve(agentUrl: string, keyid: string): JwkOkp | null {
    return this.keys.get(`${agentUrl}|${keyid}`) ?? null;
  }
}

export interface VerifyOptions {
  /** Current time in seconds; injectable for tests. */
  nowSec?: number;
  /**
   * ORDER policy: max allowed signature lifetime in seconds. The draft RECOMMENDS
   * expires <= 24h (it is not a MUST), so this is a configurable verifier policy that
   * limits replay windows. Default 24h. Pass Infinity to accept any lifetime.
   */
  maxAgeSec?: number;
  /** Allowed clock skew in seconds for `created`. */
  skewSec?: number;
}

export async function verifyWebBotAuth(
  headers: RequestHeaders,
  ctx: Omit<MessageContext, "signatureAgentValue">,
  resolver: KeyResolver,
  opts: VerifyOptions = {},
): Promise<VerifyResult> {
  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const maxAge = opts.maxAgeSec ?? 24 * 60 * 60;
  const skew = opts.skewSec ?? 5;

  if (!headers.signatureInput || !headers.signature) {
    return { status: "invalid", reason: "missing Signature or Signature-Input" };
  }

  const input = parseSignatureInput(headers.signatureInput);
  if (!input) return { status: "invalid", reason: "unparseable Signature-Input" };

  if (input.params.tag !== "web-bot-auth") {
    return { status: "invalid", reason: `tag is not web-bot-auth (got ${String(input.params.tag)})` };
  }

  const { created, expires, keyid } = input.params;
  if (typeof created !== "number" || typeof expires !== "number") {
    return { status: "invalid", reason: "missing created/expires" };
  }
  if (!keyid) return { status: "invalid", reason: "missing keyid" };
  if (now < created - skew) return { status: "invalid", keyid, reason: "created is in the future" };
  if (now > expires) return { status: "invalid", keyid, reason: "signature expired" };
  if (expires - created > maxAge) return { status: "invalid", keyid, reason: "lifetime exceeds policy max age" };

  // Coverage: @authority or @target-uri, plus the signature-agent member for this label.
  const names = new Set(input.components.map((c) => c.name));
  if (!names.has("@authority") && !names.has("@target-uri")) {
    return { status: "invalid", keyid, reason: "neither @authority nor @target-uri is covered" };
  }
  const agentComponent = input.components.find((c) => c.name === "signature-agent");
  if (!agentComponent) {
    return { status: "invalid", keyid, reason: "signature-agent component not covered" };
  }

  // The component's `key` names the Signature-Agent dictionary member. It need NOT equal
  // the signature label (the draft's own Ed25519 vector signs as `sig2` over member `agent2`).
  const agentMember = agentComponent.key ?? input.label;
  const agent = headers.signatureAgent ? parseSignatureAgent(headers.signatureAgent, agentMember) : null;
  if (!agent) return { status: "invalid", keyid, reason: "missing/unparseable Signature-Agent" };
  if (agent.type !== "directory") {
    // Unknown discovery types are ignored (Sec. 5.2.1): we can't resolve a key, so "unverified".
    return { status: "unverified", agent: agent.url, keyid, reason: `unsupported Signature-Agent type ${agent.type}` };
  }
  if (!isHttpsOrigin(agent.url)) {
    return { status: "invalid", agent: agent.url, keyid, reason: "Signature-Agent must be an https origin" };
  }

  const sig = parseSignature(headers.signature, input.label);
  if (!sig) return { status: "invalid", agent: agent.url, keyid, reason: "unparseable Signature value" };

  const base = buildSignatureBase(input, { ...ctx, signatureAgentValue: agent.rawValue });
  if (base === null) return { status: "invalid", agent: agent.url, keyid, reason: "unsupported covered component" };

  // Key resolution failure is "unverified", never "invalid".
  let jwk: JwkOkp | null;
  try {
    jwk = await resolver.resolve(agent.url, keyid);
  } catch {
    return { status: "unverified", agent: agent.url, keyid, reason: "key directory lookup failed" };
  }
  if (!jwk) return { status: "unverified", agent: agent.url, keyid, reason: "no key for (agent, keyid)" };

  if (!thumbprintMatches(jwk, keyid)) {
    return { status: "invalid", agent: agent.url, keyid, reason: "keyid does not match resolved key" };
  }

  let ok: boolean;
  try {
    const keyObject = createPublicKey({ key: jwk as unknown as JsonWebKey, format: "jwk" });
    ok = edVerify(null, Buffer.from(base, "utf8"), keyObject, sig);
  } catch {
    return { status: "invalid", agent: agent.url, keyid, reason: "signature verification error" };
  }

  return ok
    ? { status: "verified", agent: agent.url, keyid, reason: "signature valid" }
    : { status: "invalid", agent: agent.url, keyid, reason: "signature did not validate" };
}
