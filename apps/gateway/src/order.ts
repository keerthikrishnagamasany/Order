/**
 * `createOrder()` — the one place where a request is verified, decided, and (if blocked
 * or decoyed) answered. The standalone gateway, the Express middleware and the Fastify
 * hook are all thin wrappers around `check()`, so they behave identically.
 */

import type { IncomingHttpHeaders } from "node:http";
import {
  type AuthorizedTester,
  CanaryRegistry,
  type CanaryOptions,
  Engine,
  type Decision,
  type RulePack,
  type ScoringConfig,
  type Signal,
  type StateStore,
} from "@order/core";
import { referenceRules } from "@order/rules-reference";
import { verifyWebBotAuth, type KeyResolver, type VerifyStatus } from "@order/web-bot-auth";
import { decoyBody } from "./decoy.js";
import { resolveClientId, type ClientIdentityOptions } from "./identity.js";

/** Produce the fake response for a decoyed request. Plant canaries via the registry. */
export type DecoyResponder = (path: string, canaries: CanaryRegistry) => unknown;

export interface OrderOptions {
  allowlist?: ReadonlyMap<string, string>;
  /**
   * Time-boxed authorized security tests, keyed by an allowlisted identity or
   * `agent:<origin>`. Their attack payloads are logged and allowed instead of being
   * treated as a leaked key. See `AuthorizedTester`.
   */
  authorizedTesters?: ReadonlyMap<string, AuthorizedTester>;
  /** Rule pack to run. Defaults to the open reference pack; pass `combine(...)` to stack packs. */
  rules?: RulePack;
  /** Scoring thresholds for the decoy lane. */
  scoring?: ScoringConfig;
  /**
   * Where scores, rate windows and canaries live. Default: in-memory, per process. Pass a
   * shared store (e.g. RedisStateStore) so several instances agree and nothing is lost on restart.
   */
  state?: StateStore;
  /**
   * Verify Web Bot Auth signatures. Verified agents enter the trusted lane; a forged or
   * malformed signature raises a SUSPECT signal; an unresolvable key changes nothing.
   *
   * `authorities` lists the host names (with port, if not the default) this deployment serves,
   * e.g. `["api.example.com"]`, or is a predicate. A signature only verifies when the request's
   * Host is one of them, so a signature an agent made for another site can't be replayed here
   * with that site's Host. It plays the role of a JWT audience and is required.
   */
  botAuth?: { resolver: KeyResolver; authorities: readonly string[] | ((authority: string) => boolean); maxAgeSec?: number };
  /** Canary settings, e.g. a `secret` shared by all instances. See CanaryOptions. */
  canary?: Pick<CanaryOptions, "secret" | "ttlMs">;
  /** Characters of decoded query and body inspected; longer input is flagged. Default 1 MiB. */
  inspectionLimit?: number;
  /** Replace the built-in decoy content. */
  decoy?: DecoyResponder;
  /** How clients are identified. Default: the connecting socket's address. */
  clientIdentity?: ClientIdentityOptions;
  now?: () => number;
}

export interface CheckInput {
  method: string;
  /** Path plus query string, e.g. "/api/items?id=1". */
  url: string;
  headers: IncomingHttpHeaders;
  /** Request body as text (empty if none or not yet read). */
  body: string;
  remoteAddress?: string | undefined;
}

export interface CheckResult {
  decision: Decision;
  clientId: string;
  verifiedAgent?: string | undefined;
  /** Outcome of Web Bot Auth verification, if the request carried a signature. */
  botAuth?: VerifyStatus | undefined;
  /** Present when ORDER answers the request itself (blocked or decoy). */
  respond?: { status: number; body: string; contentType: string } | undefined;
  /** Milliseconds spent verifying and deciding. */
  decideMs: number;
}

export interface Order {
  engine: Engine;
  canaries: CanaryRegistry;
  check(input: CheckInput): Promise<CheckResult>;
}

function one(h: string | string[] | undefined): string | undefined {
  return Array.isArray(h) ? h.join(", ") : h;
}

function servesAuthority(authorities: readonly string[] | ((a: string) => boolean) | undefined, host: string): boolean {
  // Fail closed: with no authorities configured, no signature can verify.
  if (!host || !authorities) return false;
  return typeof authorities === "function" ? authorities(host) : authorities.some((a) => a.toLowerCase() === host);
}

/** Headers that are never credentials, or that a third-party page can set on a victim's request. */
const NOT_CREDENTIALS = new Set(["host", "content-length", "content-type", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "referer", "origin", "x-forwarded-for", "x-sim-client"]);

/** Header values a stolen canary could be replayed in (Authorization, Cookie, custom keys…), credential headers first. */
function credentialText(headers: IncomingHttpHeaders): string {
  const first: string[] = [];
  const rest: string[] = [];
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined || NOT_CREDENTIALS.has(k)) continue;
    const val = Array.isArray(v) ? v.join(" ") : v;
    (k === "authorization" || k === "cookie" || k === "proxy-authorization" || k.includes("key") || k.includes("token") ? first : rest).push(val);
  }
  return [...first, ...rest].join(" ");
}

export function createOrder(opts: OrderOptions = {}): Order {
  const canaries = new CanaryRegistry({
    ...(opts.canary ?? {}),
    ...(opts.state ? { store: opts.state } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
  const engine = new Engine({
    rules: opts.rules ?? referenceRules,
    allowlist: opts.allowlist ?? new Map(),
    canaries,
    ...(opts.authorizedTesters ? { authorizedTesters: opts.authorizedTesters } : {}),
    ...(opts.inspectionLimit !== undefined ? { inspectionLimit: opts.inspectionLimit } : {}),
    ...(opts.state ? { state: opts.state } : {}),
    ...(opts.scoring ? { scoring: opts.scoring } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
  const decoy = opts.decoy ?? decoyBody;

  async function check(input: CheckInput): Promise<CheckResult> {
    const t0 = process.hrtime.bigint();
    const url = new URL(input.url || "/", `http://${one(input.headers.host) ?? "localhost"}`);
    const clientId = resolveClientId(input.remoteAddress, input.headers, opts.clientIdentity);

    let verifiedAgent: string | undefined;
    let botAuth: VerifyStatus | undefined;
    const extraSignals: Signal[] = [];
    const sigInput = one(input.headers["signature-input"]);
    const sig = one(input.headers["signature"]);
    const host = (one(input.headers.host) ?? "").toLowerCase();
    if (opts.botAuth && sigInput && sig && !servesAuthority(opts.botAuth.authorities, host)) {
      // A signature for a site this deployment doesn't serve can never verify here.
      botAuth = "invalid";
      extraSignals.push({ name: "bot_auth_invalid", severity: "SUSPECT", where: "identity", excerpt: "authority not served here" });
    } else if (opts.botAuth && sigInput && sig) {
      const r = await verifyWebBotAuth(
        { signatureInput: sigInput, signature: sig, signatureAgent: one(input.headers["signature-agent"]) },
        { method: input.method, authority: host, path: url.pathname, targetUri: url.toString() },
        opts.botAuth.resolver,
        opts.botAuth.maxAgeSec !== undefined ? { maxAgeSec: opts.botAuth.maxAgeSec } : {},
      );
      botAuth = r.status;
      if (r.status === "verified" && r.agent) verifiedAgent = r.agent;
      else if (r.status === "invalid") {
        extraSignals.push({ name: "bot_auth_invalid", severity: "SUSPECT", where: "identity", excerpt: r.reason.slice(0, 80) });
      }
    }

    const decision = await engine.decideAsync({
      method: input.method,
      path: url.pathname,
      query: url.search.replace(/^\?/, ""),
      body: input.body,
      userAgent: one(input.headers["user-agent"]) ?? "",
      identity: one(input.headers["x-mcp-key"]),
      clientId,
      verifiedAgent,
      extraSignals,
      credentials: credentialText(input.headers),
    });

    let respond: CheckResult["respond"];
    if (decision.lane === "blocked") {
      respond = { status: decision.status, body: JSON.stringify({ error: "forbidden" }), contentType: "application/json" };
    } else if (decision.lane === "decoy") {
      respond = { status: decision.status, body: JSON.stringify(decoy(url.pathname, canaries)), contentType: "application/json" };
    }

    return {
      decision,
      clientId,
      verifiedAgent,
      botAuth,
      respond,
      decideMs: Math.round((Number(process.hrtime.bigint() - t0) / 1e6) * 1000) / 1000,
    };
  }

  return { engine, canaries, check };
}
