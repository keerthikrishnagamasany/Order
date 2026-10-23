/**
 * `createOrder()` — the one place where a request is verified, decided, and (if blocked
 * or decoyed) answered. The standalone gateway, the Express middleware and the Fastify
 * hook are all thin wrappers around `check()`, so they behave identically.
 */

import type { IncomingHttpHeaders } from "node:http";
import {
  CanaryRegistry,
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
   */
  botAuth?: { resolver: KeyResolver; maxAgeSec?: number };
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

export function createOrder(opts: OrderOptions = {}): Order {
  const canaries = new CanaryRegistry({
    ...(opts.state ? { store: opts.state } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
  const engine = new Engine({
    rules: opts.rules ?? referenceRules,
    allowlist: opts.allowlist ?? new Map(),
    canaries,
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
    if (opts.botAuth && sigInput && sig) {
      const r = await verifyWebBotAuth(
        { signatureInput: sigInput, signature: sig, signatureAgent: one(input.headers["signature-agent"]) },
        { method: input.method, authority: one(input.headers.host) ?? "", path: url.pathname, targetUri: url.toString() },
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
