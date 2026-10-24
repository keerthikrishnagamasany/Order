/**
 * Compiled examples for EXTENDING.md. This file is type-checked with the test suite
 * (`pnpm typecheck`), so the documentation can't drift from the real interfaces.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  combine,
  type MaybePromise,
  type RequestFacts,
  type RulePack,
  type Signal,
  type StateStore,
} from "@order/core";
import { referenceRules } from "@order/rules-reference";
import { HttpsDirectoryResolver, type JwkOkp, type KeyResolver, type Transport } from "@order/web-bot-auth";
import { createGateway, createOrder, type DecoyResponder } from "../src/index.js";

// 1. A rule pack -----------------------------------------------------------------------
// Pure function of the request: no I/O, no clock, no state. Return every signal that fired.
export const myRules: RulePack = {
  id: "my-company@1",
  inspect(f: RequestFacts): Signal[] {
    const out: Signal[] = [];
    if (f.path.startsWith("/internal/") && !f.identity) {
      out.push({ name: "internal_without_identity", severity: "SUSPECT", where: "path", excerpt: f.path.slice(0, 80) });
    }
    if (/\bexport\s+all\s+customers\b/i.test(f.body)) {
      out.push({ name: "bulk_export_request", severity: "SUSPECT", where: "body", excerpt: "export all customers" });
    }
    return out;
  },
};
export const rules = combine(referenceRules, myRules);

// 2. A key resolver --------------------------------------------------------------------
// Where Web Bot Auth public keys come from. Key lookups are keyed on (agent origin, keyid).
export class PartnerRegistryResolver implements KeyResolver {
  constructor(private readonly lookup: (origin: string, keyid: string) => Promise<JwkOkp | null>) {}
  resolve(agentOrigin: string, keyid: string): Promise<JwkOkp | null> {
    return this.lookup(agentOrigin, keyid); // throw to mean "couldn't check" -> unverified
  }
}

// 3. A transport -----------------------------------------------------------------------
// How key directories are fetched. Must not follow redirects. Keep the SSRF protections if
// you replace it — the default transport refuses private and metadata addresses.
export const loggingTransport =
  (inner: Transport): Transport =>
  async (url, limits) => {
    const res = await inner(url, limits);
    console.log(`directory ${url} -> ${res.status}`);
    return res;
  };

// 4. A state store ---------------------------------------------------------------------
// Scores, rate windows and canaries. Return plain values for a synchronous store, or
// Promises for a remote one. Every entry must expire.
export class MyKvStateStore implements StateStore {
  constructor(private readonly kv: { incr(k: string, by: number, ttlMs: number): Promise<number>; get(k: string): Promise<string | null>; set(k: string, v: string, ttlMs: number): Promise<void> }) {}
  hit(clientId: string, nowMs: number, windowMs: number): MaybePromise<number> {
    return this.kv.incr(`hits:${clientId}:${Math.floor(nowMs / windowMs)}`, 1, windowMs * 2);
  }
  addScore(clientId: string, points: number, _nowMs: number, ttlMs: number): MaybePromise<number> {
    return this.kv.incr(`score:${clientId}`, points, ttlMs);
  }
  async getScore(clientId: string): Promise<number> {
    return Number((await this.kv.get(`score:${clientId}`)) ?? 0);
  }
  putCanary(token: string, origin: string, _nowMs: number, ttlMs: number): MaybePromise<void> {
    return this.kv.set(`canary:${token}`, origin, ttlMs);
  }
  getCanary(token: string): MaybePromise<string | null> {
    return this.kv.get(`canary:${token}`);
  }
}

// 5. A decoy responder -----------------------------------------------------------------
// What a trapped client sees. Plant canaries so a later replay is provable.
export const myDecoy: DecoyResponder = (path, canaries) => {
  if (path.startsWith("/api/customers")) {
    return { customers: [{ id: 1, email: "jane@example.invalid", apiKey: canaries.mint(`decoy ${path}`, "cust_key").token }] };
  }
  return { status: "ok", items: [] };
};

// 6. Putting it together ---------------------------------------------------------------
export function build(kvStore: StateStore) {
  return createGateway({
    rules,
    state: kvStore,
    decoy: myDecoy,
    botAuth: { resolver: new HttpsDirectoryResolver(), authorities: ["api.example.com"] },
    clientIdentity: { trustedProxies: ["10.0.0.1"] },
    upstream: { url: "http://127.0.0.1:3000" },
    onDecision: (d) => {
      if (d.lane === "blocked" || d.lane === "decoy") console.log(JSON.stringify(d)); // ship to your SIEM
    },
  });
}

// 7. An adapter for another framework --------------------------------------------------
// Everything goes through createOrder().check(); an adapter just maps request/response shapes.
export function plainNodeHandler(app: (req: IncomingMessage, res: ServerResponse) => void) {
  const order = createOrder({ rules });
  return async (req: IncomingMessage, res: ServerResponse) => {
    const r = await order.check({ method: req.method ?? "GET", url: req.url ?? "/", headers: req.headers, body: "", remoteAddress: req.socket.remoteAddress });
    if (r.respond) {
      res.writeHead(r.respond.status, { "content-type": r.respond.contentType });
      res.end(r.respond.body);
      return;
    }
    app(req, res);
  };
}
