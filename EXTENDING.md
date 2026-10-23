# Extending ORDER

ORDER ships as a complete baseline, and every part of it can be replaced. This guide covers each
extension point: the interface you implement and a working example. The examples are taken from
[`apps/gateway/examples/extending.ts`](apps/gateway/examples/extending.ts), which is type-checked
with the test suite, so they match the real interfaces.

| You want to change | Implement | Pass it as |
|---|---|---|
| What counts as an attack | `RulePack` | `rules` |
| Where agent keys come from | `KeyResolver` | `botAuth.resolver` |
| How key directories are fetched | `Transport` | `new HttpsDirectoryResolver({ transport })` |
| Where scores and canaries live | `StateStore` | `state` |
| What a trapped client sees | `DecoyResponder` | `decoy` |
| How clients are identified | `ClientIdentityOptions` | `clientIdentity` |
| Logging, SIEM export, capture | callback | `onDecision` |
| A framework we don't ship | `createOrder().check()` | — |

## Ground rules

These keep extensions safe and keep ORDER's verdicts meaningful:

- **Rule packs are pure.** `inspect()` gets the request and returns signals. No I/O, no clock, no state. That keeps them fast, testable and safe to combine.
- **Don't claim certainty you don't have.** Only a canary replay is `CERTAIN`. Detectors raise `HARD`, `SUSPECT` or `SOFT` signals; the pipeline decides the lane.
- **Clients never choose their own identity.** Don't derive the client id from a header a client controls unless it comes through a proxy you trust.
- **Defensive only.** ORDER observes, denies and records. Extensions must not send anything back at a client or attempt to access its systems.

## 1. Rule packs

A rule pack is the unit of detection. The open reference pack is a starting point; production deployments add their own, usually kept private.

```ts
import { combine, type RequestFacts, type RulePack, type Signal } from "@order/core";
import { referenceRules } from "@order/rules-reference";

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
```

`RequestFacts.query` and `.body` are already URL-decoded (recursively), so match the decoded form. Keep `excerpt` short; it goes into logs. Severity drives the lane: `HARD` blocks, `SUSPECT` routes to the decoy, `SOFT` only adds to context.

Rules learned by `@order/reconstruct` compile to an ordinary `RulePack`, so they combine the same way: `combine(referenceRules, myRules, compileRules(approved))`.

## 2. Key resolvers

Web Bot Auth verification needs the agent's public key. `HttpsDirectoryResolver` fetches it from the agent's origin; `StaticKeyResolver` holds keys you add by hand. For anything else, such as a partner registry or a database, implement `KeyResolver`:

```ts
import type { JwkOkp, KeyResolver } from "@order/web-bot-auth";

export class PartnerRegistryResolver implements KeyResolver {
  constructor(private readonly lookup: (origin: string, keyid: string) => Promise<JwkOkp | null>) {}
  resolve(agentOrigin: string, keyid: string): Promise<JwkOkp | null> {
    return this.lookup(agentOrigin, keyid);
  }
}
```

Return `null` when you have no such key, and throw when you couldn't check (a timeout, say). Both make the request `unverified`, never `invalid`, because failing to find a key isn't evidence of hostility. The verifier still checks that the key's thumbprint matches the `keyid`, so a resolver can't hand back the wrong key.

## 3. Transports

`HttpsDirectoryResolver` uses a `Transport` to fetch directories. Replace it to add logging, route through an egress proxy, or run on a platform without `node:https`:

```ts
import type { Transport } from "@order/web-bot-auth";

export const loggingTransport =
  (inner: Transport): Transport =>
  async (url, limits) => {
    const res = await inner(url, limits);
    console.log(`directory ${url} -> ${res.status}`);
    return res;
  };
```

A transport must not follow redirects and must respect `limits.timeoutMs` and `limits.maxBytes`. **If you replace the default, keep its SSRF protections.** `Signature-Agent` is attacker-controlled, and the default transport refuses private, loopback, link-local and cloud-metadata addresses at connect time. `isPrivateAddress` and `guardedLookup` are exported so you can reuse them.

## 4. State stores

Scores, rate windows and canaries live behind `StateStore`. The default is in memory: bounded, expiring, one process. `RedisStateStore` shares state across instances. For another backend, implement the five methods:

```ts
import type { MaybePromise, StateStore } from "@order/core";

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
```

Return plain values for a synchronous store, or Promises for a remote one. With an asynchronous store use `engine.decideAsync()`; the adapters and gateway already do. **Every entry must expire**, or a long-running deployment grows without limit and a client flagged once stays flagged forever.

## 5. Decoy responders

What a trapped client sees. Make it plausible for your API, and plant canaries in it, so that if the client ever uses what it scraped, the replay is provable:

```ts
import type { DecoyResponder } from "@order/gateway";

export const myDecoy: DecoyResponder = (path, canaries) => {
  if (path.startsWith("/api/customers")) {
    return { customers: [{ id: 1, email: "jane@example.invalid", apiKey: canaries.mint(`decoy ${path}`, "cust_key").token }] };
  }
  return { status: "ok", items: [] };
};
```

Canary tokens look like `<prefix>_<24 hex>`, so give them a prefix that fits the fake data. Never put real data in a decoy.

## 6. Putting it together

```ts
import { createGateway, HttpsDirectoryResolver } from "@order/gateway";

createGateway({
  rules,
  state: kvStore,
  decoy: myDecoy,
  botAuth: { resolver: new HttpsDirectoryResolver() },
  clientIdentity: { trustedProxies: ["10.0.0.1"] },
  upstream: { url: "http://127.0.0.1:3000" },
  onDecision: (d) => {
    if (d.lane === "blocked" || d.lane === "decoy") console.log(JSON.stringify(d)); // ship to your SIEM
  },
});
```

The same options work with `orderExpress()`, `orderFastify()` and `createOrder()`, except the gateway-only ones (`upstream`, `capture`, `maxBodyBytes`, `metrics`). One difference: in the adapters, `onDecision` receives the full check result plus the final status, so the lane is `d.decision.lane` rather than `d.lane`.

## 7. Adapters for other frameworks

Every adapter is a thin wrapper around `createOrder().check()`: map your framework's request into `{ method, url, headers, body, remoteAddress }`, and if the result has `respond`, send it instead of continuing.

```ts
import type { IncomingMessage, ServerResponse } from "node:http";
import { createOrder } from "@order/gateway";

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
```

Pass already-parsed body text if your framework has it; otherwise ORDER inspects only the URL, headers and identity. Share one `Order` across adapters to share state: a canary planted through one is caught by the other.

## Contributing an extension

Good candidates for the main repo: adapters for other frameworks, state stores for common backends, and transports for edge runtimes. See [CONTRIBUTING.md](CONTRIBUTING.md). Detection rules tuned to a specific site belong in that site's private pack, not here.
