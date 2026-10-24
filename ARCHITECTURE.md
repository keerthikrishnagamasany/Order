# ORDER architecture

This document explains how ORDER is put together and why. It is the reference for
contributors and for anyone evaluating the framework before adopting it.

## The problem

A public service in 2026 sees three kinds of traffic:

1. **People** — ordinary users.
2. **Agents you want** — a partner's AI assistant calling your API, a verified crawler.
3. **Agents you don't** — scrapers, credential-stuffers, vulnerability scanners, and
   bots probing for exploits, most of them disguised as (1) or (2).

A block/allow WAF cannot tell (2) from (3), and treats (1) and (2) identically. ORDER
adds the missing dimension — identity and inferred intent — without slowing requests.

## Two speeds

ORDER deliberately splits into a **live path** and an **offline path**.

### Live path (microseconds)

Runs on every request, in-process. Only cheap work: input normalisation, regex
detection, map lookups, and an integer score. The output is a `Decision`:

```
Request → Normalise → RulePack.inspect → Pipeline.decide → Lane + Decision
```

- **Normalise** (`@order/core/normalise`): recursively URL-decodes query and body so
  detectors see `'` not `%27` and `/` not `%2F`. This defeats the single most common
  WAF bypass (encoded and double-encoded payloads). Null bytes stripped, length bounded.
- **RulePack.inspect** (pluggable): a pure function from request facts to `Signal[]`.
  Each signal has a `severity` (`HARD` / `SUSPECT` / `SOFT`), a `locus`, and a short
  loggable excerpt.
- **Pipeline.decide** (`@order/core/pipeline`): resolves signals + identity + score into
  one lane, in this fixed order of precedence:

  | # | Condition | Lane | Confidence |
  |---|-----------|------|------------|
  | 1 | a planted canary token is replayed | `blocked` | `CERTAIN` |
  | 1a | trusted identity inside an active, in-scope authorized test | `trusted` | `CERTAIN` (labelled) |
  | 2 | allowlisted identity **and** a `HARD` signal | `blocked` | `LIKELY` (leaked key) |
  | 3 | allowlisted identity, otherwise | `trusted` | `CERTAIN` |
  | 4 | any `HARD` signal | `blocked` | `LIKELY` |
  | 5 | a `SUSPECT` signal or score ≥ threshold | `decoy` | `GUESSING` |
  | 6 | none of the above | `normal` | `CERTAIN` |

### Offline path (seconds)

Runs on a capture, never in the request path. ORDER records every request/response as a
HAR 1.2 entry with its live verdict attached (`_order`). Later, `@order/reconstruct`:

1. Parses the HAR with the **REA** CLI (`inspect-web-network-capture`), which returns
   verifiable structure — records, ordering, and the sha256 of the exact artifact.
2. Projects REA's **api-surface** view to group observed endpoints.
3. Fuses that with ORDER's decision log to build a **per-client verdict**: hypotheses
   about what the client was doing, each with a confidence label and the evidence, plus
   block/allow rules proposed for human approval.

REA never guesses — a pattern is a hypothesis, not proof — and that discipline is what
makes ORDER's verdicts auditable rather than hand-wavy.

## Lanes

| Lane | Meaning | Served |
|------|---------|--------|
| `trusted` | allowlisted key or verified Web Bot Auth agent | real data, still monitored |
| `normal` | unknown but clean | ordinary public data |
| `decoy` | suspicious, unproven | convincing fake data seeded with canaries |
| `blocked` | hard signal or canary replay | `403` |

A trusted identity is **not** a free pass: a `HARD` attack signal on an allowlisted key
is treated as a likely leaked credential and dropped to `blocked` (row 2 above).

### Authorized security testing

Row 2 has an obvious side effect: a penetration tester you hired, using a trusted key,
would be blocked as a "leaked key". `authorizedTesters` makes that case explicit instead of
forcing you to switch ORDER off for the test:

- An entry is keyed by an identity or `agent:<origin>`, and **grants nothing on its own**:
  the client must already be trusted through the allowlist or a verified signature.
- Every entry has a required `expiresAt` and an optional list of path prefixes. Expired or
  out-of-scope use falls back to row 2 and leaves `authorized_test_expired` /
  `authorized_test_out_of_scope` in the log, which reconstruction reports as misuse.
- Allowed requests keep all their signals, carry `authorized_test:<label>` in their
  reasons, are counted in `order_authorized_test_total`, and reach your app with an
  `x-order-authorized-test` header (client-sent copies are stripped).
- A canary replay (row 1) still blocks: a tester who exfiltrates decoy data and uses it
  has found something real, and it should look exactly like an attack.
- Rule synthesis ignores authorized-test traffic entirely, so a tester's probes can neither
  propose a rule nor veto a real one as a false positive.

Live, the label comes only from your configuration, never from the client. Offline,
`fromHar()` reads the label (and every lane) from the capture file, so captures are trusted
input: keep them where only ORDER and you can write.

The risk is the same as any allowlist: a stolen tester key gets the tester's latitude
until it expires. Keep engagements short and scoped, and use a dedicated key per test.

## Canary tokens

Canaries are minted only when serving a `decoy` response and recorded in the
`CanaryRegistry`. They exist nowhere a legitimate client could obtain them. A client that
presents one back is therefore *provably* hostile — the only `CERTAIN` compromise marker
in the system. This converts the decoy from a passive trap into a source of hard evidence.

## The rules seam

`RulePack` is the extension point:

```ts
interface RulePack {
  readonly id: string;
  inspect(facts: RequestFacts): Signal[];  // pure, deterministic, no I/O
}
```

- **Public repo** ships `@order/rules-reference`: real, conservative, open signatures.
- **Production** injects a private `@order/rules-private` implementing the same interface
  with tuned, non-public signatures. It is git-ignored here and never published.

Because `inspect` is pure and framework-agnostic, a private pack can be developed and
tested in isolation against a fixture corpus, then dropped in with a one-line change to
the `Engine` construction.

## State and scaling

Per-client state (`ClientTracker`) is small and serialisable by design: a score, the last
lane, and a sliding window of hit timestamps. The interface is storage-agnostic, so moving
from the in-memory map to Redis is an implementation swap, not a redesign.

## What ORDER is not

- **Not an edge DDoS layer.** Put Cloudflare / a CDN in front for volumetric defence;
  ORDER is the application-aware layer behind it.
- **Not a counter-attack tool.** It observes, denies, and logs. It never acts against a
  client.
- **Not a guarantee.** Intent is inferred. Tune the reference thresholds against real
  traffic and keep a human in the loop before any auto-block.

## Package map

```
packages/core             @order/core            framework, zero deps
packages/rules-reference  @order/rules-reference open detector pack
packages/reconstruct      @order/reconstruct     REA-driven offline analysis
apps/gateway              @order/gateway         reference server + middleware adapter
```

## Verified agents (Web Bot Auth)

`@order/web-bot-auth` verifies RFC 9421 signatures tagged `web-bot-auth`
(draft-ietf-webbotauth-httpsig-protocol). Verification runs in the gateway **before**
`Engine.decide()`, so the engine stays synchronous and I/O-free:

- `verified` sets `RawRequest.verifiedAgent`; the pipeline treats it like an allowlisted
  identity (row 3 of the precedence table), including the leaked-identity rule (row 2).
- `invalid` adds a `bot_auth_invalid` SUSPECT signal via `RawRequest.extraSignals`.
- `unverified` (key not resolvable) changes nothing. The draft is explicit that failed
  discovery is not evidence of hostility.

The Signature-Agent member named by the component's `key` parameter is looked up
independently of the signature label; the draft's own test vector signs as `sig2` over
member `agent2`. Conformance is pinned by a test that runs that vector through the verifier.

## Learned rules

`synthesizeRules()` turns a capture into rule proposals:

1. Candidates come only from hostile-lane requests (`blocked`, `decoy`).
2. Blame follows the locus that fired: a request blocked for its payload does not make
   its path a candidate.
3. Each candidate is checked against benign-lane requests (`trusted`, `normal`) in the same
   capture. Any match rejects it.
4. Candidates the current pack already catches are flagged `redundant`.
5. Confidence is `LIKELY` with two or more independent clients, otherwise `GUESSING`.

`compileRules()` builds a `RulePack` from proposals a human has approved. Rejected
proposals are excluded even if marked approved. Combine with `combine(...)`.

## One decision core, several ways to run it

`createOrder().check(input)` is the single place a request is verified, decided and, if blocked
or decoyed, answered. Everything else is a thin wrapper:

- `orderExpress()` — Express/Connect middleware; inspects the body your parser already produced.
- `orderFastify()` — a `preHandler` hook, after Fastify has parsed the body.
- `createGateway()` — a standalone server: sample mode for demos, or proxy mode in front of any app.

Because they share `check()`, they behave identically, and one `Order` can back several of them
with shared state.

## Proxy mode

Only `trusted` and `normal` requests are forwarded. The body is forwarded as the exact bytes
received, and the upstream response is streamed back. Hop-by-hop headers are stripped. ORDER adds
`x-order-lane`, `x-order-client` and `x-order-verified-agent`, after removing any copies the client
sent, so the app can rely on them as long as it only accepts traffic from ORDER. Upstream
failures return `502`, timeouts `504`. Real response bodies are never retained in the capture.

## State

`StateStore` holds three things per deployment: per-client scores (expiring after the client's
last suspicious request, default 1h), per-client rate windows, and planted canaries (default 7
days). The in-memory store bounds each table (default 100,000 entries, oldest evicted first).
`RedisStateStore` uses fixed rate windows and Redis expiries, and takes a plain command function so
it works with node-redis, ioredis or any client.

Canary detection is O(candidates), not O(canaries): tokens have the shape `<prefix>_<24 hex>`, so
the engine extracts up to 32 candidates from the request and looks each up.

`Engine.decide()` runs against a synchronous store with no I/O. `Engine.decideAsync()` runs the
identical logic, written once and split around the two state accesses, against any store.

## Client identity

Scores and rate limits key on the client id, so it must not be client-chosen. The default is the
socket address. With `trustedProxies`, `X-Forwarded-For` is honoured only when the request arrives
from one of them, and the client is the right-most hop that isn't a trusted proxy, so forged
left-hand entries are ignored. The demo-only `allowSimulatedClients` flag is the only way a header
can set the id.
