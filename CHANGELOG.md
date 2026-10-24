# Changelog

ORDER is created and maintained by Keerthi Krishna Gamasany.

## Unreleased

- **Security: proxy request forgery (SSRF), found by CodeQL.** In reverse-proxy mode, a client
  could send an absolute-form (`GET http://other-host/…`) or protocol-relative (`GET //other-host/…`)
  request-target and the gateway would forward it to that host instead of the configured
  upstream. The upstream URL is now built only from configuration plus the request's path and
  query. Middleware and adapter use were not affected. A regression test sends both forms over a
  raw socket and checks that no other host is contacted. Update if you run ORDER as a proxy.
- **Security: slow regular expression (ReDoS) in the reference SQL-injection rule.** The
  comment-skipping part of the `union … select` pattern could backtrack for minutes on crafted
  input. It now runs in linear time and still detects comment-obfuscated injections; a test
  bounds its run time on hostile input.

- **Authorized security testing.** `authorizedTesters` declares time-boxed, path-scoped test
  engagements for already-trusted identities or verified agents. In-scope attack payloads
  are allowed and labelled instead of being treated as a leaked key. Expired or out-of-scope
  use falls back to blocking and is reported. `Decision.authorizedTest`, the
  `x-order-authorized-test` upstream header, the `order_authorized_test_total` metric, and the
  `_order.authorizedTest` capture field carry the label.
- Rule synthesis and verdicts now exclude or label authorized-test traffic, so a tester can't
  veto a real rule or be reported as a leaked key.
- Verdicts now report forged or replayed agent signatures, and give one clear explanation
  when a tester key is used outside its authorization.
- `pnpm demo` now shows all three stages: the lane for each request, what each client was
  most likely doing, and the rules the capture supports, including a new rule learned from
  a path no built-in rule knows and the rules rejected because they'd hit legitimate traffic.

- **Held-out evaluation (`pnpm eval`).** Learns rules from the frozen demo capture
  (`benchmarks/baseline.har`), then scores the built-in rules with and without them on 24
  labelled requests the learner never saw, through a running gateway and app. Results,
  including misses and false positives, are in `benchmarks/RESULTS.md`.
- Test: an approved learned rule is enforced by a running gateway, an unapproved one is not,
  and unrelated legitimate traffic still reaches the app.

- **Path-family learned rules.** `synthesizeRules()` also proposes the directory a probed
  path lives in (`path_prefix`), when two or more hostile clients support it, it keeps at
  least two segments, and no benign request in the capture falls under it. Families are
  always `GUESSING` and compile to `SUSPECT`, so they divert to the decoy and never block.
  On the held-out set: 8/12 caught becomes 9/12, with no new false positives.

- **Dependencies.** Adapter tests now run against Express 5.3.0 and Fastify 5.12.7, and tsx is
  4.23.15. This clears every Dependabot alert (fastify, qs, body-parser, path-to-regexp,
  find-my-way, esbuild). All of them were in test-only dependencies: ORDER's published
  packages import neither framework, so installs of ORDER were never affected.

## 0.4.0

Make ORDER deployable and installable.

- **Express and Fastify adapters** (`orderExpress`, `orderFastify`), tested against the real frameworks.
- **Reverse-proxy mode** for the gateway: trusted and normal traffic is forwarded to your app; blocked and decoyed requests never reach it. Bodies are forwarded byte-for-byte, responses streamed, and ORDER's `x-order-*` headers can't be forged by clients.
- **`createOrder().check()`**: one decision core shared by the gateway and both adapters.
- **Pluggable state** (`StateStore`): bounded, expiring in-memory default; `RedisStateStore` for sharing state across instances. `Engine.decideAsync()` for asynchronous stores.
- **Prometheus metrics** (`Metrics`), served only to loopback clients by default.
- **npm-ready packages**: compiled JavaScript with type declarations, publish metadata, per-package READMEs. `pnpm pack:check` installs the tarballs into a fresh project and runs them. `pnpm rename-scope` renames the npm scope in one step.
- **Benchmark** (`pnpm bench`): about 205,000 decisions/sec, 2.8 µs median, on a 2-vCPU VM.
- **EXTENDING.md**: every extension point, with type-checked examples.

### Fixed

- **Client-id spoofing.** The gateway and `toRawRequest` trusted the `x-sim-client` header, letting any client pick its own id and reset its score. It now requires an explicit demo-only flag; `X-Forwarded-For` is honoured only from configured trusted proxies.
- Oversized request bodies were silently truncated; they now get `413`.
- Capture, scores, rate windows and canaries grew without limit; all are now bounded and expiring.
- Canary detection scanned every token ever planted on every request; it now extracts candidates by shape and looks each up.
- The demo no longer ships in the published gateway package.

## 0.3.0

- `HttpsDirectoryResolver`: fetch agent keys from `/.well-known/http-message-signatures-directory` under the draft's rules, with caching.
- SSRF protection for directory fetches, checked at connect time and for IP literals in every notation.
- `Signature-Agent` must be an https origin; unknown discovery types are `unverified`.

## 0.2.0

- `@order/web-bot-auth`: Web Bot Auth verifier and signer (RFC 9421, Ed25519), conformance-tested against the IETF draft's Ed25519 test vector.
- Verified agents enter the `trusted` lane; forged or replayed signatures raise a `SUSPECT` signal.
- Learned-rule synthesis with false-positive checks; `compileRules()` and `combine()`.

## 0.1.0

- Four-lane decision pipeline, input normalisation, canary-seeded decoys, reference rule pack, HAR capture, offline reconstruction, reference gateway.
