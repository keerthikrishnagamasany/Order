# Security audit, October 2026

ORDER was audited with **Cloudflare's open-source [`security-audit`](https://github.com/cloudflare/security-audit-skill) method** (MIT), in its `quick` profile. Every issue it confirmed is fixed in this repository, each with a regression test in [`apps/gateway/test/audit-regressions.test.ts`](apps/gateway/test/audit-regressions.test.ts).

## How it was run

- **Reconnaissance:** four agents mapped the product, its trust boundaries, its entry points and how its code can be run safely.
- **Hunting:** seven independent hunters each owned one area of the code: the decision core, signature verification, key-directory fetching, the proxy and client identity, state and resource limits, offline learning, and repository-wide exposures.
- **Validation:** every candidate went to a **fresh verifier that did not find it**, whose job was to refute it. A verifier could confirm a finding only by reproducing it, with dummy data, inside an OS-enforced sandbox: no network, a read-only filesystem, no capabilities, and resource limits.
- **Checks:** a final critic checked the coverage. The method's own validators checked the findings and the coverage ledger.

**Result:** 12 findings confirmed, 1 lead needing deployment-specific validation, and 0 rejected.

**Limits:** this was a `quick` profile, so it is a partial pass, not a guarantee. One area was recorded as deferred: the Express and Fastify adapters, and how the host framework parses paths and bodies compared with what ORDER inspects.

## What was found and fixed

| Severity | Issue | Fix |
|---|---|---|
| High | Capture memory was bounded by entry count only: up to 10,000 full request bodies could exhaust the gateway heap. | Captures now have a byte budget (64 MiB by default) and a per-entry text cap, and request bodies are not stored unless you opt in. |
| Medium | In proxy mode, gzip or deflate bodies were inspected as compressed bytes and then decompressed by the app. | Non-identity `Content-Encoding` is refused with `415`. |
| Medium | One malformed `%` escape anywhere in the query or body switched off percent-decoding for the whole component. | Decoding is lenient: each valid escape run is decoded on its own. |
| Medium | Web Bot Auth checked `@authority` against the client's own `Host`, so a signature captured on another site could be replayed. | `botAuth.authorities` is required. A signature only verifies for host names the deployment serves. |
| Medium | A verified agent could select another origin's authorized-test engagement through `x-mcp-key`. | Tester entries apply only to the principal that earned trust: an allowlisted identity, or the exact verified origin. |
| Medium | Decoy traffic could evict planted canaries from the bounded store, which disabled canary-replay detection. | Canaries are self-verifying (HMAC over the issue time), so there is nothing to evict. |
| Medium | Attacker-chosen `Signature-Agent` origins grew the key-directory cache without limit. | The cache is bounded (LRU, expired entries first), concurrent fetches are capped, over-long origins are refused, and failure entries hold fixed text. |
| Low | The capture kept `Authorization`, `Cookie`, `x-mcp-key`, query tokens and passwords verbatim. | Credential headers are always redacted. Query values and bodies are dropped by default. |
| Low | Canaries replayed in `Authorization`, `Cookie` or the path were not checked, and 32 decoy-shaped words could push one out of the scan. | Detection covers the path and the header values. Up to 1,024 candidates are verified, and more than that raises `canary_scan_overflow`. |
| Low | Input after the first 8 KiB of the query or body was never inspected. | The whole query and body are inspected, up to `inspectionLimit` (1 MiB by default, the same as the body cap; the rules are linear, about 7-15 ms per MiB). Anything longer raises `oversize_input` instead of passing as clean. |
| Low | The default metrics gate trusted any loopback peer, including a local reverse proxy relaying the internet. | Trusted-proxy peers no longer pass the default gate. |
| Low | Offline rule synthesis decided where a signal fired by searching reason text that contains attacker-controlled excerpts. | Captures record each signal's location as structured data, and synthesis reads only that or the anchored rule prefix. |
| Lead | Path rules matched the percent-encoded path, so `/%2eenv` did not match the `/.env` rule. | Paths are percent-decoded and their dot segments resolved before matching, which also covers forms like `/x/..%2f.env`. |

## Independent review of the fixes

A separate reviewer checked the fix diff before release. It confirmed most fixes and found a few gaps, all of them closed and tested before this commit:

- **A regression in the first fix:** an early version decoyed legitimate bodies larger than 64 KiB.
- **Canary tokens:** they needed a nonce to stay unique and traceable to the decoy that issued them.
- **Canary replays still missed:** keys sent as HTTP Basic credentials or as JSON escapes, and keys pushed out of the scan by padding.
- **Path variants:** forms built from encoded slashes, such as `/x/..%2f.env`.
- **Capture redaction:** custom credential headers and credentials in the URL itself (`user:pass@`) were still stored. Captures now keep only an allowlist of headers.
- **Offline reconstruction:** the same reason-text parsing weakness as in rule synthesis.

## Breaking changes

- `botAuth` now needs `authorities` (an array of host names, or a predicate). If it is missing at runtime, no signature verifies.
- Captures no longer contain request bodies or query values unless you opt in with `capture.includeBodies` or `capture.includeQueryValues`. Header values are kept only for an allowlist of headers (`user-agent`, `accept`, `content-type` and similar). Every other header's value is redacted.
- Requests with a compressed body get `415` from the standalone gateway.
- To share canaries across instances, set the same `canary.secret` on each one.

## What held up

These controls were tested and held:

- **SSRF guard on key-directory fetches:** every private-address notation the audit tried was refused, and checks run at connect time.
- **Signature verification:** every required field is checked.
- **Proxy:** the upstream is pinned, and forged `x-order-*` headers are stripped.
- **Rule compilation:** only human-approved rules are compiled, and path-family rules never block.
- **Repository-wide checks:** no hardcoded secrets and no dynamic code execution were found, and dependencies are exact-pinned.
