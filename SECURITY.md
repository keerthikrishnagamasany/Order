# Security policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue.

- Use GitHub's **private vulnerability reporting** (Security → Report a vulnerability) on
  this repository, or
- email the maintainer at the address on the GitHub profile.

Include steps to reproduce, affected versions, and impact. You'll get an acknowledgement
and, where the report is valid, a fix timeline.

## Scope

ORDER is a **defensive** framework. In-scope reports include: detector bypasses, a way to
make the pipeline misclassify, canary leakage, capture/log injection, or a crash in the
request path.

Out of scope: requests to add offensive capability, or reports that amount to "the open
reference rules can be evaded" — that is known and expected, which is exactly why tuned
detection belongs in a private rule pack (see [ARCHITECTURE.md](ARCHITECTURE.md)).

## Handling untrusted input

ORDER processes hostile input by definition. Two rules the codebase holds to:

- Detectors run on **normalised** input: the path, query and body are percent-decoded leniently
  (one malformed escape never switches decoding off), null bytes are stripped, and input past the
  inspection limit is flagged rather than treated as clean.
- Logged excerpts are truncated. Captures redact credential headers and drop query values and
  request bodies by default.

## Audits

- **2026-10: Cloudflare `security-audit` method, quick profile.** 12 confirmed issues and 1 lead,
  all fixed with regression tests. See [SECURITY-AUDIT.md](SECURITY-AUDIT.md).
