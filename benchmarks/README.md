# Benchmarks

Two questions, two commands:

- `pnpm bench`: how fast is ORDER? (`scripts/bench.mts`)
- `pnpm eval`: do learned rules hold up on traffic they were not learned from? (`evaluate.ts`)

## Held-out evaluation

| File | What it is |
|---|---|
| `baseline.har` | The frozen 15-request capture from `pnpm demo`. Rules are learned from this and nothing else. |
| `holdout.json` | 24 labelled requests (12 benign, 12 malicious) that never appear in the baseline. |
| `evaluate.ts` | Learns from the baseline, approves with a fixed policy, runs the held-out set through a real gateway and app, and scores it. |
| `RESULTS.md` | The generated results. Never edited by hand. |

A malicious request is **caught** when it never reaches the app (decoy or blocked). A
benign request is a **false positive** when it doesn't reach the app. The approval step
is a stand-in for a human: every proposal that was not rejected and is not already covered
by the built-in rules gets approved.

### What the first run shows

See [RESULTS.md](RESULTS.md) for the numbers. In short:

- **The learned rule transferred to an unseen attacker.** It came from two scanners whose
  user agents already gave them away. In the held-out set, a scanner disguised as a browser
  probed the same path. The built-in rules let it through, and the learned rule caught it.
  It added no false positives.
- **It didn't generalise to a related path.** `/wp-json/wp/v2/settings` went through,
  because learned rules match one exact path. Path-family rules are the next step, and
  this set is what they'll be judged on.
- **The built-in rules have gaps.** They missed a cloud-credentials probe (`/.aws/credentials`),
  a quote-balanced SQL injection (`1' OR '1'='1`) and a reworded prompt injection. Phrase-list
  detectors are brittle, and this is the evidence.
- **The built-in rules cost legitimate clients.** A developer using `curl` and an integration
  using `python-requests` were both decoyed, because the reference pack treats those user
  agents as scanner-like. If developers call your API directly, allowlist your integrations
  or drop that rule from your pack.

### Keeping the held-out set honest

`holdout.json` is frozen. If its results were used to tune the rules, it would stop being
unseen data and its numbers would mean nothing. Gaps it reveals are fixed against new
examples, and the fix is then measured on a **new** held-out set (`holdout-v2.json`),
published alongside this one, never instead of it.

Captures are trusted input. `fromHar()` believes the lanes and labels written in a capture,
including the authorized-test label, so keep captures where only ORDER and you can write.
