# Contributing to ORDER

Thanks for considering a contribution. ORDER is a small, strict TypeScript monorepo; the
bar is: it builds, it's typed, it's tested, and it stays honest about what it can prove.

## Setup

```bash
corepack enable && pnpm install   # or npm install
pnpm typecheck                    # library, tests, examples and scripts, all strict
pnpm test                         # node:test suite
pnpm demo                         # run the reference gateway end to end
pnpm pack:check                   # build, pack, install into a fresh project, run
pnpm bench                        # engine and HTTP benchmarks
```

Requires Node ≥ 22.

## Ground rules

- **Type-safe.** `strict` is on, plus `noUncheckedIndexedAccess`. No `any` without a
  written reason. `pnpm typecheck` must pass.
- **Tested.** New behaviour ships with a `node:test` test. Detectors need both a
  positive case and a clean-traffic negative case (false positives are the real cost).
- **Detectors stay pure.** `RulePack.inspect` must be a pure function — no I/O, no state,
  no clock. Determinism is what lets packs be tested and swapped.
- **Confidence is honest.** Don't label an inference `CERTAIN`. Only a canary replay is.
- **No offensive tooling.** ORDER is defensive. PRs that add working exploits, attack
  bots, or counter-attack ("hack-back") capability will be declined. Inert test vectors
  that exercise a detector are fine; a functional exploit is not.

For extension points (rule packs, key resolvers, state stores, decoys, adapters), see
[EXTENDING.md](EXTENDING.md).

## Adding a detector to the reference pack

1. Add a matcher to `packages/rules-reference/src/index.ts`.
2. Keep it conservative — prefer a miss to blocking a real user.
3. Match against normalised (decoded) input; the framework decodes before calling you.
4. Add positive and negative tests in `packages/rules-reference/test/`.

## Commit and PR

- Small, focused commits with clear messages.
- Describe what changed and why; link an issue where one exists.
- `pnpm typecheck`, `pnpm test` and `pnpm pack:check` must pass.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a vulnerability.
