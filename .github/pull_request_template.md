## What this changes

<!-- One or two sentences: what, and why. Link the issue if there is one. -->

## How it was tested

<!-- New behaviour needs a test. Detectors need a positive case and a clean-traffic negative case. -->

## Checklist

- [ ] `pnpm typecheck` passes
- [ ] `pnpm test` passes
- [ ] `pnpm pack:check` passes (if package exports or build config changed)
- [ ] Docs updated (README, EXTENDING.md or ARCHITECTURE.md) if behaviour changed
- [ ] Defensive only: no exploits, attack tooling, or anything that acts against a client
- [ ] No real credentials, tokens or private data anywhere in the change
