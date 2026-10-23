# @order/core

Part of **[ORDER](https://github.com/keerthikrishnagamasany/order)**, the agent-aware gateway for the age of AI bots.

Lanes, the decision pipeline, input normalisation, canary tokens, pluggable state (in-memory or Redis), and the `RulePack` interface. Zero runtime dependencies.

```ts
import { Engine, CanaryRegistry } from "@order/core";
import { referenceRules } from "@order/rules-reference";

const engine = new Engine({ rules: referenceRules, allowlist: new Map(), canaries: new CanaryRegistry() });
const verdict = engine.decide({ method: "GET", path: "/.env", clientId: "203.0.113.9" });
// verdict.lane === "blocked"
```

Full documentation: [https://github.com/keerthikrishnagamasany/order](https://github.com/keerthikrishnagamasany/order#readme)

---

Created by **Keerthi Krishna Gamasany**. MIT licensed.
