# @order/reconstruct

Part of **[ORDER](https://github.com/keerthikrishnagamasany/order)**, the agent-aware gateway for the age of AI bots.

Offline analysis of a captured session: per-client verdicts with confidence and evidence, and learned detection rules that are checked against your legitimate traffic before a human approves them.

```ts
import { fromHar, synthesizeRules, compileRules } from "@order/reconstruct";

const proposals = synthesizeRules(fromHar(har));
// review, set approved: true, then:
const learned = compileRules(proposals);
```

Full documentation: [https://github.com/keerthikrishnagamasany/order](https://github.com/keerthikrishnagamasany/order#readme)

---

Created by **Keerthi Krishna Gamasany**. MIT licensed.
