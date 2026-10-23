# @order/rules-reference

Part of **[ORDER](https://github.com/keerthikrishnagamasany/order)**, the agent-aware gateway for the age of AI bots.

ORDER's open reference detector pack: SQL injection, path traversal, XSS, prompt injection, SSRF probes and scanner fingerprints. Conservative by design, and open by design, so pair it with your own private pack in production.

```ts
import { combine } from "@order/core";
import { referenceRules } from "@order/rules-reference";

const rules = combine(referenceRules, myPrivateRules);
```

Full documentation: [https://github.com/keerthikrishnagamasany/order](https://github.com/keerthikrishnagamasany/order#readme)

---

Created by **Keerthi Krishna Gamasany**. MIT licensed.
