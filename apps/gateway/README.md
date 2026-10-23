# @order/gateway

Part of **[ORDER](https://github.com/keerthikrishnagamasany/order)**, the agent-aware gateway for the age of AI bots.

Run ORDER in front of your app: Express middleware, a Fastify hook, or a standalone reverse proxy, plus Prometheus metrics. All three share one decision core.

```ts
import express from "express";
import { orderExpress } from "@order/gateway";

const app = express();
app.use(express.json());
app.use(orderExpress());
```

Full documentation: [https://github.com/keerthikrishnagamasany/order](https://github.com/keerthikrishnagamasany/order#readme)

---

Created by **Keerthi Krishna Gamasany**. MIT licensed.
