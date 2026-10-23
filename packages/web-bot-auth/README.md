# @order/web-bot-auth

Part of **[ORDER](https://github.com/keerthikrishnagamasany/order)**, the agent-aware gateway for the age of AI bots.

Verify and sign Web Bot Auth requests (draft-ietf-webbotauth-httpsig-protocol on RFC 9421 HTTP Message Signatures, Ed25519). Includes an HTTPS key-directory resolver with SSRF protection. Tested against the draft's own Ed25519 test vector. Zero runtime dependencies.

```ts
import { verifyWebBotAuth, HttpsDirectoryResolver } from "@order/web-bot-auth";

const result = await verifyWebBotAuth(headers, { method, authority, path, targetUri }, new HttpsDirectoryResolver());
// result.status: "verified" | "unverified" | "invalid"
```

Full documentation: [https://github.com/keerthikrishnagamasany/order](https://github.com/keerthikrishnagamasany/order#readme)

---

Created by **Keerthi Krishna Gamasany**. MIT licensed.
