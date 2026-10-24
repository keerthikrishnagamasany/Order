/**
 * Regression tests for the 2026-10 security audit (Cloudflare security-audit method, quick profile).
 * Each test replays the audit's bounded reproduction against the fixed code. Every test here failed
 * before the fix. Dummy data only; everything runs on loopback.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import { connect } from "node:net";
import { gzipSync, deflateSync } from "node:zlib";
import { generateKeyPairSync } from "node:crypto";
import type { AddressInfo } from "node:net";
import { combine, toHarEntry } from "@order/core";
import { referenceRules } from "@order/rules-reference";
import { StaticKeyResolver, signWebBotAuth, HttpsDirectoryResolver, verifyWebBotAuth, type JwkOkp } from "@order/web-bot-auth";
import { compileRules, fromHar, synthesizeRules } from "@order/reconstruct";
import { createOrder } from "../src/order.js";
import { createGateway } from "../src/server.js";
import { Metrics } from "../src/metrics.js";

const host = "app.example";
const req = (url: string, headers: Record<string, string> = {}, body = "", remoteAddress = "198.51.100.1") => ({
  method: body ? "POST" : "GET",
  url,
  headers: { host, "user-agent": "Mozilla/5.0", ...headers },
  body,
  remoteAddress,
});

function agent(origin: string) {
  const k = generateKeyPairSync("ed25519");
  const jwk = k.publicKey.export({ format: "jwk" }) as unknown as JwkOkp;
  return { origin, jwk, sign: (authority: string): Record<string, string> => ({ ...signWebBotAuth({ privateKey: k.privateKey, publicJwk: jwk, agentUrl: origin, authority }) }) };
}

async function listen(server: ReturnType<typeof createServer>) {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return `127.0.0.1:${(server.address() as AddressInfo).port}`;
}

// ---- detection bypasses -------------------------------------------------------------------------

test("audit: one malformed percent-escape no longer disables decoding (urlDecodeDeep fail-open)", async () => {
  const order = createOrder();
  for (const tail of ["&z=%", "&z=%zz", "&z=%ff"]) {
    const d = await order.check(req(`/api/items?id=1%27%20OR%201%3D1${tail}`));
    assert.equal(d.decision.lane, "blocked", `query with ${tail}`);
    const b = await order.check(req("/api/items", {}, `id=1%27%20OR%201%3D1${tail}`));
    assert.equal(b.decision.lane, "blocked", `body with ${tail}`);
  }
  const t = await order.check(req("/api/file?f=..%2F..%2F..%2Fetc%2Fpasswd&z=%"));
  assert.equal(t.decision.lane, "blocked");
});

test("audit: payloads after padding are inspected; clean large bodies pass (truncate-before-inspection + review A)", async () => {
  const order = createOrder();
  const pad = "a".repeat(70 * 1024);
  const q = await order.check(req(`/api/items?pad=${pad}&id=1'%20OR%201=1`));
  assert.equal(q.decision.lane, "blocked", "query payload after padding is caught");
  const b = await order.check(req("/api/items", {}, `pad=${pad}&id=1' OR 1=1`));
  assert.equal(b.decision.lane, "blocked", "body payload after padding is caught");
  const c = order.canaries.mint("test origin", "sk_live").token;
  const r = await order.check(req("/api/items", {}, `pad=${pad}&k=${c}`));
  assert.equal(r.decision.confidence, "CERTAIN");
  // a clean 100 KiB JSON upload is ordinary traffic, not a decoy
  const upload = JSON.stringify({ items: Array.from({ length: 2500 }, (_, i) => ({ id: i, name: `widget ${i}` })) });
  assert.ok(upload.length > 64 * 1024);
  const u = await order.check(req("/api/upload", {}, upload, "198.51.100.88"));
  assert.equal(u.decision.lane, "normal");
  // an operator who lowers the limit gets a flag instead of a silent cut
  const small = createOrder({ inspectionLimit: 1024 });
  const f = await small.check(req("/api/items", {}, `pad=${"a".repeat(2048)}&id=1' OR 1=1`, "198.51.100.99"));
  assert.ok(f.decision.signals.some((x) => x.name === "oversize_input"));
  assert.notEqual(f.decision.lane, "normal");
});

test("audit: encoded paths match path rules (path-matched-undecoded)", async () => {
  const order = createOrder();
  for (const p of ["/%2eenv", "/%2Eenv", "/.git%2Fconfig", "/%2egit/config", "/wp%2Dlogin.php"]) {
    assert.equal((await order.check(req(p))).decision.lane, "blocked", p);
  }
});

test("review: dot segments built from encoded slashes are resolved before matching (path variants)", async () => {
  const order = createOrder();
  for (const p of ["/x/..%2f.env", "/x%2f..%2f.env", "/a/b/..%2F..%2F.git/config", "/%2e%2e/.env"]) {
    assert.equal((await order.check(req(p, {}, "", "198.51.100.120"))).decision.lane, "blocked", p);
  }
  assert.equal((await order.check(req("/api/v1/products", {}, "", "198.51.100.121"))).decision.lane, "normal");
});

test("review: canaries sent as HTTP Basic credentials or JSON escapes are caught", async () => {
  const order = createOrder();
  const key = order.canaries.mint("decoy /.env key", "sk_live").token;
  const basic = Buffer.from(`${key}:`).toString("base64");
  const a = await order.check(req("/api/charges", { authorization: `Basic ${basic}` }, "", "198.51.100.130"));
  assert.equal(a.decision.confidence, "CERTAIN");
  assert.equal(a.decision.lane, "blocked");
  const escaped = JSON.stringify({ k: key }).replace("_", "\\u005f");
  const j = await order.check(req("/api/items", { "content-type": "application/json" }, escaped, "198.51.100.131"));
  assert.equal(j.decision.lane, "blocked");
  // padding the body can't push a key in Authorization out of the scan
  const pad = Array.from({ length: 1100 }, (_, i) => `x_${i.toString(16).padStart(24, "0")}`).join(" ");
  const p = await order.check(req("/api/items", { authorization: `Bearer ${key}` }, pad, "198.51.100.132"));
  assert.equal(p.decision.confidence, "CERTAIN");
});

test("review: every canary is unique and attributed to its own decoy", async () => {
  const order = createOrder();
  const a = order.canaries.mint("decoy for client A", "sk_live").token;
  const b = order.canaries.mint("decoy for client B", "sk_live").token;
  assert.notEqual(a, b);
  const d = await order.check(req(`/x?k=${a}`, {}, "", "198.51.100.140"));
  assert.ok(d.decision.reasons.includes("canary_replayed:decoy for client A"));
});

test("review: custom credential headers and URL userinfo are redacted in captures", () => {
  const e = toHarEntry({
    startedISO: "", waitedMs: 0, method: "GET", url: "http://user:dummy-pass@app.example/x",
    reqHeaders: { "x-auth-token": "dummy-tok-1", "api-key": "dummy-tok-2", "x-goog-api-key": "dummy-tok-3", "user-agent": "Mozilla/5.0" },
    reqBody: "", status: 200, respBody: "", decision: { lane: "normal", status: 200, confidence: "CERTAIN", signals: [], reasons: [] },
  });
  const s = JSON.stringify(e);
  for (const x of ["dummy-pass", "dummy-tok-1", "dummy-tok-2", "dummy-tok-3"]) assert.equal(s.includes(x), false, x);
  assert.ok(s.includes("Mozilla/5.0"));
});

test("audit: compressed request bodies are refused, never forwarded uninspected (content-encoding)", async () => {
  const seen: string[] = [];
  const app = createServer((r: IncomingMessage, res) => {
    seen.push(r.url ?? "");
    r.resume();
    res.end("ok");
  });
  const appAddr = await listen(app);
  const gw = createGateway({ upstream: { url: `http://${appAddr}` }, capture: false });
  const gwAddr = await listen(gw.server);
  try {
    const payload = JSON.stringify({ q: "x' or 1=1 --" });
    for (const [coding, bytes] of [["gzip", gzipSync(payload)], ["deflate", deflateSync(payload)]] as const) {
      const res = await fetch(`http://${gwAddr}/api/search`, {
        method: "POST",
        headers: { "content-type": "application/json", "content-encoding": coding, "user-agent": "Mozilla/5.0" },
        body: bytes,
      });
      assert.equal(res.status, 415, coding);
    }
    assert.equal(seen.length, 0, "nothing compressed reached the app");
    // identity bodies still work
    const ok = await fetch(`http://${gwAddr}/api/search`, { method: "POST", headers: { "content-type": "application/json", "user-agent": "Mozilla/5.0" }, body: '{"q":"books"}' });
    assert.equal(ok.status, 200);
  } finally {
    gw.server.close();
    app.close();
  }
});

// ---- canaries -----------------------------------------------------------------------------------

test("audit: canaries replayed in Authorization, Cookie or the path are caught (detect surface)", async () => {
  const order = createOrder();
  const key = order.canaries.mint("decoy /.env key", "sk_live").token;
  const sess = order.canaries.mint("decoy /admin token", "adm_sess").token;
  for (const [what, r] of [
    ["bearer", req("/api/items", { authorization: `Bearer ${key}` })],
    ["cookie", req("/api/items", { cookie: `session=${sess}` })],
    ["path", req(`/api/items/${key}`)],
  ] as const) {
    const d = await order.check(r);
    assert.equal(d.decision.lane, "blocked", what);
    assert.equal(d.decision.confidence, "CERTAIN", what);
  }
});

test("audit: padding a query with canary-shaped words can't hide a canary (32-candidate cap)", async () => {
  const order = createOrder();
  const key = order.canaries.mint("decoy /.env key", "sk_live").token;
  const pad = Array.from({ length: 32 }, (_, i) => `x_${i.toString(16).padStart(24, "0")}`).join("+");
  const d = await order.check(req(`/api/items?p=${pad}&key=${key}`));
  assert.equal(d.decision.lane, "blocked");
  // and an absurd amount of padding is itself suspicious rather than a free pass
  const huge = Array.from({ length: 1100 }, (_, i) => `x_${i.toString(16).padStart(24, "0")}`).join(" ");
  const h = await order.check(req("/api/items", {}, `p=${huge}&key=${key}`));
  assert.notEqual(h.decision.lane, "normal");
});

test("audit: decoy floods can't evict planted canaries (canary FIFO eviction)", async () => {
  const order = createOrder();
  const victim = await order.check(req("/admin/users", { "user-agent": "curl/8" }, "", "10.0.0.1"));
  assert.equal(victim.decision.lane, "decoy");
  const token = /adm_sess_[0-9a-f]{24}/.exec(victim.respond?.body ?? "")?.[0];
  assert.ok(token, "decoy carries a canary");
  // a store-backed registry evicted after 100,000 mints; canaries are now self-verifying
  for (let i = 0; i < 120_000; i++) order.canaries.mint("decoy /admin token", "adm_sess");
  const replay = await order.check(req(`/api/items?k=${token}`, {}, "", "10.0.0.1"));
  assert.equal(replay.decision.lane, "blocked");
  assert.equal(replay.decision.confidence, "CERTAIN");
});

test("canaries with a shared secret are recognised by another instance", async () => {
  const secret = "a-dummy-shared-secret-of-32-bytes!";
  const a = createOrder({ canary: { secret } });
  const b = createOrder({ canary: { secret } });
  const token = a.canaries.mint("decoy", "cnry").token;
  assert.equal((await b.check(req(`/x?k=${token}`))).decision.lane, "blocked");
  // a forged token with the right shape but a wrong MAC is not a canary
  const forged = token.slice(0, -4) + (token.endsWith("0000") ? "1111" : "0000");
  assert.equal((await b.check(req(`/x?k=${forged}`))).decision.lane, "normal");
});

// ---- identity binding ---------------------------------------------------------------------------

test("audit: a signature made for another site can't be replayed here with that site's Host (authority binding)", async () => {
  const ag = agent("https://agent.example");
  const order = createOrder({ botAuth: { resolver: new StaticKeyResolver().add(ag.origin, ag.jwk), authorities: [host] } });
  const forOther = ag.sign("attacker.example");
  const replay = await order.check({ ...req("/api/v1/products", forOther), headers: { ...forOther, host: "attacker.example", "user-agent": "agent/1.0" } });
  assert.equal(replay.botAuth, "invalid");
  assert.notEqual(replay.decision.lane, "trusted");
  // the real site still works
  const genuine = await order.check(req("/api/v1/products", ag.sign(host)));
  assert.equal(genuine.botAuth, "verified");
  assert.equal(genuine.decision.lane, "trusted");
});

test("audit: a verified agent can't claim another origin's authorized-test engagement (tester namespace)", async () => {
  const attacker = agent("https://agent-b.example");
  const resolver = new StaticKeyResolver().add(attacker.origin, attacker.jwk);
  const order = createOrder({
    botAuth: { resolver, authorities: [host] },
    authorizedTesters: new Map([["agent:https://tester-a.example", { label: "dummy-engagement", expiresAt: Date.now() + 3_600_000 }]]),
  });
  const d = await order.check(req("/api/items?id=1'%20OR%201=1", { ...attacker.sign(host), "x-mcp-key": "agent:https://tester-a.example" }));
  assert.equal(d.decision.lane, "blocked");
  assert.equal(d.decision.authorizedTest, undefined);
});

// ---- state and exposure -------------------------------------------------------------------------

test("audit: the key-directory cache is bounded and stores no attacker text (directory cache)", async () => {
  let lookups = 0;
  const failing = async () => {
    lookups++;
    throw new Error("getaddrinfo ENOTFOUND some-very-long-attacker-host");
  };
  let now = Date.now();
  const resolver = new HttpsDirectoryResolver({ transport: failing, maxEntries: 100, nowMs: () => now });
  const sigInput = (o: string) => `sig1=("@authority" "signature-agent";key="a");created=${Math.floor(now / 1000)};expires=${Math.floor(now / 1000) + 60};keyid="junk";tag="web-bot-auth"`;
  for (let i = 0; i < 500; i++) {
    const origin = `https://h${i}.attacker.example`;
    await verifyWebBotAuth({ signatureInput: sigInput(origin), signature: "sig1=:AAAA:", signatureAgent: `a="${origin}"` }, { method: "GET", authority: host, path: "/", targetUri: `http://${host}/` }, resolver);
  }
  assert.equal(lookups, 500);
  assert.ok(resolver.cachedOrigins <= 100, `cache holds ${resolver.cachedOrigins}`);
  // over-long origins are refused before any lookup
  const long = `https://${"a".repeat(300)}.example`;
  assert.equal(await resolver.resolve(long, "k"), null);
  assert.equal(lookups, 500);
  now += 24 * 3600 * 1000;
});

test("audit: metrics aren't served to traffic relayed by a trusted local proxy (metrics gate)", async () => {
  const gw = createGateway({ clientIdentity: { trustedProxies: ["127.0.0.1"] }, metrics: { registry: new Metrics() }, capture: false });
  const addr = await listen(gw.server);
  try {
    const res = await fetch(`http://${addr}/__order/metrics`, { headers: { "x-forwarded-for": "203.0.113.9", "user-agent": "Mozilla/5.0" } });
    assert.ok(!(await res.text()).includes("order_decisions_total"), "metrics not served");
  } finally {
    gw.server.close();
  }
  // a plain local scraper still gets them
  const local = createGateway({ metrics: { registry: new Metrics() }, capture: false });
  const a2 = await listen(local.server);
  try {
    const res = await fetch(`http://${a2}/__order/metrics`);
    assert.ok((await res.text()).includes("order_decisions_total"));
  } finally {
    local.server.close();
  }
});

test("audit: the gateway capture keeps no credentials (unredacted-request-credentials)", async () => {
  const gw = createGateway({ allowlist: new Map([["dummy_key_000", "partner"]]) });
  const addr = await listen(gw.server);
  try {
    await fetch(`http://${addr}/api/v1/login?token=dummyquerytoken`, {
      method: "POST",
      headers: { authorization: "Bearer dummy-bearer-123", cookie: "sid=dummy-session-456", "x-mcp-key": "dummy_key_000", "content-type": "application/json", "user-agent": "Mozilla/5.0" },
      body: '{"user":"alice","password":"dummy-pw-789"}',
    });
    const har = gw.recorder.toJSON();
    for (const s of ["dummy-bearer-123", "dummy-session-456", "dummy_key_000", "dummyquerytoken", "dummy-pw-789"]) assert.equal(har.includes(s), false, s);
  } finally {
    gw.server.close();
  }
});

test("audit: a raw-socket request with a 1 MiB body still respects the capture byte budget (count-only cap)", async () => {
  const gw = createGateway({ capture: { maxBytes: 2 * 1024 * 1024, includeBodies: true } });
  const addr = await listen(gw.server);
  const [h, p] = addr.split(":");
  try {
    for (let i = 0; i < 8; i++) {
      await new Promise<void>((resolve) => {
        const body = Buffer.alloc(1024 * 1024, 0xff);
        const s = connect(Number(p), h as string, () => {
          s.write(`POST /api/items HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Mozilla/5.0\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`);
          s.end(body);
        });
        s.on("data", () => {});
        s.on("close", () => resolve());
        s.on("error", () => resolve());
      });
    }
    assert.ok(gw.recorder.retainedBytes <= 2 * 1024 * 1024, `retained ${gw.recorder.retainedBytes}`);
  } finally {
    gw.server.close();
  }
});

// ---- offline learning ---------------------------------------------------------------------------

test("audit: '(path=' inside a payload excerpt can't make synthesis blame a path (payloadOnly locus spoof)", async () => {
  const order = createOrder();
  const entries = [];
  for (const [ip, url] of [["192.0.2.9", "/api/v1/products"], ["203.0.113.1", "/api/v1/checkout?q=union/*(path=*/select"], ["203.0.113.2", "/api/v1/checkout?q=union/*(path=*/select"]] as const) {
    const r = await order.check(req(url, {}, "", ip));
    entries.push(toHarEntry({ startedISO: "", waitedMs: 0, method: "GET", url: `http://${host}${url}`, reqHeaders: { "user-agent": "Mozilla/5.0" }, reqBody: "", status: r.decision.status, respBody: "", decision: r.decision, clientId: r.clientId }));
  }
  const proposals = synthesizeRules(fromHar({ log: { entries } }), { existing: referenceRules });
  assert.equal(proposals.some((p) => p.id === "path:/api/v1/checkout"), false);
  // and an old capture without loci is parsed by the anchored prefix only
  const legacy = fromHar({ log: { entries: entries.map((e) => ({ ...e, _order: { ...e._order, loci: undefined } })) } });
  assert.equal(synthesizeRules(legacy, { existing: referenceRules }).some((p) => p.id === "path:/api/v1/checkout"), false);
  // learned rules still compile and enforce as before
  assert.equal(typeof combine(referenceRules, compileRules(proposals)).inspect, "function");
});
