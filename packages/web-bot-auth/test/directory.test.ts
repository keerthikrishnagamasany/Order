import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  DIRECTORY_MEDIA_TYPE,
  DIRECTORY_PATH,
  HttpsDirectoryResolver,
  ed25519Thumbprint,
  guardedLookup,
  isHttpsOrigin,
  isPrivateAddress,
  parseDirectory,
  signWebBotAuth,
  verifyWebBotAuth,
  type JwkOkp,
  type Transport,
  type TransportResponse,
} from "../src/index.js";

const ORIGIN = "https://agent.example";

function key() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { privateKey, jwk: publicKey.export({ format: "jwk" }) as unknown as JwkOkp };
}

function ok(keys: unknown[], extra: Record<string, string> = {}): TransportResponse {
  return {
    status: 200,
    headers: { "content-type": DIRECTORY_MEDIA_TYPE, ...extra },
    body: JSON.stringify({ keys }),
  };
}

/** A fake transport that records calls and returns a scripted response. */
function fake(respond: (url: string) => TransportResponse | Promise<TransportResponse>) {
  const calls: string[] = [];
  const t: Transport = async (url) => {
    calls.push(url);
    return respond(url);
  };
  return { t, calls };
}

// --- network guard ---------------------------------------------------------

test("private, loopback, link-local and metadata addresses are refused", () => {
  for (const a of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"]) {
    assert.equal(isPrivateAddress(a), true, a);
  }
});

test("public addresses are allowed", () => {
  for (const a of ["1.1.1.1", "8.8.8.8", "104.16.0.1", "2606:4700:4700::1111"]) {
    assert.equal(isPrivateAddress(a), false, a);
  }
});

test("guardedLookup refuses a host that resolves to a private address (DNS rebinding)", async () => {
  const lookup = guardedLookup((_h, _o, cb) => cb(null, [{ address: "8.8.8.8", family: 4 }, { address: "10.0.0.5", family: 4 }]));
  const err = await new Promise<NodeJS.ErrnoException | null>((r) => lookup("evil.example", { all: true }, (e) => r(e)));
  assert.equal(err?.code, "EPRIVATE");
});

test("guardedLookup passes a public host through", async () => {
  const lookup = guardedLookup((_h, _o, cb) => cb(null, [{ address: "8.8.8.8", family: 4 }]));
  const addr = await new Promise<unknown>((r) => lookup("good.example", {}, (e, a) => r(e ?? a)));
  assert.equal(addr, "8.8.8.8");
});

test("isHttpsOrigin accepts only an exact https origin", () => {
  assert.equal(isHttpsOrigin("https://agent.example"), true);
  assert.equal(isHttpsOrigin("https://agent.example:8443"), true);
  for (const bad of ["http://agent.example", "https://agent.example/", "https://agent.example/keys", "https://u:p@agent.example", "https://agent.example?x=1", "not a url"]) {
    assert.equal(isHttpsOrigin(bad), false, bad);
  }
});

// --- directory parsing -----------------------------------------------------

test("parseDirectory keeps valid Ed25519 keys, keyed by thumbprint", () => {
  const { jwk } = key();
  const m = parseDirectory(JSON.stringify({ keys: [jwk] }), 16, 1000);
  assert.ok(m.get(ed25519Thumbprint(jwk)));
});

test("parseDirectory drops a key whose kid is not its thumbprint", () => {
  const { jwk } = key();
  const m = parseDirectory(JSON.stringify({ keys: [{ ...jwk, kid: "wrong" }] }), 16, 1000);
  assert.equal(m.size, 0);
});

test("parseDirectory drops expired and not-yet-valid keys", () => {
  const a = key().jwk;
  const b = key().jwk;
  const m = parseDirectory(JSON.stringify({ keys: [{ ...a, exp: 900 }, { ...b, nbf: 2000 }] }), 16, 1000);
  assert.equal(m.size, 0);
});

test("parseDirectory rejects too many keys and malformed bodies", () => {
  const keys = Array.from({ length: 3 }, () => key().jwk);
  assert.throws(() => parseDirectory(JSON.stringify({ keys }), 2, 0), /limit/);
  assert.throws(() => parseDirectory("not json", 16, 0), /JSON/);
  assert.throws(() => parseDirectory(JSON.stringify({ nope: [] }), 16, 0), /keys array/);
});

// --- resolver behaviour ----------------------------------------------------

test("resolver fetches the well-known path on the agent origin", async () => {
  const { jwk } = key();
  const { t, calls } = fake(() => ok([jwk]));
  const r = new HttpsDirectoryResolver({ transport: t });
  assert.deepEqual(await r.resolve(ORIGIN, ed25519Thumbprint(jwk)), jwk);
  assert.deepEqual(calls, [`${ORIGIN}${DIRECTORY_PATH}`]);
});

test("a non-origin agent value is never fetched", async () => {
  const { t, calls } = fake(() => ok([]));
  const r = new HttpsDirectoryResolver({ transport: t });
  assert.equal(await r.resolve("https://agent.example/keys", "x"), null);
  assert.equal(await r.resolve("http://agent.example", "x"), null);
  assert.equal(calls.length, 0);
});

test("redirects and non-200 statuses are failures, not followed", async () => {
  for (const status of [301, 302, 307, 404, 500]) {
    const { t } = fake(() => ({ status, headers: { location: "https://elsewhere.example/" }, body: "" }));
    const r = new HttpsDirectoryResolver({ transport: t });
    await assert.rejects(r.resolve(ORIGIN, "x"), /status/);
  }
});

test("wrong content-type is a failure", async () => {
  const { jwk } = key();
  const { t } = fake(() => ({ ...ok([jwk]), headers: { "content-type": "application/json" } }));
  await assert.rejects(new HttpsDirectoryResolver({ transport: t }).resolve(ORIGIN, "x"), /content-type/);
});

test("an oversized directory is a failure", async () => {
  const { t } = fake(() => ({ ...ok([]), body: "x".repeat(70 * 1024) }));
  await assert.rejects(new HttpsDirectoryResolver({ transport: t }).resolve(ORIGIN, "x"), /too large/);
});

test("results are cached; one fetch serves many lookups", async () => {
  const { jwk } = key();
  const { t, calls } = fake(() => ok([jwk]));
  const r = new HttpsDirectoryResolver({ transport: t });
  const id = ed25519Thumbprint(jwk);
  await r.resolve(ORIGIN, id);
  await r.resolve(ORIGIN, id);
  await r.resolve(ORIGIN, "some-other-keyid");
  assert.equal(calls.length, 1);
});

test("concurrent lookups share one in-flight fetch", async () => {
  const { jwk } = key();
  const { t, calls } = fake(() => new Promise((res) => setTimeout(() => res(ok([jwk])), 20)));
  const r = new HttpsDirectoryResolver({ transport: t });
  const id = ed25519Thumbprint(jwk);
  await Promise.all([r.resolve(ORIGIN, id), r.resolve(ORIGIN, id), r.resolve(ORIGIN, id)]);
  assert.equal(calls.length, 1);
});

test("max-age is respected, then the directory is refetched", async () => {
  const { jwk } = key();
  let now = 0;
  const { t, calls } = fake(() => ok([jwk], { "cache-control": "max-age=60" }));
  const r = new HttpsDirectoryResolver({ transport: t, nowMs: () => now });
  const id = ed25519Thumbprint(jwk);
  await r.resolve(ORIGIN, id);
  now = 59_000;
  await r.resolve(ORIGIN, id);
  assert.equal(calls.length, 1);
  now = 61_000;
  await r.resolve(ORIGIN, id);
  assert.equal(calls.length, 2);
});

test("failures are cached for at most five minutes", async () => {
  let now = 0;
  let fails = true;
  const { jwk } = key();
  const { t, calls } = fake(() => {
    if (fails) throw new Error("down");
    return ok([jwk]);
  });
  const r = new HttpsDirectoryResolver({ transport: t, nowMs: () => now, negativeTtlSec: 3600 });
  await assert.rejects(r.resolve(ORIGIN, "x"));
  now = 299_000;
  await assert.rejects(r.resolve(ORIGIN, "x"));
  assert.equal(calls.length, 1, "still negatively cached");
  fails = false;
  now = 301_000;
  assert.deepEqual(await r.resolve(ORIGIN, ed25519Thumbprint(jwk)), jwk);
  assert.equal(calls.length, 2, "negative TTL capped at 300s even when configured higher");
});

// --- end to end through the verifier ---------------------------------------

test("a signed request verifies against a fetched directory", async () => {
  const { privateKey, jwk } = key();
  const NOW = 1_800_000_000;
  const h = signWebBotAuth({ privateKey, publicJwk: jwk, agentUrl: ORIGIN, authority: "shop.example", createdSec: NOW });
  const { t } = fake(() => ok([jwk]));
  const r = await verifyWebBotAuth(
    { signatureInput: h["signature-input"], signature: h.signature, signatureAgent: h["signature-agent"] },
    { method: "GET", authority: "shop.example", path: "/", targetUri: "https://shop.example/" },
    new HttpsDirectoryResolver({ transport: t }),
    { nowSec: NOW + 5 },
  );
  assert.equal(r.status, "verified", r.reason);
});

test("an unreachable directory makes the request unverified, not invalid", async () => {
  const { privateKey, jwk } = key();
  const NOW = 1_800_000_000;
  const h = signWebBotAuth({ privateKey, publicJwk: jwk, agentUrl: ORIGIN, authority: "shop.example", createdSec: NOW });
  const { t } = fake(() => {
    throw new Error("timeout");
  });
  const r = await verifyWebBotAuth(
    { signatureInput: h["signature-input"], signature: h.signature, signatureAgent: h["signature-agent"] },
    { method: "GET", authority: "shop.example", path: "/", targetUri: "https://shop.example/" },
    new HttpsDirectoryResolver({ transport: t }),
    { nowSec: NOW + 5 },
  );
  assert.equal(r.status, "unverified");
});

test("the real transport refuses private IP literals before opening a socket", async () => {
  const { httpsTransport } = await import("../src/index.js");
  const t = httpsTransport();
  for (const u of ["https://127.0.0.1/x", "https://169.254.169.254/x", "https://10.0.0.1/x", "https://[::1]/x", "https://[::ffff:127.0.0.1]/x"]) {
    await assert.rejects(t(u, { timeoutMs: 500, maxBytes: 1000 }), (e: NodeJS.ErrnoException) => e.code === "EPRIVATE", u);
  }
});

test("the real transport refuses a hostname that resolves to a private address", async () => {
  const { httpsTransport } = await import("../src/index.js");
  const t = httpsTransport((_h, _o, cb) => cb(null, [{ address: "10.0.0.7", family: 4 }]));
  await assert.rejects(t("https://looks-public.example/x", { timeoutMs: 1000, maxBytes: 1000 }), (e: NodeJS.ErrnoException) => e.code === "EPRIVATE");
});

test("notation can't change the verdict: hex, compressed and expanded IPv6 forms", () => {
  for (const a of ["::ffff:7f00:1", "::ffff:a00:1", "::ffff:a9fe:a9fe", "0:0:0:0:0:ffff:7f00:1", "0:0:0:0:0:0:0:1", "[::1]", "::127.0.0.1", "FE80::1", "fe80::1%eth0", "64:ff9b::a00:1"]) {
    assert.equal(isPrivateAddress(a), true, a);
  }
  assert.equal(isPrivateAddress("::ffff:808:808"), false, "mapped 8.8.8.8 is public");
});
