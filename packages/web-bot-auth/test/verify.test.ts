import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  StaticKeyResolver,
  signWebBotAuth,
  verifyWebBotAuth,
  ed25519Thumbprint,
  type JwkOkp,
  type KeyResolver,
} from "../src/index.js";

const AGENT = "https://agent.example";
const AUTHORITY = "shop.example";
const NOW = 1_800_000_000;

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as unknown as JwkOkp;
  return { privateKey, jwk };
}

function ctx(authority = AUTHORITY) {
  return { method: "GET", authority, path: "/", targetUri: `https://${authority}/` };
}

function signed(opts: Partial<{ authority: string; created: number; ttl: number }> = {}) {
  const kp = keypair();
  const h = signWebBotAuth({
    privateKey: kp.privateKey,
    publicJwk: kp.jwk,
    agentUrl: AGENT,
    authority: opts.authority ?? AUTHORITY,
    createdSec: opts.created ?? NOW,
    ttlSec: opts.ttl ?? 300,
  });
  return {
    kp,
    headers: { signatureInput: h["signature-input"], signature: h.signature, signatureAgent: h["signature-agent"] },
    resolver: new StaticKeyResolver().add(AGENT, kp.jwk),
  };
}

test("keyid is the RFC 8037 thumbprint and appears in Signature-Input", () => {
  const { kp, headers } = signed();
  assert.ok(headers.signatureInput.includes(`keyid="${ed25519Thumbprint(kp.jwk)}"`));
  assert.ok(headers.signatureInput.includes('tag="web-bot-auth"'));
  assert.ok(headers.signatureInput.includes('"signature-agent";key="sig"'));
});

test("a correctly signed request is verified", async () => {
  const { headers, resolver } = signed();
  const r = await verifyWebBotAuth(headers, ctx(), resolver, { nowSec: NOW + 10 });
  assert.equal(r.status, "verified", r.reason);
  assert.equal(r.agent, AGENT);
});

test("signature replayed against a different host is invalid", async () => {
  const { headers, resolver } = signed();
  const r = await verifyWebBotAuth(headers, ctx("evil.example"), resolver, { nowSec: NOW + 10 });
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /did not validate/);
});

test("tampered signature bytes are invalid", async () => {
  const { headers, resolver } = signed();
  const flipped = headers.signature.replace(/:(.)/, (_m, c: string) => `:${c === "A" ? "B" : "A"}`);
  const r = await verifyWebBotAuth({ ...headers, signature: flipped }, ctx(), resolver, { nowSec: NOW + 10 });
  assert.equal(r.status, "invalid");
});

test("expired signature is invalid", async () => {
  const { headers, resolver } = signed({ ttl: 60 });
  const r = await verifyWebBotAuth(headers, ctx(), resolver, { nowSec: NOW + 3600 });
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /expired/);
});

test("lifetime over 24h is invalid", async () => {
  const { headers, resolver } = signed({ ttl: 2 * 24 * 3600 });
  const r = await verifyWebBotAuth(headers, ctx(), resolver, { nowSec: NOW + 10 });
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /max age/);
});

test("wrong tag is invalid", async () => {
  const { headers, resolver } = signed();
  const r = await verifyWebBotAuth(
    { ...headers, signatureInput: headers.signatureInput.replace("web-bot-auth", "something-else") },
    ctx(),
    resolver,
    { nowSec: NOW + 10 },
  );
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /tag/);
});

test("unknown key is unverified, not invalid", async () => {
  const { headers } = signed();
  const r = await verifyWebBotAuth(headers, ctx(), new StaticKeyResolver(), { nowSec: NOW + 10 });
  assert.equal(r.status, "unverified");
});

test("a failing key directory is unverified, not invalid", async () => {
  const { headers } = signed();
  const broken: KeyResolver = { resolve: () => Promise.reject(new Error("timeout")) };
  const r = await verifyWebBotAuth(headers, ctx(), broken, { nowSec: NOW + 10 });
  assert.equal(r.status, "unverified");
});

test("a directory returning a key under the wrong keyid is invalid", async () => {
  const { headers } = signed();
  const other = keypair();
  const liar: KeyResolver = { resolve: () => other.jwk };
  const r = await verifyWebBotAuth(headers, ctx(), liar, { nowSec: NOW + 10 });
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /keyid does not match/);
});

test("non-https Signature-Agent is invalid", async () => {
  const { headers, resolver } = signed();
  const r = await verifyWebBotAuth(
    { ...headers, signatureAgent: 'sig="http://agent.example/dir"' },
    ctx(),
    resolver,
    { nowSec: NOW + 10 },
  );
  assert.equal(r.status, "invalid");
});

test("missing headers are invalid", async () => {
  const r = await verifyWebBotAuth({}, ctx(), new StaticKeyResolver(), { nowSec: NOW });
  assert.equal(r.status, "invalid");
});

test("Signature-Agent with a path (not an origin) is invalid", async () => {
  const { headers, resolver } = signed();
  const r = await verifyWebBotAuth(
    { ...headers, signatureAgent: 'sig="https://agent.example/keys"' },
    ctx(),
    resolver,
    { nowSec: NOW + 10 },
  );
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /origin/);
});

test("an unknown Signature-Agent discovery type is unverified, not invalid", async () => {
  const { headers, resolver } = signed();
  const r = await verifyWebBotAuth(
    { ...headers, signatureAgent: 'sig="https://agent.example";type="something-new"' },
    ctx(),
    resolver,
    { nowSec: NOW + 10 },
  );
  assert.equal(r.status, "unverified");
});
