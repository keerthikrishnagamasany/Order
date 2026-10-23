/**
 * Interop: the official Ed25519 test vector from draft-ietf-webbotauth-httpsig-protocol-00,
 * Appendix E.2.1, verified through ORDER's real verifier. The key is RFC 9421 Appendix
 * B.1.4 "test-key-ed25519" (public part). If this passes, ORDER agrees with the standard —
 * not merely with its own signer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { StaticKeyResolver, ed25519Thumbprint, verifyWebBotAuth, type JwkOkp } from "../src/index.js";

const RFC9421_TEST_KEY_ED25519: JwkOkp = {
  kty: "OKP",
  crv: "Ed25519",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

const VECTOR = {
  authority: "example.com",
  keyid: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
  signatureAgent: 'agent2="https://signature-agent.test"',
  signatureInput:
    'sig2=("@authority" "signature-agent";key="agent2")' +
    ';created=1735689600' +
    ';keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"' +
    ';alg="ed25519"' +
    ';expires=4889289600' +
    ';nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA=="' +
    ';tag="web-bot-auth"',
  signature:
    "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:",
};

const ctx = { method: "GET", authority: VECTOR.authority, path: "/", targetUri: "https://example.com/" };

test("RFC 8037 thumbprint of the RFC 9421 test key equals the draft keyid", () => {
  assert.equal(ed25519Thumbprint(RFC9421_TEST_KEY_ED25519), VECTOR.keyid);
});

test("draft Appendix E.2.1 Ed25519 vector verifies through verifyWebBotAuth", async () => {
  const resolver = new StaticKeyResolver().add("https://signature-agent.test", RFC9421_TEST_KEY_ED25519);
  const r = await verifyWebBotAuth(
    {
      signatureInput: VECTOR.signatureInput,
      signature: VECTOR.signature,
      signatureAgent: VECTOR.signatureAgent,
    },
    ctx,
    resolver,
    // The vector's expires is ~100 years out; ORDER's 24h replay policy is a local choice,
    // so widen it here to test standards conformance on its own.
    { nowSec: 1735689700, maxAgeSec: Number.POSITIVE_INFINITY },
  );
  assert.equal(r.status, "verified", r.reason);
  assert.equal(r.agent, "https://signature-agent.test");
});

test("the same vector is invalid under ORDER's default 24h replay policy", async () => {
  const resolver = new StaticKeyResolver().add("https://signature-agent.test", RFC9421_TEST_KEY_ED25519);
  const r = await verifyWebBotAuth(
    { signatureInput: VECTOR.signatureInput, signature: VECTOR.signature, signatureAgent: VECTOR.signatureAgent },
    ctx,
    resolver,
    { nowSec: 1735689700 },
  );
  assert.equal(r.status, "invalid");
  assert.match(r.reason, /policy max age/);
});

test("the vector replayed to another host is invalid", async () => {
  const resolver = new StaticKeyResolver().add("https://signature-agent.test", RFC9421_TEST_KEY_ED25519);
  const r = await verifyWebBotAuth(
    { signatureInput: VECTOR.signatureInput, signature: VECTOR.signature, signatureAgent: VECTOR.signatureAgent },
    { ...ctx, authority: "example.org" },
    resolver,
    { nowSec: 1735689700, maxAgeSec: Number.POSITIVE_INFINITY },
  );
  assert.equal(r.status, "invalid");
});
