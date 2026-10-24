import { test } from "node:test";
import assert from "node:assert/strict";
import { HarRecorder, toHarEntry, type CaptureInput } from "../src/capture.js";
import type { Decision } from "../src/types.js";

const decision: Decision = { lane: "trusted", status: 200, confidence: "CERTAIN", signals: [], reasons: [] };

function input(over: Partial<CaptureInput> = {}): CaptureInput {
  return {
    startedISO: "2026-10-24T00:00:00Z",
    waitedMs: 1,
    method: "POST",
    url: "http://app.example/api/v1/login?token=dummyquerytoken&page=2",
    reqHeaders: {
      authorization: "Bearer dummy-bearer-123",
      cookie: "sid=dummy-session-456",
      "x-mcp-key": "dummy_key_000",
      signature: "sig1=:dummy-signature:",
      "signature-input": 'sig1=("@authority");keyid="dummy-kid"',
      "user-agent": "Mozilla/5.0",
      "x-sim-client": "client-a",
    },
    reqBody: '{"user":"alice","password":"dummy-pw-789"}',
    status: 200,
    respBody: '{"ok":true}',
    decision,
    clientId: "203.0.113.5",
    ...over,
  };
}

test("capture never stores credentials by default (audit: unredacted-request-credentials)", () => {
  const r = new HarRecorder();
  r.record(input());
  const har = r.toJSON();
  for (const secret of ["dummy-bearer-123", "dummy-session-456", "dummy_key_000", "dummy-signature", "dummy-kid", "dummyquerytoken", "dummy-pw-789"]) {
    assert.equal(har.includes(secret), false, `${secret} leaked into the capture`);
  }
  // what reconstruction needs is still there
  assert.ok(har.includes("/api/v1/login"));
  assert.ok(har.includes("Mozilla/5.0"));
  assert.ok(har.includes("client-a"));
  assert.ok(har.includes("token=%5Bredacted%5D") || har.includes("token=[redacted]"), "query parameter names are kept");
});

test("bodies and query values are kept only when the operator opts in", () => {
  const e = toHarEntry(input(), { includeBodies: true, includeQueryValues: true });
  const s = JSON.stringify(e);
  assert.ok(s.includes("dummy-pw-789"));
  assert.ok(s.includes("dummyquerytoken"));
  // credential headers stay redacted even then
  assert.equal(s.includes("dummy-bearer-123"), false);
});

test("capture memory is bounded by bytes, not just entries (audit: count-only-cap)", () => {
  const big = "�".repeat(1024 * 1024); // the 2-byte-per-char worst case from the audit
  const r = new HarRecorder({ includeBodies: true, maxBytes: 4 * 1024 * 1024 });
  for (let i = 0; i < 50; i++) r.record(input({ reqBody: big, respBody: big }));
  assert.ok(r.retainedBytes <= 4 * 1024 * 1024, `retained ${r.retainedBytes} bytes`);
  assert.ok(r.dropped > 0);
  // each stored body is truncated, while the original size is still recorded
  const entry = JSON.parse(r.toJSON()).log.entries[0];
  assert.equal(entry.request.postData.text.length, 64 * 1024);
  assert.equal(entry.request.bodySize, 1024 * 1024);
});

test("default byte budget holds against the audit's 1 MiB x many requests shape", () => {
  const big = "�".repeat(1024 * 1024);
  const r = new HarRecorder(); // defaults: bodies not kept, 64 MiB budget
  for (let i = 0; i < 200; i++) r.record(input({ reqBody: big }));
  assert.ok(r.retainedBytes < 64 * 1024 * 1024);
  assert.equal(JSON.parse(r.toJSON()).log.entries[0].request.postData, undefined);
});

test("clear() resets the byte budget", () => {
  const r = new HarRecorder({ includeBodies: true });
  r.record(input());
  assert.ok(r.retainedBytes > 0);
  r.clear();
  assert.equal(r.retainedBytes, 0);
  assert.equal(r.count, 0);
});
