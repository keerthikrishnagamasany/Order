import { test } from "node:test";
import assert from "node:assert/strict";
import { urlDecodeDeep, normalise } from "../src/normalise.js";

test("single URL-decode reveals an encoded quote", () => {
  assert.equal(urlDecodeDeep("id%3D1%27"), "id=1'");
});

test("double-encoding is defeated", () => {
  // %2527 -> %27 -> '
  assert.equal(urlDecodeDeep("%2527"), "'");
});

test("plus becomes space", () => {
  assert.equal(urlDecodeDeep("a+b"), "a b");
});

test("malformed escape does not throw and returns raw", () => {
  assert.equal(urlDecodeDeep("%zz"), "%zz");
});

test("normalise strips null bytes and bounds length", () => {
  assert.equal(normalise("a\u0000b"), "ab");
  assert.equal(normalise("x".repeat(100), 10).length, 10);
  assert.equal(normalise(undefined), "");
});
