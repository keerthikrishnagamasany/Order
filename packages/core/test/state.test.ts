import { test } from "node:test";
import assert from "node:assert/strict";
import { CanaryRegistry, canaryCandidates } from "../src/canary.js";
import { Engine } from "../src/pipeline.js";
import { MemoryStateStore, RedisStateStore, type RedisExec } from "../src/state.js";
import type { RulePack } from "../src/types.js";

const suspectOnScript: RulePack = {
  id: "t",
  inspect: (f) => (/<script/i.test(f.body) ? [{ name: "xss", severity: "SUSPECT", where: "body", excerpt: "<script" }] : []),
};

/** A tiny in-memory Redis speaking the handful of commands RedisStateStore uses. */
function fakeRedis(clock: () => number): { exec: RedisExec; keys: () => string[] } {
  const data = new Map<string, { v: string; exp: number }>();
  const live = (k: string) => {
    const e = data.get(k);
    if (e && e.exp <= clock()) data.delete(k);
    return data.get(k);
  };
  const exec: RedisExec = async (args) => {
    const [cmd, key = "", ...rest] = args;
    switch (cmd) {
      case "INCR":
      case "INCRBY": {
        const by = cmd === "INCR" ? 1 : Number(rest[0]);
        const cur = live(key);
        const n = Number(cur?.v ?? 0) + by;
        data.set(key, { v: String(n), exp: cur?.exp ?? Infinity });
        return n;
      }
      case "PEXPIRE": {
        const cur = live(key);
        if (cur) cur.exp = clock() + Number(rest[0]);
        return cur ? 1 : 0;
      }
      case "GET":
        return live(key)?.v ?? null;
      case "SET": {
        const px = rest.indexOf("PX");
        data.set(key, { v: rest[0] as string, exp: px >= 0 ? clock() + Number(rest[px + 1]) : Infinity });
        return "OK";
      }
      default:
        throw new Error(`unsupported ${cmd}`);
    }
  };
  return { exec, keys: () => [...data.keys()] };
}

test("canary candidates are extracted by shape, bounded", () => {
  const a = "cnry_live_0123456789abcdef01234567";
  const b = "adm_sess_aaaaaaaaaaaaaaaaaaaaaaaa";
  assert.deepEqual(canaryCandidates(`key=${a}&x=${b} and junk_123`), [a, b]);
  const many = Array.from({ length: 50 }, (_, i) => `c${i}_${"a".repeat(24)}`).join(" ");
  assert.equal(canaryCandidates(many).length, 32);
});

test("scores expire, so a client flagged once is not flagged forever", () => {
  let now = 0;
  const engine = new Engine({
    rules: suspectOnScript,
    allowlist: new Map(),
    canaries: new CanaryRegistry({ now: () => now }),
    scoring: { decoyThreshold: 3, suspectPoints: 2, rateWindowMs: 10_000, rateMax: 40, scoreTtlMs: 60_000 },
    now: () => now,
  });
  engine.decide({ method: "POST", path: "/x", body: "<script>", clientId: "c" });
  engine.decide({ method: "POST", path: "/x", body: "<script>", clientId: "c" }); // score 4
  assert.equal(engine.decide({ method: "GET", path: "/x", clientId: "c" }).lane, "decoy", "still hot");
  now = 61_000;
  assert.equal(engine.decide({ method: "GET", path: "/x", clientId: "c" }).lane, "normal", "cooled off after TTL");
});

test("canaries expire after their TTL", () => {
  let now = 0;
  const reg = new CanaryRegistry({ ttlMs: 1000, now: () => now });
  const c = reg.mint("decoy");
  assert.ok(reg.detect(`k=${c.token}`));
  now = 2000;
  assert.equal(reg.detect(`k=${c.token}`), null);
});

test("the memory store is size-capped", () => {
  const s = new MemoryStateStore({ maxClients: 3, maxCanaries: 2 });
  for (let i = 0; i < 10; i++) s.addScore(`c${i}`, 1, 0, 60_000);
  assert.equal(s.getScore("c0", 0), 0, "oldest evicted");
  assert.equal(s.getScore("c9", 0), 1);
  for (let i = 0; i < 5; i++) s.putCanary(`t${i}`, "o", 0, 60_000);
  assert.equal(s.canaryCount, 2);
});

test("rate tracking saturates instead of growing without limit", () => {
  const s = new MemoryStateStore();
  let n = 0;
  for (let i = 0; i < 1000; i++) n = s.hit("c", i, 10_000, 40);
  assert.equal(n, 41, "bounded at cap + 1");
});

test("decide() refuses an async store rather than silently misbehaving", () => {
  const redis = new RedisStateStore(fakeRedis(() => 0).exec);
  const engine = new Engine({ rules: suspectOnScript, allowlist: new Map(), canaries: new CanaryRegistry(), state: redis });
  assert.throws(() => engine.decide({ method: "GET", path: "/x", clientId: "c" }), /decideAsync/);
});

test("two engines sharing a Redis store agree on scores and canaries", async () => {
  const clock = () => 1_000;
  const { exec, keys } = fakeRedis(clock);
  const shared = new RedisStateStore(exec, { prefix: "t:" });
  const mk = () =>
    new Engine({
      rules: suspectOnScript,
      allowlist: new Map(),
      canaries: new CanaryRegistry({ store: shared, now: clock }),
      state: shared,
      now: clock,
    });
  const a = mk();
  const b = mk();

  // Client gets suspicious on instance A...
  await a.decideAsync({ method: "POST", path: "/x", body: "<script>", clientId: "bot" });
  await a.decideAsync({ method: "POST", path: "/x", body: "<script>", clientId: "bot" });
  // ...and instance B already knows.
  assert.equal((await b.decideAsync({ method: "GET", path: "/x", clientId: "bot" })).lane, "decoy");

  // A canary planted by A is caught when replayed to B.
  const reg = new CanaryRegistry({ store: shared, now: clock });
  const c = reg.mint("decoy /admin");
  await new Promise((r) => setImmediate(r)); // let the async write land
  const d = await b.decideAsync({ method: "GET", path: "/api", query: `key=${c.token}`, clientId: "thief" });
  assert.equal(d.lane, "blocked");
  assert.equal(d.confidence, "CERTAIN");
  assert.ok(keys().every((k) => k.startsWith("t:")), "all keys use the configured prefix");
});

test("decideAsync gives identical results to decide on the memory store", async () => {
  const mk = () => new Engine({ rules: suspectOnScript, allowlist: new Map([["k", "p"]]), canaries: new CanaryRegistry(), now: () => 0 });
  const reqs = [
    { method: "GET", path: "/a", clientId: "u" },
    { method: "POST", path: "/a", body: "<script>", clientId: "u" },
    { method: "GET", path: "/a", identity: "k", clientId: "p" },
    { method: "GET", path: "/a", clientId: "u" },
  ];
  const sync = mk();
  const asyn = mk();
  for (const r of reqs) {
    const x = sync.decide(r);
    const y = await asyn.decideAsync(r);
    assert.deepEqual(y, x);
  }
});
