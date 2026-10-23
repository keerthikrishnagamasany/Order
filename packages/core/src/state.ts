/**
 * Pluggable state: per-client scores, rate windows, and planted canaries.
 *
 * One interface, two shapes of implementation:
 *   - synchronous (MemoryStateStore, the default) — works with `Engine.decide()`;
 *   - asynchronous (e.g. RedisStateStore) — shared across many gateway instances and
 *     survives restarts; use `Engine.decideAsync()`.
 *
 * Every entry expires and every in-memory table is size-capped, so a long-running gateway
 * can't grow without limit, and a client flagged once is not flagged forever.
 */

export type MaybePromise<T> = T | Promise<T>;

export interface StateStore {
  /** Record a request; return how many this client made within the window (may saturate). */
  hit(clientId: string, nowMs: number, windowMs: number, cap: number): MaybePromise<number>;
  /** Add points to a client's score, refreshing its expiry; return the new score. */
  addScore(clientId: string, points: number, nowMs: number, ttlMs: number): MaybePromise<number>;
  /** Current score (0 if unknown or expired). */
  getScore(clientId: string, nowMs: number): MaybePromise<number>;
  /** Remember a planted canary token. */
  putCanary(token: string, origin: string, nowMs: number, ttlMs: number): MaybePromise<void>;
  /** Look up a candidate token; return where it was planted, or null. */
  getCanary(token: string, nowMs: number): MaybePromise<string | null>;
}

interface Expiring<T> {
  value: T;
  expiresAt: number;
}

/** A Map with per-entry expiry and a hard size cap (oldest-touched evicted first). */
class BoundedMap<T> {
  private readonly m = new Map<string, Expiring<T>>();
  constructor(private readonly max: number) {}

  get(k: string, now: number): T | undefined {
    const e = this.m.get(k);
    if (!e) return undefined;
    if (e.expiresAt <= now) {
      this.m.delete(k);
      return undefined;
    }
    return e.value;
  }

  set(k: string, value: T, expiresAt: number): void {
    this.m.delete(k); // re-insert so it counts as most recently touched
    this.m.set(k, { value, expiresAt });
    while (this.m.size > this.max) {
      const oldest = this.m.keys().next().value as string;
      this.m.delete(oldest);
    }
  }

  get size(): number {
    return this.m.size;
  }
}

export interface MemoryStateOptions {
  /** Max clients tracked at once. Default 100,000. */
  maxClients?: number;
  /** Max canaries remembered at once. Default 100,000. */
  maxCanaries?: number;
}

/** The default, single-process store. Synchronous, bounded, expiring. */
export class MemoryStateStore implements StateStore {
  private readonly scores: BoundedMap<number>;
  private readonly hits: BoundedMap<number[]>;
  private readonly canaries: BoundedMap<string>;

  constructor(opts: MemoryStateOptions = {}) {
    const clients = opts.maxClients ?? 100_000;
    this.scores = new BoundedMap(clients);
    this.hits = new BoundedMap(clients);
    this.canaries = new BoundedMap(opts.maxCanaries ?? 100_000);
  }

  hit(clientId: string, nowMs: number, windowMs: number, cap: number): number {
    const cutoff = nowMs - windowMs;
    const list = (this.hits.get(clientId, nowMs) ?? []).filter((t) => t > cutoff);
    list.push(nowMs);
    // Keep at most cap+1 timestamps: enough to tell "over the limit", bounded memory.
    while (list.length > cap + 1) list.shift();
    this.hits.set(clientId, list, nowMs + windowMs);
    return list.length;
  }

  addScore(clientId: string, points: number, nowMs: number, ttlMs: number): number {
    const next = (this.scores.get(clientId, nowMs) ?? 0) + points;
    this.scores.set(clientId, next, nowMs + ttlMs);
    return next;
  }

  getScore(clientId: string, nowMs: number): number {
    return this.scores.get(clientId, nowMs) ?? 0;
  }

  putCanary(token: string, origin: string, nowMs: number, ttlMs: number): void {
    this.canaries.set(token, origin, nowMs + ttlMs);
  }

  getCanary(token: string, nowMs: number): string | null {
    return this.canaries.get(token, nowMs) ?? null;
  }

  /** Number of canaries currently remembered (for tests/metrics). */
  get canaryCount(): number {
    return this.canaries.size;
  }
}

/**
 * Minimal Redis command function. Works with any client:
 *   node-redis: (args) => client.sendCommand(args)
 *   ioredis:    (args) => client.call(args[0], ...args.slice(1))
 */
export type RedisExec = (args: string[]) => Promise<unknown>;

export interface RedisStateOptions {
  /** Key prefix, so ORDER can share a Redis with other apps. Default "order:". */
  prefix?: string;
}

/**
 * Shared state in Redis, so several gateway instances see the same scores and canaries,
 * and nothing is lost on restart. Rate counting uses fixed windows (one counter per client
 * per window), which is cheap and close enough for bot scoring.
 */
export class RedisStateStore implements StateStore {
  private readonly p: string;
  constructor(
    private readonly exec: RedisExec,
    opts: RedisStateOptions = {},
  ) {
    this.p = opts.prefix ?? "order:";
  }

  async hit(clientId: string, nowMs: number, windowMs: number): Promise<number> {
    const key = `${this.p}hits:${clientId}:${Math.floor(nowMs / windowMs)}`;
    const n = Number(await this.exec(["INCR", key]));
    if (n === 1) await this.exec(["PEXPIRE", key, String(windowMs * 2)]);
    return n;
  }

  async addScore(clientId: string, points: number, _nowMs: number, ttlMs: number): Promise<number> {
    const key = `${this.p}score:${clientId}`;
    const n = Number(await this.exec(["INCRBY", key, String(points)]));
    await this.exec(["PEXPIRE", key, String(ttlMs)]);
    return n;
  }

  async getScore(clientId: string): Promise<number> {
    const v = await this.exec(["GET", `${this.p}score:${clientId}`]);
    return v == null ? 0 : Number(v);
  }

  async putCanary(token: string, origin: string, _nowMs: number, ttlMs: number): Promise<void> {
    await this.exec(["SET", `${this.p}canary:${token}`, origin, "PX", String(ttlMs)]);
  }

  async getCanary(token: string): Promise<string | null> {
    const v = await this.exec(["GET", `${this.p}canary:${token}`]);
    return v == null ? null : String(v);
  }
}

/** True if a store's method returned a Promise (i.e. the store is asynchronous). */
export function isPromise<T>(v: MaybePromise<T>): v is Promise<T> {
  return typeof (v as { then?: unknown })?.then === "function";
}
