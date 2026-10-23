/**
 * Canary tokens. ORDER's one source of CERTAINTY.
 *
 * Canaries are planted ONLY in decoy responses. They exist nowhere a legitimate client
 * could obtain them. So if a client ever presents one back to the platform, that client
 * provably scraped a decoy — not an inference, a fact. This is the only marker ORDER
 * treats as CERTAIN compromise.
 *
 * Tokens have a fixed shape, `<prefix>_<24 hex chars>`, so detection extracts the few
 * candidate tokens from a request and looks each one up, instead of scanning the request
 * for every token ever planted. Cost stays flat no matter how many canaries exist.
 */

import { randomBytes } from "node:crypto";
import { isPromise, MemoryStateStore, type MaybePromise, type StateStore } from "./state.js";

export interface Canary {
  readonly token: string;
  readonly origin: string; // where it was planted, e.g. "decoy /.env key"
}

export interface CanaryOptions {
  /** Where tokens are remembered. Default: a private in-memory store. */
  store?: StateStore;
  /** How long a planted token stays detectable. Default 7 days. */
  ttlMs?: number;
  now?: () => number;
}

const TOKEN_TAIL = /_[0-9a-f]{24}$/;
const MAX_CANDIDATES = 32;

/** Pull candidate canary tokens out of arbitrary text (bounded). */
export function canaryCandidates(text: string): string[] {
  const out: string[] = [];
  for (const word of text.match(/[A-Za-z0-9_]+/g) ?? []) {
    if (TOKEN_TAIL.test(word)) {
      out.push(word);
      if (out.length >= MAX_CANDIDATES) break;
    }
  }
  return out;
}

export class CanaryRegistry {
  readonly store: StateStore;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private minted = 0;

  constructor(opts: CanaryOptions = {}) {
    this.store = opts.store ?? new MemoryStateStore();
    this.ttlMs = opts.ttlMs ?? 7 * 24 * 60 * 60 * 1000;
    this.now = opts.now ?? Date.now;
  }

  /** Mint a canary for a given decoy origin and remember it. Prefix must be [A-Za-z0-9_]. */
  mint(origin: string, prefix = "cnry"): Canary {
    const safe = prefix.replace(/[^A-Za-z0-9_]/g, "") || "cnry";
    const token = `${safe}_${randomBytes(12).toString("hex")}`;
    const r = this.store.putCanary(token, origin, this.now(), this.ttlMs);
    if (isPromise(r)) r.catch(() => undefined); // async stores: fire-and-forget
    this.minted++;
    return { token, origin };
  }

  /** Synchronous detection. Requires a synchronous store (the default). */
  detect(presented: string): { token: string; origin: string } | null {
    const now = this.now();
    for (const token of canaryCandidates(presented)) {
      const origin = this.store.getCanary(token, now);
      if (isPromise(origin)) throw new Error("CanaryRegistry.detect() needs a synchronous store; use detectAsync()");
      if (origin !== null) return { token, origin };
    }
    return null;
  }

  /** Detection for any store, including asynchronous ones like Redis. */
  async detectAsync(presented: string): Promise<{ token: string; origin: string } | null> {
    const now = this.now();
    for (const token of canaryCandidates(presented)) {
      const origin: MaybePromise<string | null> = this.store.getCanary(token, now);
      const v = await origin;
      if (v !== null) return { token, origin: v };
    }
    return null;
  }

  /** Canaries minted by this registry instance. */
  get size(): number {
    return this.minted;
  }
}
