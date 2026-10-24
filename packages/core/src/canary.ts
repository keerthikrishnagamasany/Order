/**
 * Canary tokens. ORDER's one source of CERTAINTY.
 *
 * Canaries are planted ONLY in decoy responses. They exist nowhere a legitimate client
 * could obtain them. So if a client ever presents one back to the platform, that client
 * provably scraped a decoy — not an inference, a fact. This is the only marker ORDER
 * treats as CERTAIN compromise.
 *
 * Tokens have a fixed shape, `<prefix>_<24 hex chars>`. The 24 hex chars are the issue time
 * (8), a random nonce (4) and a truncated HMAC over prefix, time and nonce (12), keyed by a
 * registry secret. The nonce keeps every token unique, so a leak traces back to one decoy. So a
 * registry recognises its own canaries by recomputing the HMAC: no lookup, nothing stored,
 * nothing an attacker can evict by flooding decoys. Registries that share a `secret` (e.g.
 * several gateway instances) recognise each other's canaries. Without a shared secret, minted
 * tokens are also written to the state store, so instances sharing a store (Redis) still agree.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { isPromise, MemoryStateStore, type StateStore } from "./state.js";

export interface Canary {
  readonly token: string;
  readonly origin: string; // where it was planted, e.g. "decoy /.env key"
}

export interface CanaryOptions {
  /**
   * HMAC key that makes canaries self-verifying. Give every instance the same secret (at least
   * 32 random bytes, kept private) so they recognise each other's canaries without shared
   * storage, and so canaries survive restarts. Default: a random per-instance secret.
   */
  secret?: string | Uint8Array;
  /**
   * Where minted tokens are also remembered when no `secret` is configured, so instances that
   * share a store can recognise each other's canaries. Default: a private in-memory store.
   */
  store?: StateStore;
  /** How long a planted token stays detectable. Default 7 days. */
  ttlMs?: number;
  now?: () => number;
}

export interface CanaryScan {
  hit: { token: string; origin: string } | null;
  /** True when the input held more canary-shaped words than are checked, so a hit may have been missed. */
  overflow: boolean;
}

const TOKEN_TAIL = /_[0-9a-f]{24}$/;
const MAX_CANDIDATES = 32;
/** Canary-shaped words verified per request. HMAC checks are cheap and local. */
const MAX_VERIFIED = 1024;
/** Canary-shaped words looked up in the (possibly remote) store per request. */
const MAX_STORE_LOOKUPS = 32;
const MAX_ORIGINS = 256;
/** Per-token origin labels kept for attribution (labels only; detection never needs them). */
const MAX_TOKEN_LABELS = 10_000;

/** Pull candidate canary tokens out of arbitrary text, up to `limit`. Stops scanning early. */
export function canaryCandidates(text: string, limit = MAX_CANDIDATES): string[] {
  return scanCandidates(text, limit).tokens;
}

/** Candidates up to `limit`, and whether more exist (scans at most one word past the limit). */
function scanCandidates(text: string, limit: number): { tokens: string[]; more: boolean } {
  const tokens: string[] = [];
  const word = /[A-Za-z0-9_]{26,}/g;
  for (let m = word.exec(text); m !== null; m = word.exec(text)) {
    if (!TOKEN_TAIL.test(m[0])) continue;
    if (tokens.length >= limit) return { tokens, more: true };
    tokens.push(m[0]);
  }
  return { tokens, more: false };
}

/**
 * Text variants a replayed canary can hide in: JSON `\uXXXX` escapes and base64 (e.g. HTTP Basic
 * credentials, which a Stripe-style `sk_live_` key is normally sent as).
 */
export function canaryScanText(text: string): string {
  const unescaped = text.includes("\\u")
    ? text.replace(/\\u([0-9a-fA-F]{4})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
    : text;
  const extra: string[] = [];
  for (const m of text.matchAll(/(?:^|[\s:=,"'])([A-Za-z0-9+/]{36,}={0,2})(?=$|[\s,;"'&])/g)) {
    if (extra.length >= 16) break;
    try {
      const d = Buffer.from(m[1] as string, "base64").toString("latin1");
      if (/_[0-9a-f]{24}/.test(d)) extra.push(d);
    } catch {
      /* not base64 */
    }
  }
  return extra.length ? `${unescaped} ${extra.join(" ")}` : unescaped;
}

export class CanaryRegistry {
  readonly store: StateStore;
  private readonly secret: Buffer;
  private readonly sharedSecret: boolean;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private readonly origins = new Map<string, string>(); // prefix -> latest origin (fallback label)
  private readonly labels = new Map<string, string>(); // token -> origin, bounded, attribution only
  private minted = 0;

  constructor(opts: CanaryOptions = {}) {
    this.store = opts.store ?? new MemoryStateStore();
    this.sharedSecret = opts.secret !== undefined;
    this.secret = opts.secret !== undefined ? Buffer.from(opts.secret) : randomBytes(32);
    if (this.secret.length < 16) throw new Error("canary secret must be at least 16 bytes");
    this.ttlMs = opts.ttlMs ?? 7 * 24 * 60 * 60 * 1000;
    this.now = opts.now ?? Date.now;
  }

  private mac(prefix: string, issuedHex: string, nonceHex: string): string {
    return createHmac("sha256", this.secret).update(`${prefix}|${issuedHex}|${nonceHex}`).digest("hex").slice(0, 12);
  }

  /** Mint a canary for a given decoy origin. Prefix must be [A-Za-z0-9_]. */
  mint(origin: string, prefix = "cnry"): Canary {
    const safe = prefix.replace(/[^A-Za-z0-9_]/g, "") || "cnry";
    const issuedHex = (Math.floor(this.now() / 1000) >>> 0).toString(16).padStart(8, "0");
    const nonceHex = randomBytes(2).toString("hex");
    const token = `${safe}_${issuedHex}${nonceHex}${this.mac(safe, issuedHex, nonceHex)}`;
    if (this.origins.has(safe) || this.origins.size < MAX_ORIGINS) this.origins.set(safe, origin);
    this.labels.set(token, origin);
    if (this.labels.size > MAX_TOKEN_LABELS) this.labels.delete(this.labels.keys().next().value as string);
    if (!this.sharedSecret) {
      const r = this.store.putCanary(token, origin, this.now(), this.ttlMs);
      if (isPromise(r)) Promise.resolve(r).catch(() => undefined); // async stores: fire-and-forget
    }
    this.minted++;
    return { token, origin };
  }

  /** Verify a token's HMAC and age. Returns its origin label, or null. */
  private verify(token: string): string | null {
    const cut = token.length - 25; // "_" + 24 hex
    if (cut < 1) return null;
    const prefix = token.slice(0, cut);
    const issuedHex = token.slice(cut + 1, cut + 9);
    const nonceHex = token.slice(cut + 9, cut + 13);
    const mac = Buffer.from(token.slice(cut + 13), "utf8");
    const want = Buffer.from(this.mac(prefix, issuedHex, nonceHex), "utf8");
    if (mac.length !== want.length || !timingSafeEqual(mac, want)) return null;
    const ageMs = this.now() - parseInt(issuedHex, 16) * 1000;
    if (ageMs < -60_000 || ageMs > this.ttlMs) return null;
    return this.labels.get(token) ?? this.origins.get(prefix) ?? `canary ${prefix}`;
  }

  private localScan(presented: string): { hit: CanaryScan["hit"]; overflow: boolean; candidates: string[] } {
    const { tokens, more } = scanCandidates(canaryScanText(presented), MAX_VERIFIED);
    for (const token of tokens) {
      const origin = this.verify(token);
      if (origin !== null) return { hit: { token, origin }, overflow: false, candidates: tokens };
    }
    // Store lookups (no shared secret) go to prefixes this registry minted first.
    const known = tokens.filter((t) => this.origins.has(t.slice(0, t.length - 25)));
    const rest = tokens.filter((t) => !this.origins.has(t.slice(0, t.length - 25)));
    return { hit: null, overflow: more, candidates: [...known, ...rest] };
  }

  /** Synchronous scan. Store fallback requires a synchronous store (the default). */
  scan(presented: string): CanaryScan {
    const local = this.localScan(presented);
    if (local.hit || this.sharedSecret) return { hit: local.hit, overflow: local.overflow };
    const now = this.now();
    for (const token of local.candidates.slice(0, MAX_STORE_LOOKUPS)) {
      const origin = this.store.getCanary(token, now);
      if (isPromise(origin)) throw new Error("CanaryRegistry.scan() needs a synchronous store; use scanAsync()");
      if (origin !== null) return { hit: { token, origin }, overflow: false };
    }
    return { hit: null, overflow: local.overflow };
  }

  /** Scan for any store, including asynchronous ones like Redis. */
  async scanAsync(presented: string): Promise<CanaryScan> {
    const local = this.localScan(presented);
    if (local.hit || this.sharedSecret) return { hit: local.hit, overflow: local.overflow };
    const now = this.now();
    for (const token of local.candidates.slice(0, MAX_STORE_LOOKUPS)) {
      const origin = await this.store.getCanary(token, now);
      if (origin !== null) return { hit: { token, origin }, overflow: false };
    }
    return { hit: null, overflow: local.overflow };
  }

  /** Synchronous detection. */
  detect(presented: string): { token: string; origin: string } | null {
    return this.scan(presented).hit;
  }

  /** Detection for any store, including asynchronous ones like Redis. */
  async detectAsync(presented: string): Promise<{ token: string; origin: string } | null> {
    return (await this.scanAsync(presented)).hit;
  }

  /** Canaries minted by this registry instance. */
  get size(): number {
    return this.minted;
  }
}
