/**
 * HTTPS key-directory resolver (draft-ietf-webbotauth-httpsig-protocol, Sec. 5.5).
 *
 * Given a Signature-Agent origin, fetch
 *   https://<origin>/.well-known/http-message-signatures-directory
 * and return the Ed25519 key whose RFC 8037 thumbprint equals the request's keyid.
 *
 * What it enforces (MUST in the draft unless noted):
 *   - the agent value is an https origin, nothing else
 *   - status 200 only; redirects are never followed
 *   - media type application/http-message-signatures-directory+json
 *   - a JWKS body; any `kid` must equal the key's thumbprint, or the entry is dropped
 *   - SHOULD-level limits: response size, key count, wall-clock timeout, no private,
 *     loopback or link-local destinations (checked at connect time, see netguard.ts)
 *   - caching: Cache-Control max-age respected (capped); failures cached <= 5 minutes
 *
 * Not done (documented, not hidden): verifying the directory response's own signature.
 * The draft RECOMMENDS servers sign it; we fetch straight from the origin over TLS, which
 * authenticates the origin, so key material is never taken from a third party.
 */

import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import type { KeyResolver } from "./verify.js";
import { guardedLookup, isHttpsOrigin, isPrivateAddress, type LookupFn } from "./netguard.js";
import { ed25519Thumbprint, type JwkOkp } from "./thumbprint.js";

export const DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
export const DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json";

export interface TransportResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** Fetch one URL. Must not follow redirects. Injectable so the resolver is testable. */
export type Transport = (url: string, limits: { timeoutMs: number; maxBytes: number }) => Promise<TransportResponse>;

export interface DirectoryResolverOptions {
  transport?: Transport;
  timeoutMs?: number;
  maxBytes?: number;
  maxKeys?: number;
  /** Cache lifetime when the server sends no max-age. */
  defaultTtlSec?: number;
  /** Upper bound on any positive cache lifetime. */
  maxTtlSec?: number;
  /** Failure cache lifetime. The draft says no more than five minutes. */
  negativeTtlSec?: number;
  /**
   * Most directories cached at once. Origins come from unauthenticated requests, so the cache
   * is bounded: expired entries are dropped first, then the least recently used. Default 10,000.
   */
  maxEntries?: number;
  /** Most directory fetches in flight at once. Beyond this, lookups fail fast as unverified. Default 32. */
  maxConcurrent?: number;
  nowMs?: () => number;
}

/** "https://" + a DNS name (≤253) + ":65535". Longer origins are refused without any lookup. */
const MAX_ORIGIN_LENGTH = 8 + 253 + 6;

interface CacheEntry {
  expiresAt: number;
  keys: Map<string, JwkOkp> | null; // null = cached failure
  error?: string;
}

/** The real transport: node:https with the SSRF guard on every DNS resolution. */
export function httpsTransport(lookup?: LookupFn): Transport {
  return (url, { timeoutMs, maxBytes }) =>
    new Promise((resolve, reject) => {
      // Node skips the DNS lookup entirely for IP literals, so the guarded lookup never
      // runs for them. Check literal addresses here, before any socket is opened.
      let host: string;
      try {
        const u = new URL(url);
        if (u.protocol !== "https:") return reject(new Error("directory must be fetched over https"));
        host = u.hostname.replace(/^\[|\]$/g, "");
      } catch {
        return reject(new Error("invalid directory URL"));
      }
      if (isIP(host) && isPrivateAddress(host)) {
        return reject(Object.assign(new Error(`refusing to connect to non-public address ${host}`), { code: "EPRIVATE" }));
      }
      const req = httpsRequest(
        url,
        {
          method: "GET",
          headers: { accept: DIRECTORY_MEDIA_TYPE, "accept-encoding": "identity" },
          lookup: guardedLookup(lookup) as never,
          timeout: timeoutMs,
        },
        (res) => {
          const enc = String(res.headers["content-encoding"] ?? "identity").toLowerCase();
          if (enc !== "identity") {
            res.destroy();
            return reject(new Error(`unexpected content-encoding ${enc}`));
          }
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (c: Buffer) => {
            size += c.length;
            if (size > maxBytes) {
              res.destroy();
              reject(new Error(`directory exceeds ${maxBytes} bytes`));
              return;
            }
            chunks.push(c);
          });
          res.on("end", () => {
            const headers: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (v !== undefined) headers[k] = Array.isArray(v) ? v.join(", ") : v;
            }
            resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks).toString("utf8") });
          });
          res.on("error", reject);
        },
      );
      const wall = setTimeout(() => req.destroy(new Error(`directory fetch exceeded ${timeoutMs}ms`)), timeoutMs);
      req.on("timeout", () => req.destroy(new Error(`directory fetch exceeded ${timeoutMs}ms`)));
      req.on("error", (e) => {
        clearTimeout(wall);
        reject(e);
      });
      req.on("close", () => clearTimeout(wall));
      req.end();
    });
}

function maxAge(cacheControl: string | undefined): number | null {
  if (!cacheControl) return null;
  if (/\b(no-store|no-cache)\b/i.test(cacheControl)) return 0;
  const m = /max-age\s*=\s*(\d+)/i.exec(cacheControl);
  return m ? Number(m[1]) : null;
}

const B64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/;

/** Parse and validate a directory body into thumbprint -> key. Throws on malformed sets. */
export function parseDirectory(body: string, maxKeys: number, nowSec: number): Map<string, JwkOkp> {
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    throw new Error("directory is not valid JSON");
  }
  const keys = (json as { keys?: unknown })?.keys;
  if (!Array.isArray(keys)) throw new Error("directory has no keys array");
  if (keys.length > maxKeys) throw new Error(`directory has ${keys.length} keys (limit ${maxKeys})`);

  const out = new Map<string, JwkOkp>();
  for (const k of keys as Record<string, unknown>[]) {
    // Only Ed25519 is verified by this package; other key types are skipped, not fatal.
    if (k?.["kty"] !== "OKP" || k["crv"] !== "Ed25519" || typeof k["x"] !== "string") continue;
    if (!B64URL_32_BYTES.test(k["x"])) continue;
    const jwk: JwkOkp = { kty: "OKP", crv: "Ed25519", x: k["x"] };
    const tp = ed25519Thumbprint(jwk);
    if (k["kid"] !== undefined && k["kid"] !== tp) continue; // kid MUST equal the thumbprint
    if (typeof k["nbf"] === "number" && nowSec < k["nbf"]) continue;
    if (typeof k["exp"] === "number" && nowSec >= k["exp"]) continue;
    out.set(tp, jwk);
  }
  return out;
}

export class HttpsDirectoryResolver implements KeyResolver {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inflight = new Map<string, Promise<CacheEntry>>();
  private active = 0;
  private readonly transport: Transport;
  private readonly o: Required<Omit<DirectoryResolverOptions, "transport">>;

  constructor(opts: DirectoryResolverOptions = {}) {
    this.transport = opts.transport ?? httpsTransport();
    this.o = {
      timeoutMs: opts.timeoutMs ?? 2_000,
      maxBytes: opts.maxBytes ?? 64 * 1024,
      maxKeys: opts.maxKeys ?? 16,
      defaultTtlSec: opts.defaultTtlSec ?? 3_600,
      maxTtlSec: opts.maxTtlSec ?? 86_400,
      negativeTtlSec: Math.min(opts.negativeTtlSec ?? 300, 300),
      maxEntries: Math.max(1, opts.maxEntries ?? 10_000),
      maxConcurrent: Math.max(1, opts.maxConcurrent ?? 32),
      nowMs: opts.nowMs ?? Date.now,
    };
  }

  async resolve(agentOrigin: string, keyid: string): Promise<JwkOkp | null> {
    if (agentOrigin.length > MAX_ORIGIN_LENGTH || !isHttpsOrigin(agentOrigin)) return null;
    const entry = await this.directory(agentOrigin);
    if (!entry.keys) throw new Error(entry.error ?? "directory unavailable");
    return entry.keys.get(keyid) ?? null;
  }

  private async directory(origin: string): Promise<CacheEntry> {
    const now = this.o.nowMs();
    const hit = this.cache.get(origin);
    if (hit && hit.expiresAt > now) {
      this.cache.delete(origin); // refresh LRU position
      this.cache.set(origin, hit);
      return hit;
    }

    const running = this.inflight.get(origin);
    if (running) return running;

    if (this.active >= this.o.maxConcurrent) throw new Error("directory fetch capacity exceeded");
    this.active++;
    const p = this.fetchDirectory(origin).finally(() => {
      this.active--;
      this.inflight.delete(origin);
    });
    this.inflight.set(origin, p);
    return p;
  }

  /** Store an entry, keeping the cache within maxEntries: expired first, then least recently used. */
  private remember(origin: string, entry: CacheEntry): void {
    this.cache.delete(origin);
    this.cache.set(origin, entry);
    if (this.cache.size <= this.o.maxEntries) return;
    const now = this.o.nowMs();
    for (const [k, v] of this.cache) {
      if (this.cache.size <= this.o.maxEntries) break;
      if (v.expiresAt <= now) this.cache.delete(k);
    }
    for (const k of this.cache.keys()) {
      if (this.cache.size <= this.o.maxEntries) break;
      this.cache.delete(k);
    }
  }

  /** Number of directories currently cached (bounded by maxEntries). */
  get cachedOrigins(): number {
    return this.cache.size;
  }

  private async fetchDirectory(origin: string): Promise<CacheEntry> {
    const now = this.o.nowMs();
    const fail = (error: string): CacheEntry => {
      const e: CacheEntry = { expiresAt: now + this.o.negativeTtlSec * 1000, keys: null, error };
      this.remember(origin, e);
      return e;
    };
    let res: TransportResponse;
    try {
      res = await this.transport(`${origin}${DIRECTORY_PATH}`, { timeoutMs: this.o.timeoutMs, maxBytes: this.o.maxBytes });
    } catch {
      return fail("fetch failed"); // fixed text: the transport message repeats the attacker's host
    }
    if (res.status !== 200) return fail(`status ${res.status} (only 200 is accepted; redirects are not followed)`);
    const mediaType = (res.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase();
    if (mediaType !== DIRECTORY_MEDIA_TYPE) return fail(`unexpected content-type ${mediaType || "(none)"}`);
    if (Buffer.byteLength(res.body) > this.o.maxBytes) return fail("directory too large");

    let keys: Map<string, JwkOkp>;
    try {
      keys = parseDirectory(res.body, this.o.maxKeys, Math.floor(now / 1000));
    } catch (e) {
      return fail((e as Error).message);
    }
    const age = maxAge(res.headers["cache-control"]);
    const ttl = Math.min(age ?? this.o.defaultTtlSec, this.o.maxTtlSec);
    const entry: CacheEntry = { expiresAt: now + ttl * 1000, keys };
    this.remember(origin, entry);
    return entry;
  }
}
