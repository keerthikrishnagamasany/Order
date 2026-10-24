/**
 * HAR capture writer. ORDER records every request/response as a HAR 1.2 entry so the
 * session can be reconstructed offline by @order/reconstruct (which drives the REA
 * CLI). ORDER's live verdict rides along in a custom `_order` field, which REA
 * preserves. The HAR schema REA validates requires `cookies` arrays and, when
 * present, a `postData.mimeType` — both handled here.
 *
 * Captures are minimised by default: credential headers are redacted, query values and
 * request bodies are dropped, and memory is bounded by both an entry count and a byte budget.
 */

import type { Decision } from "./types.js";

export interface CaptureInput {
  startedISO: string;
  waitedMs: number;
  method: string;
  url: string;
  reqHeaders: Record<string, string>;
  reqBody: string;
  status: number;
  respBody: string;
  decision: Decision;
  /** Stable client id (source IP + identity in prod). Makes the HAR self-contained. */
  clientId?: string;
}

export interface HarEntry {
  startedDateTime: string;
  time: number;
  request: Record<string, unknown>;
  response: Record<string, unknown>;
  _order: { lane: string; confidence: string; reasons: readonly string[]; loci?: readonly string[]; client?: string; authorizedTest?: string };
  cache: Record<string, never>;
  timings: { send: number; wait: number; receive: number };
}

/**
 * Request headers whose values are kept in a capture. Every other header's value is replaced with
 * "[redacted]" (its name is kept), because custom credential headers (`x-auth-token`, `api-key`…)
 * are too varied to list.
 */
export const KEPT_HEADERS: ReadonlySet<string> = new Set([
  "host",
  "user-agent",
  "accept",
  "accept-language",
  "accept-encoding",
  "content-type",
  "content-length",
  "content-encoding",
  "connection",
  "x-sim-client",
  "signature-agent",
]);

/** Well-known credential headers. Always redacted, even if a caller adds them to the kept set. */
export const REDACTED_HEADERS: ReadonlySet<string> = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-mcp-key",
  "x-api-key",
  "signature",
  "signature-input",
]);

const REDACTED = "[redacted]";

/** What a capture may keep. The defaults keep only what offline reconstruction needs. */
export interface CapturePolicy {
  /** Keep request bodies. Default false: bodies often hold passwords and tokens. */
  includeBodies?: boolean;
  /** Keep query-string values. Default false: values are replaced with "[redacted]", names are kept. */
  includeQueryValues?: boolean;
  /** Longest request or response text kept per entry, in characters. Default 64 KiB. */
  maxBodyChars?: number;
}

function redactUrl(raw: string, keepValues: boolean): string {
  try {
    const u = new URL(raw);
    u.username = "";
    u.password = "";
    if (keepValues || !u.search) return u.toString();
    const out = new URLSearchParams();
    for (const k of u.searchParams.keys()) out.append(k, REDACTED);
    u.search = out.toString();
    return u.toString();
  } catch {
    const q = raw.indexOf("?");
    return q >= 0 ? `${raw.slice(0, q)}?${REDACTED}` : raw;
  }
}

const clip = (s: string, n: number): string => (s.length > n ? s.slice(0, n) : s);

/**
 * Build one HAR entry. Credential-bearing headers are always redacted. Query values and
 * request bodies are dropped unless the policy opts in, and kept text is capped per entry.
 * `bodySize` always records the original length, so reconstruction still sees sizes.
 */
export function toHarEntry(i: CaptureInput, policy: CapturePolicy = {}): HarEntry {
  const maxChars = Math.max(0, policy.maxBodyChars ?? 64 * 1024);
  const headers = Object.entries(i.reqHeaders).map(([name, value]) => ({
    name,
    value: KEPT_HEADERS.has(name.toLowerCase()) && !REDACTED_HEADERS.has(name.toLowerCase()) ? value : REDACTED,
  }));
  const request: Record<string, unknown> = {
    method: i.method,
    url: redactUrl(i.url, policy.includeQueryValues === true),
    httpVersion: "HTTP/1.1",
    cookies: [],
    headers,
    queryString: [],
    headersSize: -1,
    bodySize: i.reqBody.length,
  };
  if (i.reqBody && policy.includeBodies === true) {
    request["postData"] = { mimeType: "application/json", text: clip(i.reqBody, maxChars) };
  }
  const respText = clip(i.respBody, maxChars);
  return {
    startedDateTime: i.startedISO,
    time: i.waitedMs,
    request,
    response: {
      status: i.status,
      statusText: "",
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers: [{ name: "Content-Type", value: "application/json" }],
      content: { size: i.respBody.length, mimeType: "application/json", text: respText },
      redirectURL: "",
      headersSize: -1,
      bodySize: i.respBody.length,
    },
    _order: {
      lane: i.decision.lane,
      confidence: i.decision.confidence,
      reasons: i.decision.reasons,
      loci: i.decision.signals.map((s) => s.where),
      ...(i.clientId !== undefined ? { client: i.clientId } : {}),
      ...(i.decision.authorizedTest !== undefined ? { authorizedTest: i.decision.authorizedTest } : {}),
    },
    cache: {},
    timings: { send: 0, wait: i.waitedMs, receive: 0 },
  };
}

/** Approximate retained size of an entry in bytes (JS strings are UTF-16). */
function entrySize(e: HarEntry): number {
  const req = (e.request ?? {}) as { url?: string; headers?: { name: string; value: string }[]; postData?: { text?: string } };
  const res = (e.response ?? {}) as { content?: { text?: string } };
  let chars = (req.url?.length ?? 0) + (req.postData?.text?.length ?? 0) + (res.content?.text?.length ?? 0);
  for (const h of req.headers ?? []) chars += h.name.length + h.value.length;
  for (const r of e._order?.reasons ?? []) chars += r.length;
  return 2 * chars + 512;
}

export interface HarRecorderOptions extends CapturePolicy {
  /** Keep at most this many entries; the oldest are dropped first. Default 10,000. */
  maxEntries?: number;
  /** Keep at most this many bytes of entries in memory; the oldest are dropped first. Default 64 MiB. */
  maxBytes?: number;
}

/**
 * In-memory capture, bounded so a long-running gateway can't grow without limit.
 * For durable capture, export periodically with `toJSON()` (or stream entries from
 * `onDecision`) and `clear()`.
 */
export class HarRecorder {
  private entries: HarEntry[] = [];
  private sizes: number[] = [];
  private bytes = 0;
  private readonly max: number;
  private readonly maxBytes: number;
  private droppedCount = 0;
  /** The capture policy entries recorded through `record()` follow. */
  readonly policy: CapturePolicy;

  constructor(opts: HarRecorderOptions = {}) {
    this.max = Math.max(1, opts.maxEntries ?? 10_000);
    this.maxBytes = Math.max(1, opts.maxBytes ?? 64 * 1024 * 1024);
    this.policy = {
      ...(opts.includeBodies !== undefined ? { includeBodies: opts.includeBodies } : {}),
      ...(opts.includeQueryValues !== undefined ? { includeQueryValues: opts.includeQueryValues } : {}),
      ...(opts.maxBodyChars !== undefined ? { maxBodyChars: opts.maxBodyChars } : {}),
    };
  }

  /** Build an entry under this recorder's policy and add it. */
  record(input: CaptureInput): void {
    this.add(toHarEntry(input, this.policy));
  }

  add(entry: HarEntry): void {
    const size = entrySize(entry);
    this.entries.push(entry);
    this.sizes.push(size);
    this.bytes += size;
    while (this.entries.length > this.max || (this.bytes > this.maxBytes && this.entries.length > 1)) {
      this.entries.shift();
      this.bytes -= this.sizes.shift() ?? 0;
      this.droppedCount++;
    }
  }

  /** Approximate bytes currently retained. */
  get retainedBytes(): number {
    return this.bytes;
  }

  get count(): number {
    return this.entries.length;
  }

  /** Entries discarded because the cap was reached. */
  get dropped(): number {
    return this.droppedCount;
  }

  clear(): void {
    this.entries = [];
    this.sizes = [];
    this.bytes = 0;
  }

  toJSON(): string {
    return JSON.stringify(
      {
        log: {
          version: "1.2",
          creator: { name: "ORDER", version: "0.4.0" },
          entries: this.entries,
        },
      },
      null,
      2,
    );
  }
}
