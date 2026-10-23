/**
 * HAR capture writer. ORDER records every request/response as a HAR 1.2 entry so the
 * session can be reconstructed offline by @order/reconstruct (which drives the REA
 * CLI). ORDER's live verdict rides along in a custom `_order` field, which REA
 * preserves. The HAR schema REA validates requires `cookies` arrays and, when
 * present, a `postData.mimeType` — both handled here.
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
  _order: { lane: string; confidence: string; reasons: readonly string[]; client?: string };
  cache: Record<string, never>;
  timings: { send: number; wait: number; receive: number };
}

export function toHarEntry(i: CaptureInput): HarEntry {
  const headers = Object.entries(i.reqHeaders).map(([name, value]) => ({ name, value }));
  const request: Record<string, unknown> = {
    method: i.method,
    url: i.url,
    httpVersion: "HTTP/1.1",
    cookies: [],
    headers,
    queryString: [],
    headersSize: -1,
    bodySize: i.reqBody.length,
  };
  if (i.reqBody) {
    request["postData"] = { mimeType: "application/json", text: i.reqBody };
  }
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
      content: { size: i.respBody.length, mimeType: "application/json", text: i.respBody },
      redirectURL: "",
      headersSize: -1,
      bodySize: i.respBody.length,
    },
    _order: {
      lane: i.decision.lane,
      confidence: i.decision.confidence,
      reasons: i.decision.reasons,
      ...(i.clientId !== undefined ? { client: i.clientId } : {}),
    },
    cache: {},
    timings: { send: 0, wait: i.waitedMs, receive: 0 },
  };
}

export interface HarRecorderOptions {
  /** Keep at most this many entries; the oldest are dropped first. Default 10,000. */
  maxEntries?: number;
}

/**
 * In-memory capture, bounded so a long-running gateway can't grow without limit.
 * For durable capture, export periodically with `toJSON()` (or stream entries from
 * `onDecision`) and `clear()`.
 */
export class HarRecorder {
  private entries: HarEntry[] = [];
  private readonly max: number;
  private droppedCount = 0;

  constructor(opts: HarRecorderOptions = {}) {
    this.max = Math.max(1, opts.maxEntries ?? 10_000);
  }

  add(entry: HarEntry): void {
    this.entries.push(entry);
    if (this.entries.length > this.max) {
      const excess = this.entries.length - this.max;
      this.entries.splice(0, excess);
      this.droppedCount += excess;
    }
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
