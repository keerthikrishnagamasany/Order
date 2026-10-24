/**
 * Input normalisation. The single most important defensive step.
 *
 * Detectors match decoded text. If they run on raw percent-encoded input, an
 * attacker slips `%27` (a quote) or `%2F` (a slash) straight past them — the
 * classic WAF-evasion gap. We decode recursively (bounded) to also defeat
 * double-encoding like `%2527`.
 *
 * Decoding is lenient: each run of valid `%XX` escapes is decoded on its own, so one
 * malformed escape elsewhere (`&z=%`) can never switch decoding off for the rest of the
 * input. Runs that are not valid UTF-8 are decoded byte-wise.
 */

const MAX_ROUNDS = 3;

/**
 * Default inspection budget, in characters, for one decoded query or body. Matches the gateway's
 * default 1 MiB body cap, so everything the gateway accepts is inspected. The reference rules are
 * linear: about 7-15 ms per MiB.
 */
export const DEFAULT_INSPECTION_LIMIT = 1024 * 1024;

function decodeRun(run: string): string {
  try {
    return decodeURIComponent(run);
  } catch {
    return run.replace(/%([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  }
}

function decodeOnce(text: string, plusIsSpace: boolean): string {
  const t = plusIsSpace ? text.replace(/\+/g, " ") : text;
  return t.replace(/(?:%[0-9a-fA-F]{2})+/g, decodeRun);
}

/**
 * Recursively URL-decode until stable or the round budget is spent. Valid escapes are always
 * decoded; malformed ones are kept literally. `+` means space in query strings and form
 * bodies, but not in paths.
 */
export function urlDecodeDeep(input: string, rounds = MAX_ROUNDS, plusIsSpace = true): string {
  let text = input;
  for (let i = 0; i < rounds; i++) {
    const decoded = decodeOnce(text, plusIsSpace);
    if (decoded === text) break;
    text = decoded;
  }
  return text;
}

export interface Normalised {
  /** Decoded text, cut to the inspection limit. What detectors see. */
  text: string;
  /** The whole decoded text. Used for cheap, bounded scans such as canary lookup. */
  full: string;
  /** True when `full` was longer than the limit, so part of the input went uninspected. */
  truncated: boolean;
}

/** Decode, strip null bytes and apply the inspection limit, reporting whether anything was cut. */
export function normaliseWithInfo(input: string | undefined, maxLen = DEFAULT_INSPECTION_LIMIT): Normalised {
  if (!input) return { text: "", full: "", truncated: false };
  const full = urlDecodeDeep(input).replace(/\u0000/g, "");
  const truncated = full.length > maxLen;
  return { text: truncated ? full.slice(0, maxLen) : full, full, truncated };
}

/** Normalise a request component for detection. Prefer `normaliseWithInfo`, which reports truncation. */
export function normalise(input: string | undefined, maxLen = DEFAULT_INSPECTION_LIMIT): string {
  return normaliseWithInfo(input, maxLen).text;
}

/** Remove `.` and `..` segments (RFC 3986 §5.2.4) from an already-decoded path. */
function removeDotSegments(path: string): string {
  const out: string[] = [];
  const segs = path.replace(/\\/g, "/").split("/");
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i] as string;
    if (s === "..") out.pop();
    else if (s !== ".") out.push(s);
    else if (i === segs.length - 1) out.push("");
  }
  if (segs[segs.length - 1] === "..") out.push("");
  const joined = out.join("/");
  return joined.startsWith("/") ? joined : `/${joined}`;
}

/**
 * Normalise a URL path for matching: percent-decode (no `+` rule), strip null bytes, then resolve
 * dot segments, so `/x/..%2f.env` and `/%2e%2e/.env` are judged as the path an upstream that
 * decodes and normalises would serve.
 */
export function normalisePath(path: string): string {
  return removeDotSegments(urlDecodeDeep(path, MAX_ROUNDS, false).replace(/\u0000/g, ""));
}
