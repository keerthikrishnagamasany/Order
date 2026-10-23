/**
 * Minimal parsing of the three Structured-Field headers Web Bot Auth uses
 * (RFC 8941 + RFC 9421). This is intentionally scoped to what the verifier needs —
 * it is NOT a full RFC 8941 implementation — and it is strict: anything it cannot
 * parse cleanly yields null so the verifier can return "unverified" rather than guess.
 *
 *   Signature-Input: <label>=("@authority" "signature-agent";key="<label>");\
 *                    created=...;expires=...;keyid="...";alg="ed25519";tag="web-bot-auth"
 *   Signature:       <label>=:<base64>:
 *   Signature-Agent: <label>="https://directory.example"  (optional ;type="directory")
 */

export interface CoveredComponent {
  /** Component name, e.g. "@authority" or "signature-agent". */
  readonly name: string;
  /** Raw parameters as they appeared, e.g. ';key="sig"' (empty string if none). */
  readonly rawParams: string;
  /** Parsed key param value when present (for dictionary-member components). */
  readonly key?: string;
}

export interface SignatureInput {
  readonly label: string;
  readonly components: CoveredComponent[];
  /** The exact serialized value after `<label>=` — used verbatim for @signature-params. */
  readonly rawValue: string;
  readonly params: {
    created?: number;
    expires?: number;
    keyid?: string;
    alg?: string;
    tag?: string;
    nonce?: string;
  };
}

/** Split a dictionary header into `label -> rawValue` preserving the raw member text. */
function splitDictionary(header: string): Map<string, string> {
  const out = new Map<string, string>();
  // Members are comma-separated at the top level, but commas can appear inside
  // quoted strings and (parenthesised) inner lists, so scan with depth/quote state.
  let depth = 0;
  let inQuote = false;
  let start = 0;
  const members: string[] = [];
  for (let i = 0; i < header.length; i++) {
    const c = header[i];
    if (inQuote) {
      if (c === "\\") i++;
      else if (c === '"') inQuote = false;
      continue;
    }
    if (c === '"') inQuote = true;
    else if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === "," && depth === 0) {
      members.push(header.slice(start, i));
      start = i + 1;
    }
  }
  members.push(header.slice(start));
  for (const m of members) {
    const eq = m.indexOf("=");
    if (eq < 0) continue;
    const label = m.slice(0, eq).trim();
    const value = m.slice(eq + 1).trim();
    if (label) out.set(label, value);
  }
  return out;
}

function parseParams(raw: string): Record<string, string | number> {
  const params: Record<string, string | number> = {};
  // raw is a leading ';'-prefixed list, e.g. ;created=1;keyid="x";tag="web-bot-auth"
  const parts = raw.split(";").map((p) => p.trim()).filter(Boolean);
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq < 0) {
      params[p] = "";
      continue;
    }
    const k = p.slice(0, eq).trim();
    let v = p.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) {
      params[k] = v.slice(1, -1);
    } else if (/^-?\d+$/.test(v)) {
      params[k] = Number(v);
    } else {
      params[k] = v;
    }
  }
  return params;
}

/** Parse one labelled member of Signature-Input. Returns null on malformed input. */
export function parseSignatureInput(header: string, label?: string): SignatureInput | null {
  const dict = splitDictionary(header);
  const chosen = label ?? dict.keys().next().value;
  if (!chosen) return null;
  const rawValue = dict.get(chosen);
  if (rawValue === undefined) return null;

  // rawValue looks like: ("@authority" "signature-agent";key="sig");created=...;...
  const close = findInnerListClose(rawValue);
  if (close < 0) return null;
  const inner = rawValue.slice(1, close); // contents between ( and )
  const paramsRaw = rawValue.slice(close + 1); // everything after )

  const components = parseInnerList(inner);
  if (components === null) return null;

  const p = parseParams(paramsRaw);
  return {
    label: chosen,
    components,
    rawValue,
    params: {
      ...(typeof p["created"] === "number" ? { created: p["created"] } : {}),
      ...(typeof p["expires"] === "number" ? { expires: p["expires"] } : {}),
      ...(typeof p["keyid"] === "string" ? { keyid: p["keyid"] } : {}),
      ...(typeof p["alg"] === "string" ? { alg: p["alg"] } : {}),
      ...(typeof p["tag"] === "string" ? { tag: p["tag"] } : {}),
      ...(typeof p["nonce"] === "string" ? { nonce: p["nonce"] } : {}),
    },
  };
}

function findInnerListClose(s: string): number {
  if (s[0] !== "(") return -1;
  let inQuote = false;
  for (let i = 1; i < s.length; i++) {
    const c = s[i];
    if (inQuote) {
      if (c === "\\") i++;
      else if (c === '"') inQuote = false;
    } else if (c === '"') inQuote = true;
    else if (c === ")") return i;
  }
  return -1;
}

/** Parse the inner list `"@authority" "signature-agent";key="sig"` into components. */
function parseInnerList(inner: string): CoveredComponent[] | null {
  const comps: CoveredComponent[] = [];
  let i = 0;
  const n = inner.length;
  while (i < n) {
    while (i < n && inner[i] === " ") i++;
    if (i >= n) break;
    if (inner[i] !== '"') return null; // component names are quoted strings
    let j = i + 1;
    while (j < n && inner[j] !== '"') {
      if (inner[j] === "\\") j++;
      j++;
    }
    if (j >= n) return null;
    const name = inner.slice(i + 1, j);
    // params follow until the next space that is not inside quotes
    let k = j + 1;
    let inQuote = false;
    while (k < n) {
      const c = inner[k];
      if (inQuote) {
        if (c === "\\") k++;
        else if (c === '"') inQuote = false;
      } else if (c === '"') inQuote = true;
      else if (c === " ") break;
      k++;
    }
    const rawParams = inner.slice(j + 1, k);
    const keyMatch = /;key="([^"]*)"/.exec(rawParams);
    comps.push({
      name,
      rawParams,
      ...(keyMatch ? { key: keyMatch[1] } : {}),
    });
    i = k;
  }
  return comps;
}

/** Parse the Signature header member into raw signature bytes. Returns null if absent. */
export function parseSignature(header: string, label: string): Uint8Array | null {
  const dict = splitDictionary(header);
  const v = dict.get(label);
  if (!v) return null;
  // Byte sequence: :base64:
  if (!(v.startsWith(":") && v.endsWith(":"))) return null;
  const b64 = v.slice(1, -1);
  try {
    return new Uint8Array(Buffer.from(b64, "base64"));
  } catch {
    return null;
  }
}

/** Parse the Signature-Agent header member into { url, type }. Returns null if absent. */
export function parseSignatureAgent(
  header: string,
  label: string,
): { url: string; type: string; rawValue: string } | null {
  const dict = splitDictionary(header);
  const v = dict.get(label);
  if (v === undefined) {
    // Legacy bare-string form: Signature-Agent: "https://..."
    const bare = header.trim();
    if (bare.startsWith('"') && bare.endsWith('"')) {
      return { url: bare.slice(1, -1), type: "directory", rawValue: bare };
    }
    return null;
  }
  const strMatch = /^"([^"]*)"/.exec(v);
  if (!strMatch) return null;
  const typeMatch = /;type="([^"]*)"/.exec(v);
  return {
    url: strMatch[1] as string,
    type: typeMatch ? (typeMatch[1] as string) : "directory",
    rawValue: v,
  };
}
