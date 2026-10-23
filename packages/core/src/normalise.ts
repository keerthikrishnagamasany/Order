/**
 * Input normalisation. The single most important defensive step.
 *
 * Detectors match decoded text. If they run on raw percent-encoded input, an
 * attacker slips `%27` (a quote) or `%2F` (a slash) straight past them — the
 * classic WAF-evasion gap. We decode recursively (bounded) to also defeat
 * double-encoding like `%2527`, then collapse a few common obfuscations.
 */

const MAX_ROUNDS = 3;

/** Recursively URL-decode until stable or the round budget is spent. */
export function urlDecodeDeep(input: string, rounds = MAX_ROUNDS): string {
  let text = input;
  for (let i = 0; i < rounds; i++) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(text.replace(/\+/g, " "));
    } catch {
      // Malformed escape — treat the raw text as the decoded form.
      return text;
    }
    if (decoded === text) break;
    text = decoded;
  }
  return text;
}

/** Normalise a request component for detection: decode, lowercase-fold nothing
 *  (detectors are case-insensitive themselves), strip null bytes, bound length. */
export function normalise(input: string | undefined, maxLen = 8192): string {
  if (!input) return "";
  const decoded = urlDecodeDeep(input);
  const noNull = decoded.replace(/\u0000/g, "");
  return noNull.length > maxLen ? noNull.slice(0, maxLen) : noNull;
}
