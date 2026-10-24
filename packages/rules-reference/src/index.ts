/**
 * @order/rules-reference — the open, reference detector pack.
 *
 * These signatures are REAL and useful on their own: they catch the common,
 * well-known attack shapes a public-facing service sees every day. They are also
 * deliberately conservative — a miss is cheaper than blocking a real user — and,
 * being open, a determined attacker can read and evade them.
 *
 * That is the intended split. In production, load a PRIVATE pack (@order/rules-private)
 * that implements the same `RulePack` interface with tuned, non-public signatures.
 * The framework loads whatever pack you give it; see ARCHITECTURE.md ("Rules seam").
 */

import type { RequestFacts, RulePack, Severity, Signal } from "@order/core";

interface Matcher {
  readonly name: string;
  readonly severity: Severity;
  readonly where: "path" | "query" | "body";
  readonly rx: RegExp;
}

// --- paths only an attacker or scanner probes for --------------------------
const HARD_PATHS =
  /(^\/\.env\/?$|^\/\.git(\/|$)|^\/wp-login|^\/wp-admin|^\/phpmyadmin|^\/actuator(\/|$)|^\/server-status\/?$|\/config\.(json|ya?ml|php)$|\.sql$|\.bak$|\/id_rsa$)/i;
const SUSPECT_PATHS = /(^\/admin(\/|$)|^\/debug|^\/internal|^\/metrics$)/i;

// --- payload shapes in query/body ------------------------------------------
const PAYLOAD: Matcher[] = [
  {
    name: "sql_injection",
    severity: "HARD",
    where: "query",
    rx: /(?:'|")\s*(?:or|and)\s+\d+\s*=\s*\d+|union(?:\s|\/\*[^*]*\*\/)+select|;\s*drop\s+table\s/i,
  },
  {
    name: "path_traversal",
    severity: "HARD",
    where: "query",
    rx: /(?:\.\.\/){2,}|\/etc\/passwd\b|\/proc\/self\//i,
  },
  {
    name: "xss",
    severity: "SUSPECT",
    where: "query",
    rx: /<script\b|javascript:\s*\w|onerror\s*=\s*['"]?\w/i,
  },
  {
    name: "prompt_injection",
    severity: "SUSPECT",
    where: "body",
    rx: /ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:your|the|all)\s+(?:rules|instructions|guidelines)|reveal\s+(?:your|the)\s+(?:system\s+prompt|instructions|api\s*keys?|secrets?)|you\s+are\s+now\s+(?:a|an|in)\b/i,
  },
  {
    name: "ssrf_probe",
    severity: "SUSPECT",
    where: "query",
    rx: /(?:https?:\/\/)?(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost)\b/i,
  },
];

// --- scanner / automation fingerprints in the User-Agent -------------------
const SCANNER_UA =
  /\b(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nuclei|zgrab)\b|^(curl\/|python-requests\/|go-http-client)/i;

function clip(s: string, n = 80): string {
  return s.length > n ? s.slice(0, n) : s;
}

export const referenceRules: RulePack = {
  id: "reference@0.1.0",
  inspect(facts: RequestFacts): Signal[] {
    const out: Signal[] = [];

    // path reputation
    if (HARD_PATHS.test(facts.path)) {
      out.push({ name: "suspicious_path", severity: "HARD", where: "path", excerpt: clip(facts.path) });
    } else if (SUSPECT_PATHS.test(facts.path)) {
      out.push({ name: "sensitive_path", severity: "SUSPECT", where: "path", excerpt: clip(facts.path) });
    }

    // payloads — each matcher is checked against both query and body
    for (const m of PAYLOAD) {
      for (const [where, text] of [
        ["query", facts.query],
        ["body", facts.body],
      ] as const) {
        if (!text) continue;
        const hit = m.rx.exec(text);
        if (hit) {
          out.push({ name: m.name, severity: m.severity, where, excerpt: clip(hit[0]) });
          break; // one signal per matcher is enough evidence
        }
      }
    }

    // user-agent fingerprint
    if (facts.userAgent) {
      const hit = SCANNER_UA.exec(facts.userAgent);
      if (hit) {
        out.push({
          name: "scanner_user_agent",
          severity: "SUSPECT",
          where: "header",
          excerpt: clip(hit[0], 40),
        });
      }
    }

    return out;
  },
};

export default referenceRules;
