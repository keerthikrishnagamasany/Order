/**
 * Thin wrapper over the REA CLI (`rea`, the npm package `rea-agents`).
 *
 * REA parses a captured session into verifiable structure — endpoints touched, order,
 * and the sha256 of the exact artifact analysed — and never guesses: a pattern is a
 * hypothesis, not proof. That verifiable backbone is what makes ORDER's verdicts
 * auditable. REA runs OFFLINE here; it never sits in the request path.
 *
 * Install: `npm i -g rea-agents` (official: github.com/morluto/rea). If `rea` is not on
 * PATH, reconstruction degrades gracefully to the decision-log-only path.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

export interface ReaCaptureResult {
  evidenceId: string | undefined;
  totalRecords: number | undefined;
  artifact: { path?: string; sha256?: string } | undefined;
  raw: unknown;
}

export interface ReaApiSurface {
  artifact?: { path?: string; sha256?: string };
  groups?: unknown[];
  coverage?: unknown;
  limitations?: string[];
  raw: unknown;
}

export async function reaAvailable(): Promise<boolean> {
  try {
    await run("rea", ["--version"], { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

/** Parse a HAR with REA's offline capture inspector. */
export async function inspectCapture(harPath: string): Promise<ReaCaptureResult> {
  const { stdout } = await run(
    "rea",
    ["inspect-web-network-capture", harPath, "har", "--json"],
    { timeout: 60_000, maxBuffer: 64 * 1024 * 1024 },
  );
  const d = JSON.parse(stdout) as Record<string, unknown>;
  if ((d as { category?: string }).category === "invalid_input") {
    throw new Error(`REA rejected the capture: ${JSON.stringify((d as { details?: unknown }).details)}`);
  }
  const nr = (d["normalized_result"] ?? {}) as Record<string, unknown>;
  return {
    evidenceId: d["evidence_id"] as string | undefined,
    totalRecords: nr["total_records"] as number | undefined,
    artifact: undefined,
    raw: d,
  };
}

/** Project REA's api-surface view over the full evidence envelope (inline source). */
export async function apiSurface(evidenceEnvelope: unknown): Promise<ReaApiSurface> {
  const input = JSON.stringify({
    source: { kind: "inline", evidence: evidenceEnvelope },
    view: { kind: "api-surface" },
  });
  // REA's CLI takes the workflow JSON as a file path; write it to a private temp dir.
  const { writeFile, mkdtemp, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "order-rea-"));
  const f = join(dir, "view.json");
  await writeFile(f, input);
  let stdout: string;
  try {
    ({ stdout } = await run("rea", ["inspect-analysis-view", f, "--json"], {
      timeout: 60_000,
      maxBuffer: 64 * 1024 * 1024,
    }));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  const d = JSON.parse(stdout) as Record<string, unknown>;
  const nr = (d["normalized_result"] ?? d) as Record<string, unknown>;
  return {
    artifact: nr["artifact"] as { path?: string; sha256?: string } | undefined,
    groups: nr["groups"] as unknown[] | undefined,
    coverage: nr["coverage"],
    limitations: nr["limitations"] as string[] | undefined,
    raw: d,
  };
}
