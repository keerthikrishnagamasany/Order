#!/usr/bin/env node
/**
 * Prove the packages work the way a stranger would install them:
 *   1. build every package to JavaScript,
 *   2. `pnpm pack` each one exactly as it would be published,
 *   3. install all the tarballs into a fresh, empty project with npm,
 *   4. import them from plain Node (no TypeScript loader) and run a real decision.
 *
 *   pnpm pack:check
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const PACKAGES = ["packages/core", "packages/rules-reference", "packages/web-bot-auth", "packages/reconstruct", "apps/gateway"];
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"] }).toString();

const work = mkdtempSync(join(tmpdir(), "order-pack-"));
try {
  console.log("1. build");
  run("pnpm", ["-s", "build"], root);

  console.log("2. pack");
  const tarballs = [];
  for (const p of PACKAGES) {
    run("pnpm", ["pack", "--pack-destination", work], join(root, p));
  }
  for (const f of readdirSync(work)) if (f.endsWith(".tgz")) tarballs.push(join(work, f));
  if (tarballs.length !== PACKAGES.length) throw new Error(`expected ${PACKAGES.length} tarballs, got ${tarballs.length}`);

  // The published manifest must point at compiled JS, and carry no workspace: ranges.
  for (const t of tarballs) {
    const manifest = JSON.parse(run("tar", ["-xOzf", t, "package/package.json"], work));
    const deps = JSON.stringify(manifest.dependencies ?? {});
    if (deps.includes("workspace:")) throw new Error(`${manifest.name}: unresolved workspace dependency ${deps}`);
    const main = manifest.exports?.["."]?.default ?? manifest.main;
    if (!String(main).endsWith(".js")) throw new Error(`${manifest.name}: exports point at ${main}, not compiled JS`);
    const listing = run("tar", ["-tzf", t], work);
    if (!listing.includes("package/dist/index.js") || !listing.includes("package/dist/index.d.ts")) {
      throw new Error(`${manifest.name}: dist/index.js or index.d.ts missing from tarball`);
    }
    if (listing.includes("/src/") || listing.includes("/test/")) throw new Error(`${manifest.name}: ships src/ or test/`);
    console.log(`   ok ${manifest.name}@${manifest.version} (author: ${manifest.author})`);
  }

  console.log("3. install into a fresh project");
  const app = join(work, "app");
  run("mkdir", ["-p", app], work);
  writeFileSync(join(app, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
  run("npm", ["install", "--no-audit", "--no-fund", "--ignore-scripts", ...tarballs], app);

  console.log("4. import from plain Node and decide");
  writeFileSync(
    join(app, "smoke.mjs"),
    `
import { Engine, CanaryRegistry, combine } from "@order/core";
import { referenceRules } from "@order/rules-reference";
import { verifyWebBotAuth, HttpsDirectoryResolver } from "@order/web-bot-auth";
import { synthesizeRules } from "@order/reconstruct";
import { createGateway, orderExpress, orderFastify, Metrics } from "@order/gateway";
const engine = new Engine({ rules: combine(referenceRules), allowlist: new Map(), canaries: new CanaryRegistry() });
const a = engine.decide({ method: "GET", path: "/.env", clientId: "x" });
const b = engine.decide({ method: "GET", path: "/api/items", clientId: "y" });
if (a.lane !== "blocked" || b.lane !== "normal") throw new Error("wrong lanes " + a.lane + " " + b.lane);
for (const f of [verifyWebBotAuth, synthesizeRules, createGateway, orderExpress, orderFastify]) if (typeof f !== "function") throw new Error("missing export");
new HttpsDirectoryResolver(); new Metrics();
console.log("   smoke ok: /.env ->", a.lane, "| /api/items ->", b.lane);
`,
  );
  process.stdout.write(run("node", ["smoke.mjs"], app));
  console.log("\npack check passed: all packages install and run from npm tarballs");
} finally {
  rmSync(work, { recursive: true, force: true });
}
