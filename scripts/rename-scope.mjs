#!/usr/bin/env node
/**
 * Rename the npm scope across the whole repo, e.g. if `@order` is taken on npm:
 *
 *   pnpm rename-scope @ordergate
 *   pnpm install            # refresh workspace links and the lockfile
 *   pnpm build && pnpm test
 *
 * Rewrites "@order/" in source, configs, docs and lockfile. Skips node_modules, dist, .git.
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const next = process.argv[2];
if (!next || !/^@[a-z0-9][a-z0-9._-]*$/.test(next)) {
  console.error("usage: pnpm rename-scope @newscope   (lowercase, npm scope rules)");
  process.exit(1);
}
const FROM = "@order/";
const TO = `${next}/`;
const SKIP = new Set(["node_modules", "dist", ".git", "capture"]);
const EXT = /\.(ts|mts|mjs|js|json|md|yaml|yml)$/;

let files = 0;
let hits = 0;
function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (EXT.test(name) && !name.endsWith(".tsbuildinfo")) {
      const s = readFileSync(p, "utf8");
      if (s.includes(FROM)) {
        const n = s.split(FROM).length - 1;
        writeFileSync(p, s.split(FROM).join(TO));
        files++;
        hits += n;
      }
    }
  }
}
walk(process.cwd());
console.log(`renamed ${FROM} -> ${TO}: ${hits} occurrences in ${files} files`);
console.log("now run: pnpm install && pnpm build && pnpm test");
