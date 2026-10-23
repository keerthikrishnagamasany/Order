/**
 * Compose rule packs. Defence in depth: run the open reference pack, your private pack,
 * and any approved learned rules together. Order is preserved; signals are concatenated.
 */
import type { RequestFacts, RulePack, Signal } from "./types.js";

export function combine(...packs: RulePack[]): RulePack {
  return {
    id: packs.map((p) => p.id).join("+") || "empty",
    inspect(facts: RequestFacts): Signal[] {
      const out: Signal[] = [];
      for (const p of packs) out.push(...p.inspect(facts));
      return out;
    },
  };
}
