# Writing a private rule pack

The open reference pack (`@order/rules-reference`) is useful but readable by attackers.
In production you load a **private** pack with tuned signatures. It implements the same
`RulePack` interface, so the framework doesn't change.

Create a separate, private package — e.g. `@order/rules-private` (git-ignored in this
repo; publish it to a private registry or keep it in a private repo):

```ts
// @order/rules-private/src/index.ts
import type { RequestFacts, RulePack, Signal } from "@order/core";

// Your real, tuned signatures. Keep them out of any public repo.
const MY_SIGNATURES: Array<{ name: string; severity: Signal["severity"]; rx: RegExp }> = [
  // e.g. patterns specific to YOUR endpoints, abuse you've actually seen, and
  // thresholds tuned on YOUR traffic. None of this belongs in the open pack.
];

export const privateRules: RulePack = {
  id: "private@1.0.0",
  inspect(facts: RequestFacts): Signal[] {
    const out: Signal[] = [];
    for (const s of MY_SIGNATURES) {
      const hit = s.rx.exec(`${facts.query} ${facts.body}`);
      if (hit) out.push({ name: s.name, severity: s.severity, where: "query", excerpt: hit[0].slice(0, 80) });
    }
    return out;
  },
};
```

Compose it with the reference pack (defence in depth — run both):

```ts
import { referenceRules } from "@order/rules-reference";
import { privateRules } from "@order/rules-private";
import type { RulePack, RequestFacts } from "@order/core";

export const combined: RulePack = {
  id: "combined",
  inspect: (f: RequestFacts) => [...referenceRules.inspect(f), ...privateRules.inspect(f)],
};

const engine = new Engine({ rules: combined, allowlist, canaries });
```

Because `inspect` is pure, you can unit-test a private pack against a fixture corpus in
its own repo, with no dependency on the gateway or the network.
