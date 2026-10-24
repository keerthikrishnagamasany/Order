/**
 * Prometheus-format metrics, zero dependencies. Feed it decisions, serve `render()`.
 *
 *   order_decisions_total{lane}            requests by lane
 *   order_signals_total{signal}            detector hits
 *   order_bot_auth_total{result}           Web Bot Auth outcomes
 *   order_authorized_test_total{test}      requests allowed under an authorized test
 *   order_upstream_errors_total            failed forwards (proxy mode)
 *   order_decide_seconds                   decision latency histogram (excludes upstream)
 */

export interface MetricsInput {
  lane: string;
  reasons: readonly string[];
  decideMs: number;
  botAuth?: string | undefined;
  authorizedTest?: string | undefined;
  upstreamError?: string | undefined;
}

const BUCKETS = [0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1];

function label(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

export class Metrics {
  private readonly lanes = new Map<string, number>();
  private readonly signals = new Map<string, number>();
  private readonly botAuth = new Map<string, number>();
  private readonly tests = new Map<string, number>();
  private upstreamErrors = 0;
  private readonly bucketCounts = BUCKETS.map(() => 0);
  private sum = 0;
  private count = 0;

  observe(e: MetricsInput): void {
    this.lanes.set(e.lane, (this.lanes.get(e.lane) ?? 0) + 1);
    for (const r of e.reasons) {
      const m = /^([a-z_]+):(HARD|SUSPECT|SOFT)\(/.exec(r) ?? /^(canary_replayed|trusted_key_hard_signal|rate_exceeded)/.exec(r);
      if (m) this.signals.set(m[1] as string, (this.signals.get(m[1] as string) ?? 0) + 1);
    }
    if (e.botAuth) this.botAuth.set(e.botAuth, (this.botAuth.get(e.botAuth) ?? 0) + 1);
    if (e.authorizedTest) this.tests.set(e.authorizedTest, (this.tests.get(e.authorizedTest) ?? 0) + 1);
    if (e.upstreamError) this.upstreamErrors++;
    const s = e.decideMs / 1000;
    this.sum += s;
    this.count++;
    BUCKETS.forEach((b, i) => {
      if (s <= b) this.bucketCounts[i] = (this.bucketCounts[i] as number) + 1;
    });
  }

  render(): string {
    const out: string[] = [];
    const counter = (name: string, help: string, key: string, m: Map<string, number>) => {
      out.push(`# HELP ${name} ${help}`, `# TYPE ${name} counter`);
      for (const [k, v] of [...m].sort()) out.push(`${name}{${key}="${label(k)}"} ${v}`);
    };
    counter("order_decisions_total", "Requests decided, by lane.", "lane", this.lanes);
    counter("order_signals_total", "Detector signals raised, by signal.", "signal", this.signals);
    counter("order_bot_auth_total", "Web Bot Auth verification outcomes.", "result", this.botAuth);
    counter("order_authorized_test_total", "Requests allowed under an authorized security test.", "test", this.tests);
    out.push("# HELP order_upstream_errors_total Failed forwards to the upstream app.", "# TYPE order_upstream_errors_total counter", `order_upstream_errors_total ${this.upstreamErrors}`);
    out.push("# HELP order_decide_seconds Time spent verifying and deciding a request.", "# TYPE order_decide_seconds histogram");
    BUCKETS.forEach((b, i) => out.push(`order_decide_seconds_bucket{le="${b}"} ${this.bucketCounts[i]}`));
    out.push(`order_decide_seconds_bucket{le="+Inf"} ${this.count}`, `order_decide_seconds_sum ${this.sum}`, `order_decide_seconds_count ${this.count}`);
    return out.join("\n") + "\n";
  }
}
