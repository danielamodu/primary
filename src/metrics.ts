export class MetricsCollector {
  private startedAtMs = Date.now();
  private totalRequests = 0;
  private errorRequests = 0;
  private byEndpoint = new Map<string, { count: number; errors: number; latenciesMs: number[] }>();

  record(endpoint: string, status: number, latencyMs: number) {
    this.totalRequests++;
    const isErr = status >= 400;
    if (isErr) this.errorRequests++;
    let bucket = this.byEndpoint.get(endpoint);
    if (!bucket) {
      bucket = { count: 0, errors: 0, latenciesMs: [] };
      this.byEndpoint.set(endpoint, bucket);
    }
    bucket.count++;
    if (isErr) bucket.errors++;
    bucket.latenciesMs.push(latencyMs);
    if (bucket.latenciesMs.length > 500) {
      bucket.latenciesMs.shift();
    }
  }

  private percentile(arr: number[], p: number): number {
    if (!arr.length) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
    return Math.round(sorted[idx] * 100) / 100;
  }

  snapshot(extra?: Record<string, unknown>) {
    const endpoints: Record<string, unknown> = {};
    for (const [ep, b] of this.byEndpoint.entries()) {
      endpoints[ep] = {
        count: b.count,
        errors: b.errors,
        p50_ms: this.percentile(b.latenciesMs, 50),
        p95_ms: this.percentile(b.latenciesMs, 95),
      };
    }
    return {
      uptime_seconds: Math.floor((Date.now() - this.startedAtMs) / 1000),
      started_at: new Date(this.startedAtMs).toISOString(),
      requests_total: this.totalRequests,
      errors_total: this.errorRequests,
      endpoints,
      ...(extra || {}),
    };
  }
}
