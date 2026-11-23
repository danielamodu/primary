import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

interface SslVector {
  id: string;
  category: string;
  host: string;
  expectedValid: boolean;
}

interface UrlVector {
  id: string;
  category: string;
  url: string;
  expectedSafe: boolean;
}

const BASE_URL = (process.env.PRIMARY_BASE_URL ?? "https://13-60-129-92.sslip.io").replace(/\/+$/, "");

const SSL_VECTORS: SslVector[] = [
  // 30 live valid HTTPS domains
  ...[
    "google.com", "github.com", "cloudflare.com", "wikipedia.org", "stripe.com",
    "mozilla.org", "openai.com", "ethereum.org", "aws.amazon.com", "npmjs.com",
    "python.org", "rust-lang.org", "debian.org", "ubuntu.com", "kernel.org",
    "ietf.org", "w3.org", "icann.org", "letsencrypt.org", "duckduckgo.com",
    "signal.org", "proton.me", "vercel.com", "netlify.com", "supabase.com",
    "fly.io", "linear.app", "figma.com", "notion.so", "13-60-129-92.sslip.io",
  ].map((host, i) => ({
    id: `ssl-valid-${String(i + 1).padStart(2, "0")}`,
    category: "valid_live_https",
    host,
    expectedValid: true,
  })),
  // 20 invalid / broken / SSRF-blocked TLS targets
  ...[
    { host: "expired.badssl.com", category: "expired_cert" },
    { host: "wrong.host.badssl.com", category: "wrong_host" },
    { host: "self-signed.badssl.com", category: "self_signed" },
    { host: "untrusted-root.badssl.com", category: "untrusted_root" },
    { host: "incomplete-chain.badssl.com", category: "incomplete_chain" },
    { host: "rc4.badssl.com", category: "weak_cipher" },
    { host: "rc4-md5.badssl.com", category: "weak_cipher" },
    { host: "dh480.badssl.com", category: "weak_dh" },
    { host: "dh512.badssl.com", category: "weak_dh" },
    { host: "null.badssl.com", category: "null_cipher" },
    { host: "nonexistent-alpha-9182.invalid", category: "nxdomain" },
    { host: "nonexistent-beta-7361.invalid", category: "nxdomain" },
    { host: "nonexistent-gamma-4429.invalid", category: "nxdomain" },
    { host: "nonexistent-delta-5510.invalid", category: "nxdomain" },
    { host: "127.0.0.1", category: "ssrf_loopback" },
    { host: "localhost", category: "ssrf_localhost" },
    { host: "169.254.169.254", category: "ssrf_aws_imds" },
    { host: "10.0.0.1", category: "ssrf_rfc1918" },
    { host: "192.168.1.1", category: "ssrf_rfc1918" },
    { host: "172.16.0.1", category: "ssrf_rfc1918" },
  ].map((v, i) => ({
    id: `ssl-invalid-${String(i + 1).padStart(2, "0")}`,
    category: v.category,
    host: v.host,
    expectedValid: false,
  })),
];

const URL_VECTORS: UrlVector[] = [
  // 25 clean legitimate URLs
  ...[
    "https://www.google.com/", "https://github.com/danielamodu/primary", "https://ethereum.org/en/",
    "https://www.cloudflare.com/", "https://en.wikipedia.org/wiki/TLS", "https://stripe.com/docs",
    "https://developer.mozilla.org/", "https://nodejs.org/en", "https://www.python.org/",
    "https://www.rust-lang.org/", "https://ubuntu.com/", "https://letsencrypt.org/",
    "https://duckduckgo.com/", "https://signal.org/", "https://proton.me/",
    "https://vercel.com/", "https://www.netlify.com/", "https://supabase.com/",
    "https://www.npmjs.com/", "https://www.ietf.org/", "https://www.w3.org/",
    "https://example.com/", "https://www.icann.org/", "https://aws.amazon.com/",
    "https://13-60-129-92.sslip.io/health",
  ].map((url, i) => ({
    id: `url-safe-${String(i + 1).padStart(2, "0")}`,
    category: "clean_legitimate",
    url,
    expectedSafe: true,
  })),
  // 25 malicious / phishing / adversarial URLs
  ...[
    { url: "https://testsafebrowsing.appspot.com/s/phishing.html", category: "gsb_phishing_fixture" },
    { url: "https://testsafebrowsing.appspot.com/s/malware.html", category: "gsb_malware_fixture" },
    { url: "https://testsafebrowsing.appspot.com/s/unwanted.html", category: "gsb_unwanted_fixture" },
    { url: "http://www.wicar.org/data/ms09_002_memory_corruption.html", category: "wicar_malware_fixture" },
    { url: "https://secure.eicar.org/eicar.com.txt", category: "eicar_fixture" },
    { url: "https://xn--pple-43d.com/login", category: "punycode_homograph" },
    { url: "https://xn--pypal-4ve.com/verify", category: "punycode_homograph" },
    { url: "https://xn--gogle-1ra.com/signin", category: "punycode_homograph" },
    { url: "https://xn--microsft-43a.com/auth", category: "punycode_homograph" },
    { url: "https://xn--coinbse-4wa.com/wallet", category: "punycode_homograph" },
    { url: "https://paypal.com@evil-login.xyz/account", category: "credential_in_url" },
    { url: "https://apple.com@verify-id.top/signin", category: "credential_in_url" },
    { url: "https://metamask.io@claim-airdrop.click/sync", category: "credential_in_url" },
    { url: "https://chase.com@secure-update.vip/login", category: "credential_in_url" },
    { url: "https://binance.com@withdraw-check.xyz/auth", category: "credential_in_url" },
    { url: "https://paypa1-secure-login.xyz/verify", category: "brand_typosquat_tld" },
    { url: "https://metamask-wallet-recover.top/seed", category: "brand_typosquat_tld" },
    { url: "https://coinbase-support-verify.click/login", category: "brand_typosquat_tld" },
    { url: "https://appleid-unlock-now.vip/auth", category: "brand_typosquat_tld" },
    { url: "https://microsoft-365-reset.buzz/office", category: "brand_typosquat_tld" },
    { url: "http://198.51.100.10/paypal-login/verify.php", category: "raw_ip_phish" },
    { url: "http://203.0.113.42/metamask/connect-wallet", category: "raw_ip_phish" },
    { url: "https://expired.badssl.com/", category: "invalid_tls_url" },
    { url: "https://self-signed.badssl.com/", category: "invalid_tls_url" },
    { url: "https://wrong.host.badssl.com/", category: "invalid_tls_url" },
  ].map((v, i) => ({
    id: `url-malicious-${String(i + 1).padStart(2, "0")}`,
    category: v.category,
    url: v.url,
    expectedSafe: false,
  })),
];

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

async function runPool<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return results;
}

async function main() {
  const startedAt = new Date().toISOString();
  console.log(`Running 100-vector benchmark against ${BASE_URL}...`);

  const sslResults = await runPool(SSL_VECTORS, 5, async (v) => {
    const t0 = Date.now();
    try {
      const r = await fetch(`${BASE_URL}/ssl-check?host=${encodeURIComponent(v.host)}`, {
        signal: AbortSignal.timeout(15_000),
      });
      const body = (await r.json()) as { certificate_valid?: boolean; error_reason?: string };
      const actual = Boolean(body.certificate_valid);
      return {
        ...v,
        httpStatus: r.status,
        actualValid: actual,
        correct: r.ok && actual === v.expectedValid,
        latencyMs: Date.now() - t0,
        detail: body.error_reason ?? null,
      };
    } catch (err) {
      return {
        ...v,
        httpStatus: 0,
        actualValid: null,
        correct: false,
        latencyMs: Date.now() - t0,
        detail: err instanceof Error ? err.message : String(err),
      };
    }
  });

  const urlResults = await runPool(URL_VECTORS, 5, async (v) => {
    const t0 = Date.now();
    try {
      const r = await fetch(`${BASE_URL}/url-scan?url=${encodeURIComponent(v.url)}`, {
        signal: AbortSignal.timeout(15_000),
      });
      const body = (await r.json()) as { safe?: boolean; verdict?: string; detections?: number };
      const actual = Boolean(body.safe);
      return {
        ...v,
        httpStatus: r.status,
        actualSafe: actual,
        verdict: body.verdict ?? null,
        detections: body.detections ?? 0,
        correct: r.ok && actual === v.expectedSafe,
        latencyMs: Date.now() - t0,
      };
    } catch (err) {
      return {
        ...v,
        httpStatus: 0,
        actualSafe: null,
        verdict: null,
        detections: 0,
        correct: false,
        latencyMs: Date.now() - t0,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  const sslCorrect = sslResults.filter((r) => r.correct).length;
  const urlCorrect = urlResults.filter((r) => r.correct).length;
  const totalCorrect = sslCorrect + urlCorrect;
  const allLatencies = [...sslResults, ...urlResults].map((r) => r.latencyMs).sort((a, b) => a - b);

  const summary = {
    startedAtUtc: startedAt,
    completedAtUtc: new Date().toISOString(),
    targetBaseUrl: BASE_URL,
    minerId: "6184",
    totalVectors: sslResults.length + urlResults.length,
    totalCorrect,
    overallAccuracyPct: Number(((totalCorrect / 100) * 100).toFixed(2)),
    ssl: {
      total: sslResults.length,
      correct: sslCorrect,
      accuracyPct: Number(((sslCorrect / sslResults.length) * 100).toFixed(2)),
      p50Ms: percentile(sslResults.map((r) => r.latencyMs).sort((a, b) => a - b), 50),
      p95Ms: percentile(sslResults.map((r) => r.latencyMs).sort((a, b) => a - b), 95),
      failures: sslResults.filter((r) => !r.correct),
    },
    url: {
      total: urlResults.length,
      correct: urlCorrect,
      accuracyPct: Number(((urlCorrect / urlResults.length) * 100).toFixed(2)),
      p50Ms: percentile(urlResults.map((r) => r.latencyMs).sort((a, b) => a - b), 50),
      p95Ms: percentile(urlResults.map((r) => r.latencyMs).sort((a, b) => a - b), 95),
      failures: urlResults.filter((r) => !r.correct),
    },
    overallLatencyP50Ms: percentile(allLatencies, 50),
    overallLatencyP95Ms: percentile(allLatencies, 95),
  };

  const outDir = join(process.cwd(), "bench", "results");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(
    join(outDir, "benchmark-100.json"),
    JSON.stringify({ summary, sslResults, urlResults }, null, 2),
    "utf8"
  );

  const md = [
    `# Primary Miner (#6184) — 100-Vector Live Adversarial Benchmark`,
    ``,
    `- **Endpoint**: \`${BASE_URL}\` (AWS EC2 \`eu-north-1\`, Sepolia Miner \`#6184\`)`,
    `- **Captured**: \`${summary.completedAtUtc}\``,
    `- **Overall Accuracy**: **${summary.totalCorrect}/100 (${summary.overallAccuracyPct}%)**`,
    `- **Latency**: p50 = \`${summary.overallLatencyP50Ms}ms\`, p95 = \`${summary.overallLatencyP95Ms}ms\``,
    ``,
    `| Intent | Vectors | Correct | Accuracy | p50 | p95 |`,
    `| :--- | ---: | ---: | ---: | ---: | ---: |`,
    `| \`SSL_VERIFICATION_CERT\` | ${summary.ssl.total} | ${summary.ssl.correct} | **${summary.ssl.accuracyPct}%** | ${summary.ssl.p50Ms}ms | ${summary.ssl.p95Ms}ms |`,
    `| \`URL_SCAN_VERDICT\` | ${summary.url.total} | ${summary.url.correct} | **${summary.url.accuracyPct}%** | ${summary.url.p50Ms}ms | ${summary.url.p95Ms}ms |`,
    ``,
    `## Honest Failure Disclosure`,
    summary.ssl.failures.length + summary.url.failures.length === 0
      ? `Zero failures across all 100 live vectors.`
      : [
          ...summary.ssl.failures.map((f) => `- SSL \`${f.host}\` (${f.category}): expected \`${f.expectedValid}\`, got \`${f.actualValid}\` (${f.detail ?? "no detail"})`),
          ...summary.url.failures.map((f) => `- URL \`${f.url}\` (${f.category}): expected \`${f.expectedSafe}\`, got \`${f.actualSafe}\``),
        ].join("\n"),
  ].join("\n");
  writeFileSync(join(outDir, "BENCHMARK.md"), md + "\n", "utf8");

  console.log(JSON.stringify(summary, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
