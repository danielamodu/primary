import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

const BASE_URL = (process.env.PRIMARY_BASE_URL ?? "https://13-60-129-92.sslip.io").replace(/\/+$/, "");
const OUT_FILE = process.env.UPTIME_LOG_PATH ?? join(process.cwd(), "bench", "results", "uptime.jsonl");

async function probeOnce() {
  const started = Date.now();
  let healthStatus = 0;
  let sslStatus = 0;
  let sslValidValue: boolean | null = null;
  let urlStatus = 0;
  let urlSafeValue: boolean | null = null;
  let error: string | undefined;

  try {
    const h = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(10_000) });
    healthStatus = h.status;

    const s = await fetch(`${BASE_URL}/ssl-check?host=expired.badssl.com`, { signal: AbortSignal.timeout(15_000) });
    sslStatus = s.status;
    if (s.ok) {
      const sj = (await s.json()) as { certificate_valid?: boolean };
      sslValidValue = typeof sj.certificate_valid === "boolean" ? sj.certificate_valid : null;
    }

    const u = await fetch(
      `${BASE_URL}/url-scan?url=${encodeURIComponent("https://testsafebrowsing.appspot.com/s/phishing.html")}`,
      { signal: AbortSignal.timeout(15_000) }
    );
    urlStatus = u.status;
    if (u.ok) {
      const uj = (await u.json()) as { safe?: boolean };
      urlSafeValue = typeof uj.safe === "boolean" ? uj.safe : null;
    }
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
  }

  const entry = {
    timestamp: new Date().toISOString(),
    baseUrl: BASE_URL,
    ok: healthStatus === 200 && sslStatus === 200 && sslValidValue === false && urlStatus === 200 && urlSafeValue === false,
    healthStatus,
    sslStatus,
    sslExpiredCaught: sslValidValue === false,
    urlStatus,
    urlPhishCaught: urlSafeValue === false,
    totalLatencyMs: Date.now() - started,
    ...(error ? { error } : {}),
  };

  const dir = dirname(OUT_FILE);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  appendFileSync(OUT_FILE, `${JSON.stringify(entry)}\n`, "utf8");
  console.log(JSON.stringify(entry));
  if (!entry.ok) process.exitCode = 1;
}

probeOnce();
