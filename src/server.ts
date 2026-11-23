import http from "node:http";
import { fileURLToPath } from "node:url";
import { checkSsl } from "./scanners/ssl.js";
import { scanUrl } from "./scanners/url.js";
import { ThreatFeedCache } from "./feeds/cache.js";
import { MetricsCollector } from "./metrics.js";

export const SUPPORTED_INTENTS = [
  "URL_SCAN_VERDICT",
  "SSL_VERIFICATION_CERT",
  "URL_SAFE_GENERAL",
] as const;

async function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > 65_536) throw new Error("Request body exceeds 64KB limit");
    chunks.push(buf);
  }
  const text = Buffer.concat(chunks).toString("utf8").trim();
  if (!text) return {};
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  } catch {
    return { query: text };
  }
}

function pickParam(urlObj: URL, body: Record<string, unknown>, keys: string[]): string {
  const nested = body.params && typeof body.params === "object" ? (body.params as Record<string, unknown>) : {};
  for (const k of keys) {
    const q = urlObj.searchParams.get(k);
    if (q && q.trim()) return q.trim();
    const n = nested[k];
    if (typeof n === "string" && n.trim()) return n.trim();
    const b = body[k];
    if (typeof b === "string" && b.trim()) return b.trim();
  }
  return "";
}

function sendJson(res: http.ServerResponse, status: number, payload: unknown) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  });
  res.end(body);
}

export function createPrimaryServer(opts?: { feedCache?: ThreatFeedCache; skipLiveUrlFetch?: boolean }) {
  const feedCache = opts?.feedCache ?? new ThreatFeedCache({ autoSync: process.env.PRIMARY_SKIP_FEED_SYNC !== "1" });
  const metrics = new MetricsCollector();

  const server = http.createServer(async (req, res) => {
    const t0 = Date.now();
    const method = (req.method || "GET").toUpperCase();
    const urlObj = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const path = urlObj.pathname.replace(/\/+$/, "") || "/";

    const finish = (status: number, payload: unknown) => {
      metrics.record(`${method} ${path}`, status, Date.now() - t0);
      sendJson(res, status, payload);
    };

    try {
      if (path === "/" || path === "/health") {
        return finish(200, {
          status: "ok",
          service: "primary-miner",
          version: "1.0.0",
          supported_intents: SUPPORTED_INTENTS,
          endpoints: ["GET/POST /ssl-check", "GET/POST /url-scan", "GET/POST /url-safe", "GET /health", "GET /metrics"],
          feeds: feedCache.stats(),
          timestamp: new Date().toISOString(),
        });
      }

      if (path === "/metrics") {
        return finish(200, metrics.snapshot({ feeds: feedCache.stats() }));
      }

      const body = method === "POST" ? await readJsonBody(req) : {};

      if (path === "/ssl-check") {
        const rawHost = pickParam(urlObj, body, ["host", "hostname", "domain", "target", "url", "question", "query"]);
        if (!rawHost) {
          return finish(400, { error: "Missing required parameter 'host' (or 'question'/'query')" });
        }
        const result = await checkSsl(rawHost);
        return finish(200, result);
      }

      if (path === "/url-scan" || path === "/url-safe") {
        const rawUrl = pickParam(urlObj, body, ["url", "target", "link", "question", "query"]);
        if (!rawUrl) {
          return finish(400, { error: "Missing required parameter 'url' (or 'question'/'query')" });
        }
        const result = await scanUrl(rawUrl, {
          feedCache,
          skipLiveFetch: opts?.skipLiveUrlFetch ?? false,
        });
        return finish(200, result);
      }

      return finish(404, { error: `Unknown endpoint: ${method} ${path}` });
    } catch (err: any) {
      return finish(500, { error: "internal_error", message: err?.message || String(err) });
    }
  });

  return { server, feedCache, metrics };
}

// Run directly when executed as entrypoint
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.PORT || 3001);
  const host = process.env.HOST || "0.0.0.0";
  const { server, feedCache } = createPrimaryServer();
  server.listen(port, host, () => {
    console.log(`[primary-miner] listening on http://${host}:${port} (intents: ${SUPPORTED_INTENTS.join(", ")})`);
  });

  const shutdown = (sig: string) => {
    console.log(`[primary-miner] received ${sig}, shutting down gracefully...`);
    feedCache.stop();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
