import test from "node:test";
import assert from "node:assert/strict";
import { createPrimaryServer } from "../src/server.js";
import { ThreatFeedCache } from "../src/feeds/cache.js";

async function withServer(fn: (baseUrl: string) => Promise<void>) {
  const feedCache = new ThreatFeedCache({ autoSync: false });
  const { server } = createPrimaryServer({ feedCache, skipLiveUrlFetch: true });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("Failed to bind ephemeral test port");
  const baseUrl = `http://127.0.0.1:${addr.port}`;
  try {
    await fn(baseUrl);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test("GET /health and GET /metrics return 200 with structured telemetry", async () => {
  await withServer(async (base) => {
    const h = await fetch(`${base}/health`);
    assert.equal(h.status, 200);
    const hJson = (await h.json()) as any;
    assert.equal(hJson.status, "ok");
    assert.equal(hJson.service, "primary-miner");
    assert.ok(Array.isArray(hJson.supported_intents));

    const m = await fetch(`${base}/metrics`);
    assert.equal(m.status, 200);
    const mJson = (await m.json()) as any;
    assert.equal(typeof mJson.uptime_seconds, "number");
    assert.equal(typeof mJson.requests_total, "number");
  });
});

test("GET and POST /url-scan and /url-safe handle both structured params and natural-language questions", async () => {
  await withServer(async (base) => {
    // GET structured param
    const r1 = await fetch(`${base}/url-scan?url=${encodeURIComponent("http://testsafebrowsing.appspot.com/s/phishing.html")}`);
    assert.equal(r1.status, 200);
    const b1 = (await r1.json()) as any;
    assert.equal(b1.safe, false);
    assert.equal(b1.verdict, "Malicious");
    assert.ok(b1.detections >= 1);

    // POST JSON body
    const r2 = await fetch(`${base}/url-scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://www.google.com/" }),
    });
    assert.equal(r2.status, 200);
    const b2 = (await r2.json()) as any;
    assert.equal(b2.safe, true);
    assert.equal(b2.verdict, "Safe");

    // GET /url-safe with ?question=...
    const r3 = await fetch(`${base}/url-safe?question=${encodeURIComponent("Is http://malware.wicar.org/data/eicar.com safe?")}`);
    assert.equal(r3.status, 200);
    const b3 = (await r3.json()) as any;
    assert.equal(b3.safe, false);
    assert.equal(b3.verdict, "Malicious");
  });
});

test("GET and POST /ssl-check work and return 400 on missing host", async () => {
  await withServer(async (base) => {
    const rBad = await fetch(`${base}/ssl-check`);
    assert.equal(rBad.status, 400);

    const r1 = await fetch(`${base}/ssl-check?host=google.com`);
    assert.equal(r1.status, 200);
    const b1 = (await r1.json()) as any;
    assert.equal(b1.certificate_valid, true);
    assert.equal(b1.host, "google.com");

    const r2 = await fetch(`${base}/ssl-check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ params: { host: "127.0.0.1" } }),
    });
    assert.equal(r2.status, 200);
    const b2 = (await r2.json()) as any;
    assert.equal(b2.certificate_valid, false);
  });
});
