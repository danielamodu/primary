import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const __dirname = dirname(fileURLToPath(import.meta.url));
const MANIFEST_PATH = join(__dirname, "..", "manifest", "primary.yaml");
const SERVER_PATH = join(__dirname, "..", "src", "server.ts");

// Required top-level keys verified against live accepted miner 4433 (verifywire-fx-now.yaml)
const REQUIRED_TOP_KEYS = [
  "version",
  "kind",
  "slug",
  "protocol",
  "name",
  "description",
  "base_url",
  "input_schema",
  "output_schema",
  "endpoints",
  "semantics",
  "on_chain",
];

const ALLOWED_INTENTS = new Set(["URL_SCAN_VERDICT", "SSL_VERIFICATION_CERT", "URL_SAFE_GENERAL"]);

async function main() {
  const verifyRemote = process.argv.includes("--verify-remote");
  const rawYaml = readFileSync(MANIFEST_PATH, "utf8");
  const sha256Hex = createHash("sha256").update(rawYaml, "utf8").digest("hex");
  const doc = YAML.parse(rawYaml);

  if (!doc || typeof doc !== "object") {
    throw new Error("primary.yaml did not parse to a YAML object");
  }

  for (const key of REQUIRED_TOP_KEYS) {
    if (doc[key] === undefined || doc[key] === null) {
      throw new Error(`Missing required manifest key (per miner 4433 schema): ${key}`);
    }
  }

  if (String(doc.version) !== "1") throw new Error(`version must be "1", got ${doc.version}`);
  if (doc.kind !== "miner") throw new Error(`kind must be "miner", got ${doc.kind}`);
  if (doc.protocol !== "generic") throw new Error(`protocol must be "generic", got ${doc.protocol}`);
  if (!Array.isArray(doc.endpoints) || doc.endpoints.length < 3) {
    throw new Error("endpoints must declare at least 3 routes (/ssl-check, /url-scan, /url-safe)");
  }

  // Verify every endpoint path declared in primary.yaml exists in src/server.ts
  const serverSrc = readFileSync(SERVER_PATH, "utf8");
  for (const ep of doc.endpoints) {
    if (!ep.path || !ep.method) throw new Error(`Invalid endpoint entry: ${JSON.stringify(ep)}`);
    if (!serverSrc.includes(`"${ep.path}"`)) {
      throw new Error(`Endpoint ${ep.path} declared in primary.yaml is not handled in src/server.ts`);
    }
  }

  // Verify supported_intents are canonical (no broad prefixes)
  const intents = doc.semantics?.supported_intents;
  if (!Array.isArray(intents) || intents.length === 0) {
    throw new Error("semantics.supported_intents must be a non-empty array");
  }
  for (const intent of intents) {
    if (!ALLOWED_INTENTS.has(intent)) {
      throw new Error(`Unexpected or non-canonical intent in manifest: ${intent}`);
    }
  }

  if (typeof doc.on_chain?.min_price_usdc !== "number" || doc.on_chain.min_price_usdc < 0.01) {
    throw new Error(`on_chain.min_price_usdc must be >= 0.01, got ${doc.on_chain?.min_price_usdc}`);
  }

  if (verifyRemote) {
    if (String(doc.base_url).includes("REPLACE_WITH_PRIMARY_DOMAIN")) {
      throw new Error("--verify-remote failed: base_url still contains placeholder REPLACE_WITH_PRIMARY_DOMAIN");
    }
    const base = String(doc.base_url).replace(/\/+$/, "");
    const t0 = Date.now();
    const hRes = await fetch(`${base}/health`, { signal: AbortSignal.timeout(10_000) });
    if (!hRes.ok) throw new Error(`Remote /health failed with HTTP ${hRes.status}`);

    const sslRes = await fetch(`${base}/ssl-check?host=expired.badssl.com`, { signal: AbortSignal.timeout(10_000) });
    if (!sslRes.ok) throw new Error(`Remote /ssl-check failed with HTTP ${sslRes.status}`);
    const sslJson = await sslRes.json();
    const ms = Date.now() - t0;
    if (sslJson.certificate_valid !== false) {
      throw new Error(`Remote /ssl-check?host=expired.badssl.com returned certificate_valid=${sslJson.certificate_valid}`);
    }
    console.log(`REMOTE_VERIFY_OK (${ms}ms): base_url=${base}`);

    const remoteYamlUrl = process.env.PRIMARY_YAML_URL;
    if (remoteYamlUrl) {
      if (/\/main\/|\/master\//i.test(remoteYamlUrl)) {
        throw new Error(`PRIMARY_YAML_URL must be pinned to a commit SHA, never main/master: ${remoteYamlUrl}`);
      }
      const yRes = await fetch(remoteYamlUrl, { signal: AbortSignal.timeout(10_000) });
      if (!yRes.ok) throw new Error(`Remote yaml_url failed with HTTP ${yRes.status}`);
      const remoteText = await yRes.text();
      const remoteHash = createHash("sha256").update(remoteText, "utf8").digest("hex");
      if (remoteHash !== sha256Hex) {
        throw new Error(`SHA-256 mismatch! local=${sha256Hex} remote=${remoteHash}`);
      }
      console.log(`REMOTE_YAML_SHA256_MATCH: 0x${remoteHash}`);
    }
  }

  console.log(
    JSON.stringify(
      {
        valid: true,
        manifestPath: MANIFEST_PATH,
        slug: doc.slug,
        base_url: doc.base_url,
        supported_intents: intents,
        endpoints: doc.endpoints.map((e) => `${e.method} ${e.path}`),
        yaml_sha256: `0x${sha256Hex}`,
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  console.error("MANIFEST_VALIDATION_FAILED:", err.message || err);
  process.exit(1);
});
