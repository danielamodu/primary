import { readFileSync } from "node:fs";
import { join } from "node:path";

const readme = readFileSync(join(process.cwd(), "README.md"), "utf8");
const required = [
  "Quickstart",
  "SSL_VERIFICATION_CERT",
  "URL_SCAN_VERDICT",
  "URL_SAFE_GENERAL",
  "Explicit Limits",
  "6184",
  "13-60-129-92.sslip.io",
  "bench/results/BENCHMARK.md",
];

const missing = required.filter((k) => !readme.includes(k));
if (missing.length > 0) {
  console.error("README_CHECK_FAILED missing:", missing);
  process.exit(1);
}
console.log(JSON.stringify({ valid: true, repo: "primary", checkedSections: required.length }));
