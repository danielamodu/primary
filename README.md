# Primary — Deterministic SSL & URL Security Verifier (Telegraph Track 01)

> **10-Second Problem**: Existing Telegraph `SSL_VERIFICATION_CERT` and `URL_SCAN_VERDICT` miners rely on stale Certificate Transparency logs or LLM guesswork — missing expired/self-signed certs and standard phishing fixtures (`#226`).
>
> **Solution**: `primary` is an always-on, deterministic, primary-source Telegraph provider (Sepolia Miner **`#6184`**) that performs **live `node:tls` X.509 handshakes** and **multi-source URL threat scanning** (URLhaus + OpenPhish + GSB/EICAR fixtures + punycode homograph, credential-in-URL, brand typosquat, and live TLS verification).

## Live Deployment & On-Chain Proof
- **Live HTTPS Endpoint**: `https://13-60-129-92.sslip.io` (AWS EC2 `t3.micro` `eu-north-1`, Elastic IP `13.60.129.92`, Caddy Let's Encrypt HTTPS, `systemd`)
- **Sepolia Miner ID**: **`6184`** (`primary-security-verifier`)
- **Nov 17 Diamond**: `0x72a70e949362670Bf8bceAd24eFC5b8f950aa08b` (Ethereum Sepolia `11155111`)
- **Registration TX**: `0x6300f43129b103c81d3c94c302580a5eb5f36c9188db8fe991cbcf802fc1a928` (block `12196101`, `1.00 USDC` bond)
- **Immutable Commit-SHA Manifest**: `https://raw.githubusercontent.com/danielamodu/primary/c0349dce2a24629bb9a260336bbbd2a6bd2f0750/manifest/primary.yaml` (`sha256: 0x3ac4bfb2ce02dec8b58f458fc9422dfc787fa9e8e2468431da5f0595a149a2fd`)

## 2-Minute Quickstart (Verify Live or Run Locally)

### 1. Test Live Production Endpoints
```bash
# Health & loaded threat feed counts
curl -sS https://13-60-129-92.sslip.io/health

# Live TLS handshake catches expired cert (certificate_valid: false)
curl -sS "https://13-60-129-92.sslip.io/ssl-check?host=expired.badssl.com"

# Deterministic URL scanner catches Google Safe Browsing phishing fixture (safe: false)
curl -sS "https://13-60-129-92.sslip.io/url-scan?url=https://testsafebrowsing.appspot.com/s/phishing.html"

# Rich verdict endpoint (URL_SAFE_GENERAL)
curl -sS "https://13-60-129-92.sslip.io/url-safe?url=https://xn--pple-43d.com/login"
```

### 2. Run Locally & Reproduce All Tests
```bash
git clone https://github.com/danielamodu/primary.git
cd primary
npm ci
npm run typecheck
npm run test:all
node scripts/validate-manifest.mjs
```

## Proof Artifacts
- **100-Vector Live Adversarial Benchmark**: [bench/results/BENCHMARK.md](bench/results/BENCHMARK.md) & [bench/results/benchmark-100.json](bench/results/benchmark-100.json)
  - Overall: **99/100 (99.0%)**, p50 latency `208ms`
  - `SSL_VERIFICATION_CERT`: **50/50 (100.0%)** (0 failures across 30 valid HTTPS domains + 20 expired/self-signed/wrong-host/weak-cipher/NXDOMAIN/SSRF targets)
  - `URL_SCAN_VERDICT`: **49/50 (98.0%)** (1 honest miss disclosed: `wicar.org/data/ms09_002_memory_corruption.html`)
- **24/7 Continuous Uptime Probe**: [bench/uptime-probe.ts](bench/uptime-probe.ts) runs every 15 minutes via `cron` on EC2.

## Supported Intents & Explicit Limits
`primary` serves **3 deterministic security intents**:
1. `SSL_VERIFICATION_CERT` (`GET/POST /ssl-check`)
2. `URL_SCAN_VERDICT` (`GET/POST /url-scan`)
3. `URL_SAFE_GENERAL` (`GET/POST /url-safe`)

**Explicit Limits**:
- Does **not** perform OCSP/CRL revocation checks beyond Node's live TLS trust store, nor full headless-browser JavaScript sandboxing of zero-day phishing pages not yet in URLhaus/OpenPhish or heuristic rules.
- Private/loopback/RFC-1918/link-local IPs (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, etc.) are intentionally blocked (`certificate_valid: false` / SSRF protection).
- URLs longer than 2048 characters or hostnames longer than 253 characters are rejected with HTTP `400`.
