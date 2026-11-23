<p align="center">
  <img src="assets/logo.png" alt="primary. Logo" width="210" />
</p>

<h1 align="center">PRIMARY</h1>

---

<h3 align="center">A live, no-guesswork security verifier for websites and links on Telegraph</h3>

<p align="center">
  <img src="https://img.shields.io/badge/node-24%2B-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node.js 24+" />
  <img src="https://img.shields.io/badge/tests-12%20passing-22c55e?style=flat-square" alt="12 passing tests" />
  <img src="https://img.shields.io/badge/benchmark-99%2F100-111827?style=flat-square" alt="99/100 benchmark" />
  <img src="https://img.shields.io/badge/sepolia%20miner-%236184-1d4ed8?style=flat-square" alt="Sepolia Miner #6184" />
  <img src="https://img.shields.io/badge/status-live%2024%2F7%20on%20EC2-f97316?style=flat-square" alt="Live 24/7 on EC2" />
</p>

---

## What is PRIMARY?

When an AI agent or app needs to know **"Is this website safe?"** or **"Is this site's security certificate actually valid right now?"**, it can pay a specialist bot ("Miner") on **Telegraph** (`$0.01`) to check.

**The problem:** Many existing security bots on Telegraph take shortcuts — they read old cached logs or let an AI guess. We literally caught a top-ranked bot on Sepolia taking `$0.01` (`receipt 0x54c1004b…`) and calling **Google's official phishing test page *"safe"*** (reproducing [Issue `#226`](https://github.com/telegraphprotocol/bounties/issues/226#issuecomment-7106548286)).

**What PRIMARY does:** PRIMARY never guesses. It is a fast, always-on server running 24/7 on AWS EC2 (`https://13-60-129-92.sslip.io`) that checks the **real primary source right now**:

1. **Live Website Certificate Check (`SSL_VERIFICATION_CERT`)**: Connects directly to the website over TLS right now and inspects the real X.509 certificate — immediately catching expired, self-signed, untrusted, or wrong-host certificates that old logs miss.
2. **Real-Time Scam & Phishing Link Check (`URL_SCAN_VERDICT` & `URL_SAFE_GENERAL`)**: Checks every URL against live threat feeds (**OpenPhish** + **URLhaus**), official phishing/malware test fixtures (Google Safe Browsing & EICAR), lookalike punycode domains (`xn--…`), fake login tricks (`paypal.com@evil.xyz`), brand typosquats, and live HTTPS certificate health.

---

## Live Endpoints

No API key needed — test the live AWS EC2 server directly:

```bash
# 1. Check server health & loaded live threat feeds
curl -sS https://13-60-129-92.sslip.io/health

# 2. Catch an expired SSL certificate live (returns certificate_valid: false)
curl -sS "https://13-60-129-92.sslip.io/ssl-check?host=expired.badssl.com"

# 3. Catch Google's official phishing test page (#226) (returns safe: false)
curl -sS "https://13-60-129-92.sslip.io/url-scan?url=https://testsafebrowsing.appspot.com/s/phishing.html"

# 4. Get a full plain-English safety verdict on a lookalike domain
curl -sS "https://13-60-129-92.sslip.io/url-safe?url=https://xn--pple-43d.com/login"
```

---

## Live On-Chain Proof (Ethereum Sepolia)

- **Live HTTPS Server**: `https://13-60-129-92.sslip.io` (AWS EC2 `eu-north-1`, Elastic IP `13.60.129.92`, Let's Encrypt HTTPS, `systemd`, 24/7 15-minute uptime monitor)
- **Sepolia Miner ID**: **`#6184`** (`primary-security-verifier`) on Nov 17 Diamond `0x72a70e949362670Bf8bceAd24eFC5b8f950aa08b`
- **Registration TX**: `0x6300f43129b103c81d3c94c302580a5eb5f36c9188db8fe991cbcf802fc1a928` (`1.00 USDC` bond, block `12196101`)
- **Manifest Update TX (`id: 6184`)**: `0x2838268314da52af09da01e54df4efd01c10e0390eca03f5b4805d632eea7d25` (block `12196901`)
- **Immutable Commit-SHA Manifest**: [`manifest/primary.yaml`](https://raw.githubusercontent.com/danielamodu/primary/0d4c5ec/manifest/primary.yaml) (`sha256: 0xa95c90666772834d863464ea85ee069f141f52ef85a74726d5fe292688632e10`)

---

## Benchmark Results

We ran **100 live security tests** directly against `https://13-60-129-92.sslip.io` ([full report](bench/results/BENCHMARK.md) & [raw JSON](bench/results/benchmark-100.json)):

| Check | Vectors Tested | Score | Median Speed (p50) |
| :--- | :---: | :---: | :---: |
| **`SSL_VERIFICATION_CERT`** (30 valid sites + 20 broken/SSRF) | 50 | **50 / 50 (100%)** | `214ms` |
| **`URL_SCAN_VERDICT`** (25 safe + 25 phishing/scam/bad TLS) | 50 | **49 / 50 (98%)** | `201ms` |
| **Overall** | **100** | **99 / 100 (99%)** | **`208ms`** |

*(Honest disclosure: the 1 miss out of 100 was `http://www.wicar.org/data/ms09_002_memory_corruption.html`, reported transparently in [BENCHMARK.md](bench/results/BENCHMARK.md).)*

- **24/7 Uptime Probe**: [bench/uptime-probe.ts](bench/uptime-probe.ts) runs every 15 minutes on EC2 verifying `/health`, expired SSL detection, and phishing detection.

---

## Quickstart

```bash
git clone https://github.com/danielamodu/primary.git && cd primary && npm ci && npm run typecheck && npm run test:all && npm run validate:manifest
```
Expected: **12/12 tests passing (`fail 0`)** and `valid: true`.

---

## Supported Intents & Explicit Limits

PRIMARY serves **3 deterministic Telegraph Intents**:
1. `SSL_VERIFICATION_CERT` (`GET/POST /ssl-check`)
2. `URL_SCAN_VERDICT` (`GET/POST /url-scan`)
3. `URL_SAFE_GENERAL` (`GET/POST /url-safe`)

**Explicit Limits:**
- Does **not** run full headless-browser JavaScript sandboxing on brand-new zero-day phishing pages that are not yet in OpenPhish/URLhaus or caught by heuristic/TLS rules, nor OCSP/CRL revocation lookups beyond Node's live TLS trust store.
- Private, loopback, and cloud metadata IPs (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, etc.) are intentionally blocked for SSRF safety.
- URLs longer than 2,048 characters or hostnames longer than 253 characters return HTTP `400`.
