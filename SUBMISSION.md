# Telegraph Hackathon Season II — Track 01 Submission (`primary` · Miner `#6184`)

- **Project Name**: `primary` — Deterministic Live TLS & URL Security Verifier
- **Track**: Track 01 — Miners / Providers
- **Builder**: `danielamodu`
- **Repository**: `https://github.com/danielamodu/primary`
- **Live HTTPS Endpoint**: `https://13-60-129-92.sslip.io` (AWS EC2 `t3.micro` `eu-north-1`, Elastic IP `13.60.129.92`, Caddy Let's Encrypt HTTPS, `systemd`, 24/7 15-min uptime cron)

## Verified On-Chain Registration (Ethereum Sepolia Nov 17 Diamond `0x72a70e949362670Bf8bceAd24eFC5b8f950aa08b`)
- **Miner ID**: **`6184`** (`primary-security-verifier`)
- **Supported Intents**: `SSL_VERIFICATION_CERT`, `URL_SCAN_VERDICT`, `URL_SAFE_GENERAL`
- **Bond Approve TX (`5.00 USDC`)**: `0xed28f09dca9314d17fad40eb946e15de7da4f1786b81e6fd8421ad65162dceed`
- **Register TX (`registerMiner`)**: `0x6300f43129b103c81d3c94c302580a5eb5f36c9188db8fe991cbcf802fc1a928` (block `12196101`, `1.00 USDC` bond)
- **Immutable Commit-SHA Manifest**: `https://raw.githubusercontent.com/danielamodu/primary/c0349dce2a24629bb9a260336bbbd2a6bd2f0750/manifest/primary.yaml` (`sha256: 0x3ac4bfb2ce02dec8b58f458fc9422dfc787fa9e8e2468431da5f0595a149a2fd`)

## Why `primary` Exists (Live Ecosystem Proof)
While benchmarking live Telegraph incumbents on Sepolia, top-ranked incumbent `ChainSight` took `$0.01` (`receipt 0x54c1004b...`) and returned **`safe: true`** on Google Safe Browsing's official phishing test page (`https://testsafebrowsing.appspot.com/s/phishing.html`), reproducing Issue `#226` live (posted in [issuecomment-7106548286](https://github.com/telegraphprotocol/bounties/issues/226#issuecomment-7106548286)).

`primary` eliminates stale CT-log lookups and LLM guesswork by performing live `node:tls` X.509 certificate handshakes and deterministic multi-feed URL scanning (URLhaus + OpenPhish + GSB/EICAR + punycode homograph + credential-in-URL + brand typosquat + SSRF blocking).

## Reproducible Proof Artifacts
- [bench/results/BENCHMARK.md](bench/results/BENCHMARK.md) — **99/100 (99.0%)** live on EC2 (`50/50` SSL `100%`, `49/50` URL `98%`, p50 `208ms`, 1 honest miss disclosed)
- [bench/uptime-probe.ts](bench/uptime-probe.ts) — continuous 15-min 24/7 EC2 uptime & accuracy cron
- **Tests**: `npm run typecheck && npm run test:all && node scripts/validate-manifest.mjs` → **12/12 passing (`fail 0`)**
