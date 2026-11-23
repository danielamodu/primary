# Primary Miner (#6184) — 100-Vector Live Adversarial Benchmark

- **Endpoint**: `https://13-60-129-92.sslip.io` (AWS EC2 `eu-north-1`, Sepolia Miner `#6184`)
- **Captured**: `2026-11-23T14:04:05.916Z`
- **Overall Accuracy**: **99/100 (99%)**
- **Latency**: p50 = `208ms`, p95 = `4184ms`

| Intent | Vectors | Correct | Accuracy | p50 | p95 |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `SSL_VERIFICATION_CERT` | 50 | 50 | **100%** | 214ms | 4321ms |
| `URL_SCAN_VERDICT` | 50 | 49 | **98%** | 201ms | 2357ms |

## Honest Failure Disclosure
- URL `http://www.wicar.org/data/ms09_002_memory_corruption.html` (wicar_malware_fixture): expected `false`, got `true`
