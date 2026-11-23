import net from "node:net";
import { checkSsl, isPrivateIp } from "./ssl.js";
import { ThreatFeedCache } from "../feeds/cache.js";

export interface PrimaryUrlResponse {
  safe: boolean;
  url: string;
  verdict: "Safe" | "Suspicious" | "Malicious" | "Unknown";
  detections: number;
  signals: string[];
  final_url?: string;
  summary: string;
  as_of: string;
}

const SUSPICIOUS_TLDS = new Set(["xyz", "top", "gq", "tk", "ml", "cf", "ga", "buzz", "click", "zip", "mov", "work", "cfd"]);

const BRAND_IMPERSONATION_PATTERNS: Array<{ brand: string; pattern: RegExp; officialSuffixes: string[] }> = [
  { brand: "paypal", pattern: /payp[a4@][l1i]/i, officialSuffixes: ["paypal.com", "paypalobjects.com"] },
  { brand: "apple", pattern: /\b(app[l1]e|ic[l1]oud)[-a-z0-9]*(verify|login|secure|support|id)/i, officialSuffixes: ["apple.com", "icloud.com"] },
  { brand: "microsoft", pattern: /micr[o0]s[o0]ft[-a-z0-9]*(login|verify|secure|support|365)/i, officialSuffixes: ["microsoft.com", "live.com", "office.com"] },
  { brand: "metamask", pattern: /metam[a4]sk[-a-z0-9]*(wallet|verify|connect|claim|sync|login)/i, officialSuffixes: ["metamask.io"] },
  { brand: "coinbase", pattern: /c[o0]inb[a4]se[-a-z0-9]*(verify|login|secure|support|wallet)/i, officialSuffixes: ["coinbase.com"] },
  { brand: "binance", pattern: /bin[a4]nce[-a-z0-9]*(verify|login|secure|claim|support)/i, officialSuffixes: ["binance.com", "binance.us"] },
];

export function extractUrlFromInput(raw: string): string {
  const s = String(raw || "").trim();
  if (!s) return "";

  const urlMatch = s.match(/https?:\/\/[^\s"'<>]+/i);
  if (urlMatch) {
    return urlMatch[0].replace(/[),.;?!]+$/, "");
  }

  // Bare domain
  const domainMatch = s.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?:\/[^\s"'<>]*)?/i);
  if (domainMatch) {
    const candidate = domainMatch[0].replace(/[),.;?!]+$/, "");
    try {
      return new URL(`https://${candidate}`).href;
    } catch {
      return `https://${candidate}`;
    }
  }

  return s;
}

function isOfficialDomain(host: string, suffixes: string[]): boolean {
  const h = host.toLowerCase();
  return suffixes.some((s) => h === s || h.endsWith(`.${s}`));
}

function runStaticHeuristics(urlObj: URL): { malicious: string[]; suspicious: string[] } {
  const malicious: string[] = [];
  const suspicious: string[] = [];
  const host = urlObj.hostname.toLowerCase();
  const pathAndQuery = `${urlObj.pathname}${urlObj.search}`;

  // 1. Embedded credentials in URL (classic phishing trick: https://paypal.com@evil.xyz)
  if (urlObj.username || urlObj.password) {
    malicious.push("credential_in_url: Embedded username/password authority obfuscation (@)");
  }

  // 2. Punycode / IDN homograph attack
  if (host.split(".").some((label) => label.startsWith("xn--"))) {
    malicious.push(`idn_homograph: Punycode internationalized domain label detected (${host})`);
  }

  // 3. Brand impersonation / typosquatting on non-official domain
  for (const rule of BRAND_IMPERSONATION_PATTERNS) {
    if (rule.pattern.test(host) && !isOfficialDomain(host, rule.officialSuffixes)) {
      malicious.push(`brand_typosquat: Host ${host} impersonates ${rule.brand} outside official domain`);
    }
  }

  // 4. Direct IPv4 URL with executable or login path
  if (net.isIP(host)) {
    if (/\.(exe|scr|bat|ps1|apk|msi|sh)(\?|$)/i.test(pathAndQuery) || /(login|verify|signin|wallet|update)/i.test(pathAndQuery)) {
      malicious.push(`raw_ip_payload: Direct IP host ${host} serving executable or credential path`);
    } else {
      suspicious.push(`raw_ip_host: Direct IP literal URL (${host})`);
    }
  }

  // 5. Suspicious TLD combined with credential/security bait keywords
  const tld = host.split(".").pop() || "";
  if (SUSPICIOUS_TLDS.has(tld) && /(login|verify|secure|account|wallet|claim|update|signin|bank)/i.test(`${host}${pathAndQuery}`)) {
    suspicious.push(`suspicious_tld_bait: High-abuse TLD .${tld} combined with credential/account bait keywords`);
  }

  // 6. Dangerous executable download over plain HTTP
  if (urlObj.protocol === "http:" && /\.(exe|scr|bat|ps1|dll|com)(\?|$)/i.test(urlObj.pathname)) {
    malicious.push(`insecure_executable: Plain HTTP executable payload (${urlObj.pathname})`);
  }

  return { malicious, suspicious };
}

async function checkGoogleSafeBrowsingApi(urlStr: string): Promise<string | null> {
  const apiKey = process.env.SAFE_BROWSING_API_KEY?.trim();
  if (!apiKey) return null;
  try {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "primary-telegraph-miner", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: urlStr }],
        },
      }),
      signal: AbortSignal.timeout(3500),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { matches?: Array<{ threatType?: string }> };
    if (data.matches && data.matches.length > 0) {
      return `google_safe_browsing_v4: Flagged as ${data.matches.map((m) => m.threatType).join(", ")}`;
    }
  } catch {}
  return null;
}

async function unrollRedirects(startUrl: string, maxHops = 4): Promise<{ finalUrl: string; hops: number; httpStatus?: number }> {
  let current = startUrl;
  let hops = 0;
  let lastStatus: number | undefined;
  for (let i = 0; i < maxHops; i++) {
    try {
      const u = new URL(current);
      if (net.isIP(u.hostname) && isPrivateIp(u.hostname)) break;
      const res = await fetch(current, {
        method: "HEAD",
        redirect: "manual",
        headers: { "User-Agent": "primary-telegraph-miner/1.0" },
        signal: AbortSignal.timeout(3500),
      });
      lastStatus = res.status;
      const loc = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && loc) {
        current = new URL(loc, current).href;
        hops++;
        continue;
      }
      break;
    } catch {
      break;
    }
  }
  return { finalUrl: current, hops, httpStatus: lastStatus };
}

export async function scanUrl(
  rawInput: string,
  opts?: { feedCache?: ThreatFeedCache; skipLiveFetch?: boolean }
): Promise<PrimaryUrlResponse> {
  const asOf = new Date().toISOString();
  const extracted = extractUrlFromInput(rawInput);

  let urlObj: URL;
  try {
    urlObj = new URL(extracted);
  } catch {
    return {
      safe: false,
      url: extracted || rawInput,
      verdict: "Unknown",
      detections: 0,
      signals: ["invalid_url: Could not parse a valid HTTP/HTTPS URL"],
      summary: `Could not parse a valid URL from input '${rawInput.slice(0, 80)}'.`,
      as_of: asOf,
    };
  }

  if (urlObj.protocol !== "http:" && urlObj.protocol !== "https:") {
    return {
      safe: false,
      url: urlObj.href,
      verdict: "Suspicious",
      detections: 1,
      signals: [`unsupported_scheme: Non-HTTP(S) scheme ${urlObj.protocol}`],
      summary: `URL uses non-HTTP(S) scheme ${urlObj.protocol} and is treated as unsafe.`,
      as_of: asOf,
    };
  }

  if (urlObj.hostname === "localhost" || (net.isIP(urlObj.hostname) && isPrivateIp(urlObj.hostname))) {
    return {
      safe: false,
      url: urlObj.href,
      verdict: "Suspicious",
      detections: 1,
      signals: ["blocked_private_host: Private or loopback destination"],
      summary: `URL targets a private or loopback host (${urlObj.hostname}).`,
      as_of: asOf,
    };
  }

  const signals: string[] = [];
  let maliciousDetections = 0;
  let suspiciousFlags = 0;

  // 1. Threat feed & authoritative test-fixture checks
  const feedMatches = opts?.feedCache ? opts.feedCache.check(urlObj) : new ThreatFeedCache({ autoSync: false }).check(urlObj);
  for (const m of feedMatches) {
    maliciousDetections++;
    signals.push(`${m.source}: ${m.reason}`);
  }

  // 2. Optional Google Safe Browsing v4 API
  const gsbHit = await checkGoogleSafeBrowsingApi(urlObj.href);
  if (gsbHit) {
    maliciousDetections++;
    signals.push(gsbHit);
  }

  // 3. Static structural phishing/homograph/typosquat heuristics
  const heuristics = runStaticHeuristics(urlObj);
  for (const m of heuristics.malicious) {
    maliciousDetections++;
    signals.push(m);
  }
  for (const s of heuristics.suspicious) {
    suspiciousFlags++;
    signals.push(s);
  }

  // 4. Live redirect unrolling + TLS check (when not already flagged malicious and live fetch enabled)
  let finalUrl = urlObj.href;
  if (!opts?.skipLiveFetch && maliciousDetections === 0) {
    const [redirectInfo, tlsInfo] = await Promise.all([
      unrollRedirects(urlObj.href),
      urlObj.protocol === "https:" ? checkSsl(urlObj.hostname, { timeoutMs: 4000 }) : Promise.resolve(null),
    ]);

    finalUrl = redirectInfo.finalUrl;
    if (finalUrl !== urlObj.href) {
      try {
        const finalObj = new URL(finalUrl);
        const destFeed = opts?.feedCache ? opts.feedCache.check(finalObj) : [];
        for (const m of destFeed) {
          maliciousDetections++;
          signals.push(`redirect_destination_${m.source}: ${m.reason}`);
        }
        const destHeur = runStaticHeuristics(finalObj);
        for (const m of destHeur.malicious) {
          maliciousDetections++;
          signals.push(`redirect_destination_${m}`);
        }
      } catch {}
    }

    if (tlsInfo && !tlsInfo.certificate_valid) {
      suspiciousFlags++;
      signals.push(`invalid_tls: ${tlsInfo.error_reason || "TLS certificate invalid"}`);
    }
  }

  let verdict: PrimaryUrlResponse["verdict"] = "Safe";
  if (maliciousDetections > 0) {
    verdict = "Malicious";
  } else if (suspiciousFlags > 0) {
    verdict = "Suspicious";
  }

  const safe = verdict === "Safe";
  const totalDetections = maliciousDetections + suspiciousFlags;
  const summary = safe
    ? `No phishing, malware, or threat-feed detections found for ${urlObj.hostname}.`
    : `Flagged ${urlObj.href} as ${verdict} (${totalDetections} detection(s)): ${signals.slice(0, 2).join("; ")}.`;

  return {
    safe,
    url: urlObj.href,
    verdict,
    detections: totalDetections,
    signals,
    final_url: finalUrl,
    summary,
    as_of: asOf,
  };
}
