export interface ThreatMatch {
  source: string;
  reason: string;
}

// Standard industry security test URLs (Google Safe Browsing test suite & WICAR EICAR)
// Explicitly published by Google and WICAR for verifying URL scanners (fixes live bug #226).
const KNOWN_TEST_THREATS: Array<{ match: (u: URL) => boolean; source: string; reason: string }> = [
  {
    match: (u) => u.hostname === "testsafebrowsing.appspot.com" && /^\/s\/(phishing|malware|unwanted|harmful|soceng)/i.test(u.pathname),
    source: "google_safe_browsing_test_fixture",
    reason: "Google Safe Browsing official malicious/phishing test page",
  },
  {
    match: (u) => u.hostname === "malware.wicar.org" && /eicar/i.test(u.pathname),
    source: "wicar_eicar_test_fixture",
    reason: "WICAR EICAR standard anti-malware test file",
  },
  {
    match: (u) => /(^|\.)eicar\.org$/i.test(u.hostname) && /eicar(\.com|\.zip|\.txt)/i.test(u.pathname),
    source: "eicar_test_fixture",
    reason: "EICAR standard anti-malware test file",
  },
];

function normalizeUrlKey(raw: string): string {
  try {
    const u = new URL(raw.trim());
    const pathname = u.pathname === "/" ? "/" : u.pathname.replace(/\/+$/, "");
    return `${u.protocol}//${u.hostname.toLowerCase()}${u.port ? ":" + u.port : ""}${pathname}${u.search}`;
  } catch {
    return raw.trim().toLowerCase();
  }
}

export class ThreatFeedCache {
  private exactUrls = new Map<string, Set<string>>();
  private maliciousHosts = new Map<string, Set<string>>();
  private lastSyncAt: string | null = null;
  private syncTimer: NodeJS.Timeout | null = null;

  constructor(opts?: { autoSync?: boolean; refreshIntervalMs?: number }) {
    if (opts?.autoSync) {
      void this.syncAll();
      const interval = opts.refreshIntervalMs ?? 30 * 60_000;
      this.syncTimer = setInterval(() => {
        void this.syncAll();
      }, interval);
      this.syncTimer.unref?.();
    }
  }

  stop() {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
  }

  seedUrls(urls: string[], source: string) {
    for (const raw of urls) {
      const trimmed = raw.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const key = normalizeUrlKey(trimmed);
      if (!this.exactUrls.has(key)) this.exactUrls.set(key, new Set());
      this.exactUrls.get(key)!.add(source);
      try {
        const host = new URL(trimmed).hostname.toLowerCase();
        if (host && host !== "sites.google.com" && host !== "docs.google.com" && host !== "github.com" && host !== "raw.githubusercontent.com") {
          if (!this.maliciousHosts.has(host)) this.maliciousHosts.set(host, new Set());
          this.maliciousHosts.get(host)!.add(source);
        }
      } catch {}
    }
  }

  async syncAll(): Promise<{ urlhausCount: number; openphishCount: number; syncedAt: string }> {
    let urlhausCount = 0;
    let openphishCount = 0;

    const fetchFeed = async (url: string, source: string, maxLines = 25_000): Promise<number> => {
      try {
        const res = await fetch(url, {
          headers: { "User-Agent": "primary-telegraph-miner/1.0" },
          signal: AbortSignal.timeout(15_000),
        });
        if (!res.ok) return 0;
        const text = await res.text();
        const lines = text.split(/\r?\n/).filter((l) => l && !l.startsWith("#")).slice(0, maxLines);
        this.seedUrls(lines, source);
        return lines.length;
      } catch {
        return 0;
      }
    };

    [urlhausCount, openphishCount] = await Promise.all([
      fetchFeed("https://urlhaus.abuse.ch/downloads/text_online/", "urlhaus"),
      fetchFeed("https://openphish.com/feed.txt", "openphish"),
    ]);

    this.lastSyncAt = new Date().toISOString();
    return { urlhausCount, openphishCount, syncedAt: this.lastSyncAt };
  }

  check(urlObj: URL): ThreatMatch[] {
    const matches: ThreatMatch[] = [];

    for (const fixture of KNOWN_TEST_THREATS) {
      if (fixture.match(urlObj)) {
        matches.push({ source: fixture.source, reason: fixture.reason });
      }
    }

    const key = normalizeUrlKey(urlObj.href);
    const exactSources = this.exactUrls.get(key);
    if (exactSources) {
      for (const src of exactSources) {
        matches.push({ source: src, reason: `Exact URL listed in ${src} active threat feed` });
      }
    }

    const hostSources = this.maliciousHosts.get(urlObj.hostname.toLowerCase());
    if (hostSources && !exactSources) {
      for (const src of hostSources) {
        matches.push({ source: src, reason: `Host ${urlObj.hostname} listed in ${src} active threat feed` });
      }
    }

    return matches;
  }

  stats() {
    return {
      exactUrlCount: this.exactUrls.size,
      maliciousHostCount: this.maliciousHosts.size,
      lastSyncAt: this.lastSyncAt,
    };
  }
}
