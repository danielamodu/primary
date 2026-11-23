import tls from "node:tls";
import dns from "node:dns/promises";
import net from "node:net";

export interface PrimarySslResponse {
  certificate_valid: boolean;
  host: string;
  issuer?: string;
  subject_cn?: string;
  valid_from?: string;
  valid_to?: string;
  days_remaining?: number;
  tls_protocol?: string;
  error_reason?: string;
  as_of: string;
}

const PRIVATE_IPV4_PREFIXES = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
];

export function isPrivateIp(ip: string): boolean {
  const clean = ip.toLowerCase().trim();
  if (clean === "::1" || clean === "::" || clean.startsWith("fc") || clean.startsWith("fd") || clean.startsWith("fe80:")) {
    return true;
  }
  return PRIVATE_IPV4_PREFIXES.some((re) => re.test(clean));
}

export function extractHostFromInput(raw: string): string {
  const s = String(raw || "").trim();
  if (!s) return "";

  // 1. Direct URL
  const urlMatch = s.match(/https?:\/\/([^\s/?#"']+)/i);
  if (urlMatch) {
    return urlMatch[1].replace(/:\d+$/, "").replace(/\.+$/, "").toLowerCase();
  }

  // 2. Plain hostname or host:port
  if (/^[a-z0-9.-]+(:\d+)?$/i.test(s) && s.includes(".")) {
    return s.replace(/:\d+$/, "").replace(/\.+$/, "").toLowerCase();
  }

  // 3. Extract hostname from natural-language question
  const domainMatches = s.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi);
  if (domainMatches && domainMatches.length > 0) {
    return domainMatches[0].toLowerCase();
  }

  return s.replace(/:\d+$/, "").toLowerCase();
}

function tlsProbe(
  host: string,
  port: number,
  rejectUnauthorized: boolean,
  timeoutMs: number
): Promise<{
  ok: boolean;
  cert?: tls.PeerCertificate;
  protocol?: string | null;
  errorCode?: string;
  errorMessage?: string;
}> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (res: {
      ok: boolean;
      cert?: tls.PeerCertificate;
      protocol?: string | null;
      errorCode?: string;
      errorMessage?: string;
    }) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {}
      resolve(res);
    };

    const socket = tls.connect(
      {
        host,
        port,
        servername: net.isIP(host) ? undefined : host,
        rejectUnauthorized,
        minVersion: "TLSv1.2",
        timeout: timeoutMs,
      },
      () => {
        const cert = socket.getPeerCertificate(false);
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        const authErr = socket.authorizationError ? String(socket.authorizationError) : undefined;
        finish({
          ok: rejectUnauthorized ? authorized : true,
          cert: cert && Object.keys(cert).length > 0 ? cert : undefined,
          protocol,
          errorCode: authErr,
          errorMessage: authErr,
        });
      }
    );

    socket.setTimeout(timeoutMs, () => {
      finish({ ok: false, errorCode: "ETIMEDOUT", errorMessage: `TLS handshake timed out after ${timeoutMs}ms` });
    });

    socket.on("error", (err: NodeJS.ErrnoException) => {
      finish({
        ok: false,
        errorCode: err.code || err.name,
        errorMessage: err.message,
      });
    });
  });
}

function formatCertMeta(cert?: tls.PeerCertificate) {
  if (!cert) return {};
  const validFrom = cert.valid_from ? new Date(cert.valid_from) : undefined;
  const validTo = cert.valid_to ? new Date(cert.valid_to) : undefined;
  const daysRemaining =
    validTo && !Number.isNaN(validTo.getTime())
      ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000)
      : undefined;

  const issuer = cert.issuer
    ? [cert.issuer.O, cert.issuer.CN].filter(Boolean).join(" / ") || undefined
    : undefined;
  const subjectCn = cert.subject?.CN ? String(cert.subject.CN) : undefined;

  return {
    issuer,
    subject_cn: subjectCn,
    valid_from: validFrom && !Number.isNaN(validFrom.getTime()) ? validFrom.toISOString() : undefined,
    valid_to: validTo && !Number.isNaN(validTo.getTime()) ? validTo.toISOString() : undefined,
    days_remaining: daysRemaining,
  };
}

export async function checkSsl(rawHost: string, opts?: { port?: number; timeoutMs?: number }): Promise<PrimarySslResponse> {
  const asOf = new Date().toISOString();
  const host = extractHostFromInput(rawHost);
  const port = opts?.port ?? 443;
  const timeoutMs = opts?.timeoutMs ?? 6000;

  if (!host || host.length > 253) {
    return { certificate_valid: false, host: host || rawHost, error_reason: "Invalid or empty hostname", as_of: asOf };
  }

  // SSRF protection: block localhost and private/loopback IP literals
  if (host === "localhost" || host.endsWith(".localhost") || (net.isIP(host) && isPrivateIp(host))) {
    return {
      certificate_valid: false,
      host,
      error_reason: "Blocked private or loopback address",
      as_of: asOf,
    };
  }

  // Resolve DNS first to enforce SSRF guard on resolved IPs and catch NXDOMAIN cleanly
  if (!net.isIP(host)) {
    try {
      const addrs = await dns.lookup(host, { all: true });
      if (!addrs.length) {
        return { certificate_valid: false, host, error_reason: "DNS lookup returned no addresses", as_of: asOf };
      }
      if (addrs.some((a) => isPrivateIp(a.address))) {
        return { certificate_valid: false, host, error_reason: "Blocked hostname resolving to private IP", as_of: asOf };
      }
    } catch (err: any) {
      return {
        certificate_valid: false,
        host,
        error_reason: `DNS lookup failed: ${err?.code || err?.message || String(err)}`,
        as_of: asOf,
      };
    }
  }

  // 1. Strict verified TLS handshake (rejectUnauthorized: true) with 1 retry on transient socket reset/timeout
  let strict = await tlsProbe(host, port, true, timeoutMs);
  if (!strict.ok && (strict.errorCode === "ECONNRESET" || strict.errorCode === "ETIMEDOUT")) {
    await new Promise((r) => setTimeout(r, 250));
    strict = await tlsProbe(host, port, true, timeoutMs);
  }
  if (strict.ok && strict.cert) {
    const meta = formatCertMeta(strict.cert);
    const notExpired = meta.days_remaining === undefined || meta.days_remaining >= 0;
    return {
      certificate_valid: notExpired,
      host,
      ...meta,
      tls_protocol: strict.protocol || undefined,
      ...(notExpired ? {} : { error_reason: "Certificate expired" }),
      as_of: asOf,
    };
  }

  // 2. Diagnostic unverified probe to capture certificate issuer/expiry details even when invalid
  const diag = await tlsProbe(host, port, false, Math.min(timeoutMs, 3500));
  const meta = formatCertMeta(diag.cert || strict.cert);
  const reasonParts = [strict.errorCode, strict.errorMessage].filter(Boolean);
  const errorReason = Array.from(new Set(reasonParts)).join(": ") || "TLS certificate validation failed";

  return {
    certificate_valid: false,
    host,
    ...meta,
    tls_protocol: (diag.protocol || strict.protocol) || undefined,
    error_reason: errorReason,
    as_of: asOf,
  };
}
