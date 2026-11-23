import test from "node:test";
import assert from "node:assert/strict";
import { checkSsl, extractHostFromInput } from "../src/scanners/ssl.js";

test("extractHostFromInput normalizes URLs, ports, and natural-language questions", () => {
  assert.equal(extractHostFromInput("google.com"), "google.com");
  assert.equal(extractHostFromInput("https://expired.badssl.com/path?x=1"), "expired.badssl.com");
  assert.equal(extractHostFromInput("Is the TLS certificate of self-signed.badssl.com currently valid and trusted?"), "self-signed.badssl.com");
  assert.equal(extractHostFromInput("github.com:443"), "github.com");
});

test("checkSsl rejects private/loopback SSRF targets safely", async () => {
  const res = await checkSsl("127.0.0.1");
  assert.equal(res.certificate_valid, false);
  assert.match(res.error_reason || "", /private|loopback|blocked/i);
});

test("checkSsl returns certificate_valid: true for live google.com and github.com", async () => {
  const [g, gh] = await Promise.all([checkSsl("google.com"), checkSsl("github.com")]);
  assert.equal(g.certificate_valid, true, `Expected google.com valid, got: ${JSON.stringify(g)}`);
  assert.ok((g.days_remaining ?? 0) > 0);
  assert.equal(gh.certificate_valid, true, `Expected github.com valid, got: ${JSON.stringify(gh)}`);
  assert.ok((gh.days_remaining ?? 0) > 0);
});

test("checkSsl catches expired, self-signed, and wrong-host badssl.com certificates", async () => {
  const [exp, selfSigned, wrongHost] = await Promise.all([
    checkSsl("expired.badssl.com"),
    checkSsl("self-signed.badssl.com"),
    checkSsl("wrong.host.badssl.com"),
  ]);
  assert.equal(exp.certificate_valid, false, `Expected expired.badssl.com invalid, got: ${JSON.stringify(exp)}`);
  assert.match(exp.error_reason || "", /expired|CERT_HAS_EXPIRED/i);

  assert.equal(selfSigned.certificate_valid, false, `Expected self-signed.badssl.com invalid, got: ${JSON.stringify(selfSigned)}`);
  assert.match(selfSigned.error_reason || "", /self[- ]signed|SELF_SIGNED/i);

  assert.equal(wrongHost.certificate_valid, false, `Expected wrong.host.badssl.com invalid, got: ${JSON.stringify(wrongHost)}`);
  assert.match(wrongHost.error_reason || "", /altname|hostname|mismatch|ERR_TLS_CERT_ALTNAME_INVALID/i);
});

test("checkSsl fails closed cleanly on non-existent domain", async () => {
  const res = await checkSsl("nonexistent-domain-xyz-99999.invalid");
  assert.equal(res.certificate_valid, false);
  assert.ok(res.error_reason && res.error_reason.length > 0);
});
