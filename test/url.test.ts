import test from "node:test";
import assert from "node:assert/strict";
import { scanUrl, extractUrlFromInput } from "../src/scanners/url.js";
import { ThreatFeedCache } from "../src/feeds/cache.js";

test("extractUrlFromInput handles raw URLs and natural-language questions", () => {
  assert.equal(extractUrlFromInput("https://www.google.com/"), "https://www.google.com/");
  assert.equal(
    extractUrlFromInput("Is the URL http://malware.wicar.org/data/eicar.com safe to visit, with no phishing or malware?"),
    "http://malware.wicar.org/data/eicar.com"
  );
  assert.equal(extractUrlFromInput("example.com"), "https://example.com/");
});

test("scanUrl marks clean comparator sites (google.com, example.com) safe: true", async () => {
  const cache = new ThreatFeedCache({ autoSync: false });
  const [g, ex] = await Promise.all([
    scanUrl("https://www.google.com/", { feedCache: cache, skipLiveFetch: false }),
    scanUrl("https://example.com/", { feedCache: cache, skipLiveFetch: false }),
  ]);
  assert.equal(g.safe, true, `Expected google.com safe, got: ${JSON.stringify(g)}`);
  assert.equal(g.verdict, "Safe");
  assert.equal(g.detections, 0);

  assert.equal(ex.safe, true, `Expected example.com safe, got: ${JSON.stringify(ex)}`);
  assert.equal(ex.verdict, "Safe");
  assert.equal(ex.detections, 0);
});

test("scanUrl catches Google Safe Browsing phishing test page (#226) and WICAR EICAR malware test", async () => {
  const cache = new ThreatFeedCache({ autoSync: false });
  const [gsbPhish, gsbMalware, eicar] = await Promise.all([
    scanUrl("http://testsafebrowsing.appspot.com/s/phishing.html", { feedCache: cache, skipLiveFetch: true }),
    scanUrl("http://testsafebrowsing.appspot.com/s/malware.html", { feedCache: cache, skipLiveFetch: true }),
    scanUrl("http://malware.wicar.org/data/eicar.com", { feedCache: cache, skipLiveFetch: true }),
  ]);
  assert.equal(gsbPhish.safe, false);
  assert.equal(gsbPhish.verdict, "Malicious");
  assert.ok(gsbPhish.detections >= 1);

  assert.equal(gsbMalware.safe, false);
  assert.equal(gsbMalware.verdict, "Malicious");
  assert.ok(gsbMalware.detections >= 1);

  assert.equal(eicar.safe, false);
  assert.equal(eicar.verdict, "Malicious");
  assert.ok(eicar.detections >= 1);
});

test("scanUrl catches punycode homographs, credential-in-URL tricks, brand typosquats, and feed matches", async () => {
  const cache = new ThreatFeedCache({ autoSync: false });
  cache.seedUrls(["https://evil-phish-demo.example/login"], "urlhaus");

  const [homograph, credTrick, typosquat, feedHit] = await Promise.all([
    scanUrl("https://xn--pple-43d.com/login", { feedCache: cache, skipLiveFetch: true }),
    scanUrl("https://www.paypal.com@evil-login.xyz/account", { feedCache: cache, skipLiveFetch: true }),
    scanUrl("https://paypa1-secure-verify.xyz/signin", { feedCache: cache, skipLiveFetch: true }),
    scanUrl("https://evil-phish-demo.example/login", { feedCache: cache, skipLiveFetch: true }),
  ]);

  assert.equal(homograph.safe, false);
  assert.equal(credTrick.safe, false);
  assert.equal(typosquat.safe, false);
  assert.equal(feedHit.safe, false);
  assert.equal(feedHit.verdict, "Malicious");
  assert.ok(feedHit.detections >= 1);
});
