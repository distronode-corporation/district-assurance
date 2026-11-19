// Hostile-pass regressions for #92 (SRV-1, Twilio and Telnyx webhook signatures). P7 failed before
// Twilio skipped auth tokens that are not strings; the rest held.
import { strict as assert } from "node:assert";
import { createHash, createHmac, generateKeyPairSync, sign } from "node:crypto";
import { describe, it } from "node:test";

import { verifyTelnyxSignature, verifyTwilioSignature } from "../src/index.ts";

const now = new Date("2026-11-19T12:00:00.000Z");
const t = Math.floor(now.getTime() / 1000);
const pair = generateKeyPairSync("ed25519");
const KEY = Buffer.from(pair.publicKey.export({ format: "jwk" }).x!, "base64url").toString("base64");
const BODY = '{"data":{"event_type":"call.hangup","id":"e1"}}';
const telnyxSign = (stamp: string, body: string) => sign(null, Buffer.from(`${stamp}|${body}`), pair.privateKey).toString("base64");
const telnyx = (patch: Partial<Parameters<typeof verifyTelnyxSignature>[0]> = {}) =>
  verifyTelnyxSignature({ payload: BODY, signatureHeader: telnyxSign(`${t}`, BODY), timestampHeader: `${t}`, publicKeys: [KEY], now, ...patch });

describe("hostile #92: Telnyx", () => {
  it("P1: a small-order public key (a placeholder of zeros, the identity) never verifies a forged signature", () => {
    const identity = Buffer.alloc(32);
    identity[0] = 1;
    const forged = Buffer.concat([identity, Buffer.alloc(32)]).toString("base64");
    for (const key of [Buffer.alloc(32), identity]) {
      for (let d = -50; d <= 50; d++) {
        const r = verifyTelnyxSignature({ payload: '{"forged":true}', signatureHeader: forged, timestampHeader: `${t + d}`, publicKeys: [key.toString("base64")], now });
        assert.equal(r.ok, false, `${key.toString("hex")} at ${d}`);
      }
    }
  });

  it("P2: a tolerance that is not an integer from 0 to 86,400 is refused, whatever its type", () => {
    for (const toleranceSeconds of ["300", Number.MAX_VALUE, -Number.MIN_VALUE, Number.NEGATIVE_INFINITY, 2 ** 53, {}]) {
      assert.throws(() => telnyx({ toleranceSeconds: toleranceSeconds as number }), /toleranceSeconds must be an integer/, String(toleranceSeconds));
    }
    assert.equal(telnyx({ toleranceSeconds: 0 }).ok, true, "zero: this very second only");
    assert.equal(telnyx({ toleranceSeconds: -0 }).ok, true);
    assert.equal(telnyx({ toleranceSeconds: null as never, now: new Date(now.getTime() + 299_000) }).ok, true, "null is unset: the default 300");
    assert.equal(telnyx({ toleranceSeconds: 0, now: new Date(now.getTime() + 1000) }).ok, false);
  });

  it("P3: a key that matches the format but is not a point is skipped, and the next key still verifies", () => {
    const notAPoint = Buffer.alloc(32, 0xff);
    notAPoint[31] = 0x7f;
    const r = telnyx({ publicKeys: [notAPoint.toString("base64"), KEY] });
    assert.deepEqual(r, { ok: true, timestamp: t });
    assert.deepEqual(telnyx({ publicKeys: [notAPoint.toString("base64")] }), { ok: false, reason: "no_matching_signature" });
  });

  it("P4: a timestamp far in the future or the past, is refused; leading zeros are the same second", () => {
    for (const stamp of ["999999999999", "000000000001", `${t - 301}`]) {
      const r = telnyx({ timestampHeader: stamp, signatureHeader: telnyxSign(stamp, BODY) });
      assert.equal(r.ok, false, stamp);
    }
    const padded = `0${t}`;
    assert.deepEqual(telnyx({ timestampHeader: padded, signatureHeader: telnyxSign(padded, BODY) }), { ok: true, timestamp: t }, "the signed text, read as the same second");
  });

  it("P5: public keys that are not strings are skipped, never thrown on", () => {
    assert.deepEqual(telnyx({ publicKeys: [null, 42, {}, KEY] as never }), { ok: true, timestamp: t });
    assert.deepEqual(telnyx({ publicKeys: [null, 42] as never }), { ok: false, reason: "no_secret" });
  });
});

describe("hostile #92: Twilio", () => {
  const TOKEN = "12345";
  const sig = (data: string) => createHmac("sha1", TOKEN).update(data).digest("base64");
  const twilio = (url: string, payload: string, header: string | undefined) => verifyTwilioSignature({ url, payload, header, authTokens: [TOKEN] });

  it("P6: a signature made for http is refused for the https URL, and for another host", () => {
    assert.equal(twilio("https://voice.example.test/hook", "a=1", sig("http://voice.example.test/hook" + "a1")).ok, false);
    assert.equal(twilio("https://voice.example.test/hook", "a=1", sig("https://other.example.test/hook" + "a1")).ok, false);
    assert.equal(twilio("https://voice.example.test/hook", "a=1", sig("https://voice.example.test/hook" + "a1")).ok, true);
  });

  it("P7: tokens that are not strings, or only empty, are no secret", () => {
    assert.deepEqual(verifyTwilioSignature({ url: "https://x.test/h", payload: "", header: "x", authTokens: [null, 42] as never }), { ok: false, reason: "no_secret" });
  });

  it("P8: a body that adds an unsigned pair, or swaps two values between names, is refused", () => {
    const url = "https://voice.example.test/hook";
    const good = sig(`${url}From+1To+2`);
    assert.equal(twilio(url, "From=%2B1&To=%2B2", good).ok, true);
    assert.equal(twilio(url, "From=%2B1&To=%2B2&Digits=9", good).ok, false);
    assert.equal(twilio(url, "From=%2B2&To=%2B1", good).ok, false);
    // Moving a boundary between name and value: "Fro" "m+1" signs the same bytes as "From" "+1".
    assert.equal(twilio(url, "Fro=m%2B1&To=%2B2", good).ok, true, "Twilio's own scheme: names and values are concatenated");
  });

  it("P9: a bodySHA256 URL with the hash repeated, upper-cased or empty is checked against the body", () => {
    const body = '{"a":1}';
    const hash = (text: string) => createHash("sha256").update(text).digest("hex");
    const url = `https://voice.example.test/hook?bodySHA256=${hash(body)}`;
    assert.equal(twilio(url, body, sig(url)).ok, true);
    const upper = `https://voice.example.test/hook?bodySHA256=${hash(body).toUpperCase()}`;
    assert.equal(twilio(upper, body, sig(upper)).ok, true, "hex in either case");
    const twice = `https://voice.example.test/hook?bodySHA256=${hash("other")}&bodySHA256=${hash(body)}`;
    assert.deepEqual(twilio(twice, body, sig(twice)), { ok: false, reason: "body_hash_mismatch" }, "the first bodySHA256 is the one checked");
    const empty = "https://voice.example.test/hook?bodySHA256=";
    assert.deepEqual(twilio(empty, body, sig(empty)), { ok: false, reason: "body_hash_mismatch" });
  });
});

