import { strict as assert } from "node:assert";
import { createHmac, createPrivateKey, sign, verify } from "node:crypto";
import { describe, it } from "node:test";

import { verifyTelnyxSignature, verifyTwilioSignature } from "../src/webhooks/carrier.ts";
import { parseStripeEvent, signStripePayload, verifyStripeSignature } from "../src/webhooks/stripe.ts";
import { rejects } from "./helpers.ts";

const secret = "whsec_test_not_a_secret";
const payload = '{"id":"evt_1","type":"checkout.session.completed"}';
const now = new Date("2026-01-01T00:00:00.000Z");
const t = Math.floor(now.getTime() / 1000);

describe("verifyStripeSignature", () => {
  it("accepts Stripe's scheme: HMAC-SHA256 of t.payload", () => {
    const v1 = createHmac("sha256", secret).update(`${t}.${payload}`).digest("hex");
    assert.equal(signStripePayload(payload, secret, t), `t=${t},v1=${v1}`);
    assert.deepEqual(verifyStripeSignature({ payload, header: `t=${t},v1=${v1}`, secrets: [secret], now }), { ok: true, timestamp: t });
  });

  it("accepts any v1 against any configured secret, and ignores v0 and junk parts", () => {
    const good = signStripePayload(payload, "whsec_new", t).split(",")[1];
    const header = `t=${t}, v0=abc, junk, v1=${"0".repeat(64)}, ${good}`;
    assert.equal(verifyStripeSignature({ payload, header, secrets: ["", secret, "whsec_new"], now }).ok, true);
  });

  it("refuses each failure with its reason", () => {
    const header = signStripePayload(payload, secret, t);
    const check = (patch: Partial<Parameters<typeof verifyStripeSignature>[0]>) =>
      verifyStripeSignature({ payload, header, secrets: [secret], now, ...patch });
    assert.deepEqual(check({ secrets: [] }), { ok: false, reason: "no_secret" });
    assert.deepEqual(check({ secrets: [""] }), { ok: false, reason: "no_secret" });
    assert.deepEqual(check({ header: null }), { ok: false, reason: "missing_header" });
    assert.deepEqual(check({ header: undefined }), { ok: false, reason: "missing_header" });
    assert.deepEqual(check({ header: "" }), { ok: false, reason: "missing_header" });
    assert.deepEqual(check({ header: "v1=abc" }), { ok: false, reason: "malformed_header" });
    assert.deepEqual(check({ header: `t=${t}` }), { ok: false, reason: "malformed_header" });
    assert.deepEqual(check({ header: `t=1e9,v1=ab` }), { ok: false, reason: "malformed_header" });
    assert.deepEqual(check({ now: new Date(now.getTime() + 301_000) }), { ok: false, reason: "timestamp_out_of_tolerance" });
    assert.deepEqual(check({ now: new Date(now.getTime() - 301_000) }), { ok: false, reason: "timestamp_out_of_tolerance" });
    assert.equal(check({ now: new Date(now.getTime() + 301_000), toleranceSeconds: 600 }).ok, true);
    assert.deepEqual(check({ payload: `${payload} ` }), { ok: false, reason: "no_matching_signature" });
    assert.deepEqual(check({ secrets: ["whsec_other"] }), { ok: false, reason: "no_matching_signature" });
  });

  it("refuses a tolerance or a clock that would accept any age, before checking anything", () => {
    // A signature from a year ago: only a broken tolerance or clock would let it through.
    const old = signStripePayload(payload, secret, t - 365 * 86_400);
    const check = (patch: Partial<Parameters<typeof verifyStripeSignature>[0]>) => () =>
      verifyStripeSignature({ payload, header: old, secrets: [secret], now, ...patch });
    for (const toleranceSeconds of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5, 86_401, "300", null]) {
      assert.throws(check({ toleranceSeconds: toleranceSeconds as number }), rejects("invalid_input", /toleranceSeconds/), String(toleranceSeconds));
    }
    for (const bad of [new Date(Number.NaN), new Date(8.64e15 + 1), null, undefined, 1_767_225_600_000, "2026-01-01"]) {
      assert.throws(check({ now: bad as Date }), rejects("invalid_input", /now/), String(bad));
    }
    // The bounds themselves are fine: 0 accepts only this second, 86,400 a day either way.
    assert.equal(verifyStripeSignature({ payload, header: signStripePayload(payload, secret, t), secrets: [secret], now, toleranceSeconds: 0 }).ok, true);
    assert.deepEqual(verifyStripeSignature({ payload, header: old, secrets: [secret], now, toleranceSeconds: 86_400 }), { ok: false, reason: "timestamp_out_of_tolerance" });
  });
});

const event = (type: string, object: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ id: "evt_1", type, livemode: false, data: { object }, ...extra });

describe("parseStripeEvent", () => {
  it("maps identity outcomes", () => {
    for (const [type, status] of [
      ["identity.verification_session.verified", "verified"],
      ["identity.verification_session.requires_input", "requires_input"],
      ["identity.verification_session.canceled", "canceled"],
    ] as const) {
      assert.deepEqual(parseStripeEvent(event(type, { id: "vs_1" })), {
        eventId: "evt_1",
        livemode: false,
        kind: "identity",
        outcome: { sessionId: "vs_1", status },
      });
    }
  });

  it("maps Checkout outcomes", () => {
    assert.deepEqual(parseStripeEvent(event("checkout.session.completed", { id: "cs_1", payment_status: "paid" }, { livemode: true })), {
      eventId: "evt_1",
      livemode: true,
      kind: "payment",
      outcome: { kind: "completed", linkId: "cs_1", paymentStatus: "paid" },
    });
    assert.deepEqual(parseStripeEvent(event("checkout.session.async_payment_succeeded", { id: "cs_1" }))?.kind, "payment");
    for (const [type, kind] of [
      ["checkout.session.async_payment_succeeded", "async_succeeded"],
      ["checkout.session.async_payment_failed", "async_failed"],
      ["checkout.session.expired", "expired"],
    ] as const) {
      const parsed = parseStripeEvent(event(type, { id: "cs_1" }));
      assert.deepEqual(parsed, { eventId: "evt_1", livemode: false, kind: "payment", outcome: { kind, linkId: "cs_1" } });
    }
  });

  it("carries a Checkout Session's payment intent, which disputes name", () => {
    assert.deepEqual(parseStripeEvent(event("checkout.session.completed", { id: "cs_1", payment_status: "paid", payment_intent: "pi_1" }))!, {
      eventId: "evt_1",
      livemode: false,
      kind: "payment",
      outcome: { kind: "completed", linkId: "cs_1", paymentStatus: "paid", paymentIntentId: "pi_1" },
    });
    assert.deepEqual(parseStripeEvent(event("checkout.session.async_payment_succeeded", { id: "cs_1", payment_intent: null }))!, {
      eventId: "evt_1",
      livemode: false,
      kind: "payment",
      outcome: { kind: "async_succeeded", linkId: "cs_1" },
    });
  });

  it("maps dispute events: the dispute, its charge and payment intent, status and amount, never its evidence", () => {
    const object = { id: "dp_1", object: "dispute", charge: "ch_1", payment_intent: "pi_1", status: "needs_response", amount: 15000, currency: "cad", reason: "fraudulent", evidence: { customer_name: "x" } };
    for (const type of ["charge.dispute.created", "charge.dispute.updated", "charge.dispute.closed", "charge.dispute.funds_withdrawn", "charge.dispute.funds_reinstated"]) {
      assert.deepEqual(parseStripeEvent(event(type, object)), {
        eventId: "evt_1",
        livemode: false,
        kind: "dispute",
        outcome: { disputeId: "dp_1", chargeId: "ch_1", paymentIntentId: "pi_1", status: "needs_response", amountMinor: 15000, currency: "cad" },
      });
    }
    assert.deepEqual(parseStripeEvent(event("charge.dispute.closed", { ...object, status: "won", payment_intent: null }, { account: "acct_1" }))!, {
      eventId: "evt_1",
      livemode: false,
      kind: "dispute",
      outcome: { disputeId: "dp_1", chargeId: "ch_1", paymentIntentId: null, status: "won", amountMinor: 15000, currency: "cad", account: "acct_1" },
    });
    for (const bad of [
      { charge: undefined },
      { charge: 7 },
      { payment_intent: undefined },
      { payment_intent: 7 },
      { status: "maybe" },
      { status: undefined },
      { amount: -1 },
      { amount: 1.5 },
      { amount: "15000" },
      { currency: "CAD" },
      { currency: undefined },
    ]) {
      assert.equal(parseStripeEvent(event("charge.dispute.created", { ...object, ...bad })), null, JSON.stringify(bad));
    }
    assert.equal(parseStripeEvent(event("charge.dispute.something_new", object))!.kind, "ignored");
  });

  it("names other event types as ignored", () => {
    assert.deepEqual(parseStripeEvent(event("charge.refunded", { id: "ch_1" })), { eventId: "evt_1", livemode: false, kind: "ignored", type: "charge.refunded" });
  });

  it("returns null for anything that is not a well-formed event", () => {
    for (const bad of [
      "not json",
      "[]",
      "null",
      JSON.stringify({ type: "x", data: { object: { id: "a" } } }),
      JSON.stringify({ id: "e", data: { object: { id: "a" } } }),
      JSON.stringify({ id: "e", type: "x" }),
      JSON.stringify({ id: "e", type: "x", data: { object: [] } }),
      JSON.stringify({ id: "e", type: "x", data: { object: { id: 1 } } }),
      event("checkout.session.completed", { id: "cs_1" }),
      event("checkout.session.completed", { id: "cs_1", payment_status: "maybe" }),
    ]) {
      assert.equal(parseStripeEvent(bad), null, bad);
    }
  });
});

// Twilio's published examples: the auth token `12345` and the request below, from Twilio's webhook
// security documentation and the test suite of its Node library (twilio-node).
const TWILIO_TOKEN = "12345";
const TWILIO_URL = "https://mycompany.com/myapp.php?foo=1&bar=2";
const twilioForm = (caller: string) =>
  new URLSearchParams({ CallSid: "CA1234567890ABCDE", Caller: caller, Digits: "1234", From: caller, To: "+18005551212" }).toString();
const TWILIO_JSON = '{"property": "value", "boolean": true}';
const TWILIO_JSON_URL = `${TWILIO_URL}&bodySHA256=0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620`;

describe("verifyTwilioSignature", () => {
  const twilio = (url: string, payload: string, header: string | null | undefined, authTokens: readonly string[] = [TWILIO_TOKEN]) =>
    verifyTwilioSignature({ url, payload, header, authTokens });
  const sig = (token: string, data: string) => createHmac("sha1", token).update(data).digest("base64");
  const PARAMS = "CallSidCA1234567890ABCDECaller+12349013030Digits1234From+12349013030To+18005551212";

  it("accepts Twilio's published examples, form and JSON bodies", () => {
    assert.deepEqual(twilio(TWILIO_URL, twilioForm("+12349013030"), "0/KCTR6DLpKmkAf8muzZqo1nDgQ="), { ok: true });
    assert.deepEqual(twilio(TWILIO_URL, twilioForm("+14158675309"), "RSOYDt4T1cUTdK1PDd93/VVr8B8="), { ok: true });
    assert.deepEqual(twilio(TWILIO_JSON_URL, TWILIO_JSON, "a9nBmqA0ju/hNViExpshrM61xv4="), { ok: true });
  });

  it("signs parameters sorted by name, whatever their order in the body, and by value when a name repeats", () => {
    const shuffled = "To=%2B18005551212&Digits=1234&From=%2B12349013030&Caller=%2B12349013030&CallSid=CA1234567890ABCDE";
    assert.equal(twilio(TWILIO_URL, shuffled, "0/KCTR6DLpKmkAf8muzZqo1nDgQ=").ok, true);
    const body = "a=%2B2&A=%2B3&A=b&a=%2B1";
    assert.equal(twilio(TWILIO_URL, body, sig(TWILIO_TOKEN, `${TWILIO_URL}a+1a+2A+3Ab`)).ok, false, "a before A is not code-unit order");
    assert.equal(twilio(TWILIO_URL, body, sig(TWILIO_TOKEN, `${TWILIO_URL}A+3Aba+1a+2`)).ok, true);
    assert.equal(twilio(TWILIO_URL, "b=1&a=1&a=1", sig(TWILIO_TOKEN, `${TWILIO_URL}a1b1`)).ok, true, "a pair sent twice is signed once");
    assert.equal(twilio(TWILIO_URL, "b=1&a=1&a=1", sig(TWILIO_TOKEN, `${TWILIO_URL}a1a1b1`)).ok, false);
    assert.equal(twilio(TWILIO_URL, "a=2&a=1&a=2", sig(TWILIO_TOKEN, `${TWILIO_URL}a1a2`)).ok, true, "distinct values all stay");
  });

  it("accepts the URL with or without the scheme's default port, and without another port", () => {
    const body = twilioForm("+12349013030");
    const signed = (url: string) => sig(TWILIO_TOKEN, url + PARAMS);
    assert.equal(twilio("https://mycompany.com:443/myapp.php?foo=1&bar=2", body, "0/KCTR6DLpKmkAf8muzZqo1nDgQ=").ok, true);
    assert.equal(twilio(TWILIO_URL, body, signed("https://mycompany.com:443/myapp.php?foo=1&bar=2")).ok, true);
    assert.equal(twilio("http://example.test/hook", body, signed("http://example.test:80/hook")).ok, true);
    assert.equal(twilio("http://[::1]/hook", body, signed("http://[::1]:80/hook")).ok, true);
    // Twilio drops a nondefault port when signing HTTPS voice callbacks; it never adds one.
    assert.equal(twilio("https://mycompany.com:8443/myapp.php?foo=1&bar=2", body, "0/KCTR6DLpKmkAf8muzZqo1nDgQ=").ok, true);
    assert.equal(twilio("https://mycompany.com:8443/x", body, signed("https://mycompany.com:8443/x")).ok, true);
    assert.equal(twilio("http://[::1]:8080/hook", body, signed("http://[::1]/hook")).ok, true);
    assert.equal(twilio(TWILIO_URL, body, signed("https://mycompany.com:8443/myapp.php?foo=1&bar=2")).ok, false);
    assert.equal(twilio("https://mycompany.com:8443/x", body, signed("https://mycompany.com:9443/x")).ok, false);
    assert.equal(twilio("/myapp.php", body, signed("/myapp.php")).ok, true, "a URL that is not http(s) is signed as given");
  });

  it("accepts any configured auth token", () => {
    assert.equal(twilio(TWILIO_URL, twilioForm("+12349013030"), "0/KCTR6DLpKmkAf8muzZqo1nDgQ=", ["", "other", TWILIO_TOKEN]).ok, true);
  });

  it("refuses each failure with its reason", () => {
    const body = twilioForm("+12349013030");
    const good = "0/KCTR6DLpKmkAf8muzZqo1nDgQ=";
    assert.deepEqual(twilio(TWILIO_URL, body, good, []), { ok: false, reason: "no_secret" });
    assert.deepEqual(twilio(TWILIO_URL, body, good, [""]), { ok: false, reason: "no_secret" });
    assert.deepEqual(twilio(TWILIO_URL, body, null), { ok: false, reason: "missing_header" });
    assert.deepEqual(twilio(TWILIO_URL, body, undefined), { ok: false, reason: "missing_header" });
    assert.deepEqual(twilio(TWILIO_URL, body, ""), { ok: false, reason: "missing_header" });
    assert.deepEqual(twilio(TWILIO_URL, body, good, ["other"]), { ok: false, reason: "no_matching_signature" });
    assert.deepEqual(twilio(TWILIO_URL, body.replace("1234", "1235"), good), { ok: false, reason: "no_matching_signature" });
    assert.deepEqual(twilio(`${TWILIO_URL}&baz=3`, body, good), { ok: false, reason: "no_matching_signature" });
    assert.deepEqual(twilio(TWILIO_URL, body, good.slice(0, -1)), { ok: false, reason: "no_matching_signature" });
    assert.deepEqual(twilio(TWILIO_URL, body, "é".repeat(28)), { ok: false, reason: "no_matching_signature" });
    // The URL naming bodySHA256 is signed, but the body is not the one it names.
    assert.deepEqual(twilio(TWILIO_JSON_URL, `${TWILIO_JSON} `, "a9nBmqA0ju/hNViExpshrM61xv4="), { ok: false, reason: "body_hash_mismatch" });
    // Under a bodySHA256 URL, form parameters are never part of what is signed.
    assert.deepEqual(twilio(TWILIO_JSON_URL, body, sig(TWILIO_TOKEN, TWILIO_JSON_URL + PARAMS)), { ok: false, reason: "no_matching_signature" });
  });
});

// Telnyx publishes its scheme (Ed25519 over `<telnyx-timestamp>|<raw body>`, base64 headers, a
// base64 public key of 32 raw bytes) but no fixed key and signature to test against. The key pair
// here is RFC 8032's test 1, checked against that RFC's published signature first; the
// Telnyx-format signature below was made with it once and is kept as a fixed vector.
const RFC8032_SECRET = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC8032_EMPTY_SIGNATURE =
  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
const TELNYX_KEY = Buffer.from(RFC8032_PUBLIC, "hex").toString("base64");
const telnyxPrivate = createPrivateKey({
  key: { kty: "OKP", crv: "Ed25519", d: Buffer.from(RFC8032_SECRET, "hex").toString("base64url"), x: Buffer.from(RFC8032_PUBLIC, "hex").toString("base64url") },
  format: "jwk",
});
const TELNYX_BODY = '{"data":{"event_type":"call.initiated","id":"0ccc7b54-4df3-4bca-a65a-3da1ecc777f0","payload":{"call_control_id":"v3:not-a-real-call"}}}';
const TELNYX_SIGNATURE = "aO4v+j1I3BGad/bVvjeIq6ZzHIuErRYS/wMRNHtQcNvvWcJ0j50Nnts1svyA52yyTfcw9tuy3OMRW2S781xaCA==";
const telnyxSign = (stamp: string, body: string) => sign(null, Buffer.from(`${stamp}|${body}`), telnyxPrivate).toString("base64");

describe("verifyTelnyxSignature", () => {
  const telnyx = (patch: Partial<Parameters<typeof verifyTelnyxSignature>[0]> = {}) =>
    verifyTelnyxSignature({ payload: TELNYX_BODY, signatureHeader: TELNYX_SIGNATURE, timestampHeader: `${t}`, publicKeys: [TELNYX_KEY], now, ...patch });

  it("uses RFC 8032's test key pair", () => {
    assert.equal(sign(null, Buffer.alloc(0), telnyxPrivate).toString("hex"), RFC8032_EMPTY_SIGNATURE);
    assert.equal(verify(null, Buffer.alloc(0), telnyxPrivate, Buffer.from(RFC8032_EMPTY_SIGNATURE, "hex")), true);
  });

  it("accepts Telnyx's scheme: Ed25519 over timestamp|payload", () => {
    assert.equal(telnyxSign(`${t}`, TELNYX_BODY), TELNYX_SIGNATURE);
    assert.deepEqual(telnyx(), { ok: true, timestamp: t });
  });

  it("accepts any configured public key, skipping ones that are not 32 bytes of base64", () => {
    const other = Buffer.alloc(32, 7).toString("base64");
    assert.equal(telnyx({ publicKeys: ["", "not a key", other, TELNYX_KEY] }).ok, true);
  });

  it("refuses each failure with its reason", () => {
    assert.deepEqual(telnyx({ publicKeys: [] }), { ok: false, reason: "no_secret" });
    assert.deepEqual(telnyx({ publicKeys: ["", RFC8032_PUBLIC] }), { ok: false, reason: "no_secret" });
    for (const missing of [null, undefined, ""]) {
      assert.deepEqual(telnyx({ signatureHeader: missing }), { ok: false, reason: "missing_header" });
      assert.deepEqual(telnyx({ timestampHeader: missing }), { ok: false, reason: "missing_header" });
    }
    assert.deepEqual(telnyx({ signatureHeader: TELNYX_SIGNATURE.slice(4) }), { ok: false, reason: "malformed_header" });
    assert.deepEqual(telnyx({ signatureHeader: RFC8032_EMPTY_SIGNATURE }), { ok: false, reason: "malformed_header" });
    assert.deepEqual(telnyx({ timestampHeader: "1e9" }), { ok: false, reason: "malformed_header" });
    assert.deepEqual(telnyx({ timestampHeader: ` ${t}` }), { ok: false, reason: "malformed_header" });
    assert.deepEqual(telnyx({ now: new Date(now.getTime() + 301_000) }), { ok: false, reason: "timestamp_out_of_tolerance" });
    assert.deepEqual(telnyx({ now: new Date(now.getTime() - 301_000) }), { ok: false, reason: "timestamp_out_of_tolerance" });
    assert.equal(telnyx({ now: new Date(now.getTime() + 301_000), toleranceSeconds: 600 }).ok, true);
    for (const toleranceSeconds of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5, 86_401]) {
      assert.throws(() => telnyx({ now: new Date(now.getTime() + 10 ** 9), toleranceSeconds }), /toleranceSeconds must be an integer/, String(toleranceSeconds));
    }
    assert.deepEqual(telnyx({ now: new Date(Number.NaN) }), { ok: false, reason: "timestamp_out_of_tolerance" }, "an invalid clock never passes");
    assert.deepEqual(telnyx({ payload: `${TELNYX_BODY} ` }), { ok: false, reason: "no_matching_signature" });
    assert.deepEqual(telnyx({ timestampHeader: `${t + 1}` }), { ok: false, reason: "no_matching_signature" }, "the timestamp is signed");
    assert.deepEqual(telnyx({ publicKeys: [Buffer.alloc(32, 7).toString("base64")] }), { ok: false, reason: "no_matching_signature" });
    assert.deepEqual(telnyx({ signatureHeader: Buffer.alloc(64).toString("base64") }), { ok: false, reason: "no_matching_signature" });
  });

  it("takes one spelling of a signature: a header whose unused trailing bits are set is refused", () => {
    // 64 bytes in base64 leave 4 unused bits in the last character before "==". Node's decoder
    // ignores them, so 16 headers once decoded to one signature; only the one with them zero passes.
    const last = TELNYX_SIGNATURE.at(-3)!;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const value = alphabet.indexOf(last);
    assert.equal(value & 0b1111, 0, "the published vector is the canonical spelling");
    for (let bits = 1; bits < 16; bits++) {
      const header = `${TELNYX_SIGNATURE.slice(0, -3)}${alphabet[value | bits]}==`;
      assert.deepEqual(Buffer.from(header, "base64"), Buffer.from(TELNYX_SIGNATURE, "base64"), "the same signature bytes");
      assert.deepEqual(telnyx({ signatureHeader: header }), { ok: false, reason: "malformed_header" }, header);
    }
    assert.deepEqual(telnyx(), { ok: true, timestamp: t });
  });
});
