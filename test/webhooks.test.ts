import { strict as assert } from "node:assert";
import { createHmac } from "node:crypto";
import { describe, it } from "node:test";

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
