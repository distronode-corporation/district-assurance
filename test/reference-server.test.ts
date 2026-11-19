// The reference server, over a real socket on 127.0.0.1, and the scripted demo.
import { strict as assert } from "node:assert";
import { createHmac, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { createReferenceServer } from "../examples/reference-server/src/app.ts";
import { runDemo } from "../examples/reference-server/src/demo.ts";
import { StripeCheckoutLinks, StripeIdentityProvider } from "../examples/reference-server/src/stripe-adapters.ts";
import { NotImplementedError, signStripePayload, type Engine } from "../src/index.ts";
import { createTestEngine, type TestEngine } from "../src/testing/index.ts";

const SECRET = "whsec_test_not_a_secret";
const TWILIO_TOKEN = "twilio_token_not_a_secret";
const TWILIO_ORIGIN = "https://voice.example.test";
const TELNYX_PRIVATE = generateKeyPairSync("ed25519").privateKey;
const TELNYX_KEY = Buffer.from(createPublicKey(TELNYX_PRIVATE).export({ format: "jwk" }).x!, "base64url").toString("base64");

describe("reference server", () => {
  let t: TestEngine;
  let base = "";
  let close: () => Promise<void>;

  before(async () => {
    t = createTestEngine();
    const server = createReferenceServer({
      engine: t.engine,
      stripeSecrets: { identity: [SECRET], payments: [] },
      carriers: { twilio: { authTokens: [TWILIO_TOKEN], publicOrigin: TWILIO_ORIGIN }, telnyx: { publicKeys: [TELNYX_KEY] } },
      clock: t.clock,
      maxBodyBytes: 1024,
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    close = () => new Promise((resolve) => server.close(() => resolve()));
  });
  after(() => close());

  const post = (path: string, body: string, headers: Record<string, string> = {}) => fetch(`${base}${path}`, { method: "POST", body, headers });
  const signed = (body: string) => ({ "stripe-signature": signStripePayload(body, SECRET, Math.floor(t.clock.now().getTime() / 1000)) });
  const event = (id: string, type: string, object: Record<string, unknown>) => JSON.stringify({ id, type, data: { object } });

  it("answers health, the key set, and 404 for anything else", async () => {
    assert.deepEqual(await (await fetch(`${base}/healthz`)).json(), { ok: true });
    const keys = (await (await fetch(`${base}/.well-known/receipt-keys.json`)).json()) as { keys: Array<Record<string, unknown>> };
    assert.equal(keys.keys[0]!.kty, "EC");
    assert.equal("d" in keys.keys[0]!, false);
    assert.equal((await fetch(`${base}/nope`)).status, 404);
    assert.equal((await post("/healthz", "")).status, 405);
    assert.equal((await fetch(`${base}/webhooks/stripe/identity`)).status, 405);
  });

  it("verifies Stripe signatures before reading the event", async () => {
    const body = event("evt_1", "identity.verification_session.verified", { id: "vs_unknown" });
    let res = await post("/webhooks/stripe/identity", body);
    assert.equal(res.status, 400);
    assert.deepEqual(await res.json(), { error: "signature", reason: "missing_header" });
    res = await post("/webhooks/stripe/identity", body, { "stripe-signature": signStripePayload(body, "whsec_other", 1767225600) });
    assert.deepEqual(await res.json(), { error: "signature", reason: "no_matching_signature" });
    res = await post("/webhooks/stripe/payments", body, signed(body));
    assert.deepEqual(await res.json(), { error: "signature", reason: "no_secret" }, "an endpoint without a secret refuses everything");
    res = await post("/webhooks/stripe/identity", "{}", signed("{}"));
    assert.deepEqual([res.status, await res.json()], [400, { error: "malformed_event" }]);
  });

  it("applies a signed event once and ignores events of the other kind", async () => {
    const body = event("evt_2", "identity.verification_session.verified", { id: "vs_unknown" });
    assert.deepEqual(await (await post("/webhooks/stripe/identity", body, signed(body))).json(), { received: true, applied: false });
    assert.deepEqual(await (await post("/webhooks/stripe/identity", body, signed(body))).json(), { received: true, duplicate: true });
    const pay = event("evt_3", "checkout.session.expired", { id: "cs_x" });
    assert.deepEqual(await (await post("/webhooks/stripe/identity", pay, signed(pay))).json(), { received: true, applied: false });
  });

  it("refuses a body over the limit", async () => {
    const res = await post("/webhooks/stripe/identity", "x".repeat(5000));
    assert.deepEqual([res.status, await res.json()], [413, { error: "body_too_large" }]);
  });

  it("checks Twilio signatures against the public URL, query included", async () => {
    const body = "CallSid=CA1234567890ABCDE&Digits=1234";
    const url = `${TWILIO_ORIGIN}/webhooks/twilio?foo=1`;
    const signature = createHmac("sha1", TWILIO_TOKEN).update(`${url}CallSidCA1234567890ABCDEDigits1234`).digest("base64");
    const form = { "content-type": "application/x-www-form-urlencoded" };
    let res = await post("/webhooks/twilio?foo=1", body, { ...form, "x-twilio-signature": signature });
    assert.deepEqual([res.status, await res.json()], [200, { received: true }]);
    res = await post("/webhooks/twilio?foo=2", body, { ...form, "x-twilio-signature": signature });
    assert.deepEqual([res.status, await res.json()], [400, { error: "signature", reason: "no_matching_signature" }]);
    res = await post("/webhooks/twilio?foo=1", body, form);
    assert.deepEqual([res.status, await res.json()], [400, { error: "signature", reason: "missing_header" }]);
    assert.equal((await fetch(`${base}/webhooks/twilio`)).status, 405);
  });

  it("checks Telnyx signatures and their timestamp", async () => {
    const body = '{"data":{"event_type":"call.initiated"}}';
    const stamp = `${Math.floor(t.clock.now().getTime() / 1000)}`;
    const signature = sign(null, Buffer.from(`${stamp}|${body}`), TELNYX_PRIVATE).toString("base64");
    let res = await post("/webhooks/telnyx", body, { "telnyx-signature-ed25519": signature, "telnyx-timestamp": stamp });
    assert.deepEqual([res.status, await res.json()], [200, { received: true }]);
    res = await post("/webhooks/telnyx", `${body} `, { "telnyx-signature-ed25519": signature, "telnyx-timestamp": stamp });
    assert.deepEqual([res.status, await res.json()], [400, { error: "signature", reason: "no_matching_signature" }]);
    res = await post("/webhooks/telnyx", body, { "telnyx-signature-ed25519": signature, "telnyx-timestamp": `${Number(stamp) - 301}` });
    assert.deepEqual([res.status, await res.json()], [400, { error: "signature", reason: "timestamp_out_of_tolerance" }]);
    res = await post("/webhooks/telnyx", body);
    assert.deepEqual([res.status, await res.json()], [400, { error: "signature", reason: "missing_header" }]);
  });

  it("serves a receipt once the call ended, 404 before and for unknown calls", async () => {
    const { callId } = await t.engine.startCall();
    assert.equal((await fetch(`${base}/receipts/${callId}`)).status, 404);
    await t.engine.endCall(callId);
    const receipt = (await (await fetch(`${base}/receipts/${callId}`)).json()) as { body: { callId: string } };
    assert.equal(receipt.body.callId, callId);
    assert.equal((await fetch(`${base}/receipts/call_404`)).status, 404);
    assert.equal((await fetch(`${base}/receipts/bad%20id`)).status, 404);
  });

  it("answers 500 without detail when the engine fails", async () => {
    const broken = { receipt: () => { throw new Error("boom"); } } as unknown as Engine;
    const server = createReferenceServer({ engine: broken, stripeSecrets: { identity: [], payments: [] }, clock: t.clock });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const other = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const res = await fetch(`${other}/receipts/c1`);
    assert.deepEqual([res.status, await res.json()], [500, { error: "internal" }]);
    for (const carrier of ["twilio", "telnyx"]) {
      const refused = await fetch(`${other}/webhooks/${carrier}`, { method: "POST", body: "" });
      assert.deepEqual([refused.status, await refused.json()], [400, { error: "signature", reason: "no_secret" }], `${carrier} without keys refuses everything`);
    }
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("demo and Stripe adapters", () => {
  it("runs the owner-command and deposit flows end to end", async () => {
    const result = await runDemo(false);
    assert.equal(result.checksOk, true);
    assert.equal(result.ownerReceipt, null, "owner-command has no receipt step");
    assert.equal(result.tamperedFails, true);
    assert.equal(result.chainOk, true);
    assert.deepEqual(result.receipt.body.verification, { level: 2, methods: ["carrier_identity_match", "keypad_knowledge"] });
    assert.equal(result.receipt.body.payments[0]!.status, "paid");
    assert.equal(result.receipt.body.consents[0]!.purpose, "repair_texts");
  });

  it("has Stripe adapters that are planned, not built", async () => {
    await assert.rejects(new StripeIdentityProvider("rk_test").createDocumentCheck({ callId: "c", idempotencyKey: "k" }), (e: unknown) => e instanceof NotImplementedError && e.issue === "VER-5");
    await assert.rejects(
      new StripeCheckoutLinks("rk_test").createLink({ callId: "c", paymentId: "p", amountMinor: 1, currency: "cad", description: "d", idempotencyKey: "k" }),
      (e: unknown) => e instanceof NotImplementedError && e.issue === "PAY-1",
    );
  });
});
