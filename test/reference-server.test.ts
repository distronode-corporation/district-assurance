// The reference server, over a real socket on 127.0.0.1, and the scripted demo.
import { strict as assert } from "node:assert";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { createReferenceServer, securityTxt, type ReferenceServerOptions, type SecurityTxtSettings } from "../examples/reference-server/src/app.ts";
import { runDemo } from "../examples/reference-server/src/demo.ts";
import { StripeCheckoutLinks, StripeIdentityProvider } from "../examples/reference-server/src/stripe-adapters.ts";
import { NotImplementedError, signStripePayload, type Engine } from "../src/index.ts";
import { FixedClock, createTestEngine, type TestEngine } from "../src/testing/index.ts";

const SECRET = "whsec_test_not_a_secret";

describe("reference server", () => {
  let t: TestEngine;
  let base = "";
  let close: () => Promise<void>;

  before(async () => {
    t = createTestEngine();
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [SECRET], payments: [] }, clock: t.clock, maxBodyBytes: 1024 });
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

  it("answers 501 on the carrier webhooks that are not built", async () => {
    const res = await post("/webhooks/twilio", "");
    assert.deepEqual([res.status, await res.json()], [501, { error: "not_implemented", issue: "SRV-1", carrier: "twilio" }]);
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
    const res = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/receipts/c1`);
    assert.deepEqual([res.status, await res.json()], [500, { error: "internal" }]);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("reference server security.txt", () => {
  const DAY = 24 * 60 * 60 * 1000;
  // The fixed clock starts at 2026-01-01T00:00:00Z; every date here is relative to it.
  const settings = (clock: FixedClock, days: number, extra: Partial<SecurityTxtSettings> = {}): SecurityTxtSettings => ({
    contact: ["mailto:security@example.test", "https://example.test/report"],
    expires: new Date(clock.now().getTime() + days * DAY),
    ...extra,
  });
  const start = async (options: Partial<ReferenceServerOptions> & { clock: FixedClock }) => {
    const server = createReferenceServer({ engine: createTestEngine().engine, stripeSecrets: { identity: [], payments: [] }, warn: () => {}, ...options });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return {
      get: (init?: RequestInit) => fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/.well-known/security.txt`, init),
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
  };

  it("serves the host's file as plain text, with every field it was given", async () => {
    const clock = new FixedClock();
    const s = await start({ clock, securityTxt: settings(clock, 200, { policy: "https://example.test/disclosure", canonical: "https://example.test/.well-known/security.txt" }) });
    const res = await s.get();
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "text/plain; charset=utf-8");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.equal(
      await res.text(),
      [
        "Contact: mailto:security@example.test",
        "Contact: https://example.test/report",
        "Expires: 2026-07-20T00:00:00Z",
        "Policy: https://example.test/disclosure",
        "Canonical: https://example.test/.well-known/security.txt",
        "",
      ].join("\n"),
    );
    assert.equal((await s.get({ method: "POST" })).status, 405);
    await s.close();
  });

  it("serves only Contact and Expires when nothing else is set", async () => {
    const clock = new FixedClock();
    const s = await start({ clock, securityTxt: { contact: ["tel:+1-555-0100"], expires: new Date("2026-06-01T12:30:00.000Z") } });
    assert.equal(await (await s.get()).text(), "Contact: tel:+1-555-0100\nExpires: 2026-06-01T12:30:00Z\n");
    await s.close();
  });

  it("keeps nonzero milliseconds in Expires, so the file never claims an earlier expiry than the route enforces", async () => {
    const clock = new FixedClock();
    clock.advance(100);
    const s = await start({ clock, securityTxt: { contact: ["tel:+1-555-0100"], expires: new Date("2026-01-01T00:00:00.900Z") } });
    assert.equal(await (await s.get()).text(), "Contact: tel:+1-555-0100\nExpires: 2026-01-01T00:00:00.900Z\n");
    await s.close();
  });

  it("has no route without settings, and never a default address", async () => {
    const s = await start({ clock: new FixedClock() });
    const res = await s.get();
    assert.deepEqual([res.status, await res.json()], [404, { error: "not_found" }]);
    await s.close();
  });

  it("stops serving the file once it expires while the server runs", async () => {
    const clock = new FixedClock();
    const s = await start({ clock, securityTxt: settings(clock, 100) });
    clock.advance(100 * DAY - 1);
    assert.equal((await s.get()).status, 200);
    clock.advance(1);
    assert.equal((await s.get()).status, 404);
    await s.close();
  });

  it("refuses at start an Expires in the past, now, or more than a year ahead", () => {
    const clock = new FixedClock();
    const make = (securityTxt: SecurityTxtSettings) => () => createReferenceServer({ engine: createTestEngine().engine, stripeSecrets: { identity: [], payments: [] }, clock, securityTxt, warn: () => {} });
    assert.throws(make(settings(clock, -1)), /expires must be in the future/);
    assert.throws(make(settings(clock, 0)), /expires must be in the future/);
    assert.throws(make({ contact: ["mailto:a@example.test"], expires: new Date("not a date") }), /expires must be in the future/);
    assert.throws(make({ contact: ["mailto:a@example.test"], expires: new Date("2027-01-01T00:00:00.001Z") }), /at most a year ahead/);
    assert.doesNotThrow(make({ contact: ["mailto:a@example.test"], expires: new Date("2027-01-01T00:00:00.000Z") }), "exactly a year ahead is allowed");
  });

  it("refuses at start a missing contact and values that are not one-line URIs of an allowed scheme", () => {
    const clock = new FixedClock();
    const make = (extra: Partial<SecurityTxtSettings>) => () => securityTxt(settings(clock, 200, extra), clock.now(), () => {});
    assert.throws(make({ contact: [] }), /at least one contact/);
    assert.throws(make({ contact: ["security@example.test"] }), /contact must be a mailto: or tel: or https: URI/);
    assert.throws(make({ contact: ["http://example.test/report"] }), /contact must be/);
    assert.throws(make({ contact: ["https://example.test/\nPolicy: https://evil.test/"] }), /contact must be/, "a line break would add a field");
    assert.throws(make({ contact: ["mailto:a b@example.test"] }), /contact must be/);
    assert.throws(make({ contact: ["https:example.test/report"] }), /contact must be/, "the URL parser would repair this form");
    assert.throws(make({ contact: ["https:/example.test/report"] }), /contact must be/);
    assert.throws(make({ policy: "https:example.test/disclosure" }), /policy must be/);
    assert.throws(make({ canonical: "https:///example.test/.well-known/security.txt" }), /canonical must be/);
    assert.doesNotThrow(make({ contact: ["mailto:a@example.test", "tel:+1-555-0100", "https://example.test/report"] }));
    assert.throws(make({ policy: "mailto:a@example.test" }), /policy must be a https: URI/);
    assert.throws(make({ canonical: "http://example.test/.well-known/security.txt" }), /canonical must be a https: URI/);
  });

  it("warns at start when the file expires within 30 days, and not before", () => {
    const clock = new FixedClock();
    const warnings: string[] = [];
    const warn = (m: string) => warnings.push(m);
    securityTxt(settings(clock, 31), clock.now(), warn);
    assert.deepEqual(warnings, []);
    securityTxt(settings(clock, 30), clock.now(), warn);
    assert.deepEqual(warnings, ["security.txt expires at 2026-01-31T00:00:00Z: renew it before then"]);
    createReferenceServer({ engine: createTestEngine().engine, stripeSecrets: { identity: [], payments: [] }, clock, securityTxt: settings(clock, 1), warn });
    assert.equal(warnings.length, 2, "the server warns through its warn option");
  });

  it("warns through console.warn by default", (t) => {
    const clock = new FixedClock();
    const spy = t.mock.method(console, "warn", () => {});
    createReferenceServer({ engine: createTestEngine().engine, stripeSecrets: { identity: [], payments: [] }, clock, securityTxt: settings(clock, 7) });
    assert.deepEqual(spy.mock.calls.map((c) => c.arguments), [["security.txt expires at 2026-01-08T00:00:00Z: renew it before then"]]);
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
