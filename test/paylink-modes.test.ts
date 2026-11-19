// Paylink's two payment modes, the link life the engine enforces itself, and the allow-list of
// instant payment methods (PAY-7).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { ModuleRegistry } from "../src/core/module.ts";
import { validateConfig } from "../src/core/config.ts";
import { builtInModules } from "../src/modules.ts";
import { paylinkModule } from "../src/pay/paylink.ts";
import { INSTANT_PAYMENT_METHODS, outcomeAccountMatches, paymentMethodErrors } from "../src/pay/payment.ts";
import { parseStripeEvent } from "../src/webhooks/stripe.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { FakePaymentLinks } from "../src/testing/fakes.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const ACCT = "acct_business_1";
const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
const pay = { type: "paylink.request", amountMinor: 5000, currency: "cad", description: "Deposit", amountSource: "price_list" };
const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] };

function withFlow(step: Record<string, unknown>, settings: Record<string, unknown> = { mode: "platform", connectedAccountId: ACCT }): FlowConfig {
  return testConfig((c) => {
    c.modules.paylink = { settings: settings as never };
    c.flows = { deposit: { steps: [verify as never, step as never] } };
  });
}

const registry = () => new ModuleRegistry({ adapters: ["ledger", "records", "carrier", "identity", "messages", "payments", "signer"], modules: builtInModules() });

/** Problems of a config's paylink parts, without their paths. */
function problems(config: FlowConfig): string[] {
  return validateConfig(config, registry()).map((p) => p.replace(/^modules\.paylink\.settings: |^flows\.deposit\.steps\[1\] \(paylink\.request\): /, ""));
}

/** A call on the deposit flow, verified to level 2 and on the paylink step. */
async function onPayStep(t: ReturnType<typeof setup>): Promise<string> {
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  const { callId } = await t.engine.startCall({ flow: "deposit" });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

describe("paylink modes: config", () => {
  it("allows only instant payment methods, saying why the others are refused", () => {
    assert.deepEqual(paymentMethodErrors([...INSTANT_PAYMENT_METHODS]), []);
    const hole: unknown[] = [];
    hole.length = 1;
    for (const bad of [undefined, "card", [], hole, [1]]) assert.deepEqual(paymentMethodErrors(bad), ["paymentMethods must list at least one payment method"]);
    assert.deepEqual(paymentMethodErrors(["card", "card"]), ["paymentMethods has duplicates"]);
    const allowed = "(allowed: card, apple_pay, google_pay, link)";
    assert.deepEqual(paymentMethodErrors(["acss_debit", "interac", "interac_present", "us_bank_account", "bitcoin", "toString"]), [
      `payment method acss_debit is refused: pre-authorized debit settles in days, not during the call ${allowed}`,
      `payment method interac is refused: Interac is not offered for online payments ${allowed}`,
      `payment method interac_present is refused: Interac is not offered for online payments ${allowed}`,
      `payment method us_bank_account is refused: bank debits settle in days, not during the call ${allowed}`,
      `payment method bitcoin is refused: it is not an instant payment method ${allowed}`,
      `payment method toString is refused: it is not an instant payment method ${allowed}`,
    ]);
  });

  it("checks every paylink setting", () => {
    const at = (settings: unknown) => paylinkModule.validateSettings(settings);
    assert.deepEqual(at({ mode: "connect", connectedAccountId: ACCT, linkLifeMinutes: 60, paymentMethods: ["card"], maxAmountMinor: 1 }), []);
    assert.deepEqual(at({ mode: "platform", linkLifeMinutes: 5 }), []);
    assert.deepEqual(at({ mode: "cash", linkLifeMinutes: 4, paymentMethods: ["acss_debit"], x: 1 }), [
      "x is not a paylink setting",
      "mode must be connect or platform",
      "linkLifeMinutes must be an integer from 5 to 60",
      "payment method acss_debit is refused: pre-authorized debit settles in days, not during the call (allowed: card, apple_pay, google_pay, link)",
    ]);
    assert.deepEqual(at({ linkLifeMinutes: 61 }), ["linkLifeMinutes must be an integer from 5 to 60"]);
    assert.deepEqual(at({ linkLifeMinutes: 15.5 }), ["linkLifeMinutes must be an integer from 5 to 60"]);
    assert.deepEqual(at({ mode: "connect" }), ["connect mode needs connectedAccountId in the paylink settings"]);
    for (const bad of [42, "", "acct 1", "a".repeat(256)]) {
      assert.deepEqual(at({ mode: "connect", connectedAccountId: bad }), ["connectedAccountId must be 1 to 255 letters, digits, hyphens or underscores"]);
    }
  });

  it("checks a step's mode, link life and methods, and that connect mode has an account", () => {
    assert.deepEqual(problems(withFlow({ ...pay, mode: "connect", linkLifeMinutes: 10, paymentMethods: ["card", "link"] })), []);
    assert.deepEqual(problems(withFlow({ ...pay, mode: "platform" }, {})), []);
    assert.deepEqual(problems(withFlow({ ...pay, mode: "connect" }, {})), ["connect mode needs connectedAccountId in the paylink settings"]);
    assert.deepEqual(
      problems(
        testConfig((c) => {
          delete (c.modules.paylink as { settings?: unknown }).settings;
          c.flows = { deposit: { steps: [verify as never, { ...pay, mode: "connect" } as never] } };
        }),
      ),
      ["connect mode needs connectedAccountId in the paylink settings"],
    );
    // The settings' own mode applies to a step that names none.
    assert.deepEqual(problems(withFlow(pay, { mode: "connect", connectedAccountId: ACCT })), []);
    // A business account with no mode would quietly charge the platform: refused (review R7).
    assert.deepEqual(problems(withFlow({ ...pay, mode: "connect" }, { connectedAccountId: ACCT })), [
      "connectedAccountId needs an explicit mode: connect, or platform with connect chosen per step",
    ]);
    assert.deepEqual(problems(withFlow({ ...pay, linkLifeMinutes: 0, paymentMethods: ["interac"] })), [
      "linkLifeMinutes must be an integer from 5 to 60",
      "payment method interac is refused: Interac is not offered for online payments (allowed: card, apple_pay, google_pay, link)",
    ]);
    // Settings that did not validate are reported once, and the step is not cross-checked against them.
    assert.deepEqual(problems(withFlow({ ...pay, mode: "connect" }, { mode: "platform", connectedAccountId: 1 })), ["connectedAccountId must be 1 to 255 letters, digits, hyphens or underscores"]);
  });
});

describe("paylink modes: running", () => {
  it("takes a platform payment by default, with the instant methods and a 15 minute life", async () => {
    const t = setup({ config: withFlow(pay, {}) });
    const callId = await onPayStep(t);
    t.clock.advance(60_000);
    const result = await t.engine.requestPayment(callId);
    assert.deepEqual(result, { paymentId: "pay_1", status: "open", expiresAt: "2026-01-01T00:16:00.000Z" });
    assert.deepEqual(t.payments.created, [
      { paymentId: "pay_1", amountMinor: 5000, currency: "cad", mode: "platform", paymentMethods: ["card", "apple_pay", "google_pay", "link"], expiresAt: "2026-01-01T00:36:00.000Z", linkId: "cs_fake_1" },
    ]);
    const sent = (await t.ledger.list()).find((e) => e.event === "payment.link_sent")!;
    assert.deepEqual(sent.detail, { paymentId: "pay_1", linkId: "cs_fake_1", amountMinor: 5000, currency: "cad", amountSource: "price_list", mode: "platform", expiresAt: "2026-01-01T00:16:00.000Z" });
  });

  it("takes a connect payment on the business's account, and its receipt says so", async () => {
    const t = setup({ config: withFlow({ ...pay, mode: "connect", linkLifeMinutes: 5, paymentMethods: ["card"] }) });
    const callId = await onPayStep(t);
    const keys: string[] = [];
    const create = t.payments.createLink.bind(t.payments);
    t.payments.createLink = (input) => {
      keys.push(input.idempotencyKey);
      return create(input);
    };
    const { expiresAt } = await t.engine.requestPayment(callId);
    assert.equal(expiresAt, "2026-01-01T00:05:00.000Z");
    assert.deepEqual(t.payments.created[0], {
      paymentId: "pay_1",
      amountMinor: 5000,
      currency: "cad",
      mode: "connect",
      connectedAccountId: ACCT,
      paymentMethods: ["card"],
      expiresAt: "2026-01-01T00:35:00.000Z",
      linkId: "cs_fake_1",
    });
    assert.deepEqual(JSON.parse(keys[0]!), ["ws_test", callId, "pay_1", "link", "connect"], "the mode is part of the key");
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", account: ACCT }), { applied: true, callId, status: "paid" });
    const receipt = await t.engine.endCall(callId);
    assert.equal(receipt, null, "this flow has no receipt step");
    const settled = (await t.ledger.list()).filter((e) => e.event === "payment.settled");
    assert.equal(settled.length, 1);
  });

  it("takes the mode, account, life and methods from the settings outside a flow", async () => {
    const t = setup({
      config: testConfig((c) => (c.modules.paylink = { settings: { mode: "connect", connectedAccountId: ACCT, linkLifeMinutes: 30, paymentMethods: ["card", "apple_pay"] } })),
    });
    const callId = await verifiedCall(t);
    assert.equal((await t.engine.requestPayment(callId, request)).expiresAt, "2026-01-01T00:30:00.000Z");
    assert.equal(t.payments.created[0]!.mode, "connect");
    assert.equal(t.payments.created[0]!.connectedAccountId, ACCT);
    assert.deepEqual(t.payments.created[0]!.paymentMethods, ["card", "apple_pay"]);
    const receipt = await t.engine.endCall(callId);
    assert.equal(receipt!.body.payments[0]!.mode, "connect");
  });

  it("refuses a connect step whose account was removed from the settings while the call ran", async () => {
    const t = setup({ config: withFlow({ ...pay, mode: "connect" }) });
    const callId = await onPayStep(t);
    t.engine.configure(testConfig((c) => (c.modules.paylink = { settings: {} })));
    await assert.rejects(t.engine.requestPayment(callId), rejects("invalid_input", /connect mode needs connectedAccountId/));
    assert.equal(t.payments.created.length, 0);
  });

  it("ignores an outcome from another account than the payment's, and writes that down", async () => {
    const t = setup({ config: withFlow({ ...pay, mode: "connect" }) });
    const callId = await onPayStep(t);
    await t.engine.requestPayment(callId);
    const linkId = "cs_fake_1";
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId, paymentStatus: "paid" }), { applied: false }, "a platform-endpoint event");
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId, paymentStatus: "paid", account: "acct_other" }), { applied: false });
    const ignored = (await t.ledger.list()).filter((e) => e.event === "payment.outcome_ignored");
    assert.deepEqual(ignored.map((e) => e.detail), [{ paymentId: "pay_1", reason: "account" }, { paymentId: "pay_1", reason: "account" }]);
    assert.equal((await t.engine.state(callId)).phase, "paying");
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId, paymentStatus: "paid", account: ACCT }), { applied: true, callId, status: "paid" });

    const p = setup();
    const platformCall = await verifiedCall(p);
    await p.engine.requestPayment(platformCall, request);
    assert.deepEqual(await p.engine.applyPaymentOutcome({ kind: "expired", linkId: "cs_fake_1", account: ACCT }), { applied: false }, "a connected account's event for a platform payment");
    assert.equal(outcomeAccountMatches({ mode: "platform", connectedAccountId: null }, { kind: "expired", linkId: "x" }), true);
  });

  it("reads the connected account from a Stripe Connect event", () => {
    const body = (extra: Record<string, unknown>) => JSON.stringify({ id: "evt_1", type: "checkout.session.expired", livemode: false, data: { object: { id: "cs_1" } }, ...extra });
    assert.deepEqual(parseStripeEvent(body({ account: ACCT }))!, { eventId: "evt_1", livemode: false, kind: "payment", outcome: { kind: "expired", linkId: "cs_1", account: ACCT } });
    assert.deepEqual(parseStripeEvent(body({ account: 7 }))!, { eventId: "evt_1", livemode: false, kind: "payment", outcome: { kind: "expired", linkId: "cs_1" } });
  });
});

describe("paylink: the engine's own deadline", () => {
  it("expires a texted link at its deadline, at the provider first, and fails the flow", async () => {
    const t = setup({ config: withFlow({ ...pay, mode: "connect", linkLifeMinutes: 10 }) });
    const callId = await onPayStep(t);
    const { expiresAt } = await t.engine.requestPayment(callId);
    t.clock.advance(9 * 60_000);
    assert.deepEqual(await t.engine.expirePaymentLinks(callId), { expired: [] }, "not yet");
    assert.equal(t.payments.expired.length, 0);
    t.clock.advance(60_000);
    assert.equal(t.clock.now().toISOString(), expiresAt);
    assert.deepEqual(await t.engine.expirePaymentLinks(callId), { expired: ["pay_1"] });
    assert.deepEqual(t.payments.expired, [{ linkId: "cs_fake_1", mode: "connect", connectedAccountId: ACCT }]);
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
    assert.equal((await t.engine.state(callId)).phase, "open");
    assert.deepEqual(await t.engine.expirePaymentLinks(callId), { expired: [] }, "settled once");
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "expired", linkId: "cs_fake_1", account: ACCT }), { applied: false }, "Stripe's own expiry later changes nothing");
    const events = (await t.ledger.list()).map((e) => e.event);
    assert.ok(events.includes("payment.link_expired"), "the engine's expiry is in the ledger");
    assert.ok(events.indexOf("payment.link_expired") < events.lastIndexOf("payment.settled"));
  });

  it("leaves a link the provider no longer has open for its webhook, which may say paid", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.requestPayment(callId, request);
    t.payments.settle("cs_fake_1");
    t.clock.advance(15 * 60_000);
    assert.deepEqual(await t.engine.expirePaymentLinks(callId), { expired: [] });
    const expiredEvent = (await t.ledger.list()).find((e) => e.event === "payment.link_expired")!;
    assert.deepEqual(expiredEvent.detail, { paymentId: "pay_1", provider: "not_open" });
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" }), { applied: true, callId, status: "paid" });
  });

  it("never expires a link that was not texted, nor one paid while the provider was asked", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    t.clock.advance(14 * 60_000);
    assert.deepEqual(await t.engine.expirePaymentLinks(callId), { expired: [] }, "never texted: still resumable");
    t.messages.sendText = send;
    await t.engine.requestPayment(callId, request);
    t.clock.advance(15 * 60_000);
    const expire = t.payments.expireLink.bind(t.payments);
    t.payments.expireLink = async (input) => {
      await t.engine.applyPaymentOutcome({ kind: "completed", linkId: input.linkId, paymentStatus: "paid" });
      return expire(input);
    };
    assert.deepEqual(await t.engine.expirePaymentLinks(callId), { expired: [] }, "the payment won");
    assert.equal((await t.engine.endCall(callId))!.body.payments[0]!.status, "paid");
  });

  it("never expires a link whose text never went out, even past its deadline", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    t.clock.advance(61 * 60_000);
    assert.deepEqual(await t.engine.expirePaymentLinks(callId), { expired: [] });
    assert.equal(t.payments.expired.length, 0, "the provider was never asked");
    assert.equal((await t.engine.state(callId)).phase, "paying", "still open, to resume");
  });

  it("gives a text resumed late its full life, never past what the provider was asked for", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    assert.equal(t.payments.created[0]!.expiresAt, "2026-01-01T00:35:00.000Z", "the provider's 30 minutes plus a 5 minute margin, over twice the life");
    t.clock.advance(14 * 60_000);
    t.messages.sendText = send;
    assert.equal((await t.engine.requestPayment(callId, request)).expiresAt, "2026-01-01T00:29:00.000Z", "15 minutes after the text");

    const late = setup({ config: testConfig((c) => (c.modules.paylink = { settings: { linkLifeMinutes: 5 } })) });
    const lateCall = await verifiedCall(late);
    const lateSend = late.messages.sendText.bind(late.messages);
    late.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(late.engine.requestPayment(lateCall, request), /carrier down/);
    late.clock.advance(7 * 60_000);
    late.messages.sendText = lateSend;
    assert.equal(late.payments.created[0]!.expiresAt, "2026-01-01T00:35:00.000Z", "never under the adapter's 30 minutes (review R8), with a margin");
    assert.equal((await late.engine.requestPayment(lateCall, request)).expiresAt, "2026-01-01T00:12:00.000Z", "5 minutes after the text");
  });

  it("never texts a link the provider has, or nearly has, let die: it expires the request instead (review R6)", async () => {
    // An adapter with no minimum of its own: the provider is asked for exactly twice the link life.
    const payments = new FakePaymentLinks({ minLinkMinutes: 0 });
    const t = setup({ adapters: { payments }, config: testConfig((c) => (c.modules.paylink = { settings: { linkLifeMinutes: 5 } })) });
    const callId = await verifiedCall(t);
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    assert.equal(payments.created[0]!.expiresAt, "2026-01-01T00:10:00.000Z");
    t.clock.advance(12 * 60_000);
    t.messages.sendText = send;
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /could not be texted in time/));
    assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 0, "the dead link was never texted");
    assert.deepEqual(payments.expired, [{ linkId: "cs_fake_1", mode: "platform" }], "and it was expired at the provider");
    const state = await t.engine.state(callId);
    assert.equal(state.phase, "open", "the request settled; a new one may follow");
    const ledger = (await t.ledger.list()).find((e) => e.event === "payment.link_expired")!;
    assert.deepEqual(ledger.detail, { paymentId: "pay_1", provider: "expired", reason: "not_sent_in_time" });
    assert.equal((await t.engine.endCall(callId))!.body.payments[0]!.status, "expired");

    // With less than the shortest link life left (6 of 10 minutes gone, 4 left): refused too.
    // In connect mode, so the expiry goes to the business's own account.
    const uPayments = new FakePaymentLinks({ minLinkMinutes: 0 });
    const u = setup({ adapters: { payments: uPayments }, config: testConfig((c) => (c.modules.paylink = { settings: { linkLifeMinutes: 5, mode: "connect", connectedAccountId: ACCT } })) });
    const c2 = await verifiedCall(u);
    const send2 = u.messages.sendText.bind(u.messages);
    u.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(u.engine.requestPayment(c2, request), /carrier down/);
    u.clock.advance(6 * 60_000);
    u.messages.sendText = send2;
    await assert.rejects(u.engine.requestPayment(c2, request), rejects("precondition_failed"));
    assert.deepEqual(uPayments.expired, [{ linkId: "cs_fake_1", mode: "connect", connectedAccountId: ACCT }]);
    // A payment the provider settled first (it answers not_open) is left as it is.
    const vPayments = new FakePaymentLinks({ minLinkMinutes: 0 });
    const v = setup({ adapters: { payments: vPayments }, config: testConfig((c) => (c.modules.paylink = { settings: { linkLifeMinutes: 5 } })) });
    const c3 = await verifiedCall(v);
    const send3 = v.messages.sendText.bind(v.messages);
    v.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(v.engine.requestPayment(c3, request), /carrier down/);
    v.clock.advance(12 * 60_000);
    v.messages.sendText = send3;
    const expire = vPayments.expireLink.bind(vPayments);
    vPayments.expireLink = async (input) => {
      await v.engine.applyPaymentOutcome({ kind: "expired", linkId: input.linkId });
      return expire(input);
    };
    await assert.rejects(v.engine.requestPayment(c3, request), rejects("precondition_failed"));
    assert.equal((await v.ledger.list()).filter((e) => e.event === "payment.link_expired").length, 0, "already settled by the provider");
  });

  it("asks the provider for at least its minimum and at most its maximum link life (review R8)", async () => {
    const t = setup({ config: testConfig((c) => (c.modules.paylink = { settings: { linkLifeMinutes: 5 } })) });
    const callId = await verifiedCall(t);
    const { expiresAt } = await t.engine.requestPayment(callId, request);
    assert.equal(t.payments.created[0]!.expiresAt, "2026-01-01T00:35:00.000Z", "Stripe Checkout's 30 minutes plus a margin, not 10");
    assert.equal(expiresAt, "2026-01-01T00:05:00.000Z", "the engine still closes it at 5");
    const shortPayments = new FakePaymentLinks({ minLinkMinutes: 0, maxLinkMinutes: 20 });
    const short = setup({ adapters: { payments: shortPayments } });
    const c2 = await verifiedCall(short);
    await short.engine.requestPayment(c2, request);
    assert.equal(shortPayments.created[0]!.expiresAt, "2026-01-01T00:20:00.000Z", "twice 15 minutes, held to the adapter's 20");
  });

  it("refuses at save time what the payments adapter declares it cannot do (decision 7)", () => {
    const engineWith = (caps: Record<string, unknown>, config: FlowConfig) => () =>
      setup({ adapters: { payments: Object.assign(new FakePaymentLinks(), { capabilities: caps }) }, config });
    const platformOnly = { modes: ["platform"], minLinkMinutes: 30, maxLinkMinutes: 1440 };
    assert.throws(engineWith(platformOnly, withFlow({ ...pay, mode: "connect" })), (e: unknown) =>
      e instanceof Error && /flows\.deposit\.steps\[1\] \(paylink\.request\): the payments adapter does not take connect payments \(it takes: platform\)/.test(e.message),
    );
    assert.throws(
      engineWith(platformOnly, testConfig((c) => (c.modules.paylink = { settings: { mode: "connect", connectedAccountId: ACCT } }))),
      /modules\.paylink: the payments adapter does not take connect payments/,
    );
    assert.throws(engineWith({ modes: [], minLinkMinutes: 0, maxLinkMinutes: 10 }, testConfig()), /does not take platform payments \(it takes: none\)/);
    // A range the engine's ask (the minimum plus 5 minutes) can never fit in is refused when saved.
    assert.throws(engineWith({ modes: ["platform", "connect"], minLinkMinutes: 30, maxLinkMinutes: 30 }, testConfig()), /maxLinkMinutes must be at least its minLinkMinutes plus 5/);
    assert.doesNotThrow(engineWith({ modes: ["platform", "connect"], minLinkMinutes: 30, maxLinkMinutes: 35 }, testConfig()));
    assert.throws(
      engineWith({ modes: ["platform", "connect"], minLinkMinutes: 0, maxLinkMinutes: 10 }, withFlow({ ...pay, linkLifeMinutes: 15 })),
      /linkLifeMinutes 15 is longer than the payments adapter keeps a link \(10 minutes\)/,
    );
    assert.throws(
      engineWith({ modes: ["platform", "connect"], minLinkMinutes: 0, maxLinkMinutes: 10 }, testConfig()),
      /modules\.paylink: linkLifeMinutes 15 is longer/,
      "the default link life against the adapter too",
    );
    for (const bad of [null, { modes: "platform", minLinkMinutes: 0, maxLinkMinutes: 1 }, { modes: ["cash"], minLinkMinutes: 0, maxLinkMinutes: 1 }, { modes: [], minLinkMinutes: 5, maxLinkMinutes: 1 }, { modes: [], minLinkMinutes: -1, maxLinkMinutes: 1 }]) {
      assert.throws(engineWith(bad as never, testConfig()), /capabilities must be \{ modes, minLinkMinutes, maxLinkMinutes \}/, JSON.stringify(bad));
    }
    // A step whose own mode is invalid is reported for that, not checked against the adapter.
    assert.deepEqual(
      validateConfig(withFlow({ ...pay, mode: "cash" }), new ModuleRegistry({ adapters: ["ledger", "records", "carrier", "identity", "messages", "payments", "signer"], capabilities: { payments: platformOnly }, modules: builtInModules() })),
      ["flows.deposit.steps[1] (paylink.request): mode must be connect or platform"],
    );
  });

  it("expires a request too old to create its link, never asking the provider for less than its minimum", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const create = t.payments.createLink.bind(t.payments);
    t.payments.createLink = async () => {
      throw new Error("provider timed out");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /provider timed out/);
    t.payments.createLink = create;
    // Asked for 00:35; at 00:05:01 less than the provider's 30 minutes is left.
    t.clock.advance(5 * 60_000 + 1000);
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /could not be created in time/));
    assert.equal(t.payments.created.length, 0, "the provider was never asked for a time it refuses");
    const expired = (await t.ledger.list()).find((e) => e.event === "payment.link_expired")!;
    assert.deepEqual(expired.detail, { paymentId: "pay_1", provider: "not_created", reason: "not_created_in_time" });
    assert.equal((await t.engine.state(callId)).phase, "open", "settled: a new request may follow");
    assert.equal((await t.engine.requestPayment(callId, request)).status, "open");
  });

  it("leaves a link the provider no longer has open for its webhook, when it was too late to text", async () => {
    const payments = new FakePaymentLinks({ minLinkMinutes: 0 });
    const t = setup({ adapters: { payments }, config: testConfig((c) => (c.modules.paylink = { settings: { linkLifeMinutes: 5 } })) });
    const callId = await verifiedCall(t);
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    payments.settle("cs_fake_1");
    t.clock.advance(12 * 60_000);
    t.messages.sendText = send;
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed"));
    assert.equal((await t.ledger.list()).find((e) => e.event === "payment.link_expired")!.detail.provider, "not_open");
    assert.equal((await t.engine.state(callId)).phase, "paying", "not settled: the provider's webhook will");
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" }), { applied: true, callId, status: "paid" });
  });

  it("never expires a link another process is texting under its lease", async () => {
    const payments = new FakePaymentLinks({ minLinkMinutes: 0 });
    const t = setup({ adapters: { payments }, config: testConfig((c) => (c.modules.paylink = { settings: { linkLifeMinutes: 5 } })) });
    const callId = await verifiedCall(t);
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    // Resume A claims the text at 00:04:30 (5.5 of 10 minutes left). B comes 40 seconds later, with
    // under 5 minutes left: without the lease it would expire the link A is sending.
    t.clock.advance(270_000);
    let resumeB: Promise<unknown> | null = null;
    t.messages.sendText = async (input) => {
      t.clock.advance(40_000);
      resumeB = t.engine.requestPayment(callId, request);
      await assert.rejects(resumeB, rejects("precondition_failed", /another process is texting/));
      return send(input);
    };
    assert.equal((await t.engine.requestPayment(callId, request)).status, "open", "A delivered it");
    assert.ok(resumeB !== null);
    assert.equal(payments.expired.length, 0, "B never expired the link A was sending");
    // A sender that stopped: once its lease lapses, the next resume may expire the link.
    const u = setup({ adapters: { payments: new FakePaymentLinks({ minLinkMinutes: 0 }) }, config: testConfig((c) => (c.modules.paylink = { settings: { linkLifeMinutes: 5 } })) });
    const c2 = await verifiedCall(u);
    u.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(u.engine.requestPayment(c2, request), /carrier down/);
    u.clock.advance(4 * 60_000);
    await assert.rejects(u.engine.requestPayment(c2, request), /carrier down/, "claimed at 00:04, then stopped");
    u.clock.advance(2 * 60_000);
    await assert.rejects(u.engine.requestPayment(c2, request), rejects("precondition_failed", /could not be texted in time/));
  });

  it("settles a too-old request once when two resumes find it at the same time", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const create = t.payments.createLink.bind(t.payments);
    t.payments.createLink = async () => {
      throw new Error("provider timed out");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /provider timed out/);
    t.payments.createLink = create;
    t.clock.advance(5 * 60_000 + 1000);
    const both = await Promise.allSettled([t.engine.requestPayment(callId, request), t.engine.requestPayment(callId, request)]);
    assert.deepEqual(both.map((r) => r.status), ["rejected", "rejected"]);
    assert.equal((await t.ledger.list()).filter((e) => e.event === "payment.link_expired").length, 1, "settled once");
  });

  it("does not text again a link another resume texted while this one was creating it", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    t.messages.sendText = send;
    const create = t.payments.createLink.bind(t.payments);
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => (release = resolve));
    let creates = 0;
    t.payments.createLink = async (input) => {
      creates++;
      if (creates === 1) await held;
      return create(input);
    };
    const b = t.engine.requestPayment(callId, request);
    await new Promise((resolve) => setImmediate(resolve));
    const a = await t.engine.requestPayment(callId, request);
    release();
    assert.deepEqual(await b, a, "the same delivery, recorded once");
    assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 2, "the text is idempotent by key; sent twice to the fake, once to a real carrier");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "payment.link_sent").length, 1);
  });

  it("never texts a link whose request another process settled while the create was slow, and still records its payment", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const create = t.payments.createLink.bind(t.payments);
    t.payments.createLink = async () => {
      throw new Error("provider timed out");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /provider timed out/);
    // Resume A starts its create at 00:03 and the provider answers late; resume B, at 00:04:01,
    // finds the request too old to create (34 minutes needed, 30:59 left) and expires it.
    t.clock.advance(3 * 60_000);
    let answer: () => void = () => undefined;
    const late = new Promise<void>((resolve) => (answer = resolve));
    t.payments.createLink = async (input) => {
      await late;
      return create(input);
    };
    const a = t.engine.requestPayment(callId, request);
    await new Promise((resolve) => setImmediate(resolve));
    t.clock.advance(60_000 + 1000);
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /created in time/));
    answer();
    await assert.rejects(a, rejects("precondition_failed", /never texted/));
    assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 0, "the live link was never texted");
    assert.deepEqual(t.payments.expired, [{ linkId: "cs_fake_1", mode: "platform" }], "and it was expired at the provider");
    // Should the provider still report it paid (it was live for a moment), the money is recorded.
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" }), { applied: true, callId, status: "paid" });
    const settled = (await t.ledger.list()).filter((e) => e.event === "payment.settled").map((e) => e.detail);
    assert.deepEqual(settled, [
      { paymentId: "pay_1", status: "expired" },
      { paymentId: "pay_1", status: "paid", late: true },
    ]);
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" }), { applied: false }, "once");
  });

  it("records a paid outcome that arrives after the engine's own deadline expired the link, flagged late", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.requestPayment(callId, request);
    t.clock.advance(15 * 60_000);
    assert.deepEqual(await t.engine.expirePaymentLinks(callId), { expired: ["pay_1"] });
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "async_succeeded", linkId: "cs_fake_1" }), { applied: true, callId, status: "paid" });
    assert.equal((await t.engine.endCall(callId))!.body.payments[0]!.status, "paid");
  });

  it("recovers a create the provider refused near its minimum: the next resume expires the request", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    t.payments.createLink = async () => {
      throw new Error("expires_at is less than 30 minutes away");
    };
    // Asked for 00:35 at 00:00. A resume at 00:03:50 still has 31:10 left and tries; the provider
    // refuses (its own latency took it under 30). The next resume, at 00:04:10, expires the request.
    await assert.rejects(t.engine.requestPayment(callId, request), /less than 30 minutes/);
    t.clock.advance(230_000);
    await assert.rejects(t.engine.requestPayment(callId, request), /less than 30 minutes/);
    t.clock.advance(20_000);
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /created in time/));
    assert.equal((await t.engine.state(callId)).phase, "open", "not stuck in paying");
  });

  it("a sender that stalls past its lease texts a link the provider has already expired, never one that can still take money unrecorded", async () => {
    const payments = new FakePaymentLinks({ minLinkMinutes: 0 });
    const t = setup({ adapters: { payments }, config: testConfig((c) => (c.modules.paylink = { settings: { linkLifeMinutes: 5 } })) });
    const callId = await verifiedCall(t);
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    t.clock.advance(270_000);
    t.messages.sendText = async (input) => {
      // A stalls 61 seconds: B finds the lease lapsed, and expires the link at the provider.
      t.clock.advance(61_000);
      await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /texted in time/));
      return send(input);
    };
    await t.engine.requestPayment(callId, request);
    assert.deepEqual(payments.expired.map((e) => e.linkId), ["cs_fake_1"], "the provider closed it before A's text went out");
    assert.equal(await payments.expireLink({ linkId: "cs_fake_1", mode: "platform", idempotencyKey: "k" }).then((r) => r.state), "not_open", "so it cannot be paid");
  });

  it("never expires a request whose link another process created between the check and the write", async () => {
    // A store that runs a hook once, right after the write it is armed for.
    class HookedStore extends MemorySessionStore {
      hook: (() => Promise<void>) | null = null;
      override async compareAndSet(w: string, c: string, v: number, r: JsonValue) {
        const result = await super.compareAndSet(w, c, v, r);
        const run = this.hook;
        if (result.ok && run !== null) {
          this.hook = null;
          await run();
        }
        return result;
      }
    }
    const sessions = new HookedStore();
    const t = setup({ adapters: { sessions } });
    const callId = await verifiedCall(t);
    const create = t.payments.createLink.bind(t.payments);
    t.payments.createLink = async () => {
      throw new Error("provider timed out");
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /provider timed out/);
    // A, at 00:03:50, still has time to create (31:10 left) and its create is slow.
    t.clock.advance(230_000);
    let release: () => void = () => undefined;
    const slow = new Promise<void>((resolve) => (release = resolve));
    t.payments.createLink = async (input) => {
      await slow;
      return create(input);
    };
    const a = t.engine.requestPayment(callId, request);
    await new Promise((resolve) => setImmediate(resolve));
    // B, at 00:04:10, reads the request with no link yet. Right after B's first write, A's create
    // answers and A records the link; B then finds it too old from what it read.
    t.clock.advance(20_000);
    let linked: () => void = () => undefined;
    const aLinked = new Promise<void>((resolve) => (linked = resolve));
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async (input) => {
      linked();
      return send(input);
    };
    sessions.hook = async () => {
      release();
      await aLinked;
    };
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /another process created this payment link meanwhile/));
    assert.equal((await a).status, "open", "A texted its link");
    assert.equal(t.payments.expired.length, 0);
    assert.equal((await t.ledger.list()).filter((e) => e.event === "payment.link_expired").length, 0, "B expired nothing");
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" }), { applied: true, callId, status: "paid" });
  });

  it("refuses a payments adapter that declares no capabilities when the engine is built and when a config is saved", async () => {
    // A plain JavaScript adapter: no types to make it declare anything.
    const bare = { createLink: async () => ({ linkId: "cs_1", url: "https://pay.example.test/c/cs_1" }), expireLink: async () => ({ state: "expired" as const }) };
    const refused = /modules\.paylink: the payments adapter declares no capabilities \(\{ modes, minLinkMinutes, maxLinkMinutes \}\)/;
    assert.throws(() => setup({ adapters: { payments: bare as never } }), refused);
    // Built with paylink off, then a config turning it on: refused at save, never a TypeError mid-call.
    const off = setup({ adapters: { payments: bare as never }, config: testConfig((c) => delete (c.modules as Record<string, unknown>).paylink) });
    assert.throws(() => off.engine.configure(testConfig()), refused);
    // A registry that only knows adapter names cannot tell, and does not refuse.
    assert.deepEqual(validateConfig(testConfig(), new ModuleRegistry({ adapters: ["ledger", "records", "carrier", "identity", "messages", "payments", "signer", "pinVerifier"], modules: builtInModules() })), []);
  });

  it("refuses on a call that started with paylink off", async () => {
    const t = setup({ config: testConfig((c) => delete (c.modules as Record<string, unknown>).paylink) });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.expirePaymentLinks(callId), rejects("module_disabled"));
  });
});
