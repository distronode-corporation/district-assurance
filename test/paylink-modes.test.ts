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
      { paymentId: "pay_1", amountMinor: 5000, currency: "cad", mode: "platform", paymentMethods: ["card", "apple_pay", "google_pay", "link"], expiresAt: "2026-01-01T00:31:00.000Z", linkId: "cs_fake_1" },
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
      expiresAt: "2026-01-01T00:30:00.000Z",
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
    assert.equal(t.payments.created[0]!.expiresAt, "2026-01-01T00:30:00.000Z", "twice the life, from the request");
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
    assert.equal(late.payments.created[0]!.expiresAt, "2026-01-01T00:30:00.000Z", "never under the adapter's 30 minutes (review R8)");
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
    assert.equal(t.payments.created[0]!.expiresAt, "2026-01-01T00:30:00.000Z", "Stripe Checkout's 30 minutes, not 10");
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
    assert.throws(engineWith({ modes: [], minLinkMinutes: 0, maxLinkMinutes: 1 }, testConfig()), /does not take platform payments \(it takes: none\)/);
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

  it("refuses on a call that started with paylink off", async () => {
    const t = setup({ config: testConfig((c) => delete (c.modules as Record<string, unknown>).paylink) });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.expirePaymentLinks(callId), rejects("module_disabled"));
  });
});
