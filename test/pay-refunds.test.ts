// Refunds and disputes of platform payments (PAY-8): the platform is the merchant, so it refunds
// and answers disputes; connect payments stay the business's.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { EngineEvent } from "../src/core/events.ts";
import type { DisputeOutcome } from "../src/pay/refunds.ts";
import { FakePaymentLinks, type TestEngine } from "../src/testing/index.ts";
import { rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const ACCT = "acct_business_1";
const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
const pay = { type: "paylink.request", amountMinor: 5000, currency: "cad", description: "Deposit", amountSource: "price_list" };
const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] };

/** A verified call with a platform payment of 150.00 CAD, paid; Stripe named payment intent `pi_1`. */
async function paidCall(t: TestEngine): Promise<string> {
  const callId = await verifiedCall(t);
  await t.engine.requestPayment(callId, request);
  assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_1" }), { applied: true, callId, status: "paid" });
  return callId;
}

const dispute = (patch: Partial<DisputeOutcome> = {}): DisputeOutcome => ({
  disputeId: "dp_1",
  chargeId: "ch_1",
  paymentIntentId: "pi_1",
  status: "needs_response",
  amountMinor: 15000,
  currency: "cad",
  ...patch,
});

const entries = async (t: TestEngine, event: string) => (await t.ledger.list()).filter((e) => e.event === event).map((e) => e.detail);

describe("refunds: a late platform payment", () => {
  it("keeps the payment intent of a payment paid after the engine closed its link, so its disputes and refunds still land", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const { paymentId } = await t.engine.requestPayment(callId, request);
    // The call ends: the engine expires the link; a caller already on the page pays anyway.
    t.clock.advance(15 * 60_000);
    assert.deepEqual((await t.engine.expirePaymentLinks(callId)).expired, [paymentId]);
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_late" }), { applied: true, callId, status: "paid" });
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "payment.settled").at(-1)!.detail, { paymentId, status: "paid", late: true });
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ paymentIntentId: "pi_late" })), { applied: true, callId, status: "needs_response" });
    await assert.rejects(t.engine.refundPayment({ callId, paymentId, reason: "requested_by_customer" }), rejects("precondition_failed", /disputed/));
  });
});

describe("refunds: platform payments", () => {
  it("refunds a paid payment in full, with its own idempotency key, and tells the listener", async () => {
    const told: EngineEvent[] = [];
    const t = setup({ onEvent: (e) => told.push(e) });
    const callId = await paidCall(t);
    const keys: string[] = [];
    const refund = t.payments.refund.bind(t.payments);
    t.payments.refund = (input) => {
      keys.push(input.idempotencyKey);
      return refund(input);
    };
    assert.deepEqual(await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer" }), {
      refundId: "ref_1",
      status: "succeeded",
      amountMinor: 15000,
      refundedMinor: 15000,
    });
    assert.deepEqual(t.payments.refunds, [{ linkId: "cs_fake_1", paymentIntentId: "pi_1", mode: "platform", amountMinor: 15000, currency: "cad", reason: "requested_by_customer", refundId: "re_fake_1" }]);
    assert.deepEqual(JSON.parse(keys[0]!), ["ws_test", callId, "pay_1", "refund", "ref_1"]);
    const detail = { paymentId: "pay_1", refundId: "ref_1", providerRef: "re_fake_1", amountMinor: 15000, currency: "cad", reason: "requested_by_customer", status: "succeeded" };
    assert.deepEqual(await entries(t, "payment.refunded"), [detail]);
    assert.deepEqual(told.filter((e) => e.name === "payment.refunded").map((e) => e.detail), [detail], "the host's listener tells the business");
    assert.equal((await t.engine.state(callId)).phase, "open", "a refund changes nothing in the session");
    await assert.rejects(t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate" }), rejects("precondition_failed", /refunded in full/));
  });

  it("refunds in parts, never more in total than was paid", async () => {
    const t = setup();
    const callId = await paidCall(t);
    const refund = (amountMinor?: number) => t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer", ...(amountMinor === undefined ? {} : { amountMinor }) });
    assert.equal((await refund(5000)).refundedMinor, 5000);
    assert.equal((await refund(4000)).refundedMinor, 9000);
    await assert.rejects(refund(6001), rejects("invalid_input", /more than was paid/));
    assert.deepEqual(await refund(), { refundId: "ref_3", status: "succeeded", amountMinor: 6000, refundedMinor: 15000 }, "the rest, by default");
    await assert.rejects(refund(1), rejects("precondition_failed", /refunded in full/));
    assert.deepEqual(
      t.payments.refunds.map((r) => r.amountMinor),
      [5000, 4000, 6000],
    );
  });

  it("refunds by the hosted page when the outcome named no payment intent", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.requestPayment(callId, request);
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" });
    await t.engine.refundPayment({ callId, paymentId: "pay_1", amountMinor: 100, reason: "duplicate" });
    assert.deepEqual(t.payments.refunds, [{ linkId: "cs_fake_1", mode: "platform", amountMinor: 100, currency: "cad", reason: "duplicate", refundId: "re_fake_1" }]);
  });

  it("does not count a refund the provider failed, and records it", async () => {
    const t = setup();
    const callId = await paidCall(t);
    t.payments.refundStatus = "failed";
    assert.deepEqual(await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate" }), { refundId: "ref_1", status: "failed", amountMinor: 15000, refundedMinor: 0 });
    t.payments.refundStatus = "pending";
    assert.deepEqual(await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate" }), { refundId: "ref_2", status: "pending", amountMinor: 15000, refundedMinor: 15000 });
    assert.deepEqual((await entries(t, "payment.refunded")).map((d) => d.status), ["failed", "pending"]);
  });

  it("resumes a repeated request with the same key, so a payment is never refunded twice", async () => {
    const t = setup();
    const callId = await paidCall(t);
    const keys: string[] = [];
    const refund = t.payments.refund.bind(t.payments);
    t.payments.refund = async (input) => {
      keys.push(input.idempotencyKey);
      await refund(input);
      throw new Error("the answer was lost");
    };
    await assert.rejects(t.engine.refundPayment({ callId, paymentId: "pay_1", amountMinor: 5000, reason: "requested_by_customer" }), /the answer was lost/);
    await assert.rejects(
      t.engine.refundPayment({ callId, paymentId: "pay_1", amountMinor: 7000, reason: "requested_by_customer" }),
      rejects("invalid_input", /still being sent/),
    );
    t.payments.refund = (input) => {
      keys.push(input.idempotencyKey);
      return refund(input);
    };
    assert.deepEqual(await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer" }), { refundId: "ref_1", status: "succeeded", amountMinor: 5000, refundedMinor: 5000 });
    assert.equal(keys.length, 2);
    assert.equal(keys[0], keys[1], "the same idempotency key");
    assert.equal(t.payments.refunds.length, 1, "the provider refunded once");
    assert.equal((await entries(t, "payment.refunded")).length, 1);

    // Two resumes at once: the second to commit finds the answer recorded and writes nothing more.
    const u = setup();
    const c2 = await paidCall(u);
    const uRefund = u.payments.refund.bind(u.payments);
    let inner: Promise<unknown> | null = null;
    u.payments.refund = async (input) => {
      if (inner === null) {
        inner = u.engine.refundPayment({ callId: c2, paymentId: "pay_1", reason: "requested_by_customer" });
        await inner;
      }
      return uRefund(input);
    };
    assert.deepEqual(await u.engine.refundPayment({ callId: c2, paymentId: "pay_1", reason: "requested_by_customer" }), { refundId: "ref_1", status: "succeeded", amountMinor: 15000, refundedMinor: 15000 });
    assert.equal(u.payments.refunds.length, 1);
    assert.equal((await entries(u, "payment.refunded")).length, 1);
  });

  it("refunds after the call ended, and leaves the receipt as it was issued", async () => {
    const t = setup();
    const callId = await paidCall(t);
    const receipt = await t.engine.endCall(callId);
    assert.equal(receipt!.body.payments[0]!.status, "paid");
    t.clock.advance(3 * 24 * 3600_000);
    assert.equal((await t.engine.refundPayment({ callId, paymentId: "pay_1", amountMinor: 1000, reason: "requested_by_customer" })).status, "succeeded");
    assert.equal((await t.engine.applyDisputeOutcome(dispute({ disputeId: "dp_9", status: "warning_needs_response" }))).applied, true, "a dispute after the end too");
    assert.deepEqual(await t.engine.receipt(callId), receipt);
    assert.equal((await t.engine.state(callId)).phase, "ended");
  });

  it("refuses what is not a paid platform payment, and anything malformed", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.requestPayment(callId, request);
    const base = { callId, paymentId: "pay_1", reason: "requested_by_customer" as const };
    await assert.rejects(t.engine.refundPayment(base), rejects("precondition_failed", /only a paid payment/));
    await assert.rejects(t.engine.refundPayment({ ...base, paymentId: "pay_x" }), rejects("invalid_input", /no such payment/));
    await assert.rejects(t.engine.refundPayment({ ...base, reason: "goodwill" as never }), rejects("invalid_input", /reason must be one of/));
    for (const amountMinor of [0, -1, 1.5, Number.NaN]) await assert.rejects(t.engine.refundPayment({ ...base, amountMinor }), rejects("invalid_input", /positive integer/));
    await assert.rejects(t.engine.refundPayment({ ...base, callId: "call_x" }), rejects("unknown_call"));
    assert.equal(t.payments.refunds.length, 0);

    const off = setup({ config: testConfig((c) => delete (c.modules as Record<string, unknown>).paylink) });
    const { callId: offCall } = await off.engine.startCall();
    await assert.rejects(off.engine.refundPayment({ ...base, callId: offCall }), rejects("module_disabled"));
  });

  it("refuses an engine whose payments adapter cannot refund (a call paid on another engine)", async () => {
    const t = setup();
    const callId = await paidCall(t);
    const connectOnly = Object.assign(new FakePaymentLinks({ modes: ["connect"] }), { refund: undefined });
    const other = setup({
      adapters: { sessions: t.sessions, ledger: t.ledger, payments: connectOnly },
      config: testConfig((c) => (c.modules.paylink = { settings: { mode: "connect", connectedAccountId: ACCT } })),
    });
    await assert.rejects(other.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate" }), rejects("precondition_failed", /cannot refund/));
  });
});

describe("refunds: disputes", () => {
  it("records a dispute against the payment its payment intent names, and tells the listener", async () => {
    const told: EngineEvent[] = [];
    const t = setup({ onEvent: (e) => told.push(e) });
    const callId = await paidCall(t);
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute()), { applied: true, callId, status: "needs_response" });
    const detail = { paymentId: "pay_1", disputeId: "dp_1", status: "needs_response", amountMinor: 15000, currency: "cad" };
    assert.deepEqual(await entries(t, "payment.disputed"), [detail]);
    assert.deepEqual(told.filter((e) => e.name === "payment.disputed").map((e) => e.detail), [detail]);
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute()), { applied: false }, "the same dispute again changes nothing");
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ status: "under_review" })), { applied: true, callId, status: "under_review" });
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ status: "under_review", amountMinor: 14000 })), { applied: true, callId, status: "under_review" });
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ status: "lost", amountMinor: 14000 })), { applied: true, callId, status: "lost" });
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ status: "under_review" })), { applied: false }, "a lost dispute is final");
    assert.equal((await entries(t, "payment.disputed")).length, 4);
    const record = JSON.stringify(await t.ledger.list());
    assert.equal(record.includes("ch_1"), false, "the charge is how it was found, not what is written");
  });

  it("refuses a refund while a dispute is open or after it was lost, and allows one after it was won", async () => {
    const t = setup();
    const callId = await paidCall(t);
    const refund = () => t.engine.refundPayment({ callId, paymentId: "pay_1", amountMinor: 1000, reason: "requested_by_customer" });
    await t.engine.applyDisputeOutcome(dispute({ status: "warning_needs_response" }));
    await assert.rejects(refund(), rejects("precondition_failed", /disputed/));
    await t.engine.applyDisputeOutcome(dispute({ status: "warning_closed" }));
    assert.equal((await refund()).status, "succeeded", "an inquiry closed without a dispute");
    await t.engine.applyDisputeOutcome(dispute({ disputeId: "dp_2" }));
    await assert.rejects(refund(), rejects("precondition_failed", /disputed/));
    await t.engine.applyDisputeOutcome(dispute({ disputeId: "dp_2", status: "won" }));
    assert.equal((await refund()).refundedMinor, 2000);
    assert.equal(t.payments.refunds.length, 2, "the provider was never asked while disputed");

    const u = setup();
    const c2 = await paidCall(u);
    await u.engine.applyDisputeOutcome(dispute({ status: "lost" }));
    await assert.rejects(u.engine.refundPayment({ callId: c2, paymentId: "pay_1", reason: "duplicate" }), rejects("precondition_failed", /after it was lost/));
  });

  it("keeps a payment intent named by a later paid outcome, and resumes a lost refund though a dispute opened since", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.requestPayment(callId, request);
    // Paid first by an outcome that names no payment intent; the next one names it.
    assert.equal((await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" })).applied, true);
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute()), { applied: false, unbound: true });
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "async_succeeded", linkId: "cs_fake_1", paymentIntentId: "pi_1" }), { applied: false });
    // The provider makes a refund but its answer is lost; a dispute opens; the retry still learns the answer.
    const refund = t.payments.refund.bind(t.payments);
    t.payments.refund = async (input) => {
      await refund(input);
      throw new Error("the answer was lost");
    };
    await assert.rejects(t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer" }), /answer was lost/);
    assert.equal((await t.engine.applyDisputeOutcome(dispute())).applied, true, "the later payment intent was kept");
    t.payments.refund = refund;
    assert.deepEqual(await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer" }), { refundId: "ref_1", status: "succeeded", amountMinor: 15000, refundedMinor: 15000 });
    assert.equal(t.payments.refunds.length, 1, "the provider made it once");
    await assert.rejects(t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate" }), rejects("precondition_failed"));
  });

  it("ignores a dispute it cannot place, and one from a connected account", async () => {
    const t = setup();
    const callId = await paidCall(t);
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ paymentIntentId: null })), { applied: false });
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ paymentIntentId: "pi_other" })), { applied: false, unbound: true }, "not bound (yet): to be delivered again");
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ account: ACCT })), { applied: false });
    assert.deepEqual(await entries(t, "payment.outcome_ignored"), [{ paymentId: "pay_1", reason: "account" }]);
    assert.deepEqual(await entries(t, "payment.disputed"), []);
    assert.equal(typeof callId, "string");
  });

  it("binds the payment intent again when the paid event comes again, and only a paid platform payment's", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.requestPayment(callId, request);
    const bind = t.sessions.bindRef.bind(t.sessions);
    let fail = true;
    t.sessions.bindRef = async (w, ref, c) => {
      if (fail) throw new Error("store down");
      return bind(w, ref, c);
    };
    const paid = { kind: "async_succeeded", linkId: "cs_fake_1", paymentIntentId: "pi_1" } as const;
    await assert.rejects(t.engine.applyPaymentOutcome(paid), /store down/);
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute()), { applied: false, unbound: true }, "not bound yet");
    fail = false;
    assert.deepEqual(await t.engine.applyPaymentOutcome(paid), { applied: false }, "settled once");
    assert.equal((await t.engine.applyDisputeOutcome(dispute())).applied, true, "bound by the event sent again");

    // A failed payment's intent is not kept, nor a connect payment's: its disputes are the business's.
    const f = setup();
    const fCall = await verifiedCall(f);
    await f.engine.requestPayment(fCall, request);
    await f.engine.applyPaymentOutcome({ kind: "async_failed", linkId: "cs_fake_1", paymentIntentId: "pi_1" });
    assert.deepEqual(await f.engine.applyDisputeOutcome(dispute()), { applied: false, unbound: true });

    const connect = setup({ config: testConfig((cfg) => (cfg.modules.paylink = { settings: { mode: "connect", connectedAccountId: ACCT } })) });
    const connectCall = await verifiedCall(connect);
    await connect.engine.requestPayment(connectCall, request);
    assert.deepEqual(
      await connect.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_1", account: ACCT }),
      { applied: true, callId: connectCall, status: "paid" },
    );
    assert.deepEqual(await connect.engine.applyDisputeOutcome(dispute({ account: ACCT })), { applied: false, unbound: true }, "never bound");
    await assert.rejects(connect.engine.refundPayment({ callId: connectCall, paymentId: "pay_1", reason: "duplicate" }), rejects("precondition_failed", /business's/));
    assert.equal(connect.payments.refunds.length, 0);
  });
});

describe("refunds: config", () => {
  it("refuses a platform step, and platform payments outside a flow, when the payments adapter has no refund", () => {
    const noRefund = () => Object.assign(new FakePaymentLinks(), { refund: undefined });
    const flow = testConfig((c) => {
      c.modules.paylink = { settings: { mode: "connect", connectedAccountId: ACCT } };
      c.flows = { deposit: { steps: [verify as never, { ...pay, mode: "platform" } as never] } };
    });
    assert.throws(
      () => setup({ adapters: { payments: noRefund() }, config: flow }),
      (e: unknown) =>
        e instanceof Error && /flows\.deposit\.steps\[1\] \(paylink\.request\): platform payments need a payments adapter with refund/.test(e.message) && !/modules\.paylink/.test(e.message),
    );
    assert.throws(() => setup({ adapters: { payments: noRefund() } }), /modules\.paylink: platform payments need a payments adapter with refund/, "the default mode is platform");
    // Connect mode is unchanged: the business refunds on its own account.
    const connect = testConfig((c) => {
      c.modules.paylink = { settings: { mode: "connect", connectedAccountId: ACCT } };
      c.flows = { deposit: { steps: [verify as never, { ...pay, mode: "connect" } as never] } };
    });
    assert.ok(setup({ adapters: { payments: noRefund() }, config: connect }).engine);
    // A declaration cannot stand in for the method: the engine reads the adapter itself.
    const claims = Object.assign(new FakePaymentLinks(), { refund: undefined, capabilities: { modes: ["platform", "connect"], minLinkMinutes: 30, maxLinkMinutes: 1440, refund: true } });
    assert.throws(() => setup({ adapters: { payments: claims as never } }), /need a payments adapter with refund/);
  });
});
