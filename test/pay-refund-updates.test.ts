// A platform refund's later outcome at the provider (PAY-9, #117, #132): a refund Stripe first
// answers `pending` is brought to its final status by Stripe's refund update events, found by the
// provider's refund id. A pending refund stays reserved; one that fails later is released, so the
// business can refund that amount again; the receipt issued at the end of the call never changes.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { EngineEvent } from "../src/core/events.ts";
import type { RefundOutcome } from "../src/pay/refunds.ts";
import type { TestEngine } from "../src/testing/index.ts";
import { confirmAmount, rejects, setup, verifiedCall } from "./helpers.ts";

const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };

/** A verified call with a platform payment of 150.00 CAD, paid under payment intent `pi_1`. */
async function paidCall(t: TestEngine): Promise<string> {
  const callId = await verifiedCall(t);
  await confirmAmount(t.engine, callId, request);
  await t.engine.requestPayment(callId, request);
  await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_1" });
  return callId;
}

/** The same call with its first refund, in full, answered `pending` (Stripe's `re_fake_1`). */
async function pendingRefund(t: TestEngine): Promise<string> {
  const callId = await paidCall(t);
  t.payments.refundStatus = "pending";
  assert.deepEqual(await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer", sequence: 1 }), {
    refundId: "ref_1",
    status: "pending",
    amountMinor: 15000,
    refundedMinor: 15000,
  });
  return callId;
}

const update = (patch: Partial<RefundOutcome> = {}): RefundOutcome => ({
  providerRef: "re_fake_1",
  paymentIntentId: "pi_1",
  status: "succeeded",
  amountMinor: 15000,
  currency: "cad",
  ...patch,
});

const entries = async (t: TestEngine, event: string) => (await t.ledger.list()).filter((e) => e.event === event).map((e) => e.detail);

describe("refund updates: a pending refund's later outcome", () => {
  it("records a pending refund that later succeeds, once, and tells the listener", async () => {
    const told: EngineEvent[] = [];
    const t = setup({ onEvent: (e) => told.push(e) });
    const callId = await pendingRefund(t);
    assert.deepEqual(await t.engine.applyRefundOutcome(update()), { applied: true, callId, status: "succeeded" });
    const detail = { paymentId: "pay_1", refundId: "ref_1", providerRef: "re_fake_1", amountMinor: 15000, currency: "cad", status: "succeeded" };
    assert.deepEqual(await entries(t, "payment.refund_updated"), [detail]);
    assert.deepEqual(told.filter((e) => e.name === "payment.refund_updated").map((e) => e.detail), [detail]);
    // Final, and still counted: nothing is left to refund.
    await assert.rejects(t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate", sequence: 2 }), rejects("precondition_failed", /in full/));
  });

  it("releases a pending refund that later fails, so the business can refund that amount again", async () => {
    const t = setup();
    const callId = await pendingRefund(t);
    await assert.rejects(t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate", sequence: 2 }), rejects("precondition_failed", /in full/));
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ status: "failed" })), { applied: true, callId, status: "failed" });
    t.payments.refundStatus = "succeeded";
    assert.deepEqual(await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate", sequence: 2 }), {
      refundId: "ref_2",
      status: "succeeded",
      amountMinor: 15000,
      refundedMinor: 15000,
    });
    assert.deepEqual((await entries(t, "payment.refund_updated")).map((d) => d.status), ["failed"]);
  });

  it("reads Stripe's `canceled` as failed: the money was not refunded", async () => {
    const t = setup();
    const callId = await pendingRefund(t);
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ status: "canceled" })), { applied: true, callId, status: "failed" });
  });

  it("applies after the call ended, and leaves the receipt as it was issued", async () => {
    const t = setup();
    const callId = await pendingRefund(t);
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ status: "failed" })), { applied: true, callId, status: "failed" });
    assert.deepEqual(await t.engine.receipt(callId), receipt);
  });

  it("writes nothing again for a repeated event, a still-pending one, or one after the refund failed", async () => {
    const t = setup();
    await pendingRefund(t);
    for (const status of ["pending", "requires_action"] as const) assert.deepEqual(await t.engine.applyRefundOutcome(update({ status })), { applied: false });
    assert.equal((await t.engine.applyRefundOutcome(update())).applied, true);
    assert.deepEqual(await t.engine.applyRefundOutcome(update()), { applied: false });
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ status: "pending" })), { applied: false }, "a succeeded refund never goes back to pending");
    assert.equal((await t.engine.applyRefundOutcome(update({ status: "failed" }))).applied, true);
    // A failed refund is final: a late `succeeded` does not count it again.
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ status: "succeeded" })), { applied: false });
    assert.deepEqual((await entries(t, "payment.refund_updated")).map((d) => d.status), ["succeeded", "failed"]);
  });

  it("releases a refund that succeeded and later failed, as Stripe documents for some card refunds", async () => {
    const t = setup();
    const callId = await pendingRefund(t);
    assert.equal((await t.engine.applyRefundOutcome(update())).applied, true);
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ status: "failed" })), { applied: true, callId, status: "failed" });
    t.payments.refundStatus = "succeeded";
    assert.equal((await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate", sequence: 2 })).status, "succeeded");
  });

  it("does not apply an update for a refund the engine did not make, or one whose amount or currency differs", async () => {
    const t = setup();
    const callId = await paidCall(t);
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ providerRef: "re_by_hand", status: "failed" })), { applied: false }, "a payment with no refund of the engine's");
    t.payments.refundStatus = "pending";
    await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer", sequence: 1 });
    for (const patch of [{ providerRef: "re_by_hand" }, { amountMinor: 100 }, { currency: "usd" }]) {
      assert.deepEqual(await t.engine.applyRefundOutcome(update({ ...patch, status: "failed" })), { applied: false }, JSON.stringify(patch));
    }
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ paymentIntentId: null })), { applied: false });
    assert.deepEqual(await entries(t, "payment.refund_updated"), []);
  });

  it("asks for the event again while the payment is not bound, or while the engine's own refund answer is still on its way", async () => {
    const t = setup();
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ paymentIntentId: "pi_unknown" })), { applied: false, unbound: true });
    const callId = await paidCall(t);
    const refund = t.payments.refund.bind(t.payments);
    t.payments.refund = async (input) => {
      await refund(input);
      throw new Error("the answer was lost");
    };
    t.payments.refundStatus = "pending";
    await assert.rejects(t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate", sequence: 1 }), /the answer was lost/);
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ status: "failed" })), { applied: false, unbound: true });
    // The resume records the provider's first answer; the update then applies.
    t.payments.refund = refund;
    assert.equal((await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate", sequence: 1 })).status, "pending");
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ status: "failed" })), { applied: true, callId, status: "failed" });
  });

  it("ignores a connected account's event and writes it down", async () => {
    const t = setup();
    await pendingRefund(t);
    assert.deepEqual(await t.engine.applyRefundOutcome(update({ account: "acct_1", status: "failed" })), { applied: false });
    assert.deepEqual(await entries(t, "payment.outcome_ignored"), [{ paymentId: "pay_1", reason: "account" }]);
    assert.deepEqual(await entries(t, "payment.refund_updated"), []);
  });

  it("refuses what Stripe's parser would never produce, before any lookup", async () => {
    const t = setup();
    for (const bad of [
      { providerRef: "" },
      { providerRef: 7 },
      { paymentIntentId: 7 },
      { status: "maybe" },
      { amountMinor: -1 },
      { amountMinor: 1.5 },
      { currency: "CAD" },
      { currency: 7 },
      { account: 7 },
    ]) {
      await assert.rejects(t.engine.applyRefundOutcome(update(bad as Partial<RefundOutcome>)), rejects("invalid_input"), JSON.stringify(bad));
    }
  });
});
