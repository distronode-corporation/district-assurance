// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile-pass regressions for #116 (PAY-8): refunds and disputes of platform payments.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { TestEngine } from "../src/testing/index.ts";
import { confirmAmount, PHONE_ON_FILE, rejects, setup, verifiedCall } from "./helpers.ts";

const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
const base = { disputeId: "dp_1", chargeId: "ch_1", paymentIntentId: "pi_1", status: "needs_response" as const, amountMinor: 15000, currency: "cad" };

async function paidCall(t: TestEngine): Promise<{ callId: string; paymentId: string }> {
  const callId = await verifiedCall(t);
  await confirmAmount(t.engine, callId, request);
  const { paymentId } = await t.engine.requestPayment(callId, request);
  await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_1" });
  return { callId, paymentId };
}

describe("hostile #116: disputes", () => {
  it("refuses a dispute outcome the provider could never send, before anything is looked up or written", async () => {
    const t = setup();
    const { callId, paymentId } = await paidCall(t);
    const entries = (await t.ledger.list()).length;
    const bad: unknown[] = [
      { ...base, status: "lost " },
      { ...base, status: PHONE_ON_FILE },
      { ...base, status: "__proto__" },
      { ...base, amountMinor: Number.NaN },
      { ...base, amountMinor: -1 },
      { ...base, amountMinor: 1.5 },
      { ...base, currency: "CAD" },
      { ...base, currency: "‮cad" },
      { ...base, disputeId: "" },
      { ...base, disputeId: 7 },
      { ...base, paymentIntentId: 7 },
    ];
    for (const outcome of bad) await assert.rejects(t.engine.applyDisputeOutcome(outcome as never), rejects("invalid_input"), JSON.stringify(outcome));
    assert.equal((await t.ledger.list()).length, entries, "nothing ledgered");
    // A status that is not won or warning_closed would block refunds: the junk one must not have landed.
    assert.equal((await t.engine.refundPayment({ sequence: 1, callId, paymentId, reason: "requested_by_customer", amountMinor: 100 })).status, "succeeded");
  });

  it("a dispute for the same payment intent in another workspace stays in its own", async () => {
    const t = setup();
    await paidCall(t);
    const other = setup({ workspaceId: "ws_other", adapters: { sessions: t.sessions, ledger: t.ledger } });
    assert.deepEqual(await other.engine.applyDisputeOutcome(base), { applied: false, unbound: true });
  });
});

describe("hostile #116: refunds", () => {
  it("a refund answer outside the provider's three never reaches the record or the ledger", async () => {
    for (const answer of [{ refundId: "re_1", status: "paid" }, { refundId: "re_1", status: PHONE_ON_FILE }, { refundId: "re_1", status: "requested" }, { refundId: 7, status: "succeeded" }, { status: "succeeded" }, null]) {
      const t = setup();
      const { callId, paymentId } = await paidCall(t);
      const real = t.payments.refund.bind(t.payments);
      t.payments.refund = async () => answer as never;
      await assert.rejects(t.engine.refundPayment({ sequence: 1, callId, paymentId, reason: "requested_by_customer" }), rejects("precondition_failed", /provider/), JSON.stringify(answer));
      assert.equal((await t.ledger.list()).some((e) => e.event === "payment.refunded"), false);
      t.payments.refund = real;
      assert.equal((await t.engine.refundPayment({ sequence: 1, callId, paymentId, reason: "requested_by_customer" })).status, "succeeded", "resumed with the same key");
    }
  });

  it("two refunds asked at once never add up to more than was paid", async () => {
    const t = setup();
    const { callId, paymentId } = await paidCall(t);
    const results = await Promise.allSettled([
      t.engine.refundPayment({ sequence: 1, callId, paymentId, reason: "requested_by_customer", amountMinor: 10000 }),
      t.engine.refundPayment({ sequence: 2, callId, paymentId, reason: "requested_by_customer", amountMinor: 10000 }),
      t.engine.refundPayment({ sequence: 2, callId, paymentId, reason: "requested_by_customer", amountMinor: 9000 }),
    ]);
    const done = results.flatMap((r) => (r.status === "fulfilled" ? [r.value] : []));
    const sent = t.payments.refunds.reduce((sum: number, r: { amountMinor: number }) => sum + r.amountMinor, 0);
    assert.ok(sent <= 15000, `sent ${sent}`);
    assert.ok(done.every((r) => r.refundedMinor <= 15000));
  });
});
