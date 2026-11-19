// Refund and dispute inputs are read once: a getter (or a host changing the object while the engine
// waits) can never pass a check with one value and have another refunded, recorded or ledgered.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { TestEngine } from "../src/testing/index.ts";
import { confirmAmount, rejects, setup, verifiedCall } from "./helpers.ts";

const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };

function flipping<T extends object>(base: T, key: string, first: unknown, then: unknown, n = 1): T {
  let reads = 0;
  return Object.defineProperty({ ...base }, key, {
    enumerable: true,
    get() {
      reads += 1;
      return reads <= n ? first : then;
    },
  });
}

async function paidCall(t: TestEngine): Promise<{ callId: string; paymentId: string }> {
  const callId = await verifiedCall(t);
  await confirmAmount(t.engine, callId, request);
  const { paymentId } = await t.engine.requestPayment(callId, request);
  await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_1" });
  return { callId, paymentId };
}

describe("refunds: inputs are read once", () => {
  it("refunds the amount it checked, never a negative or fractional one swapped in after the check", async () => {
    for (const swapped of [-5000, 1.5, Number.NaN]) {
      const t = setup();
      const { callId, paymentId } = await paidCall(t);
      const sent: number[] = [];
      const refund = t.payments.refund.bind(t.payments);
      t.payments.refund = (input) => {
        sent.push(input.amountMinor);
        return refund(input);
      };
      const input = flipping({ callId, paymentId, reason: "requested_by_customer" }, "amountMinor", 5000, swapped, 2);
      await t.engine.refundPayment(input as never);
      assert.deepEqual(sent, [5000], String(swapped));
    }
  });

  it("records the reason it checked", async () => {
    const t = setup();
    const { callId, paymentId } = await paidCall(t);
    const input = flipping({ callId, paymentId }, "reason", "requested_by_customer", "+15555550100");
    await t.engine.refundPayment(input as never);
    const record = (await t.sessions.get("ws_test", callId))!.record as { modules: { paylink: { payments: Array<{ refunds?: Array<{ reason: string }> }> } } };
    assert.deepEqual(record.modules.paylink.payments[0]!.refunds!.map((r) => r.reason), ["requested_by_customer"]);
  });

  it("records and ledgers the dispute status it compared, for the payment intent it looked up", async () => {
    const t = setup();
    const { callId } = await paidCall(t);
    const base = { disputeId: "dp_1", chargeId: "ch_1", paymentIntentId: "pi_1", amountMinor: 15000, currency: "cad" };
    assert.deepEqual(await t.engine.applyDisputeOutcome(flipping(base, "status", "needs_response", "won") as never), { applied: true, callId, status: "needs_response" });
    const disputed = (await t.ledger.list()).filter((e) => e.event === "payment.disputed").map((e) => (e.detail as { status: string }).status);
    assert.deepEqual(disputed, ["needs_response"]);
    // Won is final: had "won" been recorded, the refund below would be allowed.
    await assert.rejects(t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer" }), (e: unknown) => rejects("precondition_failed")(e) || rejects("invalid_input")(e));
    const swappedIntent = flipping({ ...base, disputeId: "dp_2", status: "needs_response" }, "paymentIntentId", "pi_1", "pi_other", 2);
    assert.equal((await t.engine.applyDisputeOutcome(swappedIntent as never)).applied, true, "no TypeError from a payment intent that changed after its lookup");
  });
});
