// Hostile-pass regressions for #114 (PAY-3): cancel payment links, and expire open ones when the call ends.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { PaymentLinks } from "../src/core/adapters.ts";
import { confirmAmount, rejects, setup, verifiedCall } from "./helpers.ts";

const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };

function deferred<T = void>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

describe("hostile #114: closing links", () => {
  it("a cancel and an endCall closing one link at once write one link_expired, and the receipt shows it expired", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const { paymentId } = await t.engine.requestPayment(callId, request);
    const expire = t.payments.expireLink.bind(t.payments);
    const held = deferred();
    let first = true;
    t.payments.expireLink = async (input) => {
      if (first) {
        first = false;
        await held.promise;
      }
      return expire(input);
    };
    const cancel = t.engine.cancelPaymentLink(callId, paymentId);
    const ended = t.engine.endCall(callId);
    const receipt = await ended;
    held.resolve();
    assert.deepEqual(await cancel, { paymentId, status: "expired" });
    assert.equal((await t.ledger.list()).filter((e) => e.event === "payment.link_expired").length, 1);
    assert.deepEqual(receipt!.body.payments.map((p) => p.status), ["expired"]);
  });

  it("an adapter answering something other than expired or not_open never reaches the ledger as given", async () => {
    for (const state of ["paid", "", "+15555550100", undefined, null, 1]) {
      const t = setup();
      const callId = await verifiedCall(t);
      await confirmAmount(t.engine, callId, request);
      const { paymentId } = await t.engine.requestPayment(callId, request);
      const expire = t.payments.expireLink.bind(t.payments);
      t.payments.expireLink = async () => ({ state }) as never;
      await assert.rejects(t.engine.cancelPaymentLink(callId, paymentId), rejects("precondition_failed", /neither expired nor not_open/), String(state));
      assert.equal((await t.ledger.list()).some((e) => e.event === "payment.link_expired"), false, `${String(state)} reached the ledger`);
      assert.equal((await t.engine.state(callId)).phase, "paying", "left open, like a provider that threw");
      t.payments.expireLink = expire;
      assert.deepEqual(await t.engine.cancelPaymentLink(callId, paymentId), { paymentId, status: "expired" }, "the next cancel closes it");
    }
    // The same through the adapter's own cancel method, when it has one.
    for (const answer of [{ state: "paid" }, {}, null, "expired", 1]) {
      const c = setup();
      const id = await verifiedCall(c);
      await confirmAmount(c.engine, id, request);
      const { paymentId } = await c.engine.requestPayment(id, request);
      (c.payments as PaymentLinks).cancel = async () => answer as never;
      await assert.rejects(c.engine.cancelPaymentLink(id, paymentId), rejects("precondition_failed", /neither expired nor not_open/), JSON.stringify(answer));
      assert.equal((await c.ledger.list()).some((e) => e.event === "payment.link_expired"), false, `${JSON.stringify(answer)} reached the ledger`);
      assert.equal((await c.engine.state(id)).phase, "paying", "left open");
    }
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    await t.engine.requestPayment(callId, request);
    t.payments.expireLink = async () => null as never;
    await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed"), "an answer that is not even an object");
  });

  it("refuses unknown and prototype-key payment ids, and ids from another workspace's call", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    await t.engine.requestPayment(callId, request);
    for (const id of ["__proto__", "constructor", "toString", "", "pay_1 ", "\ud800"]) {
      await assert.rejects(t.engine.cancelPaymentLink(callId, id), rejects("invalid_input", /no payment with that id/), id);
    }
    const other = setup({ workspaceId: "ws_other", adapters: { sessions: t.sessions, ledger: t.ledger } });
    await assert.rejects(other.engine.cancelPaymentLink(callId, "pay_1"), rejects("unknown_call"));
    assert.equal((await t.engine.state(callId)).phase, "paying", "still open in its own workspace");
  });

  it("endCall waits for a sender holding the lease, and a sender that stalled past it records nothing after the end", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const send = t.messages.sendText.bind(t.messages);
    const held = deferred();
    const reached = deferred();
    t.messages.sendText = async (input) => {
      reached.resolve();
      await held.promise;
      return send(input);
    };
    await confirmAmount(t.engine, callId, request);
    const pending = t.engine.requestPayment(callId, request);
    await reached.promise;
    await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed", /being texted/));
    t.clock.advance(60_000);
    const receipt = await t.engine.endCall(callId);
    held.resolve();
    await pending.catch(() => undefined);
    const after = (await t.ledger.list()).filter((e) => e.seq > receipt!.body.ledger.seq);
    assert.deepEqual(after.map((e) => e.event), ["receipt.issued"], "nothing but the receipt itself after its head");
    assert.deepEqual(receipt!.body.payments.map((p) => p.status), ["expired"]);
  });

  it("a payment paid after its cancel is recorded paid and flagged late; cancelling again changes nothing", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const { paymentId } = await t.engine.requestPayment(callId, request);
    await t.engine.cancelPaymentLink(callId, paymentId);
    const entries = (await t.ledger.list()).length;
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, paymentId), { paymentId, status: "expired" });
    assert.equal((await t.ledger.list()).length, entries, "no entry for a second cancel");
    const outcome = await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" } as never);
    assert.equal(outcome.applied, true);
    assert.equal((await t.ledger.list()).filter((e) => e.event === "payment.settled").at(-1)!.detail.late, true);
  });
});
