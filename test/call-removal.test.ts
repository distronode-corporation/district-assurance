// Removing a call record (L3 #131, decided 2026-11-20): the engine refuses to remove a call record
// while its outbox holds ledger entries not yet appended, so a pending entry (a `consent.recorded`
// written while the ledger was down) is never lost with the record. The background flush keeps
// such a call listed until it is flushed; then `removeCall` removes it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditInput } from "../src/core/adapters.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { generateTestSigner, sessionStoreContract, type TestEngine } from "../src/testing/index.ts";
import { confirmAmount, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

class SwitchedLedger extends MemoryAuditLedger {
  down = false;
  override async append(input: AuditInput) {
    if (this.down) throw new Error("ledger down");
    return super.append(input);
  }
}

/** A session store that can be told to lose the race for the next removal once. */
class RacingRemovals extends MemorySessionStore {
  lose = 0;
  override async remove(workspaceId: string, callId: string, expectedVersion: number): Promise<boolean> {
    if (this.lose > 0) {
      this.lose--;
      return false;
    }
    return super.remove(workspaceId, callId, expectedVersion);
  }
}

async function endedWithConsent(t: TestEngine, ledger: SwitchedLedger): Promise<string> {
  const callId = await verifiedCall(t);
  ledger.down = true;
  await assert.rejects(t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" }), /ledger down/);
  await assert.rejects(t.engine.endCall(callId), /ledger down/);
  return callId;
}

describe("removeCall", () => {
  it("removes an ended call whose ledger entries are all appended", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
    assert.equal(await t.sessions.get("ws_test", callId), null);
    await assert.rejects(t.engine.removeCall(callId), rejects("unknown_call"));
  });

  it("refuses while the outbox holds an entry, keeps the call listed for the background flush, and removes it once flushed", async () => {
    const ledger = new SwitchedLedger();
    const sessions = new MemorySessionStore();
    const t = setup({ adapters: { ledger, sessions } });
    const callId = await endedWithConsent(t, ledger);
    await assert.rejects(t.engine.removeCall(callId), rejects("precondition_failed", /not yet on the ledger/));
    assert.notEqual(await sessions.get("ws_test", callId), null, "the record stays");
    assert.deepEqual(await t.engine.flushPending(), { flushed: [], failed: [callId] });
    assert.deepEqual(await sessions.pendingCalls("ws_test", 10), [callId], "still listed");
    ledger.down = false;
    // The removal flushes first: the pending entries land. The receipt the failed endCall could not
    // sign is still owed, so the record stays until endCall signs it; then the record goes.
    await assert.rejects(t.engine.removeCall(callId), rejects("precondition_failed", /receipt/));
    assert.ok((await ledger.list()).some((e) => e.event === "consent.recorded" && e.callId === callId), "the consent is on the ledger");
    assert.notEqual(await sessions.get("ws_test", callId), null, "the record stays for its receipt");
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
    assert.equal(await sessions.get("ws_test", callId), null);
    assert.deepEqual(await sessions.pendingCalls("ws_test", 10), [], "no longer listed");
  });

  it("never starts a call again under a removed call's id, whose ledger event ids are spent", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall({ callId: "call_host_1" });
    await t.engine.endCall(callId);
    await t.engine.removeCall(callId);
    await assert.rejects(t.engine.startCall({ callId: "call_host_1" }));
    assert.equal(await t.sessions.get("ws_test", "call_host_1"), null);
  });

  it("refuses a call that has not ended", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await assert.rejects(t.engine.removeCall(callId), rejects("precondition_failed", /has not ended/));
  });

  it("reads the record again when a write lands before the removal, and gives up after three tries", async () => {
    const sessions = new RacingRemovals();
    const t = setup({ adapters: { sessions } });
    const callId = await verifiedCall(t);
    await t.engine.endCall(callId);
    sessions.lose = 2;
    assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
    const other = await verifiedCall(t);
    await t.engine.endCall(other);
    sessions.lose = 3;
    await assert.rejects(t.engine.removeCall(other), rejects("conflict"));
    assert.notEqual(await sessions.get("ws_test", other), null);
  });

  it("keeps an ended call that still owes its receipt, and removes it once endCall signs it (CodeRabbit #139)", async () => {
    const real = generateTestSigner();
    let down = true;
    const t = setup({ adapters: { signer: { ...real, sign: (bytes) => (down ? Promise.reject(new Error("kms down")) : real.sign(bytes)) } } });
    const callId = await verifiedCall(t);
    await assert.rejects(t.engine.endCall(callId), /kms down/);
    assert.equal(await t.engine.receipt(callId), null, "ended, with its receipt still owed");
    await assert.rejects(t.engine.removeCall(callId), rejects("precondition_failed", /receipt/));
    assert.notEqual(await t.sessions.get("ws_test", callId), null, "the record stays");
    down = false;
    await t.engine.endCall(callId);
    assert.notEqual(await t.engine.receipt(callId), null);
    assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
  });

  it("keeps an ended call with a refund in flight, and removes it once the refund's answer is recorded (CodeRabbit #139)", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
    await confirmAmount(t.engine, callId, request);
    await t.engine.requestPayment(callId, request);
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_1" });
    await t.engine.endCall(callId);
    const refund = t.payments.refund.bind(t.payments);
    t.payments.refund = async () => {
      throw new Error("the answer was lost");
    };
    await assert.rejects(t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate", sequence: 1 }), /the answer was lost/);
    await assert.rejects(t.engine.removeCall(callId), rejects("precondition_failed", /not yet final/));
    assert.notEqual(await t.sessions.get("ws_test", callId), null, "the record stays");
    t.payments.refund = refund;
    await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate", sequence: 1 });
    assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
  });

  it("keeps an ended call with a pending refund until the provider's update settles it (CodeRabbit #139)", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
    await confirmAmount(t.engine, callId, request);
    await t.engine.requestPayment(callId, request);
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_1" });
    await t.engine.endCall(callId);
    t.payments.refundStatus = "pending";
    await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "duplicate", sequence: 1 });
    await assert.rejects(t.engine.removeCall(callId), rejects("precondition_failed", /not yet final/));
    const update = { providerRef: "re_fake_1", paymentIntentId: "pi_1", status: "succeeded" as const, amountMinor: 15000, currency: "cad" };
    assert.deepEqual(await t.engine.applyRefundOutcome(update), { applied: true, callId, status: "succeeded" });
    assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
    // A succeeded refund does not hold the record: a late failure after the removal is refused (SPEC).
    await assert.rejects(t.engine.applyRefundOutcome({ ...update, status: "failed" }), rejects("unknown_call"));
  });

  it("keeps an ended call whose payment link is still open, and removes it once endCall closes the link (CodeRabbit #143)", async () => {
    // With receipts off too, where no owed receipt would hold the record.
    for (const receipts of [true, false]) {
      const t = setup(receipts ? {} : { config: testConfig((c) => (c.modules.trace!.settings = { receipts: false })) });
      const callId = await verifiedCall(t);
      const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
      await confirmAmount(t.engine, callId, request);
      await t.engine.requestPayment(callId, request);
      const expire = t.payments.expireLink.bind(t.payments);
      t.payments.expireLink = async () => {
        throw new Error("provider down");
      };
      await assert.rejects(t.engine.endCall(callId), /provider down/);
      const stored = (await t.sessions.get("ws_test", callId))!.record as unknown as { state: { phase: string } };
      assert.equal(stored.state.phase, "ended", "ended, with its link still open");
      await assert.rejects(t.engine.removeCall(callId), rejects("precondition_failed", /payment link/), `receipts=${receipts}`);
      assert.notEqual(await t.sessions.get("ws_test", callId), null, "the record stays");
      t.payments.expireLink = expire;
      await t.engine.endCall(callId);
      assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
    }
  });

  it("removes an ended call whose payment link was paid, and one whose link expired (CodeRabbit #143)", async () => {
    const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
    const paidSetup = setup();
    const paid = await verifiedCall(paidSetup);
    await confirmAmount(paidSetup.engine, paid, request);
    await paidSetup.engine.requestPayment(paid, request);
    await paidSetup.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_1" });
    await paidSetup.engine.endCall(paid);
    assert.deepEqual(await paidSetup.engine.removeCall(paid), { removed: true });

    const expiredSetup = setup();
    const expired = await verifiedCall(expiredSetup);
    await confirmAmount(expiredSetup.engine, expired, request);
    await expiredSetup.engine.requestPayment(expired, request);
    expiredSetup.clock.advance(61 * 60_000);
    await expiredSetup.engine.expirePaymentLinks(expired);
    await expiredSetup.engine.endCall(expired);
    assert.equal(expiredSetup.payments.expired.length, 1, "expired once, at its deadline");
    assert.deepEqual(await expiredSetup.engine.removeCall(expired), { removed: true });
  });

  it("removes an ended call whose payment has no refund, and one that started with Paylink off", async () => {
    const t = setup();
    const paid = await verifiedCall(t);
    const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
    await confirmAmount(t.engine, paid, request);
    await t.engine.requestPayment(paid, request);
    await t.engine.endCall(paid);
    assert.deepEqual(await t.engine.removeCall(paid), { removed: true });
    const off = setup({ config: testConfig((c) => (c.modules.paylink = { enabled: false })) });
    const callId = await verifiedCall(off);
    await off.engine.endCall(callId);
    assert.deepEqual(await off.engine.removeCall(callId), { removed: true });
  });

  it("needs a session store that can remove", async () => {
    const sessions = new MemorySessionStore() as MemorySessionStore & { remove?: unknown };
    const t = setup({ adapters: { sessions } });
    const callId = await verifiedCall(t);
    await t.engine.endCall(callId);
    Object.defineProperty(sessions, "remove", { value: undefined });
    await assert.rejects(t.engine.removeCall(callId), rejects("precondition_failed", /cannot remove/));
  });

  it("is in the session store contract: a removal only at the stored version, and its pending mark goes with it", async () => {
    // A store that can remove but not list pending calls runs the same case.
    class NoPending extends MemorySessionStore {}
    Object.defineProperty(NoPending.prototype, "pendingCalls", { value: undefined });
    for (const factory of [() => new MemorySessionStore(), () => new NoPending()]) {
      const removal = sessionStoreContract(factory).find((c) => c.name.startsWith("removes a session only at its stored version"))!;
      await removal.run();
    }
  });
});
