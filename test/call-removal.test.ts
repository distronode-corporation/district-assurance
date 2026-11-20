// Removing a call record (L3 #131, decided 2026-11-20): the engine refuses to remove a call record
// while its outbox holds ledger entries not yet appended, so a pending entry (a `consent.recorded`
// written while the ledger was down) is never lost with the record. The background flush keeps
// such a call listed until it is flushed; then `removeCall` removes it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditInput } from "../src/core/adapters.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { sessionStoreContract, type TestEngine } from "../src/testing/index.ts";
import { rejects, setup, verifiedCall } from "./helpers.ts";

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
    // The removal flushes first: the pending entries land, then the record goes.
    assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
    assert.ok((await ledger.list()).some((e) => e.event === "consent.recorded" && e.callId === callId), "the consent is on the ledger");
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
