// INT-3: the SessionStore, its contract suite, two engines on one store, and conflicts.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { SessionStore } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { MAX_WRITE_ATTEMPTS, createEngine } from "../src/engine.ts";
import { TEST_KNOWLEDGE_KEY, generateTestSigner, sessionStoreContract } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig } from "./helpers.ts";

describe("MemorySessionStore passes the SessionStore contract", () => {
  for (const c of sessionStoreContract(() => new MemorySessionStore())) it(c.name, c.run);
});

describe("the contract suite", () => {
  it("catches a store that ignores the version", async () => {
    class Careless extends MemorySessionStore {
      override async compareAndSet(w: string, c: string, _v: number, r: JsonValue) {
        const stored = await this.get(w, c);
        return super.compareAndSet(w, c, stored?.version ?? 0, r);
      }
    }
    const failures = [];
    for (const c of sessionStoreContract(async () => new Careless())) await c.run().catch((e: unknown) => failures.push(e));
    assert.equal(failures.length, 1, "the expected-version case fails");
  });
});

/** A store that loses the next `n` compare-and-sets, as if another process always wrote first. */
class ContendedStore extends MemorySessionStore {
  losses = 0;
  override async compareAndSet(w: string, c: string, v: number, r: JsonValue): Promise<{ ok: true; version: number } | { ok: false }> {
    if (this.losses > 0) {
      this.losses--;
      return { ok: false };
    }
    return super.compareAndSet(w, c, v, r);
  }
}

describe("engines sharing one session store", () => {
  it("runs one call across two engines, with one attempt budget between them", async () => {
    const t = setup();
    const other = createEngine({
      workspaceId: "ws_test",
      knowledgeKey: TEST_KNOWLEDGE_KEY,
      config: testConfig(),
      clock: t.clock,
      ids: t.ids,
      adapters: { ledger: t.ledger, sessions: t.sessions, records: t.records, identity: t.identity, carrier: t.carrier, messages: t.messages, payments: t.payments, pinVerifier: t.pinVerifier, signer: generateTestSigner() },
    });
    const { callId } = await t.engine.startCall();
    await other.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitKeypad(callId, { dob: "1" })).matched, false);
    assert.deepEqual(await other.submitKeypad(callId, { dob: "2" }), { matched: false, locked: true }, "the second engine sees the first attempt");
    assert.equal((await t.engine.state(callId)).factors.length, 2);
    const second = await other.startCall();
    await t.engine.beginVerification(second.callId, { accountNumber: ACCOUNT });
    await other.submitKeypad(second.callId, { dob: DOB });
    await t.engine.startPhotoId(second.callId);
    const sessionId = t.identity.created[0]!.sessionId;
    assert.deepEqual(await other.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: true, callId: second.callId }, "the reference lives in the store");
  });

  it("gives two concurrent attempts on one call one counted attempt each, never more than the limit", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const results = await Promise.all([1, 2, 3].map((n) => t.engine.submitKeypad(callId, { dob: String(n) })));
    assert.equal(results.filter((r) => r.locked).length >= 2, true);
    assert.equal((await t.engine.state(callId)).factors.length, 2, "the policy allows two attempts per call");
  });
});

describe("compare-and-set conflicts", () => {
  it("retries a step from a fresh read, and gives up with conflict after the last attempt", async () => {
    const sessions = new ContendedStore();
    const t = setup({ adapters: { sessions } });
    const { callId } = await t.engine.startCall();
    sessions.losses = MAX_WRITE_ATTEMPTS - 1;
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.state(callId)).phase, "verifying");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "verification.started").length, 1, "one ledger entry for one saved step");
    sessions.losses = MAX_WRITE_ATTEMPTS;
    await assert.rejects(t.engine.openSensitive(callId, "keypad"), rejects("conflict"));
    assert.equal((await t.engine.state(callId)).sensitive, null);
    assert.equal(t.sessions, sessions);
  });

  it("resumes a filing whose last write was lost, with the same record", async () => {
    const sessions = new ContendedStore();
    const t = setup({ adapters: { sessions } });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    const put = t.records.putIntakeRecord.bind(t.records);
    t.records.putIntakeRecord = async (record) => {
      await put(record);
      sessions.losses = MAX_WRITE_ATTEMPTS;
    };
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), rejects("conflict"));
    await assert.rejects(t.engine.abandonIntake(callId), rejects("precondition_failed"), "the draft stays reserved for its record");
    t.records.putIntakeRecord = put;
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad" });
    assert.equal(record.recordId, "rec_1");
    assert.equal(record.confirmedBy, "voice", "the same record, not a second one");
    assert.deepEqual((await t.engine.state(callId)).recordIds, ["rec_1"]);
  });

  it("refuses an id that exists in the store, whichever engine made it", async () => {
    const store: SessionStore = new MemorySessionStore();
    const a = setup({ adapters: { sessions: store } });
    const b = setup({ adapters: { sessions: store } });
    await a.engine.startCall({ callId: "c1" });
    await assert.rejects(b.engine.startCall({ callId: "c1" }), rejects("invalid_input"));
  });
});
