// INT-3: the SessionStore, its contract suite, two engines on one store, and conflicts.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditInput, SessionStore } from "../src/core/adapters.ts";
import { MemoryAuditLedger, verifyChain } from "../src/prove/ledger.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { MAX_WRITE_ATTEMPTS, createEngine } from "../src/engine.ts";
import { buildAmountReadBack } from "../src/pay/amount.ts";
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

/** A store that loses the next `n` compare-and-sets (or only the next clears of a ledger outbox), as if another process wrote first. */
class ContendedStore extends MemorySessionStore {
  losses = 0;
  loseClears = 0;
  override async compareAndSet(w: string, c: string, v: number, r: JsonValue): Promise<{ ok: true; version: number } | { ok: false }> {
    if (this.losses > 0) {
      this.losses--;
      return { ok: false };
    }
    if (this.loseClears > 0 && (r as { outbox: unknown[] }).outbox.length === 0) {
      this.loseClears--;
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

/** A ledger that fails the next `n` appends, as an outage would. */
class FlakyLedger extends MemoryAuditLedger {
  failures = 0;
  override async append(input: AuditInput) {
    if (this.failures > 0) {
      this.failures--;
      throw new Error("ledger down");
    }
    return super.append(input);
  }
}

describe("ledger entries saved with the step (review item 6)", () => {
  it("keeps a step's entries when the ledger fails, and appends them once, in order, on the next write", async () => {
    const ledger = new FlakyLedger();
    const t = setup({ adapters: { ledger } });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    ledger.failures = 1;
    await assert.rejects(t.engine.finishVerification(callId), /ledger down/);
    assert.equal((await t.engine.state(callId)).level, 1, "the step stands");
    assert.equal((await ledger.list()).some((e) => e.event === "grant.issued"), false, "not yet in the ledger");
    await t.engine.markUntrusted(callId, "document");
    const events = (await ledger.list()).map((e) => e.event);
    assert.deepEqual(events.slice(3), ["verification.finished", "grant.issued", "session.tainted"]);
    assert.equal(verifyChain(await ledger.list()).ok, true);
  });

  it("appends nothing twice when the clear after a flush is lost, and flushLedger catches up", async () => {
    const ledger = new FlakyLedger();
    const sessions = new ContendedStore();
    const t = setup({ adapters: { ledger, sessions } });
    const { callId } = await t.engine.startCall();
    ledger.failures = 1;
    await assert.rejects(t.engine.openSensitive(callId, "keypad"), rejects("invalid_transition"));
    await assert.rejects(t.engine.markUntrusted(callId, "x"), /ledger down/);
    await t.engine.flushLedger(callId);
    await t.engine.flushLedger(callId);
    // A clear that loses its compare-and-set leaves the entries pending; the next flush appends none twice.
    sessions.loseClears = 1;
    await t.engine.redact(callId, "4242424242424242");
    assert.equal(((await sessions.get("ws_test", callId))!.record as { outbox: unknown[] }).outbox.length, 1, "still pending");
    await t.engine.flushLedger(callId);
    assert.equal(((await sessions.get("ws_test", callId))!.record as { outbox: unknown[] }).outbox.length, 0);
    const events = (await ledger.list()).map((e) => e.event);
    assert.deepEqual(events, ["call.started", "session.tainted", "redaction.applied"]);
    await assert.rejects(t.engine.flushLedger("nope"), rejects("unknown_call"));
  });

  it("keeps two workspaces' entries apart on one shared ledger, even with the same call id", async () => {
    const ledger = new MemoryAuditLedger();
    const a = setup({ adapters: { ledger } });
    const b = setup({ adapters: { ledger }, workspaceId: "ws_other" });
    await a.engine.startCall({ callId: "c1" });
    await b.engine.startCall({ callId: "c1" });
    assert.deepEqual((await ledger.list()).map((e) => e.event), ["call.started", "call.started"]);
  });

  it("refuses an entry the ledger would refuse before it is saved, so it never blocks later writes", async () => {
    const t = setup({ modules: [] });
    const { callId } = await t.engine.startCall();
    const loyalty = { manifest: { name: "loyalty", version: "1", summary: "x", provides: { factors: [], steps: [], outcomes: [] }, scopes: { grants: [], needs: {} }, adapters: [] }, validateSettings: () => [], requiredAdapters: () => [], validateStep: () => [], initCall: () => ({}), enterStep: () => null, stepStatus: () => "pending" as const };
    t.engine.use(loyalty);
    t.engine.configure(testConfig((c) => (c.modules.loyalty = {})));
    const call = await t.engine.startCall();
    await assert.rejects(
      t.engine.updateModule(call.callId, "loyalty", (slice, view) => {
        view.emit("4242 4242 4242 4242", {});
        return slice;
      }),
      rejects("invalid_input", /card number/),
    );
    await t.engine.markUntrusted(call.callId, "x");
    assert.equal((await t.ledger.list()).at(-1)!.event, "session.tainted", "later writes are not blocked");
    assert.ok(callId);
  });

  it("resumes a payment and a receipt whose step was saved while the ledger was down", async () => {
    const ledger = new FlakyLedger();
    const t = setup({ adapters: { ledger } });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    t.carrier.set("+15555550100", { identityMatch: "match" });
    await t.engine.checkCarrier(callId);
    const request = { amountMinor: 100, currency: "cad", description: "x", amountSource: "price_list" as const };
    // The ledger goes down: verification's entries stay pending, and so do the read-back's and the
    // caller's yes, each saved before its flush fails; the payment's reservation is saved before
    // its flush of all of those fails, with no link created yet.
    ledger.failures = 4;
    await assert.rejects(t.engine.finishVerification(callId), /ledger down/);
    await assert.rejects(t.engine.readBackPayment(callId, request), /ledger down/);
    const { digest } = buildAmountReadBack("en", { amountMinor: 100, currency: "cad", description: "x" });
    await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest, confirmedBy: "keypad" }), /ledger down/);
    await assert.rejects(t.engine.requestPayment(callId, request), /ledger down/);
    assert.equal((await t.engine.state(callId)).phase, "paying", "reserved, no link yet");
    assert.equal(t.payments.created.length, 0);
    assert.equal((await t.engine.requestPayment(callId, request)).paymentId, "pay_1", "resumed");
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" });
    ledger.failures = 1;
    await assert.rejects(t.engine.endCall(callId), /ledger down/);
    const receipt = await t.engine.endCall(callId);
    assert.equal(receipt!.body.payments[0]!.status, "paid");
    assert.equal((await ledger.list()).filter((e) => e.event === "call.ended").length, 1);
    assert.deepEqual(
      (await ledger.list()).filter((e) => e.event.startsWith("payment.")).map((e) => e.event),
      ["payment.amount_read_back", "payment.amount_confirmed", "payment.link_sent", "payment.settled"],
      "every pending entry was appended once, in order",
    );
    assert.equal(verifyChain(await ledger.list()).ok, true);
  });

  it("makes the memory ledger idempotent by event id", async () => {
    const ledger = new MemoryAuditLedger();
    const input: AuditInput = { eventId: "c:2:0", callId: "c", actor: "code", event: "call.ended", at: "2026-01-01T00:00:00.000Z", detail: {} };
    const first = await ledger.append(input);
    assert.deepEqual(await ledger.append(input), first);
    assert.equal((await ledger.list()).length, 1);
    assert.equal(first.eventId, "c:2:0");
  });
});
