// INT-7: the business is told of lockouts, once per lock and capped per workspace, and may lift one.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, AttemptCounters, AuditInput, LockNotice } from "../src/core/adapters.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { NOTICES_PER_HOUR, claimNotice, noticeKey, numberKeyFor } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeNotifier, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, PHONE_ON_FILE, PIN, rejects, setup, testConfig } from "./helpers.ts";

const T0 = Date.parse("2026-01-01T00:00:00.000Z");
const iso = (ms: number): string => new Date(ms).toISOString();
const HOUR = 3_600_000;
const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const CALLING = "+15555550142";
const NUMBER = numberKeyFor(TEST_KNOWLEDGE_KEY, CALLING);
const LONG_AGO = "2000-01-01T00:00:00.000Z";
const counter = (scope: "subject" | "number", key: string, factor = "pin"): AttemptCounterKey => ({ workspaceId: "ws_test", factor, scope, key });

/** A test engine with a notifier, where `lockAfterFailures` failures lock hard. */
function alerted(lockAfterFailures = 2, options: { counters?: AttemptCounters; ledger?: MemoryAuditLedger } = {}): TestEngine & { notifier: FakeNotifier } {
  const notifier = new FakeNotifier();
  const config = testConfig((c) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { lockAfterFailures }));
  const t = setup({ config, adapters: { notifier, ...options } });
  return { ...t, notifier };
}

async function call(t: TestEngine, input: { accountNumber?: string; subjectKey?: string; callingNumber?: string } = {}): Promise<string> {
  const { callId } = await t.engine.startCall();
  const subject = input.subjectKey === undefined ? { accountNumber: input.accountNumber ?? ACCOUNT } : { subjectKey: input.subjectKey };
  await t.engine.beginVerification(callId, { ...subject, ...(input.callingNumber === undefined ? {} : { callingNumber: input.callingNumber }) });
  return callId;
}

const lockedEntries = async (t: TestEngine) => (await t.ledger.list()).filter((e) => e.event === "verification.locked");

/** A ledger that refuses appends while `down`. */
class FlakyLedger extends MemoryAuditLedger {
  down = false;

  override append(input: AuditInput) {
    return this.down ? Promise.reject(new Error("ledger down")) : super.append(input);
  }
}

describe("lock notices", () => {
  it("tell the business once per lock, however many attempts and engines it refuses, with the counter and never a value", async () => {
    const counters = new MemoryAttemptCounters();
    const t = alerted(2, { counters });
    const first = await call(t, { callingNumber: CALLING });
    assert.deepEqual(await t.engine.submitPin(first, "0000"), { matched: false, locked: false });
    assert.equal(t.notifier.notices.length, 0, "a failure that locks nothing is not a notice");
    t.clock.advance(5_000);
    assert.deepEqual(await t.engine.submitPin(first, "1111"), { matched: false, locked: true });
    const until = iso(T0 + 24 * HOUR);
    const notice: LockNotice = { workspaceId: "ws_test", factor: "pin", scope: "subject", key: SUBJECT, hard: true, until, capped: false };
    assert.deepEqual(t.notifier.notices, [notice]);
    // The same lock refuses again: on this engine, a new call, and a second engine on the same store.
    for (let i = 0; i < 3; i++) assert.deepEqual(await t.engine.submitPin(await call(t), PIN), { matched: false, locked: true });
    const otherNotifier = new FakeNotifier();
    const other = createTestEngine({ config: t.engine.config, clock: t.clock, adapters: { counters, notifier: otherNotifier } });
    assert.deepEqual(await other.engine.submitPin(await call(other), PIN), { matched: false, locked: true });
    assert.equal((await lockedEntries(t)).length, 4, "every refusal is in the ledger");
    assert.equal((await lockedEntries(other)).length, 1);
    assert.deepEqual(t.notifier.notices, [notice], "one notice for the lock");
    assert.deepEqual(otherNotifier.notices, [], "the other engine found it told");
    const told = JSON.stringify(t.notifier.notices);
    for (const value of [ACCOUNT, PIN, "0000", CALLING, PHONE_ON_FILE]) assert.equal(told.includes(value), false, "no value or phone number");
  });

  it("name the calling number by its keyed hash, and tell a wait after a failure as well as a hard lock", async () => {
    const t = alerted(10);
    const callId = await call(t, { accountNumber: "not-digits", callingNumber: CALLING });
    assert.deepEqual(await t.engine.submitPin(callId, "0000"), { matched: false, locked: false });
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true }, "inside the wait");
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true }, "the same wait");
    assert.deepEqual(t.notifier.notices, [{ workspaceId: "ws_test", factor: "pin", scope: "number", key: NUMBER, hard: false, until: iso(T0 + 5_000), capped: false }]);
    assert.equal((await lockedEntries(t)).length, 2);
  });

  it("go out only after the ledger entry is written", async () => {
    const ledger = new FlakyLedger();
    const t = alerted(1, { ledger });
    const callId = await call(t);
    ledger.down = true;
    await assert.rejects(t.engine.submitPin(callId, "0000"), /ledger down/);
    assert.equal(t.notifier.notices.length, 0, "the entry is saved, not yet written");
    ledger.down = false;
    await t.engine.flushLedger(callId);
    assert.equal((await ledger.list()).filter((e) => e.event === "verification.locked").length, 1);
    assert.deepEqual(t.notifier.notices.map((n) => [n.scope, n.hard]), [["subject", true]]);
    await t.engine.flushLedger(callId);
    assert.equal(t.notifier.notices.length, 1, "told once");
  });

  it("never block the call or the ledger when the notifier throws, rejects or hangs, or the bookkeeping fails", async () => {
    for (const fail of ["throws", "rejects", "hangs"] as const) {
      const t = alerted(1);
      t.notifier.fail = fail;
      assert.deepEqual(await t.engine.submitPin(await call(t), "0000"), { matched: false, locked: true }, fail);
      assert.equal(t.notifier.notices.length, 1, fail);
      assert.equal((await lockedEntries(t)).length, 1, fail);
      assert.deepEqual(await t.engine.submitPin(await call(t), PIN), { matched: false, locked: true }, `${fail}: the next call runs`);
    }
    class NoNotices extends MemoryAttemptCounters {
      override recordFailure(key: AttemptCounterKey, at: string, since: string) {
        return key.factor.startsWith("notice:") ? Promise.reject(new Error("counters down")) : super.recordFailure(key, at, since);
      }
    }
    const t = alerted(1, { counters: new NoNotices() });
    assert.deepEqual(await t.engine.submitPin(await call(t), "0000"), { matched: false, locked: true });
    assert.equal(t.notifier.notices.length, 0);
    assert.equal((await lockedEntries(t)).length, 1);
  });

  it(`are capped at ${NOTICES_PER_HOUR} an hour per workspace, the last one saying so`, async () => {
    const t = alerted(1);
    const subjects = Array.from({ length: NOTICES_PER_HOUR + 5 }, (_, i) => i.toString(16).padStart(64, "a"));
    for (const subjectKey of subjects) assert.deepEqual(await t.engine.submitPin(await call(t, { subjectKey }), "0000"), { matched: false, locked: true });
    assert.equal((await lockedEntries(t)).length, NOTICES_PER_HOUR + 5, "every lock is in the ledger");
    assert.equal(t.notifier.notices.length, NOTICES_PER_HOUR);
    assert.deepEqual(t.notifier.notices.map((n) => n.capped), [...Array.from({ length: NOTICES_PER_HOUR - 1 }, () => false), true]);
    assert.deepEqual(t.notifier.notices.map((n) => n.key), subjects.slice(0, NOTICES_PER_HOUR));
    t.clock.advance(HOUR);
    await t.engine.submitPin(await call(t, { subjectKey: "b".repeat(64) }), "0000");
    assert.equal(t.notifier.notices.at(-1)!.key, "b".repeat(64), "an hour later, notices resume");
    assert.equal(t.notifier.notices.at(-1)!.capped, false);
    const elsewhere = alerted(1);
    await elsewhere.engine.submitPin(await call(elsewhere, { subjectKey: "c".repeat(64) }), "0000");
    assert.equal(elsewhere.notifier.notices.length, 1, "another workspace has its own cap");
  });

  it("keep their bookkeeping under notice kinds, apart from every factor's counter", async () => {
    const counters = new MemoryAttemptCounters();
    const key = counter("subject", SUBJECT);
    assert.deepEqual(noticeKey(key), { ...key, factor: "notice:pin" });
    const now = new Date(T0);
    assert.deepEqual(await claimNotice(counters, key, iso(T0 + 5_000), now), { capped: false });
    assert.equal(await claimNotice(counters, key, iso(T0 + 5_000), now), null, "the same lock");
    assert.equal(await claimNotice(counters, key, iso(T0 + 1_000), now), null, "an earlier end: a lock already told");
    assert.deepEqual(await claimNotice(counters, key, iso(T0 + 15_000), now), { capped: false }, "a later lock");
    assert.deepEqual(await counters.get(key, LONG_AGO), [], "the factor's counter is untouched");
  });
});

describe("unlock", () => {
  it("clears only its counter, grants nothing, is recorded with the member, and lets a later lock be told again", async () => {
    const t = alerted(1);
    const first = await call(t, { callingNumber: CALLING });
    assert.deepEqual(await t.engine.submitPin(first, "0000"), { matched: false, locked: true });
    await t.engine.submitKeypad(await call(t), { dob: "1" });
    const stranger = "d".repeat(64);
    await t.engine.submitPin(await call(t, { subjectKey: stranger }), "0000");
    const before = await t.engine.state(first);
    t.clock.advance(60_000);

    await t.engine.unlock({ workspaceId: "ws_test", factor: "pin", scope: "subject", key: SUBJECT, memberId: "member_42" });

    assert.deepEqual(await t.counters.get(counter("subject", SUBJECT), LONG_AGO), [], "its counter is clear");
    assert.equal((await t.counters.get(counter("number", NUMBER), LONG_AGO)).length, 1, "the number's stays");
    assert.equal((await t.counters.get(counter("subject", SUBJECT, "keypad_knowledge"), LONG_AGO)).length, 1, "another factor's stays");
    assert.equal((await t.counters.get(counter("subject", stranger), LONG_AGO)).length, 1, "another subject's stays");
    const entry = (await t.ledger.list()).at(-1)!;
    assert.deepEqual(
      { callId: entry.callId, actor: entry.actor, event: entry.event, at: entry.at, detail: entry.detail },
      { callId: null, actor: "member", event: "verification.unlocked", at: iso(T0 + 60_000), detail: { kind: "pin", scope: "subject", memberId: "member_42" } },
    );
    assert.equal(JSON.stringify(entry).includes(SUBJECT), false, "the ledger never holds the key");

    assert.deepEqual(await t.engine.state(first), before, "the call that locked is as it was: no factor, no level, no grant");
    assert.equal(before.level, 0);
    assert.equal(before.grant, null);
    assert.deepEqual(await t.engine.submitPin(await call(t, { callingNumber: CALLING }), PIN), { matched: false, locked: true }, "the number is still locked");
    const again = await call(t);
    assert.deepEqual((await t.engine.state(again)).factors, [], "the caller starts from nothing");
    assert.deepEqual(await t.engine.submitPin(again, PIN), { matched: true, locked: false }, "and verifies like anyone");

    const told = t.notifier.notices.length;
    await t.engine.unlock({ workspaceId: "ws_test", factor: "pin", scope: "subject", key: SUBJECT, memberId: "member_42" });
    await t.engine.submitPin(await call(t), "0000");
    assert.equal(t.notifier.notices.length, told + 1, "a new lock after an unlock is told");
  });

  it("refuses another workspace, an unknown factor or scope, a malformed key or member, and card data", async () => {
    const t = alerted(1);
    const ok = { workspaceId: "ws_test", factor: "pin", scope: "subject" as const, key: SUBJECT, memberId: "m-1@example.test" };
    const cases: Array<[object, RegExp]> = [
      [{ workspaceId: "ws_other" }, /workspace/],
      [{ factor: "caller_id" }, /factor/],
      [{ scope: "account" }, /scope/],
      [{ key: SUBJECT.toUpperCase() }, /key/],
      [{ memberId: "" }, /memberId/],
      [{ memberId: "a b" }, /memberId/],
      [{ memberId: "4242424242424242" }, /card number/],
    ];
    const entries = (await t.ledger.list()).length;
    for (const [patch, message] of cases) await assert.rejects(t.engine.unlock({ ...ok, ...patch } as typeof ok), rejects("invalid_input", message));
    assert.equal((await t.ledger.list()).length, entries, "nothing recorded");
  });

  it("is refused by an engine without counters, which locks nothing", async () => {
    const config = testConfig((c) => (c.modules.badge!.settings = { factors: ["photo_id"] }));
    const t = createTestEngine({ config, adapters: { counters: undefined } });
    await assert.rejects(
      t.engine.unlock({ workspaceId: "ws_test", factor: "pin", scope: "subject", key: SUBJECT, memberId: "m" }),
      rejects("precondition_failed", /counters/),
    );
  });
});
