// Hostile pass on #118 (INT-7 lock notices and unlock), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounters } from "../src/core/adapters.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { NOTICES_PER_HOUR } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeNotifier, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, testConfig } from "./helpers.ts";

const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const CALLING = "+15555550142";
const LONG_AGO = "2000-01-01T00:00:00.000Z";
const OK = { workspaceId: "ws_test", factor: "pin", scope: "subject" as const, key: SUBJECT, memberId: "member_42" };

function alerted(options: { counters?: AttemptCounters; ledger?: MemoryAuditLedger; workspaceId?: string } = {}): TestEngine & { notifier: FakeNotifier } {
  const notifier = new FakeNotifier();
  const workspaceId = options.workspaceId ?? "ws_test";
  const config = testConfig((c) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { lockAfterFailures: 1 }));
  const t = createTestEngine({
    workspaceId,
    config,
    adapters: { notifier, ...(options.counters === undefined ? {} : { counters: options.counters }), ...(options.ledger === undefined ? {} : { ledger: options.ledger }) },
  });
  t.records.putSubject(workspaceId, testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
  return { ...t, notifier };
}

async function call(t: TestEngine, input: { subjectKey?: string; callingNumber?: string } = {}): Promise<string> {
  const { callId } = await t.engine.startCall();
  const subject = input.subjectKey === undefined ? { accountNumber: ACCOUNT } : { subjectKey: input.subjectKey };
  await t.engine.beginVerification(callId, { ...subject, ...(input.callingNumber === undefined ? {} : { callingNumber: input.callingNumber }) });
  return callId;
}

describe("#118 hostile: unlock input", () => {
  it("R1 refuses non-string keys and member ids that a regex would coerce, and a missing input, recording nothing", async () => {
    const t = alerted();
    await t.engine.submitPin(await call(t), "0000");
    const entries = (await t.ledger.list()).length;
    const cases: object[] = [{ key: [SUBJECT] }, { key: { toString: () => SUBJECT } }, { memberId: 4242 }, { memberId: ["member_42"] }, { workspaceId: ["ws_test"] }];
    for (const patch of cases) await assert.rejects(t.engine.unlock({ ...OK, ...patch } as typeof OK), rejects("invalid_input"), JSON.stringify(patch));
    await assert.rejects(t.engine.unlock(null as unknown as typeof OK), rejects("invalid_input"));
    assert.equal((await t.ledger.list()).length, entries, "nothing recorded");
    assert.equal((await t.counters.get({ workspaceId: "ws_test", factor: "pin", scope: "subject", key: SUBJECT }, LONG_AGO)).length, 1, "still locked");
  });

  it("R2 prototype-shaped factor kinds are refused; a prototype-shaped member id is a plain value", async () => {
    const t = alerted();
    for (const factor of ["__proto__", "constructor", "toString"]) await assert.rejects(t.engine.unlock({ ...OK, factor }), rejects("invalid_input", /factor/));
    await t.engine.unlock({ ...OK, memberId: "__proto__" });
    const last = (await t.ledger.list()).at(-1)!;
    assert.equal(Object.hasOwn(last.detail, "memberId") && last.detail.memberId, "__proto__");
  });

  it("R3 every unlock is recorded, even by engines whose id generators repeat (a restart, a second process)", async () => {
    const ledger = new MemoryAuditLedger();
    const counters = new MemoryAttemptCounters();
    const one = alerted({ ledger, counters });
    const two = alerted({ ledger, counters });
    await one.engine.unlock({ ...OK, memberId: "member_1" });
    await two.engine.unlock({ ...OK, memberId: "member_2" });
    const unlocks = (await ledger.list()).filter((e) => e.event === "verification.unlocked").map((e) => e.detail.memberId);
    assert.deepEqual(unlocks, ["member_1", "member_2"]);
  });

  it("R4 a ledger that refuses the record leaves the lock in place: no unrecorded unlock", async () => {
    class Down extends MemoryAuditLedger {
      override append(): never {
        throw new Error("ledger down");
      }
    }
    const counters = new MemoryAttemptCounters();
    const t = alerted({ counters });
    await t.engine.submitPin(await call(t), "0000");
    const down = alerted({ counters, ledger: new Down() });
    await assert.rejects(down.engine.unlock(OK), /ledger down/);
    assert.deepEqual(await t.engine.submitPin(await call(t), PIN), { matched: false, locked: true });
  });
});

describe("#118 hostile: notices", () => {
  it("R5 two workspaces on one counters store keep their own caps: one's flood never silences the other", async () => {
    const counters = new MemoryAttemptCounters();
    const a = alerted({ counters, workspaceId: "ws_a" });
    const b = alerted({ counters, workspaceId: "ws_b" });
    for (let i = 0; i < NOTICES_PER_HOUR + 3; i++) await a.engine.submitPin(await call(a, { subjectKey: i.toString(16).padStart(64, "a") }), "0000");
    assert.equal(a.notifier.notices.length, NOTICES_PER_HOUR);
    await b.engine.submitPin(await call(b), "0000");
    assert.deepEqual(b.notifier.notices.map((n) => [n.workspaceId, n.capped]), [["ws_b", false]]);
  });

  it("R6 a notice carries no digits the caller keyed and no calling number", async () => {
    const t = alerted();
    const callId = await call(t, { callingNumber: CALLING });
    await t.engine.submitPin(callId, "0000");
    await t.engine.submitPin(await call(t, { callingNumber: CALLING }), "9999");
    const text = JSON.stringify(t.notifier.notices);
    for (const secret of [ACCOUNT, CALLING, CALLING.slice(1), "0000", "9999", PIN]) assert.equal(text.includes(secret), false, secret);
    for (const n of t.notifier.notices) assert.deepEqual(Object.keys(n).sort(), ["capped", "factor", "hard", "key", "scope", "until", "workspaceId"]);
  });

  it("R8 a lock entry appended again after an outage, on two engines, is told once", async () => {
    class Flaky extends MemoryAuditLedger {
      down = false;
      override append(input: Parameters<MemoryAuditLedger["append"]>[0]) {
        return this.down ? Promise.reject(new Error("ledger down")) : super.append(input);
      }
    }
    const ledger = new Flaky();
    const counters = new MemoryAttemptCounters();
    const one = alerted({ ledger, counters });
    const two = createTestEngine({ config: testConfig((c) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { lockAfterFailures: 1 })), adapters: { notifier: one.notifier, ledger, counters, sessions: one.sessions, records: one.records }, clock: one.clock });
    const callId = await call(one);
    ledger.down = true;
    await assert.rejects(one.engine.submitPin(callId, "0000"), /ledger down/);
    ledger.down = false;
    await Promise.all([one.engine.flushLedger(callId), two.engine.flushLedger(callId)]);
    assert.equal(one.notifier.notices.length, 1);
  });
});
