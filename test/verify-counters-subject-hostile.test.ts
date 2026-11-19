// Hostile pass on #71 (VER-1 counters), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import { BadgeModule } from "../src/verify/badge.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, setup, testConfig } from "./helpers.ts";

const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const LONG_AGO = "2000-01-01T00:00:00.000Z";
const subjKey = (workspaceId = "ws_test"): AttemptCounterKey => ({ workspaceId, factor: "pin", scope: "subject", key: SUBJECT });
const WRONG = ["1357", "2468", "3579", "4680", "5791", "6802", "7913", "8024", "9135", "0246", "1470", "2581"];

describe("#71 hostile: the subject a host names", () => {
  it("W1 a subject key that is not a string is refused, so the PIN is never judged without the subject's counter", async () => {
    const t = setup();
    for (const subjectKey of [[SUBJECT], { toString: () => SUBJECT }]) {
      const { callId } = await t.engine.startCall();
      await assert.rejects(t.engine.beginVerification(callId, { subjectKey: subjectKey as unknown as string }), rejects("invalid_input", /subjectKey/), JSON.stringify(subjectKey));
    }
  });

  it("W1b ...so twelve wrong PINs on a host-named subject always lock it", async () => {
    const t = setup();
    let locked = false;
    for (const pin of WRONG) {
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { subjectKey: SUBJECT });
      t.clock.advance(900_000);
      if ((await t.engine.submitPin(callId, pin)).locked) locked = true;
    }
    assert.equal(locked, true);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: SUBJECT });
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true }, "the right PIN is refused while the lock holds");
  });

  it("W2 a subject key read twice cannot be swapped after it was checked", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    let reads = 0;
    const input = {
      get subjectKey() {
        reads++;
        return reads === 1 ? SUBJECT : "f".repeat(64);
      },
    };
    await t.engine.beginVerification(callId, input);
    t.clock.advance(900_000);
    await t.engine.submitPin(callId, "0000");
    assert.equal((await t.counters.get(subjKey(), LONG_AGO)).length, 1, "the failure is on the subject that was checked");
    assert.equal((await t.counters.get({ ...subjKey(), key: "f".repeat(64) }, LONG_AGO)).length, 0, "never on the swapped one");
    assert.equal(reads, 1, "read once");
  });
});

describe("#71 hostile: stores, clocks and tenants", () => {
  it("W3 a clock set back after a failure never shortens the wait it started", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, "0000");
    t.clock.advance(-3_600_000);
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true });
  });

  it("W4 two workspaces on one counters store never lock each other's subject with the same key", async () => {
    const counters = new MemoryAttemptCounters();
    const config = testConfig((c) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { lockAfterFailures: 1 }));
    const a = createTestEngine({ workspaceId: "ws_a", config, adapters: { counters } });
    const b = createTestEngine({ workspaceId: "ws_b", config, adapters: { counters } });
    for (const t of [a, b]) t.records.putSubject(t.engine.workspaceId, testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
    const ca = (await a.engine.startCall()).callId;
    await a.engine.beginVerification(ca, { accountNumber: ACCOUNT });
    assert.deepEqual(await a.engine.submitPin(ca, "0000"), { matched: false, locked: true });
    const cb = (await b.engine.startCall()).callId;
    await b.engine.beginVerification(cb, { accountNumber: ACCOUNT });
    assert.deepEqual(await b.engine.submitPin(cb, PIN), { matched: true, locked: false });
  });

  it("W5 concurrent entries on a call's last attempt judge only one", async () => {
    const t = setup({ config: testConfig((c) => ((c.modules.badge!.settings as { pin: { maxAttemptsPerCall: number } }).pin.maxAttemptsPerCall = 1)) });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const [wrong, right] = await Promise.all([t.engine.submitPin(callId, "0000"), t.engine.submitPin(callId, PIN)]);
    const factors = (await t.engine.state(callId)).factors;
    assert.equal(factors.length, 1, "exactly one entry judged");
    // The judged entry answers as judged; the other is refused, the call's last attempt used.
    const [judged, refused] = factors[0]!.passed ? [right, wrong] : [wrong, right];
    assert.deepEqual(judged, { matched: factors[0]!.passed, locked: !factors[0]!.passed });
    assert.deepEqual(refused, { matched: false, locked: true });
  });

  it("W6 lockout settings that are not plain numbers are refused, prototype keys included", () => {
    const badge = new BadgeModule([]);
    const base = { factors: ["pin"], pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 } };
    for (const lockout of [
      { backoffSeconds: [5, 15, 60, 300, Infinity] },
      { backoffSeconds: [5, 15, 60, 300, Number.NaN] },
      { backoffSeconds: [5, 15, 60, 300, "900"] },
      // eslint-disable-next-line no-sparse-arrays
      { backoffSeconds: [5, 15, 60, , 900] },
      { lockAfterFailures: 0 },
      { lockAfterFailures: 1.5 },
      { windowHours: 1e308 },
      JSON.parse('{"__proto__": {"lockAfterFailures": 1}}'),
      { constructor: 1 },
      [],
      "10",
    ]) {
      assert.ok(badge.validateSettings({ ...base, lockout }).length > 0, JSON.stringify(lockout));
    }
  });
});
