// VER-1: failure counters and lockouts across calls, per subject and per calling number.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, AttemptCounters } from "../src/core/adapters.ts";
import { EngineError } from "../src/core/errors.ts";
import { defaultConfig } from "../src/modules.ts";
import { badgeModule } from "../src/verify/badge.ts";
import { DEFAULT_LOCKOUT, counterKeys, lockState, lockoutOf, numberKeyFor, type Lockout } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, attemptCountersContract, createTestEngine, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig, waitOut } from "./helpers.ts";

const T0 = Date.parse("2026-01-01T00:00:00.000Z");
const iso = (ms: number): string => new Date(ms).toISOString();
const HOUR = 3_600_000;
const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const LONG_AGO = "2000-01-01T00:00:00.000Z";
const subjectCounter = (factor: string, key = SUBJECT): AttemptCounterKey => ({ workspaceId: "ws_test", factor, scope: "subject", key });

/** Holds the first `gate` reads until all of them are in, so racing attempts all find the counters open. */
class Barrier extends MemoryAttemptCounters {
  held: Array<() => void> = [];
  gate = 0;
  override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    if (this.gate > 0) {
      this.gate--;
      await new Promise<void>((resolve) => {
        this.held.push(resolve);
        if (this.gate === 0) for (const release of this.held) release();
      });
    }
    return super.get(key, since);
  }
}

describe("MemoryAttemptCounters passes the AttemptCounters contract", () => {
  for (const c of attemptCountersContract(() => new MemoryAttemptCounters())) it(c.name, c.run);
});

/** A store with one flaw at a time, to show the contract suite catches it. */
class FlawedCounters implements AttemptCounters {
  readonly #failures = new Map<string, string[]>();
  readonly flaw: "racy" | "ignores_since" | "shares_keys" | "keeps_after_reset" | "removes_by_rewrite" | "removes_all";

  constructor(flaw: FlawedCounters["flaw"]) {
    this.flaw = flaw;
  }

  #id(key: AttemptCounterKey): string {
    return this.flaw === "shares_keys" ? `${key.workspaceId}/${key.factor}` : JSON.stringify(key);
  }

  #read(key: AttemptCounterKey, since: string): string[] {
    const all = [...(this.#failures.get(this.#id(key)) ?? [])];
    return this.flaw === "ignores_since" ? all : all.filter((t) => t >= since);
  }

  async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    return this.#read(key, since);
  }

  /** Atomic (read and write with no await between) except in the racy mode, so each mode has only its own flaw. */
  async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    const before = this.#read(key, LONG_AGO);
    if (this.flaw === "racy") await new Promise((resolve) => setImmediate(resolve));
    this.#failures.set(this.#id(key), [...before, at]);
    return this.#read(key, since);
  }

  /** Atomic except in the rewrite mode, which reads, yields and writes back, as a reset and a rewrite would. */
  async removeFailure(key: AttemptCounterKey, at: string): Promise<void> {
    const before = this.#read(key, LONG_AGO);
    if (this.flaw === "removes_by_rewrite") await new Promise((resolve) => setImmediate(resolve));
    const i = before.lastIndexOf(at);
    if (i !== -1) before.splice(i, 1);
    if (this.flaw === "removes_by_rewrite") this.#failures.set(this.#id(key), before);
    else this.#failures.set(this.#id(key), this.flaw === "removes_all" && i !== -1 ? [] : this.#read(key, LONG_AGO).filter((_, j) => j !== i));
  }

  async reset(key: AttemptCounterKey): Promise<void> {
    if (this.flaw !== "keeps_after_reset") this.#failures.delete(this.#id(key));
  }
}

describe("the counters contract suite", () => {
  for (const flaw of ["racy", "ignores_since", "shares_keys", "keeps_after_reset", "removes_by_rewrite", "removes_all"] as const) {
    it(`catches a store that ${flaw.startsWith("removes") ? "" : "is "}${flaw.replaceAll("_", " ")}`, async () => {
      const failed: string[] = [];
      for (const c of attemptCountersContract(() => new FlawedCounters(flaw))) await c.run().catch(() => failed.push(c.name));
      assert.ok(failed.length > 0, flaw);
    });
  }
});

describe("lockState: the waits and the hard lock, on a fixed clock", () => {
  const failures = (n: number, at = T0) => Array.from({ length: n }, () => iso(at));

  it("is open with no failures", () => {
    assert.equal(lockState(DEFAULT_LOCKOUT, [], new Date(T0)), null);
  });

  it("waits 5, 15, 60, 300 and 900 seconds after the latest failure, then 900 until the hard lock", () => {
    const waits = [5, 15, 60, 300, 900, 900, 900, 900, 900];
    waits.forEach((seconds, i) => {
      const until = T0 + seconds * 1000;
      assert.deepEqual(lockState(DEFAULT_LOCKOUT, failures(i + 1), new Date(until - 1)), { hard: false, until: iso(until) }, `after ${i + 1}`);
      assert.equal(lockState(DEFAULT_LOCKOUT, failures(i + 1), new Date(until)), null, `after ${i + 1}, once waited`);
    });
  });

  it("counts the wait from the latest failure", () => {
    assert.deepEqual(lockState(DEFAULT_LOCKOUT, [iso(T0), iso(T0 + 60_000)], new Date(T0 + 60_000)), { hard: false, until: iso(T0 + 75_000) });
  });

  it("locks hard after 10 failures, until the oldest of the last 10 leaves the 24-hour window", () => {
    const spread = Array.from({ length: 12 }, (_, i) => iso(T0 + i * HOUR));
    assert.deepEqual(lockState(DEFAULT_LOCKOUT, failures(10), new Date(T0 + 23 * HOUR)), { hard: true, until: iso(T0 + 24 * HOUR) });
    assert.deepEqual(lockState(DEFAULT_LOCKOUT, spread, new Date(T0 + 12 * HOUR)), { hard: true, until: iso(T0 + 2 * HOUR + 24 * HOUR) });
  });

  it("follows stricter settings", () => {
    const strict: Lockout = { backoffSeconds: [10, 30, 120, 600, 1800, 3600], lockAfterFailures: 3, windowHours: 48 };
    assert.deepEqual(lockState(strict, failures(2), new Date(T0)), { hard: false, until: iso(T0 + 30_000) });
    assert.deepEqual(lockState(strict, failures(3), new Date(T0)), { hard: true, until: iso(T0 + 48 * HOUR) });
  });

  it("fills in the defaults, and never shares them", () => {
    const lockout = lockoutOf(undefined);
    assert.deepEqual(lockout, { backoffSeconds: [5, 15, 60, 300, 900], lockAfterFailures: 10, windowHours: 24 });
    lockout.backoffSeconds.push(1);
    assert.deepEqual(DEFAULT_LOCKOUT.backoffSeconds, [5, 15, 60, 300, 900]);
    assert.deepEqual(lockoutOf({ lockAfterFailures: 4 }).lockAfterFailures, 4);
    // As a host's config can carry them, e.g. `lockAfterFailures: env.MAX` with the variable unset.
    const unset = { backoffSeconds: undefined, lockAfterFailures: undefined, windowHours: undefined } as unknown as Parameters<typeof lockoutOf>[0];
    assert.deepEqual(lockoutOf(unset), lockoutOf(undefined), "a setting given as undefined keeps its default");
    const given = [10, 30, 120, 600, 1800];
    const copied = lockoutOf({ backoffSeconds: given });
    copied.backoffSeconds.push(1);
    assert.deepEqual(given, [10, 30, 120, 600, 1800]);
  });

  it("counts a key left out of an older call as none", () => {
    assert.deepEqual(counterKeys("w", "pin", { subjectKey: SUBJECT }), [{ workspaceId: "w", factor: "pin", scope: "subject", key: SUBJECT }]);
  });

  it("keys a subject and a calling number apart, and never keeps the number", () => {
    const numberKey = numberKeyFor(TEST_KNOWLEDGE_KEY, "+15555550142");
    assert.match(numberKey, /^[0-9a-f]{64}$/);
    assert.notEqual(numberKey, numberKeyFor(TEST_KNOWLEDGE_KEY, "+15555550143"));
    assert.deepEqual(counterKeys("w", "pin", { subjectKey: null, numberKey: null }), []);
    assert.deepEqual(counterKeys("w", "pin", { subjectKey: SUBJECT, numberKey }), [
      { workspaceId: "w", factor: "pin", scope: "subject", key: SUBJECT },
      { workspaceId: "w", factor: "pin", scope: "number", key: numberKey },
    ]);
  });
});

describe("the counters adapter's shape (iMac hostile pass on 607b324)", () => {
  it("is checked when the engine is built: a store without removeFailure, written before it existed, is refused", () => {
    const legacy = new MemoryAttemptCounters();
    const store = { get: legacy.get.bind(legacy), recordFailure: legacy.recordFailure.bind(legacy), reset: legacy.reset.bind(legacy) };
    assert.throws(() => setup({ adapters: { counters: store as unknown as AttemptCounters } }), (e: unknown) => e instanceof Error && /counters adapter is missing removeFailure/.test(e.message));
    assert.throws(() => setup({ adapters: { counters: {} as unknown as AttemptCounters } }), /missing get, recordFailure, removeFailure, reset/);
    for (const counters of [null, 7, "counters"]) {
      assert.throws(() => setup({ adapters: { counters: counters as unknown as AttemptCounters } }), (e: unknown) => e instanceof EngineError && e.code === "invalid_input" && /missing get/.test(e.message), String(counters));
    }
    assert.equal(setup({ adapters: { counters: new MemoryAttemptCounters() } }).counters instanceof MemoryAttemptCounters, true);
  });
});

describe("lockouts across calls", () => {
  /** A new call verifying the test account, as a caller calling again. */
  async function call(t: TestEngine, input: { accountNumber?: string; callingNumber?: string } = {}): Promise<string> {
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: input.accountNumber ?? ACCOUNT, ...(input.callingNumber === undefined ? {} : { callingNumber: input.callingNumber }) });
    return callId;
  }

  it("refuses during the wait without judging or using the call's attempt, then locks hard after 10 failures in 24 hours", async () => {
    const t = setup();
    const first = await call(t);
    assert.deepEqual(await t.engine.submitKeypad(first, { dob: "1" }), { matched: false, locked: false });
    assert.deepEqual(await t.engine.submitKeypad(first, { dob: DOB }), { matched: false, locked: true }, "inside the 5-second wait, even the right answer");
    assert.equal((await t.engine.state(first)).factors.length, 1, "the refused attempt was not judged");
    const refused = (await t.ledger.list()).at(-1)!;
    assert.equal(refused.event, "verification.locked");
    assert.deepEqual(refused.detail, { kind: "keypad_knowledge", scope: "subject", hard: false, until: iso(T0 + 5_000) });
    t.clock.advance(5_000);
    assert.deepEqual(await t.engine.submitKeypad(first, { dob: "2" }), { matched: false, locked: true }, "the call's second attempt was still there, and is its last");
    for (let failures = 2; failures < 9; failures++) {
      waitOut(t);
      assert.deepEqual(await t.engine.submitKeypad(await call(t), { dob: "3" }), { matched: false, locked: false });
    }
    waitOut(t);
    const tenth = await call(t);
    assert.deepEqual(await t.engine.submitKeypad(tenth, { dob: "4" }), { matched: false, locked: true }, "the tenth failure locks");
    const until = iso(T0 + 24 * HOUR);
    assert.deepEqual((await t.ledger.list()).at(-1)!.detail, { kind: "keypad_knowledge", scope: "subject", hard: true, until });
    t.clock.advance(20 * HOUR);
    const later = await call(t);
    assert.deepEqual(await t.engine.submitKeypad(later, { dob: DOB }), { matched: false, locked: true }, "a new call, hours later, and the right answer");
    assert.deepEqual((await t.engine.state(later)).factors, []);
    t.clock.advance(Date.parse(until) - t.clock.now().getTime());
    assert.deepEqual(await t.engine.submitKeypad(later, { dob: DOB }), { matched: true, locked: false }, "the oldest failure left the window");
    assert.deepEqual(await t.counters.get(subjectCounter("keypad_knowledge"), LONG_AGO), [], "a pass forgets the failures");
    const ledger = JSON.stringify(await t.ledger.list());
    for (const value of [DOB, ACCOUNT, SUBJECT]) assert.equal(ledger.includes(value), false, "no value in the ledger");
  });

  it("counts each factor kind apart", async () => {
    const t = setup();
    const callId = await call(t);
    await t.engine.submitKeypad(callId, { dob: "1" });
    assert.deepEqual(await t.engine.submitPin(callId, "4826"), { matched: true, locked: false }, "a keypad failure does not hold the PIN back");
  });

  it("counts an unknown subject by its key too, so a lock never tells which accounts exist", async () => {
    const t = setup();
    const answers: unknown[][] = [];
    for (const account of [ACCOUNT, "99999999"]) {
      const seen: unknown[] = [];
      for (let i = 0; i < 10; i++) {
        waitOut(t);
        seen.push(await t.engine.submitKeypad(await call(t, { accountNumber: account }), { dob: "1" }));
      }
      waitOut(t);
      seen.push(await t.engine.submitKeypad(await call(t, { accountNumber: account }), { dob: DOB }));
      answers.push(seen);
    }
    assert.deepEqual(answers[0], answers[1]);
    assert.deepEqual(answers[0]!.at(-1), { matched: false, locked: true });
    const details = (await t.ledger.list()).filter((e) => e.event === "verification.locked").map((e) => ({ ...e.detail, until: null }));
    assert.deepEqual(details.slice(0, 2), details.slice(2), "the same ledger detail");
  });

  it("keeps a line's failures against other accounts through a pass on its own", async () => {
    const t = setup({ config: testConfig((c) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { lockAfterFailures: 3 })) });
    const line = { callingNumber: "+15555550142" };
    const answers: unknown[] = [];
    for (let i = 0; i < 3; i++) {
      waitOut(t);
      answers.push(await t.engine.submitKeypad(await call(t, { ...line, accountNumber: `9999999${i}` }), { dob: "1" }));
      waitOut(t);
      if (i < 2) answers.push(await t.engine.submitKeypad(await call(t, line), { dob: DOB }));
    }
    assert.deepEqual(answers, [
      { matched: false, locked: false },
      { matched: true, locked: false },
      { matched: false, locked: false },
      { matched: true, locked: false },
      { matched: false, locked: true },
    ]);
    assert.deepEqual((await t.ledger.list()).at(-1)!.detail, { kind: "keypad_knowledge", scope: "number", hard: true, until: iso(T0 + 900_000 + 24 * HOUR) });
  });

  it("counts a call saved before calling numbers were kept by its subject only", async () => {
    const seen: AttemptCounterKey[] = [];
    class Spy extends MemoryAttemptCounters {
      override async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
        seen.push(key);
        return super.recordFailure(key, at, since);
      }
    }
    const t = setup({ adapters: { counters: new Spy() } });
    const callId = await call(t);
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as { modules: { badge: { numberKey?: unknown } } };
    delete record.modules.badge.numberKey;
    assert.deepEqual(await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never), { ok: true, version: stored.version + 1 });
    assert.deepEqual(await t.engine.submitPin(callId, "0000"), { matched: false, locked: false });
    assert.deepEqual(seen, [subjectCounter("pin")]);
  });

  it("does not forget the failures for a pass that a restart made stale", async () => {
    let restart = async (): Promise<void> => undefined;
    const plugin = { kind: "voice_passphrase", summary: "a passphrase", maxAttemptsPerCall: 3, adapters: [], judge: async () => (await restart(), true) };
    const t = setup({
      badge: badgeModule({ factors: [plugin] }),
      config: testConfig((c) => {
        c.policy.levels[0] = { level: 1, anyOf: [["voice_passphrase"]] };
        (c.modules.badge!.settings as { factors: string[] }).factors.push("voice_passphrase");
      }),
    });
    const callId = await call(t);
    restart = async () => {
      await t.engine.finishVerification(callId);
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    };
    await assert.rejects(t.engine.submitFactor(callId, "voice_passphrase", "x"), rejects("precondition_failed", /restarted/));
    assert.equal((await t.counters.get(subjectCounter("voice_passphrase"), LONG_AGO)).length, 1, "the stale pass reset nothing");
  });

  it("forgets the subject's counter after a pass, keeps the calling number through a restart, and refuses one that is not E.164", async () => {
    const t = setup();
    const callId = await call(t, { callingNumber: "+15555550142" });
    await t.engine.submitPin(callId, "0000");
    t.clock.advance(5_000);
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const numberCounter: AttemptCounterKey = { workspaceId: "ws_test", factor: "pin", scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, "+15555550142") };
    assert.equal((await t.counters.get(numberCounter, LONG_AGO)).length, 1);
    assert.deepEqual(await t.engine.submitPin(callId, "0001"), { matched: false, locked: false });
    assert.equal((await t.counters.get(numberCounter, LONG_AGO)).length, 2, "the number was kept through the restart");
    t.clock.advance(15_000);
    assert.deepEqual(await t.engine.submitPin(callId, "4826"), { matched: true, locked: false });
    assert.deepEqual(await t.counters.get(numberCounter, LONG_AGO), [iso(T0), iso(T0 + 5_000)], "the pass takes back only its own failure on the number");
    assert.deepEqual(await t.counters.get(subjectCounter("pin"), LONG_AGO), []);
    for (const callingNumber of ["5555550142", "+0555", "anonymous", ""]) {
      await assert.rejects(t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber }), rejects("invalid_input", /E\.164/));
    }
  });

  it("follows stricter settings from the config", async () => {
    const t = setup({ config: testConfig((c) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { lockAfterFailures: 2, windowHours: 48 })) });
    await t.engine.submitPin(await call(t), "0000");
    waitOut(t);
    assert.deepEqual(await t.engine.submitPin(await call(t), "0000"), { matched: false, locked: true });
    t.clock.advance(30 * HOUR);
    assert.deepEqual(await t.engine.submitPin(await call(t), "4826"), { matched: false, locked: true }, "48 hours, not 24");
  });

  it("keeps a failure another engine records on the line while a pass is being forgotten (CodeRabbit, PR 71)", async () => {
    /** Lets a second engine fail on the same line just as the pass starts taking its own failure off the number. */
    class Interleave extends MemoryAttemptCounters {
      during: (() => Promise<unknown>) | null = null;
      async #once(key: AttemptCounterKey): Promise<void> {
        const run = this.during;
        if (key.scope !== "number" || run === null) return;
        this.during = null;
        await run();
      }
      override async removeFailure(key: AttemptCounterKey, at: string): Promise<void> {
        await this.#once(key);
        return super.removeFailure(key, at);
      }
      override async reset(key: AttemptCounterKey): Promise<void> {
        await this.#once(key);
        return super.reset(key);
      }
    }
    const counters = new Interleave();
    const a = setup({ adapters: { counters } });
    const b = createTestEngine({ config: testConfig(), clock: a.clock, ids: a.ids, adapters: { records: a.records, ledger: a.ledger, counters } });
    const line = { callingNumber: "+15555550142" };
    const own = await call(a, line);
    const { callId: other } = await b.engine.startCall();
    await b.engine.beginVerification(other, { ...line, accountNumber: "99999990" });
    counters.during = async () => {
      waitOut(a);
      assert.deepEqual(await b.engine.submitKeypad(other, { dob: "1" }), { matched: false, locked: false });
    };
    assert.deepEqual(await a.engine.submitKeypad(own, { dob: DOB }), { matched: true, locked: false });
    assert.equal(counters.during, null, "the second engine failed during the pass's cleanup");
    const numberCounter: AttemptCounterKey = { workspaceId: "ws_test", factor: "keypad_knowledge", scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, line.callingNumber) };
    assert.deepEqual(await counters.get(numberCounter, LONG_AGO), [iso(T0 + 900_000)], "only the pass's own failure came off the line");
  });

  it("lets one of two attempts racing on two engines be judged, and refuses the other as locked", async () => {
    const counters = new Barrier();
    const a = setup({ adapters: { counters } });
    const b = createTestEngine({ config: testConfig(), clock: a.clock, ids: a.ids, adapters: { records: a.records, ledger: a.ledger, counters } });
    assert.equal(b.counters, counters, "the test engine keeps the counters it was given");
    const line = { accountNumber: ACCOUNT, callingNumber: "+15555550142" };
    const one = await call(a, line);
    const { callId: two } = await b.engine.startCall();
    await b.engine.beginVerification(two, line);
    counters.gate = 2;
    const results = await Promise.all([a.engine.submitPin(one, "0000"), b.engine.submitPin(two, "1111")]);
    assert.deepEqual(results.map((r) => r.locked).sort(), [false, true]);
    const judged = (await a.engine.state(one)).factors.length + (await b.engine.state(two)).factors.length;
    assert.equal(judged, 1, "only one entry was judged");
    assert.equal((await a.counters.get(subjectCounter("pin"), LONG_AGO)).length, 2, "both were counted before judging");
    const numberCounter: AttemptCounterKey = { workspaceId: "ws_test", factor: "pin", scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, "+15555550142") };
    assert.equal((await a.counters.get(numberCounter, LONG_AGO)).length, 1, "the refused one stopped at the counter that raced");
    const [refusedCall, refusedSessions] = results[0]!.locked ? [one, a.sessions] : [two, b.sessions];
    const stored = (await refusedSessions.get("ws_test", refusedCall))!.record as { modules: { badge: { attempts: Record<string, number> } } };
    assert.equal(stored.modules.badge.attempts.pin, 0, "the refused one gave back the call's attempt");
    const locked = (await a.ledger.list()).filter((e) => e.event === "verification.locked");
    assert.deepEqual(locked.map((e) => e.detail), [{ kind: "pin", scope: "subject", hard: false, until: iso(T0 + 5_000) }]);
  });

  it("makes the second of two right entries for one account at once wait, unjudged, until the first's pass is accepted (decision 1)", async () => {
    // Two genuine callers for one account, on two lines, enter the right PIN at the same instant.
    // The first's failure is recorded before it is judged, so the second meets a wait: it is not
    // judged and not skipped, and the clock never moves here, so only the first's pass lets it in.
    const counters = new Barrier();
    const t = setup({ adapters: { counters } });
    const one = await call(t, { callingNumber: "+15555550142" });
    const two = await call(t, { callingNumber: "+15555550143" });
    counters.gate = 2;
    const results = await Promise.all([t.engine.submitPin(one, "4826"), t.engine.submitPin(two, "4826")]);
    assert.deepEqual(results, [
      { matched: true, locked: false },
      { matched: false, locked: true },
    ], "the first is judged and passes; the second, with the right PIN too, waits");
    assert.deepEqual((await t.engine.state(two)).factors, [], "the waiting entry was not judged");
    const stored = (await t.sessions.get("ws_test", two))!.record as { modules: { badge: { attempts: Record<string, number> } } };
    assert.equal(stored.modules.badge.attempts.pin, 0, "the waiting entry gave back the call's attempt");
    const locked = (await t.ledger.list()).filter((e) => e.event === "verification.locked");
    assert.deepEqual(locked.map((e) => e.detail), [{ kind: "pin", scope: "subject", hard: false, until: iso(T0 + 5_000) }], "the wait is the first's provisional failure");
    assert.deepEqual(await t.counters.get(subjectCounter("pin"), LONG_AGO), [], "the first's pass forgot both failures on the subject");
    assert.deepEqual(await t.engine.submitPin(two, "4826"), { matched: true, locked: false }, "once the pass is accepted, the second gets in at once, with no time passed");
  });

  it("makes the second of two entries for one account at once wait the longer wait for two when the first fails", async () => {
    const counters = new Barrier();
    const t = setup({ adapters: { counters } });
    const one = await call(t, { callingNumber: "+15555550142" });
    const two = await call(t, { callingNumber: "+15555550143" });
    counters.gate = 2;
    const results = await Promise.all([t.engine.submitPin(one, "0000"), t.engine.submitPin(two, "4826")]);
    assert.deepEqual(results, [
      { matched: false, locked: false },
      { matched: false, locked: true },
    ]);
    assert.equal((await t.counters.get(subjectCounter("pin"), LONG_AGO)).length, 2, "both failures stand on the subject");
    t.clock.advance(5_000);
    assert.deepEqual(await t.engine.submitPin(two, "4826"), { matched: false, locked: true }, "the 5-second wait is not enough after two failures");
    t.clock.advance(10_000);
    assert.deepEqual(await t.engine.submitPin(two, "4826"), { matched: true, locked: false }, "after 15 seconds the second gets in");
  });

  it("counts a host's factor plug-in, and needs the counters for it", async () => {
    const plugin = { kind: "voice_passphrase", summary: "a passphrase", maxAttemptsPerCall: 3, adapters: [], judge: async () => false };
    const badge = badgeModule({ factors: [plugin] });
    assert.deepEqual(badge.requiredAdapters({ factors: ["voice_passphrase"] }), ["records", "counters"]);
    const t = setup({
      badge,
      config: testConfig((c) => {
        c.policy.levels[0] = { level: 1, anyOf: [["voice_passphrase"]] };
        (c.modules.badge!.settings as { factors: string[] }).factors.push("voice_passphrase");
      }),
    });
    const callId = await call(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "voice_passphrase", "x"), { matched: false, locked: false });
    assert.deepEqual(await t.engine.submitFactor(callId, "voice_passphrase", "x"), { matched: false, locked: true });
    assert.equal((await t.counters.get(subjectCounter("voice_passphrase"), LONG_AGO)).length, 1);
  });

  it("refuses an attempt on a call Badge was off for, and a locked one outside verification, with no ledger entry", async () => {
    const t = setup({ config: { ...defaultConfig(), modules: {} } });
    const { callId } = await t.engine.startCall();
    t.engine.configure(testConfig());
    await assert.rejects(t.engine.submitPin(callId, "4826"), rejects("module_disabled", /was off when this call started/));
    const open = await t.engine.startCall();
    await t.engine.beginVerification(open.callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(open.callId, "0000");
    await t.engine.finishVerification(open.callId);
    await assert.rejects(t.engine.submitPin(open.callId, "4826"), rejects("invalid_transition"), "locked or not, a call that is not verifying is refused first");
    assert.equal((await t.ledger.list()).some((e) => e.event === "verification.locked"), false);
  });
});
