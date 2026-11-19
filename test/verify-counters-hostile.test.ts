// VER-1 counters under two engines and flawed or malformed stores, from the iMac's hostile passes on
// wp-a 607b324 and 85e0766.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import { numberKeyFor } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, attemptCountersContract, createTestEngine, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PIN, setup, testConfig, waitOut } from "./helpers.ts";

const LINE = "+15555550142";
const LONG_AGO = "2000-01-01T00:00:00.000Z";
const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const numKey = (factor: string): AttemptCounterKey => ({ workspaceId: "ws_test", factor, scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, LINE) });
const subjKey = (factor: string): AttemptCounterKey => ({ workspaceId: "ws_test", factor, scope: "subject", key: SUBJECT });

async function call(t: TestEngine, accountNumber = ACCOUNT): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber, callingNumber: LINE });
  return callId;
}
const settle = <T>(p: Promise<T>) => p.then((v) => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e: String(e) }));

describe("wp-a: two engines, one counter store", () => {
  it("same-millisecond fail on engine B and pass on engine A: exactly one failure stays on the number", async () => {
    const counters = new MemoryAttemptCounters();
    const a = setup({ adapters: { counters } });
    const b = createTestEngine({ config: testConfig(), clock: a.clock, ids: a.ids, adapters: { records: a.records, ledger: a.ledger, counters } });
    const own = await call(a);
    const other = await call(b, "99999990");
    // Both at the FixedClock's same instant.
    const [ra, rb] = await Promise.all([a.engine.submitKeypad(own, { dob: DOB }), b.engine.submitKeypad(other, { dob: "1" })]);
    assert.equal(ra.matched, true);
    assert.equal(rb.matched, false, "the wrong answer for the unknown account fails");
    const left = await counters.get(numKey("keypad_knowledge"), LONG_AGO);
    assert.deepEqual(left, [a.clock.now().toISOString()], `failures on the number: ${JSON.stringify(left)}`);
  });

  it("pass cannot lift a hard lock others put on the number", async () => {
    const counters = new MemoryAttemptCounters();
    const a = setup({ adapters: { counters } });
    // 9 failures from other accounts, then the owner's pass is the 10th recorded: it is judged, passes, takes only its own off.
    for (let i = 0; i < 9; i++) await counters.recordFailure(numKey("keypad_knowledge"), new Date(Date.parse("2025-12-31T23:00:00.000Z") + i).toISOString(), LONG_AGO);
    waitOut(a);
    const own = await call(a);
    const r = await a.engine.submitKeypad(own, { dob: DOB });
    assert.equal(r.matched, true);
    const left = await counters.get(numKey("keypad_knowledge"), LONG_AGO);
    assert.equal(left.length >= 9, true);
    // An 11th, failing from another account, is refused locked.
    const c2 = await call(a, "99999990");
    const r2 = await a.engine.submitKeypad(c2, { dob: "1" });
    const after = await counters.get(numKey("keypad_knowledge"), LONG_AGO);
    assert.deepEqual(r2, { matched: false, locked: true });
    assert.equal(after.length, 10);
  });

  it("subject scope: a pass on line A forgets the subject's failures up to it and keeps one engine B recorded on line B in between", async () => {
    class Interleave extends MemoryAttemptCounters {
      during: (() => Promise<unknown>) | null = null;
      override async removeFailure(key: AttemptCounterKey, at: string): Promise<void> {
        const run = this.during;
        if (key.scope === "subject" && run !== null) {
          this.during = null;
          await run();
        }
        return super.removeFailure(key, at);
      }
    }
    const counters = new Interleave();
    const a = setup({ adapters: { counters } });
    const b = createTestEngine({ config: testConfig(), clock: a.clock, ids: a.ids, adapters: { records: a.records, ledger: a.ledger, counters } });
    const own = await call(a);
    const { callId: attacker } = await b.engine.startCall();
    await b.engine.beginVerification(attacker, { accountNumber: ACCOUNT, callingNumber: "+15555550199" });
    let before: string[] | null = null;
    let judged: unknown = null;
    counters.during = async () => {
      waitOut(a);
      judged = await b.engine.submitKeypad(attacker, { dob: "1" });
      before = await counters.get(subjKey("keypad_knowledge"), LONG_AGO);
    };
    assert.equal((await a.engine.submitKeypad(own, { dob: DOB })).matched, true);
    assert.deepEqual(judged, { matched: false, locked: false }, "the hook ran and the attacker's submit was judged and failed");
    assert.ok(before !== null && (before as string[]).includes(a.clock.now().toISOString()), `the attacker's failure is on the subject before reset: ${JSON.stringify(before)}`);
    const left = await counters.get(subjKey("keypad_knowledge"), LONG_AGO);
    // Recorded after the pass (T13): the pass's cleanup is not its to forget.
    assert.equal(left.length, 1, "the attacker's later failure on the subject stays");
  });
});

describe("wp-a: flawed stores", () => {
  it("removeFailure throws: the pass is already on the call, submit rejects, the failure stays (fail closed)", async () => {
    class Throws extends MemoryAttemptCounters {
      override async removeFailure(): Promise<void> {
        throw new Error("store 503");
      }
    }
    const counters = new Throws();
    const a = setup({ adapters: { counters } });
    const own = await call(a);
    const r = await settle(a.engine.submitKeypad(own, { dob: DOB }));
    const state = await a.engine.state(own);
    const left = await counters.get(numKey("keypad_knowledge"), LONG_AGO);
    assert.equal(state.factors.length, 1, "the pass is on the call");
    assert.equal(r.ok, false);
    assert.equal(left.length, 1);
  });

  it("a host store written before removeFailure existed: refused when the engine is built", async () => {
    const legacy = new MemoryAttemptCounters() as unknown as Record<string, unknown>;
    const store = {
      get: (k: AttemptCounterKey, s: string) => (legacy.get as Function).call(legacy, k, s),
      recordFailure: (k: AttemptCounterKey, at: string, s: string) => (legacy.recordFailure as Function).call(legacy, k, at, s),
      reset: (k: AttemptCounterKey) => (legacy.reset as Function).call(legacy, k),
    };
    assert.throws(() => setup({ adapters: { counters: store as never } }), (e: unknown) => /invalid_input/.test(String((e as { code?: string }).code)) && /removeFailure/.test(String(e)));
  });

  it("each method missing, or a non-function value, is refused at construction", () => {
    const fn = async () => undefined;
    const full = { get: fn, recordFailure: fn, removeFailure: fn, reset: fn };
    const bads: unknown[] = [true, 1, "fn", {}, null, Object.create(null), { call: fn }, Symbol("x")];
    for (const name of ["get", "recordFailure", "removeFailure", "reset"]) {
      const { [name as keyof typeof full]: _drop, ...rest } = full;
      assert.throws(() => setup({ adapters: { counters: rest as never } }), new RegExp(name), `missing ${name}`);
      for (const bad of bads) assert.throws(() => setup({ adapters: { counters: { ...full, [name]: bad } as never } }), new RegExp(name), `${name}=${typeof bad}`);
    }
    // Prototype methods (a class instance) pass; a getter returning a function passes.
    assert.doesNotThrow(() => setup({ adapters: { counters: new MemoryAttemptCounters() } }));
  });

  it("odd adapters: null, a primitive, a Proxy that throws", () => {
    const out: string[] = [];
    for (const counters of [null, 0, "x", new Proxy({}, { get() { throw new Error("trap"); } })]) {
      try {
        setup({ adapters: { counters: counters as never } });
        out.push("ACCEPTED");
      } catch (e) {
        out.push(String((e as { code?: string }).code ?? (e as Error).name) + ": " + String((e as Error).message).slice(0, 60));
      }
    }
    assert.deepEqual(out.map((o) => o.split(":")[0]), ["invalid_input", "invalid_input", "invalid_input", "invalid_input"], out.join(" | "));
  });

  it("contract suite vs a store whose removeFailure removes the OLDEST failure whatever `at`", async () => {
    class Oldest extends MemoryAttemptCounters {
      override async removeFailure(key: AttemptCounterKey): Promise<void> {
        const all = await this.get(key, LONG_AGO);
        if (all.length === 0) return;
        await this.reset(key);
        for (const t of all.slice(1)) await this.recordFailure(key, t, LONG_AGO);
      }
    }
    const failed: string[] = [];
    for (const c of attemptCountersContract(() => new Oldest())) await c.run().catch(() => failed.push(c.name));
    assert.ok(failed.length > 0);
  });

  it("contract suite vs a store whose removeFailure is a no-op", async () => {
    class Noop extends MemoryAttemptCounters {
      override async removeFailure(): Promise<void> {}
    }
    const failed: string[] = [];
    for (const c of attemptCountersContract(() => new Noop())) await c.run().catch(() => failed.push(c.name));
    assert.ok(failed.length > 0);
  });
});

describe("wp-a: PIN path", () => {
  it("a PIN pass takes its own failure off the number, keeps another account's", async () => {
    const counters = new MemoryAttemptCounters();
    const a = setup({ adapters: { counters } });
    a.clock.advance(1);
    await counters.recordFailure(numKey("pin"), new Date(Date.parse("2026-01-01T00:00:00.000Z")).toISOString(), LONG_AGO);
    waitOut(a);
    const own = await call(a);
    assert.equal((await a.engine.submitPin(own, PIN)).matched, true);
    assert.deepEqual(await counters.get(numKey("pin"), LONG_AGO), ["2026-01-01T00:00:00.000Z"], "the seeded failure survives, the pass's own is gone");
  });
});

describe("wp-a: calling numbers", () => {
  it("refuses a calling number that is not a string, never coerced into one by the E.164 check", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    for (const callingNumber of [["+15555550142"], { toString: () => "+15555550142" }, 15555550142]) {
      await assert.rejects(
        t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: callingNumber as unknown as string }),
        (e: unknown) => e instanceof Error && /E\.164/.test(e.message),
        JSON.stringify(callingNumber),
      );
    }
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: "+15555550142" });
  });
});
