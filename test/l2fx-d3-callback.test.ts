// Callback dials, round 3 of the L2 review: a resumed callback is counted once per day across
// workers (U8), no dial is claimed on an ended call (U9), and a callback's lock notice names the
// counter that locked (U10).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, CallbackDialer } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { CALLBACKS_PLACED, MAX_CALLBACKS_PER_DAY } from "../src/verify/callback.ts";
import { numberKeyFor } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeCallbackDialer, FakeNotifier, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, type TestEngine, type TestEngineOptions } from "../src/testing/index.ts";
import { ACCOUNT, PIN, setup, testConfig } from "./helpers.ts";

const CALLING = "+15555550199";
const DAY = 86_400_000;
const PLACED: AttemptCounterKey = { workspaceId: "ws_test", factor: CALLBACKS_PLACED, scope: "subject", key: subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT) };

function callbackConfig(lockout?: unknown): FlowConfig {
  return testConfig((c) => {
    c.modules.badge = {
      settings: {
        factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "callback"],
        pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 },
        ...(lockout === undefined ? {} : { lockout }),
      } as never,
    };
    c.policy.levels[1]!.anyOf.push(["pin", "callback"]);
  });
}

async function firstCall(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall({});
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
  assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
  return callId;
}

/** Counters whose next read of the daily-limit counter waits once armed. */
class Gated extends MemoryAttemptCounters {
  armed = false;
  release: () => void = () => undefined;
  reached: Promise<void> = Promise.resolve();
  #gate: Promise<void> = Promise.resolve();
  #hit: () => void = () => undefined;
  arm(): void {
    this.armed = true;
    this.#gate = new Promise((r) => (this.release = r));
    this.reached = new Promise((r) => (this.#hit = r));
  }
  override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    if (this.armed && key.factor === CALLBACKS_PLACED) {
      this.armed = false;
      this.#hit();
      await this.#gate;
    }
    return super.get(key, since);
  }
}

/** A placed callback whose first dial failed, a day later, with two workers about to resume it. */
async function dayOld(o: TestEngineOptions & { counters: Gated }) {
  const fake = new FakeCallbackDialer();
  let failing = true;
  const dialer: CallbackDialer = { async dial(input) { if (failing) throw new Error("telephony down"); return fake.dial(input); } };
  const t = setup({ config: callbackConfig(), ...o, adapters: { counters: o.counters, dialer } });
  const asking = await firstCall(t);
  await t.engine.requestCallback(asking);
  t.clock.advance(DAY);
  failing = false;
  return { t, fake, asking };
}

const placedToday = (t: TestEngine, counters: MemoryAttemptCounters) => counters.get(PLACED, new Date(t.clock.now().getTime() - DAY + 1).toISOString());

describe("U8: a resumed callback is counted once, across workers", () => {
  it("two resumes at once count it once and ring once", async () => {
    const counters = new Gated();
    const { t, fake, asking } = await dayOld({ counters });
    counters.arm();
    const one = t.engine.requestCallback(asking);
    await counters.reached;
    await t.engine.requestCallback(asking);
    counters.release();
    await one;
    assert.equal((await placedToday(t, counters)).length, 1, "counted once");
    assert.equal(fake.dialed.length, 1);
  });

  it("at the limit's last place, the second worker neither counts it nor fails it", async () => {
    const counters = new Gated();
    const { t, fake, asking } = await dayOld({ counters });
    const now = t.clock.now().getTime();
    for (let i = 0; i < MAX_CALLBACKS_PER_DAY - 1; i++) await counters.recordFailure(PLACED, new Date(now - 1000 * (i + 1)).toISOString(), new Date(now - DAY + 1).toISOString());
    counters.arm();
    const one = t.engine.requestCallback(asking);
    await counters.reached;
    await t.engine.requestCallback(asking);
    counters.release();
    await one;
    assert.equal(fake.dialed.length, 1, "the last place is taken by this callback");
    assert.equal((await placedToday(t, counters)).length, MAX_CALLBACKS_PER_DAY);
  });

  it("a resume after the counting worker saved its count dials with it", async () => {
    const counters = new Gated();
    const { t, fake, asking } = await dayOld({ counters });
    // The worker that counted it stopped before claiming the dial: its count is in the store.
    const record = (await t.sessions.get("ws_test", "call_2"))!;
    const at = t.clock.now().toISOString();
    const r = structuredClone(record.record) as { modules: { badge: { callback: Record<string, unknown> } } };
    r.modules.badge.callback.admitting = at;
    assert.equal((await t.sessions.compareAndSet("ws_test", "call_2", record.version, r as never)).ok, true);
    await counters.recordFailure(PLACED, at, new Date(t.clock.now().getTime() - DAY + 1).toISOString());
    t.clock.advance(60_000);
    await t.engine.requestCallback(asking);
    assert.equal(fake.dialed.length, 1);
    assert.equal((await placedToday(t, counters)).length, 1, "not counted again");
  });

  it("a claim left by a worker that never counted holds: no ring, no count, until a day has passed", async () => {
    const counters = new Gated();
    const { t, fake, asking } = await dayOld({ counters });
    const record = (await t.sessions.get("ws_test", "call_2"))!;
    const r = structuredClone(record.record) as { modules: { badge: { callback: Record<string, unknown> } } };
    r.modules.badge.callback.admitting = t.clock.now().toISOString();
    assert.equal((await t.sessions.compareAndSet("ws_test", "call_2", record.version, r as never)).ok, true);
    await t.engine.requestCallback(asking);
    assert.equal(fake.dialed.length, 0);
    assert.equal((await placedToday(t, counters)).length, 0);
    t.clock.advance(DAY);
    await t.engine.requestCallback(asking);
    assert.equal(fake.dialed.length, 1, "a day later it is claimed and counted again");
  });
});

describe("U8: a resumed callback voided while the store is read", () => {
  it("is neither counted nor dialed", async () => {
    const counters = new Gated();
    const { t, fake, asking } = await dayOld({ counters });
    const read = t.records.getSubject.bind(t.records);
    let calls = 0;
    t.records.getSubject = async (w, key) => {
      const subject = await read(w, key);
      if (++calls === 1) await t.engine.markUntrusted("call_2", "crm_note");
      return subject;
    };
    await t.engine.requestCallback(asking);
    assert.equal(calls, 1);
    assert.equal(fake.dialed.length, 0);
    assert.equal((await placedToday(t, counters)).length, 0);
  });
});

describe("U9: no dial is claimed once the callback call ended", () => {
  it("a callback call ended while the store was read never rings, and nothing follows its receipt", async () => {
    const t = setup({ config: callbackConfig() });
    const asking = await firstCall(t);
    const read = t.records.getSubject.bind(t.records);
    let calls = 0;
    t.records.getSubject = async (w, key) => {
      const subject = await read(w, key);
      if (++calls === 1) await t.engine.endCall("call_2");
      return subject;
    };
    await t.engine.requestCallback(asking);
    assert.equal(calls, 1);
    assert.equal(t.dialer.dialed.length, 0, "zero dials");
    const ledger = (await t.ledger.list()).filter((e) => e.callId === "call_2").map((e) => e.event);
    assert.equal(ledger.at(-1), "receipt.issued");
  });
});

describe("U10: a callback's lock notice names the counter that locked", () => {
  it("a number lock started by a failed callback names the calling number's key", async () => {
    const counters = new MemoryAttemptCounters();
    const notifier = new FakeNotifier();
    const t = setup({ config: callbackConfig({ lockAfterFailures: 2 }), adapters: { counters, notifier } });
    const numberKey = numberKeyFor(TEST_KNOWLEDGE_KEY, CALLING);
    // An earlier failed callback from the same number, against another account.
    const now = t.clock.now().toISOString();
    await counters.recordFailure({ workspaceId: "ws_test", factor: "callback", scope: "number", key: numberKey }, now, "2000-01-01T00:00:00.000Z");
    t.clock.advance(900_000);
    await t.engine.requestCallback(await firstCall(t));
    const { ref } = t.dialer.dialed.at(-1)!;
    await t.engine.applyCallbackOutcome({ ref, answered: false, confirmed: false });
    for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
    const notices = notifier.notices.filter((n) => n.factor === "callback" && n.scope === "number");
    assert.equal(notices.length, 1);
    assert.equal(notices[0]!.key, numberKey);
  });
});
