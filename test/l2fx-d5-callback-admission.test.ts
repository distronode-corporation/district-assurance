// Callback dials, V6 of the L2 review: a resumed dial whose admission is known not to have counted
// (the daily-limit read failed) is not held for a day; one that may have counted stays held.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, CallbackDialer } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { CALLBACKS_PLACED } from "../src/verify/callback.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeCallbackDialer, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, PIN, setup, testConfig } from "./helpers.ts";

const CALLING = "+15555550199";
const DAY = 86_400_000;
const PLACED: AttemptCounterKey = { workspaceId: "ws_test", factor: CALLBACKS_PLACED, scope: "subject", key: subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT) };

function callbackConfig(): FlowConfig {
  return testConfig((c) => {
    c.modules.badge = {
      settings: {
        factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "callback"],
        pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 },
      } as never,
    };
    c.policy.levels[1]!.anyOf.push(["pin", "callback"]);
  });
}

/** Counters whose next daily-limit read, or next daily-limit count, runs a hook once armed. */
class Faulty extends MemoryAttemptCounters {
  onGet: (() => Promise<void>) | null = null;
  onRecord: ((write: () => Promise<string[]>) => Promise<string[]>) | null = null;
  override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    const hook = key.factor === CALLBACKS_PLACED ? this.onGet : null;
    if (hook !== null) {
      this.onGet = null;
      await hook();
    }
    return super.get(key, since);
  }
  override async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    const hook = key.factor === CALLBACKS_PLACED ? this.onRecord : null;
    if (hook === null) return super.recordFailure(key, at, since);
    this.onRecord = null;
    return hook(() => super.recordFailure(key, at, since));
  }
}

/** A placed callback whose first dial failed, a day later, about to be resumed. */
async function dayOld(counters: Faulty) {
  const fake = new FakeCallbackDialer();
  let failing = true;
  const dialer: CallbackDialer = { async dial(input) { if (failing) throw new Error("telephony down"); return fake.dial(input); } };
  const t = setup({ config: callbackConfig(), adapters: { counters, dialer } });
  const { callId: asking } = await t.engine.startCall({});
  await t.engine.beginVerification(asking, { accountNumber: ACCOUNT, callingNumber: CALLING });
  assert.equal((await t.engine.submitPin(asking, PIN)).matched, true);
  await t.engine.requestCallback(asking);
  t.clock.advance(DAY);
  failing = false;
  return { t, fake, asking };
}

const placedToday = (t: TestEngine, counters: MemoryAttemptCounters) => counters.get(PLACED, new Date(t.clock.now().getTime() - DAY + 1).toISOString());
const admitting = async (t: TestEngine) => ((await t.sessions.get("ws_test", "call_2"))!.record as unknown as { modules: { badge: { callback: { admitting?: string } } } }).modules.badge.callback.admitting;

describe("V6: an admission known not to have counted is recoverable", () => {
  it("a daily-limit read that failed leaves no claim: the next try counts once and rings", async () => {
    const counters = new Faulty();
    const { t, fake, asking } = await dayOld(counters);
    counters.onGet = async () => {
      throw new Error("counters down");
    };
    await t.engine.requestCallback(asking);
    assert.equal(fake.dialed.length, 0);
    assert.equal(await admitting(t), undefined, "the claim is taken back");
    t.clock.advance(60_000);
    await t.engine.requestCallback(asking);
    assert.equal(fake.dialed.length, 1, "rings within the day");
    assert.equal((await placedToday(t, counters)).length, 1, "counted once");
  });

  it("a claim taken back while a newer try holds its own leaves the newer one", async () => {
    const counters = new Faulty();
    const { t, fake, asking } = await dayOld(counters);
    let newer: string | undefined;
    counters.onGet = async () => {
      // This try's claim is a day old by the time its read fails: another try claims, counts and rings.
      t.clock.advance(DAY);
      await t.engine.requestCallback(asking);
      newer = await admitting(t);
      throw new Error("counters down");
    };
    await t.engine.requestCallback(asking);
    assert.notEqual(newer, undefined);
    assert.equal(await admitting(t), newer, "the newer claim stays");
    assert.equal(fake.dialed.length, 1);
    assert.equal((await placedToday(t, counters)).length, 1);
  });

  it("a claim whose take-back write fails stays held (fail closed)", async () => {
    const counters = new Faulty();
    const { t, fake, asking } = await dayOld(counters);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    counters.onGet = async () => {
      t.sessions.compareAndSet = async () => {
        throw new Error("store down");
      };
      throw new Error("counters down");
    };
    await t.engine.requestCallback(asking);
    t.sessions.compareAndSet = cas;
    assert.notEqual(await admitting(t), undefined);
    await t.engine.requestCallback(asking);
    assert.equal(fake.dialed.length, 0, "held, no ring");
    assert.equal((await placedToday(t, counters)).length, 0);
  });
});

describe("V6: an admission that may have counted stays charged", () => {
  it("a count that saved and then failed: the next try rings with it and counts nothing more", async () => {
    const counters = new Faulty();
    const { t, fake, asking } = await dayOld(counters);
    counters.onRecord = async (write) => {
      await write();
      throw new Error("answer lost");
    };
    await t.engine.requestCallback(asking);
    assert.equal(fake.dialed.length, 0);
    t.clock.advance(60_000);
    await t.engine.requestCallback(asking);
    assert.equal(fake.dialed.length, 1);
    assert.equal((await placedToday(t, counters)).length, 1, "counted once");
  });

  it("a count that failed with no answer keeps the claim: no second count, no ring, within the day", async () => {
    const counters = new Faulty();
    const { t, fake, asking } = await dayOld(counters);
    counters.onRecord = async () => {
      throw new Error("no answer");
    };
    await t.engine.requestCallback(asking);
    t.clock.advance(60_000);
    await t.engine.requestCallback(asking);
    assert.notEqual(await admitting(t), undefined);
    assert.equal(fake.dialed.length, 0);
    assert.equal((await placedToday(t, counters)).length, 0);
  });
});
