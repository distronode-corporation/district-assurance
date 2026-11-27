// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Callback claims, V5b of the L2 review: a claim on the callback call is this try's only when the
// call holds this try's own token. A claim write that saved nothing, then another try's claim before
// the read-back, is not this try's; a claim saved with no token is no try's (fail closed).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, CallbackDialer } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { CALLBACKS_PLACED } from "../src/verify/callback.ts";
import { numberKeyFor } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeCallbackDialer, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, PIN, setup, testConfig } from "./helpers.ts";

const CALLING = "+15555550199";
const DAY = 86_400_000;
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const numberKey: AttemptCounterKey = { workspaceId: "ws_test", factor: "callback", scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, CALLING) };
const PLACED: AttemptCounterKey = { workspaceId: "ws_test", factor: CALLBACKS_PLACED, scope: "subject", key: subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT) };

type Callback = { forgetPending?: boolean; forgetClaimed?: true; forgetClaimToken?: string; admitting?: string; admittingToken?: string };
type Slice = { modules: { badge: { callback: Callback } } };

function callbackConfig(): FlowConfig {
  return testConfig((c) => {
    c.modules.badge = { settings: { factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "callback"], pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 } } as never };
    c.policy.levels[1]!.anyOf.push(["pin", "callback"]);
  });
}

async function firstCall(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
  assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
  return callId;
}

/** Writes `change` over the stored callback call as another try would, in a write of its own. */
async function anotherTry(t: TestEngine, callId: string, change: (c: Callback) => void): Promise<void> {
  const stored = (await t.sessions.get("ws_test", callId))!;
  const other = structuredClone(stored.record) as unknown as Slice;
  change(other.modules.badge.callback);
  assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, other as unknown as JsonValue)).ok, true);
}

/** Fails once the write that matches, unsaved, after `meanwhile` (another try's write). */
function failWrite(t: TestEngine, when: (before: Callback, after: Callback) => boolean, meanwhile: () => Promise<void>): void {
  const cas = t.sessions.compareAndSet.bind(t.sessions);
  t.sessions.compareAndSet = async (workspaceId, callId, version, record) => {
    const before = ((await t.sessions.get(workspaceId, callId))?.record as Slice | undefined)?.modules.badge.callback;
    if (before !== undefined && when(before, (record as unknown as Slice).modules.badge.callback)) {
      t.sessions.compareAndSet = cas;
      await meanwhile();
      throw new Error("store blip");
    }
    return cas(workspaceId, callId, version, record as JsonValue);
  };
}

/** Throws on the next read of the daily-limit counter, after `meanwhile`. */
class Faulty extends MemoryAttemptCounters {
  onGet: (() => Promise<void>) | null = null;
  override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    const hook = key.factor === CALLBACKS_PLACED ? this.onGet : null;
    if (hook !== null) {
      this.onGet = null;
      await hook();
      throw new Error("counters down");
    }
    return super.get(key, since);
  }
}

/** A placed callback whose first dial failed, a day later, about to be resumed. */
async function dayOld(counters: Faulty) {
  const fake = new FakeCallbackDialer();
  let failing = true;
  const dialer: CallbackDialer = { async dial(input) { if (failing) throw new Error("telephony down"); return fake.dial(input); } };
  const t = setup({ config: callbackConfig(), adapters: { counters, dialer } });
  const asking = await firstCall(t);
  await t.engine.requestCallback(asking);
  t.clock.advance(DAY);
  failing = false;
  return { t, fake, asking };
}

const placedToday = (t: TestEngine, counters: MemoryAttemptCounters) => counters.get(PLACED, new Date(t.clock.now().getTime() - DAY + 1).toISOString());
const callbackOn = async (t: TestEngine, callId: string) => ((await t.sessions.get("ws_test", callId))!.record as unknown as Slice).modules.badge.callback;

describe("V5b: a passed callback's cleanup claim", () => {
  it("a claim write that saved nothing, then another try's claim: this try removes nothing", async () => {
    const t = setup({ config: callbackConfig() });
    await t.engine.requestCallback(await firstCall(t));
    const { ref, callId } = t.dialer.dialed.at(-1)!;
    failWrite(
      t,
      (b, a) => b.forgetClaimed !== true && a.forgetClaimed === true,
      () => anotherTry(t, callId, (c) => Object.assign(c, { forgetClaimed: true, forgetClaimToken: "another-try" })),
    );
    assert.equal((await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true })).applied, true);
    assert.equal((await t.counters.get(numberKey, LONG_AGO)).length, 1, "the removal is the other try's to make");
    assert.equal((await callbackOn(t, callId)).forgetPending, true);
  });

  it("this try's own claim, saved before its write failed (the ledger), still removes", async () => {
    const t = setup({ config: callbackConfig() });
    await t.engine.requestCallback(await firstCall(t));
    const { ref } = t.dialer.dialed.at(-1)!;
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    t.sessions.compareAndSet = async (workspaceId, id, version, record) => {
      const saved = await cas(workspaceId, id, version, record);
      if ((record as unknown as Slice).modules.badge.callback.forgetClaimed === true) {
        t.sessions.compareAndSet = cas;
        throw new Error("ledger blip after the save");
      }
      return saved;
    };
    await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true }).catch(() => undefined);
    assert.deepEqual(await t.counters.get(numberKey, LONG_AGO), [], "the claim was this try's");
  });
});

describe("V5b: a resumed dial's admission claim", () => {
  it("a claim write that saved nothing, then another try's claim of the same millisecond with no token: no count, no ring", async () => {
    const counters = new Faulty();
    const { t, fake, asking } = await dayOld(counters);
    const at = t.clock.now().toISOString();
    failWrite(
      t,
      (b, a) => b.admitting !== at && a.admitting === at,
      () => anotherTry(t, "call_2", (c) => (c.admitting = at)),
    );
    await t.engine.requestCallback(asking);
    assert.equal(fake.dialed.length, 0, "left to the try that holds the claim");
    assert.equal((await placedToday(t, counters)).length, 0, "not counted by this try");
  });

  it("a failed daily-limit read takes back only this try's claim, not another's of the same millisecond", async () => {
    const counters = new Faulty();
    const { t, fake, asking } = await dayOld(counters);
    const at = t.clock.now().toISOString();
    counters.onGet = () => anotherTry(t, "call_2", (c) => Object.assign(c, { admitting: at, admittingToken: "another-try" }));
    await t.engine.requestCallback(asking);
    const callback = await callbackOn(t, "call_2");
    assert.equal(callback.admitting, at);
    assert.equal(callback.admittingToken, "another-try", "the other try's claim stays");
    assert.equal(fake.dialed.length, 0);
  });
});
