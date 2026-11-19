// L2 fix T13, callback path (PR #130 review, option c): a passed callback's own failure on the calling
// number is claimed on the callback call before it is taken off, so a repeated outcome that replays
// the cleanup never takes off another failure of the same millisecond. The subject's part replays.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { numberKeyFor } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, PIN, setup, testConfig } from "./helpers.ts";

const CALLING = "+15555550199";
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const numberKey: AttemptCounterKey = { workspaceId: "ws_test", factor: "callback", scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, CALLING) };
const subjectKey: AttemptCounterKey = { workspaceId: "ws_test", factor: "callback", scope: "subject", key: subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT) };

type Slice = { modules: { badge: { callback?: { forgetPending?: boolean; forgetClaimed?: true; at?: string } } } };

function callbackConfig(): FlowConfig {
  return testConfig((c) => {
    c.modules.badge = { settings: { factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "callback"], pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 } } };
    c.policy.levels[1]!.anyOf.push(["pin", "callback"]);
    c.flows = { callback: { steps: [{ type: "badge.verify", level: 2, factors: ["pin", "callback", "carrier_identity_match"], scopes: ["payment.request"] }] } };
  });
}

/** A callback placed and dialed from a first call that keyed the right PIN from CALLING. */
async function dialed(t: TestEngine): Promise<{ ref: string; callId: string }> {
  const { callId: first } = await t.engine.startCall();
  await t.engine.beginVerification(first, { accountNumber: ACCOUNT, callingNumber: CALLING });
  assert.equal((await t.engine.submitPin(first, PIN)).matched, true);
  await t.engine.requestCallback(first);
  return t.dialer.dialed.at(-1)!;
}

/** Fails once the write that matches, before it is saved (`unsaved`) or as a store blip after another run's cleanup. */
function failWrite(t: TestEngine, when: (before: Slice, after: Slice) => boolean, meanwhile?: () => Promise<void>): void {
  const cas = t.sessions.compareAndSet.bind(t.sessions);
  t.sessions.compareAndSet = async (workspaceId, callId, version, record) => {
    const before = (await t.sessions.get(workspaceId, callId))?.record as Slice | undefined;
    if (before !== undefined && when(before, record as unknown as Slice)) {
      t.sessions.compareAndSet = cas;
      await meanwhile?.();
      throw new Error("store blip");
    }
    return cas(workspaceId, callId, version, record as JsonValue);
  };
}
const pending = async (t: TestEngine, callId: string) => ((await t.sessions.get("ws_test", callId))!.record as Slice).modules.badge.callback;

describe("T13: a replayed callback-pass cleanup", () => {
  it("keeps another failure recorded on the calling number in the callback's millisecond", async () => {
    const t = setup({ config: callbackConfig() });
    const { ref, callId } = await dialed(t);
    // The write that takes the pending cleanup off the call is lost.
    failWrite(t, (b, a) => b.modules.badge.callback?.forgetPending === true && a.modules.badge.callback?.forgetPending === false);
    await assert.rejects(t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true }), /store blip/);
    assert.deepEqual(await t.counters.get(numberKey, LONG_AGO), [], "the pass took its own failure off the number");
    assert.deepEqual(await t.counters.get(subjectKey, LONG_AGO), []);
    const at = (await pending(t, callId))!.at!;
    // Another account's failure from the same line, in the callback's millisecond.
    await t.counters.recordFailure(numberKey, at, LONG_AGO);
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true }), { applied: false });
    assert.deepEqual(await t.counters.get(numberKey, LONG_AGO), [at], "the replay removed nothing");
    assert.equal((await pending(t, callId))!.forgetPending, false, "and nothing is pending");
  });

  it("a claim that is not saved removes nothing and stays pending, for the repeated outcome", async () => {
    const t = setup({ config: callbackConfig() });
    const { ref, callId } = await dialed(t);
    failWrite(t, (b, a) => b.modules.badge.callback?.forgetClaimed !== true && a.modules.badge.callback?.forgetClaimed === true);
    assert.equal((await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true })).applied, true);
    assert.equal((await t.counters.get(numberKey, LONG_AGO)).length, 1, "not claimed, so not taken off");
    assert.equal((await pending(t, callId))!.forgetPending, true);
    await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true });
    assert.deepEqual(await t.counters.get(numberKey, LONG_AGO), [], "the repeated outcome runs it");
    assert.equal((await pending(t, callId))!.forgetPending, false);
  });

  it("a claim write that fails after another run finished the cleanup removes nothing", async () => {
    const t = setup({ config: callbackConfig() });
    const { ref, callId } = await dialed(t);
    failWrite(
      t,
      (b, a) => b.modules.badge.callback?.forgetClaimed !== true && a.modules.badge.callback?.forgetClaimed === true,
      async () => {
        const stored = (await t.sessions.get("ws_test", callId))!;
        const done = structuredClone(stored.record) as unknown as Slice;
        done.modules.badge.callback!.forgetPending = false;
        await t.sessions.compareAndSet("ws_test", callId, stored.version, done as unknown as JsonValue);
      },
    );
    await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true });
    assert.equal((await t.counters.get(numberKey, LONG_AGO)).length, 1, "this run removed nothing");
  });
});

describe("T13: another run took the callback cleanup while this one was about to claim it", () => {
  for (const other of ["claimed it", "finished it"] as const) {
    it(`another run ${other}: this one removes nothing`, async () => {
      const t = setup({ config: callbackConfig() });
      const { ref, callId } = await dialed(t);
      const removeFailure = t.counters.removeFailure.bind(t.counters);
      let once = true;
      t.counters.removeFailure = async (key, at) => {
        await removeFailure(key, at);
        if (key.scope !== "subject" || key.factor !== "callback" || !once) return;
        once = false;
        const stored = (await t.sessions.get("ws_test", callId))!;
        const next = structuredClone(stored.record) as unknown as Slice;
        if (other === "claimed it") next.modules.badge.callback!.forgetClaimed = true;
        else next.modules.badge.callback!.forgetPending = false;
        await t.sessions.compareAndSet("ws_test", callId, stored.version, next as unknown as JsonValue);
      };
      await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true });
      assert.equal((await t.counters.get(numberKey, LONG_AGO)).length, 1, "this run removed nothing");
    });
  }
});
