// L2 fix T13, number side (PR #130 review, option c): a pass claims its own-failure removals on the
// call before it runs them, so a cleanup replayed after its clearing write was lost removes nothing
// more, even when another failure on the same number shares the pass's millisecond.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { numberKeyFor } from "../src/verify/counters.ts";
import { TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, setup } from "./helpers.ts";

const LINE = "+15555550142";
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const numberKey: AttemptCounterKey = { workspaceId: "ws_test", factor: "keypad_knowledge", scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, LINE) };

type Badge = { modules: { badge: { forgetOwed?: unknown } } };

/** Refuses the next write that takes a call's owed cleanup off it, as a store blip would. */
function loseClearOnce(t: TestEngine): void {
  const cas = t.sessions.compareAndSet.bind(t.sessions);
  let lose = true;
  t.sessions.compareAndSet = async (workspaceId, callId, version, record) => {
    const before = (await t.sessions.get(workspaceId, callId))?.record as Badge | undefined;
    if (lose && before?.modules.badge.forgetOwed !== undefined && (record as unknown as Badge).modules.badge.forgetOwed === undefined) {
      lose = false;
      throw new Error("store blip");
    }
    return cas(workspaceId, callId, version, record as JsonValue);
  };
}

describe("T13: a replayed pass cleanup removes nothing more on the number", () => {
  it("keeps another failure recorded on the line in the pass's millisecond", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: LINE });
    loseClearOnce(t);
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
    assert.notEqual(((await t.sessions.get("ws_test", callId))!.record as Badge).modules.badge.forgetOwed, undefined, "the cleanup is still owed");
    assert.deepEqual(await t.counters.get(numberKey, LONG_AGO), [], "the pass took its own failure off the line");
    // Another account's failure from the same line, in the same millisecond as the pass.
    const at = t.clock.now().toISOString();
    await t.counters.recordFailure(numberKey, at, LONG_AGO);
    // The call's next factor runs the owed cleanup again.
    await t.engine.submitPin(callId, "0000");
    assert.deepEqual(await t.counters.get(numberKey, LONG_AGO), [at], "the replay removed nothing");
    assert.equal(((await t.sessions.get("ws_test", callId))!.record as Badge).modules.badge.forgetOwed, undefined, "and the cleanup is no longer owed");
  });
});

describe("T13: a claim that is not this run's runs no removal", () => {
  async function passWith(t: TestEngine): Promise<string> {
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: LINE });
    return callId;
  }
  const owedOf = async (t: TestEngine, callId: string) => ((await t.sessions.get("ws_test", callId))!.record as Badge).modules.badge.forgetOwed;

  it("a claim whose read of the call fails removes nothing, and the call's next factor runs the cleanup", async () => {
    const t = setup();
    const callId = await passWith(t);
    const get = t.sessions.get.bind(t.sessions);
    let reads = 0;
    let failAt = -1;
    t.sessions.get = async (workspaceId, id) => {
      if (reads++ === failAt) throw new Error("store blip");
      return get(workspaceId, id);
    };
    // The pass's own write reads once, and the cleanup reads once before its claim.
    const removeFailure = t.counters.removeFailure.bind(t.counters);
    t.counters.removeFailure = async (key, at) => {
      if (key.scope === "subject" && failAt === -1) failAt = reads;
      return removeFailure(key, at);
    };
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
    assert.equal((await t.counters.get(numberKey, LONG_AGO)).length, 1, "the number's removal did not run");
    assert.notEqual(await owedOf(t, callId), undefined, "and is still owed");
    await t.engine.submitPin(callId, "0000");
    assert.deepEqual(await t.counters.get(numberKey, LONG_AGO), []);
  });

  it("a claim write that fails after another run finished the cleanup removes nothing", async () => {
    const t = setup();
    const callId = await passWith(t);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    t.sessions.compareAndSet = async (workspaceId, id, version, record) => {
      const owed = (record as unknown as { modules: { badge: { forgetOwed?: { claimed?: true } } } }).modules.badge.forgetOwed;
      if (owed?.claimed === true) {
        // Another run claimed, cleaned and cleared it in the meantime; this write fails unsaved.
        t.sessions.compareAndSet = cas;
        const stored = (await t.sessions.get(workspaceId, id))!;
        const done = structuredClone(stored.record) as unknown as Badge;
        delete done.modules.badge.forgetOwed;
        await cas(workspaceId, id, stored.version, done as unknown as JsonValue);
        throw new Error("store blip");
      }
      return cas(workspaceId, id, version, record);
    };
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await t.counters.get(numberKey, LONG_AGO)).length, 1, "this run removed nothing");
  });
});
