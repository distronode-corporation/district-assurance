// L2 fix T7 (PR #130 review): a call stored before Badge kept `callback` reads it as the empty state
// a new call starts with, so a taint or a change of subject on it never throws.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { ACCOUNT, setup } from "./helpers.ts";
import type { TestEngine } from "../src/testing/index.ts";

/** Takes the Badge slice's `callback` off a stored call, as a record saved before the field existed. */
async function dropCallback(t: TestEngine, callId: string): Promise<void> {
  const stored = (await t.sessions.get("ws_test", callId))!;
  const record = structuredClone(stored.record) as { modules: { badge: { callback?: unknown } } };
  delete record.modules.badge.callback;
  assert.deepEqual(await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never), { ok: true, version: stored.version + 1 });
}
const callbackOf = async (t: TestEngine, callId: string) => ((await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { callback?: { status: string } } } }).modules.badge.callback;

describe("T7: a stored Badge slice without callback", () => {
  it("a taint on it reads the empty callback state", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await dropCallback(t, callId);
    await t.engine.markUntrusted(callId, "sms");
    assert.equal((await callbackOf(t, callId))?.status, "none");
  });

  it("a change of subject on it reads the empty callback state", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.finishVerification(callId);
    await dropCallback(t, callId);
    await t.engine.beginVerification(callId, { accountNumber: "99999990" });
    assert.equal((await callbackOf(t, callId))?.status, "none");
  });
});
