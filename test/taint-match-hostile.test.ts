// Hostile-pass regressions for #86 (VER-7 engine fix): a taint voids the keypad or PIN match made before it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { PinVerifier } from "../src/core/adapters.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, setup, testConfig, waitOut } from "./helpers.ts";

/** A PIN verifier whose answer the test releases, so a taint can land while the PIN is judged. */
function heldVerifier(pin: string) {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let reached!: () => void;
  const started = new Promise<void>((r) => (reached = r));
  const verifier: PinVerifier = {
    verify: async (input) => {
      reached();
      await gate;
      return { matched: input.pin === pin };
    },
  };
  return { verifier, release, started };
}

describe("hostile #86: a taint and the match", () => {
  it("a PIN judged while the taint lands never unlocks anything sent out", async () => {
    const held = heldVerifier(PIN);
    const t = setup({
      adapters: { pinVerifier: held.verifier },
      config: testConfig((c) => {
        (c.modules.badge!.settings as { pin: { mode: string } }).pin.mode = "verifier";
      }),
    });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const judged = t.engine.submitPin(callId, PIN);
    await held.started;
    await t.engine.markUntrusted(callId, "crm_note");
    held.release();
    await judged.catch(() => undefined);
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"), "no identity link on a match from before the taint");
    await assert.rejects(t.engine.checkCarrier(callId), rejects("precondition_failed"), "no carrier check either");
    assert.equal(t.messages.sent.length, 0);
  });

  it("a second engine on the same stores sees the taint's reset", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    const other = setup({ adapters: { sessions: t.sessions, ledger: t.ledger, records: t.records, messages: t.messages } });
    await other.engine.markUntrusted(callId, "transcript");
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"));
  });

  it("the attempts used before the taint still count after it", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    // Each wrong guess is judged past the wait the one before started, so only the attempt limit locks.
    for (let i = 0; i < 2; i++) {
      assert.deepEqual(await t.engine.submitPin(callId, "0000"), { matched: false, locked: false });
      waitOut(t);
    }
    await t.engine.markUntrusted(callId, "crm_note");
    assert.deepEqual(await t.engine.submitPin(callId, "0000"), { matched: false, locked: true }, "the third attempt, as before the taint");
    waitOut(t);
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true }, "the taint gives no new guesses");
  });

  it("a second taint while a PIN is judged on an already tainted call: the pass neither counts nor restores the match", async () => {
    const held = heldVerifier(PIN);
    const t = setup({
      adapters: { pinVerifier: held.verifier },
      config: testConfig((c) => {
        (c.modules.badge!.settings as { pin: { mode: string } }).pin.mode = "verifier";
      }),
    });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall();
    await t.engine.markUntrusted(callId, "crm_note");
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const judged = t.engine.submitPin(callId, PIN);
    await held.started;
    await t.engine.markUntrusted(callId, "transcript");
    held.release();
    await assert.rejects(judged, rejects("precondition_failed", /untrusted content entered the call while this entry was judged/));
    await assert.rejects(t.engine.checkCarrier(callId), rejects("precondition_failed"), "no carrier check on the stale match");
    assert.equal((await t.engine.state(callId)).factors.length, 0, "the pass is not recorded");
  });

  it("a pass judged across a taint never counts toward a grant issued after it", async () => {
    const held = heldVerifier(PIN);
    const t = setup({
      adapters: { pinVerifier: held.verifier },
      config: testConfig((c) => {
        (c.modules.badge!.settings as { pin: { mode: string } }).pin.mode = "verifier";
      }),
    });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const judged = t.engine.submitPin(callId, PIN);
    await held.started;
    await t.engine.markUntrusted(callId, "crm_note");
    held.release();
    await assert.rejects(judged, rejects("precondition_failed"));
    assert.equal((await t.engine.finishVerification(callId)).level, 0, "no factor from before the taint counts");
  });

  it("counts the taints of a call saved before taints were counted", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as { modules: { badge: { taints?: number } } };
    delete record.modules.badge.taints;
    assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never)).ok, true);
    await t.engine.markUntrusted(callId, "crm_note");
    const after = (await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { taints?: number } } };
    assert.equal(after.modules.badge.taints, 1);
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false }, "an entry after the taint counts");
  });
});
