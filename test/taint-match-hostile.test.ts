// Hostile-pass regressions for #86 (VER-7 engine fix): a taint voids the keypad or PIN match made before it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { PinVerifier } from "../src/core/adapters.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, setup, testConfig } from "./helpers.ts";

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
    for (let i = 0; i < 2; i++) await t.engine.submitPin(callId, "0000");
    await t.engine.markUntrusted(callId, "crm_note");
    await t.engine.submitPin(callId, "0000");
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true }, "the taint gives no new guesses");
  });
});
