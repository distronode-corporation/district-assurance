// Sean, 2026-11-19: a taint while a verification is open fails that verification. No level is
// granted from it, however many factors matched before or after the taint, and the caller must start
// a new verification, which starts from no factors.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { ACCOUNT, DOB, PHONE_ON_FILE, setup, testConfig } from "./helpers.ts";

describe("a taint during an open verification", () => {
  it("T1 keypad matched, then the taint, then finishVerification: no level, no grant", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
    await t.engine.markUntrusted(callId, "crm_note");
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 0, scopes: [] });
    const state = await t.engine.state(callId);
    assert.deepEqual([state.level, state.grant], [0, null]);
    assert.equal(await t.engine.authorize(callId, "intake.file"), false);
    const finished = (await t.ledger.list()).filter((e) => e.event === "verification.finished").at(-1)!;
    assert.deepEqual(finished.detail, { level: 0, methods: [], discounted: [], capped: false, policyVersion: "default-1", configRevision: "default", voidedByTaint: true });
  });

  it("T2 a factor matched after the taint, in the same verification, does not count either", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.markUntrusted(callId, "crm_note");
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 0, scopes: [] });
  });

  it("T3 the caller starts again: a new verification after the taint counts as usual", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.markUntrusted(callId, "crm_note");
    assert.equal((await t.engine.finishVerification(callId)).level, 0);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.state(callId)).factors.length, 0, "the new verification starts from no factors");
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
  });

  it("T4 a taint before verification began, or after it finished, voids nothing that comes later", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.markUntrusted(callId, "crm_note");
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    await t.engine.markUntrusted(callId, "second_note");
    assert.equal((await t.engine.state(callId)).level, 0, "the taint still drops the level it had");
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
  });

  it("T5 in a flow, the badge.verify step fails: it finished below its level", async () => {
    const t = setup({
      config: testConfig((c) => {
        c.flows = { deposit: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["intake.file"] }] } };
      }),
    });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.markUntrusted(callId, "crm_note");
    assert.equal((await t.engine.finishVerification(callId)).level, 0);
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
  });
});
