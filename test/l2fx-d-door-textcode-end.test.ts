// #79 x #47: a door grant at its controller and a texted code with the SMS adapter, both in flight
// on one call. endCall refuses until both have answered, and nothing lands in the call's ledger
// after receipt.issued, whichever answers first.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AccessController, UnlockResult } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { FakeAccessController, MemoryCodeStore, createTestEngine, generateTestSigner, testSubject, TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, testConfig } from "./helpers.ts";

const config = (): FlowConfig =>
  testConfig((c) => {
    c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "text_code"] } };
    c.policy.textCodeCountryCodes = ["1"];
    c.policy.scopes["entry.open"] = 2;
    c.modules.gate = { settings: { targets: [{ id: "front-door", controller: "lobby", ref: "door-1" }] } };
    c.modules.trace = { settings: { receipts: true, wordings: [] } };
  });

const settle = async () => {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
};

/** A world whose door and SMS adapter each hold their answer until told. */
function world() {
  const fake = new FakeAccessController("confirm");
  const doors: Array<() => void> = [];
  const door: AccessController = {
    unlock: (input) => new Promise<UnlockResult>((resolve) => doors.push(() => void fake.unlock(input).then(resolve))),
  };
  const t: TestEngine = createTestEngine({ config: config(), adapters: { access: { lobby: door }, accessSigner: generateTestSigner("gate-key-1"), codes: new MemoryCodeStore() } });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } }));
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  const texts: Array<() => void> = [];
  t.messages.sendText = () => new Promise((r) => texts.push(() => r({ messageId: "m" })));
  return { t, doors, texts };
}

/** Both in flight: a code sent while verifying, then the grant at the door once the call is open at level 2. */
async function bothInFlight(w: ReturnType<typeof world>): Promise<{ callId: string; grant: Promise<unknown> }> {
  const { t } = w;
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  assert.equal((await t.engine.submitKeypad(callId, { dob: DOB })).matched, true);
  await t.engine.sendTextCode(callId);
  await settle();
  assert.equal(w.texts.length, 1, "the code is with the SMS adapter");
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  const grant = t.engine.grantAccess(callId, { target: "front-door" });
  await settle();
  assert.equal(w.doors.length, 1, "the grant is at the door");
  return { callId, grant };
}

const afterReceipt = async (t: TestEngine, callId: string) => {
  const ledger = (await t.ledger.list()).filter((e) => e.callId === callId);
  const at = ledger.findIndex((e) => e.event === "receipt.issued");
  assert.notEqual(at, -1, "a receipt was issued");
  return ledger.slice(at + 1).map((e) => e.event);
};

describe("#79 x #47: a door grant and a texted code in flight at the end", () => {
  for (const first of ["door", "text"] as const) {
    it(`refuses to end until both answered (${first} first), and nothing follows the receipt`, async () => {
      const w = world();
      const { t } = w;
      const { callId, grant } = await bothInFlight(w);
      await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed"), "both in flight");
      (first === "door" ? w.doors : w.texts)[0]!();
      await settle();
      await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed"), `the ${first === "door" ? "text" : "door"} is still in flight`);
      (first === "door" ? w.texts : w.doors)[0]!();
      await settle();
      assert.deepEqual(await grant, { grantId: "acc_1", status: "delivered", confirmed: true });
      assert.notEqual(await t.engine.endCall(callId), null);
      await settle();
      assert.deepEqual(await afterReceipt(t, callId), []);
      const events = (await t.ledger.list()).filter((e) => e.callId === callId).map((e) => e.event);
      assert.ok(events.includes("verification.code_sent") && events.includes("access.delivered"), "both outcomes are on the receipt's side of the ledger");
    });
  }
});
