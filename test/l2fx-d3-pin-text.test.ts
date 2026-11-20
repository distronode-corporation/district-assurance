// PIN enrolment and texted codes, round 3 of the L2 review: enrolment applies today's attestation
// cap (U12), a retry after a ledger failure finishes its own enrolment (U13), an SMS is dispatched
// only under its own unexpired hold (U14), and a call stored without textCode reads as no code (U15).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { MemoryCodeStore, TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig } from "./helpers.ts";

const NEW_ACCOUNT = "20481937";
const NEW_PHONE = "+15555550142";
const SUBJ = subjectKeyFor(TEST_KNOWLEDGE_KEY, NEW_ACCOUNT);
const X = "5831";

function pinWorld(patch: (c: FlowConfig) => void = () => undefined): TestEngine {
  const t = setup({ config: testConfig(patch) });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: NEW_ACCOUNT, phoneOnFile: NEW_PHONE, knowledge: { dob: DOB } }));
  t.carrier.set(NEW_PHONE, { identityMatch: "match" });
  return t;
}

async function verified(t: TestEngine, attestation?: "failed"): Promise<string> {
  const { callId } = await t.engine.startCall(attestation === undefined ? {} : { attestation });
  await t.engine.beginVerification(callId, { accountNumber: NEW_ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

describe("U12: PIN enrolment applies today's attestation cap", () => {
  it("a level 2 grant capped to 1 by a cap turned on since cannot choose a PIN", async () => {
    const t = pinWorld();
    const callId = await verified(t, "failed");
    t.engine.configure(testConfig((c) => (c.policy.attestationCaps = { failed: 1 })));
    await assert.rejects(t.engine.enrolPin(callId, { pin: X, confirm: X }), rejects("scope_denied"));
    assert.equal((await t.records.getSubject("ws_test", SUBJ))!.pinDigest, undefined);
  });

  it("a grant the cap leaves at level 2 still can", async () => {
    const t = pinWorld();
    const callId = await verified(t, "failed");
    t.engine.configure(testConfig((c) => (c.policy.attestationCaps = { failed: 2, none: 1 })));
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: X, confirm: X }), { enrolled: true });
  });
});

describe("U13: a retry after the ledger failed finishes its own enrolment", () => {
  for (const max of [1, 3]) {
    it(`returns enrolled without a second pin.enrolled (maxAttemptsPerCall ${max})`, async () => {
      const t = pinWorld((c) => ((c.modules.badge!.settings as { pin: { maxAttemptsPerCall: number } }).pin.maxAttemptsPerCall = max));
      const callId = await verified(t);
      const append = t.ledger.append.bind(t.ledger);
      let fail = true;
      t.ledger.append = async (input) => {
        if (fail && input.event === "pin.enrolled") {
          fail = false;
          throw new Error("ledger down");
        }
        return append(input);
      };
      await assert.rejects(t.engine.enrolPin(callId, { pin: X, confirm: X }), /ledger down/);
      assert.deepEqual(await t.engine.enrolPin(callId, { pin: X, confirm: X }), { enrolled: true });
      assert.equal((await t.ledger.list()).filter((e) => e.event === "pin.enrolled").length, 1);
      // Another call's retry of the same PIN never passes for this call's enrolment.
      const other = await verified(t);
      await assert.rejects(t.engine.enrolPin(other, { pin: X, confirm: X }), rejects("precondition_failed"));
      // A different PIN on the same call is not this enrolment either.
      const different = await t.engine.enrolPin(callId, { pin: "7350", confirm: "7350" }).catch(() => ({ enrolled: false }));
      assert.equal(different.enrolled, false);
      // Once its entry is in the ledger, a retry is refused as before.
      const again = await t.engine.enrolPin(callId, { pin: X, confirm: X }).catch(() => ({ enrolled: false }));
      assert.equal(again.enrolled, false);
    });
  }
});

function codeWorld(countries = ["1"]): TestEngine {
  const config = testConfig((c) => {
    c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "text_code"] } };
    c.policy.textCodeCountryCodes = countries;
    c.modules.trace = { settings: { receipts: true, wordings: [] } };
  });
  return setup({ config, adapters: { codes: new MemoryCodeStore() } });
}

async function matchedCall(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  assert.equal((await t.engine.submitKeypad(callId, { dob: DOB })).matched, true);
  return callId;
}

const settle = async () => {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
};

describe("U14: an SMS goes out only under its own unexpired hold", () => {
  it("a send whose job starts after its hold passed texts nothing, and the call may end", async () => {
    const t = codeWorld();
    const callId = await matchedCall(t);
    await t.engine.sendTextCode(callId);
    // Before the deferred job runs: its hold passes.
    t.clock.advance(30_000);
    await settle();
    assert.equal(t.messages.sent.length, 0, "no SMS");
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "verification.code_refused").map((e) => e.detail), [{ reason: "send_failed" }]);
    assert.notEqual(await t.engine.endCall(callId), null);
  });

  it("within its hold, it is sent as before", async () => {
    const t = codeWorld();
    const callId = await matchedCall(t);
    await t.engine.sendTextCode(callId);
    t.clock.advance(29_999);
    await settle();
    assert.equal(t.messages.sent.length, 1);
  });
});

describe("U15: a call stored without textCode reads as no code", () => {
  const strip = async (t: TestEngine, callId: string) => {
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as { modules: { badge: Record<string, unknown> } };
    delete record.modules.badge.textCode;
    assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never)).ok, true);
  };

  it("a check before any send is the precondition error", async () => {
    const t = codeWorld();
    const callId = await matchedCall(t);
    await strip(t, callId);
    await assert.rejects(t.engine.checkTextCode(callId, "123456"), rejects("precondition_failed", /no code was sent/));
  });

  it("a refused send holds a code that never matches", async () => {
    const t = codeWorld(["44"]);
    const callId = await matchedCall(t);
    await strip(t, callId);
    assert.deepEqual(await t.engine.sendTextCode(callId), { sent: true });
    await settle();
    assert.deepEqual(await t.engine.checkTextCode(callId, "123456"), { matched: false, locked: false });
  });
});
