// Hostile pass on #79 (VER-2 texted codes), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { MemoryCodeStore, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, setup, testConfig } from "./helpers.ts";

const CALLING = "+15555550199";

function codeSetup(codes: unknown = new MemoryCodeStore(), patch: (c: FlowConfig) => void = () => undefined): TestEngine {
  const config = testConfig((c) => {
    c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "text_code"] } };
    c.policy.textCodeCountryCodes = ["1"];
    c.modules.trace = { settings: { receipts: true, wordings: [] } };
    patch(c);
  });
  return setup({ config, adapters: { codes: codes as MemoryCodeStore } });
}

async function matchedCall(t: TestEngine, callingNumber?: string): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, callingNumber === undefined ? { accountNumber: ACCOUNT } : { accountNumber: ACCOUNT, callingNumber });
  assert.equal((await t.engine.submitKeypad(callId, { dob: DOB })).matched, true);
  return callId;
}

const settle = async () => {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
};

describe("#79 hostile: can a caller tell a refused send?", () => {
  it("C1 with a calling number, a send refused by the subject's limit makes the same store calls before the reply as a sent one", async () => {
    const trace = async (refuseSubject: boolean) => {
      const steps: string[] = [];
      const store = new MemoryCodeStore();
      const codes = {
        take: async (input: Parameters<MemoryCodeStore["take"]>[0]) => {
          steps.push(`codes.take`);
          return refuseSubject && input.key.scope === "subject" ? false : store.take(input);
        },
      };
      const t = codeSetup(codes);
      const callId = await matchedCall(t, CALLING);
      steps.length = 0;
      t.messages.sendText = () => new Promise(() => undefined);
      assert.deepEqual(await t.engine.sendTextCode(callId), { sent: true });
      return steps;
    };
    assert.deepEqual(await trace(true), await trace(false));
  });

  it("C1b ...and that refused send is counted on the number too", async () => {
    const store = new MemoryCodeStore();
    const codes = { take: async (input: Parameters<MemoryCodeStore["take"]>[0]) => (input.key.scope === "subject" ? false : store.take(input)) };
    const t = codeSetup(codes);
    const callId = await matchedCall(t, CALLING);
    await t.engine.sendTextCode(callId);
    await settle();
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "verification.code_refused").map((e) => e.detail), [{ reason: "subject_limit" }]);
    const numberKey = (await t.sessions.get("ws_test", callId))!.record as unknown as { modules: { badge: { numberKey: string } } };
    assert.equal(await store.take({ workspaceId: "ws_test", key: { scope: "number", key: numberKey.modules.badge.numberKey }, at: t.clock.now().toISOString(), max: 10, windowSeconds: 86_400, minIntervalSeconds: 60 }), false, "the number already has a send within 60 seconds");
  });
});
