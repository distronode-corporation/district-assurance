// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Texted codes (VER-2), from the L2 review (cr-main, text-code.ts:118 and :133): a code's
// validity starts after the awaited work, and each send holds the end of the call until its own
// ledger entry is written, so a refused resend cannot release a pending send's hold.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { MemoryCodeStore, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, setup, testConfig } from "./helpers.ts";

function codeSetup(codes: unknown = new MemoryCodeStore()): TestEngine {
  const config = testConfig((c: FlowConfig) => {
    c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "text_code"] } };
    c.policy.textCodeCountryCodes = ["1"];
    c.modules.trace = { settings: { receipts: true, wordings: [] } };
  });
  return setup({ config, adapters: { codes: codes as MemoryCodeStore } });
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

const ended = (e: unknown) => (e as { code?: string }).code === "precondition_failed";

describe("text codes: the clock is read after the awaited work", () => {
  it("a code whose send took longer than its lifetime is still live for its full lifetime", async () => {
    const store = new MemoryCodeStore();
    let slow = false;
    let t!: TestEngine;
    const codes = {
      take: async (input: Parameters<MemoryCodeStore["take"]>[0]) => {
        // The store answers 11 minutes later than it was asked.
        if (slow) t.clock.advance(660_000);
        return store.take(input);
      },
    };
    t = codeSetup(codes);
    const callId = await matchedCall(t);
    slow = true;
    await t.engine.sendTextCode(callId);
    slow = false;
    await settle();
    const code = /\d{6}/.exec(t.messages.sent.at(-1)!.body)![0];
    t.clock.advance(590_000);
    assert.deepEqual(await t.engine.checkTextCode(callId, code), { matched: true, locked: false }, "600 seconds from when it was made");
  });

  it("the send hold runs from after the awaited work too", async () => {
    const store = new MemoryCodeStore();
    let slow = false;
    let t!: TestEngine;
    const codes = {
      take: async (input: Parameters<MemoryCodeStore["take"]>[0]) => {
        if (slow) t.clock.advance(60_000);
        return store.take(input);
      },
    };
    t = codeSetup(codes);
    const callId = await matchedCall(t);
    t.messages.sendText = () => new Promise(() => undefined);
    slow = true;
    await t.engine.sendTextCode(callId);
    await settle();
    await assert.rejects(t.engine.endCall(callId), ended, "still within 30 seconds of the write");
  });
});

describe("text codes: each send holds the call until its own entry", () => {
  const after = async (t: TestEngine, callId: string) => {
    const ledger = (await t.ledger.list()).filter((e) => e.callId === callId);
    return ledger.slice(ledger.findIndex((e) => e.event === "receipt.issued") + 1).map((e) => e.event);
  };

  it("a refused resend while a send is with the SMS adapter does not release that send's hold", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    const answers: Array<() => void> = [];
    t.messages.sendText = () => new Promise((r) => answers.push(() => r({ messageId: "m" })));
    await t.engine.sendTextCode(callId);
    await settle();
    // Within 60 seconds: refused by the subject's interval, and its entry is written at once.
    await t.engine.sendTextCode(callId);
    await settle();
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "verification.code_refused").map((e) => e.detail), [{ reason: "subject_limit" }]);
    await assert.rejects(t.engine.endCall(callId), ended, "the first send still holds");
    answers[0]!();
    await settle();
    assert.notEqual(await t.engine.endCall(callId), null);
    assert.deepEqual(await after(t, callId), []);
    assert.ok((await t.ledger.list()).some((e) => e.event === "verification.code_sent" && e.callId === callId), "the first send's entry is in the ledger");
  });

  it("a hold past its time no longer blocks, while a later one does", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    const answers: Array<() => void> = [];
    t.messages.sendText = () => new Promise((r) => answers.push(() => r({ messageId: "m" })));
    await t.engine.sendTextCode(callId);
    await settle();
    t.clock.advance(61_000);
    await t.engine.sendTextCode(callId);
    await settle();
    await assert.rejects(t.engine.endCall(callId), ended);
    t.clock.advance(30_000);
    assert.notEqual(await t.engine.endCall(callId), null, "both holds are past their time");
    answers[0]!();
    answers[1]!();
    await settle();
    assert.deepEqual(await after(t, callId), []);
  });
});
