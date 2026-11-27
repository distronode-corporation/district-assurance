// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// U14, round 4: a texted code's dispatch is claimed in a write on the call ("sending", under an
// unexpired hold, renewed for TEXT_SEND_HOLD_SECONDS from the claim), so endCall refuses between
// the claim and the SMS adapter's answer, and nothing lands in the ledger after receipt.issued.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { MemoryCodeStore, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig } from "./helpers.ts";

function codeWorld(): TestEngine {
  const config = testConfig((c: FlowConfig) => {
    c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "text_code"] } };
    c.policy.textCodeCountryCodes = ["1"];
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

/** Holds the next read of the call in the session store until released: the deferred send's claim. */
function gateNextRead(t: TestEngine) {
  const get = t.sessions.get.bind(t.sessions);
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let reached!: () => void;
  const hit = new Promise<void>((r) => (reached = r));
  t.sessions.get = async (w, c) => {
    t.sessions.get = get;
    reached();
    await gate;
    return get(w, c);
  };
  return { release, hit };
}

const afterReceipt = async (t: TestEngine, callId: string) => {
  const ledger = (await t.ledger.list()).filter((e) => e.callId === callId);
  const at = ledger.findIndex((e) => e.event === "receipt.issued");
  assert.notEqual(at, -1, "a receipt was issued");
  return ledger.slice(at + 1).map((e) => e.event);
};

describe("U14: the SMS dispatch is claimed on the call", () => {
  it("endCall refuses between the claim and the adapter's answer, though the send's first hold passed", async () => {
    const t = codeWorld();
    const callId = await matchedCall(t);
    let answer!: () => void;
    let ended: unknown = "not tried";
    t.messages.sendText = async () => {
      // Between the claim and the answer: the first hold passes, and the host tries to end the call.
      t.clock.advance(2_000);
      ended = await t.engine.endCall(callId).then(
        () => "ended",
        (e: unknown) => e,
      );
      return new Promise((r) => (answer = () => r({ messageId: "m" })));
    };
    await t.engine.sendTextCode(callId);
    // Before the deferred job runs: its first read of the call waits.
    const read = gateNextRead(t);
    await read.hit;
    // The deferred job claims 29 seconds into its first hold.
    t.clock.advance(29_000);
    read.release();
    await settle();
    assert.ok(rejects("precondition_failed")(ended), `endCall refused while the claim stands (got ${String(ended)})`);
    answer();
    await settle();
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "verification.code_sent").length, 1);
    assert.notEqual(await t.engine.endCall(callId), null);
    assert.deepEqual(await afterReceipt(t, callId), []);
  });

  it("a crashed send holds the call only for one hold from its claim", async () => {
    const t = codeWorld();
    const callId = await matchedCall(t);
    t.messages.sendText = () => new Promise(() => undefined);
    await t.engine.sendTextCode(callId);
    await settle();
    t.clock.advance(29_999);
    await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed"));
    t.clock.advance(1);
    assert.notEqual(await t.engine.endCall(callId), null);
    assert.deepEqual(await afterReceipt(t, callId), []);
  });

  it("a claim that finds the call ended (by an engine whose clock runs ahead) texts nothing and writes nothing", async () => {
    const t = codeWorld();
    const callId = await matchedCall(t);
    await t.engine.sendTextCode(callId);
    const read = gateNextRead(t);
    await read.hit;
    // Another engine ended the call while the claim waited: the stored call is ended, the hold looks live here.
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as { state: { phase: string } };
    record.state.phase = "ended";
    assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never)).ok, true);
    const before = (await t.ledger.list()).length;
    read.release();
    await settle();
    assert.equal(t.messages.sent.length, 0, "no SMS");
    assert.equal((await t.ledger.list()).length, before, "nothing after the end");
  });

  it("a claim after the hold passed texts nothing and records send_failed", async () => {
    const t = codeWorld();
    const callId = await matchedCall(t);
    await t.engine.sendTextCode(callId);
    t.clock.advance(30_000);
    await settle();
    assert.equal(t.messages.sent.length, 0);
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "verification.code_refused").map((e) => e.detail), [{ reason: "send_failed" }]);
  });
});
