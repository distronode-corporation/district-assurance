// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// T14 (CWE-367): enrolPin stores a PIN only while the call is still open, holds a grant at
// PIN_ENROLMENT_LEVEL or above, and still belongs to the subject the try was reserved for. Both
// windows are checked: before the pending entry is written, and between it and the store's write.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { CallRecord } from "../src/core/runtime.ts";
import type { BadgeSlice } from "../src/verify/badge.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup } from "./helpers.ts";

const NEW_ACCOUNT = "20481937";
const NEW_PHONE = "+15555550142";
const SUBJ = subjectKeyFor(TEST_KNOWLEDGE_KEY, NEW_ACCOUNT);
const X = "5831";

function world(): TestEngine {
  const t = setup();
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: NEW_ACCOUNT, phoneOnFile: NEW_PHONE, knowledge: { dob: DOB } }));
  t.carrier.set(NEW_PHONE, { identityMatch: "match" });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  return t;
}

async function verify(t: TestEngine, callId: string, accountNumber: string): Promise<void> {
  await t.engine.beginVerification(callId, { accountNumber });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
}

async function verified(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall();
  await verify(t, callId, NEW_ACCOUNT);
  return callId;
}

const pending = async (t: TestEngine, callId: string) => {
  const record = (await t.sessions.get("ws_test", callId))!.record as unknown as CallRecord;
  return (record.modules.badge as unknown as BadgeSlice).pinPending ?? [];
};

/** Runs `meanwhile` right after the write that records the try's pending entry commits. */
function afterPendingWrite(t: TestEngine, meanwhile: () => Promise<unknown>): void {
  const cas = t.sessions.compareAndSet.bind(t.sessions);
  let armed = true;
  t.sessions.compareAndSet = async (...args: Parameters<typeof cas>) => {
    const result = await cas(...args);
    const badge = (args[3] as unknown as CallRecord).modules?.badge as unknown as BadgeSlice | undefined;
    if (armed && (badge?.pinPending?.length ?? 0) > 0) {
      armed = false;
      await meanwhile();
    }
    return result;
  };
}

describe("T14: the call is checked again before the pending entry", () => {
  it("a call ended while the try was judged stores nothing and leaves no entry", async () => {
    const t = world();
    const callId = await verified(t);
    const read = t.records.getSubject.bind(t.records);
    t.records.getSubject = async (w, k) => {
      const subject = await read(w, k);
      await t.engine.endCall(callId);
      return subject;
    };
    await assert.rejects(t.engine.enrolPin(callId, { pin: X, confirm: X }), rejects("invalid_transition"));
    t.records.getSubject = read;
    assert.equal((await t.records.getSubject("ws_test", SUBJ))!.pinDigest, undefined, "no PIN stored");
    assert.deepEqual(await pending(t, callId), []);
  });

  it("a grant that expired while the try was judged stores nothing", async () => {
    const t = world();
    const callId = await verified(t);
    const expiresAt = Date.parse((await t.engine.state(callId)).grant!.expiresAt);
    const read = t.records.getSubject.bind(t.records);
    t.records.getSubject = async (w, k) => {
      t.clock.advance(expiresAt - t.clock.now().getTime());
      return read(w, k);
    };
    await assert.rejects(t.engine.enrolPin(callId, { pin: X, confirm: X }), rejects("scope_denied"));
    assert.equal((await read("ws_test", SUBJ))!.pinDigest, undefined);
    assert.deepEqual(await pending(t, callId), []);
  });
});

describe("T14: the call is checked again between the pending entry and the store's write", () => {
  it("a call ended after the entry was written stores nothing and takes the entry back", async () => {
    const t = world();
    const callId = await verified(t);
    afterPendingWrite(t, () => t.engine.endCall(callId));
    await assert.rejects(t.engine.enrolPin(callId, { pin: X, confirm: X }), rejects("invalid_transition"));
    assert.equal((await t.records.getSubject("ws_test", SUBJ))!.pinDigest, undefined, "no PIN stored");
    assert.deepEqual(await pending(t, callId), [], "the entry is taken back");
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "pin.enrolled"), []);
  });

  it("verification restarted for another subject, verified at level 2 again: nothing is stored for the first", async () => {
    const t = world();
    const callId = await verified(t);
    afterPendingWrite(t, () => verify(t, callId, ACCOUNT));
    await assert.rejects(t.engine.enrolPin(callId, { pin: X, confirm: X }), rejects("precondition_failed", /another subject/));
    assert.equal((await t.records.getSubject("ws_test", SUBJ))!.pinDigest, undefined, "the first subject has no PIN");
    assert.deepEqual(await pending(t, callId), []);
  });

  it("with nothing changed, the PIN is stored and recorded once", async () => {
    const t = world();
    const callId = await verified(t);
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: X, confirm: X }), { enrolled: true });
    assert.notEqual((await t.records.getSubject("ws_test", SUBJ))!.pinDigest, undefined);
    assert.equal((await t.ledger.list()).filter((e) => e.event === "pin.enrolled").length, 1);
  });
});
