// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile pass on #74 (VER-6 PIN enrolment and reset), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, pinOnFile, rejects, setup, testConfig } from "./helpers.ts";

const NEW_ACCOUNT = "20481937";
const NEW_PHONE = "+15555550142";
const NEW_SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, NEW_ACCOUNT);
const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const CHOSEN = "5831";
const pinSettings = (c: FlowConfig) => c.modules.badge!.settings as { pin: { maxAttemptsPerCall: number } };

function enrolSetup(): TestEngine {
  const t = setup({ config: testConfig((c) => (pinSettings(c).pin.maxAttemptsPerCall = 5)) });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: NEW_ACCOUNT, phoneOnFile: NEW_PHONE, knowledge: { dob: DOB } }));
  t.carrier.set(NEW_PHONE, { identityMatch: "match" });
  return t;
}

async function verified(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: NEW_ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

/** An input whose `pin` is one value on its first read and another after. */
function swapping(first: string, then: string) {
  let reads = 0;
  return {
    get pin() {
      reads++;
      return reads === 1 ? first : then;
    },
    confirm: then,
  };
}

describe("#74 hostile: the PIN a caller chooses", () => {
  it("P1 a PIN read twice cannot store one value and pass the checks with another: the date of birth is never stored", async () => {
    const t = enrolSetup();
    const callId = await verified(t);
    const result = await t.engine.enrolPin(callId, swapping(DOB, CHOSEN)).catch((e: unknown) => e);
    const stored = (await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest;
    assert.equal(await pinOnFile(stored, NEW_SUBJECT, DOB), false, "the weak value is never on file");
    if (stored !== undefined) assert.ok(await pinOnFile(stored, NEW_SUBJECT, CHOSEN), "what is on file is what was checked");
    assert.ok(result !== undefined);
  });

  it("P2 ...nor a malformed value the PIN factor can never match, which would leave the subject without a usable PIN", async () => {
    const t = enrolSetup();
    const callId = await verified(t);
    await t.engine.enrolPin(callId, swapping("12", CHOSEN)).catch(() => undefined);
    const stored = (await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest;
    assert.equal(await pinOnFile(stored, NEW_SUBJECT, "12"), false);
  });

  it("P2b a PIN that is a string on its first read and not after is still read once", async () => {
    const t = enrolSetup();
    const callId = await verified(t);
    let reads = 0;
    const input = {
      get pin() {
        reads++;
        return reads === 1 ? CHOSEN : ([CHOSEN] as unknown as string);
      },
      confirm: CHOSEN,
    };
    assert.deepEqual(await t.engine.enrolPin(callId, input), { enrolled: true });
    assert.equal(reads, 1);
  });

  it("P3 a PIN or confirmation that is not a string is malformed, never coerced", async () => {
    const t = enrolSetup();
    const callId = await verified(t);
    for (const input of [{ pin: [CHOSEN], confirm: CHOSEN }, { pin: CHOSEN, confirm: [CHOSEN] }, { pin: { toString: () => CHOSEN }, confirm: CHOSEN }]) {
      assert.deepEqual(await t.engine.enrolPin(callId, input as never), { enrolled: false, reason: "malformed" }, JSON.stringify(input));
    }
    assert.equal((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, undefined);
  });
});

describe("#74 hostile: the business's reset", () => {
  it("P4 a subject key that is not a string is refused before anything changes", async () => {
    const t = setup();
    for (const subjectKey of [[OWNER], { toString: () => OWNER }]) {
      await assert.rejects(t.engine.resetPin(subjectKey as never), rejects("invalid_input", /subjectKey/), JSON.stringify(subjectKey));
    }
    assert.notEqual((await t.records.getSubject("ws_test", OWNER))!.pinDigest, undefined, "the PIN is still on file");
    assert.equal((await t.ledger.list()).some((e) => e.event === "pin.reset"), false);
  });

  it("P5 a reset clears the PIN lock it was asked to, so the owner can enrol and pass again", async () => {
    const t = setup({ config: testConfig((c) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { lockAfterFailures: 1 })) });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitPin(callId, "0000"), { matched: false, locked: true });
    await t.engine.resetPin(OWNER);
    const key: AttemptCounterKey = { workspaceId: "ws_test", factor: "pin", scope: "subject", key: OWNER };
    assert.deepEqual(await t.counters.get(key, "2000-01-01T00:00:00.000Z"), []);
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.pinDigest, undefined, "the reset removed the PIN");
    // The owner enrols again through the engine, on a fresh call verified to level 2.
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const enrol = await t.engine.startCall();
    await t.engine.beginVerification(enrol.callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitKeypad(enrol.callId, { dob: DOB }), { matched: true, locked: false });
    await t.engine.checkCarrier(enrol.callId);
    assert.equal((await t.engine.finishVerification(enrol.callId)).level, 2);
    assert.deepEqual(await t.engine.enrolPin(enrol.callId, { pin: PIN, confirm: PIN }), { enrolled: true });
    const next = await t.engine.startCall();
    await t.engine.beginVerification(next.callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitPin(next.callId, PIN), { matched: true, locked: false });
  });
});
