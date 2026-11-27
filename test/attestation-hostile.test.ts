// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile-pass regressions for #104 (VER-10, caller ID attestation): every attack held.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { validatePolicy as validatePolicyRaw, type Attestation, type AssuranceLevel } from "../src/core/policy.ts";
import { problemMessage } from "../src/core/module.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";

/** The policy validator's sentences, as the tests read them. */
const validatePolicy = (...args: Parameters<typeof validatePolicyRaw>): string[] => validatePolicyRaw(...args).map(problemMessage);
import type { TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig } from "./helpers.ts";

function capped(caps: unknown, base?: TestEngine): TestEngine {
  const t = base ?? setup();
  t.engine.configure(testConfig((c) => (c.policy.attestationCaps = caps as Partial<Record<Attestation, AssuranceLevel>>)));
  return t;
}

async function strongCall(t: TestEngine, attestation?: Attestation): Promise<string> {
  const { callId } = await t.engine.startCall(attestation === undefined ? {} : { attestation });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.startPhotoId(callId);
  await t.engine.applyIdentityOutcome({ sessionId: t.identity.created.at(-1)!.sessionId, status: "verified" });
  return callId;
}

describe("hostile #104: what a host passes as the attestation", () => {
  it("V1: anything but A, B, C, failed or none is refused, and no call is opened", async () => {
    const t = setup();
    for (const attestation of ["a", "A ", " A", "TN-Validation-Passed", "", null, 1, {}, ["A"], "__proto__", "toString", "constructor", "A\uD800"]) {
      await assert.rejects(t.engine.startCall({ callId: "c_x", attestation: attestation as Attestation }), rejects("invalid_input"), String(attestation));
    }
    assert.equal(await t.sessions.get("ws_test", "c_x"), null, "nothing stored");
    assert.equal((await t.ledger.list()).length, 0, "nothing in the ledger");
  });

  it("V2: the attestation is set once: a second startCall on the id cannot change it", async () => {
    const t = capped({ failed: 1 });
    const { callId } = await t.engine.startCall({ attestation: "failed" });
    await assert.rejects(t.engine.startCall({ callId, attestation: "A" }), rejects("invalid_input"));
    // The original call, verified strongly, is still capped as "failed".
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    await t.engine.applyIdentityOutcome({ sessionId: t.identity.created.at(-1)!.sessionId, status: "verified" });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
  });
});

describe("hostile #104: the policy's caps", () => {
  it("V3: caps of the wrong shape, keys or levels are refused by validatePolicy", () => {
    const policy = testConfig().policy;
    for (const caps of [null, [], "C:2", 2, { c: 2 }, { "C ": 2 }, { C: "2" }, { C: 2.5 }, { C: -1 }, { C: 4 }, { C: Number.NaN }, { C: true }, JSON.parse('{"__proto__":1}'), { toString: 1 }]) {
      const errors = validatePolicy({ ...policy, attestationCaps: caps as never });
      assert.ok(errors.map(problemMessage).some((e) => e.startsWith("attestationCaps")), JSON.stringify(caps));
    }
    assert.deepEqual(validatePolicy({ ...policy, attestationCaps: { A: 3, B: 3, C: 2, failed: 0, none: 2 } }), []);
  });

  it("V4: a cap set after a grant was issued applies to that grant at once, on another engine too", async () => {
    const sessions = new MemorySessionStore();
    const a = setup({ adapters: { sessions } });
    const callId = await strongCall(a, "C");
    assert.equal((await a.engine.finishVerification(callId)).level, 3);
    assert.equal(await a.engine.authorize(callId, "payout.update"), true);
    const b = setup({ adapters: { sessions, ledger: a.ledger } });
    capped({ C: 1 }, b);
    assert.equal(await b.engine.authorize(callId, "payout.update"), false, "the other engine's cap holds on the stored grant");
    capped({ C: 1 }, a);
    assert.equal(await a.engine.authorize(callId, "payout.update"), false);
    assert.equal(await a.engine.authorize(callId, "status.read"), true, "what level 1 allows still works");
  });

  it("V5: a cap of 0 issues no grant and opens no verified scope, and never lists the attestation as a method", async () => {
    const t = capped({ none: 0 });
    const callId = await strongCall(t);
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 0, scopes: [] });
    assert.equal(await t.engine.authorize(callId, "payment.request"), false);
    const receipt = (await t.engine.endCall(callId))!;
    assert.equal(receipt.body.verification.level, 0);
    assert.equal(receipt.body.attestation, "none");
    assert.equal((receipt.body.verification.methods as string[]).includes("none"), false);
  });

  it("V6: no cap ever raises a level, for any attestation and any cap", async () => {
    for (const attestation of ["A", "B", "C", "failed", "none"] as const) {
      const t = capped({ [attestation]: 3 });
      const { callId } = await t.engine.startCall({ attestation });
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitKeypad(callId, { dob: DOB });
      const level = (await t.engine.finishVerification(callId)).level;
      assert.ok(level <= 1, `${attestation} raised to ${level}`);
    }
  });
});
