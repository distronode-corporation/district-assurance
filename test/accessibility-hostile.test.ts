// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile-pass regressions for #111 (VER-11, the accessible verification path). A5 failed before
// the collector ended an entry when the clock went back; the rest held.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import type { CallRecord } from "../src/core/runtime.ts";
import { TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig } from "./helpers.ts";

const POSTAL = "K1A0B1";
const SPOKEN = { fields: { postal_code: "ca_postal_code" as const }, maxAttemptsPerCall: 2 };

type Accessibility = { spokenKeypadFields?: string[]; keypadIdleSeconds?: number; maxKeypadIdleSeconds?: number };

/** Spoken answers on, a level 1 set of spoken_knowledge alone, and Badge's accessibility settings. */
function accessibleConfig(accessibility: Accessibility = { spokenKeypadFields: ["dob"] }, patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.spoken = structuredClone(SPOKEN);
    c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["spoken_knowledge"]] };
    const settings = c.modules.badge!.settings as { factors: string[]; accessibility?: Accessibility };
    settings.factors.push("spoken_knowledge");
    settings.accessibility = accessibility;
    patch(c);
  });
}

function accessibleSetup(config: FlowConfig = accessibleConfig()): TestEngine {
  const t = setup({ config });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB, postal_code: POSTAL }, pin: "4826" }));
  return t;
}

async function verifying(t: TestEngine, input: Parameters<TestEngine["engine"]["startCall"]>[0] = {}): Promise<string> {
  const { callId } = await t.engine.startCall(input);
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  return callId;
}

async function attempts(t: TestEngine, callId: string): Promise<Record<string, number>> {
  const stored = await t.sessions.get("ws_test", callId);
  return (stored!.record as unknown as CallRecord).modules.badge as unknown as Record<string, number>;
}


describe("hostile #111: the accessible path", () => {
  it("A1: a relay or TTY call leaves no mark in any ledger entry or the receipt, whatever it does", async () => {
    for (const access of ["relay", "tty"] as const) {
      const t = accessibleSetup();
      const callId = await verifying(t, { access });
      await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "wrong", dob: "11111111" });
      await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K one A zero B one", dob: "one nine eight five zero two one four" });
      await t.engine.finishVerification(callId);
      await t.engine.markUntrusted(callId, "relay operator text");
      const receipt = await t.engine.endCall(callId);
      const everything = JSON.stringify([await t.ledger.list(), receipt]);
      // The host's own taint label may say "relay"; the engine itself writes neither word.
      const own = everything.replaceAll("relay operator text", "");
      assert.equal(/\b(relay|tty|access)\b/i.test(own), false, access);
    }
  });

  it("A2: a spoken PIN is refused before it counts, in every spelling that is the pin field, and others are not a PIN", async () => {
    const t = accessibleSetup();
    const callId = await verifying(t);
    for (const entry of [{ pin: "4826" }, { pin: "4826", dob: "x" }, JSON.parse('{"pin": 4826}')]) {
      await assert.rejects(t.engine.submitFactor(callId, "spoken_knowledge", entry), rejects("invalid_input", /never taken by speech/));
    }
    const badge = (await attempts(t, callId)) as unknown as { attempts: Record<string, number> };
    assert.deepEqual(badge.attempts ?? {}, {}, "no attempt used");
  });

  it("A3: concurrent spoken and keypad answers never use more than the shared keypad budget", async () => {
    const t = accessibleSetup(accessibleConfig(undefined, (c) => (c.policy.maxKeypadAttemptsPerCall = 3)));
    const callId = await verifying(t);
    const wrongSpoken = { postal_code: "K1A 0B1", dob: "11111111" };
    // Two waves of two at once: within the engine's five write attempts, so none ends in conflict.
    const results = [];
    for (let wave = 0; wave < 2; wave++) {
      results.push(...(await Promise.all([t.engine.submitFactor(callId, "spoken_knowledge", wrongSpoken), t.engine.submitKeypad(callId, { dob: "11111111" })])));
    }
    const badge = (await attempts(t, callId)) as unknown as { attempts: Record<string, number> };
    assert.ok((badge.attempts.keypad_knowledge ?? 0) <= 3, JSON.stringify(badge.attempts));
    assert.ok(results.filter((r) => r.locked).length >= 1);
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: false, locked: true }, "the right answer after the budget is gone");
  });

  it("A4: the access mark takes only relay or tty, read once", async () => {
    const t = accessibleSetup();
    for (const access of ["RELAY", "relay ", "", null, 1, ["relay"], { toString: () => "relay" }]) {
      await assert.rejects(t.engine.startCall({ access: access as never }), rejects("invalid_input"), String(access));
    }
  });
});
