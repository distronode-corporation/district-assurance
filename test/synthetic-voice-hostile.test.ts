// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile pass on #108 (VER-14 synthetic voice signal), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { createTestEngine, type TestEngine } from "../src/testing/index.ts";
import { rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const THRESHOLDS = { acme: { spokenKnowledgeAbove: 0.5, levelOneAbove: 0.8 } };

function voiceConfig(): FlowConfig {
  return testConfig((c) => {
    (c.modules.badge!.settings as { syntheticVoice?: unknown }).syntheticVoice = structuredClone(THRESHOLDS);
  });
}

async function voiceEntries(t: TestEngine): Promise<unknown[]> {
  return (await t.ledger.list()).filter((e) => e.event === "verification.synthetic_voice").map((e) => e.detail);
}

describe("#108 hostile: what a report takes", () => {
  it("V1 a vendor that is not a string (an array or a toString object naming a configured vendor) is invalid_input, nothing applied or ledgered", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    for (const vendor of [["acme"], { toString: () => "acme" }, new String("acme")]) {
      await assert.rejects(t.engine.reportSyntheticVoice(callId, { score: 0.99, vendor } as never), rejects("invalid_input"), String(vendor));
    }
    assert.equal((await t.engine.state(callId)).level, 3, "nothing applied");
    assert.deepEqual(await voiceEntries(t), []);
  });

  it("V2 prototype names, unknown vendors and bad scores are refused before the call is touched", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    for (const vendor of ["__proto__", "constructor", "toString", "hasOwnProperty", "ACME", "acme ", ""]) {
      await assert.rejects(t.engine.reportSyntheticVoice(callId, { score: 0.99, vendor }), rejects("invalid_input"), vendor);
    }
    for (const score of [Number.NaN, Infinity, -Infinity, -0.01, 1.01, "0.9", null, undefined, new Number(0.9), 10n]) {
      await assert.rejects(t.engine.reportSyntheticVoice(callId, { score, vendor: "acme" } as never), rejects("invalid_input"), String(score));
    }
    for (const input of [null, undefined, 0.9, "acme", [0.9, "acme"]]) {
      await assert.rejects(t.engine.reportSyntheticVoice(callId, input as never), rejects("invalid_input"), String(input));
    }
    assert.equal((await t.engine.state(callId)).level, 3);
    assert.deepEqual(await voiceEntries(t), []);
  });
});

describe("#108 hostile: order and replay", () => {
  it("V3 a lower score after a higher one never lifts the cap, and a late report after the end is refused with nothing ledgered", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    await t.engine.reportSyntheticVoice(callId, { score: 0.9, vendor: "acme" });
    await t.engine.reportSyntheticVoice(callId, { score: 0, vendor: "acme" });
    assert.deepEqual([(await t.engine.state(callId)).syntheticVoice, (await t.engine.state(callId)).level], ["level_1", 1]);
    await t.engine.finishVerification(callId).catch(() => undefined);
    assert.equal((await t.engine.state(callId)).level <= 1, true, "a fresh finish stays held");
    await t.engine.endCall(callId);
    const entries = (await voiceEntries(t)).length;
    await assert.rejects(t.engine.reportSyntheticVoice(callId, { score: 0.99, vendor: "acme" }));
    assert.equal((await voiceEntries(t)).length, entries);
  });

  it("V4 two reports at once on two engines sharing the stores: the highest band holds, each is ledgered once", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    const second = createTestEngine({ config: voiceConfig(), adapters: { sessions: t.sessions, ledger: t.ledger, records: t.records } });
    await Promise.all([t.engine.reportSyntheticVoice(callId, { score: 0.9, vendor: "acme" }), second.engine.reportSyntheticVoice(callId, { score: 0.1, vendor: "acme" })]);
    const state = await t.engine.state(callId);
    assert.deepEqual([state.syntheticVoice, state.level], ["level_1", 1]);
    assert.deepEqual((await voiceEntries(t)).map((d) => (d as { band: string }).band).sort(), ["clear", "level_1"]);
  });

  it("V5 the ledger and receipt never carry the score", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    await t.engine.reportSyntheticVoice(callId, { score: 0.8123456789, vendor: "acme" });
    const receipt = await t.engine.endCall(callId);
    const text = JSON.stringify([await t.ledger.list(), receipt]);
    assert.equal(text.includes("0.8123456789"), false);
    assert.equal(JSON.stringify(receipt).includes("acme"), false, "no vendor on the receipt");
  });
});
