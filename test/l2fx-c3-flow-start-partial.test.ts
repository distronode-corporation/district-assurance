// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// L2 fix U11 (PR #130 review, round 3): a flow start whose later counter write fails takes back the
// starts it had already counted, so the subject's slot is not spent on a flow that never attached.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { FLOW_START, numberKeyFor, recordFlowStarts } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, setup, testConfig } from "./helpers.ts";

const LINE = "+15555550142";
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const subject: AttemptCounterKey = { workspaceId: "ws_test", factor: FLOW_START, scope: "subject", key: subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT) };
const number: AttemptCounterKey = { workspaceId: "ws_test", factor: FLOW_START, scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, LINE) };
const limits = { subject: 5, number: 10 };

/** Refuses the number's flow start before writing it; `alsoRemove` refuses taking one back too. */
class Refusing extends MemoryAttemptCounters {
  alsoRemove = false;
  override async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    if (key.factor === FLOW_START && key.scope === "number") throw new Error("counters 503");
    return super.recordFailure(key, at, since);
  }
  override async removeFailure(key: AttemptCounterKey, at: string): Promise<void> {
    if (this.alsoRemove) throw new Error("counters 503");
    return super.removeFailure(key, at);
  }
}

describe("U11: a flow start whose later counter write fails", () => {
  it("takes the subject's start back and passes the store's error on", async () => {
    const counters = new Refusing();
    await assert.rejects(recordFlowStarts(counters, limits, [subject, number], new Date(0)), /counters 503/);
    assert.deepEqual(await counters.get(subject, LONG_AGO), []);
  });

  it("a take-back the store refuses too keeps the start (fail closed) and passes the first error on", async () => {
    const counters = new Refusing();
    counters.alsoRemove = true;
    await assert.rejects(recordFlowStarts(counters, limits, [subject, number], new Date(0)), /counters 503/);
    assert.equal((await counters.get(subject, LONG_AGO)).length, 1);
  });

  it("on the engine: a door flow that never attached spends no start of the subject's", async () => {
    const counters = new Refusing();
    const t = setup({
      adapters: { counters },
      config: testConfig((c: FlowConfig) => {
        c.policy.scopes["entry.open"] = 2;
        c.flows = { door: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["entry.open"] }] } };
      }),
    });
    const { callId } = await t.engine.startCall({ callingNumber: LINE });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.finishVerification(callId);
    await assert.rejects(t.engine.startFlow(callId, "door"), /counters 503/);
    assert.deepEqual(await counters.get(subject, LONG_AGO), []);
  });
});
