// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// L2 review (PR #130, CodeRabbit on e9fa8ce): a flow start that wrote nothing takes back every
// counter it took, each on its own, so one refused take-back never keeps another counter's slot;
// the start's own error is kept beside the take-back's.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { MemorySessionStore } from "../src/core/session-store.ts";
import { FLOW_START, numberKeyFor } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { EngineError } from "../src/core/errors.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, setup, testConfig } from "./helpers.ts";

const CALLING = "+15555550142";
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const subject: AttemptCounterKey = { workspaceId: "ws_test", factor: FLOW_START, scope: "subject", key: subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT) };
const number: AttemptCounterKey = { workspaceId: "ws_test", factor: FLOW_START, scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, CALLING) };

/** Refuses the first flow-start take-back it is asked for, whichever counter that is. */
class RefusesFirstRemove extends MemoryAttemptCounters {
  refused: string | null = null;
  override async removeFailure(key: AttemptCounterKey, at: string): Promise<void> {
    if (key.factor === FLOW_START && this.refused === null) {
      this.refused = key.scope;
      throw new Error("counters 503");
    }
    return super.removeFailure(key, at);
  }
}

describe("a flow start that wrote nothing", () => {
  it("takes back every other counter when one take-back is refused, and keeps the start's own error", async () => {
    const counters = new RefusesFirstRemove();
    const t = setup({
      adapters: { counters },
      config: testConfig((c) => {
        c.flows = { pay: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] }] } };
      }),
    });
    const { callId } = await t.engine.startCall({ callingNumber: CALLING });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.finishVerification(callId);
    Object.assign(t.sessions as MemorySessionStore, { compareAndSet: async () => ({ ok: false as const }) });
    await assert.rejects(t.engine.startFlow(callId, "pay"), (e: unknown) => {
      assert.ok(e instanceof AggregateError, "both failures are reported");
      assert.ok(e.errors[0] instanceof EngineError && e.errors[0].code === "conflict", "the start's own error comes first");
      assert.match(String(e.errors[1]), /counters 503/);
      return true;
    });
    const kept = counters.refused === "subject" ? subject : number;
    const other = kept === subject ? number : subject;
    assert.equal((await counters.get(kept, LONG_AGO)).length, 1, "the refused take-back keeps its start (fail closed)");
    assert.deepEqual(await counters.get(other, LONG_AGO), [], "the other counter's start is still taken back");
  });
});
