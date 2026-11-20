// PR #130 review X0: a limited flow that attaches between beginVerification's late count (which
// found no flow) and its subject write is counted before the subject is written.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { FLOW_START } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, rejects, setup, testConfig } from "./helpers.ts";

const LONG_AGO = "2000-01-01T00:00:00.000Z";
const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const limited = (subject: number): FlowConfig =>
  testConfig((c) => {
    c.flows = { pay: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] }] } };
    (c.modules.badge!.settings as { lockout?: unknown }).lockout = { flowStartsPerHour: { subject } };
  });
const subjectStarts = async (t: TestEngine) => (await t.counters.get({ workspaceId: "ws_test", factor: FLOW_START, scope: "subject", key: SUBJECT }, LONG_AGO)).length;
type Rec = { flow: { counted: string[] } | null; modules: { badge: { subjectKey: string | null } } };

/** Attaches the flow on the call just before beginVerification's subject write first tries to save. */
function attachInGap(t: TestEngine, callId: string): void {
  const cas = t.sessions.compareAndSet.bind(t.sessions);
  let done = false;
  t.sessions.compareAndSet = async (...args) => {
    if (!done && (args[3] as unknown as Rec).modules.badge.subjectKey !== null) {
      done = true;
      await t.engine.startFlow(callId, "pay");
    }
    return cas(...args);
  };
}

describe("l2fx-b5 X0: a limited flow attached in beginVerification's gap", () => {
  it("refuses a subject at its limit, and never writes it", async () => {
    const t = setup({ config: limited(1) });
    const other = (await t.engine.startCall({ flow: "pay" })).callId;
    await t.engine.beginVerification(other, { accountNumber: ACCOUNT });
    const { callId } = await t.engine.startCall();
    attachInGap(t, callId);
    await assert.rejects(t.engine.beginVerification(callId, { accountNumber: ACCOUNT }), rejects("rate_limited"));
    const record = (await t.sessions.get("ws_test", callId))!.record as unknown as Rec;
    assert.equal(record.modules.badge.subjectKey, null, "the subject was never written");
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
  });

  it("counts a subject under its limit once, then starts verification", async () => {
    const t = setup({ config: limited(5) });
    const { callId } = await t.engine.startCall();
    attachInGap(t, callId);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const record = (await t.sessions.get("ws_test", callId))!.record as unknown as Rec;
    assert.equal(record.modules.badge.subjectKey, SUBJECT);
    assert.deepEqual(record.flow!.counted, [`subject:${SUBJECT}`]);
    assert.equal(await subjectStarts(t), 1);
    assert.equal((await t.engine.flowPosition(callId))!.status, "running");
  });
});
