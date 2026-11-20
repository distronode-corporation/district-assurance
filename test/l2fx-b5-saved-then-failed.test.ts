// PR #130 review W0: a late flow count's write that saved and then failed (the ledger append after
// it) still gives back the counts another verification on the call took first.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { FLOW_START } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, setup, testConfig } from "./helpers.ts";

const LONG_AGO = "2000-01-01T00:00:00.000Z";
const limited = (): FlowConfig =>
  testConfig((c) => {
    c.flows = { pay: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] }] } };
  });
const subjectStarts = async (t: TestEngine) =>
  (await t.counters.get({ workspaceId: "ws_test", factor: FLOW_START, scope: "subject", key: subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT) }, LONG_AGO)).length;

describe("l2fx-b5 W0: a counting write that saved, then failed", () => {
  it("gives back the count an overlapping verification took first", async () => {
    const t = setup({ config: limited() });
    // The ledger is down: the call's start is saved with its entries pending, so every later
    // write saves and then fails on the append.
    t.ledger.append = () => Promise.reject(new Error("ledger down"));
    await assert.rejects(t.engine.startCall({ callId: "call_w0", flow: "pay" }), /ledger down/);
    const callId = "call_w0";

    const record = t.counters.recordFailure.bind(t.counters);
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    let reached!: () => void;
    const atCount = new Promise<void>((resolve) => (reached = resolve));
    let first = true;
    t.counters.recordFailure = async (key, ...rest) => {
      if (key.factor === FLOW_START && first) {
        first = false;
        reached();
        await held;
      }
      return record(key, ...rest);
    };
    const a = t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await atCount;
    // This one counts the subject and takes it on the call (saved), then fails on the ledger.
    await assert.rejects(t.engine.beginVerification(callId, { accountNumber: ACCOUNT }), /ledger down/);
    assert.equal(await subjectStarts(t), 1);
    release();
    // The first one's write saves too, finds the subject taken, and fails on the ledger.
    await assert.rejects(a, /ledger down/);
    assert.equal(await subjectStarts(t), 1, "the first one's count, taken second, is given back");
    const flow = ((await t.sessions.get("ws_test", callId))!.record as { flow: { counted: string[] } }).flow;
    assert.equal(flow.counted.length, 1, "the call holds the subject's count once");
  });
});
