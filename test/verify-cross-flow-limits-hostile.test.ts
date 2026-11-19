// Hostile pass on #120 (VER-15 limits across flows), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { FLOW_START, numberKeyFor } from "../src/verify/counters.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig } from "./helpers.ts";

const LONG_AGO = "2000-01-01T00:00:00.000Z";
const CALLING = "+15555550142";
const NUMBER = numberKeyFor(TEST_KNOWLEDGE_KEY, CALLING);
const startCounter = (key: string, workspaceId = "ws_test"): AttemptCounterKey => ({ workspaceId, factor: FLOW_START, scope: "number", key });
const verify2 = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] };

function cfg(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.flows = { pay: { steps: [verify2] }, status: { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"], scopes: ["status.read"] }] } };
    patch(c);
  });
}

const starts = async (t: TestEngine, key = NUMBER, workspaceId = "ws_test") => (await t.counters.get(startCounter(key, workspaceId), LONG_AGO)).length;

describe("#120 hostile: counting starts", () => {
  it("X1 two startFlow calls racing on one call attach one flow and count one start", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ callingNumber: CALLING });
    const results = await Promise.allSettled([t.engine.startFlow(callId, "pay"), t.engine.startFlow(callId, "pay")]);
    assert.deepEqual(results.map((r) => r.status).sort(), ["fulfilled", "rejected"]);
    assert.equal(await starts(t), 1, "the start the call refused is not counted");
  });

  it("X2 two startCall calls racing on one host call id open one call and count one start", async () => {
    const t = setup({ config: cfg() });
    const results = await Promise.allSettled([1, 2].map(() => t.engine.startCall({ callId: "call_same", flow: "pay", callingNumber: CALLING })));
    assert.deepEqual(results.map((r) => r.status).sort(), ["fulfilled", "rejected"]);
    assert.equal(await starts(t), 1);
  });

  it("X2b ...and the same races on a flow whose starts are not limited count nothing", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ callingNumber: CALLING });
    await Promise.allSettled([t.engine.startFlow(callId, "status"), t.engine.startFlow(callId, "status")]);
    await Promise.allSettled([1, 2].map(() => t.engine.startCall({ callId: "call_status", flow: "status", callingNumber: CALLING })));
    assert.equal(await starts(t), 0);
  });

  it("X2c a start whose write saved and then failed (the ledger down) stays counted", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ callingNumber: CALLING });
    const append = t.ledger.append.bind(t.ledger);
    t.ledger.append = () => Promise.reject(new Error("ledger down"));
    await assert.rejects(t.engine.startFlow(callId, "pay"), /ledger down/);
    t.ledger.append = append;
    assert.equal((await t.engine.flowPosition(callId))!.status, "running");
    assert.equal(await starts(t), 1);
  });

  it("X3 calling numbers that are not strings are refused, never coerced into one", async () => {
    const t = setup({ config: cfg() });
    for (const callingNumber of [[CALLING], { toString: () => CALLING }, 15555550142]) {
      await assert.rejects(t.engine.startCall({ callingNumber: callingNumber as unknown as string }), rejects("invalid_input", /E\.164/), JSON.stringify(callingNumber));
    }
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: [CALLING] as unknown as string }), rejects("invalid_input", /E\.164/));
  });

  it("X4 two workspaces on one counters store, same number: each has its own limit", async () => {
    const counters = new MemoryAttemptCounters();
    const limit = cfg((c) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { flowStartsPerHour: { number: 1 } }));
    const a = createTestEngine({ workspaceId: "ws_a", config: limit, adapters: { counters } });
    const b = createTestEngine({ workspaceId: "ws_b", config: limit, adapters: { counters } });
    await a.engine.startCall({ flow: "pay", callingNumber: CALLING });
    await assert.rejects(a.engine.startCall({ flow: "pay", callingNumber: CALLING }), rejects("rate_limited"));
    const { callId } = await b.engine.startCall({ flow: "pay", callingNumber: CALLING });
    assert.equal((await b.engine.flowPosition(callId))!.status, "running");
  });

  it("X5 a flow failed by the subject limit at a restart leaves no grant that authorizes its scope", async () => {
    const limit = cfg((c) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { flowStartsPerHour: { subject: 1 } }));
    const t = setup({ config: limit });
    const first = (await t.engine.startCall({ flow: "pay" })).callId;
    await t.engine.beginVerification(first, { accountNumber: ACCOUNT });
    const second = (await t.engine.startCall({ flow: "pay" })).callId;
    await assert.rejects(t.engine.beginVerification(second, { accountNumber: ACCOUNT }), rejects("rate_limited"));
    await assert.rejects(t.engine.submitKeypad(second, { dob: DOB }));
    assert.equal(await t.engine.authorize(second, "payment.request"), false);
    assert.equal((await t.engine.flowPosition(second))!.status, "failed");
  });
});
