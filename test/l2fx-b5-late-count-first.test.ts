// PR #130 review U3b: beginVerification counts a running limited flow's start before it writes the
// subject, so over the limit no factor can be judged for that subject in between.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { FLOW_START } from "../src/verify/counters.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig } from "./helpers.ts";

const limited = (): FlowConfig =>
  testConfig((c) => {
    c.flows = { pay: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] }] } };
    (c.modules.badge!.settings as { lockout?: unknown }).lockout = { flowStartsPerHour: { subject: 1 } };
  });

describe("l2fx-b5 U3b: the late flow count comes before the subject", () => {
  it("lets no factor pass during a beginVerification whose subject is over the limit", async () => {
    const t = setup({ config: limited() });
    const other = (await t.engine.startCall({ flow: "pay" })).callId;
    await t.engine.beginVerification(other, { accountNumber: ACCOUNT });
    const { callId } = await t.engine.startCall({ flow: "pay" });

    // The flow-start counters are read (to find the limit) while an overlapping factor entry runs.
    const get = t.counters.get.bind(t.counters);
    let overlapped: Promise<unknown> | undefined;
    t.counters.get = (key, since) => {
      if (key.factor === FLOW_START && overlapped === undefined) {
        overlapped = t.engine.submitKeypad(callId, { dob: DOB }).then(
          (result) => result,
          (e: unknown) => e,
        );
        // The count waits for the entry, so the entry is judged before the count can decide.
        return overlapped.then(() => get(key, since));
      }
      return get(key, since);
    };
    await assert.rejects(t.engine.beginVerification(callId, { accountNumber: ACCOUNT }), rejects("rate_limited"));
    const entry = await overlapped;
    assert.ok(rejects("invalid_transition")(entry), "the entry is never judged: verification has not started");
    const position = (await t.engine.flowPosition(callId))!;
    assert.equal(position.status, "failed");
    assert.equal(position.index, 0, "no step completed");
    const badge = ((await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { subjectKey: string | null } } }).modules.badge;
    assert.equal(badge.subjectKey, null, "the subject was never written");
  });

  it("keeps the count when the start's own write fails after it (the safe side)", async () => {
    const t = setup({ config: limited() });
    const { callId } = await t.engine.startCall({ flow: "pay" });
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    // The counting write saves; the subject's write then finds the call moved every time.
    t.sessions.compareAndSet = async (...args) =>
      (args[3] as { modules: { badge: { subjectKey: string | null } } }).modules.badge.subjectKey !== null ? { ok: false as const } : cas(...args);
    await assert.rejects(t.engine.beginVerification(callId, { accountNumber: ACCOUNT }), rejects("conflict"));
    t.sessions.compareAndSet = cas;
    const slice = ((await t.sessions.get("ws_test", callId))!.record as { flow: { counted: string[] } }).flow;
    assert.equal(slice.counted.length, 1, "the subject is taken on the call");
    // A retry for the same subject counts nothing more, and starts verification.
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.flowPosition(callId))!.status, "running");
  });
});
