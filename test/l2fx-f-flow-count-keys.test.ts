// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// PR #130 review (CodeRabbit on 07e50ea), flow-start counts:
// - startFlow counts on the keys the call had when it was read; a subject verification bound before
//   the flow attached is counted again, inside the attach write, and the unused count given back.
// - beginVerification's late count judges only keys the flow has not admitted: a key another
//   overlapping verification admitted is never counted twice and never fails the flow.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { FLOW_START, numberKeyFor } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig } from "./helpers.ts";

const LONG_AGO = "2000-01-01T00:00:00.000Z";
const CALLING = "+15555550142";
const NUMBER = numberKeyFor(TEST_KNOWLEDGE_KEY, CALLING);
const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const limited = (limits: { subject?: number; number?: number }): FlowConfig =>
  testConfig((c) => {
    c.flows = { pay: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] }] } };
    (c.modules.badge!.settings as { lockout?: unknown }).lockout = { flowStartsPerHour: limits };
  });
const counter = (scope: "subject" | "number", key: string): AttemptCounterKey => ({ workspaceId: "ws_test", factor: FLOW_START, scope, key });
const starts = async (t: TestEngine, scope: "subject" | "number", key: string) => (await t.counters.get(counter(scope, key), LONG_AGO)).length;
type Rec = { flow: { counted: string[]; status: string } | null; modules: { badge: { subjectKey: string | null } } };
const stored = async (t: TestEngine, callId: string) => (await t.sessions.get("ws_test", callId))!.record as unknown as Rec;

/** Verification that names the subject and finishes, so the call is open again. */
async function verifySubject(t: TestEngine, callId: string): Promise<void> {
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
  await t.engine.finishVerification(callId);
}

/** Runs `inGap` once, just before the first write that attaches a flow tries to save. */
function beforeAttach(t: TestEngine, inGap: () => Promise<void>, every = false): void {
  const cas = t.sessions.compareAndSet.bind(t.sessions);
  let done = false;
  t.sessions.compareAndSet = async (...args) => {
    const record = args[3] as unknown as Rec;
    if ((every || !done) && record.flow !== null && record.flow.counted !== undefined && record.flow.status !== "failed") {
      done = true;
      await inGap();
    }
    return cas(...args);
  };
}

describe("l2fx-f: startFlow re-checks its counter keys when it attaches", () => {
  it("counts a subject bound while the start was counted, and refuses it over the limit", async () => {
    const t = setup({ config: limited({ subject: 1 }) });
    const other = (await t.engine.startCall({ flow: "pay" })).callId;
    await t.engine.beginVerification(other, { accountNumber: ACCOUNT });
    assert.equal(await starts(t, "subject", SUBJECT), 1, "the subject's one start is used");
    const { callId } = await t.engine.startCall();
    beforeAttach(t, () => verifySubject(t, callId));
    await assert.rejects(t.engine.startFlow(callId, "pay"), rejects("rate_limited"));
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
    assert.equal(await starts(t, "subject", SUBJECT), 1, "over the limit: not counted");
  });

  it("gives back the number-only count and counts the number and the subject once each", async () => {
    const t = setup({ config: limited({ subject: 5, number: 5 }) });
    const { callId } = await t.engine.startCall();
    beforeAttach(t, () => verifySubject(t, callId));
    await t.engine.startFlow(callId, "pay", { callingNumber: CALLING });
    const record = await stored(t, callId);
    assert.equal(record.flow!.status, "running");
    assert.deepEqual([...record.flow!.counted].sort(), [`number:${NUMBER}`, `subject:${SUBJECT}`]);
    assert.equal(await starts(t, "number", NUMBER), 1, "the first count was given back");
    assert.equal(await starts(t, "subject", SUBJECT), 1);
  });

  it("gives up with conflict when the keys move on every attempt, keeping no count", async () => {
    const t = setup({ config: limited({ subject: 5 }) });
    const { callId } = await t.engine.startCall();
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    let n = 0;
    beforeAttach(
      t,
      async () => {
        // Another subject is bound on the call each time the flow is about to attach.
        const now = (await t.sessions.get("ws_test", callId))!;
        const record = structuredClone(now.record) as unknown as Rec;
        record.modules.badge.subjectKey = `subject_${++n}`;
        await cas("ws_test", callId, now.version, record as unknown as JsonValue);
      },
      true,
    );
    await assert.rejects(t.engine.startFlow(callId, "pay"), rejects("conflict"));
    assert.equal((await stored(t, callId)).flow, null);
    for (let i = 1; i <= n; i++) assert.equal(await starts(t, "subject", `subject_${i}`), 0, `subject_${i} given back`);
  });
});

/**
 * Two overlapping beginVerification calls: B reads the flow with nothing counted, then waits on its
 * count; A counts the subject's one start and saves it on the flow; B's count then runs, and its
 * next write lands before A's subject write. Settles both, A first.
 */
async function overlap(t: TestEngine, callId: string, input: { accountNumber: string; callingNumber?: string }) {
  const get = t.counters.get.bind(t.counters);
  const cas = t.sessions.compareAndSet.bind(t.sessions);
  let releaseB!: () => void;
  const gate = new Promise<void>((r) => (releaseB = r));
  let reached!: () => void;
  const bWaits = new Promise<void>((r) => (reached = r));
  let held = false;
  t.counters.get = async (key, since) => {
    if (!held && key.factor === FLOW_START && key.scope === "subject") {
      held = true;
      reached();
      await gate;
    }
    return get(key, since);
  };
  let aCounted = false;
  let bWrote: (() => void) | null = null;
  t.sessions.compareAndSet = async (...args) => {
    const record = args[3] as unknown as Rec;
    if (!aCounted && record.flow?.counted.length === 1 && record.modules.badge.subjectKey === null) {
      aCounted = true;
      const saved = await cas(...args);
      const next = new Promise<void>((r) => (bWrote = r));
      releaseB();
      await next;
      return saved;
    }
    const saved = await cas(...args);
    const wrote = bWrote;
    bWrote = null;
    wrote?.();
    return saved;
  };
  const b = t.engine.beginVerification(callId, input);
  await bWaits;
  const a = t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  return Promise.allSettled([a, b]);
}

describe("l2fx-f: overlapping beginVerification calls on one limited flow", () => {
  it("does not fail the flow on the subject the other call admitted, nor count it twice", async () => {
    const t = setup({ config: limited({ subject: 1 }) });
    const { callId } = await t.engine.startCall({ flow: "pay" });
    const [, b] = await overlap(t, callId, { accountNumber: ACCOUNT });
    assert.equal(b.status, "fulfilled", "B is not refused for A's admitted subject");
    const record = await stored(t, callId);
    assert.equal(record.flow!.status, "running");
    assert.deepEqual(record.flow!.counted, [`subject:${SUBJECT}`]);
    assert.equal(record.modules.badge.subjectKey, SUBJECT);
    assert.equal(await starts(t, "subject", SUBJECT), 1);
  });

  it("mixed: skips the admitted subject and counts the new number", async () => {
    const t = setup({ config: limited({ subject: 1, number: 1 }) });
    const { callId } = await t.engine.startCall({ flow: "pay" });
    const [, b] = await overlap(t, callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
    assert.equal(b.status, "fulfilled");
    const record = await stored(t, callId);
    assert.equal(record.flow!.status, "running");
    assert.deepEqual(record.flow!.counted, [`subject:${SUBJECT}`, `number:${NUMBER}`]);
    assert.equal(await starts(t, "subject", SUBJECT), 1);
    assert.equal(await starts(t, "number", NUMBER), 1);
  });

  it("mixed: skips the admitted subject, and fails the flow on a new number over its limit", async () => {
    const t = setup({ config: limited({ subject: 1, number: 1 }) });
    await t.engine.startCall({ flow: "pay", callingNumber: CALLING });
    assert.equal(await starts(t, "number", NUMBER), 1, "the number's one start is used");
    const { callId } = await t.engine.startCall({ flow: "pay" });
    const [, b] = await overlap(t, callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
    assert.equal(b.status, "rejected");
    assert.ok(rejects("rate_limited")((b as PromiseRejectedResult).reason));
    const record = await stored(t, callId);
    assert.equal(record.flow!.status, "failed");
    assert.deepEqual(record.flow!.counted, [`subject:${SUBJECT}`]);
    assert.equal(await starts(t, "subject", SUBJECT), 1);
    assert.equal(await starts(t, "number", NUMBER), 1, "over the limit: not counted");
  });
});
