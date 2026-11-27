// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// L2 fix U5 (PR #130 review, round 3): a call owes one cleanup per saved pass, so two factors passing
// at once on one call each get theirs, and neither settles the other's.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import { numberKeyFor } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PIN, setup } from "./helpers.ts";

const LINE = "+15555550142";
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const keysOf = (factor: string): AttemptCounterKey[] => [
  { workspaceId: "ws_test", factor, scope: "subject", key: OWNER },
  { workspaceId: "ws_test", factor, scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, LINE) },
];

describe("U5: two passes at once on one call", () => {
  it("each pass's counters are cleaned up, and nothing stays owed", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: LINE });
    const results = await Promise.all([t.engine.submitKeypad(callId, { dob: DOB }), t.engine.submitPin(callId, PIN)]);
    assert.deepEqual(results, [
      { matched: true, locked: false },
      { matched: true, locked: false },
    ]);
    for (const key of [...keysOf("keypad_knowledge"), ...keysOf("pin")]) assert.deepEqual(await t.counters.get(key, LONG_AGO), [], `${key.factor} ${key.scope}`);
    const badge = ((await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { forgetOwed?: unknown; forgetsOwed?: unknown } } }).modules.badge;
    assert.equal(badge.forgetOwed ?? badge.forgetsOwed, undefined, "nothing owed");
  });

  it("a cleanup stored before cleanups were kept one per pass is still run", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: LINE });
    const at = t.clock.now().toISOString();
    const keys = keysOf("keypad_knowledge");
    for (const key of keys) await t.counters.recordFailure(key, at, LONG_AGO);
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as { modules: { badge: { forgetOwed?: unknown } } };
    record.modules.badge.forgetOwed = { keys, at };
    await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never);
    t.clock.advance(900_000);
    await t.engine.submitPin(callId, PIN);
    for (const key of keys) assert.deepEqual(await t.counters.get(key, LONG_AGO), [], `${key.scope}`);
    const badge = ((await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { forgetOwed?: unknown; forgetsOwed?: unknown } } }).modules.badge;
    assert.equal(badge.forgetOwed ?? badge.forgetsOwed, undefined, "nothing owed");
  });
});
