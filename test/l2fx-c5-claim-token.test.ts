// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// L2 fix V5 (PR #130 review, round 4): a cleanup's claim is this run's only when the call holds this
// run's own claim. A claim write that saved nothing, followed by another run's claim before the
// read-back, runs none of the removals.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { numberKeyFor } from "../src/verify/counters.ts";
import { TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, DOB, setup } from "./helpers.ts";

const LINE = "+15555550142";
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const numberKey: AttemptCounterKey = { workspaceId: "ws_test", factor: "keypad_knowledge", scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, LINE) };

type Owed = { claimed?: true; claimToken?: string };
type Badge = { modules: { badge: { forgetsOwed?: Owed[] } } };

describe("V5: another run's claim is not this run's", () => {
  it("a claim write that saved nothing, then another run's claim: this run removes nothing", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: LINE });
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    t.sessions.compareAndSet = async (workspaceId, id, version, record) => {
      if ((record as unknown as Badge).modules.badge.forgetsOwed?.[0]?.claimed === true) {
        // Another run saves its own claim first; this run's write fails unsaved.
        t.sessions.compareAndSet = cas;
        const stored = (await t.sessions.get(workspaceId, id))!;
        const other = structuredClone(stored.record) as unknown as Badge;
        Object.assign(other.modules.badge.forgetsOwed![0]!, { claimed: true, claimToken: "another-run" });
        await cas(workspaceId, id, stored.version, other as unknown as JsonValue);
        throw new Error("store blip");
      }
      return cas(workspaceId, id, version, record);
    };
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
    assert.equal((await t.counters.get(numberKey, LONG_AGO)).length, 1, "the removal is the other run's to make");
  });

  it("this run's own claim, saved before its write failed (the ledger), still runs the removals", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: LINE });
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    t.sessions.compareAndSet = async (workspaceId, id, version, record) => {
      const saved = await cas(workspaceId, id, version, record);
      if ((record as unknown as Badge).modules.badge.forgetsOwed?.[0]?.claimed === true) {
        t.sessions.compareAndSet = cas;
        throw new Error("ledger blip after the save");
      }
      return saved;
    };
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
    assert.deepEqual(await t.counters.get(numberKey, LONG_AGO), [], "the claim was this run's");
  });
});
