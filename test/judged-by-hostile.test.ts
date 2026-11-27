// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile-pass regressions for #83 (VER-8, the policy version and config revision in grants and
// receipts). V1 failed before the receipt took only the two fields from lastJudgedBy; V2 held; V3
// failed before each field was taken only when it is text.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { CallRecord } from "../src/core/runtime.ts";
import { verifyReceipt } from "../src/prove/receipt.ts";
import { verifiedCall, setup } from "./helpers.ts";

/** Rewrites the Badge part of a stored call, as an older engine or a damaged store would have left it. */
async function editBadge(t: ReturnType<typeof setup>, callId: string, edit: (badge: Record<string, unknown>) => void): Promise<void> {
  const stored = (await t.sessions.get("ws_test", callId))!;
  const record = structuredClone(stored.record) as unknown as CallRecord;
  edit(record.modules.badge as unknown as Record<string, unknown>);
  assert.deepEqual(await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never), { ok: true, version: stored.version + 1 });
}

describe("hostile #83: who judged the verification", () => {
  it("V1: a stored lastJudgedBy holding other fields never changes the receipt's level or methods", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.markUntrusted(callId, "document");
    await editBadge(t, callId, (badge) => {
      badge.lastJudgedBy = { policyVersion: "default-1", configRevision: "default", level: 3, methods: ["photo_id"] };
    });
    const receipt = (await t.engine.endCall(callId))!;
    assert.deepEqual(receipt.body.verification, { level: 0, methods: [], policyVersion: "default-1", configRevision: "default" });
    assert.equal(verifyReceipt(receipt, t.engine.receiptKeys()), true);
  });

  it("V2: a call stored before VER-8 (no lastJudgedBy, a grant without the fields) still ends with a receipt that names neither", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await editBadge(t, callId, (badge) => {
      delete badge.lastJudgedBy;
    });
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as unknown as CallRecord;
    const grant = record.state.grant as unknown as Record<string, unknown>;
    delete grant.policyVersion;
    delete grant.configRevision;
    await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never);
    assert.equal(await t.engine.authorize(callId, "status.read"), true, "the old grant still works");
    const receipt = (await t.engine.endCall(callId))!;
    assert.deepEqual(Object.keys(receipt.body.verification).sort(), ["level", "methods"]);
  });
});

describe("hostile #83: a damaged lastJudgedBy", () => {
  it("V3: one that lacks a field, or holds one that is not text, drops that field and the receipt still signs", async () => {
    for (const [judged, expected] of [
      [{ policyVersion: "default-1" }, { policyVersion: "default-1" }],
      [{ configRevision: "default" }, { configRevision: "default" }],
      [{ policyVersion: 7, configRevision: { x: 1 } }, {}],
      [{ policyVersion: null, configRevision: "default" }, { configRevision: "default" }],
      [[], {}],
      ["default-1", {}],
    ] as const) {
      const t = setup();
      const callId = await verifiedCall(t);
      await editBadge(t, callId, (badge) => {
        badge.lastJudgedBy = judged;
      });
      const receipt = (await t.engine.endCall(callId))!;
      assert.notEqual(receipt, null, JSON.stringify(judged));
      const { level: _level, methods: _methods, ...by } = receipt.body.verification as Record<string, unknown>;
      assert.deepEqual(by, expected, JSON.stringify(judged));
      assert.equal(verifyReceipt(receipt, t.engine.receiptKeys()), true);
    }
  });
});
