// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// confirmIntake against a call that changes between its first read and its reserving write, and a
// filing abandoned while it is written and followed by a new intake.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { heard, rejects, setup, verifiedCall } from "./helpers.ts";

type Stored = { version: number; record: { modules: { dossier: { intake: { filing: unknown; values: Record<string, unknown> } | null } } } };

/** A call with an open repair draft, its read-back heard, and a session store whose next read is `edit`ed. */
async function drafted(edit: (copy: Stored) => void) {
  const t = setup();
  const callId = await verifiedCall(t);
  await t.engine.startIntake(callId, "repair");
  await t.engine.setIntakeField(callId, "issue", "leak");
  const readBack = await heard(t, callId);
  const read = t.sessions.get.bind(t.sessions);
  let first = true;
  t.sessions.get = async (w, id) => {
    const got = await read(w, id);
    if (!first || got === null) return got;
    first = false;
    const copy = structuredClone(got) as unknown as Stored;
    edit(copy);
    return copy as never;
  };
  return { t, callId, readBack, restore: () => (t.sessions.get = read) };
}

describe("confirmIntake: a draft that moved between the first read and the reservation", () => {
  it("refuses when the first read saw a filing already reserved and the reservation finds none", async () => {
    const { t, callId, readBack, restore } = await drafted((copy) => {
      copy.record.modules.dossier.intake!.filing = { recordId: "rec_other" };
    });
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), rejects("conflict", /draft changed while it was being filed/));
    restore();
    assert.equal((await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack })).values.issue, "leak", "a second confirmation files it");
  });

  it("refuses when the values the first read digested are not the ones being filed", async () => {
    const { t, callId, readBack, restore } = await drafted((copy) => {
      copy.record.modules.dossier.intake!.values = { issue: "a different issue" };
    });
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), rejects("conflict", /draft changed while it was being filed/));
    restore();
    assert.equal(await t.records.getIntakeRecord("ws_test", "rec_1"), null, "nothing was stored");
  });
});

describe("confirmIntake: abandoned while written, then a new intake", () => {
  it("files nothing when a new draft is open by the time the write lands", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    const put = t.records.putIntakeRecord.bind(t.records);
    t.records.putIntakeRecord = async (record, seen) => {
      await t.engine.abandonIntake(callId);
      await t.engine.startIntake(callId, "repair");
      return put(record, seen);
    };
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), rejects("precondition_failed", /abandoned while it was written/));
    assert.equal(await t.records.getIntakeRecord("ws_test", "rec_1"), null);
    assert.deepEqual((await t.engine.state(callId)).recordIds, []);
  });
});
