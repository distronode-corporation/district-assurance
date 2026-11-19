// Hostile-pass regressions for #76 (FIL-1 read-back, FIL-4 conditional fields). I1 and I2 failed
// before their fixes (a required field named constructor, a lone surrogate in text); the rest held.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { IntakeForm } from "../src/file/intake.ts";
import { rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const label = (en: string) => ({ en, fr: en });

function withForm(form: IntakeForm) {
  return setup({ config: testConfig((c) => (c.modules.dossier = { settings: { forms: [form] } as never })) });
}

describe("hostile #76: what is filed", () => {
  it("I1: a required field named like an Object.prototype member is still required", async () => {
    const t = withForm({ formId: "f", version: "1", fields: [{ key: "constructor", label: label("Builder"), type: "text", required: true }] });
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "f");
    const { digest } = await t.engine.intakeReadBack(callId);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: digest }), rejects("invalid_input", /required fields missing: constructor/));
  });

  it("I2: a text value that is not Unicode text (a lone surrogate) is refused, never filed", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    for (const raw of ["leak \uD800", "\uDC00 under the sink", "a\uD83Db"]) {
      const result = await t.engine.setIntakeField(callId, "issue", raw);
      assert.equal(result.ok, false, JSON.stringify(raw));
    }
    assert.equal((await t.engine.setIntakeField(callId, "issue", "leak \u1f4a7")).ok, true, "a whole pair is text");
  });
});

describe("hostile #76: the read-back the caller heard", () => {
  it("I3: a value changed after the read-back is refused; changed back, the same read-back files", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "Leak");
    const heard = await t.engine.intakeReadBack(callId);
    await t.engine.setIntakeField(callId, "issue", "Fire");
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: heard.digest }), rejects("precondition_failed"));
    await t.engine.setIntakeField(callId, "issue", "Leak");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: heard.digest });
    assert.deepEqual(record.values, { issue: "Leak" });
  });

  it("I4: a read-back digest of the wrong type, case, length or padding is refused, and nothing is filed", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "Leak");
    const { digest } = await t.engine.intakeReadBack(callId);
    for (const readBack of [undefined, null, 42, [digest], { toString: () => digest }, ` ${digest}`, `${digest}0`, digest.slice(1), "", "0".repeat(64)]) {
      await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: readBack as string }), rejects("precondition_failed"), String(readBack).slice(0, 20));
    }
    assert.equal((await t.records.getIntakeRecord("ws_test", "rec_1")) === null, true);
  });

  it("I5: a read-back in another locale's words is not the one this call heard", async () => {
    const t = setup();
    const en = await verifiedCall(t, "en");
    const fr = await verifiedCall(t, "fr");
    for (const callId of [en, fr]) {
      await t.engine.startIntake(callId, "repair");
      await t.engine.setIntakeField(callId, "issue", "Leak");
    }
    const enHeard = await t.engine.intakeReadBack(en);
    await assert.rejects(t.engine.confirmIntake(fr, { confirmedBy: "voice", readBack: enHeard.digest }), rejects("precondition_failed"));
  });

  it("I6: a field hidden after it was given is neither read back, filed nor in the ledger, and cannot be set while hidden", async () => {
    const t = withForm({
      formId: "f",
      version: "1",
      fields: [
        { key: "issue", label: label("Issue"), type: "text", required: true },
        { key: "urgent", label: label("Urgent"), type: "yes_no", required: false },
        { key: "since", label: label("Since"), type: "date", required: true, showIf: { field: "urgent", equals: true } },
      ],
    });
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "f");
    await t.engine.setIntakeField(callId, "issue", "Leak");
    await t.engine.setIntakeField(callId, "urgent", "yes");
    await t.engine.setIntakeField(callId, "since", "2026-11-01");
    await t.engine.setIntakeField(callId, "urgent", "no");
    const heard = await t.engine.intakeReadBack(callId);
    assert.equal(heard.text.includes("November"), false, "the hidden date is not read");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad", readBack: heard.digest });
    assert.deepEqual(Object.keys(record.values).sort(), ["issue", "urgent"]);
    assert.equal(JSON.stringify(await t.ledger.list()).includes("2026-11-01"), false, "the hidden value is in no ledger entry");
    await assert.rejects(t.engine.setIntakeField(callId, "since", "2026-11-02"), rejects("invalid_transition"));
  });
});
