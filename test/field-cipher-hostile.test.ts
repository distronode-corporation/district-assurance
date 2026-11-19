// Hostile-pass regressions for #78 (FIL-2, encrypted sensitive intake fields): every attack held.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { IntakeRecord } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import type { IntakeForm } from "../src/file/intake.ts";
import { FakeFieldCipher, MemoryRecordStore } from "../src/testing/fakes.ts";
import { TEST_KNOWLEDGE_KEY, testSubject } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

/** A record store with the subject setup() seeds in its own. */
function seeded<T extends MemoryRecordStore>(store: T): T {
  store.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
  return store;
}

const SIN = "046 454 286"; // made up
const secure: IntakeForm = {
  formId: "secure",
  version: "1",
  fields: [
    { key: "issue", label: { en: "Issue", fr: "Issue" }, type: "text", required: true },
    { key: "sin", label: { en: "SIN", fr: "NAS" }, type: "text", required: true, sensitive: true },
  ],
};
const config = () => testConfig((c) => (c.modules.dossier = { settings: { forms: [structuredClone(secure)] } as unknown as JsonValue }));

async function draftOn(t: ReturnType<typeof setup>): Promise<string> {
  const callId = await verifiedCall(t);
  await t.engine.startIntake(callId, "secure");
  await t.engine.setIntakeField(callId, "issue", "Leak");
  await t.engine.setIntakeField(callId, "sin", SIN);
  return callId;
}

/** A record store whose next put stores the record and then fails, as a lost answer would. */
class StoredThenFailed extends MemoryRecordStore {
  failNext = 0;
  override async putIntakeRecord(record: IntakeRecord): Promise<void> {
    await super.putIntakeRecord(record);
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("answer lost");
    }
  }
}

describe("hostile #78: sensitive values", () => {
  it("G1: a filing whose store answer was lost holds endCall until it is confirmed, then it is in the receipt", async () => {
    const records = seeded(new StoredThenFailed());
    const t = setup({ config: config(), adapters: { fieldCipher: new FakeFieldCipher(), records } });
    const callId = await draftOn(t);
    records.failNext = 1;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), /answer lost/);
    await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed", /being filed/));
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    const receipt = (await t.engine.endCall(callId))!;
    assert.deepEqual(receipt.body.records.map((r) => r.recordId), [record.recordId]);
  });

  it("G2: a cipher answering nothing usable is refused, nothing is stored, and the plaintext is in no error", async () => {
    for (const answer of [undefined, null, "", SIN, 42, { toString: () => "x" }, [SIN]]) {
      const records = seeded(new MemoryRecordStore());
      const t = setup({ config: config(), adapters: { fieldCipher: { encrypt: async () => answer as string }, records } });
      const callId = await draftOn(t);
      await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), (e: unknown) => e instanceof Error && !e.message.includes(SIN), String(answer));
      assert.equal(await records.getIntakeRecord("ws_test", "rec_1"), null, String(answer));
    }
  });

  it("G3: the plaintext is in no ledger entry, receipt, stored record or session after filing", async () => {
    const cipher = new FakeFieldCipher();
    const sessions = new MemorySessionStore();
    const t = setup({ config: config(), adapters: { fieldCipher: cipher, sessions } });
    const callId = await draftOn(t);
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad" });
    const receipt = await t.engine.endCall(callId);
    const everything = JSON.stringify([await t.ledger.list(), receipt, await t.records.getIntakeRecord("ws_test", record.recordId), await sessions.get("ws_test", callId), record]);
    for (const piece of [SIN, SIN.replaceAll(" ", ""), "046454286"]) assert.equal(everything.includes(piece), false, piece);
    assert.equal(cipher.decrypt(String(record.values.sin)), SIN, "the host's own key reads it back");
  });

  it("G4: an open draft dropped at endCall leaves no plaintext in the session store", async () => {
    const sessions = new MemorySessionStore();
    const t = setup({ config: config(), adapters: { fieldCipher: new FakeFieldCipher(), sessions } });
    const callId = await draftOn(t);
    await t.engine.endCall(callId);
    assert.equal(JSON.stringify(await sessions.get("ws_test", callId)).includes(SIN), false);
  });

  it("G5: an engine without the cipher on the same stores refuses to file, and the engine with it files the same record", async () => {
    const sessions = new MemorySessionStore();
    const records = seeded(new MemoryRecordStore());
    const cipher = new FakeFieldCipher();
    const a = setup({ config: config(), adapters: { fieldCipher: cipher, sessions, records } });
    const callId = await draftOn(a);
    const bare = setup({ adapters: { sessions, records, ledger: a.ledger } });
    bare.engine.configure(testConfig());
    await assert.rejects(bare.engine.confirmIntake(callId, { confirmedBy: "voice" }), rejects("precondition_failed", /fieldCipher/));
    const record = await a.engine.confirmIntake(callId, { confirmedBy: "voice" });
    assert.equal(cipher.decrypt(String((await records.getIntakeRecord("ws_test", record.recordId))!.values.sin)), SIN);
  });

  it("G6: the context the cipher is given names this workspace, record and field, and cannot change the record", async () => {
    const seen: unknown[] = [];
    const t = setup({
      config: config(),
      adapters: {
        fieldCipher: {
          encrypt: async (plain, context) => {
            seen.push(structuredClone(context));
            (context as { recordId: string }).recordId = "rec_other";
            return `sealed:${plain.length}`;
          },
        },
      },
    });
    const callId = await draftOn(t);
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    assert.deepEqual(seen, [{ workspaceId: "ws_test", recordId: record.recordId, field: "sin" }]);
    assert.notEqual(record.recordId, "rec_other");
  });
});
