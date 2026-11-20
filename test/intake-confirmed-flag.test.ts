// The RecordStore's confirmed flag (L3 #131, decided 2026-11-20): a stored intake record counts as
// filed only once the confirmation that filed it committed. `deliverRecord`, `exportSubject` and
// upload links skip a row without the flag (one a refusal left behind when its delete failed), and
// an erasure still deletes it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { DocumentScanner, IntakeRecord } from "../src/core/adapters.ts";
import { deliverRecord } from "../src/file/delivery.ts";
import { MemoryDocumentStore, createUploadLink } from "../src/file/upload.ts";
import { FakeRecordDelivery, MemoryRecordStore, TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, heard, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const destination = { destinationId: "crm", url: "https://hooks.example.test/records", secret: "whsec_flag_test_not_a_secret" };

async function confirmed(t: TestEngine): Promise<{ callId: string; record: IntakeRecord }> {
  const callId = await verifiedCall(t);
  await t.engine.startIntake(callId, "repair");
  await t.engine.setIntakeField(callId, "issue", "Leaking tap");
  const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
  return { callId, record };
}

const deliver = (t: TestEngine, recordId: string, delivery = new FakeRecordDelivery()) =>
  deliverRecord({ workspaceId: "ws_test", recordId, destination, records: t.records, delivery, ledger: t.ledger, clock: t.clock, sleep: async () => undefined });

describe("intake records: the confirmed flag", () => {
  it("marks the stored record confirmed when the confirmation commits", async () => {
    const t = setup();
    const { record } = await confirmed(t);
    assert.equal(await t.records.isIntakeRecordConfirmed("ws_test", record.recordId), true);
  });

  it("skips a stored row no confirmation committed: no delivery, no export, no upload link; an erasure still deletes it", async () => {
    const t = setup();
    const { callId, record } = await confirmed(t);
    // What a refusal after the write leaves when its delete fails: the row, never marked.
    const left: IntakeRecord = { ...record, recordId: "rec_left", values: { issue: "never confirmed" } };
    await t.records.putIntakeRecord(left);
    assert.equal(await t.records.isIntakeRecordConfirmed("ws_test", "rec_left"), false);

    const fake = new FakeRecordDelivery();
    await assert.rejects(deliver(t, "rec_left", fake), rejects("invalid_input", /no confirmed record rec_left/));
    assert.deepEqual(fake.posts, []);
    assert.equal((await deliver(t, record.recordId)).delivered, true);

    const exported = await t.engine.exportSubject({ workspaceId: "ws_test", subjectKey: SUBJECT });
    assert.deepEqual(exported.body.intakeRecords.map((r) => r.recordId), [record.recordId]);
    assert.equal(JSON.stringify(exported).includes("never confirmed"), false);

    const context = { workspaceId: "ws_test", documents: new MemoryDocumentStore(), clock: t.clock, records: t.records, ids: t.ids, scanner: {} as DocumentScanner };
    await assert.rejects(createUploadLink({ callId, recordId: "rec_left", allowedTypes: ["application/pdf"], maxBytes: 100 }, context), rejects("precondition_failed", /not a confirmed record/));

    const erased = await t.engine.eraseSubject({ workspaceId: "ws_test", subjectKey: SUBJECT });
    assert.deepEqual([...erased.recordIds].sort(), [record.recordId, "rec_left"].sort());
    assert.equal(await t.records.getIntakeRecord("ws_test", "rec_left"), null);
  });

  it("keeps the mark owed on the call when the commit's ledger append fails, and removeCall makes it before the record goes", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "Leaking tap");
    const readBack = await heard(t, callId);
    // The filing write commits, then its ledger append fails: confirmIntake throws before the mark.
    const append = t.ledger.append.bind(t.ledger);
    let down = true;
    t.ledger.append = async (input) => {
      if (down && input.event === "intake.confirmed") throw new Error("ledger down");
      return append(input);
    };
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), /ledger down/);
    const [stored] = await t.records.listIntakeRecords("ws_test", SUBJECT);
    assert.equal(await t.records.isIntakeRecordConfirmed("ws_test", stored!.recordId), false);
    down = false;
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
    assert.equal(await t.records.isIntakeRecordConfirmed("ws_test", stored!.recordId), true, "marked before the call record went");
  });

  it("answers a confirmation retried on a call an older build filed, which names no owed mark", async () => {
    const t = setup();
    const { callId, record } = await confirmed(t);
    const stored = (await t.sessions.get("ws_test", callId))!;
    const old = structuredClone(stored.record) as { modules: { dossier: { marksOwed?: string[] } } };
    delete old.modules.dossier.marksOwed;
    assert.deepEqual(await t.sessions.compareAndSet("ws_test", callId, stored.version, old as never), { ok: true, version: stored.version + 1 });
    assert.deepEqual(await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: "ignored on a retry" }), record);
  });

  it("removes a call on an engine with Dossier off", async () => {
    const t = setup({ config: testConfig((c) => (c.modules.dossier = { enabled: false })) });
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
  });

  it("keeps the call record while an owed mark cannot be made", async () => {
    class Down extends MemoryRecordStore {
      down = false;
      override async confirmIntakeRecord(workspaceId: string, recordId: string): Promise<void> {
        if (this.down) throw new Error("store down");
        return super.confirmIntakeRecord(workspaceId, recordId);
      }
    }
    const records = new Down();
    const t = setup({ adapters: { records } });
    records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "Leaking tap");
    records.down = true;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), /store down/);
    await t.engine.endCall(callId);
    await assert.rejects(t.engine.removeCall(callId), rejects("precondition_failed", /confirmed record is not yet marked/));
    assert.notEqual(await t.sessions.get("ws_test", callId), null);
    records.down = false;
    assert.deepEqual(await t.engine.removeCall(callId), { removed: true });
  });

  it("keeps a filing whose mark failed unconfirmed, and a confirmation asked again marks it and gives the same record", async () => {
    class FailingMark extends MemoryRecordStore {
      fail = true;
      override async confirmIntakeRecord(workspaceId: string, recordId: string): Promise<void> {
        if (this.fail) throw new Error("store down");
        return super.confirmIntakeRecord(workspaceId, recordId);
      }
    }
    const records = new FailingMark();
    const t = setup({ adapters: { records } });
    records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "Leaking tap");
    const readBack = await heard(t, callId);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), /store down/);
    const [stored] = await records.listIntakeRecords("ws_test", SUBJECT);
    assert.equal(await records.isIntakeRecordConfirmed("ws_test", stored!.recordId), false);
    await assert.rejects(deliver({ ...t, records }, stored!.recordId), rejects("invalid_input"));
    records.fail = false;
    const again = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack });
    assert.deepEqual(again, stored);
    assert.equal(await records.isIntakeRecordConfirmed("ws_test", stored!.recordId), true);
  });
});
