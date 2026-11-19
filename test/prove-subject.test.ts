import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { IntakeRecord } from "../src/core/adapters.ts";
import type { CallRecord } from "../src/core/runtime.ts";
import type { DossierSlice } from "../src/file/dossier.ts";
import { defaultConfig } from "../src/modules.ts";
import { verifyChain } from "../src/prove/ledger.ts";
import { receiptPayload, verifyReceipt, type SignedReceipt } from "../src/prove/receipt.ts";
import { SUBJECT_EXPORT_DOMAIN, subjectExportPayload, verifySubjectExport, type SignedSubjectExport } from "../src/prove/subject.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, type TestEngine } from "../src/testing/index.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { MemoryRecordStore, testSubject } from "../src/testing/fakes.ts";
import { ACCOUNT, DOB, PIN, rejects, setup, testConfig, verifiedCall, wording } from "./helpers.ts";

const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const request = { workspaceId: "ws_test", subjectKey: SUBJECT };

/** A verified call that files a repair record, consents to texts and ends with a receipt. */
async function filedCall(t: TestEngine, issue = "leak under the sink"): Promise<{ callId: string; record: IntakeRecord; receipt: SignedReceipt }> {
  const callId = await verifiedCall(t);
  await t.engine.startIntake(callId, "repair");
  await t.engine.setIntakeField(callId, "issue", issue);
  const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
  await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
  const receipt = (await t.engine.endCall(callId))!;
  return { callId, record, receipt };
}

async function callRecord(t: TestEngine, callId: string): Promise<CallRecord> {
  return (await t.sessions.get("ws_test", callId))!.record as unknown as CallRecord;
}

describe("intake records carry the matched subject", () => {
  it("files under the subject a keypad match found", async () => {
    const t = setup();
    const { record } = await filedCall(t);
    assert.equal(record.subjectKey, SUBJECT);
    assert.equal((await t.records.getIntakeRecord("ws_test", record.recordId))!.subjectKey, SUBJECT);
  });

  it("files under no subject when none was matched, and such a record is never listed", async () => {
    // Badge off and intake open to anyone: a record filed with no subject matched.
    const t = setup({
      config: testConfig((c) => {
        c.modules.badge = { enabled: false };
        c.policy.scopes["intake.file"] = 0;
      }),
    });
    const { callId } = await t.engine.startCall();
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad" });
    assert.equal(record.subjectKey, null);
    assert.deepEqual(await t.records.listIntakeRecords("ws_test", SUBJECT), []);
    const exported = await t.engine.exportSubject(request);
    assert.deepEqual(exported.body.intakeRecords, []);
    assert.ok(exported.body.limits.some((l) => /no matched subject/.test(l) && /cannot find it/.test(l)), "the export says so");
  });
});

describe("exportSubject", () => {
  it("returns everything stored about the subject, signed as an export", async () => {
    const t = setup();
    const { callId, record, receipt } = await filedCall(t);
    // A second workspace on the same ledger, with the same sequential ids, and an entry with no event id.
    const other = createTestEngine({ config: testConfig(), workspaceId: "ws_other", adapters: { ledger: t.ledger } });
    other.records.putSubject("ws_other", (await t.records.getSubject("ws_test", SUBJECT))!);
    await filedCall(other);
    await t.ledger.append({ callId: null, actor: "system", event: "module.event", at: "2026-01-01T00:00:00.000Z", detail: { recordId: record.recordId } });

    const exported = await t.engine.exportSubject({ ...request, kept: [{ what: "repair records", reason: "Kept six years for the warranty, by law." }] });
    const body = exported.body;
    assert.deepEqual([body.v, body.type, body.workspaceId, body.subjectKey, body.issuedAt], [1, "subject_export", "ws_test", SUBJECT, "2026-01-01T00:00:00.000Z"]);
    assert.deepEqual(body.intakeRecords, [record]);
    assert.equal(body.intakeRecords[0]!.values.issue, "leak under the sink", "values included");
    assert.equal(body.pinDigestOnFile, true);
    const subject = (await t.records.getSubject("ws_test", SUBJECT))!;
    assert.equal(JSON.stringify(exported).includes(subject.pinDigest!), false, "never the digest");
    assert.deepEqual(body.consents.map((c) => [c.callId, c.purpose, c.answer]), [[callId, "texts", "yes"]]);
    assert.deepEqual(body.calls, [callId]);
    assert.deepEqual(body.receipts, [{ receiptId: receipt.body.receiptId, callId }]);
    assert.deepEqual(body.ledgerEntries.map((e) => [e.event, e.callId]), [
      ["intake.confirmed", callId],
      ["consent.recorded", callId],
      ["receipt.issued", callId],
    ], "this workspace's entries only");
    const all = await t.ledger.list();
    for (const e of body.ledgerEntries) assert.equal(all.find((a) => a.seq === e.seq)!.hash, e.hash);
    assert.deepEqual(body.heldByHost.map((h) => h.what), ["subject record", "PIN in the host's PIN store"]);
    assert.deepEqual(body.kept.map((k) => k.what), ["ledger entries", "receipts", "call records", "consents", "repair records"]);
    assert.match(body.kept[0]!.reason, /append-only/);
    assert.match(body.kept[0]!.reason, /unkeyed SHA-256 of a short value can be confirmed/);
    assert.equal(body.kept[4]!.reason, "Kept six years for the warranty, by law.");

    assert.equal(verifySubjectExport(exported, t.engine.receiptKeys()), true);
    const changed: SignedSubjectExport = structuredClone(exported);
    changed.body.pinDigestOnFile = false;
    assert.equal(verifySubjectExport(changed, t.engine.receiptKeys()), false);
  });

  it("can never verify as a receipt, nor a receipt as an export", async () => {
    const t = setup();
    const { receipt } = await filedCall(t);
    const exported = await t.engine.exportSubject(request);
    assert.equal(new TextDecoder().decode(subjectExportPayload(exported.body)).startsWith(`${SUBJECT_EXPORT_DOMAIN}\n{`), true, "the signed bytes name the type");
    assert.equal(verifyReceipt(exported as unknown as SignedReceipt, t.engine.receiptKeys()), false);
    assert.equal(verifySubjectExport(receipt as unknown as SignedSubjectExport, t.engine.receiptKeys()), false);
    assert.notDeepEqual(subjectExportPayload(receipt.body as never), receiptPayload(receipt.body));
  });

  it("fails verification on a wrong algorithm, an unknown key or a malformed signature", async () => {
    const t = setup();
    const exported = await t.engine.exportSubject(request);
    const keys = t.engine.receiptKeys();
    assert.equal(verifySubjectExport({ ...exported, alg: "RS256" as "ES256" }, keys), false);
    assert.equal(verifySubjectExport({ ...exported, kid: "nope" }, keys), false);
    assert.equal(verifySubjectExport({ ...exported, signature: "AAAA" }, keys), false);
    assert.equal(verifySubjectExport(exported, [{ kid: exported.kid, kty: "nope" }]), false);
    for (const bad of [null, undefined, "x", 1]) assert.equal(verifySubjectExport(bad as never, keys), false, String(bad));
    assert.equal(verifySubjectExport(exported, null as never), false);
  });

  it("lists only the consents recorded under the subject, not one recorded after the call matched another", async () => {
    const t = setup();
    const other = "87654321";
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: other, phoneOnFile: "+15555550199", knowledge: { dob: DOB } }));
    const callId = await verifiedCall(t);
    await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    // The same call, no flow: another subject is verified and consents.
    await t.engine.beginVerification(callId, { accountNumber: other });
    await t.engine.submitKeypad(callId, { dob: DOB });
    const theirs = await t.engine.recordConsent(callId, { purpose: "texts", answer: "no" });
    assert.equal(theirs.subjectKey, subjectKeyFor(TEST_KNOWLEDGE_KEY, other));

    const body = (await t.engine.exportSubject(request)).body;
    assert.deepEqual(body.calls, [callId]);
    assert.deepEqual(body.consents.map((c) => [c.subjectKey, c.answer]), [[SUBJECT, "yes"]]);
    assert.equal(JSON.stringify(body).includes(theirs.consentId), false, "nothing of theirs");
    assert.ok(body.limits.some((l) => /under another subject/.test(l)));
  });

  it("answers with nothing for a subject with nothing on file, and skips a call record that is gone", async () => {
    const t = setup();
    const empty = (await t.engine.exportSubject({ ...request, subjectKey: "a".repeat(64) })).body;
    assert.deepEqual([empty.intakeRecords, empty.pinDigestOnFile, empty.calls, empty.ledgerEntries, empty.receipts], [[], false, [], [], []]);

    const { callId } = await filedCall(t);
    const get = t.sessions.get.bind(t.sessions);
    t.sessions.get = async (w, id) => (id === callId ? null : get(w, id));
    const body = (await t.engine.exportSubject(request)).body;
    assert.deepEqual([body.intakeRecords.length, body.calls, body.consents, body.receipts], [1, [callId], [], []]);
  });

  it("refuses another workspace, a malformed subject key, a bad kept list and a missing adapter", async () => {
    const t = setup();
    await assert.rejects(t.engine.exportSubject({ ...request, workspaceId: "ws_other" }), rejects("invalid_input", /another workspace/));
    await assert.rejects(t.engine.exportSubject({ ...request, subjectKey: "A".repeat(64) }), rejects("invalid_input", /64 lower-case hex/));
    for (const kept of ["x", ["x"], [{ what: 1, reason: "r" }], [{ what: " ", reason: "r" }], [{ what: "w" }], [{ what: "w", reason: "" }], [{ what: "w", reason: "r", extra: 1 }]]) {
      await assert.rejects(t.engine.exportSubject({ ...request, kept: kept as never }), rejects("invalid_input", /kept must be/), JSON.stringify(kept));
    }
    const unsigned = setup({ config: testConfig((c) => (c.modules.trace = { settings: { receipts: false, wordings: [structuredClone(wording)] } })), adapters: { signer: undefined } });
    await assert.rejects(unsigned.engine.exportSubject(request), rejects("precondition_failed", /no signer/));
    const bare = createTestEngine({ config: { ...defaultConfig(), modules: { trace: { settings: { receipts: false } } } }, adapters: { records: undefined } });
    await assert.rejects(bare.engine.exportSubject(request), rejects("precondition_failed", /records adapter/));
    await assert.rejects(bare.engine.eraseSubject(request), rejects("precondition_failed", /records adapter/));
  });
});

describe("eraseSubject", () => {
  it("deletes the records and the PIN digest, and the chain and every receipt still verify", async () => {
    const t = setup();
    const first = await filedCall(t);
    const second = await filedCall(t, "broken window");
    const before = await t.ledger.list();

    const result = await t.engine.eraseSubject(request);
    assert.deepEqual([result.erased, result.recordIds, result.pinDigest], [true, [first.record.recordId, second.record.recordId], true]);
    const entry = result.entry!;
    assert.deepEqual([entry.event, entry.actor, entry.callId, entry.detail], ["subject.erased", "member", null, { recordIds: ["rec_1", "rec_2"], pinDigest: true }]);
    assert.equal(JSON.stringify(entry).includes(SUBJECT), false, "the entry names no subject");

    assert.equal(await t.records.getIntakeRecord("ws_test", first.record.recordId), null);
    assert.equal(await t.records.getIntakeRecord("ws_test", second.record.recordId), null);
    const subject = (await t.records.getSubject("ws_test", SUBJECT))!;
    assert.equal(subject.pinDigest, undefined);
    assert.equal(subject.phoneOnFile, "+15555550100", "the rest of the subject record is the host's");
    for (const { callId, record } of [first, second]) {
      const slice = (await callRecord(t, callId)).modules.dossier as unknown as DossierSlice;
      assert.equal(slice.confirmed, null, "the call's copy of the values is gone");
      assert.deepEqual(slice.records, [{ recordId: record.recordId, formId: "repair", digest: record.digest }], "the digest stays");
    }

    const after = await t.ledger.list();
    assert.deepEqual(after.slice(0, before.length), before, "no entry changed or removed");
    assert.equal(verifyChain(after).ok, true);
    for (const { callId, receipt } of [first, second]) {
      assert.deepEqual(await t.engine.receipt(callId), receipt);
      assert.equal(verifyReceipt(receipt, t.engine.receiptKeys()), true);
    }

    const exported = (await t.engine.exportSubject(request)).body;
    assert.deepEqual([exported.intakeRecords, exported.pinDigestOnFile], [[], false]);
  });

  it("does nothing the second time", async () => {
    const t = setup();
    const { callId } = await filedCall(t);
    await t.engine.eraseSubject(request);
    const entries = (await t.ledger.list()).length;
    const version = (await t.sessions.get("ws_test", callId))!.version;
    assert.deepEqual(await t.engine.eraseSubject(request), { erased: false, recordIds: [], pinDigest: false, entry: null });
    assert.equal((await t.ledger.list()).length, entries);
    assert.equal((await t.sessions.get("ws_test", callId))!.version, version);
  });

  it("finishes after a failed delete without a second entry", async () => {
    const t = setup();
    await filedCall(t);
    const remove = t.records.deleteIntakeRecords.bind(t.records);
    t.records.deleteIntakeRecords = async () => {
      throw new Error("database down");
    };
    await assert.rejects(t.engine.eraseSubject(request), /database down/);
    t.records.deleteIntakeRecords = remove;
    const entries = (await t.ledger.list()).length;
    const retried = await t.engine.eraseSubject(request);
    assert.equal(retried.entry!.seq, entries, "the same entry");
    assert.deepEqual((await t.ledger.list()).slice(entries).map((e) => e.event), ["subject.erasure_completed"], "only the completion is appended");
    assert.deepEqual(await t.records.listIntakeRecords("ws_test", SUBJECT), []);
    assert.equal((await t.engine.eraseSubject(request)).erased, false);
  });

  it("finishes the same erasure after the records went and the PIN digest delete failed", async () => {
    const t = setup();
    const { record } = await filedCall(t);
    const removePin = t.records.deletePinDigest.bind(t.records);
    t.records.deletePinDigest = async () => {
      throw new Error("database down");
    };
    await assert.rejects(t.engine.eraseSubject(request), /database down/);
    assert.equal(await t.records.getIntakeRecord("ws_test", record.recordId), null, "the records went");
    t.records.deletePinDigest = removePin;
    const first = (await t.ledger.list()).find((e) => e.event === "subject.erased")!;
    const retried = await t.engine.eraseSubject(request);
    assert.deepEqual([retried.entry, retried.recordIds, retried.pinDigest], [first, [record.recordId], true], "the original entry and plan");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "subject.erased").length, 1);
    assert.equal((await t.records.getSubject("ws_test", SUBJECT))!.pinDigest, undefined);
  });

  it("finishes an unfinished erasure, then erases what was filed since, in one call", async () => {
    const t = setup();
    const subject = (await t.records.getSubject("ws_test", SUBJECT))!;
    const first = await filedCall(t);
    await t.records.deletePinDigest("ws_test", SUBJECT);
    const remove = t.records.deleteIntakeRecords.bind(t.records);
    t.records.deleteIntakeRecords = async () => {
      throw new Error("database down");
    };
    await assert.rejects(t.engine.eraseSubject(request), /database down/);
    t.records.deleteIntakeRecords = remove;
    // Since then: the host put the PIN back, and another record was filed.
    t.records.putSubject("ws_test", subject);
    const second = await filedCall(t, "broken window");
    const result = await t.engine.eraseSubject(request);
    assert.deepEqual([result.recordIds, result.pinDigest], [[first.record.recordId, second.record.recordId], true]);
    assert.deepEqual(result.entry!.detail, { recordIds: [second.record.recordId], pinDigest: true });
    const plans = (await t.ledger.list()).filter((e) => e.event === "subject.erased");
    assert.deepEqual(plans[0]!.detail, { recordIds: [first.record.recordId], pinDigest: false });
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event.startsWith("subject.")).map((e) => e.event), [
      "subject.erased",
      "subject.erasure_completed",
      "subject.erased",
      "subject.erasure_completed",
    ]);
    assert.deepEqual(await t.records.listIntakeRecords("ws_test", SUBJECT), []);
  });

  it("gives a later erasure of a PIN the host put back an entry of its own", async () => {
    const t = setup();
    const subject = (await t.records.getSubject("ws_test", SUBJECT))!;
    const first = await t.engine.eraseSubject(request);
    t.records.putSubject("ws_test", subject);
    const second = await t.engine.eraseSubject(request);
    assert.deepEqual([second.erased, second.recordIds, second.pinDigest], [true, [], true]);
    assert.notEqual(second.entry!.seq, first.entry!.seq, "a new entry");
    assert.notEqual(second.entry!.eventId, first.entry!.eventId);
    assert.equal((await t.ledger.list()).filter((e) => e.event === "subject.erased").length, 2);
    assert.equal(verifyChain(await t.ledger.list()).ok, true);
  });

  it("is not undone by a confirmation of the same record still writing when it ran", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    // Two confirmations of one reservation: the first's write is held until after the erase.
    const put = t.records.putIntakeRecord.bind(t.records);
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => (release = resolve));
    let writes = 0;
    t.records.putIntakeRecord = async (record) => {
      writes++;
      if (writes === 1) await held;
      await put(record);
    };
    const slow = t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    while (writes === 0) await new Promise((resolve) => setImmediate(resolve));
    const fast = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    assert.equal(writes, 2);
    assert.deepEqual((await t.engine.eraseSubject(request)).recordIds, [fast.recordId]);
    release();
    assert.deepEqual(await slow, fast);
    assert.equal(await t.records.getIntakeRecord("ws_test", fast.recordId), null, "the late write stored nothing");
    assert.deepEqual(await t.records.listIntakeRecords("ws_test", SUBJECT), []);
  });

  it("erases a PIN digest alone, and a record whose call record is gone", async () => {
    const t = setup();
    const pinOnly = await t.engine.eraseSubject(request);
    assert.deepEqual([pinOnly.erased, pinOnly.recordIds, pinOnly.pinDigest], [true, [], true]);

    const { callId } = await filedCall(t);
    const get = t.sessions.get.bind(t.sessions);
    t.sessions.get = async (w, id) => (id === callId ? null : get(w, id));
    const result = await t.engine.eraseSubject(request);
    assert.deepEqual([result.erased, result.recordIds, result.pinDigest], [true, ["rec_1"], false]);
    assert.equal(await t.records.getIntakeRecord("ws_test", "rec_1"), null);
  });

  it("leaves an open draft alone, and is refused while a record of the subject is being filed", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "drip");
    assert.equal((await t.engine.eraseSubject(request)).erased, true);
    assert.equal(((await callRecord(t, callId)).modules.dossier as unknown as DossierSlice).intake!.values.issue, "drip", "a draft is not a record");

    // Stored, then the store answers with an error: the record is filed and its filing still reserved.
    const put = t.records.putIntakeRecord.bind(t.records);
    t.records.putIntakeRecord = async (record) => {
      await put(record);
      throw new Error("timeout");
    };
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), /timeout/);
    const entries = (await t.ledger.list()).length;
    await assert.rejects(t.engine.eraseSubject(request), rejects("precondition_failed", /being filed/));
    assert.equal((await t.ledger.list()).length, entries, "nothing appended");
    t.records.putIntakeRecord = put;
    await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    assert.deepEqual((await t.engine.eraseSubject(request)).recordIds, ["rec_2"]);
  });

  it("an erased PIN no longer verifies on a call already verifying, and no call record keeps a copy of it", async () => {
    const t = setup();
    const digest = (await t.records.getSubject("ws_test", SUBJECT))!.pinDigest!;
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: SUBJECT });
    assert.equal(JSON.stringify(await callRecord(t, callId)).includes(digest), false, "the call record holds no PIN digest");
    await t.engine.eraseSubject(request);
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: false }, "the erased PIN does not pass");
  });

  it("deleting a PIN digest of an unknown subject does nothing", async () => {
    const t = setup();
    await t.records.deletePinDigest("ws_test", "b".repeat(64));
    assert.equal(await t.records.getSubject("ws_test", "b".repeat(64)), null);
  });
});

describe("MemoryRecordStore keys", () => {
  it("keeps workspaces apart when an id holds a slash: deleting north's desk/r1 leaves north/desk's r1", async () => {
    const store = new MemoryRecordStore();
    const record = (workspaceId: string, recordId: string): IntakeRecord => ({
      workspaceId, recordId, callId: "c1", subjectKey: "s1", formId: "f", formVersion: "1", values: {}, digest: "d", confirmedBy: "keypad", confirmedAt: "2026-01-01T00:00:00.000Z",
    });
    await store.putIntakeRecord(record("north/desk", "r1"));
    await store.deleteIntakeRecords("north", ["desk/r1"]);
    assert.notEqual(await store.getIntakeRecord("north/desk", "r1"), null);
    await store.putIntakeRecord(record("north/desk", "r1"));
    assert.equal((await store.listIntakeRecords("north/desk", "s1")).length, 1, "and no tombstone for it either");
    const subject = testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: "+15550100", knowledge: { dob: DOB } });
    store.putSubject("north/desk", subject);
    assert.equal(await store.getSubject("north", `desk/${subject.subjectKey}`), null);
  });
});
