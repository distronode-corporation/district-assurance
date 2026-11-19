// Hostile pass on #105 (PRV-7 subject access and deletion), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { IntakeRecord } from "../src/core/adapters.ts";
import { verifyReceipt, type SignedReceipt } from "../src/prove/receipt.ts";
import { verifySubjectExport, type SignedSubjectExport } from "../src/prove/subject.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, type TestEngine } from "../src/testing/index.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { ACCOUNT, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const request = { workspaceId: "ws_test", subjectKey: SUBJECT };

async function filedCall(t: TestEngine, issue = "leak under the sink"): Promise<{ callId: string; record: IntakeRecord; receipt: SignedReceipt }> {
  const callId = await verifiedCall(t);
  await t.engine.startIntake(callId, "repair");
  await t.engine.setIntakeField(callId, "issue", issue);
  const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
  await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
  const receipt = (await t.engine.endCall(callId))!;
  return { callId, record, receipt };
}

async function events(t: TestEngine, name: string): Promise<number> {
  return (await t.ledger.list()).filter((e) => e.event === name).length;
}

describe("#105 hostile: what a subject request takes", () => {
  it("S1 a subject key that is not a string (an array of the key, a toString object) or a request that is not an object is invalid_input, nothing read or written", async () => {
    const t = setup();
    await filedCall(t);
    const before = (await t.ledger.list()).length;
    const pinBefore = (await t.records.getSubject("ws_test", SUBJECT))!.pinDigest;
    const reads: unknown[] = [];
    const get = t.records.getSubject.bind(t.records);
    t.records.getSubject = async (ws, key) => (reads.push(key), get(ws, key));
    for (const subjectKey of [[SUBJECT], { toString: () => SUBJECT }, new String(SUBJECT)]) {
      await assert.rejects(t.engine.exportSubject({ workspaceId: "ws_test", subjectKey } as never), rejects("invalid_input"), "export");
      await assert.rejects(t.engine.eraseSubject({ workspaceId: "ws_test", subjectKey } as never), rejects("invalid_input"), "erase");
    }
    for (const input of [null, undefined, 7, "ws_test"]) {
      await assert.rejects(t.engine.exportSubject(input as never), rejects("invalid_input"), `export ${String(input)}`);
      await assert.rejects(t.engine.eraseSubject(input as never), rejects("invalid_input"), `erase ${String(input)}`);
    }
    assert.deepEqual(reads, []);
    assert.equal((await t.ledger.list()).length, before);
    assert.equal((await t.records.getSubject("ws_test", SUBJECT))!.pinDigest, pinBefore, "the PIN digest stays");
  });
});

describe("#105 hostile: store faults during an erase", () => {
  it("S2 a delete that fails once is carried out by the retry, with one subject.erased and one completion", async () => {
    const t = setup();
    const { record } = await filedCall(t);
    const del = t.records.deleteIntakeRecords.bind(t.records);
    let fail = true;
    t.records.deleteIntakeRecords = async (ws, ids) => {
      if (fail) {
        fail = false;
        throw new Error("store down");
      }
      return del(ws, ids);
    };
    await assert.rejects(t.engine.eraseSubject(request), /store down/);
    assert.notEqual(await t.records.getIntakeRecord("ws_test", record.recordId), null, "nothing deleted yet");
    const result = await t.engine.eraseSubject(request);
    assert.deepEqual([result.erased, result.recordIds, result.pinDigest], [true, [record.recordId], true]);
    assert.equal(await t.records.getIntakeRecord("ws_test", record.recordId), null);
    assert.equal((await t.records.getSubject("ws_test", SUBJECT))!.pinDigest, undefined);
    assert.deepEqual([await events(t, "subject.erased"), await events(t, "subject.erasure_completed")], [1, 1]);
    assert.equal((await t.engine.eraseSubject(request)).erased, false, "then nothing is left");
    assert.deepEqual([await events(t, "subject.erased"), await events(t, "subject.erasure_completed")], [1, 1]);
  });

  it("S3 a completion append that is lost after it was written is not written twice", async () => {
    const t = setup();
    await filedCall(t);
    const append = t.ledger.append.bind(t.ledger);
    let lose = true;
    t.ledger.append = async (input) => {
      const entry = await append(input);
      if (lose && input.event === "subject.erasure_completed") {
        lose = false;
        throw new Error("answer lost");
      }
      return entry;
    };
    await assert.rejects(t.engine.eraseSubject(request), /answer lost/);
    assert.equal((await t.engine.eraseSubject(request)).erased, false);
    assert.deepEqual([await events(t, "subject.erased"), await events(t, "subject.erasure_completed")], [1, 1]);
  });

  it("S4 two erasures at once append one plan and one completion", async () => {
    const t = setup();
    const { record } = await filedCall(t);
    const [a, b] = await Promise.all([t.engine.eraseSubject(request), t.engine.eraseSubject(request)]);
    assert.deepEqual([a.recordIds, b.recordIds], [[record.recordId], [record.recordId]]);
    assert.deepEqual([await events(t, "subject.erased"), await events(t, "subject.erasure_completed")], [1, 1]);
  });

  it("S5 an erase while another call files a record of the subject erases what is on file; the late record waits for the next erase", async () => {
    const t = setup();
    await filedCall(t);
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "door stuck");
    const put = t.records.putIntakeRecord.bind(t.records);
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let entered!: () => void;
    const inPut = new Promise<void>((r) => (entered = r));
    t.records.putIntakeRecord = async (r) => {
      entered();
      await held;
      return put(r);
    };
    const confirming = t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    await inPut;
    const before = (await t.ledger.list()).length;
    // The new record is not listed yet, so only the first call's copy is forgotten; the erase goes
    // ahead with what is on file. Then the late filing lands under the subject for a later erase.
    const result = await t.engine.eraseSubject(request);
    assert.equal(result.erased, true);
    release();
    const late = await confirming;
    assert.notEqual(await t.records.getIntakeRecord("ws_test", late.recordId), null, "a record filed after the plan is kept for the next erase");
    const again = await t.engine.eraseSubject(request);
    assert.deepEqual(again.recordIds, [late.recordId]);
    assert.ok((await t.ledger.list()).length > before);
  });
});

describe("#105 hostile: two workspaces", () => {
  it("S6 an erase in one workspace never touches another's records or PIN on a shared record store and ledger", async () => {
    const t = setup();
    await filedCall(t);
    const other = createTestEngine({ config: testConfig(), workspaceId: "ws_other", adapters: { ledger: t.ledger, records: t.records } });
    t.records.putSubject("ws_other", (await t.records.getSubject("ws_test", SUBJECT))!);
    const { record: theirs } = await filedCall(other);
    await t.engine.eraseSubject(request);
    assert.notEqual(await t.records.getIntakeRecord("ws_other", theirs.recordId), null);
    assert.notEqual((await t.records.getSubject("ws_other", SUBJECT))!.pinDigest, undefined);
    const exported = await other.engine.exportSubject({ workspaceId: "ws_other", subjectKey: SUBJECT });
    assert.deepEqual(exported.body.intakeRecords.map((r) => r.recordId), [theirs.recordId]);
    assert.equal((await other.engine.eraseSubject({ workspaceId: "ws_other", subjectKey: SUBJECT })).erased, true, "their own first erasure, not taken as done");
    await assert.rejects(other.engine.eraseSubject(request), rejects("invalid_input"), "another workspace's request");
  });
});

describe("#105 hostile: what is signed and what is ledgered", () => {
  it("S7 an export never verifies as a receipt and a receipt never as an export; bad shapes are false, never a throw", async () => {
    const t = setup();
    const { receipt } = await filedCall(t);
    const exported = await t.engine.exportSubject(request);
    const keys = t.engine.receiptKeys();
    assert.equal(verifySubjectExport(exported, keys), true);
    assert.equal(verifyReceipt({ ...exported } as unknown as SignedReceipt, keys), false);
    assert.equal(verifySubjectExport({ ...receipt } as unknown as SignedSubjectExport, keys), false);
    assert.equal(verifySubjectExport({ ...exported, body: receipt.body } as unknown as SignedSubjectExport, keys), false);
    for (const bad of [null, undefined, 7, {}, { ...exported, signature: 5 }, { ...exported, kid: { toString: () => exported.kid } }]) {
      assert.equal(verifySubjectExport(bad as never, keys), false);
    }
    assert.equal(verifySubjectExport(exported, null as never), false);
  });

  it("S8 after an erase, nothing in the ledger carries the subject key, the values or the PIN digest", async () => {
    const t = setup();
    const pinDigest = (await t.records.getSubject("ws_test", SUBJECT))!.pinDigest!;
    await filedCall(t, "leak under the sink at 12 Rue Example");
    await t.engine.eraseSubject(request);
    const text = JSON.stringify(await t.ledger.list());
    for (const secret of [SUBJECT, pinDigest, "Rue Example", ACCOUNT]) assert.equal(text.includes(secret), false, secret.slice(0, 8));
  });
});
