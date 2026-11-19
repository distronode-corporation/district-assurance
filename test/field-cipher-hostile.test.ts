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

/** The digest of the read-back the caller heard, or any digest once no draft is open (a filed or released intake asks for none). */
async function readBackOf(t: { engine: { intakeReadBack(callId: string): Promise<{ digest: string }> } }, callId: string): Promise<string> {
  return t.engine.intakeReadBack(callId).then((r) => r.digest, () => "0".repeat(64));
}

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
    { key: "policy", label: { en: "Policy number", fr: "Numéro de police" }, type: "text", required: true, sensitive: true },
  ],
};
const config = () => testConfig((c) => (c.modules.dossier = { settings: { forms: [structuredClone(secure)] } as unknown as JsonValue }));

async function draftOn(t: ReturnType<typeof setup>): Promise<string> {
  const callId = await verifiedCall(t);
  await t.engine.startIntake(callId, "secure");
  await t.engine.setIntakeField(callId, "issue", "Leak");
  await t.engine.setIntakeField(callId, "policy", SIN);
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
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), /answer lost/);
    await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed", /being filed/));
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) });
    const receipt = (await t.engine.endCall(callId))!;
    assert.deepEqual(receipt.body.records.map((r) => r.recordId), [record.recordId]);
  });

  it("G2: a cipher answering nothing usable is refused, nothing is stored, and the plaintext is in no error", async () => {
    for (const answer of [undefined, null, "", SIN, 42, { toString: () => "x" }, [SIN]]) {
      const records = seeded(new MemoryRecordStore());
      const t = setup({ config: config(), adapters: { fieldCipher: { encrypt: async () => answer as string }, records } });
      const callId = await draftOn(t);
      await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), (e: unknown) => e instanceof Error && !e.message.includes(SIN), String(answer));
      assert.equal(await records.getIntakeRecord("ws_test", "rec_1"), null, String(answer));
    }
  });

  it("G3: the plaintext is in no ledger entry, receipt, stored record or session after filing", async () => {
    const cipher = new FakeFieldCipher();
    const sessions = new MemorySessionStore();
    const t = setup({ config: config(), adapters: { fieldCipher: cipher, sessions } });
    const callId = await draftOn(t);
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad", readBack: await readBackOf(t, callId) });
    const receipt = await t.engine.endCall(callId);
    const everything = JSON.stringify([await t.ledger.list(), receipt, await t.records.getIntakeRecord("ws_test", record.recordId), await sessions.get("ws_test", callId), record]);
    for (const piece of [SIN, SIN.replaceAll(" ", ""), "046454286"]) assert.equal(everything.includes(piece), false, piece);
    assert.equal(cipher.decrypt(String(record.values.policy)), SIN, "the host's own key reads it back");
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
    await assert.rejects(bare.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(bare, callId) }), rejects("precondition_failed", /fieldCipher/));
    const record = await a.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(a, callId) });
    assert.equal(cipher.decrypt(String((await records.getIntakeRecord("ws_test", record.recordId))!.values.policy)), SIN);
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
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) });
    assert.deepEqual(seen, [{ workspaceId: "ws_test", recordId: record.recordId, field: "policy" }]);
    assert.notEqual(record.recordId, "rec_other");
  });

  it("G7: a failing cipher never holds the call open: the filing is released as failed, the draft dropped, no value kept", async () => {
    const failures: Array<[string, (plain: string) => Promise<string>]> = [
      ["cipher_error", async (plain) => Promise.reject(new Error(`KMS refused ${plain}`))],
      ["no_ciphertext", async () => ""],
    ];
    for (const [reason, encrypt] of failures) {
      const sessions = new MemorySessionStore();
      const records = seeded(new MemoryRecordStore());
      const t = setup({ config: config(), adapters: { fieldCipher: { encrypt }, sessions, records } });
      const callId = await draftOn(t);
      await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), (e: unknown) => e instanceof Error && e.message.includes(`(${reason})`) && !e.message.includes(SIN), reason);
      const failed = (await t.ledger.list()).filter((e) => e.event === "record.filing_failed");
      assert.deepEqual(failed.map((e) => e.detail), [{ recordId: "rec_1", formId: "secure", fields: ["policy"], reason }], reason);
      assert.equal(JSON.stringify(await sessions.get("ws_test", callId)).includes(SIN), false, "no plaintext kept");
      await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), rejects("invalid_transition"), "nothing left to retry");
      const receipt = (await t.engine.endCall(callId))!;
      assert.deepEqual(receipt.body.records, [], "nothing filed");
      assert.equal(await records.getIntakeRecord("ws_test", "rec_1"), null);
      assert.equal(JSON.stringify(await t.ledger.list()).includes(SIN), false, reason);
    }
  });

  it("G8: a cipher that fails while another process files the same record, or after another released it", async () => {
    let fail!: () => void;
    const slow = { encrypt: () => new Promise<string>((_, reject) => (fail = () => reject(new Error("timeout")))) };
    // Filed by the other process: the failing one returns that record, and no failure is ledgered.
    const sessions = new MemorySessionStore();
    const records = seeded(new MemoryRecordStore());
    const a = setup({ config: config(), adapters: { fieldCipher: slow, sessions, records } });
    const callId = await draftOn(a);
    const failing = a.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(a, callId) });
    await new Promise((resolve) => setImmediate(resolve));
    const b = setup({ config: config(), adapters: { fieldCipher: new FakeFieldCipher(), sessions, records, ledger: a.ledger } });
    const filed = await b.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(b, callId) });
    fail();
    assert.deepEqual(await failing, filed);
    assert.equal((await a.ledger.list()).some((e) => e.event === "record.filing_failed"), false);
    // Two processes whose ciphers both fail: the first releases the filing, the second finds nothing
    // left to release, and one failure is ledgered.
    const shared = new MemorySessionStore();
    const c = setup({ config: config(), adapters: { fieldCipher: slow, sessions: shared } });
    const other = await draftOn(c);
    const first = c.engine.confirmIntake(other, { confirmedBy: "voice", readBack: await readBackOf(c, other) });
    await new Promise((resolve) => setImmediate(resolve));
    const failFirst = fail;
    const d = setup({ config: config(), adapters: { fieldCipher: slow, sessions: shared, ledger: c.ledger } });
    const second = d.engine.confirmIntake(other, { confirmedBy: "voice", readBack: await readBackOf(d, other) });
    await new Promise((resolve) => setImmediate(resolve));
    failFirst();
    await assert.rejects(first, rejects("precondition_failed", /nothing was filed/));
    fail();
    await assert.rejects(second, rejects("precondition_failed", /nothing was filed/));
    assert.equal((await c.ledger.list()).filter((e) => e.event === "record.filing_failed").length, 1);
  });
});

describe("FIL-2: a failed filing is never logged for a record that ends up stored", () => {
  /** Two engines on one session store, record store and ledger; B's write held until released. */
  async function twoEngines() {
    let fail!: () => void;
    const slow = { encrypt: () => new Promise<string>((_, reject) => (fail = () => reject(new Error("timeout")))) };
    const sessions = new MemorySessionStore();
    const records = seeded(new MemoryRecordStore());
    const a = setup({ config: config(), adapters: { fieldCipher: slow, sessions, records } });
    const callId = await draftOn(a);
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let entered!: () => void;
    const inPut = new Promise<void>((r) => (entered = r));
    const bRecords = Object.create(records) as MemoryRecordStore;
    bRecords.putIntakeRecord = async (r: IntakeRecord) => {
      entered();
      await held;
      return records.putIntakeRecord(r);
    };
    const b = setup({ config: config(), adapters: { fieldCipher: new FakeFieldCipher(), sessions, records: bRecords, ledger: a.ledger } });
    return { a, b, callId, records, fail: () => fail(), release, inPut };
  }
  const events = async (t: ReturnType<typeof setup>) => (await t.ledger.list()).map((e) => e.event).filter((e) => e.startsWith("record.") || e.startsWith("intake."));

  it("W1 one process's cipher fails while another has sealed the record and is writing it: nothing is logged as failed, the writer files it", async () => {
    const w = await twoEngines();
    const failing = w.a.engine.confirmIntake(w.callId, { confirmedBy: "voice", readBack: await readBackOf(w.a, w.callId) });
    await new Promise((resolve) => setImmediate(resolve));
    const filing = w.b.engine.confirmIntake(w.callId, { confirmedBy: "voice", readBack: await readBackOf(w.b, w.callId) });
    await w.inPut;
    w.fail();
    await assert.rejects(failing, rejects("conflict", /another process is writing this record/));
    w.release();
    const filed = await filing;
    assert.notEqual(await w.records.getIntakeRecord("ws_test", filed.recordId), null);
    assert.deepEqual(await events(w.a), ["intake.started", "intake.confirmed"], "no record.filing_failed");
    assert.deepEqual(await w.a.engine.confirmIntake(w.callId, { confirmedBy: "voice", readBack: await readBackOf(w.a, w.callId) }), filed, "a retry gets the winner's record");
  });

  it("W2 the failing process released first: the other writes nothing and gets the same outcome", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    const late = { encrypt: async (plain: string) => (await held, `sealed:${plain.length}`) };
    let fail!: () => void;
    const slow = { encrypt: () => new Promise<string>((_, reject) => (fail = () => reject(new Error("timeout")))) };
    const sessions = new MemorySessionStore();
    const records = seeded(new MemoryRecordStore());
    const a = setup({ config: config(), adapters: { fieldCipher: slow, sessions, records } });
    const callId = await draftOn(a);
    const failing = a.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(a, callId) });
    await new Promise((resolve) => setImmediate(resolve));
    const b = setup({ config: config(), adapters: { fieldCipher: late, sessions, records, ledger: a.ledger } });
    const sealing = b.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(b, callId) });
    await new Promise((resolve) => setImmediate(resolve));
    fail();
    await assert.rejects(failing, rejects("precondition_failed", /nothing was filed/));
    release();
    await assert.rejects(sealing, rejects("precondition_failed", /nothing was filed/));
    const id = (await a.ledger.list()).find((e) => e.event === "record.filing_failed")!.detail.recordId as string;
    assert.equal(await records.getIntakeRecord("ws_test", id), null, "the released record is never stored");
    assert.deepEqual(await events(a), ["intake.started", "record.filing_failed"]);
  });

  it("W3 a writer whose write fails gives up its claim, so a later failing cipher releases the filing", async () => {
    let fail = false;
    const cipher = { encrypt: async (plain: string) => { if (fail) throw new Error("kms down"); return `sealed:${plain.length}`; } };
    class Down extends MemoryRecordStore {
      override async putIntakeRecord(): Promise<void> {
        throw new Error("store down");
      }
    }
    const t = setup({ config: config(), adapters: { fieldCipher: cipher, records: seeded(new Down()) } });
    const callId = await draftOn(t);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), /store down/);
    fail = true;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), rejects("precondition_failed", /nothing was filed/));
    assert.deepEqual(await events(t), ["intake.started", "record.filing_failed"]);
  });

  it("W4 a claim left by a writer that never finished goes stale after two minutes, so a failing cipher never holds the call open for good", async () => {
    const sessions = new MemorySessionStore();
    class Stuck extends MemoryRecordStore {
      override putIntakeRecord(): Promise<void> {
        return new Promise<void>(() => undefined);
      }
    }
    const records = seeded(new MemoryRecordStore());
    const x = setup({ config: config(), adapters: { fieldCipher: new FakeFieldCipher(), sessions, records: seeded(new Stuck()) } });
    const callId = await draftOn(x);
    void x.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(x, callId) });
    await new Promise((resolve) => setImmediate(resolve));
    const failing = { encrypt: async () => { throw new Error("kms down"); } };
    const y = setup({ config: config(), adapters: { fieldCipher: failing, sessions, records, ledger: x.ledger } });
    y.clock.advance(119_000);
    await assert.rejects(y.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(y, callId) }), rejects("conflict"), "a live claim holds");
    y.clock.advance(2_000);
    await assert.rejects(y.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(y, callId) }), rejects("precondition_failed", /nothing was filed/));
    assert.equal((await y.engine.state(callId)).phase, "open", "the call can end");
  });

  it("W5 two processes seal the same record and one files it first: the other writes nothing again and returns the filed record", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    const late = { encrypt: async (plain: string) => (await held, `late:${plain.length}`) };
    const sessions = new MemorySessionStore();
    const records = seeded(new MemoryRecordStore());
    const a = setup({ config: config(), adapters: { fieldCipher: late, sessions, records } });
    const callId = await draftOn(a);
    const slow = a.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(a, callId) });
    await new Promise((resolve) => setImmediate(resolve));
    const b = setup({ config: config(), adapters: { fieldCipher: new FakeFieldCipher(), sessions, records, ledger: a.ledger } });
    const filed = await b.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(b, callId) });
    release();
    assert.deepEqual(await slow, filed, "the record the first writer stored, not a second ciphertext");
    assert.deepEqual(await records.getIntakeRecord("ws_test", filed.recordId), filed);
    assert.equal((await a.ledger.list()).filter((e) => e.event === "intake.confirmed").length, 1);
  });

  it("W6 the same, when the call has moved on to another intake: the slow writer still writes nothing again", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    const late = { encrypt: async (plain: string) => (await held, `late:${plain.length}`) };
    const sessions = new MemorySessionStore();
    const records = seeded(new MemoryRecordStore());
    const a = setup({ config: config(), adapters: { fieldCipher: late, sessions, records } });
    const callId = await draftOn(a);
    const slow = a.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(a, callId) });
    await new Promise((resolve) => setImmediate(resolve));
    const b = setup({ config: config(), adapters: { fieldCipher: new FakeFieldCipher(), sessions, records, ledger: a.ledger } });
    const filed = await b.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(b, callId) });
    await b.engine.startIntake(callId, "secure");
    release();
    assert.equal((await slow).recordId, filed.recordId);
    assert.deepEqual(await records.getIntakeRecord("ws_test", filed.recordId), filed, "the stored record is the first writer's");
  });

  it("R1 a write the store kept before failing is deleted when a failing cipher later releases the filing", async () => {
    let fail = false;
    const cipher = { encrypt: async (plain: string) => { if (fail) throw new Error("kms down"); return `sealed:${plain.length}`; } };
    const records = seeded(new StoredThenFailed());
    const t = setup({ config: config(), adapters: { fieldCipher: cipher, records } });
    const callId = await draftOn(t);
    records.failNext = 1;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), /answer lost/);
    assert.notEqual(await records.getIntakeRecord("ws_test", "rec_1"), null, "the store kept it");
    fail = true;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), rejects("precondition_failed", /nothing was filed/));
    assert.equal(await records.getIntakeRecord("ws_test", "rec_1"), null, "released, so deleted");
    const receipt = (await t.engine.endCall(callId))!;
    assert.deepEqual(receipt.body.records, []);
  });

  it("R2 one write failing never gives up another write's claim", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let puts = 0;
    class Mixed extends MemoryRecordStore {
      override async putIntakeRecord(record: IntakeRecord): Promise<void> {
        puts++;
        if (puts === 1) {
          await held;
          return super.putIntakeRecord(record);
        }
        throw new Error("store down");
      }
    }
    const sessions = new MemorySessionStore();
    const records = seeded(new Mixed());
    const a = setup({ config: config(), adapters: { fieldCipher: new FakeFieldCipher(), sessions, records } });
    const callId = await draftOn(a);
    const pending = a.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(a, callId) });
    while (puts === 0) await new Promise((resolve) => setImmediate(resolve));
    const b = setup({ config: config(), adapters: { fieldCipher: new FakeFieldCipher(), sessions, records, ledger: a.ledger } });
    await assert.rejects(b.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(b, callId) }), /store down/);
    const failing = { encrypt: async () => { throw new Error("kms down"); } };
    const c = setup({ config: config(), adapters: { fieldCipher: failing, sessions, records, ledger: a.ledger } });
    await assert.rejects(c.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(c, callId) }), rejects("conflict"), "the first write still holds its claim");
    release();
    const filed = await pending;
    assert.deepEqual(await records.getIntakeRecord("ws_test", filed.recordId), filed);
  });

  it("R3 a write that outlives its claim stores nothing once the filing was released, and files nothing", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let writing = false;
    class Slow extends MemoryRecordStore {
      override async putIntakeRecord(record: IntakeRecord): Promise<void> {
        writing = true;
        await held;
        return super.putIntakeRecord(record);
      }
    }
    const sessions = new MemorySessionStore();
    const records = seeded(new Slow());
    const x = setup({ config: config(), adapters: { fieldCipher: new FakeFieldCipher(), sessions, records } });
    const callId = await draftOn(x);
    const slow = x.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(x, callId) });
    while (!writing) await new Promise((resolve) => setImmediate(resolve));
    const failing = { encrypt: async () => { throw new Error("kms down"); } };
    const y = setup({ config: config(), adapters: { fieldCipher: failing, sessions, records, ledger: x.ledger } });
    y.clock.advance(121_000);
    await assert.rejects(y.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(y, callId) }), rejects("precondition_failed", /nothing was filed/));
    release();
    await assert.rejects(slow, rejects("precondition_failed", /nothing was filed/));
    assert.equal(await records.getIntakeRecord("ws_test", "rec_1"), null, "the late write stored nothing");
    assert.equal((await x.ledger.list()).some((e) => e.event === "intake.confirmed"), false);
  });

  it("R4 a release whose delete failed is carried on by the next confirmation, even with a working cipher", async () => {
    let fail = true;
    const cipher = { encrypt: async (plain: string) => { if (fail) throw new Error("kms down"); return `sealed:${plain.length}`; } };
    let deleteDown = true;
    class NoDelete extends MemoryRecordStore {
      override async deleteIntakeRecords(workspaceId: string, recordIds: readonly string[]): Promise<void> {
        if (deleteDown) throw new Error("delete down");
        return super.deleteIntakeRecords(workspaceId, recordIds);
      }
    }
    const records = seeded(new NoDelete());
    const t = setup({ config: config(), adapters: { fieldCipher: cipher, records } });
    const callId = await draftOn(t);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), /delete down/);
    fail = false;
    deleteDown = false;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), rejects("precondition_failed", /nothing was filed/));
    const failed = (await t.ledger.list()).filter((e) => e.event === "record.filing_failed");
    assert.deepEqual(failed.map((e) => e.detail.reason), ["cipher_error"], "released once, with the reason it began with");
    assert.equal(await records.getIntakeRecord("ws_test", "rec_1"), null);
    assert.equal((await t.engine.state(callId)).phase, "open", "the call can end");
  });

  it("R5 two releases at once: one completes, the other finds it done", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let deletes = 0;
    class SlowDelete extends MemoryRecordStore {
      override async deleteIntakeRecords(workspaceId: string, recordIds: readonly string[]): Promise<void> {
        deletes++;
        if (deletes === 1) await held;
        return super.deleteIntakeRecords(workspaceId, recordIds);
      }
    }
    const sessions = new MemorySessionStore();
    const records = seeded(new SlowDelete());
    const failing = { encrypt: async () => { throw new Error("kms down"); } };
    const a = setup({ config: config(), adapters: { fieldCipher: failing, sessions, records } });
    const callId = await draftOn(a);
    const first = a.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(a, callId) });
    while (deletes === 0) await new Promise((resolve) => setImmediate(resolve));
    const b = setup({ config: config(), adapters: { fieldCipher: failing, sessions, records, ledger: a.ledger } });
    await assert.rejects(b.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(b, callId) }), rejects("precondition_failed", /nothing was filed/));
    release();
    await assert.rejects(first, rejects("precondition_failed", /nothing was filed/));
    assert.equal((await a.ledger.list()).filter((e) => e.event === "record.filing_failed").length, 1);
  });
});
