// SRV-4: the reference server's SQLite stores pass the PRV-5 contract suites, and keep what they
// hold across a restart.
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { SqliteAuditLedger, SqliteRecordStore, openSqliteDatabase, openSqliteStores } from "../examples/reference-server/src/sqlite-stores.ts";
import type { IntakeRecord } from "../src/core/adapters.ts";
import { verifyChain } from "../src/prove/ledger.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, testConfig } from "./helpers.ts";
import { auditLedgerContract, recordStoreContract } from "./prv5-contracts.ts";

const dir = mkdtempSync(join(tmpdir(), "da-sqlite-"));
after(() => rmSync(dir, { recursive: true, force: true }));
let files = 0;
const newFile = () => join(dir, `stores-${++files}.db`);

const record = (recordId: string, issue = "leaking tap"): IntakeRecord => ({
  recordId,
  workspaceId: "w",
  callId: "call_1",
  formId: "repair",
  formVersion: "1",
  values: { issue },
  digest: "c".repeat(64),
  confirmedBy: "keypad",
  confirmedAt: "2026-01-01T00:00:00.000Z",
});

const entry = (n: number) => ({ callId: `call_${n}`, actor: "code" as const, event: "module.event" as const, at: "2026-01-01T00:00:00.000Z", detail: { n } });

describe("SqliteAuditLedger passes the AuditLedger contract", () => {
  for (const c of auditLedgerContract(() => new SqliteAuditLedger(openSqliteDatabase(":memory:")))) it(c.name, c.run);
});

describe("SqliteAuditLedger on a file passes the AuditLedger contract", () => {
  for (const c of auditLedgerContract(() => openSqliteStores(newFile()).ledger)) it(c.name, c.run);
});

describe("SqliteRecordStore passes the RecordStore contract", () => {
  for (const c of recordStoreContract((subjects) => {
    const store = new SqliteRecordStore(openSqliteDatabase(":memory:"));
    for (const { workspaceId, subject } of subjects) store.putSubject(workspaceId, subject);
    return store;
  })) {
    it(c.name, c.run);
  }
});

describe("SQLite stores", () => {
  it("keep the ledger, subjects and records across a restart, and the chain goes on", async () => {
    const path = newFile();
    const first = openSqliteStores(path);
    first.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
    const t = createTestEngine({ config: testConfig(), adapters: { records: first.records, ledger: first.ledger } });
    const { callId } = await t.engine.startCall({ locale: "en" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
    await t.engine.endCall(callId);
    await first.records.putIntakeRecord(record("rec_1"));
    const before = await first.ledger.list();
    assert.ok(before.length > 3);
    first.close();

    const second = openSqliteStores(path);
    assert.deepEqual(await second.ledger.list(), before);
    assert.deepEqual(verifyChain(before), { ok: true, head: await second.ledger.head() });
    assert.deepEqual(await second.records.getIntakeRecord("w", "rec_1"), record("rec_1"));
    const restarted = createTestEngine({ config: testConfig(), adapters: { records: second.records, ledger: second.ledger } });
    // Real call ids are random. Sequential ids start again at call_1 after a restart, and the
    // ledger would rightly take the new call's event ids for the old call's, so skip one.
    restarted.ids.next("call");
    const again = await restarted.engine.startCall({ locale: "fr" });
    await restarted.engine.beginVerification(again.callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await restarted.engine.submitKeypad(again.callId, { dob: DOB }), { matched: true, locked: false }, "the subject survived");
    const after = await second.ledger.list();
    assert.equal(after[before.length]!.prevHash, before.at(-1)!.hash);
    assert.equal(verifyChain(after).ok, true);
    assert.equal(JSON.stringify(after).includes(DOB), false, "no keyed value in the ledger");
    second.close();
  });

  it("refuse any change or removal of a ledger entry, from any connection", async () => {
    const path = newFile();
    const stores = openSqliteStores(path);
    await stores.ledger.append(entry(1));
    const other = openSqliteDatabase(path);
    assert.throws(() => other.exec(`UPDATE audit_entries SET entry = '{}'`), /append-only/);
    assert.throws(() => other.exec("DELETE FROM audit_entries"), /append-only/);
    assert.equal(verifyChain(await stores.ledger.list()).ok, true);
    other.close();
    stores.close();
  });

  it("keep one chain when two connections append to one file", async () => {
    const path = newFile();
    const a = openSqliteStores(path);
    const b = openSqliteStores(path);
    const appended = await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 === 0 ? a : b).ledger.append({ ...entry(i), eventId: `e${i % 5}` })));
    assert.deepEqual(new Set(appended.map((e) => e.seq)), new Set([1, 2, 3, 4, 5]), "each eventId once, across connections");
    const stored = await b.ledger.list();
    assert.equal(stored.length, 5);
    assert.deepEqual(verifyChain(stored), { ok: true, head: await a.ledger.head() });
    a.close();
    b.close();
  });

  it("keep the first filing of a record id, and replace a subject the host puts again", async () => {
    const records = new SqliteRecordStore(openSqliteDatabase(":memory:"));
    await records.putIntakeRecord(record("rec_1"));
    await records.putIntakeRecord(record("rec_1", "something else"));
    assert.deepEqual(await records.getIntakeRecord("w", "rec_1"), record("rec_1"));
    records.putSubject("w", { subjectKey: "s", phoneOnFile: "+15555550100", knowledge: {} });
    records.putSubject("w", { subjectKey: "s", phoneOnFile: "+15555550199", knowledge: {} });
    assert.equal((await records.getSubject("w", "s"))!.phoneOnFile, "+15555550199");
  });

  it("create the database file readable and writable by its owner only", { skip: process.platform === "win32" }, () => {
    const path = newFile();
    openSqliteDatabase(path).close();
    assert.equal(statSync(path).mode & 0o777, 0o600);
  });
});
