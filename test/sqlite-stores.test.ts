// SRV-4: the reference server's SQLite stores pass the PRV-5 contract suites, and keep what they
// hold across a restart.
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { SqliteAuditLedger, SqliteRecordStore, openSqliteDatabase, openSqliteStores } from "../examples/reference-server/src/sqlite-stores.ts";
import type { IntakeRecord } from "../src/core/adapters.ts";
import { MemoryAuditLedger, verifyChain } from "../src/prove/ledger.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, testConfig } from "./helpers.ts";
import { auditLedgerContract, recordStoreContract } from "./prv5-contracts.ts";

const dir = mkdtempSync(join(tmpdir(), "da-sqlite-"));
// Every connection opened on a file is closed before the directory is removed (Windows refuses to
// remove an open file), including those of a test that failed before its own close.
const opened: { close(): void }[] = [];
const track = <T extends { close(): void }>(connection: T): T => {
  opened.push(connection);
  return connection;
};
after(() => {
  for (const connection of opened) {
    try {
      connection.close();
    } catch {
      // Already closed by its own test.
    }
  }
  rmSync(dir, { recursive: true, force: true });
});
let files = 0;
const newFile = () => join(dir, `stores-${++files}.db`);
const openStores = (path: string) => track(openSqliteStores(path));
const openDatabase = (path: string) => track(openSqliteDatabase(path));

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

describe("MemoryAuditLedger passes the copied AuditLedger contract", () => {
  for (const c of auditLedgerContract(() => new MemoryAuditLedger())) it(c.name, c.run);
});

describe("SqliteAuditLedger passes the AuditLedger contract", () => {
  for (const c of auditLedgerContract(() => new SqliteAuditLedger(openSqliteDatabase(":memory:")))) it(c.name, c.run);
});

describe("SqliteAuditLedger on a file passes the AuditLedger contract", () => {
  for (const c of auditLedgerContract(() => openStores(newFile()).ledger)) it(c.name, c.run);
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

describe("SqliteRecordStore on a file passes the RecordStore contract", () => {
  for (const c of recordStoreContract((subjects) => {
    const { records } = openStores(newFile());
    for (const { workspaceId, subject } of subjects) records.putSubject(workspaceId, subject);
    return records;
  })) {
    it(c.name, c.run);
  }
});

describe("SQLite stores", () => {
  it("keep the ledger, subjects and records across a restart, and the chain goes on", async () => {
    const path = newFile();
    const first = openStores(path);
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

    const second = openStores(path);
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
    const stores = openStores(path);
    await stores.ledger.append(entry(1));
    const other = openDatabase(path);
    assert.throws(() => other.exec(`UPDATE audit_entries SET entry = '{}'`), /append-only/);
    assert.throws(() => other.exec("DELETE FROM audit_entries"), /append-only/);
    const replace = "INSERT OR REPLACE INTO audit_entries (seq, event_id, hash, entry) VALUES (?, ?, ?, '{}')";
    assert.throws(() => other.prepare(replace).run(1, null, "0".repeat(64)), /append-only/, "no replacing a seq");
    await stores.ledger.append({ ...entry(2), eventId: "e2" });
    assert.throws(() => other.prepare(replace).run(3, JSON.stringify("e2"), "0".repeat(64)), /append-only/, "no replacing an eventId, bound as the store binds it");
    assert.equal((await stores.ledger.list()).length, 2);
    assert.equal(verifyChain(await stores.ledger.list()).ok, true);
    other.close();
    stores.close();
  });

  it("keep one chain when two connections append to one file", async () => {
    const path = newFile();
    const a = openStores(path);
    const b = openStores(path);
    const appended = await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 === 0 ? a : b).ledger.append({ ...entry(i), eventId: `e${i % 5}` })));
    assert.deepEqual(new Set(appended.map((e) => e.seq)), new Set([1, 2, 3, 4, 5]), "each eventId once, across connections");
    const stored = await b.ledger.list();
    assert.equal(stored.length, 5);
    assert.deepEqual(verifyChain(stored), { ok: true, head: await a.ledger.head() });
    a.close();
    b.close();
  });

  it("keep ids apart that differ only in a lone surrogate, as the memory stores do", async () => {
    // node:sqlite binds text as UTF-8, where every lone surrogate becomes U+FFFD.
    const path = newFile();
    const stores = openStores(path);
    stores.records.putSubject("ws\uD800", { subjectKey: "s", phoneOnFile: "+15555550101", knowledge: {} });
    stores.records.putSubject("ws\uDC00", { subjectKey: "s", phoneOnFile: "+15555550102", knowledge: {} });
    stores.records.putSubject("w", { subjectKey: "k\uD800", phoneOnFile: "+15555550103", knowledge: {} });
    assert.equal((await stores.records.getSubject("ws\uD800", "s"))!.phoneOnFile, "+15555550101", "never another workspace's number on file");
    assert.equal((await stores.records.getSubject("ws\uDC00", "s"))!.phoneOnFile, "+15555550102");
    assert.equal(await stores.records.getSubject("w", "k\uDBFF"), null);
    await stores.records.putIntakeRecord({ ...record("r\uD800"), workspaceId: "w" });
    assert.equal(await stores.records.getIntakeRecord("w", "r\uDBFF"), null, "a record never filed");
    assert.deepEqual(await stores.records.getIntakeRecord("w", "r\uD800"), record("r\uD800"));
    const first = await stores.ledger.append({ ...entry(1), eventId: "e\uD800" });
    const second = await stores.ledger.append({ ...entry(2), eventId: "e\uDBFF" });
    assert.notDeepEqual(second, first, "another eventId is another entry");
    assert.deepEqual(await stores.ledger.append({ ...entry(3), eventId: "e\uD800" }), first);
    stores.close();
    const reopened = openStores(path);
    assert.deepEqual((await reopened.ledger.list()).map((e) => e.eventId), ["e\uD800", "e\uDBFF"]);
    reopened.close();
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

  it("refuse a file: URI, whose file would not get the owner-only mode", () => {
    assert.throws(() => openSqliteDatabase(`file:${newFile()}`), /not a file: URI/);
    assert.throws(() => openSqliteStores(`FILE:${newFile()}?mode=rwc`), /not a file: URI/);
  });

  it("create the database file readable and writable by its owner only", { skip: process.platform === "win32" }, () => {
    const path = newFile();
    openDatabase(path).close();
    assert.equal(statSync(path).mode & 0o777, 0o600);
  });
});
