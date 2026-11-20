// SRV-4 SQLite stores under attack (a hostile pass on #95): file modes, hostile input checked
// against the memory stores, and races and faults across connections. Each pins safe behaviour.
import { strict as assert } from "node:assert";
import { chmodSync, closeSync, existsSync, mkdtempSync, openSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { SqliteAuditLedger, SqliteRecordStore, openSqliteDatabase, openSqliteStores } from "../examples/reference-server/src/sqlite-stores.ts";
import { MemoryAuditLedger, verifyChain } from "../src/prove/ledger.ts";
import { MemoryRecordStore } from "../src/testing/index.ts";

const dir = mkdtempSync(join(tmpdir(), "da-sqlite-attack-"));
const opened: { close(): void }[] = [];
after(() => {
  for (const c of opened) {
    try {
      c.close();
    } catch {
      // Closed by its own test.
    }
  }
  rmSync(dir, { recursive: true, force: true });
});
let files = 0;
const newFile = () => join(dir, `attack-${++files}.db`);
const track = <T extends { close(): void }>(c: T): T => {
  opened.push(c);
  return c;
};
const entry = (n: number, more: object = {}) => ({ callId: `call_${n}`, actor: "code" as const, event: "module.event" as const, at: "2026-01-01T00:00:00.000Z", detail: { n }, ...more });

describe("attack: file modes", { skip: process.platform === "win32" }, () => {
  it("the WAL and shared-memory files SQLite creates beside the database are owner-only too", async () => {
    const path = newFile();
    const stores = track(openSqliteStores(path));
    await stores.ledger.append(entry(1));
    stores.records.putSubject("w", { subjectKey: "s", phoneOnFile: "+15555550100", knowledge: {} });
    for (const file of [`${path}-wal`, `${path}-shm`]) {
      assert.equal(existsSync(file), true, file);
      assert.equal(statSync(file).mode & 0o077, 0, `${file} is readable or writable by others`);
    }
  });

  it("a database file that already exists readable by others is refused, never used", () => {
    const path = newFile();
    closeSync(openSync(path, "w", 0o644));
    chmodSync(path, 0o644);
    assert.throws(() => track(openSqliteDatabase(path)), /readable or writable by others/);
    chmodSync(path, 0o600);
    track(openSqliteDatabase(path)).close();
  });

  it("a WAL or shared-memory file left beside the database readable by others is refused too", () => {
    for (const suffix of ["-wal", "-shm"]) {
      const path = newFile();
      closeSync(openSync(path, "w", 0o600));
      closeSync(openSync(`${path}${suffix}`, "w", 0o644));
      chmodSync(`${path}${suffix}`, 0o644);
      assert.throws(() => track(openSqliteDatabase(path)), new RegExp(`${suffix}.*readable or writable by others`), suffix);
      chmodSync(`${path}${suffix}`, 0o600);
      track(openSqliteDatabase(path)).close();
    }
  });
});

describe("attack: hostile input against the memory reference", () => {
  it("list answers as the memory ledger does for every fromSeq a host could pass", async () => {
    const sqlite = new SqliteAuditLedger(openSqliteDatabase(":memory:"));
    const memory = new MemoryAuditLedger();
    for (let n = 1; n <= 3; n++) {
      await sqlite.append(entry(n));
      await memory.append(entry(n));
    }
    for (const from of [undefined, 0, -1, 1.5, 2, 3, 4, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      assert.deepEqual(await sqlite.list(from), await memory.list(from), String(from));
    }
  });

  it("round-trips prototype keys, -0, large and tiny numbers, and keeps the chain valid after a restart", async () => {
    const path = newFile();
    const stores = track(openSqliteStores(path));
    const detail = JSON.parse('{"__proto__": {"x": 1}, "constructor": "c", "big": 1e21, "tiny": 5e-324, "neg": -0}') as Record<string, unknown>;
    const appended = await stores.ledger.append(entry(1, { detail }));
    stores.records.putSubject("__proto__", { subjectKey: "constructor", phoneOnFile: "+15555550100", knowledge: JSON.parse('{"__proto__": "d"}') as Record<string, string> });
    stores.close();
    const again = track(openSqliteStores(path));
    const listed = await again.ledger.list();
    assert.equal(verifyChain(listed).ok, true);
    assert.equal(listed[0]!.hash, appended.hash);
    assert.equal(Object.hasOwn(listed[0]!.detail, "__proto__"), true, "an own key, not a prototype");
    const subject = await again.records.getSubject("__proto__", "constructor");
    assert.equal(subject!.phoneOnFile, "+15555550100");
    assert.equal(Object.getPrototypeOf(subject!.knowledge), Object.prototype, "never a polluted prototype");
    assert.equal(await again.records.getSubject("w", "constructor"), null);
  });

  it("keeps a U+FFFD id apart from the lone surrogates it would have collapsed with", async () => {
    const records = new SqliteRecordStore(openSqliteDatabase(":memory:"));
    const memory = new MemoryRecordStore();
    for (const [i, id] of ["k\uD800", "k\uDC00", "k�"].entries()) {
      for (const store of [records, memory]) store.putSubject("w", { subjectKey: id, phoneOnFile: `+1555555010${i}`, knowledge: {} });
    }
    for (const id of ["k\uD800", "k\uDC00", "k�", "k"]) assert.deepEqual(await records.getSubject("w", id), await memory.getSubject("w", id), JSON.stringify(id));
  });
});

describe("attack: races and faults", () => {
  it("two connections appending one eventId at once store it once, and both get that entry", async () => {
    const path = newFile();
    const a = track(openSqliteStores(path));
    const b = track(openSqliteStores(path));
    const [x, y] = await Promise.all([a.ledger.append(entry(1, { eventId: "same" })), b.ledger.append(entry(2, { eventId: "same" }))]);
    assert.deepEqual(x, y);
    assert.equal((await a.ledger.list()).length, 1);
  });

  it("an append another connection's lock times out leaves nothing, and the next append continues the chain", async () => {
    const path = newFile();
    const a = track(openSqliteStores(path));
    await a.ledger.append(entry(1));
    // A second connection holds the write lock; a short timeout makes the wait fail at once.
    const blocker = track(openSqliteDatabase(path));
    blocker.exec("BEGIN IMMEDIATE");
    const { DatabaseSync } = await import("node:sqlite");
    const impatient = new SqliteAuditLedger(track(new DatabaseSync(path, { timeout: 1 })));
    await assert.rejects(impatient.append(entry(2)));
    blocker.exec("ROLLBACK");
    const next = await impatient.append(entry(3));
    assert.equal(next.seq, 2);
    assert.equal(verifyChain(await a.ledger.list()).ok, true);
  });

  it("a card number refused mid-transaction leaves the connection usable, with nothing stored", async () => {
    const ledger = new SqliteAuditLedger(openSqliteDatabase(":memory:"));
    await assert.rejects(ledger.append(entry(1, { detail: { note: "4242 4242 4242 4242" } })));
    const ok = await ledger.append(entry(2));
    assert.equal(ok.seq, 1);
    assert.equal((await ledger.list()).length, 1);
  });
});
