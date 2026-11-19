// SRV-4: optional persistent stores for the reference server, on `node:sqlite` (built into Node,
// so no new dependency, not even an optional peer). `SqliteAuditLedger` and `SqliteRecordStore`
// keep the guarantees of the memory adapters and pass the same contract suites
// (`auditLedgerContract`, `recordStoreContract`), so a server that restarts keeps its ledger, its
// subjects and the records callers confirmed.
//
//   const stores = openSqliteStores("./district-assurance.db");
//   createEngine({ ..., adapters: { ..., records: stores.records, ledger: stores.ledger } });
//
// `node:sqlite` is synchronous: every method runs its statements without yielding, so appends and
// filings in one process never interleave. Appends take the database's write lock (BEGIN
// IMMEDIATE), so several processes on one file also keep one chain; a process waits up to the busy
// timeout for another's lock, blocking its event loop meanwhile. Fine for a reference server, not
// tuned for production.
import { closeSync, openSync, statSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import { GENESIS_HASH, chainEntry, type AuditEntry, type AuditInput, type AuditLedger, type IntakeRecord, type RecordStore, type SubjectRecord } from "../../../src/index.ts";

/** How long a connection waits for another connection's write lock before it fails, in ms. */
export const SQLITE_BUSY_TIMEOUT_MS = 5_000;

/**
 * Opens (and creates, readable and writable by its owner only) a database file, in WAL mode so
 * readers do not wait for a writer. `":memory:"` opens a database that lives as long as the
 * connection. A `file:` URI is refused: SQLite would open the file the URI names, not the path
 * whose mode was set, so the database could be created readable by others. A file that already
 * exists readable or writable by group or others is refused too (the mode only applies when the
 * file is created), since its subjects and records would be readable to them. SQLite creates its
 * WAL and shared-memory files with the database file's mode.
 */
export function openSqliteDatabase(path: string): DatabaseSync {
  if (/^file:/i.test(path)) throw new Error("openSqliteDatabase takes a filesystem path, not a file: URI");
  if (path !== ":memory:") {
    closeSync(openSync(path, "a", 0o600));
    // Windows has no group or other bits to check.
    if (process.platform !== "win32" && (statSync(path).mode & 0o077) !== 0) {
      throw new Error(`the database file ${path} is readable or writable by others; make it owner-only (chmod 600) first`);
    }
  }
  const db = new DatabaseSync(path, { timeout: SQLITE_BUSY_TIMEOUT_MS });
  db.exec("PRAGMA journal_mode = WAL");
  return db;
}

/**
 * A key as it is bound in SQL: its JSON string. node:sqlite binds text as UTF-8, which turns every
 * lone surrogate into U+FFFD, so two ids that differ only there would share a row; JSON escapes
 * them (`\ud800`) instead, and keeps every id apart, as the memory stores do.
 */
const key = (id: string): string => JSON.stringify(id);

/** Runs `body` in a write transaction: committed if it returns, rolled back if it throws. */
function writeTransaction<T>(db: DatabaseSync, body: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = body();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

/**
 * The audit ledger in a table. Each row holds an entry exactly as `chainEntry` built it, as JSON,
 * so it reads back with the same hash. Triggers refuse any UPDATE or DELETE, and any INSERT whose
 * `seq` or `eventId` is already stored (so INSERT OR REPLACE cannot swap an entry), so the table is
 * append-only for every connection that keeps the triggers, not only this class. A connection can
 * still drop them and rewrite a row; the hash chain shows it (verifyChain). `eventId` is UNIQUE: an
 * id is appended once, and a second append returns the first entry.
 */
export class SqliteAuditLedger implements AuditLedger {
  readonly #db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.#db = db;
    db.exec(`
      CREATE TABLE IF NOT EXISTS audit_entries (
        seq INTEGER PRIMARY KEY,
        event_id TEXT UNIQUE,
        hash TEXT NOT NULL,
        entry TEXT NOT NULL
      ) STRICT;
      CREATE TRIGGER IF NOT EXISTS audit_entries_no_update BEFORE UPDATE ON audit_entries
        BEGIN SELECT RAISE(ABORT, 'the audit ledger is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS audit_entries_no_delete BEFORE DELETE ON audit_entries
        BEGIN SELECT RAISE(ABORT, 'the audit ledger is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS audit_entries_no_replace BEFORE INSERT ON audit_entries
        WHEN EXISTS (SELECT 1 FROM audit_entries WHERE seq = NEW.seq OR (NEW.event_id IS NOT NULL AND event_id = NEW.event_id))
        BEGIN SELECT RAISE(ABORT, 'the audit ledger is append-only'); END;
    `);
  }

  async append(input: AuditInput): Promise<AuditEntry> {
    return writeTransaction(this.#db, () => {
      if (input.eventId !== undefined) {
        const seen = this.#db.prepare("SELECT entry FROM audit_entries WHERE event_id = ?").get(key(input.eventId));
        if (seen !== undefined) return JSON.parse(seen.entry as string) as AuditEntry;
      }
      const head = this.#head();
      // chainEntry refuses card data; the transaction is then rolled back with nothing stored.
      const entry = chainEntry(input, head.seq + 1, head.hash);
      this.#db
        .prepare("INSERT INTO audit_entries (seq, event_id, hash, entry) VALUES (?, ?, ?, ?)")
        .run(entry.seq, entry.eventId === undefined ? null : key(entry.eventId), entry.hash, JSON.stringify(entry));
      return entry;
    });
  }

  async head(): Promise<{ seq: number; hash: string }> {
    return this.#head();
  }

  async list(fromSeq = 1): Promise<AuditEntry[]> {
    return this.#db
      .prepare("SELECT entry FROM audit_entries WHERE seq >= ? ORDER BY seq")
      .all(fromSeq)
      .map((row) => JSON.parse(row.entry as string) as AuditEntry);
  }

  #head(): { seq: number; hash: string } {
    const last = this.#db.prepare("SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1").get();
    return last === undefined ? { seq: 0, hash: GENESIS_HASH } : { seq: last.seq as number, hash: last.hash as string };
  }
}

/**
 * Subjects and intake records in two tables, keyed by (workspace, id) as two columns, each bound as
 * its JSON string, so no pair can collide with another. Records are JSON, copied in and out by construction. An intake record
 * is filed once per (workspace, recordId): a retry of the same record changes nothing, and the
 * first filing stands.
 */
export class SqliteRecordStore implements RecordStore {
  readonly #db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.#db = db;
    db.exec(`
      CREATE TABLE IF NOT EXISTS subjects (
        workspace_id TEXT NOT NULL,
        subject_key TEXT NOT NULL,
        subject TEXT NOT NULL,
        PRIMARY KEY (workspace_id, subject_key)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS intake_records (
        workspace_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        record TEXT NOT NULL,
        PRIMARY KEY (workspace_id, record_id)
      ) STRICT;
    `);
  }

  /** Adds or replaces a subject: the host's own record, which the engine only reads. */
  putSubject(workspaceId: string, subject: SubjectRecord): void {
    this.#db
      .prepare("INSERT INTO subjects (workspace_id, subject_key, subject) VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET subject = excluded.subject")
      .run(key(workspaceId), key(subject.subjectKey), JSON.stringify(subject));
  }

  async getSubject(workspaceId: string, subjectKey: string): Promise<SubjectRecord | null> {
    const row = this.#db.prepare("SELECT subject FROM subjects WHERE workspace_id = ? AND subject_key = ?").get(key(workspaceId), key(subjectKey));
    return row === undefined ? null : (JSON.parse(row.subject as string) as SubjectRecord);
  }

  async putIntakeRecord(record: IntakeRecord): Promise<void> {
    this.#db
      .prepare("INSERT INTO intake_records (workspace_id, record_id, record) VALUES (?, ?, ?) ON CONFLICT DO NOTHING")
      .run(key(record.workspaceId), key(record.recordId), JSON.stringify(record));
  }

  async getIntakeRecord(workspaceId: string, recordId: string): Promise<IntakeRecord | null> {
    const row = this.#db.prepare("SELECT record FROM intake_records WHERE workspace_id = ? AND record_id = ?").get(key(workspaceId), key(recordId));
    return row === undefined ? null : (JSON.parse(row.record as string) as IntakeRecord);
  }
}

/** Both stores on one database file, and a `close` for the connection. */
export function openSqliteStores(path: string): { records: SqliteRecordStore; ledger: SqliteAuditLedger; close(): void } {
  const db = openSqliteDatabase(path);
  return { records: new SqliteRecordStore(db), ledger: new SqliteAuditLedger(db), close: () => db.close() };
}
