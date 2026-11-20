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
import { closeSync, linkSync, lstatSync, mkdtempSync, openSync, rmSync, rmdirSync, type Stats } from "node:fs";
import { dirname, join } from "node:path";
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
 * file is created), since its subjects and records would be readable to them, and so is a WAL,
 * shared-memory or rollback journal file left beside it (SQLite creates new ones with the database
 * file's mode, but keeps the mode of one that exists).
 *
 * An existing file is checked by path and never opened here: on Linux and macOS, closing any
 * descriptor on a file drops every POSIX lock this process holds on it, including those of another
 * SQLite connection to it, which could then corrupt its WAL. A new file is created, exclusively
 * and owner-only, under a private name in a directory made beside it (so on its filesystem), closed
 * there, and then linked into place: no descriptor is ever opened or closed on the database path
 * outside SQLite, even while another thread or process opens the path. A symbolic link is refused, at the database path and
 * beside it: SQLite follows it and uses the target's WAL and shared-memory files, not the ones
 * checked here. Any other file type (a directory, a FIFO) is refused too.
 *
 * POSIX only: on Windows a file is refused, since the owner-only mode sets no ACL there and the
 * file would be as readable as its directory makes it. There is no option to allow it; a Windows
 * host uses another store (or `":memory:"`, which keeps nothing across a restart).
 */
export function openSqliteDatabase(path: string): DatabaseSync {
  if (/^file:/i.test(path)) throw new Error("openSqliteDatabase takes a filesystem path, not a file: URI");
  if (path !== ":memory:") {
    if (process.platform === "win32") {
      throw new Error("openSqliteDatabase refuses a database file on Windows, where an owner-only mode sets no ACL: the file-backed stores are POSIX only, so a Windows host uses another store");
    }
    let info = lstatIfExists(path);
    if (info === undefined) {
      createOwnerOnly(path);
      info = lstatSync(path);
    }
    assertOwnerOnlyFile(path, info);
    for (const file of [`${path}-wal`, `${path}-shm`, `${path}-journal`]) {
      const sidecar = lstatIfExists(file);
      if (sidecar !== undefined) assertOwnerOnlyFile(file, sidecar);
    }
  }
  const db = new DatabaseSync(path, { timeout: SQLITE_BUSY_TIMEOUT_MS });
  try {
    db.exec("PRAGMA journal_mode = WAL");
  } catch (error) {
    // Not a database, or unreadable: the connection is closed (close cannot fail on an open
    // connection) and the reason thrown.
    db.close();
    throw error;
  }
  return db;
}

/**
 * Creates an empty owner-only file at `path`, or leaves alone one another thread or process created
 * there first (the caller checks it as any existing file). The descriptor that creates it is on a
 * private name in a new owner-only directory beside `path`, and is closed before the file is linked
 * into place; then the private name and directory are removed, also when a step fails.
 */
function createOwnerOnly(path: string): void {
  const staging = mkdtempSync(join(dirname(path), ".sqlite-create-"));
  const staged = join(staging, "database");
  const cleanUp = () => {
    rmSync(staged, { force: true });
    rmdirSync(staging);
  };
  try {
    closeSync(openSync(staged, "wx", 0o600));
    try {
      linkSync(staged, path);
    } catch (error) {
      // Created there since the look: checked as any existing file is.
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  } catch (error) {
    try {
      cleanUp();
    } catch {
      // The error that stopped the create says more than the cleanup's.
    }
    throw error;
  }
  // A private directory left behind is an error too.
  cleanUp();
}

/** The file's own status (a symbolic link's, not its target's), or undefined if there is none. */
function lstatIfExists(file: string): Stats | undefined {
  try {
    return lstatSync(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function assertOwnerOnlyFile(file: string, info: Stats): void {
  if (info.isSymbolicLink()) throw new Error(`${file} is a symbolic link, and SQLite would use the WAL and shared-memory files beside its target; give the target's own path`);
  if (!info.isFile()) throw new Error(`${file} is not a regular file`);
  if ((info.mode & 0o077) !== 0) throw new Error(`the database file ${file} is readable or writable by others; make it owner-only (chmod 600) first`);
}

/**
 * A key as it is bound in SQL: its JSON string. node:sqlite binds text as UTF-8, which turns every
 * lone surrogate into U+FFFD, so two ids that differ only there would share a row; JSON escapes
 * them (`\ud800`) instead, and keeps every id apart, as the memory stores do.
 */
const key = (id: string): string => JSON.stringify(id);

/**
 * Entries, subjects and records as stored: JSON, except that JSON.stringify writes -0 as 0. -0 is
 * stored as the string NUL "-0", and every string that starts with NUL gets one more NUL in front,
 * so no stored string can be read back as -0, and reading takes the added NUL away again. The
 * entry's hash is over canonical JSON, which writes -0 as 0, so it is the same either way.
 */
const NEGATIVE_ZERO = "\u0000-0";
const toStored = (value: unknown): string =>
  JSON.stringify(value, (_key, v: unknown) => (Object.is(v, -0) ? NEGATIVE_ZERO : typeof v === "string" && v.startsWith("\u0000") ? `\u0000${v}` : v));
const fromStored = <T>(text: unknown): T =>
  JSON.parse(text as string, (_key, v: unknown) => (typeof v === "string" && v.startsWith("\u0000") ? (v === NEGATIVE_ZERO ? -0 : v.slice(1)) : v)) as T;

/**
 * Runs `body` in a write transaction: committed if it returns, rolled back if it throws. SQLite may
 * have rolled the transaction back already (SQLITE_FULL, a trigger's RAISE(ROLLBACK)), and a
 * ROLLBACK then would throw and hide why; and if the ROLLBACK itself fails, the error that caused
 * it is still the one thrown.
 */
function writeTransaction<T>(db: DatabaseSync, body: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = body();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    if (db.isTransaction) {
      try {
        db.exec("ROLLBACK");
      } catch {
        // The error that made the rollback necessary says more than the rollback's own.
      }
    }
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
        if (seen !== undefined) return fromStored<AuditEntry>(seen.entry);
      }
      const head = this.#head();
      // chainEntry refuses card data; the transaction is then rolled back with nothing stored.
      const entry = chainEntry(input, head.seq + 1, head.hash);
      this.#db
        .prepare("INSERT INTO audit_entries (seq, event_id, hash, entry) VALUES (?, ?, ?, ?)")
        .run(entry.seq, entry.eventId === undefined ? null : key(entry.eventId), entry.hash, toStored(entry));
      return entry;
    });
  }

  async head(): Promise<{ seq: number; hash: string }> {
    return this.#head();
  }

  /** One page: SQLite reads at most `limit` rows (LIMIT -1 is no limit). */
  async list(fromSeq = 1, limit?: number): Promise<AuditEntry[]> {
    if (limit !== undefined && !(Number.isSafeInteger(limit) && limit >= 1)) throw new TypeError("SqliteAuditLedger.list: limit must be an integer of 1 or more");
    return this.#db
      .prepare("SELECT entry FROM audit_entries WHERE seq >= ? ORDER BY seq LIMIT ?")
      .all(fromSeq, limit ?? -1)
      .map((row) => fromStored<AuditEntry>(row.entry));
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
      CREATE TABLE IF NOT EXISTS erased_records (
        workspace_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        PRIMARY KEY (workspace_id, record_id)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS subject_erasures (
        workspace_id TEXT NOT NULL,
        subject_key TEXT NOT NULL,
        erasures INTEGER NOT NULL,
        PRIMARY KEY (workspace_id, subject_key)
      ) STRICT;
    `);
  }

  /** Adds or replaces a subject: the host's own record, which the engine only reads. */
  putSubject(workspaceId: string, subject: SubjectRecord): void {
    this.#db
      .prepare("INSERT INTO subjects (workspace_id, subject_key, subject) VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET subject = excluded.subject")
      .run(key(workspaceId), key(subject.subjectKey), toStored(subject));
  }

  async getSubject(workspaceId: string, subjectKey: string): Promise<SubjectRecord | null> {
    const row = this.#db.prepare("SELECT subject FROM subjects WHERE workspace_id = ? AND subject_key = ?").get(key(workspaceId), key(subjectKey));
    return row === undefined ? null : fromStored<SubjectRecord>(row.subject);
  }

  async putIntakeRecord(record: IntakeRecord, erasuresSeen?: number): Promise<void> {
    // One statement, so the checks and the insert are one atomic step against every connection: a
    // deleted id stays deleted, and a record reserved before its subject's latest erasure stores
    // nothing. A record under no subject, or written without `erasuresSeen`, is not guarded.
    const guarded = erasuresSeen !== undefined && record.subjectKey !== null;
    this.#db
      .prepare(
        "INSERT INTO intake_records (workspace_id, record_id, record) SELECT ?, ?, ?" +
          " WHERE NOT EXISTS (SELECT 1 FROM erased_records WHERE workspace_id = ? AND record_id = ?)" +
          " AND (? = 0 OR COALESCE((SELECT erasures FROM subject_erasures WHERE workspace_id = ? AND subject_key = ?), 0) <= ?)" +
          " ON CONFLICT DO NOTHING",
      )
      .run(
        key(record.workspaceId),
        key(record.recordId),
        toStored(record),
        key(record.workspaceId),
        key(record.recordId),
        guarded ? 1 : 0,
        key(record.workspaceId),
        key(record.subjectKey ?? ""),
        guarded ? erasuresSeen : 0,
      );
  }

  async getIntakeRecord(workspaceId: string, recordId: string): Promise<IntakeRecord | null> {
    const row = this.#db.prepare("SELECT record FROM intake_records WHERE workspace_id = ? AND record_id = ?").get(key(workspaceId), key(recordId));
    return row === undefined ? null : fromStored<IntakeRecord>(row.record);
  }

  // Subject requests (PRV-7).
  async listIntakeRecords(workspaceId: string, subjectKey: string): Promise<IntakeRecord[]> {
    const rows = this.#db.prepare("SELECT record FROM intake_records WHERE workspace_id = ?").all(key(workspaceId));
    return rows.map((row) => fromStored<IntakeRecord>(row.record)).filter((r) => r.subjectKey === subjectKey);
  }

  async deleteIntakeRecords(workspaceId: string, recordIds: readonly string[]): Promise<void> {
    for (const recordId of recordIds) {
      this.#db.prepare("INSERT INTO erased_records (workspace_id, record_id) VALUES (?, ?) ON CONFLICT DO NOTHING").run(key(workspaceId), key(recordId));
      this.#db.prepare("DELETE FROM intake_records WHERE workspace_id = ? AND record_id = ?").run(key(workspaceId), key(recordId));
    }
  }

  async markSubjectErased(workspaceId: string, subjectKey: string): Promise<void> {
    // One statement: two erasures at once, from any connection, count two.
    this.#db
      .prepare("INSERT INTO subject_erasures (workspace_id, subject_key, erasures) VALUES (?, ?, 1) ON CONFLICT DO UPDATE SET erasures = erasures + 1")
      .run(key(workspaceId), key(subjectKey));
  }

  async subjectErasures(workspaceId: string, subjectKey: string): Promise<number> {
    const row = this.#db.prepare("SELECT erasures FROM subject_erasures WHERE workspace_id = ? AND subject_key = ?").get(key(workspaceId), key(subjectKey));
    return row === undefined ? 0 : (row.erasures as number);
  }

  async deletePinDigest(workspaceId: string, subjectKey: string): Promise<void> {
    this.#update(workspaceId, subjectKey, (subject) => {
      delete subject.pinDigest;
      // The enrolment id names the digest's enrolment, and goes with it, as on a reset.
      delete subject.pinEnrolmentId;
      // The duress PIN is a PIN too: left alone, it would still pass for the subject (VER-12).
      delete subject.duressDigest;
      return true;
    });
  }

  // PIN (VER-6) and duress PIN (VER-12) writes: each reads and writes the subject in one immediate
  // transaction, so two processes on the file never both pass the check.

  async putPinDigest(workspaceId: string, subjectKey: string, digest: string | null, enrolmentId?: string): Promise<boolean> {
    return this.#update(workspaceId, subjectKey, (subject) => {
      if (digest === null) {
        delete subject.pinDigest;
        delete subject.pinEnrolmentId;
        delete subject.duressDigest;
        return true;
      }
      if (subject.pinDigest !== undefined) return false;
      subject.pinDigest = digest;
      if (enrolmentId !== undefined) subject.pinEnrolmentId = enrolmentId;
      return true;
    });
  }

  async putDuressDigest(workspaceId: string, subjectKey: string, digest: string | null, ifPinDigest?: string): Promise<boolean> {
    return this.#update(workspaceId, subjectKey, (subject) => {
      if (digest === null) {
        delete subject.duressDigest;
        return true;
      }
      if (subject.pinDigest !== ifPinDigest) return false;
      subject.duressDigest = digest;
      return true;
    });
  }

  #update(workspaceId: string, subjectKey: string, change: (subject: SubjectRecord) => boolean): boolean {
    return writeTransaction(this.#db, () => {
      const row = this.#db.prepare("SELECT subject FROM subjects WHERE workspace_id = ? AND subject_key = ?").get(key(workspaceId), key(subjectKey));
      const subject = row === undefined ? null : fromStored<SubjectRecord>(row.subject);
      const changed = subject !== null && change(subject);
      if (changed) {
        this.#db.prepare("UPDATE subjects SET subject = ? WHERE workspace_id = ? AND subject_key = ?").run(toStored(subject), key(workspaceId), key(subjectKey));
      }
      return changed;
    });
  }
}

/** Both stores on one database file, and a `close` for the connection, which is closed if either store's schema fails. */
export function openSqliteStores(path: string): { records: SqliteRecordStore; ledger: SqliteAuditLedger; close(): void } {
  const db = openSqliteDatabase(path);
  try {
    return { records: new SqliteRecordStore(db), ledger: new SqliteAuditLedger(db), close: () => db.close() };
  } catch (error) {
    db.close();
    throw error;
  }
}
