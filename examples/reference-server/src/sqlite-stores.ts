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
import { closeSync, linkSync, lstatSync, mkdtempSync, openSync, readdirSync, realpathSync, rmSync, rmdirSync, statSync, type Stats } from "node:fs";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { GENESIS_HASH, chainEntry, type AuditEntry, type AuditInput, type AuditLedger, type IntakeRecord, type RecordStore, type SubjectRecord } from "../../../src/index.ts";

/** How long a connection waits for another connection's write lock before it fails, in ms. */
export const SQLITE_BUSY_TIMEOUT_MS = 5_000;

/**
 * The SQLite versions with the fix for the WAL-reset bug (https://sqlite.org/wal.html#walresetbug):
 * in every version from 3.7.0 through 3.51.2, two connections on one file in WAL mode, in separate
 * threads or processes, writing or checkpointing at the same instant could corrupt the database.
 * 3.51.3 fixed it, and every later release has the fix except 3.52.0, which was withdrawn and is
 * counted as without it; 3.44.6 and 3.50.7 are backports of it. Per release line: [minor, the first
 * fixed patch].
 */
const WAL_RESET_BACKPORTS: readonly (readonly [number, number])[] = [
  [44, 6],
  [50, 7],
  [51, 3],
];

/**
 * Whether a SQLite build of `version` (as `sqlite_version()` gives it) has the WAL-reset fix. A
 * version that does not parse counts as one without it.
 */
export function sqliteHasWalResetFix(version: string): boolean {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (match === null) return false;
  const [major, minor, patch] = [Number(match[1]), Number(match[2]), Number(match[3])];
  if (major !== 3) return major > 3;
  if (minor === 52) return false;
  const line = WAL_RESET_BACKPORTS.find(([fixedMinor]) => fixedMinor === minor);
  return line === undefined ? minor > 51 : patch >= line[1];
}

/** Options for {@link openSqliteDatabase}. */
export type SqliteOpenOptions = {
  /**
   * The SQLite version the journal mode is chosen for, in place of the one this Node bundles
   * (`sqlite_version()`): a seam for tests of each choice. A host leaves it out.
   */
  sqliteVersion?: string;
};

/**
 * Opens (and creates, readable and writable by its owner only) a database file. On a SQLite build
 * with the WAL-reset fix (`sqliteHasWalResetFix`) the file is in WAL mode, so readers do not wait
 * for a writer; on an older build, such as the SQLite 3.50.0 that Node 24.2 bundles, it uses a
 * rollback journal (`journal_mode = DELETE`), which the bug does not touch, and a file left in WAL
 * mode is moved back to one. `":memory:"` opens a database that lives as long as the connection,
 * on any build. A `file:` URI is refused: SQLite would open the file the URI names, not the path
 * whose mode was set, so the database could be created readable by others. A file that already
 * exists readable or writable by group or others is refused too (the mode only applies when the
 * file is created), since its subjects and records would be readable to them, and so is a WAL,
 * shared-memory or rollback journal file left beside it (SQLite creates new ones with the database
 * file's mode, but keeps the mode of one that exists).
 *
 * The checks read entries by name and SQLite then opens the same names, so no other account may
 * be able to change an entry in between. That is a host requirement, enforced here before any file
 * is created or opened: the database's directory is owned by the current user and not writable by
 * group or others, and no directory above it is writable by others unless it has the sticky bit
 * (as /tmp has). Ownership is not checked where there are no user ids (no `process.getuid`).
 *
 * An existing file is checked by path and never opened here: on Linux and macOS, closing any
 * descriptor on a file drops every POSIX lock this process holds on it, including those of another
 * SQLite connection to it, which could then corrupt its WAL. A new file is created, exclusively
 * and owner-only, under a private name in a directory made in the directory the path resolves to
 * (so on its filesystem), closed there, and then linked into place: no descriptor is ever opened
 * or closed on the database path outside SQLite, even while another thread or process opens the
 * path. A symbolic link is refused, at the database path and beside it: SQLite follows it and uses
 * the target's WAL and shared-memory files, not the ones checked here. A file with a second hard
 * link is refused too, since SQLite names the WAL after the name it opens, and connections through
 * two names would keep two WALs for one database; the one second link allowed is another opener's
 * private name for a file it has just linked into place, which it removes next. Any other file
 * type (a directory, a FIFO) is refused too.
 *
 * POSIX only: on Windows a file is refused, since the owner-only mode sets no ACL there and the
 * file would be as readable as its directory makes it. There is no option to allow it; a Windows
 * host uses another store (or `":memory:"`, which keeps nothing across a restart).
 */
export function openSqliteDatabase(path: string, options: SqliteOpenOptions = {}): DatabaseSync {
  if (/^file:/i.test(path)) throw new Error("openSqliteDatabase takes a filesystem path, not a file: URI");
  if (path !== ":memory:") {
    if (process.platform === "win32") {
      throw new Error("openSqliteDatabase refuses a database file on Windows, where an owner-only mode sets no ACL: the file-backed stores are POSIX only, so a Windows host uses another store");
    }
    let info = lstatIfExists(path);
    const directory = assertPrivateDirectory(dirname(path));
    if (info === undefined) {
      createOwnerOnly(path, directory);
      info = lstatSync(path);
    }
    assertOwnerOnlyFile(path, info);
    if (info.nlink > 1) assertNoAlias(path, directory, info);
    for (const file of [`${path}-wal`, `${path}-shm`, `${path}-journal`]) {
      const sidecar = lstatIfExists(file);
      if (sidecar !== undefined) assertOwnerOnlyFile(file, sidecar);
    }
  }
  const db = new DatabaseSync(path, { timeout: SQLITE_BUSY_TIMEOUT_MS });
  try {
    const version = options.sqliteVersion ?? String(db.prepare("SELECT sqlite_version() AS version").get()!.version);
    const wal = sqliteHasWalResetFix(version);
    const mode = db.prepare(wal ? "PRAGMA journal_mode = WAL" : "PRAGMA journal_mode = DELETE").get()!.journal_mode;
    // SQLite answers with the mode it is in: a build with the bug never goes on in WAL mode.
    if (!wal && mode === "wal") throw new Error(`${path} is in WAL mode, which SQLite ${version} cannot use safely (the WAL-reset bug), and could not leave it while another connection had it open`);
  } catch (error) {
    // Not a database, or unreadable: the connection is closed (close cannot fail on an open
    // connection) and the reason thrown.
    db.close();
    throw error;
  }
  return db;
}

/**
 * The real path of `directory`, once it is checked: owned by the current user (where there are
 * user ids) and not writable by group or others, under ancestors that others cannot write, or
 * that have the sticky bit.
 */
function assertPrivateDirectory(directory: string): string {
  // The native realpath resolves `link/..` on the filesystem; the JS one takes it away by name first.
  const real = realpathSync.native(directory);
  const info = statSync(real);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (uid !== undefined && info.uid !== uid) throw new Error(`the database directory ${real} is owned by another user; keep the database in a directory the server's own user owns`);
  if ((info.mode & 0o022) !== 0) throw new Error(`the database directory ${real} is writable by group or others, who could swap a file between the checks and SQLite's open; make it owner-only (chmod 700) first`);
  for (let below = real, above = dirname(real); above !== below; below = above, above = dirname(above)) {
    const mode = statSync(above).mode;
    if ((mode & 0o002) !== 0 && (mode & 0o1000) === 0) throw new Error(`${above}, above the database directory, is writable by others without the sticky bit, so they could replace the directory; keep the database elsewhere`);
  }
  return real;
}

/**
 * Refuses a file with a second hard link, unless that link is another opener's private name for
 * it (a `.sqlite-create-*` directory beside it holding the same file), which that opener removes
 * once the file is in place. If the private name is gone by the time it is looked for, the file is
 * looked at again: one link then is the file alone.
 */
function assertNoAlias(path: string, directory: string, info: Stats): void {
  for (const name of readdirSync(directory)) {
    if (!name.startsWith(".sqlite-create-")) continue;
    const staged = lstatIfPresent(join(directory, name, "database"));
    if (staged !== undefined && staged.dev === info.dev && staged.ino === info.ino) return;
  }
  const again = lstatSync(path);
  if (again.dev === info.dev && again.ino === info.ino && again.nlink === 1) return;
  throw new Error(`the database file ${path} has another hard link, and SQLite would keep a separate WAL for each name; remove the other links first`);
}

/**
 * Creates an empty owner-only file at `path`, or leaves alone one another thread or process created
 * there first (the caller checks it as any existing file). The descriptor that creates it is on a
 * private name in a new owner-only directory in `directory` (the real path of the path's own
 * directory, so the link never crosses a filesystem), and is closed before the file is linked into
 * place; then the private name and directory are removed, also when a step fails.
 */
function createOwnerOnly(path: string, directory: string): void {
  const staging = mkdtempSync(join(directory, ".sqlite-create-"));
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

/** Like lstatIfExists, but a path under something that is not a directory counts as absent too. */
function lstatIfPresent(file: string): Stats | undefined {
  try {
    return lstatIfExists(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOTDIR") return undefined;
    throw error;
  }
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
      CREATE TABLE IF NOT EXISTS confirmed_records (
        workspace_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
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

  async confirmIntakeRecord(workspaceId: string, recordId: string): Promise<void> {
    // One statement: only a record the store holds is marked.
    this.#db
      .prepare(
        "INSERT INTO confirmed_records (workspace_id, record_id) SELECT workspace_id, record_id FROM intake_records WHERE workspace_id = ? AND record_id = ? ON CONFLICT DO NOTHING",
      )
      .run(key(workspaceId), key(recordId));
  }

  async isIntakeRecordConfirmed(workspaceId: string, recordId: string): Promise<boolean> {
    return this.#db.prepare("SELECT 1 FROM confirmed_records WHERE workspace_id = ? AND record_id = ?").get(key(workspaceId), key(recordId)) !== undefined;
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
    // One transaction: a failure part-way deletes none of them, and the erasure is asked again.
    writeTransaction(this.#db, () => {
      for (const recordId of recordIds) {
        this.#db.prepare("INSERT INTO erased_records (workspace_id, record_id) VALUES (?, ?) ON CONFLICT DO NOTHING").run(key(workspaceId), key(recordId));
        this.#db.prepare("DELETE FROM intake_records WHERE workspace_id = ? AND record_id = ?").run(key(workspaceId), key(recordId));
        this.#db.prepare("DELETE FROM confirmed_records WHERE workspace_id = ? AND record_id = ?").run(key(workspaceId), key(recordId));
      }
    });
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
