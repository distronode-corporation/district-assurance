// SRV-4 SQLite stores under attack (a hostile pass on #95): file modes, hostile input checked
// against the memory stores, and races and faults across connections. Each pins safe behaviour.
import { strict as assert } from "node:assert";
import fs, { chmodSync, closeSync, existsSync, linkSync, mkdirSync, mkdtempSync, openSync, readdirSync, readlinkSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { after, describe, it, mock } from "node:test";

import { SqliteAuditLedger, SqliteRecordStore, openSqliteDatabase, openSqliteStores } from "../examples/reference-server/src/sqlite-stores.ts";
import { MemoryAuditLedger, verifyChain } from "../src/prove/ledger.ts";
import { MemoryRecordStore } from "../src/testing/index.ts";

// The real path: SQLite and /proc name files by it.
const dir = realpathSync(mkdtempSync(join(tmpdir(), "da-sqlite-attack-")));
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
const onFile = { skip: process.platform === "win32" ? "file-backed storage is refused on Windows" : false };

type FsCall = { fn: string; path: string; flags?: unknown };
const SPIED = ["openSync", "closeSync", "linkSync", "lstatSync", "mkdtempSync", "rmSync", "rmdirSync"] as const;

/**
 * Spies on the fs functions sqlite-stores.ts imports, for the length of `body`. Each call is recorded
 * with the path it acts on (a close with the path its descriptor was opened on, a link with the new
 * name), then `hook` may throw in its place, then the real function runs.
 */
function spyOnFs<T>(body: (calls: FsCall[]) => T, hook?: (call: FsCall) => void): T {
  const calls: FsCall[] = [];
  const opened = new Map<number, string>();
  const spies = SPIED.map((fn) => {
    const real = fs[fn] as (...args: unknown[]) => unknown;
    return mock.method(fs, fn, (...args: unknown[]) => {
      const call: FsCall =
        fn === "closeSync" ? { fn, path: opened.get(args[0] as number) ?? "?" } : fn === "linkSync" ? { fn, path: String(args[1]) } : fn === "openSync" ? { fn, path: String(args[0]), flags: args[1] } : { fn, path: String(args[0]) };
      calls.push(call);
      hook?.(call);
      const result = real(...args);
      if (fn === "openSync") opened.set(result as number, call.path);
      return result;
    });
  });
  syncBuiltinESMExports();
  try {
    return body(calls);
  } finally {
    for (const spy of spies) spy.mock.restore();
    syncBuiltinESMExports();
  }
}

/** The descriptors opened and closed, by path. */
const descriptorCalls = (calls: FsCall[]) => calls.filter((c) => c.fn === "openSync" || c.fn === "closeSync");
const fsError = (code: string, call: FsCall) => Object.assign(new Error(`${code}: refused by the test, ${call.fn} '${call.path}'`), { code });
/** The private creating directories openSqliteDatabase left in the test directory: none, always. */
const stagingLeft = () => readdirSync(dir).filter((name) => name.startsWith(".sqlite-create-"));

/** How many of this process's descriptors are open on `path` or its WAL and shared-memory files (Linux). */
const descriptorsOn = (path: string): number =>
  readdirSync("/proc/self/fd").filter((fd) => {
    try {
      return [path, `${path}-wal`, `${path}-shm`].includes(readlinkSync(`/proc/self/fd/${fd}`));
    } catch {
      return false;
    }
  }).length;

/** A connection whose ROLLBACK fails, as one can on an I/O error. */
function rollbackFails(db: DatabaseSync): DatabaseSync {
  return new Proxy(db, {
    get(target, prop) {
      if (prop === "exec") {
        return (sql: string) => {
          if (sql === "ROLLBACK") throw new Error("disk I/O error during rollback");
          target.exec(sql);
        };
      }
      const value: unknown = Reflect.get(target, prop);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

const entry = (n: number, more: object = {}) => ({ callId: `call_${n}`, actor: "code" as const, event: "module.event" as const, at: "2026-01-01T00:00:00.000Z", detail: { n }, ...more });

describe("attack: file modes", { skip: process.platform === "win32" }, () => {
  it("the WAL and shared-memory files SQLite creates beside the database are owner-only too", async () => {
    const path = newFile();
    // In WAL mode whatever SQLite this Node bundles (a build with the WAL-reset bug uses a rollback journal).
    const db = track(openSqliteDatabase(path, { sqliteVersion: "3.53.0" }));
    const stores = { ledger: new SqliteAuditLedger(db), records: new SqliteRecordStore(db) };
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

  it("a rollback journal left beside the database readable by others is refused too", () => {
    const path = newFile();
    track(openSqliteDatabase(path)).close();
    writeFileSync(`${path}-journal`, "", { mode: 0o644 });
    chmodSync(`${path}-journal`, 0o644);
    assert.throws(() => track(openSqliteDatabase(path)), /-journal.*readable or writable by others/);
  });

  it("an existing database file is never opened outside SQLite, since closing any descriptor on it drops SQLite's locks", async () => {
    const path = newFile();
    // Another connection in this process holds the file, mid-transaction, as a busy server's would.
    const holder = track(openSqliteStores(path));
    await holder.ledger.append(entry(1));
    const busy = track(openSqliteDatabase(path));
    busy.exec("BEGIN IMMEDIATE");
    const calls = spyOnFs((seen) => {
      track(openSqliteDatabase(path)).close();
      return seen;
    });
    busy.exec("ROLLBACK");
    assert.deepEqual(descriptorCalls(calls), [], "checked by path, with no descriptor of its own");
    assert.deepEqual(calls.map((c) => c.fn), ["lstatSync", "lstatSync", "lstatSync", "lstatSync"], "the file and its three sidecars, looked at by path");
    assert.equal(verifyChain(await holder.ledger.list()).ok, true);
  });

  it("a new database file is created owner-only in a private directory beside it and linked into place, so no descriptor is ever on its path", () => {
    const path = newFile();
    const calls = spyOnFs((seen) => {
      track(openSqliteDatabase(path)).close();
      return seen;
    });
    const descriptors = descriptorCalls(calls);
    assert.deepEqual(
      descriptors.filter((c) => c.path === path),
      [],
      "never opened or closed on the database path",
    );
    const [open, close] = descriptors;
    assert.equal(descriptors.length, 2);
    assert.deepEqual([open!.flags, close!.path], ["wx", open!.path], "created exclusively, and closed, under its private name");
    assert.equal(dirname(dirname(open!.path)), dir, "in a directory beside the database, on its filesystem");
    assert.ok(calls.findIndex((c) => c.fn === "closeSync") < calls.findIndex((c) => c.fn === "linkSync" && c.path === path), "closed before it is linked into place");
    assert.deepEqual(stagingLeft(), [], "the private name and its directory are removed");
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(statSync(path).nlink, 1, "one name, the database path");
  });

  it("a database file another process or thread creates between the check and the link is checked as an existing one", () => {
    const path = newFile();
    writeFileSync(path, "", { mode: 0o644 });
    chmodSync(path, 0o644);
    let first = true;
    // The first look by path finds nothing, as if the other process had not yet created the file.
    const calls = spyOnFs(
      (seen) => {
        assert.throws(() => track(openSqliteDatabase(path)), /readable or writable by others/);
        return seen;
      },
      (call) => {
        if (call.fn === "lstatSync" && call.path === path && first) {
          first = false;
          throw fsError("ENOENT", call);
        }
      },
    );
    assert.deepEqual(descriptorCalls(calls).filter((c) => c.path === path), [], "nothing opened on the database path");
    assert.ok(calls.some((c) => c.fn === "linkSync" && c.path === path), "the link found the file there (EEXIST)");
    assert.deepEqual(stagingLeft(), []);
    assert.equal(statSync(path).mode & 0o777, 0o644, "the other process's file is left as it is");
  });

  it("a create that fails partway leaves no private directory behind, and throws the failure's own error", () => {
    for (const [fn, code] of [["openSync", "EACCES"], ["linkSync", "EPERM"], ["mkdtempSync", "EACCES"]] as const) {
      const path = newFile();
      spyOnFs(
        () => assert.throws(() => openSqliteDatabase(path), { code }, fn),
        (call) => {
          if (call.fn === fn) throw fsError(code, call);
        },
      );
      assert.deepEqual(stagingLeft(), [], fn);
      assert.equal(existsSync(path), false, `${fn}: no database file`);
    }
  });

  it("a cleanup that fails keeps the error that made it necessary, and fails the open when nothing else did", () => {
    const failed = newFile();
    spyOnFs(
      () => assert.throws(() => openSqliteDatabase(failed), { code: "EPERM" }, "the link's error, not the cleanup's"),
      (call) => {
        if (call.fn === "linkSync") throw fsError("EPERM", call);
        if (call.fn === "rmdirSync") throw fsError("EBUSY", call);
      },
    );
    const path = newFile();
    spyOnFs(
      () => assert.throws(() => openSqliteDatabase(path), { code: "EBUSY" }, "a directory left behind is not ignored"),
      (call) => {
        if (call.fn === "rmdirSync") throw fsError("EBUSY", call);
      },
    );
    for (const left of stagingLeft()) rmSync(join(dir, left), { recursive: true, force: true });
  });

  it("a path in a missing directory, or under a file, fails with the filesystem's error", () => {
    assert.throws(() => openSqliteDatabase(join(dir, "missing", "x.db")), { code: "ENOENT" });
    const file = newFile();
    track(openSqliteDatabase(file)).close();
    assert.throws(() => openSqliteDatabase(join(file, "x.db")), { code: "ENOTDIR" });
  });

  it("a symlinked database path is refused, since SQLite would use the target's own WAL file", () => {
    const target = newFile();
    track(openSqliteDatabase(target)).close();
    writeFileSync(`${target}-wal`, "", { mode: 0o644 });
    chmodSync(`${target}-wal`, 0o644);
    const link = join(dir, `link-${++files}.db`);
    symlinkSync(target, link);
    assert.throws(() => track(openSqliteDatabase(link)), /symbolic link/);
    assert.equal(statSync(`${target}-wal`).size, 0, "the target's WAL was never written");
  });

  it("a symlinked WAL file, or a database path that is not a regular file, is refused", () => {
    const path = newFile();
    track(openSqliteDatabase(path)).close();
    const elsewhere = newFile();
    writeFileSync(elsewhere, "", { mode: 0o600 });
    symlinkSync(elsewhere, `${path}-wal`);
    assert.throws(() => track(openSqliteDatabase(path)), /-wal is a symbolic link/);
    const directory = join(dir, `dir-${++files}.db`);
    mkdirSync(directory, { mode: 0o700 });
    assert.throws(() => track(openSqliteDatabase(directory)), /not a regular file/);
  });

  it("a path through a symbolic link and '..' is staged in the directory it resolves to, on the database's filesystem", () => {
    const data = join(dir, `data-${++files}`);
    mkdirSync(join(data, "releases"), { recursive: true, mode: 0o700 });
    const config = join(dir, `config-${++files}`);
    mkdirSync(config, { mode: 0o700 });
    symlinkSync(join(data, "releases"), join(config, "current"));
    // Not join(): it would take `current/..` away before the filesystem resolves the link.
    const path = `${config}/current/../store.db`;
    const calls = spyOnFs((seen) => {
      track(openSqliteDatabase(path)).close();
      return seen;
    });
    const staging = calls.find((c) => c.fn === "mkdtempSync");
    assert.equal(dirname(staging!.path), data, "staged beside the file the path names, not beside its lexical parent");
    assert.equal(statSync(join(data, "store.db")).mode & 0o777, 0o600);
    assert.equal(existsSync(join(config, "store.db")), false);
    assert.deepEqual(readdirSync(data).filter((name) => name.startsWith(".sqlite-create-")), []);
  });

  it("a database file with a second hard link is refused, by either name, since SQLite keeps a WAL per name", () => {
    const path = newFile();
    track(openSqliteDatabase(path)).close();
    const alias = newFile();
    linkSync(path, alias);
    assert.throws(() => track(openSqliteDatabase(path)), /hard link/);
    assert.throws(() => track(openSqliteDatabase(alias)), /hard link/);
    // A second link in a private creating directory that is not the file is still an alias.
    const staging = mkdtempSync(join(dir, ".sqlite-create-"));
    writeFileSync(join(staging, "database"), "", { mode: 0o600 });
    assert.throws(() => track(openSqliteDatabase(path)), /hard link/);
    rmSync(staging, { recursive: true });
    rmSync(alias);
    track(openSqliteDatabase(path)).close();
  });

  it("a database file another opener has linked into place, before it removes its private name, opens", () => {
    const path = newFile();
    track(openSqliteDatabase(path)).close();
    // Another process's create, between its link and the unlink of its private name.
    const staging = mkdtempSync(join(dir, ".sqlite-create-"));
    linkSync(path, join(staging, "database"));
    assert.equal(statSync(path).nlink, 2);
    track(openSqliteDatabase(path)).close();
    // And when the private name goes between this opener's look at the file and its look beside it.
    spyOnFs(
      () => track(openSqliteDatabase(path)).close(),
      (call) => {
        if (call.fn === "lstatSync" && call.path === join(staging, "database")) rmSync(staging, { recursive: true, force: true });
      },
    );
    assert.equal(existsSync(staging), false);
    assert.equal(statSync(path).nlink, 1);
  });
});

describe("attack: the database's directory", onFile, () => {
  it("a directory group or others can write is refused, since an entry there could be swapped between the checks and SQLite's open", () => {
    for (const mode of [0o770, 0o707]) {
      const sub = join(dir, `open-${++files}`);
      mkdirSync(sub, { mode: 0o700 });
      chmodSync(sub, mode);
      assert.throws(() => track(openSqliteDatabase(join(sub, "x.db"))), /writable by group or others/, mode.toString(8));
      assert.equal(existsSync(join(sub, "x.db")), false, "nothing created there");
      chmodSync(sub, 0o700);
      track(openSqliteDatabase(join(sub, "x.db"))).close();
    }
  });

  it("an ancestor others can write is refused, unless it has the sticky bit (as /tmp has)", () => {
    const outer = join(dir, `outer-${++files}`);
    mkdirSync(join(outer, "inner"), { recursive: true, mode: 0o700 });
    chmodSync(outer, 0o777);
    assert.throws(() => track(openSqliteDatabase(join(outer, "inner", "x.db"))), /writable by others without the sticky bit/);
    chmodSync(outer, 0o1777);
    track(openSqliteDatabase(join(outer, "inner", "x.db"))).close();
    chmodSync(outer, 0o700);
  });

  it("a directory in /tmp, which is sticky, opens", { skip: !existsSync("/tmp") || (statSync("/tmp").mode & 0o1002) !== 0o1002 ? "no sticky, world-writable /tmp" : false }, () => {
    const sticky = mkdtempSync("/tmp/da-sqlite-sticky-");
    try {
      track(openSqliteDatabase(join(sticky, "x.db"))).close();
    } finally {
      rmSync(sticky, { recursive: true, force: true });
    }
  });

  it("a directory another user owns is refused; where there are no user ids, ownership is not checked", () => {
    const sub = join(dir, `owned-${++files}`);
    mkdirSync(sub, { mode: 0o700 });
    const getuid = Object.getOwnPropertyDescriptor(process, "getuid")!;
    Object.defineProperty(process, "getuid", { ...getuid, value: () => statSync(sub).uid + 1 });
    try {
      assert.throws(() => track(openSqliteDatabase(join(sub, "x.db"))), /owned by another user/);
      Object.defineProperty(process, "getuid", { ...getuid, value: undefined });
      track(openSqliteDatabase(join(sub, "x.db"))).close();
    } finally {
      Object.defineProperty(process, "getuid", getuid);
    }
  });
});

describe("attack: the journal mode follows the SQLite build (the WAL-reset bug)", onFile, () => {
  const journalMode = (db: DatabaseSync) => db.prepare("PRAGMA journal_mode").get()!.journal_mode;

  it("WAL only on a build with the fix (3.51.3 and later, or the 3.44.6 and 3.50.7 backports); rollback journaling otherwise", () => {
    const cases: [string, string][] = [
      ["3.50.0", "delete"],
      ["3.50.6", "delete"],
      ["3.51.2", "delete"],
      ["3.52.0", "delete"],
      ["3.44.5", "delete"],
      ["3.45.0", "delete"],
      ["not a version", "delete"],
      ["3.51.3", "wal"],
      ["3.53.0", "wal"],
      ["3.44.6", "wal"],
      ["3.50.7", "wal"],
      ["3.100.0", "wal"],
      ["4.0.0", "wal"],
    ];
    for (const [sqliteVersion, mode] of cases) {
      const db = track(openSqliteDatabase(newFile(), { sqliteVersion }));
      assert.equal(journalMode(db), mode, sqliteVersion);
      db.close();
    }
  });

  it("a database left in WAL mode is moved to rollback journaling by an affected build", () => {
    const path = newFile();
    const fixed = track(openSqliteDatabase(path, { sqliteVersion: "3.53.0" }));
    fixed.exec("CREATE TABLE t (x INTEGER) STRICT; INSERT INTO t VALUES (1);");
    fixed.close();
    const affected = track(openSqliteDatabase(path, { sqliteVersion: "3.50.0" }));
    assert.equal(journalMode(affected), "delete");
    assert.deepEqual(affected.prepare("SELECT x FROM t").all().map((row) => row.x), [1]);
    affected.close();
  });

  it("an in-memory database opens on any build", () => {
    for (const sqliteVersion of ["3.50.0", "3.53.0"]) {
      const db = openSqliteDatabase(":memory:", { sqliteVersion });
      assert.equal(journalMode(db), "memory");
      db.close();
    }
  });
});

describe("attack: Windows", () => {
  it("file-backed storage is refused on Windows, where an owner-only mode sets no ACL; an in-memory database still opens", () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
    Object.defineProperty(process, "platform", { ...platform, value: "win32" });
    try {
      const path = newFile();
      assert.throws(() => openSqliteDatabase(path), /refuses a database file on Windows/);
      assert.throws(() => openSqliteStores(path), /refuses a database file on Windows/);
      assert.equal(existsSync(path), false, "no file created");
      openSqliteDatabase(":memory:").close();
    } finally {
      Object.defineProperty(process, "platform", platform);
    }
  });
});

describe("attack: a failed open leaks no connection", { skip: process.platform !== "linux" ? "counts descriptors in /proc" : false }, () => {
  it("a file that is not a database is refused, and its connection closed", () => {
    const path = newFile();
    writeFileSync(path, "x".repeat(4096), { mode: 0o600 });
    assert.throws(() => openSqliteDatabase(path), /not a database/);
    assert.equal(descriptorsOn(path), 0);
  });

  it("a store whose schema cannot be created closes the connection, and the schema's error is the one thrown", () => {
    const path = newFile();
    const db = openSqliteDatabase(path);
    db.exec("CREATE VIEW audit_entries AS SELECT 1 AS seq");
    db.close();
    assert.throws(() => openSqliteStores(path), /cannot create BEFORE trigger on view/);
    assert.equal(descriptorsOn(path), 0);
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

  it("round-trips prototype keys, -0, large and tiny numbers, and keeps the chain valid after a restart", onFile, async () => {
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
    assert.equal(Object.is(listed[0]!.detail.neg, -0), true, "-0 stays -0, as in the memory ledger");
    assert.deepEqual(listed[0]!.detail, appended.detail);
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
  it("two connections appending one eventId at once store it once, and both get that entry", onFile, async () => {
    const path = newFile();
    const a = track(openSqliteStores(path));
    const b = track(openSqliteStores(path));
    const [x, y] = await Promise.all([a.ledger.append(entry(1, { eventId: "same" })), b.ledger.append(entry(2, { eventId: "same" }))]);
    assert.deepEqual(x, y);
    assert.equal((await a.ledger.list()).length, 1);
  });

  it("an append another connection's lock times out leaves nothing, and the next append continues the chain", onFile, async () => {
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

  it("-0 and strings that look like its stored form round-trip in entries and records, with the hash unchanged", onFile, async () => {
    const path = newFile();
    const stores = track(openSqliteStores(path));
    const tricky = { neg: -0, list: [-0, 0, "\u0000-0"], tag: "\u0000-0", escaped: "\u0000\u0000-0", nul: "\u0000", plain: "-0" };
    const appended = await stores.ledger.append(entry(1, { eventId: "neg", detail: tricky }));
    const values = { neg: -0, zero: 0, tag: "\u0000-0", nul: "\u0000x" };
    await stores.records.putIntakeRecord({ recordId: "r", workspaceId: "w", callId: "c", subjectKey: "s", formId: "f", formVersion: "1", values, digest: "c".repeat(64), confirmedBy: "keypad", confirmedAt: "2026-01-01T00:00:00.000Z" });
    stores.close();
    const again = track(openSqliteStores(path));
    const [listed] = await again.ledger.list();
    for (const got of [listed!, await again.ledger.append(entry(9, { eventId: "neg" }))]) {
      assert.equal(Object.is(got.detail.neg, -0), true);
      assert.equal(Object.is((got.detail.list as unknown[])[0], -0), true);
      assert.equal(Object.is((got.detail.list as unknown[])[1], 0), true);
      assert.deepEqual(got.detail, tricky);
      assert.equal(got.hash, appended.hash);
    }
    assert.equal(verifyChain([listed!]).ok, true);
    for (const record of [await again.records.getIntakeRecord("w", "r"), ...(await again.records.listIntakeRecords("w", "s"))]) {
      assert.equal(Object.is(record!.values.neg, -0), true);
      assert.equal(Object.is(record!.values.zero, 0), true);
      assert.deepEqual(record!.values, values);
    }
  });

  it("an append a trigger rolls back with its transaction (RAISE(ROLLBACK)) rejects with the trigger's error, not the rollback's", async () => {
    const db = openSqliteDatabase(":memory:");
    const ledger = new SqliteAuditLedger(db);
    db.exec("CREATE TRIGGER hostile BEFORE INSERT ON audit_entries BEGIN SELECT RAISE(ROLLBACK, 'rolled back by a trigger'); END");
    await assert.rejects(ledger.append(entry(1)), /rolled back by a trigger/);
    assert.equal(db.isTransaction, false);
    db.exec("DROP TRIGGER hostile");
    assert.equal((await ledger.append(entry(2))).seq, 1);
  });

  it("an append that fills the disk rejects with SQLite's error, rolled back, and the connection stays usable", async () => {
    const db = openSqliteDatabase(":memory:");
    const ledger = new SqliteAuditLedger(db);
    await ledger.append(entry(1));
    db.exec("PRAGMA max_page_count = 1");
    await assert.rejects(ledger.append(entry(2, { detail: { note: "x".repeat(100_000) } })), /database or disk is full/);
    assert.equal(db.isTransaction, false);
    db.exec("PRAGMA max_page_count = 1000000");
    assert.equal((await ledger.append(entry(3))).seq, 2);
  });

  it("a PIN write SQLite rolls back itself (disk full) rejects with SQLite's error, and the connection stays usable", async () => {
    const db = openSqliteDatabase(":memory:");
    const records = new SqliteRecordStore(db);
    records.putSubject("w", { subjectKey: "s", phoneOnFile: "+15555550100", knowledge: {} });
    db.exec("PRAGMA max_page_count = 1");
    await assert.rejects(records.putPinDigest("w", "s", "1".repeat(100_000)), /database or disk is full/);
    assert.equal(db.isTransaction, false);
    db.exec("PRAGMA max_page_count = 1000000");
    assert.equal(await records.putPinDigest("w", "s", "1".repeat(64)), true);
  });

  it("a rollback that fails too keeps the error that caused it", async () => {
    const ledger = new SqliteAuditLedger(rollbackFails(openSqliteDatabase(":memory:")));
    await assert.rejects(ledger.append(entry(1, { detail: { note: "4242 4242 4242 4242" } })), /never carry a card number/);
    const records = new SqliteRecordStore(rollbackFails(openSqliteDatabase(":memory:")));
    records.putSubject("w", { subjectKey: "s", phoneOnFile: "+15555550100", knowledge: {} });
    // A digest JSON cannot carry fails inside the transaction, as the subject is written.
    await assert.rejects(records.putPinDigest("w", "s", 1n as unknown as string), /BigInt/);
  });
});
