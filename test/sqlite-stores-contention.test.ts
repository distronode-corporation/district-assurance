// SRV-4 SQLite stores (#95) under real contention: a PIN enrolment and an append on one connection
// start while another connection holds the write lock (BEGIN IMMEDIATE) with its own write in it,
// and the lock is released only once the contender has begun its transaction or done a read. The
// contender runs in a worker thread (test/fixtures/sqlite-contender.ts), so it blocks inside SQLite
// while this thread releases; the two connections are coordinated by messages, never by sleeps.
// Without the transaction around the check, the contender reads the old state and writes over the
// winner's (or collides with its seq), and these tests fail.
import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import { Worker } from "node:worker_threads";

import { openSqliteDatabase, openSqliteStores } from "../examples/reference-server/src/sqlite-stores.ts";
import { GENESIS_HASH, chainEntry, type AuditEntry } from "../src/index.ts";
import { verifyChain } from "../src/prove/ledger.ts";
import type { ContenderMessage, ContenderTask } from "./fixtures/sqlite-contender.ts";
import type { CreatorMessage } from "./fixtures/sqlite-creator.ts";

const dir = realpathSync(mkdtempSync(join(tmpdir(), "da-sqlite-contend-")));
after(() => rmSync(dir, { recursive: true, force: true }));
let files = 0;
const newFile = () => join(dir, `contend-${++files}.db`);

const S = "s".repeat(64);
const subject = { subjectKey: S, phoneOnFile: "+15555550100", knowledge: { dob: "a".repeat(64) } };
const entry = (n: number, more: object = {}) => ({ callId: `call_${n}`, actor: "code" as const, event: "module.event" as const, at: "2026-01-01T00:00:00.000Z", detail: { n }, ...more });

/**
 * Holds the write lock on `path` with `hold`'s write in it, starts `task` on a worker's connection,
 * and commits at the worker's first transaction start or read. Resolves with the worker's answer.
 */
function contend(path: string, task: ContenderTask, hold: (db: ReturnType<typeof openSqliteDatabase>) => void): Promise<ContenderMessage & { step: "done" }> {
  const holder = openSqliteDatabase(path);
  const worker = new Worker(new URL("./fixtures/sqlite-contender.ts", import.meta.url), { workerData: { path, task } });
  const steps: string[] = [];
  return new Promise((resolve, reject) => {
    let done: (ContenderMessage & { step: "done" }) | undefined;
    worker.on("message", (message: ContenderMessage) => {
      steps.push(message.step);
      if (message.step === "ready") {
        holder.exec("BEGIN IMMEDIATE");
        hold(holder);
        worker.postMessage("go");
      } else if (message.step === "done") {
        done = message;
      } else if (holder.isTransaction) {
        holder.exec("COMMIT");
      }
    });
    worker.on("error", reject);
    worker.on("exit", () => {
      holder.close();
      if (done === undefined) reject(new Error(`the worker exited without an answer, after ${steps.join(", ")}`));
      else resolve(done);
    });
  });
}

describe("SQLite writes contending for the write lock across connections", { skip: process.platform === "win32" ? "file-backed storage is refused on Windows" : false, timeout: 60_000 }, () => {
  it("an enrolment started while another connection's enrolment holds the lock stores nothing, and the winner's digest keeps its enrolment id", async () => {
    const path = newFile();
    const stores = openSqliteStores(path);
    stores.records.putSubject("w", subject);
    const answer = await contend(path, { kind: "pin", workspaceId: "w", subjectKey: S, digest: "2".repeat(64), enrolmentId: "enr_b" }, (db) => {
      db.prepare("UPDATE subjects SET subject = ? WHERE workspace_id = ? AND subject_key = ?").run(
        JSON.stringify({ ...subject, pinDigest: "1".repeat(64), pinEnrolmentId: "enr_a" }),
        JSON.stringify("w"),
        JSON.stringify(S),
      );
    });
    assert.deepEqual(answer, { step: "done", result: false }, "the later enrolment replaces nothing");
    const kept = await stores.records.getSubject("w", S);
    assert.deepEqual([kept!.pinDigest, kept!.pinEnrolmentId], ["1".repeat(64), "enr_a"], "only the winner's digest and enrolment id");
    stores.close();
  });

  it("an append started while another connection's append holds the lock goes after it, on one chain", async () => {
    const path = newFile();
    const stores = openSqliteStores(path);
    const held = chainEntry(entry(1), 1, GENESIS_HASH);
    const answer = await contend(path, { kind: "append", input: entry(2) }, (db) => {
      db.prepare("INSERT INTO audit_entries (seq, event_id, hash, entry) VALUES (?, NULL, ?, ?)").run(held.seq, held.hash, JSON.stringify(held));
    });
    assert.equal(answer.error, undefined, answer.error);
    const appended = answer.result as AuditEntry;
    assert.deepEqual([appended.seq, appended.prevHash], [2, held.hash], "after the held entry, never a second seq 1");
    const stored = await stores.ledger.list();
    assert.deepEqual(stored, [held, appended]);
    assert.equal(verifyChain(stored).ok, true);
    stores.close();
  });

  it("an append of an eventId another connection's held append stores returns that entry, stored once", async () => {
    const path = newFile();
    const stores = openSqliteStores(path);
    const held = chainEntry(entry(1, { eventId: "same" }), 1, GENESIS_HASH);
    const answer = await contend(path, { kind: "append", input: entry(2, { eventId: "same" }) }, (db) => {
      db.prepare("INSERT INTO audit_entries (seq, event_id, hash, entry) VALUES (?, ?, ?, ?)").run(held.seq, JSON.stringify("same"), held.hash, JSON.stringify(held));
    });
    assert.deepEqual(answer, { step: "done", result: held }, "the first entry for the id, not an error");
    assert.deepEqual(await stores.ledger.list(), [held]);
    stores.close();
  });

  it("a thread creating the file never holds a descriptor on the database path that another connection has opened", async () => {
    // Closing any descriptor on a file drops every POSIX lock the process holds on it, so a
    // descriptor on the database path, closed after another connection opened it, would drop that
    // connection's locks. The worker pauses at that close while this thread opens the path.
    const path = newFile();
    const flag = new Int32Array(new SharedArrayBuffer(4));
    const worker = new Worker(new URL("./fixtures/sqlite-creator.ts", import.meta.url), { workerData: { path, gate: flag.buffer } });
    const messages: CreatorMessage[] = [];
    let ours: ReturnType<typeof openSqliteDatabase> | undefined;
    const release = (value: number) => {
      Atomics.store(flag, 0, value);
      Atomics.notify(flag, 0);
    };
    await new Promise<void>((resolve, reject) => {
      worker.on("message", (message: CreatorMessage) => {
        messages.push(message);
        try {
          if (message.step === "holding") {
            // The worker holds its creating descriptor open: this connection opens the path now.
            ours = openSqliteDatabase(path);
            ours.exec("CREATE TABLE IF NOT EXISTS t (x INTEGER) STRICT; BEGIN IMMEDIATE; INSERT INTO t VALUES (1);");
            release(1);
          } else if (message.step === "opened") {
            ours!.exec("COMMIT");
            release(2);
          }
        } catch (error) {
          release(2);
          reject(error as Error);
        }
      });
      worker.on("error", reject);
      worker.on("exit", () => resolve());
    });
    ours?.close();
    const [holding, opened, done] = messages;
    assert.equal(holding?.step, "holding");
    assert.equal(holding!.step === "holding" && holding!.dbPathExisted, false, "the database path did not exist while the worker held its descriptor");
    assert.notEqual(holding!.step === "holding" && holding!.openedPath, path, "the descriptor was never on the database path");
    assert.deepEqual([opened, done], [{ step: "opened" }, { step: "done" }], "the worker opened the file this thread created, by the existing-file check");
    const reader = openSqliteDatabase(path);
    assert.deepEqual(reader.prepare("SELECT x FROM t").all().map((row) => row.x), [1], "one database, with this thread's write");
    reader.close();
    assert.deepEqual(readdirSync(dir).filter((name) => !name.startsWith("contend-")), [], "no temporary directory left behind");
  });
});
