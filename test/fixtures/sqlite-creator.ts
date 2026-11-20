// A worker thread that opens a new database file, for test/sqlite-stores-contention.test.ts. Its
// first close of a descriptor (the one openSqliteDatabase opened to create the file) waits until
// the test thread says go, so the test can open the same path on its own connection, and take its
// locks, while this thread holds that descriptor. The test thread is told which path the descriptor
// was opened on, and whether the database path existed then.
//
// The gate's phases: 0 while the worker holds its descriptor, 1 once the test thread has opened the
// path, 2 once it has committed. A wait that times out, or wakes to another phase, closes what the
// worker holds and fails through `done`, so the test cannot pass without the two opens overlapping.
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { parentPort, workerData } from "node:worker_threads";

import { openSqliteDatabase } from "../../examples/reference-server/src/sqlite-stores.ts";

export type CreatorMessage =
  | { step: "holding"; openedPath: string; dbPathExisted: boolean }
  | { step: "opened" }
  | { step: "done"; error?: string };

const port = parentPort!;
const { path, gate, waitMs = 30_000 } = workerData as { path: string; gate: SharedArrayBuffer; waitMs?: number };
const say = (message: CreatorMessage) => port.postMessage(message);
const flag = new Int32Array(gate);

/**
 * Waits while the gate is at `from`, then requires `to`. A release that arrived before the wait
 * ("not-equal") is fine, as long as it is `to`. Bounded, so a broken test fails instead of hanging.
 */
function waitFor(from: number, to: number): void {
  const result = Atomics.wait(flag, 0, from, waitMs);
  const phase = Atomics.load(flag, 0);
  if (result === "timed-out") throw new Error(`the gate timed out at phase ${phase}, waiting for ${to}`);
  if (phase !== to) throw new Error(`the gate is at phase ${phase}, not ${to}`);
}

const realOpen = fs.openSync;
const realClose = fs.closeSync;
const opened = new Map<number, string>();
let paused = false;
fs.openSync = ((file: fs.PathLike, flags: fs.OpenMode, mode?: fs.Mode) => {
  const fd = realOpen(file, flags, mode);
  opened.set(fd, String(file));
  return fd;
}) as typeof fs.openSync;
fs.closeSync = (fd: number) => {
  if (!paused) {
    paused = true;
    say({ step: "holding", openedPath: opened.get(fd)!, dbPathExisted: fs.existsSync(path) });
    try {
      waitFor(0, 1);
    } catch (error) {
      // The descriptor is closed, and the create fails with the gate's error.
      realClose(fd);
      throw error;
    }
  }
  realClose(fd);
};
syncBuiltinESMExports();

try {
  const db = openSqliteDatabase(path);
  say({ step: "opened" });
  // Held open until the test thread has checked its own locks.
  try {
    waitFor(1, 2);
  } finally {
    db.close();
  }
  say({ step: "done" });
} catch (error) {
  say({ step: "done", error: String(error) });
}
