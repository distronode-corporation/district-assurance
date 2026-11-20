// A worker thread that opens a new database file, for test/sqlite-stores-contention.test.ts. Its
// first close of a descriptor (the one openSqliteDatabase opened to create the file) waits until
// the test thread says go, so the test can open the same path on its own connection, and take its
// locks, while this thread holds that descriptor. The test thread is told which path the descriptor
// was opened on, and whether the database path existed then.
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { parentPort, workerData } from "node:worker_threads";

import { openSqliteDatabase } from "../../examples/reference-server/src/sqlite-stores.ts";

export type CreatorMessage =
  | { step: "holding"; openedPath: string; dbPathExisted: boolean }
  | { step: "opened" }
  | { step: "done"; error?: string };

const port = parentPort!;
const { path, gate } = workerData as { path: string; gate: SharedArrayBuffer };
const say = (message: CreatorMessage) => port.postMessage(message);
const flag = new Int32Array(gate);

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
    // Bounded, so a broken test fails instead of hanging.
    Atomics.wait(flag, 0, 0, 30_000);
  }
  realClose(fd);
};
syncBuiltinESMExports();

try {
  const db = openSqliteDatabase(path);
  say({ step: "opened" });
  // Held open until the test thread has checked its own locks.
  Atomics.wait(flag, 0, 1, 30_000);
  db.close();
  say({ step: "done" });
} catch (error) {
  say({ step: "done", error: String(error) });
}
