// A second connection, in a worker thread, for test/sqlite-stores-contention.test.ts. Its database
// handle tells the test thread when it is about to begin a transaction and when each read has
// returned, so the test can release its own write lock at a known point, without a sleep: the
// worker blocks inside SQLite while it waits, and the test thread is free to answer.
import { once } from "node:events";
import { DatabaseSync } from "node:sqlite";
import { parentPort, workerData } from "node:worker_threads";

import { SQLITE_BUSY_TIMEOUT_MS, SqliteAuditLedger, SqliteRecordStore } from "../../examples/reference-server/src/sqlite-stores.ts";
import type { AuditInput } from "../../src/index.ts";

export type ContenderTask =
  | { kind: "pin"; workspaceId: string; subjectKey: string; digest: string; enrolmentId: string }
  | { kind: "append"; input: AuditInput };

export type ContenderMessage = { step: "ready" } | { step: "begin" } | { step: "read" } | { step: "done"; result?: unknown; error?: string };

const port = parentPort!;
const { path, task } = workerData as { path: string; task: ContenderTask };
const say = (message: ContenderMessage) => port.postMessage(message);

const real = new DatabaseSync(path, { timeout: SQLITE_BUSY_TIMEOUT_MS });
const bound = (target: object, prop: string | symbol): unknown => {
  const value: unknown = Reflect.get(target, prop);
  return typeof value === "function" ? value.bind(target) : value;
};
const db = new Proxy(real, {
  get(target, prop) {
    if (prop === "exec") {
      return (sql: string) => {
        if (sql.startsWith("BEGIN")) say({ step: "begin" });
        target.exec(sql);
      };
    }
    if (prop === "prepare") {
      return (sql: string) =>
        new Proxy(target.prepare(sql), {
          get(statement, p) {
            if (p !== "get") return bound(statement, p);
            return (...args: Parameters<typeof statement.get>) => {
              const row = statement.get(...args);
              say({ step: "read" });
              return row;
            };
          },
        });
    }
    return bound(target, prop);
  },
});

try {
  // The stores are built (their schema statements run) before the test thread takes its lock.
  let run: () => Promise<unknown>;
  if (task.kind === "pin") {
    const records = new SqliteRecordStore(db);
    run = () => records.putPinDigest(task.workspaceId, task.subjectKey, task.digest, task.enrolmentId);
  } else {
    const ledger = new SqliteAuditLedger(db);
    run = () => ledger.append(task.input);
  }
  say({ step: "ready" });
  await once(port, "message");
  say({ step: "done", result: await run() });
} catch (error) {
  say({ step: "done", error: String(error) });
} finally {
  real.close();
}
