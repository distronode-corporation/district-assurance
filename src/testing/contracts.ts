// Contract suites: the guarantees a host's durable adapter must keep, written once and run
// against any implementation. Each suite returns its cases as plain async functions, so a host
// runs them under whatever test runner it uses (node:test, vitest, jest):
//
//   for (const c of sessionStoreContract(() => new MyDatabaseSessionStore(...))) it(c.name, c.run);
import { strict as assert } from "node:assert";

import type { AttemptCounterKey, AttemptCounters, SessionStore } from "../core/adapters.ts";

export interface ContractCase {
  name: string;
  run(): Promise<void>;
}

/** The SessionStore contract (INT-3). `factory` returns a new, empty store for each case. */
export function sessionStoreContract(factory: () => SessionStore | Promise<SessionStore>): ContractCase[] {
  const cases: Array<[string, (store: SessionStore) => Promise<void>]> = [
    [
      "creates a session at version 1 and returns copies",
      async (store) => {
        const record = { phase: "open", items: [1] };
        assert.equal(await store.create("w", "c1", record), true);
        record.items.push(2);
        const got = await store.get("w", "c1");
        assert.deepEqual(got, { version: 1, record: { phase: "open", items: [1] } });
        (got!.record as { items: number[] }).items.push(3);
        assert.deepEqual((await store.get("w", "c1"))!.record, { phase: "open", items: [1] });
      },
    ],
    [
      "refuses to create a session that exists, and keeps the first",
      async (store) => {
        await store.create("w", "c1", { n: 1 });
        assert.equal(await store.create("w", "c1", { n: 2 }), false);
        assert.deepEqual(await store.get("w", "c1"), { version: 1, record: { n: 1 } });
      },
    ],
    [
      "keeps workspaces apart and answers null for an unknown session",
      async (store) => {
        await store.create("w1", "c1", { n: 1 });
        assert.equal(await store.get("w2", "c1"), null);
        assert.equal(await store.get("w1", "c2"), null);
        assert.equal(await store.create("w2", "c1", { n: 2 }), true);
        assert.deepEqual((await store.get("w1", "c1"))!.record, { n: 1 });
      },
    ],
    [
      "writes only on the expected version, one version at a time",
      async (store) => {
        await store.create("w", "c1", { n: 1 });
        assert.deepEqual(await store.compareAndSet("w", "c1", 1, { n: 2 }), { ok: true, version: 2 });
        assert.deepEqual(await store.compareAndSet("w", "c1", 1, { n: 3 }), { ok: false });
        assert.deepEqual(await store.get("w", "c1"), { version: 2, record: { n: 2 } });
        assert.deepEqual(await store.compareAndSet("w", "c1", 2, { n: 3 }), { ok: true, version: 3 });
        assert.deepEqual(await store.compareAndSet("w", "missing", 1, { n: 1 }), { ok: false });
        assert.deepEqual(await store.compareAndSet("w2", "c1", 3, { n: 9 }), { ok: false });
      },
    ],
    [
      "lets exactly one of two concurrent writers on the same version win",
      async (store) => {
        await store.create("w", "c1", { n: 0 });
        const results = await Promise.all([store.compareAndSet("w", "c1", 1, { n: 1 }), store.compareAndSet("w", "c1", 1, { n: 2 })]);
        assert.equal(results.filter((r) => r.ok).length, 1);
        const stored = await store.get("w", "c1");
        assert.equal(stored!.version, 2);
        assert.equal((stored!.record as { n: number }).n, results.findIndex((r) => r.ok) + 1, "the stored record is the winner's");
      },
    ],
    [
      "never lets two workspace and call id pairs share a key",
      async (store) => {
        assert.equal(await store.create("north", "branch/c1", { n: 1 }), true);
        assert.equal(await store.create("north/branch", "c1", { n: 2 }), true);
        assert.deepEqual((await store.get("north", "branch/c1"))!.record, { n: 1 });
        assert.deepEqual((await store.get("north/branch", "c1"))!.record, { n: 2 });
        assert.equal(await store.bindRef("a", "b/c", "c1"), true);
        assert.equal(await store.resolveRef("a/b", "c"), null);
      },
    ],
    [
      "binds a reference once, per workspace, and resolves it",
      async (store) => {
        assert.equal(await store.resolveRef("w", "payment:cs_1"), null);
        assert.equal(await store.bindRef("w", "payment:cs_1", "c1"), true);
        assert.equal(await store.bindRef("w", "payment:cs_1", "c2"), false);
        assert.equal(await store.resolveRef("w", "payment:cs_1"), "c1");
        assert.equal(await store.resolveRef("w2", "payment:cs_1"), null);
      },
    ],
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body(await factory()) }));
}

const T0 = "2026-01-01T00:00:00.000Z";
const at = (seconds: number): string => new Date(Date.parse(T0) + seconds * 1000).toISOString();
const counter = (patch: Partial<AttemptCounterKey> = {}): AttemptCounterKey => ({ workspaceId: "w", factor: "pin", scope: "subject", key: "a".repeat(64), ...patch });

/** The AttemptCounters contract (VER-1). `factory` returns a new, empty store for each case. */
export function attemptCountersContract(factory: () => AttemptCounters | Promise<AttemptCounters>): ContractCase[] {
  const cases: Array<[string, (store: AttemptCounters) => Promise<void>]> = [
    [
      "starts empty, and returns each failure in the order recorded, the new one last",
      async (store) => {
        assert.deepEqual(await store.get(counter(), T0), []);
        assert.deepEqual(await store.recordFailure(counter(), at(1), T0), [at(1)]);
        assert.deepEqual(await store.recordFailure(counter(), at(1), T0), [at(1), at(1)], "two failures at the same instant are two");
        assert.deepEqual(await store.recordFailure(counter(), at(7), T0), [at(1), at(1), at(7)]);
        assert.deepEqual(await store.get(counter(), T0), [at(1), at(1), at(7)]);
      },
    ],
    [
      "returns only failures at or after since",
      async (store) => {
        await store.recordFailure(counter(), at(0), T0);
        await store.recordFailure(counter(), at(10), T0);
        assert.deepEqual(await store.get(counter(), at(10)), [at(10)]);
        assert.deepEqual(await store.recordFailure(counter(), at(20), at(5)), [at(10), at(20)]);
        assert.deepEqual(await store.get(counter(), at(21)), []);
      },
    ],
    [
      "keeps every part of the key apart: workspace, factor, scope and key",
      async (store) => {
        await store.recordFailure(counter(), at(1), T0);
        for (const other of [{ workspaceId: "w2" }, { factor: "keypad_knowledge" }, { scope: "number" as const }, { key: "b".repeat(64) }]) {
          assert.deepEqual(await store.get(counter(other), T0), [], JSON.stringify(other));
        }
        await store.recordFailure(counter({ workspaceId: "north", factor: "branch/pin" }), at(1), T0);
        assert.deepEqual(await store.get(counter({ workspaceId: "north/branch", factor: "pin" }), T0), [], "no two keys share an id");
      },
    ],
    [
      "resets one key and leaves the others",
      async (store) => {
        await store.recordFailure(counter(), at(1), T0);
        await store.recordFailure(counter({ scope: "number" }), at(1), T0);
        await store.reset(counter());
        await store.reset(counter({ key: "c".repeat(64) }));
        assert.deepEqual(await store.get(counter(), T0), []);
        assert.deepEqual(await store.get(counter({ scope: "number" }), T0), [at(1)]);
        assert.deepEqual(await store.recordFailure(counter(), at(2), T0), [at(2)], "counting starts again");
      },
    ],
    [
      "loses no failure to concurrent writers, and the last to record sees them all",
      async (store) => {
        const lists = await Promise.all(Array.from({ length: 10 }, () => store.recordFailure(counter(), at(1), T0)));
        assert.equal((await store.get(counter(), T0)).length, 10);
        assert.deepEqual(lists.map((l) => l.length).sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], "each writer sees the ones before it");
      },
    ],
    [
      "returns copies",
      async (store) => {
        const list = await store.recordFailure(counter(), at(1), T0);
        list.push(at(2));
        (await store.get(counter(), T0)).push(at(3));
        assert.deepEqual(await store.get(counter(), T0), [at(1)]);
      },
    ],
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body(await factory()) }));
}
