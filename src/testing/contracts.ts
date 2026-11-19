// Contract suites: the guarantees a host's durable adapter must keep, written once and run
// against any implementation. Each suite returns its cases as plain async functions, so a host
// runs them under whatever test runner it uses (node:test, vitest, jest):
//
//   for (const c of sessionStoreContract(() => new MyDatabaseSessionStore(...))) it(c.name, c.run);
import { strict as assert } from "node:assert";

import type { IntakeRecord, RecordStore, SessionStore } from "../core/adapters.ts";

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

/**
 * What a RecordStore must keep for subject erasures (PRV-7): a record reserved before an erasure
 * (its `erasuresSeen` older than the count) is never stored, one reserved after it is, and a deleted
 * id stays deleted. `factory` returns a new, empty store for each case.
 */
export function recordStoreErasureContract(factory: () => RecordStore | Promise<RecordStore>): ContractCase[] {
  const record = (recordId: string, subjectKey: string | null = "s1"): IntakeRecord => ({
    recordId, workspaceId: "w", callId: "c1", subjectKey, formId: "f", formVersion: "1", values: { a: "x" }, digest: "d", confirmedBy: "keypad", confirmedAt: "2026-01-01T00:00:00.000Z",
  });
  const cases: Array<[string, (store: RecordStore) => Promise<void>]> = [
    [
      "stores nothing for a record reserved before its subject was erased, and stores one reserved after",
      async (store) => {
        const seen = await store.subjectErasures("w", "s1");
        await store.markSubjectErased("w", "s1");
        assert.equal(await store.subjectErasures("w", "s1"), seen + 1);
        await store.putIntakeRecord(record("r1"), seen);
        assert.equal(await store.getIntakeRecord("w", "r1"), null);
        assert.deepEqual(await store.listIntakeRecords("w", "s1"), []);
        await store.putIntakeRecord(record("r2"), seen + 1);
        assert.equal((await store.getIntakeRecord("w", "r2"))?.recordId, "r2");
      },
    ],
    [
      "counts erasures per workspace and subject, and guards only the erased subject",
      async (store) => {
        await store.markSubjectErased("w", "s1");
        await store.markSubjectErased("w", "s1");
        assert.equal(await store.subjectErasures("w", "s1"), 2);
        assert.equal(await store.subjectErasures("w", "s2"), 0);
        assert.equal(await store.subjectErasures("w2", "s1"), 0);
        await store.putIntakeRecord(record("r3", "s2"), 0);
        await store.putIntakeRecord(record("r4", null), 0);
        assert.notEqual(await store.getIntakeRecord("w", "r3"), null);
        assert.notEqual(await store.getIntakeRecord("w", "r4"), null, "a record under no subject is never guarded");
      },
    ],
    [
      "keeps a deleted id deleted: a later write of it stores nothing",
      async (store) => {
        await store.putIntakeRecord(record("r5"));
        await store.deleteIntakeRecords("w", ["r5", "gone"]);
        await store.putIntakeRecord(record("r5"));
        assert.equal(await store.getIntakeRecord("w", "r5"), null);
      },
    ],
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body(await factory()) }));
}
