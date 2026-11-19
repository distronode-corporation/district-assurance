// Contract suites: the guarantees a host's durable adapter must keep, written once and run
// against any implementation. Each suite returns its cases as plain async functions, so a host
// runs them under whatever test runner it uses (node:test, vitest, jest):
//
//   for (const c of sessionStoreContract(() => new MyDatabaseSessionStore(...))) it(c.name, c.run);
import { strict as assert } from "node:assert";

import type { CodeSendKey, CodeStore, SessionStore } from "../core/adapters.ts";

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

/** The CodeStore contract (VER-2). `factory` returns a new, empty store for each case. */
export function codeStoreContract(factory: () => CodeStore | Promise<CodeStore>): ContractCase[] {
  const subject: CodeSendKey = { scope: "subject", key: "a".repeat(64) };
  const at = (seconds: number) => new Date(Date.UTC(2026, 0, 1) + seconds * 1000).toISOString();
  const limits = { max: 3, windowSeconds: 3600, minIntervalSeconds: 60 };
  const cases: Array<[string, (store: CodeStore) => Promise<void>]> = [
    [
      "counts up to the limit in the window, counts nothing it refuses, and counts again once the window moves on",
      async (store) => {
        const take = (seconds: number) => store.take({ workspaceId: "w", key: subject, at: at(seconds), ...limits });
        assert.equal(await take(0), true);
        assert.equal(await take(60), true);
        assert.equal(await take(120), true);
        assert.equal(await take(180), false, "the limit");
        assert.equal(await take(3599), false);
        assert.equal(await take(3600), true, "the first send left the window, and the refusals were not counted");
        assert.equal(await take(3660), true);
        assert.equal(await take(3720), true);
        assert.equal(await take(3780), false);
      },
    ],
    [
      "refuses a send inside the minimum interval, without counting it",
      async (store) => {
        const take = (seconds: number) => store.take({ workspaceId: "w", key: subject, at: at(seconds), ...limits });
        assert.equal(await take(0), true);
        assert.equal(await take(59), false);
        assert.equal(await take(60), true, "the refusal at 59 seconds did not restart the interval");
      },
    ],
    [
      "keeps workspaces, scopes and keys apart",
      async (store) => {
        const one = { ...limits, max: 1 };
        assert.equal(await store.take({ workspaceId: "w", key: subject, at: at(0), ...one }), true);
        assert.equal(await store.take({ workspaceId: "w", key: subject, at: at(600), ...one }), false);
        assert.equal(await store.take({ workspaceId: "w2", key: subject, at: at(600), ...one }), true);
        assert.equal(await store.take({ workspaceId: "w", key: { scope: "number", key: subject.key }, at: at(600), ...one }), true);
        assert.equal(await store.take({ workspaceId: "w", key: { scope: "subject", key: "b".repeat(64) }, at: at(600), ...one }), true);
      },
    ],
    [
      "never lets concurrent sends count past the limit",
      async (store) => {
        const results = await Promise.all(Array.from({ length: 6 }, () => store.take({ workspaceId: "w", key: subject, at: at(0), ...limits, minIntervalSeconds: 0 })));
        assert.equal(results.filter(Boolean).length, 3);
      },
    ],
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body(await factory()) }));
}
