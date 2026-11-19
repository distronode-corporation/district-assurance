// Contract suites: the guarantees a host's durable adapter must keep, written once and run
// against any implementation. Each suite returns its cases as plain async functions, so a host
// runs them under whatever test runner it uses (node:test, vitest, jest):
//
//   for (const c of sessionStoreContract(() => new MyDatabaseSessionStore(...))) it(c.name, c.run);
import { strict as assert } from "node:assert";

import type { AuditEntry, AuditInput, AuditLedger, SessionStore } from "../core/adapters.ts";
import { verifyChain } from "../prove/ledger.ts";

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
    [
      "keeps a call's pending ledger mark with its writes, per workspace, if it lists pending calls",
      async (store) => {
        // `pendingCalls` is optional (INT-5); a store without it has nothing more to keep here.
        if (store.pendingCalls === undefined) return;
        const pending = async (w: string) => (await store.pendingCalls!(w, 10)).sort();
        await store.create("w", "c1", { n: 1 }, { ledgerPending: true });
        await store.create("w", "c2", { n: 1 }, { ledgerPending: false });
        await store.create("w", "c3", { n: 1 }, { ledgerPending: true });
        await store.create("w2", "c4", { n: 1 }, { ledgerPending: true });
        assert.deepEqual(await pending("w"), ["c1", "c3"]);
        assert.equal((await store.pendingCalls("w", 1)).length, 1, "at most `limit` ids");
        assert.deepEqual(await pending("w3"), []);
        await store.compareAndSet("w", "c1", 1, { n: 2 }, { ledgerPending: false });
        await store.compareAndSet("w", "c2", 1, { n: 2 }, { ledgerPending: true });
        assert.deepEqual(await store.compareAndSet("w", "c3", 9, { n: 2 }, { ledgerPending: false }), { ok: false });
        assert.equal(await store.create("w", "c3", { n: 9 }, { ledgerPending: false }), false);
        await store.compareAndSet("w", "c3", 1, { n: 2 });
        assert.deepEqual(await pending("w"), ["c2", "c3"], "a lost write, a refused create and a write without a hint change no mark");
        assert.deepEqual(await pending("w2"), ["c4"]);
      },
    ],
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body(await factory()) }));
}

const replayEntry = (n: number): AuditInput => ({
  eventId: JSON.stringify(["w", "c1", 2, n]),
  callId: "c1",
  actor: "code",
  event: "module.event",
  at: `2026-01-01T00:00:0${n}.000Z`,
  detail: { n },
});

/**
 * The AuditLedger contract (PRV-5). `factory` returns a new, empty ledger for each case.
 *
 * INT-5 stand-in: this holds only the case the engine's outbox relies on. PRV-5 (wp-c) brings the
 * full `auditLedgerContract`; when both land, this case joins that suite's list.
 */
export function auditLedgerContract(factory: () => AuditLedger | Promise<AuditLedger>): ContractCase[] {
  const cases: Array<[string, (ledger: AuditLedger) => Promise<void>]> = [
    [
      "appends a replayed run of eventIds once, as a retried flush does: only the new ones append",
      async (ledger) => {
        const first: AuditEntry[] = [];
        for (const n of [0, 1]) first.push(await ledger.append(replayEntry(n)));
        const replayed: AuditEntry[] = [];
        for (const n of [0, 1, 2, 3]) replayed.push(await ledger.append(replayEntry(n)));
        assert.deepEqual(replayed.slice(0, 2), first, "a replayed id returns its first entry");
        assert.deepEqual(
          replayed.map((e) => e.seq),
          [1, 2, 3, 4],
        );
        const stored = await ledger.list();
        assert.deepEqual(stored, replayed);
        assert.deepEqual(verifyChain(stored), { ok: true, head: await ledger.head() });
      },
    ],
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body(await factory()) }));
}
