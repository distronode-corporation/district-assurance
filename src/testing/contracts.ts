// Contract suites: the guarantees a host's durable adapter must keep, written once and run
// against any implementation. Each suite returns its cases as plain async functions, so a host
// runs them under whatever test runner it uses (node:test, vitest, jest):
//
//   for (const c of sessionStoreContract(() => new MyDatabaseSessionStore(...))) it(c.name, c.run);
//
// `moduleContract` is the same idea for the author of an outside module (MOD-1).
import { strict as assert } from "node:assert";
import { inspect } from "node:util";

import type { AttemptCounterKey, AttemptCounters, CodeSendKey, CodeStore, SessionStore } from "../core/adapters.ts";
// PRV-5: the AuditLedger and RecordStore contracts.
import type { AuditEntry, AuditInput, AuditLedger, IntakeRecord, RecordStore, SubjectRecord } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import { GENESIS_HASH, chainEntry, verifyChain } from "../prove/ledger.ts";
import { canonicalJson } from "../core/canonical.ts";
import { checkManifest, type AssuranceModule, type FlowStep, type StepContext, type StepView } from "../core/module.ts";
import { defaultVerificationPolicy, type VerificationPolicy } from "../core/policy.ts";
import { newSession, type Grant, type SessionState } from "../core/session.ts";
import { isDenseArray, isObject } from "../core/shape.ts";
import { builtInModules } from "../modules.ts";

export interface ContractCase {
  name: string;
  run(): Promise<void>;
}

/**
 * Keys that differ only in a lone UTF-16 surrogate, and the replacement character a store that
 * encodes keys as UTF-8 turns each of them into (SQLite with a TEXT key does). A JavaScript string
 * can hold either, so a store must keep all three apart. Escaped here: the files stay ASCII.
 */
const SURROGATE_KEYS = ["k\ud800", "k\udc00", "k\udbff", "k\ufffd"] as const;

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
      "keeps keys that differ only in a lone UTF-16 surrogate apart: workspaces, calls and references",
      async (store) => {
        for (const [i, key] of SURROGATE_KEYS.entries()) {
          assert.equal(await store.create("w", key, { n: i }), true, `call ${JSON.stringify(key)}`);
          assert.equal(await store.create(key, "c1", { n: i }), true, `workspace ${JSON.stringify(key)}`);
          assert.equal(await store.bindRef("w", key, `call_${i}`), true, `reference ${JSON.stringify(key)}`);
        }
        for (const [i, key] of SURROGATE_KEYS.entries()) {
          assert.deepEqual(await store.get("w", key), { version: 1, record: { n: i } });
          assert.deepEqual((await store.get(key, "c1"))!.record, { n: i });
          assert.equal(await store.resolveRef("w", key), `call_${i}`);
        }
        assert.deepEqual(await store.compareAndSet("w", SURROGATE_KEYS[0], 1, { n: 9 }), { ok: true, version: 2 });
        assert.deepEqual(await store.get("w", SURROGATE_KEYS[1]), { version: 1, record: { n: 1 } }, "a write to one never lands on another");
      },
    ],
    [
      "copies a record in on every write, so a caller changing it afterwards changes nothing",
      async (store) => {
        await store.create("w", "c1", { items: [1] });
        const next = { items: [2] };
        assert.deepEqual(await store.compareAndSet("w", "c1", 1, next), { ok: true, version: 2 });
        next.items.push(3);
        assert.deepEqual(await store.get("w", "c1"), { version: 2, record: { items: [2] } });
      },
    ],
    [
      "creates one session and binds one reference when two processes ask at once",
      async (store) => {
        const created = await Promise.all([store.create("w", "c1", { n: 1 }), store.create("w", "c1", { n: 2 })]);
        assert.deepEqual(created.filter(Boolean).length, 1, "one create succeeds");
        assert.deepEqual((await store.get("w", "c1"))!.record, { n: created.indexOf(true) + 1 }, "and its record stands");
        const bound = await Promise.all([store.bindRef("w", "payment:cs_1", "c1"), store.bindRef("w", "payment:cs_1", "c2")]);
        assert.deepEqual(bound.filter(Boolean).length, 1, "one bind succeeds");
        assert.equal(await store.resolveRef("w", "payment:cs_1"), `c${bound.indexOf(true) + 1}`, "and its call stands");
      },
    ],
    [
      "binds the same reference in two workspaces, each to its own call",
      async (store) => {
        assert.equal(await store.bindRef("w", "payment:cs_1", "c1"), true);
        assert.equal(await store.bindRef("w2", "payment:cs_1", "c2"), true, "a reference in one workspace never blocks another's");
        assert.equal(await store.resolveRef("w", "payment:cs_1"), "c1");
        assert.equal(await store.resolveRef("w2", "payment:cs_1"), "c2");
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
    [
      "removes a session only at its stored version, with its pending mark, if it can remove",
      async (store) => {
        // `remove` is optional; a store without it has nothing more to keep here.
        if (store.remove === undefined) return;
        await store.create("w", "c1", { n: 1 }, { ledgerPending: true });
        await store.create("w2", "c1", { n: 1 });
        assert.equal(await store.remove("w", "c1", 2), false, "not at another version");
        assert.equal(await store.remove("w", "missing", 1), false);
        assert.equal(await store.remove("w", "c1", 1), true);
        assert.equal(await store.get("w", "c1"), null);
        assert.equal(await store.remove("w", "c1", 1), false, "once");
        assert.notEqual(await store.get("w2", "c1"), null, "workspaces apart");
        if (store.pendingCalls !== undefined) assert.deepEqual(await store.pendingCalls("w", 10), [], "the mark goes with it");
      },
    ],
    [
      "lists the pending calls listed least recently first, so the same few never hold back the rest",
      async (store) => {
        if (store.pendingCalls === undefined) return;
        for (const id of ["c1", "c2", "c3"]) await store.create("w", id, { n: 1 }, { ledgerPending: true });
        // Calls that stay pending (their flush keeps failing) must not be the only ones listed.
        const seen = new Set<string>();
        for (let run = 0; run < 3; run++) for (const id of await store.pendingCalls("w", 1)) seen.add(id);
        assert.deepEqual([...seen].sort(), ["c1", "c2", "c3"], "three runs of one reach all three calls");
        const twos = [await store.pendingCalls("w", 2), await store.pendingCalls("w", 2)].flat();
        assert.deepEqual([...new Set(twos)].sort(), ["c1", "c2", "c3"], "two runs of two reach all three calls");
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
      "removes one failure by its time, keeps the others, and does nothing when there is none",
      async (store) => {
        for (const s of [1, 1, 5]) await store.recordFailure(counter(), at(s), T0);
        await store.recordFailure(counter({ scope: "number" }), at(1), T0);
        await store.removeFailure(counter(), at(1));
        assert.deepEqual(await store.get(counter(), T0), [at(1), at(5)], "one of two at the same instant");
        await store.removeFailure(counter(), at(9));
        await store.removeFailure(counter({ key: "c".repeat(64) }), at(1));
        assert.deepEqual(await store.get(counter(), T0), [at(1), at(5)]);
        assert.deepEqual(await store.get(counter({ scope: "number" }), T0), [at(1)], "other keys keep theirs");
      },
    ],
    [
      "loses no failure recorded while one is being removed",
      async (store) => {
        await store.recordFailure(counter(), at(1), T0);
        await Promise.all([store.removeFailure(counter(), at(1)), ...Array.from({ length: 5 }, () => store.recordFailure(counter(), at(2), T0))]);
        assert.deepEqual(await store.get(counter(), T0), [at(2), at(2), at(2), at(2), at(2)]);
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

const contractEntry = (n: number, more: Partial<AuditInput> = {}): AuditInput => ({
  callId: `call_${n}`,
  actor: "code",
  event: "module.event",
  at: `2026-01-01T00:00:${String(n % 60).padStart(2, "0")}.000Z`,
  detail: { module: "contract", event: "case", detail: { n, list: [n] } },
  ...more,
});

/**
 * The AuditLedger contract (PRV-5). `factory` returns a new, empty ledger for each case. A ledger
 * appends in order, keeps a valid hash chain (each entry as `chainEntry` builds it, SPEC.md section
 * 10), copies in and out, never changes an entry once appended, appends an `eventId` once, refuses
 * card data, and stays one chain under concurrent appends.
 */
export function auditLedgerContract(factory: () => AuditLedger | Promise<AuditLedger>): ContractCase[] {
  const cases: Array<[string, (ledger: AuditLedger) => Promise<void>]> = [
    [
      "starts empty, at the genesis head",
      async (ledger) => {
        assert.deepEqual(await ledger.head(), { seq: 0, hash: GENESIS_HASH });
        assert.deepEqual(await ledger.list(), []);
      },
    ],
    [
      "appends in order, one seq at a time, on a valid chain that keeps every field",
      async (ledger) => {
        const inputs = [contractEntry(1), contractEntry(2, { callId: null, actor: "system", eventId: "e2" }), contractEntry(3)];
        const appended: AuditEntry[] = [];
        for (const input of inputs) appended.push(await ledger.append(input));
        assert.deepEqual(appended, [
          chainEntry(inputs[0]!, 1, GENESIS_HASH),
          chainEntry(inputs[1]!, 2, appended[0]!.hash),
          chainEntry(inputs[2]!, 3, appended[1]!.hash),
        ]);
        assert.deepEqual(await ledger.list(), appended);
        assert.deepEqual(verifyChain(appended), { ok: true, head: { seq: 3, hash: appended[2]!.hash } });
        assert.deepEqual(await ledger.head(), { seq: 3, hash: appended[2]!.hash });
      },
    ],
    [
      "lists from a seq, in order, as a slice that continues the chain",
      async (ledger) => {
        const appended: AuditEntry[] = [];
        for (let n = 1; n <= 4; n++) appended.push(await ledger.append(contractEntry(n)));
        assert.deepEqual(await ledger.list(1), appended);
        const tail = await ledger.list(3);
        assert.deepEqual(tail, appended.slice(2));
        assert.equal(verifyChain(tail, { seq: 2, hash: appended[1]!.hash }).ok, true);
        assert.deepEqual(await ledger.list(5), []);
      },
    ],
    [
      "lists at most `limit` entries from a seq, as one page",
      async (ledger) => {
        const appended: AuditEntry[] = [];
        for (let n = 1; n <= 5; n++) appended.push(await ledger.append(contractEntry(n)));
        assert.deepEqual(await ledger.list(1), appended, "no limit, every entry");
        assert.deepEqual(await ledger.list(undefined, 2), appended.slice(0, 2), "a limit from the start");
        assert.deepEqual(await ledger.list(1, 1), appended.slice(0, 1), "a page of one");
        assert.deepEqual(await ledger.list(1, 5), appended, "a page of exactly all");
        assert.deepEqual(await ledger.list(2, 2), appended.slice(1, 3), "fromSeq plus limit");
        const page = await ledger.list(4, 10);
        assert.deepEqual(page, appended.slice(3), "a limit beyond the rest gives the rest");
        assert.equal(verifyChain(page, { seq: 3, hash: appended[2]!.hash }).ok, true, "a page continues the chain");
        assert.deepEqual(await ledger.list(6, 3), [], "past the head, nothing");
      },
    ],
    [
      "refuses a limit that is not an integer of 1 or more",
      async (ledger) => {
        await ledger.append(contractEntry(1));
        for (const limit of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
          await assert.rejects(ledger.list(1, limit), `limit ${limit}`);
        }
        assert.equal((await ledger.list()).length, 1, "and still lists");
      },
    ],
    [
      "copies in and out, so a caller cannot change what is stored",
      async (ledger) => {
        const input = contractEntry(1);
        const returned = await ledger.append(input);
        (input.detail.detail as { list: number[] }).list.push(99);
        (returned.detail.detail as { list: number[] }).list.push(98);
        returned.event = "call.ended";
        const listed = await ledger.list();
        (listed[0]!.detail.detail as { list: number[] }).list.push(97);
        listed[0]!.hash = GENESIS_HASH;
        const stored = await ledger.list();
        assert.deepEqual(stored, [chainEntry(contractEntry(1), 1, GENESIS_HASH)]);
        assert.equal(verifyChain(stored).ok, true);
      },
    ],
    [
      "never changes an entry once appended, and only moves its head forward",
      async (ledger) => {
        await ledger.append(contractEntry(1));
        await ledger.append(contractEntry(2));
        const before = await ledger.list();
        const head = await ledger.head();
        await ledger.append(contractEntry(3));
        const after = await ledger.list();
        assert.deepEqual(after.slice(0, 2), before);
        assert.equal(after[2]!.prevHash, head.hash);
        assert.equal((await ledger.head()).seq, head.seq + 1);
      },
    ],
    [
      "appends an eventId once: a second append returns the first entry",
      async (ledger) => {
        const first = await ledger.append(contractEntry(1, { eventId: "e1" }));
        assert.deepEqual(await ledger.append(contractEntry(2, { eventId: "e1" })), first);
        await ledger.append(contractEntry(3));
        await ledger.append(contractEntry(3));
        assert.deepEqual(await ledger.append(contractEntry(4, { eventId: "e1" })), first);
        assert.deepEqual(
          (await ledger.list()).map((e) => e.seq),
          [1, 2, 3],
          "entries without an eventId always append",
        );
      },
    ],
    [
      "returns a copy for a replayed eventId too, so a caller cannot change what is stored",
      async (ledger) => {
        await ledger.append(contractEntry(1, { eventId: "e1" }));
        const replayed = await ledger.append(contractEntry(2, { eventId: "e1" }));
        (replayed.detail.detail as { list: number[] }).list.push(99);
        replayed.hash = GENESIS_HASH;
        const stored = await ledger.list();
        assert.deepEqual(stored, [chainEntry(contractEntry(1, { eventId: "e1" }), 1, GENESIS_HASH)]);
        assert.equal(verifyChain(stored).ok, true);
      },
    ],
    [
      "refuses an eventId holding a lone UTF-16 surrogate, and never stores it as another eventId",
      async (ledger) => {
        // The ledger hashes every entry as canonical JSON (RFC 8785), which has no lone surrogate:
        // such an eventId is refused, never repaired into a well-formed one that could collide.
        for (const eventId of SURROGATE_KEYS.filter((key) => !key.isWellFormed())) {
          await assert.rejects(ledger.append(contractEntry(1, { eventId })), JSON.stringify(eventId));
        }
        assert.deepEqual(await ledger.list(), [], "nothing stored");
        const kept = await ledger.append(contractEntry(2, { eventId: "k\ufffd" }));
        assert.deepEqual(await ledger.list(), [kept], "a well-formed eventId appends");
      },
    ],
    [
      "refuses a detail that carries a card number, and stores nothing",
      async (ledger) => {
        await assert.rejects(
          ledger.append(contractEntry(1, { detail: { note: "4242 4242 4242 4242" } })),
          (e: unknown) => e instanceof EngineError && e.code === "invalid_input",
        );
        assert.deepEqual(await ledger.list(), []);
        assert.deepEqual(await ledger.head(), { seq: 0, hash: GENESIS_HASH });
      },
    ],
    [
      "keeps one valid chain under concurrent appends",
      async (ledger) => {
        await ledger.append(contractEntry(0));
        const appended = await Promise.all(Array.from({ length: 20 }, (_, i) => ledger.append(contractEntry(i + 1))));
        assert.deepEqual(
          appended.map((e) => e.seq).sort((a, b) => a - b),
          Array.from({ length: 20 }, (_, i) => i + 2),
        );
        const stored = await ledger.list();
        assert.equal(stored.length, 21);
        assert.deepEqual(verifyChain(stored), { ok: true, head: await ledger.head() });
        for (const entry of appended) assert.deepEqual(stored[entry.seq - 1], entry, "each append returned what was stored");
      },
    ],
    [
      "stores one entry for concurrent appends of one eventId",
      async (ledger) => {
        const appended = await Promise.all(Array.from({ length: 5 }, (_, i) => ledger.append(contractEntry(i + 1, { eventId: "same" }))));
        for (const entry of appended) assert.deepEqual(entry, appended[0]);
        assert.equal((await ledger.list()).length, 1);
      },
    ],
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
      "holds the minimum interval even when it is longer than the window",
      async (store) => {
        const take = (seconds: number) => store.take({ workspaceId: "w", key: subject, at: at(seconds), max: 3, windowSeconds: 30, minIntervalSeconds: 60 });
        assert.equal(await take(0), true);
        assert.equal(await take(30), false, "the first send left the window but is still inside the interval");
        assert.equal(await take(60), true);
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

/** A subject the RecordStore contract puts in a new store, in a workspace. */
export interface SeededSubject {
  workspaceId: string;
  subject: SubjectRecord;
}

const contractSubject = (subjectKey: string, more: Partial<SubjectRecord> = {}): SubjectRecord => ({
  subjectKey,
  phoneOnFile: "+15555550100",
  knowledge: { dob: "a".repeat(64), postal: "b".repeat(64) },
  ...more,
});

const contractRecord = (workspaceId: string, recordId: string): IntakeRecord => ({
  recordId,
  workspaceId,
  callId: "call_1",
  subjectKey: null,
  formId: "maintenance",
  formVersion: "1",
  values: { issue: "leaking tap", rooms: 2, urgent: true },
  digest: "c".repeat(64),
  confirmedBy: "voice",
  confirmedAt: "2026-01-01T00:00:00.000Z",
});

/**
 * The RecordStore contract (PRV-5). `factory` returns a new store holding exactly the subjects it
 * is given (subjects are the host's own records; the engine only reads them) and no intake record.
 * A store copies in and out, keeps workspaces apart, and files an intake record idempotently by
 * `recordId`, also when the engine retries it concurrently.
 */
export function recordStoreContract(factory: (subjects: SeededSubject[]) => RecordStore | Promise<RecordStore>): ContractCase[] {
  const subjects: SeededSubject[] = [
    { workspaceId: "w", subject: contractSubject("1".repeat(64), { pinDigest: "d".repeat(64) }) },
    { workspaceId: "w", subject: contractSubject("2".repeat(64)) },
    { workspaceId: "north", subject: contractSubject("branch/3") },
    { workspaceId: "north/branch", subject: contractSubject("3", { phoneOnFile: "+15555550199" }) },
    ...SURROGATE_KEYS.map((key, i) => ({ workspaceId: "w", subject: contractSubject(key, { phoneOnFile: `+1555555011${i}` }) })),
    ...SURROGATE_KEYS.map((key, i) => ({ workspaceId: key, subject: contractSubject("4", { phoneOnFile: `+1555555012${i}` }) })),
    // Another workspace's subject with the same key as the second one: a deletion must not reach it.
    { workspaceId: "w2", subject: contractSubject("2".repeat(64), { phoneOnFile: "+15555550101" }) },
  ];
  const cases: Array<[string, (store: RecordStore) => Promise<void>]> = [
    [
      "returns a subject as stored, with or without a PIN digest, and null for an unknown one",
      async (store) => {
        assert.deepEqual(await store.getSubject("w", "1".repeat(64)), subjects[0]!.subject);
        const plain = await store.getSubject("w", "2".repeat(64));
        assert.deepEqual(plain, subjects[1]!.subject);
        assert.equal("pinDigest" in plain!, false);
        assert.equal(await store.getSubject("w", "f".repeat(64)), null);
      },
    ],
    [
      "returns copies of subjects",
      async (store) => {
        const got = await store.getSubject("w", "1".repeat(64));
        got!.phoneOnFile = "+15555550123";
        got!.knowledge.dob = "e".repeat(64);
        assert.deepEqual(await store.getSubject("w", "1".repeat(64)), subjects[0]!.subject);
      },
    ],
    [
      "keeps workspaces apart, and never lets two workspace and id pairs share a key",
      async (store) => {
        assert.equal(await store.getSubject("w2", "1".repeat(64)), null);
        assert.deepEqual(await store.getSubject("north", "branch/3"), subjects[2]!.subject);
        assert.deepEqual(await store.getSubject("north/branch", "3"), subjects[3]!.subject);
        await store.putIntakeRecord(contractRecord("north", "branch/r1"));
        await store.putIntakeRecord(contractRecord("north/branch", "r1"));
        assert.deepEqual(await store.getIntakeRecord("north", "branch/r1"), contractRecord("north", "branch/r1"));
        assert.deepEqual(await store.getIntakeRecord("north/branch", "r1"), contractRecord("north/branch", "r1"));
        assert.equal(await store.getIntakeRecord("w", "branch/r1"), null);
      },
    ],
    [
      "keeps keys that differ only in a lone UTF-16 surrogate apart: subjects, records and workspaces",
      async (store) => {
        for (const [i, key] of SURROGATE_KEYS.entries()) {
          assert.equal((await store.getSubject("w", key))!.phoneOnFile, `+1555555011${i}`, `subject ${JSON.stringify(key)}`);
          assert.equal((await store.getSubject(key, "4"))!.phoneOnFile, `+1555555012${i}`, `workspace ${JSON.stringify(key)}`);
          await store.putIntakeRecord({ ...contractRecord("w", key), callId: `call_${i}` });
          await store.putIntakeRecord({ ...contractRecord(key, "r1"), callId: `call_${i}` });
        }
        for (const [i, key] of SURROGATE_KEYS.entries()) {
          assert.equal((await store.getIntakeRecord("w", key))!.callId, `call_${i}`, `record ${JSON.stringify(key)}`);
          assert.equal((await store.getIntakeRecord(key, "r1"))!.callId, `call_${i}`, `workspace ${JSON.stringify(key)}`);
        }
        assert.equal(await store.getSubject("w", "k"), null);
      },
    ],
    [
      "stores an intake record and returns copies",
      async (store) => {
        assert.equal(await store.getIntakeRecord("w", "rec_1"), null);
        const record = contractRecord("w", "rec_1");
        await store.putIntakeRecord(record);
        record.values.issue = "changed after filing";
        const got = await store.getIntakeRecord("w", "rec_1");
        assert.deepEqual(got, contractRecord("w", "rec_1"));
        got!.values.rooms = 3;
        assert.deepEqual(await store.getIntakeRecord("w", "rec_1"), contractRecord("w", "rec_1"));
      },
    ],
    [
      "files a record idempotently by recordId",
      async (store) => {
        await store.putIntakeRecord(contractRecord("w", "rec_1"));
        await store.putIntakeRecord(contractRecord("w", "rec_1"));
        await store.putIntakeRecord(contractRecord("w", "rec_2"));
        assert.deepEqual(await store.getIntakeRecord("w", "rec_1"), contractRecord("w", "rec_1"));
        assert.deepEqual(await store.getIntakeRecord("w", "rec_2"), contractRecord("w", "rec_2"));
      },
    ],
    [
      "files concurrent puts, of one record and of many, without losing one",
      async (store) => {
        await Promise.all([
          store.putIntakeRecord(contractRecord("w", "rec_same")),
          store.putIntakeRecord(contractRecord("w", "rec_same")),
          ...Array.from({ length: 10 }, (_, i) => store.putIntakeRecord(contractRecord("w", `rec_${i}`))),
        ]);
        assert.deepEqual(await store.getIntakeRecord("w", "rec_same"), contractRecord("w", "rec_same"));
        for (let i = 0; i < 10; i++) assert.deepEqual(await store.getIntakeRecord("w", `rec_${i}`), contractRecord("w", `rec_${i}`));
      },
    ],
    [
      "keeps a record unconfirmed until confirmIntakeRecord marks it, idempotently, and never marks an id it does not hold",
      async (store) => {
        assert.equal(await store.isIntakeRecordConfirmed("w", "rec_c"), false);
        await store.confirmIntakeRecord("w", "rec_c");
        assert.equal(await store.isIntakeRecordConfirmed("w", "rec_c"), false, "a mark before the write marks nothing");
        await store.putIntakeRecord(contractRecord("w", "rec_c"));
        assert.equal(await store.isIntakeRecordConfirmed("w", "rec_c"), false, "a stored record starts unconfirmed");
        await store.confirmIntakeRecord("w", "rec_c");
        await store.confirmIntakeRecord("w", "rec_c");
        assert.equal(await store.isIntakeRecordConfirmed("w", "rec_c"), true);
        await store.putIntakeRecord(contractRecord("w", "rec_c"));
        assert.equal(await store.isIntakeRecordConfirmed("w", "rec_c"), true, "a retried write keeps the mark");
        assert.deepEqual(await store.getIntakeRecord("w", "rec_c"), contractRecord("w", "rec_c"), "the mark is not part of the record");
        await store.putIntakeRecord(contractRecord("w2", "rec_c"));
        assert.equal(await store.isIntakeRecordConfirmed("w2", "rec_c"), false, "workspaces apart");
        await store.deleteIntakeRecords("w", ["rec_c"]);
        await store.confirmIntakeRecord("w", "rec_c");
        assert.equal(await store.isIntakeRecordConfirmed("w", "rec_c"), false, "a deleted record is never confirmed");
        assert.equal(await store.getIntakeRecord("w", "rec_c"), null);
      },
    ],
    [
      "deletes a subject's PIN and duress digests, keeps the rest, and deleting a missing one is harmless",
      async (store) => {
        const key = "2".repeat(64);
        const pin = "e".repeat(64);
        const duress = "f".repeat(64);
        for (const w of ["w", "w2"]) {
          assert.equal(await store.putPinDigest(w, key, pin, w === "w" ? "enr_del" : undefined), true, `${w}: the PIN digest is stored`);
          assert.equal(await store.putDuressDigest(w, key, duress, pin), true, `${w}: the duress digest is stored`);
        }
        assert.deepEqual(await store.getSubject("w", key), { ...subjects[1]!.subject, pinDigest: pin, pinEnrolmentId: "enr_del", duressDigest: duress });
        await store.deletePinDigest("w", key);
        const gone = await store.getSubject("w", key);
        assert.deepEqual(gone, subjects[1]!.subject, "the phone on file and the knowledge are kept");
        assert.equal("pinDigest" in gone!, false);
        assert.equal("duressDigest" in gone!, false);
        assert.equal("pinEnrolmentId" in gone!, false, "the enrolment id goes with the PIN it names");
        // Deleting again, and deleting for a subject the store does not have, change nothing and create nothing.
        await store.deletePinDigest("w", key);
        await store.deletePinDigest("w", "f".repeat(64));
        await store.deletePinDigest("w3", key);
        assert.deepEqual(await store.getSubject("w", key), subjects[1]!.subject);
        assert.equal(await store.getSubject("w", "f".repeat(64)), null);
        assert.equal(await store.getSubject("w3", key), null);
        // The same key in another workspace keeps both digests.
        assert.deepEqual(await store.getSubject("w2", key), { ...subjects.at(-1)!.subject, pinDigest: pin, duressDigest: duress });
      },
    ],
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body(await factory(structuredClone(subjects))) }));
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

export interface ModuleContractOptions {
  /** Valid settings for the module, as a FlowConfig would hold them. Default: none (undefined). */
  settings?: unknown;
  /** Valid flow steps, at least one of each step type the module provides. Default: `{ type }` for each. */
  steps?: readonly FlowStep[];
  /** The policy the steps are checked under. Default: `defaultVerificationPolicy()`. */
  policy?: VerificationPolicy;
  /** The modules the manifest must not clash with. Default: the built-in modules. */
  installed?: readonly AssuranceModule[];
}

/**
 * Values settings and steps can hold when they come from storage or an operator's editor: every
 * JSON type, keys that read as JavaScript internals, keys named like methods, a long string, lone
 * UTF-16 surrogates (JSON can carry them, and `encodeURIComponent` or a strict decoder throws on
 * them), deep nesting, and a missing value. A validator answers each with sentences, never a crash.
 */
function garbage(): unknown[] {
  const sparse: unknown[] = [];
  sparse.length = 2;
  let deep: unknown = "x";
  for (let i = 0; i < 100; i++) deep = [deep];
  return [
    undefined,
    null,
    true,
    false,
    0,
    -1,
    0.5,
    1e308,
    "",
    " ",
    "x",
    "x".repeat(100_000),
    "\uD800",
    "a\uDFFFb",
    "__proto__",
    "constructor",
    [],
    [null],
    ["x", 1],
    sparse,
    {},
    { x: null },
    JSON.parse('{"__proto__": {"polluted": true}}'),
    JSON.parse('{"toString": 1, "valueOf": 1, "constructor": 1, "hasOwnProperty": 1}'),
    deep,
  ];
}

/** Each way to spoil a value: replace it, or anything inside it, with garbage; drop a key; add one. */
function* spoiled(value: unknown, path: string): Generator<[path: string, value: unknown]> {
  for (const g of garbage()) yield [path, g];
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      for (const [at, inner] of spoiled(value[i], `${path}[${i}]`)) yield [at, value.with(i, inner)];
    }
  } else if (isObject(value)) {
    yield* spoiledFields(value, path, []);
  }
}

/** Spoils each field of an object but the `keep` ones, drops each, and adds an unknown one. */
function* spoiledFields(value: Record<string, unknown>, path: string, keep: readonly string[]): Generator<[path: string, value: unknown]> {
  for (const key of Object.keys(value).filter((k) => !keep.includes(k))) {
    for (const [at, inner] of spoiled(value[key], `${path}.${key}`)) yield [at, { ...value, [key]: inner }];
    const rest = { ...value };
    delete rest[key];
    yield [`${path}.${key} (missing)`, rest];
  }
  yield [`${path}.unexpected_field`, { ...value, unexpected_field: 1 }];
}

/** A deep copy that nothing can change: a module that writes to what it is given throws. */
function frozen<T>(value: T): T {
  const copy = structuredClone(value);
  const freeze = (v: unknown): void => {
    if (typeof v !== "object" || v === null) return;
    Object.freeze(v);
    for (const inner of Object.values(v)) freeze(inner);
  };
  freeze(copy);
  return copy;
}

const show = (value: unknown) => inspect(value, { depth: 2, maxArrayLength: 3, maxStringLength: 20, breakLength: Infinity });

/** Runs `fn`, and fails the case naming what it was given if it throws. */
function mustNotThrow<T>(what: string, fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    assert.fail(`${what} threw: ${e instanceof Error ? e.message : show(e)}`);
  }
}

function assertSentences(value: unknown, what: string): void {
  // Dense only: every() skips a hole, which is no sentence.
  assert.ok(isDenseArray(value) && value.every((s) => typeof s === "string"), `${what} must return a list of strings, got ${show(value)}`);
}

function assertJson(value: unknown, what: string): string {
  return mustNotThrow(`${what} must return JSON: canonicalJson`, () => canonicalJson(value));
}

function assertNullOrString(value: unknown, what: string): void {
  assert.ok(value === null || typeof value === "string", `${what} must return null or a sentence, got ${show(value)}`);
}

/** Calls a module's step is judged on: a new call, a verified one, a tainted one, an ended one. */
function sampleStates(): SessionState[] {
  const at = "2026-01-01T00:00:00.000Z";
  const open = newSession("call_contract", "ws_contract", at);
  const grant: Grant = { grantId: "grant_contract", level: 2, scopes: ["status.read"], issuedAt: at, expiresAt: "2026-01-01T00:15:00.000Z", policyVersion: "1", configRevision: "contract" };
  const verified: SessionState = { ...open, level: 2, grant, factors: [{ kind: "keypad_knowledge", passed: true, at }] };
  return [open, verified, { ...verified, tainted: true, level: 0, grant: null }, { ...open, phase: "ended", endedAt: at }];
}

const STEP_STATUSES: readonly unknown[] = ["pending", "complete", "failed"];

/**
 * The module contract (MOD-1): what an outside module must keep before a host installs it with
 * `engine.use(module)`. The manifest passes `checkManifest` against the modules it joins; the
 * validators answer garbage with sentences and never throw; `initCall`, `enterStep` and the
 * optional hooks return JSON and change nothing they are given; `stepStatus` is pure.
 *
 *   for (const c of moduleContract(myModule, { settings, steps })) it(c.name, c.run);
 */
export function moduleContract(module: AssuranceModule, options: ModuleContractOptions = {}): ContractCase[] {
  const { manifest } = module;
  const settings = options.settings;
  const steps = options.steps ?? manifest.provides.steps.map((type) => ({ type }));
  const policy = options.policy ?? defaultVerificationPolicy();
  const installed = options.installed ?? builtInModules();
  const goodContext = (): StepContext =>
    Object.freeze({ settings: frozen(settings), policy: frozen(policy), adapters: new Set(module.requiredAdapters(frozen(settings))), capabilities: Object.freeze({}) });
  const emptyContext = (): StepContext => Object.freeze({ settings: null, policy: null, adapters: new Set<string>(), capabilities: Object.freeze({}) });
  /** validateStep on a frozen context. A host shares its adapter set, so a change to it fails the case. */
  const validateStep = (step: FlowStep, ctx: StepContext, what: string): string[] => {
    const before = [...ctx.adapters];
    const problems = mustNotThrow(what, () => module.validateStep(frozen(step), ctx));
    assert.deepEqual([...ctx.adapters], before, `${what} must not change the adapters it is given`);
    return problems;
  };

  const cases: Array<[string, () => void]> = [
    [
      "the manifest passes checkManifest against the modules it joins, and is JSON",
      () => {
        assert.deepEqual(checkManifest(manifest, installed), []);
        assertJson(manifest, "the manifest");
      },
    ],
    [
      "accepts its sample settings and a sample of every step it provides",
      () => {
        assert.deepEqual(module.validateSettings(frozen(settings)), [], "the sample settings");
        const adapters = module.requiredAdapters(frozen(settings));
        assertSentences(adapters, "requiredAdapters");
        for (const adapter of manifest.adapters) assert.ok(adapters.includes(adapter), `requiredAdapters must include the manifest's ${adapter}`);
        for (const type of manifest.provides.steps) assert.ok(steps.some((s) => s.type === type), `no sample step of type ${type}`);
        for (const step of steps) {
          assert.ok(manifest.provides.steps.includes(step.type), `the sample step ${step.type} is not one the module provides`);
          assert.deepEqual(validateStep(step, goodContext(), `validateStep(${step.type})`), [],`the sample step ${show(step)}`);
        }
      },
    ],
    [
      "validateSettings never throws on garbage, and answers with sentences",
      () => {
        for (const [at, value] of spoiled(settings, "settings")) {
          const what = `validateSettings with ${at} spoiled, as ${show(value)},`;
          assertSentences(mustNotThrow(what, () => module.validateSettings(frozen(value))), what);
        }
      },
    ],
    [
      "validateStep, stepLevel and stepGrants never throw on a garbage step",
      () => {
        for (const step of steps) {
          for (const [at, value] of spoiledFields(step, step.type, ["type"])) {
            const bad = value as FlowStep;
            const what = `with ${at} spoiled, as ${show(value)},`;
            for (const ctx of [goodContext(), emptyContext()]) {
              assertSentences(validateStep(bad, ctx, `validateStep ${what}`), `validateStep ${what}`);
            }
            // validateConfig asks for a step's level and grants even when the step has problems.
            const level = mustNotThrow(`stepLevel ${what}`, () => module.stepLevel?.(frozen(bad)) ?? null);
            assert.ok(level === null || [0, 1, 2, 3].includes(level), `stepLevel ${what} must return a level from 0 to 3, or null`);
            const grants = mustNotThrow(`stepGrants ${what}`, () => module.stepGrants?.(frozen(bad)) ?? null);
            if (grants !== null) assertSentences(grants, `stepGrants ${what}`);
          }
        }
      },
    ],
    [
      "initCall and enterStep return JSON, the same each time, and change nothing they are given",
      () => {
        const slice = mustNotThrow("initCall", () => module.initCall(frozen(settings)));
        const json = assertJson(slice, "initCall");
        assert.equal(canonicalJson(module.initCall(frozen(settings))), json, "initCall must return the same part each time");
        for (const step of steps) {
          const what = `enterStep(${step.type})`;
          const mark = assertJson(mustNotThrow(what, () => module.enterStep(frozen(step), frozen(slice))), what);
          assert.equal(canonicalJson(module.enterStep(frozen(step), frozen(slice))), mark, `${what} must return the same mark each time`);
        }
      },
    ],
    [
      "stepStatus is pure: the same view gets the same answer, in any order, and nothing changes",
      () => {
        const slice = module.initCall(frozen(settings));
        for (const step of steps) {
          const mark = module.enterStep(frozen(step), frozen(slice));
          const views: StepView[] = sampleStates().map((state) => frozen({ state, slice, mark }));
          const judge = (view: StepView) => mustNotThrow(`stepStatus(${step.type})`, () => module.stepStatus(frozen(step), view));
          const first = views.map(judge);
          for (const status of first) assert.ok(STEP_STATUSES.includes(status), `stepStatus(${step.type}) returned ${show(status)}`);
          assert.deepEqual([...views].reverse().map(judge).reverse(), first, `stepStatus(${step.type}) must not depend on earlier calls`);
          assert.deepEqual(views.map(judge), first, `stepStatus(${step.type}) must give the same answer each time`);
        }
      },
    ],
    [
      "the optional hooks it has return what they promise, and change nothing they are given",
      () => {
        const slice = module.initCall(frozen(settings));
        if (module.cannotRunStep !== undefined) {
          for (const step of steps) assertNullOrString(mustNotThrow("cannotRunStep", () => module.cannotRunStep!(frozen(step), frozen(slice), "en")), "cannotRunStep");
        }
        // validateConfig calls both without catching, and only once the settings are valid: each
        // must answer sentences for the sample settings and steps, and change nothing.
        if (module.validateFlow !== undefined) {
          const ctx = goodContext();
          const before = [...ctx.adapters];
          assertSentences(mustNotThrow("validateFlow", () => module.validateFlow!(frozen(steps), ctx)), "validateFlow");
          assert.deepEqual([...ctx.adapters], before, "validateFlow must not change the adapters it is given");
        }
        if (module.checkAdapters !== undefined) {
          assertSentences(mustNotThrow("checkAdapters", () => module.checkAdapters!(frozen(settings), Object.freeze({}))), "checkAdapters");
        }
        if (module.blocksEnd !== undefined) assertNullOrString(mustNotThrow("blocksEnd", () => module.blocksEnd!(frozen(slice), new Date("2026-01-01T00:00:00.000Z"))), "blocksEnd");
        if (module.onUntrusted !== undefined) assertJson(mustNotThrow("onUntrusted", () => module.onUntrusted!(frozen(slice))), "onUntrusted");
        if (module.receiptPart !== undefined) {
          for (const state of sampleStates()) {
            const part = mustNotThrow("receiptPart", () => module.receiptPart!(frozen(slice), frozen(state)));
            assert.ok(isObject(part), "receiptPart must return an object");
            assertJson(part, "receiptPart");
          }
        }
      },
    ],
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body() }));
}
