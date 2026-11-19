// Contract suites: the guarantees a host's durable adapter must keep, written once and run
// against any implementation. Each suite returns its cases as plain async functions, so a host
// runs them under whatever test runner it uses (node:test, vitest, jest):
//
//   for (const c of sessionStoreContract(() => new MyDatabaseSessionStore(...))) it(c.name, c.run);
import { strict as assert } from "node:assert";

import type { SessionStore } from "../core/adapters.ts";
// PRV-5: the AuditLedger and RecordStore contracts.
import type { AuditEntry, AuditInput, AuditLedger, IntakeRecord, RecordStore, SubjectRecord } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import { GENESIS_HASH, chainEntry, verifyChain } from "../prove/ledger.ts";

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
      "keeps eventIds that differ only in a lone UTF-16 surrogate apart",
      async (ledger) => {
        const appended: AuditEntry[] = [];
        for (const [i, eventId] of SURROGATE_KEYS.entries()) appended.push(await ledger.append(contractEntry(i + 1, { eventId })));
        assert.deepEqual(
          appended.map((e) => [e.seq, e.eventId]),
          SURROGATE_KEYS.map((eventId, i) => [i + 1, eventId]),
          "each appends, and keeps its eventId as given",
        );
        for (const [i, eventId] of SURROGATE_KEYS.entries()) assert.deepEqual(await ledger.append(contractEntry(9, { eventId })), appended[i], "and is appended once");
        assert.deepEqual(await ledger.list(), appended);
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
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body(await factory(structuredClone(subjects))) }));
}
