// A stand-in for the PRV-5 contract suites until they reach main: a copy of `auditLedgerContract`
// and `recordStoreContract` from src/testing/contracts.ts on branch wp-c (commit 4aec656), with
// imports pointed at src/. When PRV-5 is merged, delete this file and import both suites from
// "../src/testing/index.ts" instead.
import { strict as assert } from "node:assert";

import type { AuditEntry, AuditInput, AuditLedger, IntakeRecord, RecordStore, SubjectRecord } from "../src/core/adapters.ts";
import { EngineError } from "../src/core/errors.ts";
import { GENESIS_HASH, chainEntry, verifyChain } from "../src/prove/ledger.ts";
import type { ContractCase } from "../src/testing/contracts.ts";

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
