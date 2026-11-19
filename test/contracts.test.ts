// PRV-5: the AuditLedger and RecordStore contract suites, run against the memory adapters, and
// shown to catch adapters that break them.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditEntry, AuditInput, IntakeRecord, SubjectRecord } from "../src/core/adapters.ts";
import { GENESIS_HASH, MemoryAuditLedger, chainEntry } from "../src/prove/ledger.ts";
import { type ContractCase, MemoryRecordStore, type SeededSubject, auditLedgerContract, recordStoreContract } from "../src/testing/index.ts";

function seed<S extends MemoryRecordStore>(store: S, subjects: SeededSubject[]): S {
  for (const { workspaceId, subject } of subjects) store.putSubject(workspaceId, subject);
  return store;
}

const memoryRecordStore = (subjects: SeededSubject[]) => seed(new MemoryRecordStore(), subjects);

/** The names of the cases that fail. */
async function failing(cases: ContractCase[]): Promise<string[]> {
  const failed: string[] = [];
  for (const c of cases) await c.run().catch(() => failed.push(c.name));
  return failed;
}

describe("MemoryAuditLedger passes the AuditLedger contract", () => {
  for (const c of auditLedgerContract(() => new MemoryAuditLedger())) it(c.name, c.run);
});

describe("MemoryRecordStore passes the RecordStore contract", () => {
  for (const c of recordStoreContract(memoryRecordStore)) it(c.name, c.run);
});

describe("the AuditLedger contract", () => {
  it("catches a ledger that hands out what it stores", async () => {
    class Leaky {
      readonly entries: AuditEntry[] = [];
      async append(input: AuditInput): Promise<AuditEntry> {
        const last = this.entries.at(-1);
        const entry = chainEntry(input, (last?.seq ?? 0) + 1, last?.hash ?? GENESIS_HASH);
        this.entries.push(entry);
        return entry;
      }
      async head() {
        const last = this.entries.at(-1);
        return { seq: last?.seq ?? 0, hash: last?.hash ?? GENESIS_HASH };
      }
      async list(fromSeq = 1) {
        return this.entries.filter((e) => e.seq >= fromSeq);
      }
    }
    assert.deepEqual(await failing(auditLedgerContract(() => new Leaky())), [
      "copies in and out, so a caller cannot change what is stored",
      "appends an eventId once: a second append returns the first entry",
      "stores one entry for concurrent appends of one eventId",
    ]);
  });

  it("catches a ledger whose appends interleave, forking the chain", async () => {
    class Racy extends MemoryAuditLedger {
      readonly #entries: AuditEntry[] = [];
      override async append(input: AuditInput): Promise<AuditEntry> {
        const head = await this.head();
        await new Promise((resolve) => setImmediate(resolve));
        const entry = chainEntry(input, head.seq + 1, head.hash);
        this.#entries.push(entry);
        return structuredClone(entry);
      }
      override async head() {
        const last = this.#entries.at(-1);
        return { seq: last?.seq ?? 0, hash: last?.hash ?? GENESIS_HASH };
      }
      override async list(fromSeq = 1) {
        return structuredClone(this.#entries.filter((e) => e.seq >= fromSeq));
      }
    }
    const failed = await failing(auditLedgerContract(() => new Racy()));
    assert.ok(failed.includes("keeps one valid chain under concurrent appends"), failed.join(", "));
  });

  it("catches a ledger that rewrites an entry, or skips the card number check", async () => {
    class Rewriting extends MemoryAuditLedger {
      override async list(fromSeq = 1) {
        const entries = await super.list(fromSeq);
        if (entries.length > 2) entries[0]!.detail = { rewritten: true };
        return entries;
      }
    }
    assert.ok((await failing(auditLedgerContract(() => new Rewriting()))).includes("never changes an entry once appended, and only moves its head forward"));

    class Careless extends MemoryAuditLedger {
      override async append(input: AuditInput) {
        return super.append({ ...input, detail: JSON.stringify(input.detail).includes("4242") ? { redacted: true } : input.detail });
      }
    }
    assert.deepEqual(await failing(auditLedgerContract(() => new Careless())), ["refuses a detail that carries a card number, and stores nothing"]);
  });
});

describe("the RecordStore contract", () => {
  it("catches a store whose keys collide across workspaces", async () => {
    class Joined {
      readonly #subjects = new Map<string, SubjectRecord>();
      readonly #records = new Map<string, IntakeRecord>();
      constructor(subjects: SeededSubject[]) {
        for (const { workspaceId, subject } of subjects) this.#subjects.set(`${workspaceId}/${subject.subjectKey}`, structuredClone(subject));
      }
      async getSubject(workspaceId: string, subjectKey: string) {
        return structuredClone(this.#subjects.get(`${workspaceId}/${subjectKey}`) ?? null);
      }
      async putIntakeRecord(record: IntakeRecord) {
        this.#records.set(`${record.workspaceId}/${record.recordId}`, structuredClone(record));
      }
      async getIntakeRecord(workspaceId: string, recordId: string) {
        return structuredClone(this.#records.get(`${workspaceId}/${recordId}`) ?? null);
      }
    }
    assert.deepEqual(await failing(recordStoreContract((subjects) => new Joined(subjects))), [
      "keeps workspaces apart, and never lets two workspace and id pairs share a key",
    ]);
  });

  it("catches a store that refuses a retried record", async () => {
    class Strict extends MemoryRecordStore {
      readonly #filed = new Set<string>();
      override async putIntakeRecord(record: IntakeRecord) {
        const key = JSON.stringify([record.workspaceId, record.recordId]);
        if (this.#filed.has(key)) throw new Error("duplicate key");
        this.#filed.add(key);
        return super.putIntakeRecord(record);
      }
    }
    assert.deepEqual(await failing(recordStoreContract((subjects) => seed(new Strict(), subjects))), [
      "files a record idempotently by recordId",
      "files concurrent puts, of one record and of many, without losing one",
    ]);
  });

  it("catches a store that hands out what it stores", async () => {
    class Leaky extends MemoryRecordStore {
      readonly #records = new Map<string, IntakeRecord>();
      override async putIntakeRecord(record: IntakeRecord) {
        this.#records.set(JSON.stringify([record.workspaceId, record.recordId]), record);
      }
      override async getIntakeRecord(workspaceId: string, recordId: string) {
        return this.#records.get(JSON.stringify([workspaceId, recordId])) ?? null;
      }
    }
    assert.deepEqual(await failing(recordStoreContract((subjects) => seed(new Leaky(), subjects))), ["stores an intake record and returns copies"]);
  });
});
