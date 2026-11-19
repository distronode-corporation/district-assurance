// PRV-5: the AuditLedger and RecordStore contract suites, run against the memory adapters, and
// shown to catch adapters that break them.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditEntry, AuditInput, IntakeRecord, SubjectRecord } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { GENESIS_HASH, MemoryAuditLedger, chainEntry } from "../src/prove/ledger.ts";
import { type ContractCase, MemoryRecordStore, type SeededSubject, auditLedgerContract, recordStoreContract, sessionStoreContract } from "../src/testing/index.ts";

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
      async list(fromSeq = 1, limit?: number) {
        if (limit !== undefined && !(Number.isSafeInteger(limit) && limit >= 1)) throw new TypeError("bad limit");
        return this.entries.filter((e) => e.seq >= fromSeq).slice(0, limit);
      }
    }
    assert.deepEqual(await failing(auditLedgerContract(() => new Leaky())), [
      "copies in and out, so a caller cannot change what is stored",
      "appends an eventId once: a second append returns the first entry",
      "returns a copy for a replayed eventId too, so a caller cannot change what is stored",
      "stores one entry for concurrent appends of one eventId",
    ]);
  });

  it("catches a ledger that ignores the page size, or takes any limit", async () => {
    class Unpaged extends MemoryAuditLedger {
      override list(fromSeq?: number): Promise<AuditEntry[]> {
        return super.list(fromSeq);
      }
    }
    assert.deepEqual(await failing(auditLedgerContract(() => new Unpaged())), [
      "lists at most `limit` entries from a seq, as one page",
      "refuses a limit that is not an integer of 1 or more",
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
      // FIL-2 (#78), VER-6 (#74), VER-12 (#124) and PRV-7 (#105) writes; the PRV-5 contract does not exercise them yet.
      async deleteIntakeRecords() {}
      async listIntakeRecords() {
        return [];
      }
      async markSubjectErased() {}
      async subjectErasures() {
        return 0;
      }
      async deletePinDigest() {}
      async putPinDigest() {
        return false;
      }
      async putDuressDigest() {
        return false;
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

/**
 * A key as a store that encodes keys as UTF-8 keeps it: a lone surrogate becomes U+FFFD, so keys
 * that differ only in one collapse into one (SQLite with a TEXT key, #95).
 */
const utf8Key = (key: string): string => Buffer.from(key, "utf8").toString("utf8");

describe("the contracts catch a store that collapses keys differing only in a lone surrogate", () => {
  it("SessionStore", async () => {
    class Collapsing extends MemorySessionStore {
      override create(w: string, c: string, record: JsonValue) {
        return super.create(utf8Key(w), utf8Key(c), record);
      }
      override get(w: string, c: string) {
        return super.get(utf8Key(w), utf8Key(c));
      }
      override compareAndSet(w: string, c: string, version: number, record: JsonValue) {
        return super.compareAndSet(utf8Key(w), utf8Key(c), version, record);
      }
      override bindRef(w: string, ref: string, callId: string) {
        return super.bindRef(utf8Key(w), utf8Key(ref), callId);
      }
      override resolveRef(w: string, ref: string) {
        return super.resolveRef(utf8Key(w), utf8Key(ref));
      }
    }
    assert.deepEqual(await failing(sessionStoreContract(() => new Collapsing())), ["keeps keys that differ only in a lone UTF-16 surrogate apart: workspaces, calls and references"]);
  });

  it("AuditLedger", async () => {
    class Collapsing extends MemoryAuditLedger {
      override append(input: AuditInput) {
        return super.append(input.eventId === undefined ? input : { ...input, eventId: utf8Key(input.eventId) });
      }
    }
    assert.deepEqual(await failing(auditLedgerContract(() => new Collapsing())), ["refuses an eventId holding a lone UTF-16 surrogate, and never stores it as another eventId"]);
  });

  it("RecordStore", async () => {
    class Collapsing extends MemoryRecordStore {
      override putSubject(w: string, subject: SubjectRecord) {
        super.putSubject(utf8Key(w), { ...subject, subjectKey: utf8Key(subject.subjectKey) });
      }
      override async getSubject(w: string, key: string) {
        const got = await super.getSubject(utf8Key(w), utf8Key(key));
        return got === null ? null : { ...got, subjectKey: key };
      }
      override putIntakeRecord(record: IntakeRecord) {
        return super.putIntakeRecord({ ...record, workspaceId: utf8Key(record.workspaceId), recordId: utf8Key(record.recordId) });
      }
      override async getIntakeRecord(w: string, id: string) {
        const got = await super.getIntakeRecord(utf8Key(w), utf8Key(id));
        return got === null ? null : { ...got, workspaceId: w, recordId: id };
      }
    }
    assert.deepEqual(await failing(recordStoreContract((subjects) => seed(new Collapsing(), subjects))), [
      "keeps keys that differ only in a lone UTF-16 surrogate apart: subjects, records and workspaces",
    ]);
  });
});
