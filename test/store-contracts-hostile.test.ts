// Hostile-pass regressions for #73 (PRV-5, the store contracts): broken stores that must fail a
// contract. T1, T3, T4 and T5 passed the contracts before their cases were added; T2 was caught.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditEntry, AuditInput, SessionStore, StoredSession } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { MemoryAuditLedger, chainEntry, GENESIS_HASH } from "../src/prove/ledger.ts";
import { auditLedgerContract, sessionStoreContract } from "../src/testing/index.ts";

const tick = () => new Promise((resolve) => setImmediate(resolve));

async function failures(cases: Array<{ name: string; run: () => Promise<void> }>): Promise<string[]> {
  const failed: string[] = [];
  for (const c of cases) await c.run().catch(() => failed.push(c.name));
  return failed;
}

/** Keeps the record a compareAndSet was given, not a copy of it. */
class AliasingWrites extends MemorySessionStore {
  readonly #live = new Map<string, StoredSession>();
  override async compareAndSet(w: string, c: string, v: number, record: JsonValue) {
    const result = await super.compareAndSet(w, c, v, record);
    if (result.ok) this.#live.set(JSON.stringify([w, c]), { version: result.version, record });
    return result;
  }
  override async get(w: string, c: string) {
    return this.#live.get(JSON.stringify([w, c])) ?? super.get(w, c);
  }
}

/** Checks, waits, then writes: two creates of one id at once both succeed, and the second wins. */
class RacyCreate extends MemorySessionStore {
  readonly #rows = new Map<string, StoredSession>();
  override async create(w: string, c: string, record: JsonValue) {
    const key = JSON.stringify([w, c]);
    if (this.#rows.has(key)) return false;
    await tick();
    this.#rows.set(key, { version: 1, record: structuredClone(record) });
    return super.create(w, c, record).then(() => true);
  }
  override async get(w: string, c: string) {
    const row = this.#rows.get(JSON.stringify([w, c]));
    return row === undefined ? super.get(w, c) : structuredClone(row);
  }
}

/** The same race on references: two binds of one reference at once both succeed, the last wins. */
class RacyBind implements SessionStore {
  readonly #inner = new MemorySessionStore();
  readonly #refs = new Map<string, string>();
  create = (w: string, c: string, r: JsonValue) => this.#inner.create(w, c, r);
  get = (w: string, c: string) => this.#inner.get(w, c);
  compareAndSet = (w: string, c: string, v: number, r: JsonValue) => this.#inner.compareAndSet(w, c, v, r);
  async bindRef(w: string, ref: string, callId: string) {
    const key = JSON.stringify([w, ref]);
    if (this.#refs.has(key)) return false;
    await tick();
    this.#refs.set(key, callId);
    return true;
  }
  async resolveRef(w: string, ref: string) {
    return this.#refs.get(JSON.stringify([w, ref])) ?? null;
  }
}

/** A reference bound in one workspace blocks the same reference in every other. */
class GlobalRefs implements SessionStore {
  readonly #inner = new MemorySessionStore();
  readonly #refs = new Map<string, { w: string; callId: string }>();
  create = (w: string, c: string, r: JsonValue) => this.#inner.create(w, c, r);
  get = (w: string, c: string) => this.#inner.get(w, c);
  compareAndSet = (w: string, c: string, v: number, r: JsonValue) => this.#inner.compareAndSet(w, c, v, r);
  async bindRef(w: string, ref: string, callId: string) {
    if (this.#refs.has(ref)) return false;
    this.#refs.set(ref, { w, callId });
    return true;
  }
  async resolveRef(w: string, ref: string) {
    const found = this.#refs.get(ref);
    return found !== undefined && found.w === w ? found.callId : null;
  }
}

/** Hands back the stored entry itself, not a copy, for an eventId it already holds. */
class AliasingReplay extends MemoryAuditLedger {
  readonly #byId = new Map<string, AuditEntry>();
  readonly #rows: AuditEntry[] = [];
  override async append(input: AuditInput): Promise<AuditEntry> {
    const seen = input.eventId === undefined ? undefined : this.#byId.get(input.eventId);
    if (seen !== undefined) return seen;
    const last = this.#rows.at(-1);
    const entry = chainEntry(structuredClone(input), (last?.seq ?? 0) + 1, last?.hash ?? GENESIS_HASH);
    this.#rows.push(entry);
    if (input.eventId !== undefined) this.#byId.set(input.eventId, entry);
    return structuredClone(entry);
  }
  override async head() {
    const last = this.#rows.at(-1);
    return { seq: last?.seq ?? 0, hash: last?.hash ?? GENESIS_HASH };
  }
  override async list(fromSeq = 1, limit?: number) {
    if (limit !== undefined && !(Number.isSafeInteger(limit) && limit >= 1)) throw new TypeError("bad limit");
    return structuredClone(this.#rows.filter((e) => e.seq >= fromSeq).slice(0, limit));
  }
}

describe("hostile #73: the contracts catch", () => {
  it("T1: a session store that keeps the record a write was given, not a copy", async () => {
    assert.notDeepEqual(await failures(sessionStoreContract(() => new AliasingWrites())), []);
  });

  it("T2: a session store whose create checks, waits, then writes (two creates of one id both succeed)", async () => {
    assert.notDeepEqual(await failures(sessionStoreContract(() => new RacyCreate())), []);
  });

  it("T3: a session store whose bindRef checks, waits, then writes (two binds both succeed)", async () => {
    assert.notDeepEqual(await failures(sessionStoreContract(() => new RacyBind())), []);
  });

  it("T4: a session store where a reference in one workspace blocks the same reference in another", async () => {
    assert.notDeepEqual(await failures(sessionStoreContract(() => new GlobalRefs())), []);
  });

  it("T5: a ledger that hands back the stored entry itself for an eventId it already holds", async () => {
    assert.notDeepEqual(await failures(auditLedgerContract(() => new AliasingReplay())), []);
  });

  it("T6: the memory stores pass them all", async () => {
    assert.deepEqual(await failures(sessionStoreContract(() => new MemorySessionStore())), []);
    assert.deepEqual(await failures(auditLedgerContract(() => new MemoryAuditLedger())), []);
  });
});
