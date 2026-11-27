// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile-pass regressions for #73 (PRV-5, the store contracts): broken stores that must fail a
// contract. T1, T3, T4, T5 and T7 passed the contracts before their cases were added; T2 was caught.
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

  it("T6: a ledger that quietly ignores a prune it must refuse (below its base)", async () => {
    class SilentRollback extends MemoryAuditLedger {
      override async prune(checkpoint: { seq: number; hash: string }): Promise<void> {
        await super.prune(checkpoint).catch(() => undefined);
      }
    }
    assert.ok(
      (await failures(auditLedgerContract(() => new SilentRollback()))).includes(
        "refuses to prune at or below its base, past its head, or at an entry it does not hold",
      ),
      "a store that swallows the refusal instead of throwing fails the case",
    );
  });

  it("T7: a store whose prune removes the rows and moves the base as two steps, torn apart by an append", async () => {
    // The removal and the base move must be one step: an append landing between them sees the rows
    // gone and no base moved, chains from the genesis, and forks the ledger (review of #170). This
    // store has its own rows so the tear is exact; it may fail other cases for its shortcuts, the
    // point is the race case catching what the earlier pruned-ledger cases missed.
    class TornPruner extends MemoryAuditLedger {
      readonly rows: AuditEntry[] = [];
      override async append(i: AuditInput): Promise<AuditEntry> {
        const seen = i.eventId === undefined ? undefined : this.rows.find((e) => e.eventId === i.eventId);
        if (seen !== undefined) return structuredClone(seen);
        const prev = this.rows.at(-1) ?? (await this.base()) ?? { seq: 0, hash: GENESIS_HASH };
        const entry = chainEntry(i, prev.seq + 1, prev.hash);
        this.rows.push(entry);
        return structuredClone(entry);
      }
      override async head() {
        const last = this.rows.at(-1);
        const base = await this.base();
        return last !== undefined ? { seq: last.seq, hash: last.hash } : (base ?? { seq: 0, hash: GENESIS_HASH });
      }
      override async list(fromSeq = 1, limit?: number) {
        return structuredClone(this.rows.filter((e) => e.seq >= fromSeq).slice(0, limit));
      }
      #baseValue: { seq: number; hash: string } | null = null;
      override async base() {
        return this.#baseValue === null ? null : { ...this.#baseValue };
      }
      override async prune(checkpoint: { seq: number; hash: string }): Promise<void> {
        const at = this.rows.findIndex((e) => e.seq === checkpoint.seq);
        if (at === -1 || this.rows[at]!.hash !== checkpoint.hash) throw new Error("not held");
        // Statement 1: the rows go. Statement 2, after a round trip of its own: the base moves.
        this.rows.splice(0, at + 1);
        await new Promise((resolve) => setImmediate(resolve));
        this.#baseValue = { ...checkpoint };
      }
    }
    const failed: string[] = [];
    for (const c of auditLedgerContract(() => new TornPruner())) await c.run().catch(() => failed.push(c.name));
    assert.ok(failed.includes("keeps one consistent ledger while a prune races appends"), `the race case catches the torn store (failed: ${failed.join("; ")})`);
    // And the tear itself, directly: an append during the prune chains from the genesis.
    const torn = new TornPruner();
    for (let n = 1; n <= 3; n++) await torn.append({ callId: `c${n}`, actor: "code", event: "module.event", at: "2026-01-01T00:00:00.000Z", detail: { n } });
    const [third] = await torn.list(3, 1);
    const pruned = torn.prune({ seq: 3, hash: third!.hash });
    // Appends right away: it runs while the prune is parked between its two statements.
    const forked = await torn.append({ callId: "c4", actor: "code", event: "module.event", at: "2026-01-01T00:00:00.000Z", detail: { n: 4 } });
    await pruned;
    assert.equal(forked.prevHash, GENESIS_HASH, "the append between the two statements chains from the genesis");
  });

  it("T8: the memory stores pass them all", async () => {
    assert.deepEqual(await failures(sessionStoreContract(() => new MemorySessionStore())), []);
    assert.deepEqual(await failures(auditLedgerContract(() => new MemoryAuditLedger())), []);
  });
});
