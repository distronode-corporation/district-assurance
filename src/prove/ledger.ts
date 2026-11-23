// The append-only, hash-chained audit ledger. Each entry's hash covers its own fields and the
// previous entry's hash, so changing, removing or reordering any entry breaks every hash after
// it. `MemoryAuditLedger` is the reference implementation; a durable one keeps the same chain.
import type { AuditEntry, AuditInput, AuditLedger } from "../core/adapters.ts";
import { canonicalJson, type JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { sha256Hex } from "../core/hash.ts";
import { findCardNumbers } from "../core/redaction.ts";

export const GENESIS_HASH = "0".repeat(64);

/** The hash of an entry: SHA-256 over the canonical JSON of every field except `hash`. */
export function hashEntry(entry: Omit<AuditEntry, "hash">): string {
  return sha256Hex(canonicalJson(entry));
}

const HEX_DIGEST = /^[0-9a-f]{64}$/;

/**
 * Whether any string in a detail value carries a card number. SHA-256 hex digests are skipped:
 * they are fingerprints the engine wrote, and their digit runs would match by chance.
 */
export function detailCarriesCardNumber(value: JsonValue): boolean {
  if (typeof value === "string") return !HEX_DIGEST.test(value) && findCardNumbers(value).length > 0;
  if (value === null || typeof value !== "object") return false;
  const items = Array.isArray(value) ? value : Object.values(value);
  return items.some(detailCarriesCardNumber);
}

/** Builds the next entry of a chain. Refuses detail text that carries a card number. */
export function chainEntry(input: AuditInput, seq: number, prevHash: string): AuditEntry {
  if (detailCarriesCardNumber(input.detail)) {
    throw new EngineError("invalid_input", "audit detail must never carry a card number");
  }
  const unsigned: Omit<AuditEntry, "hash"> = {
    seq,
    prevHash,
    ...(input.eventId === undefined ? {} : { eventId: input.eventId }),
    callId: input.callId,
    actor: input.actor,
    event: input.event,
    at: input.at,
    detail: structuredClone(input.detail),
  };
  return { ...unsigned, hash: hashEntry(unsigned) };
}

/**
 * Whether an entry read back from storage still has its hash. A changed entry can hold what
 * canonical JSON refuses (`1e999` in stored JSON parses as Infinity): that is a break, not a crash.
 */
function hashMatches(entry: Omit<AuditEntry, "hash">, hash: string): boolean {
  try {
    return hashEntry(entry) === hash;
  } catch {
    return false;
  }
}

export type ChainCheck = { ok: true; head: { seq: number; hash: string } } | { ok: false; seq: number; reason: "seq" | "prev_hash" | "hash" };

/**
 * The point a ledger continues from: its base when it has been pruned below one, else the genesis.
 * A ledger with no `base` (one that cannot prune) has never been pruned.
 */
export async function ledgerBase(ledger: AuditLedger): Promise<{ seq: number; hash: string }> {
  return (await ledger.base?.()) ?? { seq: 0, hash: GENESIS_HASH };
}

/**
 * Checks a run of entries. By default the run must start at the genesis; pass `from` to check a
 * slice that continues a known head.
 */
export function verifyChain(entries: readonly AuditEntry[], from: { seq: number; hash: string } = { seq: 0, hash: GENESIS_HASH }): ChainCheck {
  let expectedSeq = from.seq + 1;
  let prevHash = from.hash;
  for (const entry of entries) {
    // Storage can hand back anything: an entry that is not an object is a break at the seq it holds, never a crash.
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return { ok: false, seq: expectedSeq, reason: "seq" };
    if (entry.seq !== expectedSeq) return { ok: false, seq: entry.seq, reason: "seq" };
    if (entry.prevHash !== prevHash) return { ok: false, seq: entry.seq, reason: "prev_hash" };
    const { hash, ...rest } = entry;
    if (!hashMatches(rest, hash)) return { ok: false, seq: entry.seq, reason: "hash" };
    prevHash = hash;
    expectedSeq++;
  }
  return { ok: true, head: { seq: expectedSeq - 1, hash: prevHash } };
}

/** In memory. Entries are copied in and out, so a caller cannot change what is stored. */
export class MemoryAuditLedger implements AuditLedger {
  readonly #entries: AuditEntry[] = [];
  readonly #byEventId = new Map<string, AuditEntry>();
  /** The eventIds of pruned entries: an id the ledger once appended stays spent, its entry gone. */
  readonly #prunedEventIds = new Set<string>();
  #base: { seq: number; hash: string } | null = null;

  async append(input: AuditInput): Promise<AuditEntry> {
    const seen = input.eventId === undefined ? undefined : this.#byEventId.get(input.eventId);
    if (seen !== undefined) return structuredClone(seen);
    if (input.eventId !== undefined && this.#prunedEventIds.has(input.eventId)) {
      throw new EngineError("precondition_failed", "MemoryAuditLedger.append: this eventId's entry was pruned, and the id stays spent");
    }
    const last = this.#entries.at(-1);
    // A pruned ledger's first append continues the chain from its base, the checkpoint it pruned below.
    const prev = last ?? this.#base ?? { seq: 0, hash: GENESIS_HASH };
    const entry = chainEntry(input, prev.seq + 1, prev.hash);
    this.#entries.push(entry);
    if (input.eventId !== undefined) this.#byEventId.set(input.eventId, entry);
    return structuredClone(entry);
  }

  async head(): Promise<{ seq: number; hash: string }> {
    const last = this.#entries.at(-1);
    if (last !== undefined) return { seq: last.seq, hash: last.hash };
    // Every entry pruned: the head is the checkpoint the ledger continues from.
    return this.#base === null ? { seq: 0, hash: GENESIS_HASH } : { ...this.#base };
  }

  async list(fromSeq = 1, limit?: number): Promise<AuditEntry[]> {
    if (limit !== undefined && !(Number.isSafeInteger(limit) && limit >= 1)) throw new TypeError("MemoryAuditLedger.list: limit must be an integer of 1 or more");
    return structuredClone(this.#entries.filter((e) => e.seq >= fromSeq).slice(0, limit));
  }

  async base(): Promise<{ seq: number; hash: string } | null> {
    return this.#base === null ? null : { ...this.#base };
  }

  async prune(checkpoint: { seq: number; hash: string }): Promise<void> {
    if (!(Number.isSafeInteger(checkpoint.seq) && checkpoint.seq >= 1)) {
      throw new TypeError("MemoryAuditLedger.prune: the checkpoint's seq must be an integer of 1 or more");
    }
    if (this.#base !== null && checkpoint.seq <= this.#base.seq) {
      throw new EngineError("precondition_failed", `MemoryAuditLedger.prune: the ledger has already pruned through seq ${this.#base.seq}`);
    }
    const head = await this.head();
    if (checkpoint.seq > head.seq) throw new EngineError("precondition_failed", `MemoryAuditLedger.prune: the ledger does not hold seq ${checkpoint.seq}`);
    const at = this.#entries.findIndex((e) => e.seq === checkpoint.seq);
    // The checkpoint must name this ledger's entry at its seq, never another chain's.
    if (at === -1 || this.#entries[at]!.hash !== checkpoint.hash) {
      throw new EngineError("precondition_failed", "MemoryAuditLedger.prune: the checkpoint does not name an entry of this ledger");
    }
    // The pruned entries' event ids stay spent, their entries gone: a replay must not write a
    // second entry for an id the ledger once appended, and cannot return the first, which no
    // longer exists. A durable store keeps the id (a tombstone row or the like), never frees it.
    for (const removed of this.#entries.splice(0, at + 1)) {
      if (removed.eventId !== undefined) {
        this.#byEventId.delete(removed.eventId);
        this.#prunedEventIds.add(removed.eventId);
      }
    }
    this.#base = { seq: checkpoint.seq, hash: checkpoint.hash };
  }
}
