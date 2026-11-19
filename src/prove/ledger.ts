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

export type ChainCheck = { ok: true; head: { seq: number; hash: string } } | { ok: false; seq: number; reason: "seq" | "prev_hash" | "hash" };

/**
 * Checks a run of entries. By default the run must start at the genesis; pass `from` to check a
 * slice that continues a known head.
 */
export function verifyChain(entries: readonly AuditEntry[], from: { seq: number; hash: string } = { seq: 0, hash: GENESIS_HASH }): ChainCheck {
  let expectedSeq = from.seq + 1;
  let prevHash = from.hash;
  for (const entry of entries) {
    if (entry.seq !== expectedSeq) return { ok: false, seq: entry.seq, reason: "seq" };
    if (entry.prevHash !== prevHash) return { ok: false, seq: entry.seq, reason: "prev_hash" };
    const { hash, ...rest } = entry;
    if (hashEntry(rest) !== hash) return { ok: false, seq: entry.seq, reason: "hash" };
    prevHash = hash;
    expectedSeq++;
  }
  return { ok: true, head: { seq: expectedSeq - 1, hash: prevHash } };
}

/** In memory. Entries are copied in and out, so a caller cannot change what is stored. */
export class MemoryAuditLedger implements AuditLedger {
  readonly #entries: AuditEntry[] = [];
  readonly #byEventId = new Map<string, AuditEntry>();

  async append(input: AuditInput): Promise<AuditEntry> {
    const seen = input.eventId === undefined ? undefined : this.#byEventId.get(input.eventId);
    if (seen !== undefined) return structuredClone(seen);
    const last = this.#entries.at(-1);
    const entry = chainEntry(input, (last?.seq ?? 0) + 1, last?.hash ?? GENESIS_HASH);
    this.#entries.push(entry);
    if (input.eventId !== undefined) this.#byEventId.set(input.eventId, entry);
    return structuredClone(entry);
  }

  async head(): Promise<{ seq: number; hash: string }> {
    const last = this.#entries.at(-1);
    return { seq: last?.seq ?? 0, hash: last?.hash ?? GENESIS_HASH };
  }

  async list(fromSeq = 1, limit?: number): Promise<AuditEntry[]> {
    if (limit !== undefined && !(Number.isSafeInteger(limit) && limit >= 1)) throw new TypeError("MemoryAuditLedger.list: limit must be an integer of 1 or more");
    return structuredClone(this.#entries.filter((e) => e.seq >= fromSeq).slice(0, limit));
  }
}
