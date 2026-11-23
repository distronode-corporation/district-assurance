// Ledger export: a run of ledger entries as newline-delimited JSON, one canonical entry per line,
// closed by a signed trailer that names where the run starts, where it ends and the ledger head
// at export time. An auditor or a SIEM checks the trailer with the public key set, the run with
// `verifyChain` from the trailer's start, and takes the next run from the trailer's cursor, so
// consecutive exports join into one checked chain. A pruned ledger exports from its base, the
// checkpoint it pruned below: its runs start there, and a reader pairs them with the signed
// checkpoint (`signLedgerCheckpoint`). Entries never carry values (SPEC.md, section
// 9), so the export carries none either.
import { createPublicKey, verify, type JsonWebKey } from "node:crypto";

import type { AuditEntry, AuditLedger, ReceiptSigner } from "../core/adapters.ts";
import { canonicalJson } from "../core/canonical.ts";
import type { Clock } from "../core/clock.ts";
import { EngineError } from "../core/errors.ts";
import { isObject } from "../core/shape.ts";
import { GENESIS_HASH, ledgerBase, verifyChain } from "./ledger.ts";

/** A point on the chain: an entry's `seq` and `hash`, or `{seq: 0, hash: GENESIS_HASH}`. */
export interface ChainPoint {
  seq: number;
  hash: string;
}

export interface LedgerExportTrailerBody {
  v: 1;
  type: "ledger_export";
  /** The host's name for this ledger, so runs from two ledgers cannot be spliced together. */
  ledgerId: string;
  /** The point the run continues: the entry before its first line. */
  from: ChainPoint;
  /** The last entry in the run; equal to `from` when the run is empty. */
  through: ChainPoint;
  /** Entries in the run. */
  count: number;
  /** The ledger head when the export was taken. The run is complete when `through` reaches it. */
  head: ChainPoint;
  exportedAt: string;
  /** Pass as `cursor` to take the next run. */
  cursor: string;
}

export interface LedgerExportTrailer {
  trailer: LedgerExportTrailerBody;
  alg: "ES256";
  kid: string;
  /** base64url of the 64-byte P1363 signature over `ledgerExportPayload(trailer)`. */
  signature: string;
}

export interface LedgerExportInput {
  ledger: AuditLedger;
  signer: ReceiptSigner;
  clock: Clock;
  ledgerId: string;
  /** The first entry to export, 1 or more. Give this or `cursor`, not both. */
  fromSeq?: number;
  /** A previous trailer's cursor: the run continues right after it, and only if the ledger still holds it. */
  cursor?: string;
  /** At most this many entries; the trailer's cursor takes the rest. */
  limit?: number;
}

/**
 * The signed bytes start with a fixed context line, so a trailer signature can never pass as a
 * receipt signature (whose payload is the bare canonical body) or the other way round, even
 * under the same key.
 */
const PAYLOAD_CONTEXT = "district-assurance ledger export v1\n";

/** The exact bytes that are signed. */
export function ledgerExportPayload(body: LedgerExportTrailerBody): Uint8Array {
  return new TextEncoder().encode(PAYLOAD_CONTEXT + canonicalJson(body));
}

const HEX_DIGEST = /^[0-9a-f]{64}$/;
const CURSOR = /^(0|[1-9][0-9]{0,15})\.([0-9a-f]{64})$/;

/** A cursor names a chain point: `<seq>.<hash>`. It carries no value, only the chain position. */
export function encodeCursor(point: ChainPoint): string {
  return `${point.seq}.${point.hash}`;
}

/** The chain point a cursor names, or null for anything that is not a cursor. */
export function decodeCursor(cursor: string): ChainPoint | null {
  const m = CURSOR.exec(cursor);
  return m === null ? null : { seq: Number(m[1]), hash: m[2]! };
}

function isPositiveInteger(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 1;
}

/** The most entries one read of the walk from a run's end to the head asks for. */
export const EXPORT_WALK_PAGE = 1000;

/**
 * Whether the chain continues from `point` to `head` as the ledger holds it, read in pages of at
 * most EXPORT_WALK_PAGE entries each (a read may bring fewer). A page short of the head is signed only when this holds, so a
 * page that verifies on its own but is not the start of the signed head's chain (an entry swapped
 * for another chain's) is never vouched for. Answers the seq where the walk failed, or null.
 */
async function walkToHead(ledger: AuditLedger, point: ChainPoint, head: ChainPoint): Promise<number | null> {
  let at = point;
  while (at.seq < head.seq) {
    const count = Math.min(EXPORT_WALK_PAGE, head.seq - at.seq);
    // Only the entries asked for: one before them or past them is no part of this read.
    const page = (await ledger.list(at.seq + 1, count)).filter((e) => e.seq > at.seq && e.seq <= at.seq + count);
    const check = verifyChain(page, at);
    if (!check.ok) return check.seq;
    // A ledger may hand back fewer entries than asked ("at most limit"): the walk goes on from
    // where the page ended. A read that brings no entry at all means the chain stops before the head.
    if (check.head.seq === at.seq) return at.seq + 1;
    at = check.head;
  }
  return at.hash === head.hash ? null : head.seq;
}

/**
 * The chain point at `seq` as the ledger holds it, or null when the ledger does not hold it. A
 * pruned ledger's base counts as held: its entry is gone, but the chain continues from it, so a
 * run may start or a cursor may resume there.
 */
async function pointHeld(ledger: AuditLedger, base: ChainPoint, seq: number): Promise<ChainPoint | null> {
  if (seq === 0) return { seq: 0, hash: GENESIS_HASH };
  if (seq === base.seq) return { ...base };
  const [entry] = await ledger.list(seq, 1);
  return entry?.seq === seq ? { seq, hash: entry.hash } : null;
}

/** Where a run starts, from `fromSeq` or a cursor, checked against the ledger and its base. */
async function startPoint(input: { ledger: AuditLedger; base: ChainPoint; fromSeq?: number | undefined; cursor?: string | undefined }, head: ChainPoint): Promise<ChainPoint> {
  if (input.cursor !== undefined) {
    const point = decodeCursor(input.cursor);
    if (point === null || point.seq > head.seq) throw new EngineError("invalid_input", "exportLedger: the cursor is not a cursor of this ledger");
    // A cursor whose entry is gone or different means the ledger changed under it: refuse. The base
    // counts as held, so a cursor naming it resumes there: a pruned ledger's runs start at it.
    const held = await pointHeld(input.ledger, input.base, point.seq);
    if (held?.hash !== point.hash) throw new EngineError("precondition_failed", "exportLedger: the ledger no longer holds the cursor's entry");
    return point;
  }
  const fromSeq = input.fromSeq!;
  if (fromSeq > head.seq + 1) throw new EngineError("invalid_input", "exportLedger: fromSeq is past the ledger head");
  // The earliest a pruned ledger holds is its base: an export that asks for entries below it
  // (a full export) starts at the checkpoint instead, and the run is everything the ledger holds.
  if (fromSeq <= input.base.seq + 1) return { ...input.base };
  const point = await pointHeld(input.ledger, input.base, fromSeq - 1);
  if (point === null) throw new EngineError("precondition_failed", `exportLedger: the ledger does not hold seq ${fromSeq - 1}`);
  return point;
}

/**
 * Exports ledger entries from `fromSeq` (or after a `cursor`) as newline-delimited JSON: one line
 * per entry in canonical JSON, then one trailer line, each ending in a newline. The run stops at
 * the head read when the export starts (and at `limit`). A pruned ledger starts at its base: a
 * `fromSeq` below the base exports everything the ledger still holds, from the checkpoint on, and
 * the trailer's `from` is that checkpoint, which a reader checks against the signed
 * `ledger_checkpoint` (a `fromSeq` or cursor above the base works as on a whole ledger). The run
 * is checked against the chain before the trailer is signed, so a ledger that was tampered with is
 * refused, never vouched for.
 */
export async function* exportLedger(input: LedgerExportInput): AsyncGenerator<string, void, undefined> {
  // Each read once: a getter read again could pass a check with one value and run with another.
  const { ledger, signer, clock, ledgerId, fromSeq, cursor, limit } = input;
  if ((fromSeq === undefined) === (cursor === undefined)) {
    throw new EngineError("invalid_input", "exportLedger: give fromSeq or cursor, exactly one");
  }
  if (fromSeq !== undefined && !isPositiveInteger(fromSeq)) throw new EngineError("invalid_input", "exportLedger: fromSeq must be an integer of 1 or more");
  if (limit !== undefined && !isPositiveInteger(limit)) throw new EngineError("invalid_input", "exportLedger: limit must be an integer of 1 or more");
  if (typeof ledgerId !== "string" || ledgerId === "") throw new EngineError("invalid_input", "exportLedger: ledgerId must be a non-empty string");

  const head = await ledger.head();
  const base = await ledgerBase(ledger);
  // The trailer signs the head, so it must be a point the ledger holds: its last entry, or its
  // base when every entry was pruned (the head is then the checkpoint the chain continues from).
  if ((await pointHeld(ledger, base, head.seq))?.hash !== head.hash) throw new EngineError("precondition_failed", "exportLedger: the ledger head does not match its last entry");
  const from = await startPoint(cursor === undefined ? { ledger, base, fromSeq } : { ledger, base, cursor }, head);
  const last = Math.min(head.seq, from.seq + (limit ?? Number.MAX_SAFE_INTEGER));
  // The run's entries, in reads of at most EXPORT_WALK_PAGE: an adapter that hands back more is cut
  // to what was asked, and one that hands back fewer ("at most limit") is asked again for the
  // rest, until a read brings nothing. Each entry is appended on its own, never spread as arguments.
  const entries: AuditEntry[] = [];
  for (let next = from.seq + 1; next <= last; ) {
    const count = Math.min(EXPORT_WALK_PAGE, last - next + 1);
    const page = (await ledger.list(next, count)).filter((e) => e.seq >= next && e.seq < next + count);
    if (page.length === 0) break;
    for (const entry of page) entries.push(entry);
    next = page.at(-1)!.seq + 1;
  }
  const check = verifyChain(entries, from);
  if (!check.ok) throw new EngineError("precondition_failed", `exportLedger: the ledger chain does not verify at seq ${check.seq}`);
  // A verified prefix is not enough: the run must reach the end it was meant to, and at the head
  // it must end on the head that is signed, so a short or rewritten read is never vouched for.
  if (check.head.seq !== last || (last === head.seq && check.head.hash !== head.hash)) {
    throw new EngineError("precondition_failed", "exportLedger: the ledger run does not reach its expected end");
  }
  // A page short of the head must be the start of the head's chain: walked to the head, in
  // bounded pages, before anything is signed. An export reads the ledger from the run to the head.
  if (last < head.seq) {
    const broken = await walkToHead(ledger, check.head, head);
    if (broken !== null) throw new EngineError("precondition_failed", `exportLedger: the ledger chain does not reach the head from the run's end, at seq ${broken}`);
  }

  const trailer: LedgerExportTrailerBody = {
    v: 1,
    type: "ledger_export",
    ledgerId,
    from,
    through: check.head,
    count: entries.length,
    head,
    exportedAt: clock.now().toISOString(),
    cursor: encodeCursor(check.head),
  };
  // Signed before any line is handed out, so a signer that fails, answers anything but a 64-byte
  // P1363 signature (a key store's DER), or signs with another key than the one it publishes, never
  // leaves a consumer with entries and no valid trailer: the signature is checked against the
  // signer's own public key as an auditor would check it.
  const signature = await signer.sign(ledgerExportPayload(trailer));
  if (signature.byteLength !== 64) throw new EngineError("invalid_input", `exportLedger: the signer returned ${signature.byteLength} bytes, not a 64-byte P1363 signature`);
  const signed: LedgerExportTrailer = { trailer, alg: signer.algorithm, kid: signer.keyId, signature: Buffer.from(signature).toString("base64url") };
  if (!signatureValid(signed, [{ ...signer.publicJwk(), kid: signer.keyId }])) {
    throw new EngineError("invalid_input", "exportLedger: the signer's signature does not verify against its own public key");
  }
  for (const entry of entries) yield `${canonicalJson(entry)}\n`;
  yield `${canonicalJson(signed)}\n`;
}

export type LedgerExportCheck =
  | { ok: true; entries: AuditEntry[]; trailer: LedgerExportTrailerBody }
  | { ok: false; reason: "malformed" | "signature" | "chain" | "continuity"; seq?: number };

function isChainPoint(v: unknown): v is ChainPoint {
  const p = v as ChainPoint;
  return typeof v === "object" && v !== null && Number.isSafeInteger(p.seq) && p.seq >= 0 && typeof p.hash === "string" && HEX_DIGEST.test(p.hash);
}

function isTrailer(v: unknown): v is LedgerExportTrailer {
  const t = v as LedgerExportTrailer;
  if (typeof v !== "object" || v === null || typeof t.trailer !== "object" || t.trailer === null) return false;
  const b = t.trailer;
  return (
    typeof t.kid === "string" &&
    typeof t.signature === "string" &&
    b.v === 1 &&
    b.type === "ledger_export" &&
    typeof b.ledgerId === "string" &&
    isChainPoint(b.from) &&
    isChainPoint(b.through) &&
    isChainPoint(b.head) &&
    b.through.seq >= b.from.seq &&
    b.head.seq >= b.through.seq &&
    b.count === b.through.seq - b.from.seq &&
    typeof b.exportedAt === "string" &&
    b.cursor === encodeCursor(b.through)
  );
}

function signatureValid(t: LedgerExportTrailer, keys: ReadonlyArray<JsonWebKey & { kid?: string }>): boolean {
  if (t.alg !== "ES256" || !Array.isArray(keys)) return false;
  const jwk = keys.find((k: unknown) => typeof k === "object" && k !== null && (k as { kid?: unknown }).kid === t.kid);
  if (jwk === undefined) return false;
  try {
    const key = createPublicKey({ key: jwk, format: "jwk" });
    const signature = Buffer.from(t.signature, "base64url");
    if (signature.length !== 64) return false;
    return verify("sha256", ledgerExportPayload(t.trailer), { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
}

/**
 * Checks an export, given as the whole NDJSON text, against a public key set (the receipt key
 * set, which keeps retired keys). Pass `after`, the previous run's trailer, to also check that
 * this run continues it on the same ledger. Never throws on bad input.
 */
export function verifyLedgerExport(
  ndjson: string,
  keys: ReadonlyArray<JsonWebKey & { kid?: string }>,
  after?: LedgerExportTrailerBody,
): LedgerExportCheck {
  if (typeof ndjson !== "string" || !ndjson.endsWith("\n")) return { ok: false, reason: "malformed" };
  const parsed: unknown[] = [];
  try {
    for (const line of ndjson.slice(0, -1).split("\n")) parsed.push(JSON.parse(line));
  } catch {
    return { ok: false, reason: "malformed" };
  }
  const signed = parsed.pop();
  if (!isTrailer(signed)) return { ok: false, reason: "malformed" };
  if (!signatureValid(signed, keys)) return { ok: false, reason: "signature" };
  const { trailer } = signed;
  if (after !== undefined && (typeof after !== "object" || after === null || after.ledgerId !== trailer.ledgerId || after.cursor !== encodeCursor(trailer.from))) {
    return { ok: false, reason: "continuity" };
  }
  // An entry line that is not an object is malformed, not a break in the chain: verifyChain would
  // report it as a break at the seq it should hold (SRV-7), so it is checked here first.
  if (!parsed.every(isObject)) return { ok: false, reason: "malformed" };
  const entries = parsed as unknown[] as AuditEntry[];
  const check = verifyChain(entries, trailer.from);
  if (!check.ok) return { ok: false, reason: "chain", seq: check.seq };
  // A run cut short does not reach the signed end; a run rebuilt from the same start ends on another hash.
  if (check.head.seq !== trailer.through.seq || check.head.hash !== trailer.through.hash) return { ok: false, reason: "chain" };
  return { ok: true, entries, trailer };
}

