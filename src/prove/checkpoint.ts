// A signed checkpoint of a pruned ledger: the last entry a host removed, with how many entries that
// prune cut and when, signed under its own domain so it can never verify as a receipt or an export
// trailer. A reader who holds the checkpoint and the entries after it can check the chain from the
// checkpoint on without the entries before it, which are gone; the signature is the host's word that
// the chain stood there. A host writes the checkpoint (its own storage, as it keeps export
// trailers), then prunes below it with `pruneLedger`; the trailer a full export signed over the same
// point plays the same role today, and this is its first-class form.
import { createPublicKey, verify, type JsonWebKey } from "node:crypto";

import type { AuditLedger, ReceiptSigner } from "../core/adapters.ts";
import { canonicalJson } from "../core/canonical.ts";
import type { Clock } from "../core/clock.ts";
import { EngineError } from "../core/errors.ts";
import { isObject } from "../core/shape.ts";
import type { ChainPoint } from "./export.ts";
import { EXPORT_WALK_PAGE } from "./export.ts";
import { ledgerBase, verifyChain, type ChainCheck } from "./ledger.ts";
import type { SignedDocument } from "./receipt.ts";

/** Named in the signed bytes, ahead of the body, so a checkpoint and a receipt never verify as each other. */
export const LEDGER_CHECKPOINT_DOMAIN = "district-assurance/ledger-checkpoint/v1";

/** A checkpoint of a pruned ledger: the point the chain continues from, signed by the host. */
export interface LedgerCheckpointBody {
  v: 1;
  type: "ledger_checkpoint";
  /** The host's name for this ledger, as an export trailer's: a checkpoint cannot be moved to another ledger's history. */
  ledgerId: string;
  /** The last entry the prune removed: the first entry the ledger still holds is `seq + 1`. */
  seq: number;
  /** The entry at `seq`, as the verified chain read it. */
  hash: string;
  /** How many entries this checkpoint cut: the gap between the ledger's previous base and this one. */
  prunedCount: number;
  /** ISO 8601: when the checkpoint was signed. */
  at: string;
}

export type SignedLedgerCheckpoint = SignedDocument<LedgerCheckpointBody>;

/** A checkpoint a host passes with the key set that verifies it, wherever a reader or an export anchors on one. */
export interface LedgerCheckpointRef {
  checkpoint: SignedLedgerCheckpoint;
  keys: ReadonlyArray<JsonWebKey & { kid?: string }>;
}

/** The exact bytes that are signed: the domain, a newline, then the canonical body. */
export function ledgerCheckpointPayload(body: LedgerCheckpointBody): Uint8Array {
  return new TextEncoder().encode(`${LEDGER_CHECKPOINT_DOMAIN}\n${canonicalJson(body)}`);
}

const HEX_DIGEST = /^[0-9a-f]{64}$/;

/** An ISO 8601 UTC time as the engine writes it (`toISOString`). */
function isUtcTime(value: unknown): value is string {
  return typeof value === "string" && (() => {
    const ms = Date.parse(value);
    return !Number.isNaN(ms) && new Date(ms).toISOString() === value;
  })();
}

function isCheckpointBody(body: unknown): body is LedgerCheckpointBody {
  if (!isObject(body)) return false;
  const b = body as unknown as LedgerCheckpointBody;
  return (
    b.v === 1 &&
    b.type === "ledger_checkpoint" &&
    typeof b.ledgerId === "string" &&
    b.ledgerId !== "" &&
    Number.isSafeInteger(b.seq) &&
    b.seq >= 1 &&
    typeof b.hash === "string" &&
    HEX_DIGEST.test(b.hash) &&
    // At least one entry was cut, and never more than the seq covers: there are only `seq` entries below it.
    Number.isSafeInteger(b.prunedCount) &&
    b.prunedCount >= 1 &&
    b.prunedCount <= b.seq &&
    isUtcTime(b.at)
  );
}

export type LedgerCheckpointCheck =
  | { ok: true; point: ChainPoint; body: LedgerCheckpointBody }
  | { ok: false; reason: "malformed" | "signature" };

/**
 * Checks a signed checkpoint against a public key set (the receipt key set), as
 * `verifyLedgerExport` checks a trailer. Never throws: bad input of any shape is `malformed`, an
 * unknown `kid`, a wrong algorithm, a malformed signature or any change to the body is `signature`.
 * The whole key set verifies checkpoints, a retired key included: a checkpoint carries no issue time
 * to hold against a retirement. Answers the checkpoint's point, which a reader hands to
 * `verifyChain` as its starting point.
 */
export function verifyLedgerCheckpoint(checkpoint: unknown, keys: ReadonlyArray<JsonWebKey & { kid?: string }>): LedgerCheckpointCheck {
  // A parsed checkpoint can be anything: check the envelope before reading it.
  if (typeof checkpoint !== "object" || checkpoint === null) return { ok: false, reason: "malformed" };
  if (!Array.isArray(keys)) return { ok: false, reason: "signature" };
  const signed = checkpoint as SignedLedgerCheckpoint;
  if (signed.alg !== "ES256" || typeof signed.kid !== "string" || signed.kid === "" || typeof signed.signature !== "string") {
    return { ok: false, reason: "malformed" };
  }
  if (!isCheckpointBody(signed.body)) return { ok: false, reason: "malformed" };
  try {
    const jwk = keys.find((k: unknown) => typeof k === "object" && k !== null && (k as { kid?: unknown }).kid === signed.kid);
    if (jwk === undefined) return { ok: false, reason: "signature" };
    const key = createPublicKey({ key: jwk, format: "jwk" });
    const signature = Buffer.from(signed.signature, "base64url");
    if (signature.length !== 64) return { ok: false, reason: "signature" };
    if (!verify("sha256", ledgerCheckpointPayload(signed.body), { key, dsaEncoding: "ieee-p1363" }, signature)) {
      return { ok: false, reason: "signature" };
    }
    return { ok: true, point: { seq: signed.body.seq, hash: signed.body.hash }, body: signed.body };
  } catch {
    return { ok: false, reason: "signature" };
  }
}

/**
 * The chain from `from` up to `seq`, read in pages of at most `EXPORT_WALK_PAGE` entries and
 * verified as it goes. Answers the check for the pages it read: `head.seq` reaches `seq` when the
 * ledger holds it, and stays short of it when a read brings nothing more.
 */
async function chainTo(ledger: AuditLedger, from: ChainPoint, seq: number): Promise<ChainCheck> {
  let at = from;
  for (;;) {
    const count = Math.min(EXPORT_WALK_PAGE, seq - at.seq);
    // Only the entries asked for: one before them or past them is no part of this read.
    const page = (await ledger.list(at.seq + 1, count)).filter((e) => e.seq > at.seq && e.seq <= at.seq + count);
    const check = verifyChain(page, at);
    if (!check.ok) return check;
    // A read that brings no entry at all means the chain stops before `seq`.
    if (check.head.seq === at.seq) return check;
    if (check.head.seq >= seq) return check;
    at = check.head;
  }
}

function isPositiveInteger(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 1;
}

export interface LedgerCheckpointInput {
  signer: ReceiptSigner;
  clock: Clock;
  ledgerId: string;
  /** The entry to checkpoint, 1 or more: the head when left out. */
  seq?: number;
}

/**
 * Signs a checkpoint of the ledger at `seq` (the head by default): the chain from the ledger's base
 * to that entry is read in bounded pages and verified before anything is signed, so a ledger that
 * was tampered with is never vouched for. Refuses an empty ledger, a `seq` past the head, a `seq`
 * at or below the base the ledger has already pruned to (nothing would be cut), a `ledgerId` that
 * is not a non-empty string, and a signer that does not answer a 64-byte P1363 signature or does not
 * verify against its own public key. The answer is the document the host writes before pruning;
 * `prunedCount` is the gap between the base and the checkpoint.
 */
export async function signLedgerCheckpoint(ledger: AuditLedger, input: LedgerCheckpointInput): Promise<SignedLedgerCheckpoint> {
  // Each input is read once: a getter read again could pass a check with one value and sign with another.
  const { signer, clock, ledgerId, seq } = input;
  if (typeof ledgerId !== "string" || ledgerId === "") throw new EngineError("invalid_input", "signLedgerCheckpoint: ledgerId must be a non-empty string");
  if (seq !== undefined && !isPositiveInteger(seq)) throw new EngineError("invalid_input", "signLedgerCheckpoint: seq must be an integer of 1 or more");
  const head = await ledger.head();
  if (head.seq === 0) throw new EngineError("precondition_failed", "signLedgerCheckpoint: the ledger is empty; there is no entry to checkpoint");
  const at = seq ?? head.seq;
  if (at > head.seq) throw new EngineError("invalid_input", `signLedgerCheckpoint: seq ${at} is past the ledger head`);
  const base = await ledgerBase(ledger);
  if (at <= base.seq) throw new EngineError("precondition_failed", `signLedgerCheckpoint: the ledger has already pruned through seq ${base.seq}, and nothing would be cut`);
  const check = await chainTo(ledger, base, at);
  if (!check.ok) throw new EngineError("precondition_failed", `signLedgerCheckpoint: the ledger chain does not verify at seq ${check.seq}`);
  if (check.head.seq !== at) throw new EngineError("precondition_failed", `signLedgerCheckpoint: the ledger does not hold seq ${at}`);
  const body: LedgerCheckpointBody = {
    v: 1,
    type: "ledger_checkpoint",
    ledgerId,
    seq: at,
    hash: check.head.hash,
    prunedCount: at - base.seq,
    at: clock.now().toISOString(),
  };
  // Signed as an export signs its trailer: a failing signer never leaves a host with a checkpoint
  // that cannot verify, and the signature is checked against the signer's own public key.
  const signature = await signer.sign(ledgerCheckpointPayload(body));
  if (signature.byteLength !== 64) {
    throw new EngineError("invalid_input", `signLedgerCheckpoint: the signer returned ${signature.byteLength} bytes, not a 64-byte P1363 signature`);
  }
  const signed: SignedLedgerCheckpoint = { body, alg: signer.algorithm, kid: signer.keyId, signature: Buffer.from(signature).toString("base64url") };
  if (!verifyLedgerCheckpoint(signed, [{ ...signer.publicJwk(), kid: signer.keyId }]).ok) {
    throw new EngineError("invalid_input", "signLedgerCheckpoint: the signer's signature does not verify against its own public key");
  }
  return signed;
}

export interface PruneLedgerInput {
  /** The host's name for this ledger: the checkpoint must name it, and never another ledger's. */
  ledgerId: string;
  checkpoint: SignedLedgerCheckpoint;
  keys: ReadonlyArray<JsonWebKey & { kid?: string }>;
}

/**
 * Prunes the ledger below the checkpoint the host wrote: the checkpoint is verified against the
 * key set and must name this ledger, the point it names must be the ledger's (its base, when that
 * checkpoint was already pruned below, or an entry it holds with that hash), its `prunedCount`
 * must name the gap it cuts here, and the ledger's `prune` removes every entry at or below it,
 * as one step. Refuses a checkpoint the ledger has already pruned past, one that does not verify,
 * one signed before an earlier prune (its `prunedCount` no longer names the gap), and a ledger
 * that cannot prune. The checkpoint is the host's to write first: pruning below a checkpoint that
 * no longer exists leaves a ledger nobody can check. Answers the point the ledger is now pruned
 * below; the same checkpoint handed in again, also by a second pruner racing the first, prunes
 * nothing and answers the point.
 */
export async function pruneLedger(ledger: AuditLedger, input: PruneLedgerInput): Promise<ChainPoint> {
  if (ledger.prune === undefined || ledger.base === undefined) {
    throw new EngineError("precondition_failed", "pruneLedger: this ledger cannot prune");
  }
  const { ledgerId, keys } = input;
  if (typeof ledgerId !== "string" || ledgerId === "") throw new EngineError("invalid_input", "pruneLedger: ledgerId must be a non-empty string");
  const check = verifyLedgerCheckpoint(input.checkpoint, keys);
  if (!check.ok) {
    throw new EngineError(
      "invalid_input",
      check.reason === "signature" ? "pruneLedger: the checkpoint's signature does not verify against the key set" : "pruneLedger: not a signed ledger_checkpoint document",
    );
  }
  if (check.body.ledgerId !== ledgerId) {
    throw new EngineError("invalid_input", `pruneLedger: the checkpoint names the ledger ${check.body.ledgerId}, not ${ledgerId}`);
  }
  const base = await ledgerBase(ledger);
  const point = check.point;
  // A checkpoint the ledger has already pruned past never prunes again: the base only moves forward.
  if (point.seq < base.seq || (point.seq === base.seq && point.hash !== base.hash)) {
    throw new EngineError("precondition_failed", `pruneLedger: the ledger has already pruned through seq ${base.seq}`);
  }
  // The same checkpoint handed in again after its prune: already done, and pruning nothing.
  if (point.seq === base.seq) return point;
  if (check.body.prunedCount !== point.seq - base.seq) {
    throw new EngineError("invalid_input", `pruneLedger: the checkpoint says it cuts ${check.body.prunedCount} entries, but this prune cuts ${point.seq - base.seq}: sign it again after the last prune`);
  }
  // The checkpoint must name this ledger's entry at its seq, read once before anything is removed.
  const [entry] = await ledger.list(point.seq, 1);
  if (entry?.seq !== point.seq || entry.hash !== point.hash) {
    throw new EngineError("precondition_failed", "pruneLedger: the ledger does not hold the checkpoint's entry");
  }
  try {
    await ledger.prune(point);
  } catch (error) {
    // A second pruner with the same checkpoint may have raced this one to it: the ledger pruned
    // below the point already, and refusing would read as a failure of a prune that happened.
    const after = await ledger.base();
    if (after !== null && after.seq === point.seq && after.hash === point.hash) return point;
    throw error;
  }
  // Read back: a prune that answered without moving the base leaves a host exporting below its base.
  const after = await ledger.base();
  if (after === null || after.seq !== point.seq || after.hash !== point.hash) {
    throw new EngineError("precondition_failed", "pruneLedger: the ledger did not prune to the checkpoint");
  }
  return point;
}
