// Access and deletion requests for one subject (PRV-7). A person can ask the business for what it
// holds about them, and in some cases ask it to delete that; what the law requires in a given case
// is the business's to decide. These are host calls the business makes from its own code, never a
// step of a call: they take no call id, no flow step names them, and nothing a caller or the model
// says can reach them.
//
// The export lists what the engine stored about the subject and is signed under its own domain
// (the signed bytes name the document type), so it can never verify as a receipt. The erase
// deletes the subject's intake records and PIN digest through the RecordStore and appends
// `subject.erased`. It never changes a ledger entry or a receipt: they hold ids and digests, never
// values, and changing them would break the chain or a signature.
import { createPublicKey, verify, type JsonWebKey } from "node:crypto";

import type { AttemptCounterKey, AttemptCounters, AuditEntry, ConsentRevocation, ConsentStore, IntakeRecord, ReceiptSigner, RecordStore } from "../core/adapters.ts";
import { canonicalJson } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import type { CallRecord, EngineRuntime } from "../core/runtime.ts";
import { isObject, unknownKeys } from "../core/shape.ts";
import type { ConsentRecord } from "./consent.ts";
import { TRACE, type TraceSlice } from "./trace.ts";
import { CALLBACKS_PLACED } from "../verify/callback.ts";
import { FLOW_START, noticeKey } from "../verify/counters.ts";
import { duressFlagKey, hiddenCounterKey, isUnderDuress, recordClear } from "../verify/duress-flag.ts";

/** Named in the signed bytes, ahead of the body, so an export and a receipt never verify as each other. */
export const SUBJECT_EXPORT_DOMAIN = "district-assurance/subject-export/v1";

/** Something kept after an erase, or held outside the engine, and why. */
export interface KeptItem {
  what: string;
  reason: string;
}

export interface SubjectExportBody {
  v: 1;
  type: "subject_export";
  exportId: string;
  workspaceId: string;
  subjectKey: string;
  issuedAt: string;
  /** The intake records filed under the subject, values included. */
  intakeRecords: IntakeRecord[];
  /** Whether a PIN digest is on file. Never the digest. */
  pinDigestOnFile: boolean;
  /** The consents recorded under the subject on the calls below, each with its original answer. */
  consents: ConsentRecord[];
  /** The revocations the ConsentStore holds for those consents (none without one), by consent id. */
  revocations: ConsentRevocation[];
  /** The calls the intake records name. */
  calls: string[];
  /** The ledger entries naming one of the records, consents or receipts: ids only. */
  ledgerEntries: Array<{ seq: number; hash: string; event: string; callId: string | null }>;
  receipts: Array<{ receiptId: string; callId: string }>;
  /** Data about the subject that the host holds, not the engine. */
  heldByHost: KeptItem[];
  /** What an erase keeps, and why: the engine's own reasons, then the business's. */
  kept: KeptItem[];
  /** What this export cannot find. */
  limits: string[];
}

export interface SignedSubjectExport {
  body: SubjectExportBody;
  alg: "ES256";
  kid: string;
  /** base64url of the 64-byte P1363 signature over `subjectExportPayload(body)`. */
  signature: string;
}

export interface SubjectRequest {
  workspaceId: string;
  /** The subject key (64 lower-case hex), as Badge matched it. */
  subjectKey: string;
}

export interface ErasureResult {
  /** False when nothing was on file: nothing was deleted and nothing appended. */
  erased: boolean;
  /** The intake records deleted. */
  recordIds: string[];
  /** Whether a PIN digest was deleted. */
  pinDigest: boolean;
  /** The `subject.erased` ledger entry, or null. */
  entry: AuditEntry | null;
}

const ENGINE_KEPT: readonly KeptItem[] = [
  {
    what: "ledger entries",
    reason:
      "The ledger is append-only and hash-chained: changing or removing an entry breaks every hash after it. Entries hold ids and SHA-256 digests of record values, never the values, and are kept as integrity records for the retention period. An unkeyed SHA-256 of a short value can be confirmed by anyone who guesses the value and hashes it.",
  },
  {
    what: "receipts",
    reason:
      "A signed receipt carries the same record digests, kept as integrity records for the retention period; changing one breaks its signature. The same caution about guessing short values applies.",
  },
  {
    what: "call records",
    reason:
      "Each call record in the SessionStore keeps the record digests (as the receipt does), the call's consents and Badge's working copy of the matched subject (the keyed digests of the values on file and the number on file, never the PIN digest) until the host's session retention removes it. The erase drops the copy of a record's values a call keeps.",
  },
  {
    what: "consents",
    reason:
      "Consents stay in their call records, and in the host's ConsentStore when the engine has one, where a later revocation finds them; a consent, or its refusal, can be the business's proof of what the caller agreed to.",
  },
];

const HELD_BY_HOST: readonly KeptItem[] = [
  {
    what: "subject record",
    reason:
      "The subject record (the number on file and the keyed digests of the values on file) is the host's data, read through its RecordStore; the host answers for it. An erase removes only its PIN and duress PIN digests.",
  },
  {
    what: "PIN in the host's PIN store",
    reason:
      "With the PIN factor in verifier mode, the PIN stays in the host's own PIN store, which the engine never reads: pinDigestOnFile says nothing about it, and an erase cannot delete it.",
  },
];

const LIMITS: readonly string[] = [
  "A record filed on a call with no matched subject (no keypad or PIN match before it was confirmed) is filed under no subject: this export cannot find it, and an erase cannot delete it.",
  "Consents are found only on the calls listed here (the calls of the subject's records in the RecordStore, a record still being filed included), and only on those still in the SessionStore: a call the host's session retention removed is listed, but its consents are not (the ConsentStore is read by consent id, never by subject), and only those recorded once the call matched this subject: a consent recorded before any match, or under another subject, is not listed.",
  "A record being filed when the export is taken can be listed before its filing is confirmed: the engine writes it to the RecordStore first, and deletes it by id if the filing then fails, is refused or is abandoned. Until that delete succeeds the record stays and is listed: after a refusal the delete is tried once, and a failed release or abandonment is carried on by the next confirmation or abandonIntake call.",
  "Attempts are counted across calls under the subject and under a keyed digest of the calling number. This export does not list them. An erase resets the subject's: each installed factor's failures and lock notices, its hidden duress count, flow starts, callbacks placed and the duress flag. The calling number's counters are not the subject's and stay until their window passes. A subject under duress gets one more entry in its count of duress clearings, which is kept (a time per clearing, under the subject key), so a duress alert delivered after the erase never sets the flag again.",
];

/** The exact bytes that are signed: the domain, a newline, then the canonical body. */
export function subjectExportPayload(body: SubjectExportBody): Uint8Array {
  return new TextEncoder().encode(`${SUBJECT_EXPORT_DOMAIN}\n${canonicalJson(body)}`);
}

/**
 * Checks an export against a key set, as `verifyReceipt` checks a receipt. False for an unknown
 * `kid`, a wrong algorithm, a malformed signature or any change to the body. Never throws on bad input.
 */
export function verifySubjectExport(exported: SignedSubjectExport, keys: ReadonlyArray<JsonWebKey & { kid?: string }>): boolean {
  try {
    if (exported.alg !== "ES256") return false;
    // A string kid only: an export and a key that both omit it would otherwise match.
    if (typeof exported.kid !== "string") return false;
    const jwk = keys.find((k) => k.kid === exported.kid);
    if (jwk === undefined) return false;
    const key = createPublicKey({ key: jwk, format: "jwk" });
    const signature = Buffer.from(exported.signature, "base64url");
    if (signature.length !== 64) return false;
    return verify("sha256", subjectExportPayload(exported.body), { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
}

/** The request's fields, each read once. Not an object is invalid_input, never a TypeError. */
function readRequest(input: unknown): { workspaceId: unknown; subjectKey: unknown; kept: unknown } {
  if (!isObject(input)) throw new EngineError("invalid_input", "a subject request is an object: { workspaceId, subjectKey }");
  const { workspaceId, subjectKey, kept } = input;
  return { workspaceId, subjectKey, kept };
}

function checkRequest(rt: EngineRuntime, input: { workspaceId: unknown; subjectKey: unknown }): RecordStore {
  if (input.workspaceId !== rt.workspaceId) throw new EngineError("invalid_input", "the request names another workspace");
  // A string only: a regex test coerces, so an array of the key would pass and then miss the
  // subject's records (found by equality) while finding its PIN digest (found by the key's text).
  if (typeof input.subjectKey !== "string" || !/^[0-9a-f]{64}$/.test(input.subjectKey)) {
    throw new EngineError("invalid_input", "subjectKey must be 64 lower-case hex characters");
  }
  const records: RecordStore | undefined = rt.adapter("records");
  if (records === undefined) throw new EngineError("precondition_failed", "subject requests need the records adapter");
  return records;
}

function checkKept(kept: unknown): KeptItem[] {
  if (kept === undefined) return [];
  const ok =
    Array.isArray(kept) &&
    kept.every(
      (k: unknown) =>
        isObject(k) &&
        unknownKeys(k, ["what", "reason"]).length === 0 &&
        typeof k.what === "string" &&
        k.what.trim() !== "" &&
        typeof k.reason === "string" &&
        k.reason.trim() !== "",
    );
  if (!ok) throw new EngineError("invalid_input", "kept must be a list of { what, reason }, both non-empty text");
  return (kept as KeptItem[]).map((k) => ({ what: k.what, reason: k.reason }));
}

/** The work's result, or null when the call is gone (the host's session retention removed it). */
async function unlessGone<T>(work: Promise<T>): Promise<T | null> {
  try {
    return await work;
  } catch (e) {
    if (e instanceof EngineError && e.code === "unknown_call") return null;
    throw e;
  }
}

function callsOf(records: readonly IntakeRecord[]): string[] {
  return [...new Set(records.map((r) => r.callId))];
}

/**
 * Everything the engine stored about one subject, as one signed JSON bundle. `kept` adds what the
 * business must keep by law, with its reason; the engine lists its own. Needs the `records` and
 * `signer` adapters. Reads the whole ledger once.
 */
export async function exportSubject(rt: EngineRuntime, input: SubjectRequest & { kept?: KeptItem[] }): Promise<SignedSubjectExport> {
  // Read once: the subject key checked is the one whose data is gathered and named in the export.
  const { workspaceId, subjectKey: key, kept } = readRequest(input);
  const records = checkRequest(rt, { workspaceId, subjectKey: key });
  const subjectKey = key as string;
  const hostKept = checkKept(kept);
  const signer: ReceiptSigner | undefined = rt.adapter("signer");
  if (signer === undefined) throw new EngineError("precondition_failed", "an export is signed, and the engine has no signer adapter");
  const intakeRecords = await records.listIntakeRecords(rt.workspaceId, subjectKey);
  const subject = await records.getSubject(rt.workspaceId, subjectKey);
  const calls = callsOf(intakeRecords);
  const consents: ConsentRecord[] = [];
  const receipts: SubjectExportBody["receipts"] = [];
  for (const callId of calls) {
    const call: CallRecord | null = await unlessGone(rt.read(callId));
    if (call === null) continue;
    const trace = call.modules[TRACE] as unknown as TraceSlice;
    // Only the consents recorded under this subject: a call can match another subject later.
    consents.push(...trace.consents.filter((c) => c.subjectKey === subjectKey));
    if (trace.receipt !== null) receipts.push({ receiptId: trace.receipt.body.receiptId, callId });
  }
  // A revocation is kept apart from its consent, in the ConsentStore: each listed consent's comes
  // with it, so the export never shows a yes the subject has since withdrawn as standing.
  const store = rt.adapter("consents") as ConsentStore | undefined;
  const revocations: ConsentRevocation[] = [];
  for (const consent of store === undefined ? [] : consents) {
    const revoked = (await store!.getConsent(rt.workspaceId, consent.consentId))?.revoked ?? null;
    if (revoked !== null) revocations.push(revoked);
  }
  // A ledger can be shared by several workspaces: an entry counts only when its event id (a JSON
  // tuple starting with the workspace) says it is this workspace's.
  const prefix = `${JSON.stringify([rt.workspaceId]).slice(0, -1)},`;
  const ids = new Set([...intakeRecords.map((r) => r.recordId), ...consents.map((c) => c.consentId), ...receipts.map((r) => r.receiptId)]);
  const ledgerEntries = (await rt.adapter("ledger").list())
    .filter((e) => e.eventId?.startsWith(prefix) === true && [e.detail.recordId, e.detail.consentId, e.detail.receiptId].some((id) => typeof id === "string" && ids.has(id)))
    .map((e) => ({ seq: e.seq, hash: e.hash, event: e.event, callId: e.callId }));
  const body: SubjectExportBody = {
    v: 1,
    type: "subject_export",
    exportId: rt.ids.next("sxp"),
    workspaceId: rt.workspaceId,
    subjectKey,
    issuedAt: rt.now(),
    intakeRecords,
    pinDigestOnFile: subject?.pinDigest !== undefined,
    consents,
    revocations,
    calls,
    ledgerEntries,
    receipts,
    heldByHost: structuredClone([...HELD_BY_HOST]),
    kept: [...structuredClone([...ENGINE_KEPT]), ...hostKept],
    limits: [...LIMITS],
  };
  const signature = await signer.sign(subjectExportPayload(body));
  return { body, alg: signer.algorithm, kid: signer.keyId, signature: Buffer.from(signature).toString("base64url") };
}

/**
 * The event id of a subject's `n`th erasure (from 0) or of its completion. Keyed, so it names no
 * subject to anyone without the knowledge key.
 */
async function erasureEventId(rt: EngineRuntime, subjectKey: string, n: number, event: "subject.erased" | "subject.erasure_completed"): Promise<string> {
  // The knowledge HMAC is asynchronous (#72): awaited, or the id would hold a Promise.
  return JSON.stringify([rt.workspaceId, null, event, await rt.hmac(`${event}:${subjectKey}:${n}`)]);
}

/** Carries out the plan an erasure entry holds, then appends its completion. Every step is idempotent. */
async function carryOut(rt: EngineRuntime, records: RecordStore, subjectKey: string, n: number, entry: AuditEntry): Promise<ErasureResult> {
  const recordIds = entry.detail.recordIds as string[];
  const pinDigest = entry.detail.pinDigest as boolean;
  await records.deleteIntakeRecords(rt.workspaceId, recordIds);
  if (pinDigest) await records.deletePinDigest(rt.workspaceId, subjectKey);
  await rt.adapter("ledger").append({
    eventId: await erasureEventId(rt, subjectKey, n, "subject.erasure_completed"),
    callId: null,
    actor: "member",
    event: "subject.erasure_completed",
    at: rt.now(),
    detail: { erasureSeq: entry.seq },
  });
  return { erased: true, recordIds, pinDigest, entry };
}

/** What an erase resets in the AttemptCounters store: the store, if the engine has one, and the installed factor kinds. */
export interface ErasureCounters {
  counters: AttemptCounters | undefined;
  factors: readonly string[];
}

/**
 * Resets every counter kept under the subject key (see LIMITS). A subject under duress is first
 * counted as cleared, as `clearDuress` does, so an alert of an earlier entry, delivered later, never
 * sets the flag again. Resets are idempotent, so a retry does them again harmlessly.
 */
async function forgetCounters(rt: EngineRuntime, { counters, factors }: ErasureCounters, subjectKey: string): Promise<void> {
  if (counters === undefined) return;
  const w = rt.workspaceId;
  const subject = (factor: string): AttemptCounterKey => ({ workspaceId: w, factor, scope: "subject", key: subjectKey });
  const flag = duressFlagKey(w, subjectKey);
  if (await isUnderDuress(counters, flag)) await recordClear(counters, w, subjectKey, rt.clock.now());
  const keys = [flag, subject(FLOW_START), subject(CALLBACKS_PLACED), ...factors.flatMap((kind) => [subject(kind), hiddenCounterKey(w, kind, subjectKey)])];
  for (const key of keys) {
    await counters.reset(key);
    await counters.reset(noticeKey(key));
  }
}

/**
 * Deletes what the engine stored about one subject: their intake records (and the copy a call
 * keeps of one), their PIN and duress PIN digests, and the counters kept under their key. The
 * counters are reset on every request, with nothing else on file too. The `subject.erased` entry is appended first and holds the
 * plan (the record ids, and whether a PIN digest goes); `subject.erasure_completed` follows once
 * every delete is done. Each erasure of a subject is numbered, and its event ids are keyed on the
 * subject and that number: a retry after a failed delete finds the unfinished plan, carries it out
 * and appends nothing twice, while a later erasure (say of a PIN the host put back) gets an entry of
 * its own. With nothing on file and nothing unfinished, it does nothing. `forget` drops a call's
 * copy of the records; the engine passes Dossier's. Reads the whole ledger once.
 */
export async function eraseSubject(
  rt: EngineRuntime,
  input: SubjectRequest,
  forget: (callId: string, recordIds: readonly string[]) => Promise<void>,
  counters: ErasureCounters,
): Promise<ErasureResult> {
  // Read once: the subject key checked is the one erased and named in the ledger.
  const { workspaceId, subjectKey: key } = readRequest(input);
  const records = checkRequest(rt, { workspaceId, subjectKey: key });
  const subjectKey = key as string;
  const ledger = rt.adapter("ledger");
  const appended = new Map((await ledger.list()).map((e) => [e.eventId, e]));
  let n = 0;
  while (appended.has(await erasureEventId(rt, subjectKey, n, "subject.erased"))) n++;
  // The last erasure, unfinished: carry out its plan before looking for anything filed since.
  let finished: ErasureResult | null = null;
  if (n > 0 && !appended.has(await erasureEventId(rt, subjectKey, n - 1, "subject.erasure_completed"))) {
    finished = await carryOut(rt, records, subjectKey, n - 1, appended.get(await erasureEventId(rt, subjectKey, n - 1, "subject.erased"))!);
  }
  // Counted before the listing: a filing reserved before now and written after it stores nothing,
  // whether or not this listing sees it, so no record the plan misses can bring values back.
  await records.markSubjectErased(rt.workspaceId, subjectKey);
  const found = await records.listIntakeRecords(rt.workspaceId, subjectKey);
  const onFile = await records.getSubject(rt.workspaceId, subjectKey);
  // A duress PIN digest alone is a PIN digest to erase too (VER-12).
  const pinDigest = onFile?.pinDigest !== undefined || onFile?.duressDigest !== undefined;
  const recordIds = found.map((r) => r.recordId);
  await forgetCounters(rt, counters, subjectKey);
  if (recordIds.length === 0 && !pinDigest) return finished ?? { erased: false, recordIds, pinDigest, entry: null };
  for (const callId of callsOf(found)) await unlessGone(forget(callId, recordIds));
  // Two erasures at once append the same id: the first plan appended is the one both carry out.
  // A plan that does not cover what this erasure found (another erasure's, which read the same
  // number before a record was filed) is carried out, and this one takes the next number.
  let fresh: ErasureResult;
  for (;;) {
    const entry = await ledger.append({
      eventId: await erasureEventId(rt, subjectKey, n, "subject.erased"),
      callId: null,
      actor: "member",
      event: "subject.erased",
      at: rt.now(),
      detail: { recordIds, pinDigest },
    });
    fresh = await carryOut(rt, records, subjectKey, n, entry);
    if (recordIds.every((id) => fresh.recordIds.includes(id)) && (fresh.pinDigest || !pinDigest)) break;
    n++;
  }
  if (finished === null) return fresh;
  return { erased: true, recordIds: [...finished.recordIds, ...fresh.recordIds], pinDigest: finished.pinDigest || fresh.pinDigest, entry: fresh.entry };
}
