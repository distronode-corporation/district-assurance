// PIN enrolment and reset (VER-6).
//
// A caller who verified to level 2 or above on this call chooses a PIN: keyed twice, each entry
// hashed the way the PIN factor hashes it and the two compared in constant time, then the digest
// is stored through `RecordStore.putPinDigest`. The digits are never kept, logged or written to
// the ledger. Changing a PIN on file is the business's call (`resetPin`, from the host's code), not
// the caller's: a caller enrols only when no PIN is on file. In `verifier` mode the host's own PIN
// store enrols and resets, and the engine refuses.
//
// The duress PIN (VER-12): a second PIN the business enrols for a subject, which a caller made to
// call under pressure enters instead. It passes like the PIN everywhere the caller can reach, while
// `authorize` refuses money, contact and access on that call and the host's `DuressNotifier` is told.
import type { AttemptCounters, AuditEntry, SubjectRecord } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import { assertFlowNotEnded, currentStep } from "../core/flow.ts";
import { hexDigestsEqual } from "../core/hash.ts";
import type { EngineRuntime } from "../core/runtime.ts";
import { BADGE, type BadgeSlice } from "./badge.ts";
import { PIN_OUTCOMES, pinTag, type BadgeSettings, type PinOutcome, type PinSettings } from "./factors.ts";
import { isKeypadEntry } from "./knowledge.ts";

/** The level a caller must reach on this call before choosing a PIN. */
export const PIN_ENROLMENT_LEVEL = 2;

/**
 * Why a chosen PIN was not stored, or that it was. `weak` does not say which rule it broke, so
 * the answer never tells a caller whether a value they tried is one on file.
 */
export type PinEnrolmentResult =
  | { enrolled: true }
  | {
      enrolled: false;
      /** `malformed`: not digits of the configured length. `mismatch`: the two entries differ. `weak`: one digit, a run, or a value on file. `locked`: no more tries on this call. */
      reason: "malformed" | "mismatch" | "weak" | "locked";
    };

const SUBJECT_KEY = /^[0-9a-f]{64}$/;

/** Every digit the same (1111), or a run up or down the keypad's digits (1234, 4321, 7890). */
export function isWeakPin(pin: string): boolean {
  const steps = new Set<number>();
  for (let i = 1; i < pin.length; i++) steps.add((Number(pin[i]) - Number(pin[i - 1]) + 10) % 10);
  return steps.size === 1 && [0, 1, 9].includes([...steps][0]!);
}

/**
 * Judges a chosen PIN and its confirmation. Both are keyed and compared as digests, in constant
 * time; the PIN is then refused if it is weak or equals the subject's account number or any
 * keypad knowledge on file (compared as keyed hashes, every field, even after a match).
 */
export function pinEnrolmentProblem(
  settings: PinSettings,
  hmac: (data: string) => string,
  subject: SubjectRecord,
  pin: string,
  confirm: string,
): "malformed" | "mismatch" | "weak" | null {
  if (!wellFormedPin(settings, pin) || !wellFormedPin(settings, confirm)) return "malformed";
  const digest = hmac(`pin:${subject.subjectKey}:${pin}`);
  if (!hexDigestsEqual(digest, hmac(`pin:${subject.subjectKey}:${confirm}`))) return "mismatch";
  // A duress PIN on file (VER-12) is never also the PIN.
  const duress = hexDigestsEqual(hmac(`duress:${subject.subjectKey}:${pin}`), subject.duressDigest ?? "");
  return knowledgeOnFile(hmac, subject, pin) || duress || isWeakPin(pin) ? "weak" : null;
}

function wellFormedPin(settings: PinSettings, entry: string): boolean {
  return isKeypadEntry(entry) && entry.length >= settings.minDigits && entry.length <= settings.maxDigits;
}

/** Whether a PIN equals the subject's account number or any keypad knowledge on file: keyed hashes, every field, even after a match. */
function knowledgeOnFile(hmac: (data: string) => string, subject: SubjectRecord, pin: string): boolean {
  let onFile = hexDigestsEqual(hmac(`subject:${pin}`), subject.subjectKey);
  for (const [field, stored] of Object.entries(subject.knowledge)) onFile = hexDigestsEqual(hmac(`field:${field}:${pin}`), stored) || onFile;
  return onFile;
}

/**
 * Judges a duress PIN the business enrols (VER-12). Refused, as `weak`, when it equals the PIN on
 * file, the account number or any keypad knowledge, or is one digit or a run, as a PIN is. Only
 * for a subject with a PIN on file.
 */
export function duressPinProblem(
  settings: PinSettings,
  hmac: (data: string) => string,
  subject: SubjectRecord & { pinDigest: string },
  pin: string,
): "malformed" | "weak" | null {
  if (!wellFormedPin(settings, pin)) return "malformed";
  const samePin = hexDigestsEqual(hmac(`pin:${subject.subjectKey}:${pin}`), subject.pinDigest);
  return knowledgeOnFile(hmac, subject, pin) || samePin || isWeakPin(pin) ? "weak" : null;
}

/** Badge's PIN settings. Enrolment and reset are refused while the `pin` factor is off. */
function pinSettings(rt: EngineRuntime): PinSettings {
  const settings = rt.settings<BadgeSettings>(BADGE);
  if (!settings.factors.includes("pin")) throw new EngineError("precondition_failed", "the pin factor is turned off");
  return settings.pin!;
}

/**
 * Lets a caller who verified to level 2 or above on this call choose a PIN, keyed twice. The
 * try is counted before it is judged (the PIN's attempts per call). Refused while a flow runs or
 * after it ended, on a call that is not open, without a grant at level 2 or above, and when the
 * subject already has a PIN (the business resets it first). The digest is stored only if the
 * subject has none at that moment; each try records its digest as pending on the call first, so a
 * retry with the same PIN finishes an enrolment whose last write failed, even after the limit.
 */
export async function enrolPin(rt: EngineRuntime, callId: string, input: { pin: string; confirm: string }): Promise<PinEnrolmentResult> {
  const settings = pinSettings(rt);
  if (settings.mode === "verifier") throw new EngineError("precondition_failed", "in verifier mode the host's own PIN store enrols PINs");
  const reserved = await rt.update(callId, (draft) => {
    const record = draft.record;
    assertFlowNotEnded(record);
    if (currentStep(record) !== null) throw new EngineError("precondition_failed", "a PIN is chosen outside a flow, not during one");
    if (record.state.phase !== "open") throw new EngineError("invalid_transition", `a PIN is chosen on an open call, not while ${record.state.phase}`);
    const grant = record.state.grant;
    if (grant === null || grant.level < PIN_ENROLMENT_LEVEL || rt.clock.now().getTime() >= Date.parse(grant.expiresAt)) {
      throw new EngineError("scope_denied", `choosing a PIN needs a verification at level ${PIN_ENROLMENT_LEVEL} or above on this call`);
    }
    const s = draft.slice<BadgeSlice>(BADGE);
    const pending = [...(s.pinPending ?? [])];
    const used = s.pinEnrolments ?? 0;
    // Past the limit, a try may only finish an enrolment this call already stored: it is not counted.
    if (used >= settings.maxAttemptsPerCall) return pending.length === 0 ? null : { subjectKey: s.subjectKey!, pending, overLimit: true };
    s.pinEnrolments = used + 1;
    return { subjectKey: s.subjectKey!, pending, overLimit: false };
  });
  if (reserved === null) return { enrolled: false, reason: "locked" };
  const records = rt.adapter("records");
  const subject = await records.getSubject(rt.workspaceId, reserved.subjectKey);
  if (subject === null) throw new EngineError("precondition_failed", "the verified subject is not on file");
  const digest = rt.hmac(`pin:${reserved.subjectKey}:${input.pin}`);
  const ours = (p: { subjectKey: string; digest: string }) => p.subjectKey === reserved.subjectKey && hexDigestsEqual(p.digest, digest);
  // A PIN on file is refused, unless it is one this call stored and has not yet recorded (the
  // session write after the store's write failed): the same PIN again finishes that enrolment.
  const resuming = subject.pinDigest !== undefined && hexDigestsEqual(subject.pinDigest, digest) && reserved.pending.some(ours);
  if (reserved.overLimit && !resuming) return { enrolled: false, reason: "locked" };
  if (subject.pinDigest !== undefined && !resuming) throw new EngineError("precondition_failed", "a PIN is on file; only the business can reset it");
  const problem = pinEnrolmentProblem(settings, (d) => rt.hmac(d), subject, input.pin, input.confirm);
  if (problem !== null) return { enrolled: false, reason: problem };
  if (!resuming) {
    // Recorded before the store's write, so a retry can finish an enrolment whose last write failed.
    // Each try adds its own entry, so two tries at once on this call never overwrite each other's.
    await rt.update(callId, (draft) => {
      const s = draft.slice<BadgeSlice>(BADGE);
      s.pinPending = [...(s.pinPending ?? []), { subjectKey: reserved.subjectKey, digest }];
    });
    // Stored only if the subject still has no PIN: of two enrolments at once, one wins and the
    // other is refused without replacing the winner's PIN, and takes its own entry back, so a
    // retry of it can never pass for the winner's enrolment.
    if (!(await records.putPinDigest(rt.workspaceId, reserved.subjectKey, digest))) {
      await rt.update(callId, (draft) => {
        const s = draft.slice<BadgeSlice>(BADGE);
        const i = s.pinPending!.findIndex(ours);
        if (i !== -1) s.pinPending!.splice(i, 1);
      });
      throw new EngineError("precondition_failed", "a PIN is on file; only the business can reset it");
    }
  }
  await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    // Once per enrolment: a retry, or another try of the same PIN, may already have recorded it.
    const left = s.pinPending!.filter((p) => !ours(p));
    if (left.length === s.pinPending!.length) return;
    s.pinPending = left;
    draft.emit("pin.enrolled", "caller", {});
  });
  return { enrolled: true };
}

/**
 * The business resets a subject's PIN (a host call from its own staff tools, never a caller's).
 * In `keyed_hash` mode the digest on file is removed, so the subject has no PIN until they enrol
 * again at level 2; in `verifier` mode the host's own store resets the PIN itself. Either way the
 * subject's PIN failure counters (VER-1) are cleared, and `pin.reset` goes to the ledger, with no
 * call.
 */
export async function resetPin(rt: EngineRuntime, subjectKey: string, counters: AttemptCounters | undefined): Promise<void> {
  const settings = pinSettings(rt);
  if (!SUBJECT_KEY.test(subjectKey)) throw new EngineError("invalid_input", "subjectKey must be 64 lower-case hex characters");
  if (settings.mode === "keyed_hash") {
    // The duress PIN goes too: it must differ from the PIN, and the next PIN is not chosen yet.
    await rt.adapter("records").putPinDigest(rt.workspaceId, subjectKey, null);
    await rt.adapter("records").putDuressDigest(rt.workspaceId, subjectKey, null);
  }
  await counters?.reset({ workspaceId: rt.workspaceId, factor: "pin", scope: "subject", key: subjectKey });
  await rt.adapter("ledger").append({ callId: null, actor: "member", event: "pin.reset", at: rt.now(), detail: { subjectKey } });
}

/** Why a duress PIN was not stored, or that it was. `weak` does not say which rule it broke. */
export type DuressEnrolmentResult = { enrolled: true } | { enrolled: false; reason: "malformed" | "weak" };

/** Badge's PIN settings for duress PIN work: `keyed_hash` mode (the host's verifier keeps its own). */
function duressPinSettings(rt: EngineRuntime, subjectKey: string): PinSettings {
  const settings = pinSettings(rt);
  if (settings.mode === "verifier") throw new EngineError("precondition_failed", "in verifier mode the host's own PIN store keeps the duress PIN");
  if (!SUBJECT_KEY.test(subjectKey)) throw new EngineError("invalid_input", "subjectKey must be 64 lower-case hex characters");
  return settings;
}

/**
 * The business enrols, or replaces, a subject's duress PIN (VER-12): a host call from its own
 * tools, never a caller's. Needs `pin.duress` on in `keyed_hash` mode and a subject with a PIN on
 * file. Stored as its own keyed digest through `RecordStore.putDuressDigest`. Nothing goes to the
 * ledger, so the ledger never shows who has one.
 */
export async function enrolDuressPin(rt: EngineRuntime, subjectKey: string, pin: string): Promise<DuressEnrolmentResult> {
  const settings = duressPinSettings(rt, subjectKey);
  if (settings.duress === undefined) throw new EngineError("precondition_failed", "the duress PIN is turned off");
  const records = rt.adapter("records");
  const subject = await records.getSubject(rt.workspaceId, subjectKey);
  const pinDigest = subject?.pinDigest;
  if (subject === null || pinDigest === undefined) throw new EngineError("precondition_failed", "a duress PIN needs a subject with a PIN on file");
  const problem = duressPinProblem(settings, (d) => rt.hmac(d), { ...subject, pinDigest }, pin);
  if (problem !== null) return { enrolled: false, reason: problem };
  await records.putDuressDigest(rt.workspaceId, subjectKey, rt.hmac(`duress:${subjectKey}:${pin}`));
  return { enrolled: true };
}

/** The business removes a subject's duress PIN (a host call). Allowed while `pin.duress` is off, to clean up. */
export async function removeDuressPin(rt: EngineRuntime, subjectKey: string): Promise<void> {
  duressPinSettings(rt, subjectKey);
  await rt.adapter("records").putDuressDigest(rt.workspaceId, subjectKey, null);
}

/**
 * What a `pin` factor ledger entry's `tag` says (VER-12), for the holder of the knowledge key: the
 * outcome whose tag matches, or null when it is not a PIN entry or no outcome matches (a wrong key,
 * or a changed entry).
 */
export function readPinTag(hmac: (data: string) => string, entry: Pick<AuditEntry, "eventId" | "event" | "detail">): PinOutcome | null {
  const { eventId, event, detail } = entry;
  if (event !== "verification.factor" || detail.kind !== "pin" || eventId === undefined || typeof detail.tag !== "string") return null;
  const tag = detail.tag;
  return PIN_OUTCOMES.find((outcome) => hexDigestsEqual(pinTag(hmac, eventId, outcome), tag)) ?? null;
}
