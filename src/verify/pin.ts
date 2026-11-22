// PIN enrolment and reset (VER-6).
//
// A caller who verified to level 2 or above on this call chooses a PIN: keyed twice, each entry
// hashed the way the PIN factor hashes it and the two compared in constant time, then an Argon2id
// record of the keyed PIN (pin-hash.ts, ADR-29) is stored through `RecordStore.putPinDigest`. The
// digits are never kept, logged or written to the ledger. Changing a PIN on file is the business's
// call (`resetPin`, from the host's code), not the caller's: a caller enrols only when no PIN is on
// file. In `verifier` mode the host's own PIN store enrols and resets, and the engine refuses.
//
// The duress PIN (VER-12): a second PIN the business enrols for a subject, which a caller made to
// call under pressure enters instead. It passes like the PIN everywhere the caller can reach, while
// `authorize` refuses money, contact and access on that call and the host's `DuressNotifier` is told.
import type { AttemptCounters, AuditEntry, SubjectRecord } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import { assertFlowNotEnded, currentStep } from "../core/flow.ts";
import { hexDigestsEqual } from "../core/hash.ts";
import { capCallLevel } from "../core/policy.ts";
import type { CallRecord, EngineRuntime } from "../core/runtime.ts";
import { BADGE, type BadgeSlice } from "./badge.ts";
import { forgetUpTo, isCallingNumber } from "./counters.ts";
import { hiddenCounterKey } from "./duress-flag.ts";
import { PIN_OUTCOMES, pinTag, type BadgeSettings, type PinOutcome, type PinSettings } from "./factors.ts";
import { isKeypadEntry } from "./knowledge.ts";
import { checkPinRecord, hashPinRecord } from "./pin-hash.ts";

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
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * Whether a PIN is one the engine refuses as `weak` by its digits alone: every digit the same
 * (1111), or a run up or down the keypad's digits with 0 following 9 (1234, 4321, 7890, 9012). The
 * rule `enrolPin` and `enrolDuressPin` apply, so a host that takes PINs itself (`verifier` mode,
 * its own sign-up) refuses the same ones. Returns true for anything that is not a well-formed PIN
 * (one to 32 ASCII digits, `isKeypadEntry`): a value that is not a string, an empty string, any
 * other character, or more than 32 digits, so it fails closed. A well-formed PIN is judged on its
 * digit pattern. Length policy and knowledge matches stay host checks.
 */
export function isWeakPin(pin: string): boolean {
  // A host passes what its own form or keypad gave it: anything that is not keypad digits is weak,
  // so refused, never coerced (a regex test would turn a number or an array into its text first).
  if (typeof pin !== "string" || !isKeypadEntry(pin)) return true;
  const steps = new Set<number>();
  for (let i = 1; i < pin.length; i++) steps.add((Number(pin[i]) - Number(pin[i - 1]) + 10) % 10);
  return steps.size === 1 && [0, 1, 9].includes([...steps][0]!);
}

/**
 * Judges a chosen PIN and its confirmation. Both are keyed and compared as digests, in constant
 * time; the PIN is then refused if it is weak or equals the subject's account number or any
 * keypad knowledge on file (compared as keyed hashes, every field, even after a match).
 */
export async function pinEnrolmentProblem(
  settings: PinSettings,
  hmac: (data: string) => Promise<string>,
  subject: SubjectRecord,
  pin: string,
  confirm: string,
): Promise<"malformed" | "mismatch" | "weak" | null> {
  if (!wellFormedPin(settings, pin) || !wellFormedPin(settings, confirm)) return "malformed";
  const digest = await hmac(`pin:${subject.subjectKey}:${pin}`);
  if (!hexDigestsEqual(digest, await hmac(`pin:${subject.subjectKey}:${confirm}`))) return "mismatch";
  // A duress PIN on file (VER-12) is never also the PIN. One Argon2id run whether or not one is on file.
  const duress = (await checkPinRecord(subject.duressDigest, await hmac(`duress:${subject.subjectKey}:${pin}`))).match;
  return (await knowledgeOnFile(hmac, subject, pin)) || duress || isWeakPin(pin) ? "weak" : null;
}

function wellFormedPin(settings: PinSettings, entry: string): boolean {
  return isKeypadEntry(entry) && entry.length >= settings.minDigits && entry.length <= settings.maxDigits;
}

/** Whether a PIN equals the subject's account number or any keypad knowledge on file: keyed hashes, every field, even after a match. */
async function knowledgeOnFile(hmac: (data: string) => Promise<string>, subject: SubjectRecord, pin: string): Promise<boolean> {
  let onFile = hexDigestsEqual(await hmac(`subject:${pin}`), subject.subjectKey);
  for (const [field, stored] of Object.entries(subject.knowledge)) onFile = hexDigestsEqual(await hmac(`field:${field}:${pin}`), stored) || onFile;
  return onFile;
}

/**
 * Judges a duress PIN the business enrols (VER-12). Refused, as `weak`, when it equals the PIN on
 * file, the account number or any keypad knowledge, or is one digit or a run, as a PIN is. Only
 * for a subject with a PIN on file.
 */
export async function duressPinProblem(
  settings: PinSettings,
  hmac: (data: string) => Promise<string>,
  subject: SubjectRecord & { pinDigest: string },
  pin: string,
): Promise<"malformed" | "weak" | null> {
  if (!wellFormedPin(settings, pin)) return "malformed";
  const samePin = (await checkPinRecord(subject.pinDigest, await hmac(`pin:${subject.subjectKey}:${pin}`))).match;
  return (await knowledgeOnFile(hmac, subject, pin)) || samePin || isWeakPin(pin) ? "weak" : null;
}

/**
 * What choosing a PIN needs of the call: no flow running or ended, the call open, and a grant at
 * PIN_ENROLMENT_LEVEL or above (under the attestation cap) that has not expired. With a subject key, also that verification is
 * still for that subject.
 */
function assertCanEnrol(rt: EngineRuntime, record: CallRecord, subjectKey?: string): void {
  assertFlowNotEnded(record);
  if (currentStep(record) !== null) throw new EngineError("precondition_failed", "a PIN is chosen outside a flow, not during one");
  if (record.state.phase !== "open") throw new EngineError("invalid_transition", `a PIN is chosen on an open call, not while ${record.state.phase}`);
  const grant = record.state.grant;
  // The grant's level under today's attestation cap, as `authorize` reads it: a cap turned on since
  // the grant was issued applies to it.
  if (grant === null || capCallLevel(rt.policy, grant.level, record) < PIN_ENROLMENT_LEVEL || rt.clock.now().getTime() >= Date.parse(grant.expiresAt)) {
    throw new EngineError("scope_denied", `choosing a PIN needs a verification at level ${PIN_ENROLMENT_LEVEL} or above on this call`);
  }
  if (subjectKey !== undefined && (record.modules[BADGE] as unknown as BadgeSlice).subjectKey !== subjectKey) {
    throw new EngineError("precondition_failed", "verification restarted for another subject; choose the PIN again");
  }
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
  // Each read once, as a string (anything else is an empty, malformed entry): a getter read again
  // could store the digest of one value after the checks passed another (a date of birth, a run,
  // two digits the PIN factor never accepts).
  const given: { pin: unknown; confirm: unknown } = { pin: input.pin, confirm: input.confirm };
  const pin = typeof given.pin === "string" ? given.pin : "";
  const confirm = typeof given.confirm === "string" ? given.confirm : "";
  const reserved = await rt.update(callId, (draft) => {
    assertCanEnrol(rt, draft.record);
    const s = draft.slice<BadgeSlice>(BADGE);
    const pending = [...(s.pinPending ?? [])];
    // The enrolment this call recorded whose pin.enrolled the ledger has not taken yet: entries are
    // appended in order, so one waiting in the outbox is that last one's.
    const owed = s.pinEnrolled !== undefined && draft.record.outbox.some((e) => e.name === "pin.enrolled") ? [s.pinEnrolled] : [];
    const used = s.pinEnrolments ?? 0;
    // Past the limit, a try may only finish an enrolment this call already stored: it is not counted.
    if (used >= settings.maxAttemptsPerCall) return pending.length === 0 && owed.length === 0 ? null : { subjectKey: s.subjectKey!, pending, done: owed, overLimit: true, enrolmentId: null };
    s.pinEnrolments = used + 1;
    // This try's own id: the call and its try number, so no other call or try shares it.
    return { subjectKey: s.subjectKey!, pending, done: owed, overLimit: false, enrolmentId: `${callId}:${used + 1}` };
  });
  if (reserved === null) return { enrolled: false, reason: "locked" };
  const records = rt.adapter("records");
  const subject = await records.getSubject(rt.workspaceId, reserved.subjectKey);
  if (subject === null) throw new EngineError("precondition_failed", "the verified subject is not on file");
  const keyedPin = await rt.hmac(`pin:${reserved.subjectKey}:${pin}`);
  // A PIN on file is refused, unless the store says this call's own try stored it (by its id, kept
  // with the digest) and the call has not recorded it yet: the session write after the store's
  // write failed, and the same PIN again finishes that enrolment. Another call's enrolment of the
  // same PIN, or one after a reset, never passes for this call's.
  const stored = subject.pinDigest !== undefined && (await checkPinRecord(subject.pinDigest, keyedPin)).match ? subject.pinEnrolmentId : undefined;
  const mine = (p: { subjectKey: string; enrolmentId: string }) => p.enrolmentId === stored && p.subjectKey === reserved.subjectKey;
  // Recorded by this call, and its ledger entry failed after the write that recorded it (this
  // try's write appended it): the same PIN again is that enrolment, finished.
  if (stored !== undefined && reserved.done.some(mine)) return { enrolled: true };
  const resuming = stored !== undefined && reserved.pending.some(mine);
  if (reserved.overLimit && !resuming) return { enrolled: false, reason: "locked" };
  if (subject.pinDigest !== undefined && !resuming) throw new EngineError("precondition_failed", "a PIN is on file; only the business can reset it");
  const problem = await pinEnrolmentProblem(settings, (d) => rt.hmac(d), subject, pin, confirm);
  if (problem !== null) return { enrolled: false, reason: problem };
  let enrolmentId = stored!;
  if (!resuming) {
    enrolmentId = reserved.enrolmentId!;
    // A new Argon2id record, salted afresh (ADR-29); the digits are never kept.
    const digest = await hashPinRecord(keyedPin);
    // Recorded before the store's write, so a retry can finish an enrolment whose last write failed.
    // Each try adds its own entry, so two tries at once on this call never overwrite each other's.
    // Only while the call can still choose a PIN for this subject: it may have ended, lost its grant
    // or restarted verification for another subject while the try was judged.
    await rt.update(callId, (draft) => {
      assertCanEnrol(rt, draft.record, reserved.subjectKey);
      const s = draft.slice<BadgeSlice>(BADGE);
      s.pinPending = [...(s.pinPending ?? []), { subjectKey: reserved.subjectKey, digest, enrolmentId }];
    });
    const takeBack = () =>
      rt.update(callId, (draft) => {
        const s = draft.slice<BadgeSlice>(BADGE);
        s.pinPending = s.pinPending!.filter((p) => p.enrolmentId !== enrolmentId);
      });
    // Checked again, as the call is now, with nothing in between this check and the store's write.
    try {
      assertCanEnrol(rt, await rt.read(callId), reserved.subjectKey);
    } catch (error) {
      await takeBack();
      throw error;
    }
    // Stored only if the subject still has no PIN: of two enrolments at once, one wins and the
    // other is refused without replacing the winner's PIN, and takes its own entry back.
    if (!(await records.putPinDigest(rt.workspaceId, reserved.subjectKey, digest, enrolmentId))) {
      await takeBack();
      throw new EngineError("precondition_failed", "a PIN is on file; only the business can reset it");
    }
  }
  await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    // Once per enrolment, in the write that checks it: only the entry of the try that stored the PIN
    // records it, and a retry that ran meanwhile may already have.
    const left = s.pinPending!.filter((p) => p.enrolmentId !== enrolmentId);
    if (left.length === s.pinPending!.length) return;
    s.pinPending = left;
    s.pinEnrolled = { subjectKey: reserved.subjectKey, enrolmentId };
    draft.emit("pin.enrolled", "caller", {});
  });
  return { enrolled: true };
}

/**
 * The business resets a subject's PIN (a host call from its own staff tools, never a caller's).
 * In `keyed_hash` mode the digest on file is removed, so the subject has no PIN until they enrol
 * again at level 2; in `verifier` mode the host's own store resets the PIN itself. Either way the
 * subject's PIN failure counters (VER-1), the hidden one of VER-12 included, are cleared, and
 * `pin.reset` goes to the ledger, with no call. A duress flag stays until `clearDuress`.
 */
export async function resetPin(rt: EngineRuntime, subjectKey: string, counters: AttemptCounters | undefined): Promise<void> {
  const settings = pinSettings(rt);
  // A string only: a regex test turns an array into its text, which a record store finds while the
  // counters, keyed by the value, are left as they were.
  if (typeof subjectKey !== "string" || !SUBJECT_KEY.test(subjectKey)) throw new EngineError("invalid_input", "subjectKey must be 64 lower-case hex characters");
  // The duress PIN goes too, in the store's same atomic step: it must differ from the PIN, the next
  // PIN is not chosen yet, and a duress PIN the business enrols against that next PIN must survive.
  if (settings.mode === "keyed_hash") await rt.adapter("records").putPinDigest(rt.workspaceId, subjectKey, null);
  await counters?.reset({ workspaceId: rt.workspaceId, factor: "pin", scope: "subject", key: subjectKey });
  // The PIN's hidden failures too (VER-12): the business's reset lifts every PIN lock on the
  // subject, the one a duress PIN entry could not clear included. The duress flag stays.
  await counters?.reset(hiddenCounterKey(rt.workspaceId, "pin", subjectKey));
  await rt.adapter("ledger").append({ callId: null, actor: "member", event: "pin.reset", at: rt.now(), detail: { subjectKey } });
}

/** What `replacePin` takes: the PIN record expected on file, the one to put there, and the number on file to write with it. */
export interface PinReplacement {
  /** The record on file now (`SubjectRecord.pinDigest`), or null when none is. */
  from: string | null;
  /** The new record (`pinDigest`), or null to remove the PIN. */
  to: string | null;
  /** Written in the same step: E.164, or "" for no number on file. Absent: left as it is. */
  phoneOnFile?: string;
  /**
   * To finish a change that threw `PinChangeUnfinishedError`: its `at`. When the record on file is
   * already `to`, the change is taken as landed and only its cleanup runs, forgetting the PIN
   * failures recorded up to `at` and none after.
   */
  resume?: string;
}

/**
 * A PIN change landed (the new record, or none, and the number are on file), but forgetting its
 * counters or appending `pin.reset` failed after. Not a refusal: the host finishes it by asking for
 * the same change again with `resume: at`. Names no PIN; the store's or ledger's error is `cause`.
 */
export class PinChangeUnfinishedError extends Error {
  /** When the change began, ISO 8601: its cleanup forgets the PIN failures up to this, never later ones. */
  readonly at: string;

  constructor(at: string, cause: unknown) {
    super("the PIN change is on file, but its counters or its pin.reset entry were not written; finish it with resume", { cause });
    this.name = "PinChangeUnfinishedError";
    this.at = at;
  }
}

/**
 * The business replaces or removes a subject's PIN in one compare-and-set (`RecordStore.replacePinDigest`):
 * false, changing nothing, when the record on file is no longer `from`, so of two changes at once
 * one answers false. A host call from the business's own tools, `keyed_hash` mode only. When a PIN
 * was on file, the subject's PIN failures recorded up to the change's start are forgotten after it
 * lands (the hidden ones included, VER-12), never a later one, and `pin.reset` is appended; a first
 * PIN forgets and writes nothing. A failure of those after the change landed is
 * `PinChangeUnfinishedError`, finished with `resume`.
 */
export async function replacePin(rt: EngineRuntime, subjectKey: string, change: PinReplacement, counters: AttemptCounters | undefined): Promise<boolean> {
  const settings = pinSettings(rt);
  if (settings.mode !== "keyed_hash") throw new EngineError("precondition_failed", "in verifier mode the host's own PIN store replaces the PIN");
  if (typeof subjectKey !== "string" || !SUBJECT_KEY.test(subjectKey)) throw new EngineError("invalid_input", "subjectKey must be 64 lower-case hex characters");
  // Each field read once: a getter read again could change a value after it was checked.
  const { from, to, phoneOnFile, resume }: { [K in keyof PinReplacement]?: unknown } = typeof change === "object" && change !== null ? change : {};
  const errors: string[] = [];
  if (from !== null && (typeof from !== "string" || from === "")) errors.push("from must be the PIN record on file, or null");
  if (to !== null && (typeof to !== "string" || to === "")) errors.push("to must be a PIN record, or null");
  if (phoneOnFile !== undefined && !(typeof phoneOnFile === "string" && (phoneOnFile === "" || isCallingNumber(phoneOnFile)))) errors.push("phoneOnFile must be E.164 or empty");
  if (resume !== undefined && !(typeof resume === "string" && ISO_TIME.test(resume) && Number.isFinite(Date.parse(resume)))) errors.push("resume must be the at of a PinChangeUnfinishedError");
  if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
  const records = rt.adapter("records");
  // The change's start: failures up to it are the old PIN's to forget; one recorded after may be against the new PIN.
  const at = (resume as string | undefined) ?? rt.now();
  // A resumed change that already landed is not written again: `to` on file is its own (records are
  // salted, so no other change wrote the same one), or, for a removal, no PIN is on file.
  const onFile = resume === undefined ? null : await records.getSubject(rt.workspaceId, subjectKey);
  const landed = onFile !== null && (onFile.pinDigest ?? null) === to;
  const replaced = landed || (await records.replacePinDigest(rt.workspaceId, subjectKey, from as string | null, to as string | null, phoneOnFile as string | undefined));
  // A first PIN has nothing to forget. A resumed removal does: the PIN it removed is gone, whatever `from` says.
  if (!replaced || (from === null && !(landed && to === null))) return replaced;
  try {
    // Badge never runs without the counters adapter (the config check refuses it).
    await forgetBefore(counters!, subjectKey, rt.workspaceId, new Date(at));
    await rt.adapter("ledger").append({ callId: null, actor: "member", event: "pin.reset", at: rt.now(), detail: { subjectKey } });
  } catch (error) {
    throw new PinChangeUnfinishedError(at, error);
  }
  return true;
}

/** Forgets the subject's PIN failures, and its hidden ones (VER-12), recorded up to `at`; later ones stay. */
async function forgetBefore(counters: AttemptCounters, subjectKey: string, workspaceId: string, at: Date): Promise<void> {
  await forgetUpTo(counters, { workspaceId, factor: "pin", scope: "subject", key: subjectKey }, at);
  await forgetUpTo(counters, hiddenCounterKey(workspaceId, "pin", subjectKey), at);
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
  const problem = await duressPinProblem(settings, (d) => rt.hmac(d), { ...subject, pinDigest }, pin);
  if (problem !== null) return { enrolled: false, reason: problem };
  // Stored only if the PIN checked against is still the one on file: a reset and a new PIN since the
  // read could otherwise leave the duress PIN equal to the PIN, raising the alarm on every login.
  if (!(await records.putDuressDigest(rt.workspaceId, subjectKey, await hashPinRecord(await rt.hmac(`duress:${subjectKey}:${pin}`)), pinDigest))) {
    throw new EngineError("conflict", "the PIN changed while the duress PIN was being stored; try again");
  }
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
  const tagged = taggedEntry(entry);
  return tagged === null ? null : (PIN_OUTCOMES.find((outcome) => hexDigestsEqual(pinTag(hmac, tagged.eventId, outcome), tagged.tag)) ?? null);
}

/** The event id and tag of a `pin` factor entry, or null for any other entry (shared by both readers). */
function taggedEntry(entry: Pick<AuditEntry, "eventId" | "event" | "detail">): { eventId: string; tag: string } | null {
  const { eventId, event, detail } = entry;
  if (event !== "verification.factor" || detail.kind !== "pin" || eventId === undefined || typeof detail.tag !== "string") return null;
  return { eventId, tag: detail.tag };
}

/** `readPinTag` through the knowledge key's asynchronous HMAC (a key store's, for example). */
export async function readPinTagWith(hmac: (data: string) => Promise<string>, entry: Pick<AuditEntry, "eventId" | "event" | "detail">): Promise<PinOutcome | null> {
  const tagged = taggedEntry(entry);
  if (tagged === null) return null;
  // Every outcome's tag is computed, so the time taken never says which one matched.
  const tags = await Promise.all(PIN_OUTCOMES.map((outcome) => pinTag(hmac, tagged.eventId, outcome)));
  return PIN_OUTCOMES.find((_, i) => hexDigestsEqual(tags[i]!, tagged.tag)) ?? null;
}
