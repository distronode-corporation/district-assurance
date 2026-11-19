// PIN enrolment and reset (VER-6).
//
// A caller who verified to level 2 or above on this call chooses a PIN: keyed twice, each entry
// hashed the way the PIN factor hashes it and the two compared in constant time, then the digest
// is stored through `RecordStore.putPinDigest`. The digits are never kept, logged or written to
// the ledger. Changing a PIN on file is the business's call (`resetPin`, from the host's code), not
// the caller's: a caller enrols only when no PIN is on file. In `verifier` mode the host's own PIN
// store enrols and resets, and the engine refuses.
import type { AttemptCounters, SubjectRecord } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import { assertFlowNotEnded, currentStep } from "../core/flow.ts";
import { hexDigestsEqual } from "../core/hash.ts";
import type { EngineRuntime } from "../core/runtime.ts";
import { BADGE, type BadgeSlice } from "./badge.ts";
import type { BadgeSettings, PinSettings } from "./factors.ts";
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
  const wellFormed = (entry: string) => isKeypadEntry(entry) && entry.length >= settings.minDigits && entry.length <= settings.maxDigits;
  if (!wellFormed(pin) || !wellFormed(confirm)) return "malformed";
  const digest = hmac(`pin:${subject.subjectKey}:${pin}`);
  if (!hexDigestsEqual(digest, hmac(`pin:${subject.subjectKey}:${confirm}`))) return "mismatch";
  let onFile = hexDigestsEqual(hmac(`subject:${pin}`), subject.subjectKey);
  for (const [field, stored] of Object.entries(subject.knowledge)) onFile = hexDigestsEqual(hmac(`field:${field}:${pin}`), stored) || onFile;
  return onFile || isWeakPin(pin) ? "weak" : null;
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
 * subject has none at that moment; the call records it as pending first, so a retry with the same
 * PIN finishes an enrolment whose last write failed.
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
    const used = s.pinEnrolments ?? 0;
    if (used >= settings.maxAttemptsPerCall) return null;
    s.pinEnrolments = used + 1;
    return { subjectKey: s.subjectKey!, pending: s.pinPending };
  });
  if (reserved === null) return { enrolled: false, reason: "locked" };
  const records = rt.adapter("records");
  const subject = await records.getSubject(rt.workspaceId, reserved.subjectKey);
  if (subject === null) throw new EngineError("precondition_failed", "the verified subject is not on file");
  const digest = rt.hmac(`pin:${reserved.subjectKey}:${input.pin}`);
  // A PIN on file is refused, unless it is the one this call stored and has not yet recorded (the
  // session write after the store's write failed): the same PIN again finishes that enrolment.
  const pending = reserved.pending;
  const resuming =
    subject.pinDigest !== undefined &&
    pending !== undefined &&
    pending.subjectKey === reserved.subjectKey &&
    hexDigestsEqual(pending.digest, subject.pinDigest) &&
    hexDigestsEqual(pending.digest, digest);
  if (subject.pinDigest !== undefined && !resuming) throw new EngineError("precondition_failed", "a PIN is on file; only the business can reset it");
  const problem = pinEnrolmentProblem(settings, (d) => rt.hmac(d), subject, input.pin, input.confirm);
  if (problem !== null) return { enrolled: false, reason: problem };
  if (!resuming) {
    // Recorded before the store's write, so a retry can finish an enrolment whose last write failed.
    await rt.update(callId, (draft) => {
      draft.slice<BadgeSlice>(BADGE).pinPending = { subjectKey: reserved.subjectKey, digest };
    });
    // Stored only if the subject still has no PIN: of two calls enrolling at once, one wins and the
    // other is refused without replacing the winner's PIN.
    if (!(await records.putPinDigest(rt.workspaceId, reserved.subjectKey, digest))) {
      throw new EngineError("precondition_failed", "a PIN is on file; only the business can reset it");
    }
  }
  await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    // Once per enrolment: a retry that ran meanwhile may already have recorded it.
    if (s.pinPending?.digest !== digest) return;
    delete s.pinPending;
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
  if (settings.mode === "keyed_hash") await rt.adapter("records").putPinDigest(rt.workspaceId, subjectKey, null);
  await counters?.reset({ workspaceId: rt.workspaceId, kind: "pin", key: { subject: subjectKey } });
  await rt.adapter("ledger").append({ callId: null, actor: "member", event: "pin.reset", at: rt.now(), detail: { subjectKey } });
}
