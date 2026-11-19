// The callback factor (VER-9). Caller ID can be spoofed, so the business calls back the number it
// has on file: whatever number the first call came from, the callback reaches the line on record.
// It proves possession of that line, as a texted code does, and shares its weaknesses (a SIM swap,
// a port-out, call forwarding, someone else answering), so the policy counts it as possession and
// never alone.
//
// The call that asks is ended, never held, and never gains a level from the callback. The callback
// is its own call: the engine creates it for the subject the first call matched (choosing it is not
// a factor), the dialer rings the number on file, and `callback` is recorded there only when the
// number answered and the person keyed the confirmation. Its level and grant are its own.
//
// A request is refused, silently, when no keypad or PIN factor matched, when the subject has no
// number on file, when the callback counters are locked, or past the daily limit per subject; the
// caller hears the same as for a placed one. A failure is counted before the line is dialed, like
// an attempt before it is judged, and a pass forgets it.
import type { AttemptCounterKey, SubjectRecord } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import type { CallDraft, EngineRuntime } from "../core/runtime.ts";
import { canApply } from "../core/session.ts";
import { BADGE, allowFactor, type BadgeSlice, type CallbackState, type OutcomeResult } from "./badge.ts";
import { counterKeys, currentLock, forgetPass, isCallingNumber, lockoutOf, recordedAt, recordFailures, type Lock } from "./counters.ts";
import type { BadgeSettings } from "./factors.ts";

export const CALLBACK = "callback";

/** Callbacks placed per subject in any 24 hours, on any call and any engine of the workspace. */
export const MAX_CALLBACKS_PER_DAY = 3;

/** The counter the daily limit is kept in. Not a factor kind: no plug-in can take a name with a dot. */
export const CALLBACKS_PLACED = "callback.placed";

const DAY_MS = 86_400_000;

/** What the host's dialer reports about a callback. */
export interface CallbackOutcome {
  /** The dialer's reference, as `CallbackDialer.dial` returned it. */
  ref: string;
  /** The number on file answered. No answer, a busy line or a failed dial is false. */
  answered: boolean;
  /** The person who answered keyed the confirmation. Keys only: voicemail and answering machines never confirm. */
  confirmed: boolean;
}

/** What placing an allowed callback needs. */
export interface CallbackPlan {
  callbackCallId: string;
  subjectKey: string;
  subject: SubjectRecord;
  keys: AttemptCounterKey[];
  lock: Lock | null;
  /** ISO 8601. When the callback's failure was counted, so a pass forgets that one. */
  at: string;
}

/**
 * Decides a callback on the call that asks: the plan for a placed one, or null for a refused one.
 * The caller is not told which. Asked again once decided, it gives the same answer, so a placed
 * callback that failed before it rang is resumed. Asked again while undecided (the counters or the
 * write failed), it completes the decision for the subject first reserved, counting nothing twice.
 */
export async function requestCallback(rt: EngineRuntime, callId: string): Promise<CallbackPlan | null> {
  const before = await rt.read(callId);
  const current = before.modules[BADGE] as unknown as BadgeSlice | undefined;
  if (current === undefined) throw new EngineError("module_disabled", `${BADGE} was off when this call started`);
  if (current.callback.status === "placed") return planOf(current.callback);
  // Refused, or voided (by a taint or a new subject) while it was decided: the same silent answer.
  if (current.callback.status === "refused" || current.callback.status === "void") return null;
  const resume = current.callback.status === "requested";
  const reserved = resume
    ? current.callback
    : await rt.update(callId, (draft) => {
        allowFactor(rt, draft.record, CALLBACK);
        draft.assertCan({ type: "factor_recorded", factor: { kind: CALLBACK, passed: false, at: rt.now() } });
        // The callback call runs the flow again from its first step, so that is where one is asked for.
        if (draft.record.flow !== null && draft.record.flow.index !== 0) throw new EngineError("precondition_failed", "a callback is asked for on the flow's first step");
        const s = draft.slice<BadgeSlice>(BADGE);
        if (s.callback.status !== "none") throw new EngineError("precondition_failed", "a callback was already asked for on this call");
        // Only after a keypad or PIN match, only to a number on file, and never on a call that
        // untrusted content entered: the taint dropped what the call had matched.
        if (draft.record.state.tainted || !s.knowledgeMatched || !isCallingNumber(s.subject!.phoneOnFile)) {
          s.callback = { ...s.callback, status: "refused" };
          draft.emit("verification.callback_finished", "code", { outcome: "refused" });
          return null;
        }
        s.callback = {
          ...s.callback,
          status: "requested",
          callId: rt.ids.next("call"),
          keys: counterKeys(rt.workspaceId, CALLBACK, s),
          subjectKey: s.subjectKey,
          subject: s.subject,
          epoch: s.epoch,
          at: rt.clock.now().toISOString(),
        };
        return { ...s.callback };
      });
  if (reserved === null) return null;
  const decided = await allowCallback(rt, reserved, resume);
  return rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    // Voided while it was decided (untrusted content, or verification restarted for another
    // subject): refused, as any refusal is. What was counted stays counted.
    if (s.callback.status === "void") {
      s.callback = { ...s.callback, status: "refused", lock: null };
      draft.emit("verification.callback_finished", "code", { outcome: "refused" });
      return null;
    }
    // Another try of this request decided it meanwhile: its answer stands.
    if (s.callback.status !== "requested") return s.callback.status === "placed" ? planOf(s.callback) : null;
    // Verification restarted, perhaps for another subject, while this was decided: what was
    // reserved for the subject that matched is never placed for another, nor counted again.
    const placed = decided.placed && s.epoch === reserved.epoch && s.subjectKey === reserved.subjectKey;
    s.callback = { ...s.callback, status: placed ? "placed" : "refused", lock: placed ? decided.hard : null };
    if (decided.lock !== null) draft.emit("verification.locked", "code", { kind: CALLBACK, scope: decided.lock.scope, hard: decided.lock.hard, until: decided.lock.until });
    if (!placed) {
      draft.emit("verification.callback_finished", "code", { outcome: "refused" });
      return null;
    }
    draft.emit("verification.callback_started", "code", { callbackCallId: s.callback.callId });
    return planOf(s.callback);
  });
}

/** The plan from what the request reserved, never from the call's subject now. */
function planOf(callback: CallbackState): CallbackPlan {
  return { callbackCallId: callback.callId!, subjectKey: callback.subjectKey!, subject: callback.subject!, keys: callback.keys, lock: callback.lock, at: callback.at! };
}

/**
 * The counters, as at the time the request was reserved: refused while the callback counters are
 * locked or the subject is at its daily limit. Otherwise the callback is counted toward the limit
 * and as a failure, before it is placed. A resumed request finds what it already counted (a
 * failure at its own time) and does not count it again.
 */
async function allowCallback(rt: EngineRuntime, reserved: CallbackState, resume: boolean): Promise<{ placed: boolean; lock: Lock | null; hard: Lock | null }> {
  const counters = rt.adapter("counters");
  const lockout = lockoutOf(rt.settings<BadgeSettings>(BADGE).lockout);
  const at = reserved.at!;
  const now = new Date(at);
  const placed: AttemptCounterKey = { workspaceId: rt.workspaceId, factor: CALLBACKS_PLACED, scope: "subject", key: reserved.subjectKey! };
  const since = new Date(now.getTime() - DAY_MS + 1).toISOString();
  let counted = resume ? recordedAt(await counters.get(placed, since), at) : null;
  if (counted === null) {
    const lock = await currentLock(counters, lockout, reserved.keys, now);
    if (lock !== null) return { placed: false, lock, hard: null };
    if ((await counters.get(placed, since)).length >= MAX_CALLBACKS_PER_DAY) return { placed: false, lock: null, hard: null };
    counted = await counters.recordFailure(placed, at, since);
  }
  // Another request got in first: the list this one returned is over the limit.
  if (counted.length > MAX_CALLBACKS_PER_DAY) return { placed: false, lock: null, hard: null };
  const recorded = await recordFailures(counters, lockout, reserved.keys, now, resume);
  if (recorded.raced !== null) return { placed: false, lock: recorded.raced, hard: null };
  return { placed: true, lock: null, hard: recorded.hard };
}

/**
 * Starts verification on a new callback call, in the write that creates it: the subject the call
 * that asked matched, no factors, and the callback waiting to be dialed.
 */
export function beginCallbackCall(draft: CallDraft, plan: CallbackPlan, requestedOn: string): void {
  draft.apply({ type: "verification_started", reset: true });
  const s = draft.slice<BadgeSlice>(BADGE);
  s.epoch++;
  s.subjectKey = plan.subjectKey;
  s.subject = plan.subject;
  s.callback = {
    status: "dialing",
    callId: requestedOn,
    ref: null,
    keys: plan.keys,
    lock: plan.lock,
    subjectKey: plan.subjectKey,
    subject: plan.subject,
    epoch: null,
    at: plan.at,
    forgetPending: false,
  };
  draft.emit("verification.started", "code", { subject: "callback", requestedOn });
}

/**
 * Dials the number on file for a callback call, keeps the dialer's reference, then binds it to the
 * call. The number is read from the store each time it dials, a retry included, never from the copy
 * taken when verification began: a number the business changed since (after a SIM swap, say) is
 * the one rung, and with no number on file now the callback fails without ringing. A retry dials
 * again with the same idempotency key, so the line rings once.
 */
export async function dialCallback(rt: EngineRuntime, callId: string): Promise<void> {
  const record = await rt.read(callId);
  const s = record.modules[BADGE] as unknown as BadgeSlice;
  let ref = s.callback.ref;
  if (s.callback.status === "dialing") {
    const onFile = await rt.adapter("records").getSubject(rt.workspaceId, s.subjectKey!);
    const to = onFile?.phoneOnFile ?? "";
    if (!isCallingNumber(to)) {
      await rt.update(callId, (draft) => {
        const callback = draft.slice<BadgeSlice>(BADGE).callback;
        if (callback.status !== "dialing") return;
        callback.status = "failed";
        draft.emit("verification.callback_finished", "code", { outcome: "refused" });
      });
      return;
    }
    ({ ref } = await rt.adapter("dialer").dial({ callId, to, locale: record.locale, idempotencyKey: rt.idempotencyKey(callId, CALLBACK) }));
    const kept = await rt.update(callId, (draft) => {
      const callback = draft.slice<BadgeSlice>(BADGE).callback;
      if (callback.status !== "dialing") return false;
      callback.status = "dialed";
      callback.ref = ref;
      return true;
    });
    // Voided while it was dialed (untrusted content): its outcome would never count.
    if (!kept) return;
  }
  if (ref !== null) await rt.bindRef(`callback:${ref}`, callId);
}

/**
 * The dialer's outcome. `callback` is recorded, passed only when the number on file answered and
 * the person keyed the confirmation. Unknown, late, repeated or voided outcomes are ignored. A
 * pass then forgets the callback's failure; until that is done, a repeated outcome retries only it.
 */
export async function applyCallbackOutcome(rt: EngineRuntime, outcome: CallbackOutcome): Promise<OutcomeResult> {
  const callId = await rt.resolveRef(`callback:${outcome.ref}`);
  if (callId === null) return { applied: false };
  const done = await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    if (s.callback.status === "passed" && s.callback.forgetPending) return { passed: true, repeated: true, keys: s.callback.keys, at: s.callback.at! };
    const passed = outcome.answered && outcome.confirmed;
    const factor = { kind: CALLBACK, passed, at: rt.now() };
    if (s.callback.status !== "dialed" || !canApply(draft.record.state, { type: "factor_recorded", factor })) return null;
    s.callback = { ...s.callback, status: passed ? "passed" : "failed", forgetPending: passed };
    draft.apply({ type: "factor_recorded", factor });
    draft.emit("verification.factor", "system", { kind: CALLBACK, passed });
    const result = passed ? "passed" : outcome.answered ? "no_confirmation" : "no_answer";
    draft.emit("verification.callback_finished", "system", { outcome: result, requestedOn: s.callback.callId });
    const lock = s.callback.lock;
    if (!passed && lock !== null) draft.emit("verification.locked", "code", { kind: CALLBACK, scope: lock.scope, hard: lock.hard, until: lock.until });
    return { passed, repeated: false, keys: s.callback.keys, at: s.callback.at! };
  });
  if (done === null) return { applied: false };
  if (done.passed) {
    await forgetPass(rt.adapter("counters"), lockoutOf(rt.settings<BadgeSettings>(BADGE).lockout), done.keys, new Date(done.at));
    await rt.update(callId, (draft) => {
      draft.slice<BadgeSlice>(BADGE).callback.forgetPending = false;
    });
  }
  return done.repeated ? { applied: false } : { applied: true, callId };
}
