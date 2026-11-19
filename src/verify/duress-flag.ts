// The duress flag (VER-12, "flag until cleared"): once a duress PIN is entered for a subject, the
// subject stays under duress, on every call and every engine, until the business clears it.
//
// A duress entry looks like a pass to the caller, the counters across calls included: the visible
// counter is reset as on a pass. So that an attacker who knows the duress PIN cannot use it to
// clear their wrong guesses at the real one, every entered factor's failures on the subject are
// also counted in a hidden counter that a duress entry never resets, and its hard lock holds. And
// while the flag is set, every later pass on the subject is a duress entry: alerted, its scopes
// refused, and the same to the caller as any pass. Both live in the AttemptCounters store every
// engine shares, under kinds no factor kind can be (factor kinds are snake_case).
import type { AttemptCounterKey, AttemptCounters } from "../core/adapters.ts";
import { hmacSha256Hex } from "../core/hash.ts";
import { DEFAULT_LOCKOUT, lockState, type Lock, type Lockout } from "./counters.ts";

/** The flag's counter kind: one entry while the subject is under duress. */
export const DURESS_FLAG = "duress.flag";

/** The first instant the store keeps the flag from: it never leaves a window. */
const FOREVER = "1970-01-01T00:00:00.000Z";

export function duressFlagKey(workspaceId: string, subjectKey: string): AttemptCounterKey {
  return { workspaceId, factor: DURESS_FLAG, scope: "subject", key: subjectKey };
}

/**
 * The subject's clearings so far, one entry per `clearDuress`, never reset: a position in the
 * sequence of clearings that a duress entry records, so the flag set again for it on delivery of
 * its alert is never set again over a clearing that came after the entry.
 */
export function duressClearsKey(workspaceId: string, subjectKey: string): AttemptCounterKey {
  return { workspaceId, factor: "duress.clears", scope: "subject", key: subjectKey };
}

export async function clearsSoFar(counters: AttemptCounters, workspaceId: string, subjectKey: string): Promise<number> {
  return (await counters.get(duressClearsKey(workspaceId, subjectKey), FOREVER)).length;
}

export async function recordClear(counters: AttemptCounters, workspaceId: string, subjectKey: string, at: Date): Promise<void> {
  await counters.recordFailure(duressClearsKey(workspaceId, subjectKey), at.toISOString(), FOREVER);
}

/** What the ledger's `duress.cleared` names: a keyed digest of the subject, which the business can match with its knowledge key, and no one else can. */
export function duressClearedSubject(knowledgeKey: string | Uint8Array, subjectKey: string): string {
  return hmacSha256Hex(knowledgeKey, duressClearedData(subjectKey));
}

export function duressClearedData(subjectKey: string): string {
  return `duress.cleared:${subjectKey}`;
}

/** The hidden counter of one factor kind's failures on a subject, which a duress entry never resets. */
export function hiddenCounterKey(workspaceId: string, kind: string, subjectKey: string): AttemptCounterKey {
  return { workspaceId, factor: `duress.hidden.${kind}`, scope: "subject", key: subjectKey };
}

/** The writes a hidden cleanup makes, whichever pass it follows: the most failures a window holds before its hard lock. */
const HIDDEN_CLEANUP_WRITES = DEFAULT_LOCKOUT.lockAfterFailures;

/**
 * After a pass whose hidden failure was recorded at `at`: a pass not under duress takes off the
 * hidden failures up to it (the latest first, a hard lock's worth), never a later one; a duress
 * entry takes off only its own. Either way one read and the same number of writes, the rest taking
 * off nothing (no failure is recorded at the epoch), so the round trips never tell a duress pass
 * from another. Not safe to run twice: the caller claims it first.
 */
export async function forgetHidden(counters: AttemptCounters, key: AttemptCounterKey, at: string, duress: boolean): Promise<void> {
  const failures = await counters.get(key, FOREVER);
  const own = duress ? [at] : failures.filter((f) => Date.parse(f) <= Date.parse(at)).slice(-HIDDEN_CLEANUP_WRITES);
  for (let i = 0; i < HIDDEN_CLEANUP_WRITES; i++) await counters.removeFailure(key, own[i] ?? FOREVER);
}

export async function isUnderDuress(counters: AttemptCounters, key: AttemptCounterKey): Promise<boolean> {
  return (await counters.get(key, FOREVER)).length > 0;
}

/** Sets the flag. Setting it twice is harmless: it is cleared as a whole. */
export async function flagDuress(counters: AttemptCounters, key: AttemptCounterKey, at: Date): Promise<void> {
  await counters.recordFailure(key, at.toISOString(), FOREVER);
}

/** The hard lock the hidden failures hold now, or null: its waits are not applied, only its lock. */
export function hiddenHardLock(lockout: Lockout, failures: readonly string[], now: Date): Lock | null {
  const state = lockState(lockout, failures, now);
  return state?.hard === true ? { scope: "subject", ...state } : null;
}

/** The first instant of the window that ends now, as the visible counters use it. */
export function hiddenWindowStart(lockout: Lockout, now: Date): string {
  return new Date(now.getTime() - lockout.windowHours * 3_600_000 + 1).toISOString();
}
