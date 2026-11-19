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
import { lockState, type Lock, type Lockout } from "./counters.ts";

/** The flag's counter kind: one entry while the subject is under duress. */
export const DURESS_FLAG = "duress.flag";

/** The first instant the store keeps the flag from: it never leaves a window. */
const FOREVER = "1970-01-01T00:00:00.000Z";

export function duressFlagKey(workspaceId: string, subjectKey: string): AttemptCounterKey {
  return { workspaceId, factor: DURESS_FLAG, scope: "subject", key: subjectKey };
}

/** The hidden counter of one factor kind's failures on a subject, which a duress entry never resets. */
export function hiddenCounterKey(workspaceId: string, kind: string, subjectKey: string): AttemptCounterKey {
  return { workspaceId, factor: `duress.hidden.${kind}`, scope: "subject", key: subjectKey };
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
