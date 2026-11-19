// Failure counters and lockouts across calls (VER-1). A per-call limit alone lets a caller call
// again: a 4-digit PIN with 3 attempts per call falls within about 3,300 calls. So every factor the
// caller enters is also counted per subject and per calling number, in a store every engine of the
// workspace shares, with a growing wait after each failure and a hard lock after too many in a
// window.
//
// A failure is recorded before the entry is judged, like the per-call attempt, so a crash, a
// failing verifier or a second process never gives a free try; a pass forgets the failures.
// Subjects are counted by subject key whether or not they exist, so a lock never says which
// accounts are real. The calling number is counted as a keyed hash, never as the number.
import type { AttemptCounterKey, AttemptCounters } from "../core/adapters.ts";
import { hmacSha256Hex } from "../core/hash.ts";
import { isDenseArray, isIntegerIn, isObject, unknownKeys } from "../core/shape.ts";

/** Lockout settings, in Badge's settings. The defaults are also the floors: a config can only be stricter. */
export interface LockoutSettings {
  /** The wait after the 1st, 2nd, ... failure in the window; the last entry repeats. Default and floors: 5, 15, 60, 300, 900. 5 to 10 entries. */
  backoffSeconds?: number[];
  /** Failures in the window that lock until the oldest of them leaves it. Default 10, at most 10. */
  lockAfterFailures?: number;
  /** The window, in hours. Default 24, from 24 to 168. */
  windowHours?: number;
}

export type Lockout = Required<LockoutSettings>;

export const DEFAULT_LOCKOUT: Readonly<Lockout> = Object.freeze({
  backoffSeconds: Object.freeze([5, 15, 60, 300, 900]) as number[],
  lockAfterFailures: 10,
  windowHours: 24,
});

const LOCKOUT_KEYS = ["backoffSeconds", "lockAfterFailures", "windowHours"];
const CALLING_NUMBER = /^\+[1-9][0-9]{1,14}$/;

/** What a lock says: which counter, whether only the business (or time) lifts it, and until when. */
export interface Lock {
  scope: AttemptCounterKey["scope"];
  /** True for the lock after too many failures in the window; false for a wait after a failure. */
  hard: boolean;
  /** ISO 8601. */
  until: string;
}

/** Every problem with Badge's `lockout` setting. Absent is fine: the defaults apply. */
export function lockoutSettingsErrors(value: unknown): string[] {
  if (value === undefined) return [];
  if (!isObject(value)) return ["lockout must be an object"];
  const errors = unknownKeys(value, LOCKOUT_KEYS).map((k) => `lockout.${k} is not a lockout setting`);
  const backoff = value.backoffSeconds;
  if (backoff !== undefined) {
    if (!isDenseArray(backoff) || backoff.length < 5 || backoff.length > 10 || !backoff.every((s) => isIntegerIn(s, 1, 86_400))) {
      errors.push("lockout.backoffSeconds must list 5 to 10 whole seconds, each at most 86400");
    } else if (backoff.some((s, i) => (s as number) < backoffFloor(i))) {
      errors.push("lockout.backoffSeconds must not go below 5, 15, 60, 300, 900 (900 after that)");
    }
  }
  if (value.lockAfterFailures !== undefined && !isIntegerIn(value.lockAfterFailures, 1, DEFAULT_LOCKOUT.lockAfterFailures)) {
    errors.push("lockout.lockAfterFailures must be 1 to 10");
  }
  if (value.windowHours !== undefined && !isIntegerIn(value.windowHours, DEFAULT_LOCKOUT.windowHours, 168)) {
    errors.push("lockout.windowHours must be 24 to 168");
  }
  return errors;
}

function backoffFloor(index: number): number {
  return DEFAULT_LOCKOUT.backoffSeconds[Math.min(index, DEFAULT_LOCKOUT.backoffSeconds.length - 1)]!;
}

/** Validated settings with the defaults filled in. */
export function lockoutOf(settings: LockoutSettings | undefined): Lockout {
  return { ...DEFAULT_LOCKOUT, backoffSeconds: [...DEFAULT_LOCKOUT.backoffSeconds], ...settings };
}

/** Whether a string is a calling number the engine counts: E.164. A withheld number is not passed at all. */
export function isCallingNumber(value: string): boolean {
  return CALLING_NUMBER.test(value);
}

/** The key a calling number is counted under: `HMAC-SHA256(knowledgeKey, "number:" + number)`, hex. */
export function numberKeyFor(knowledgeKey: string | Uint8Array, callingNumber: string): string {
  return hmacSha256Hex(knowledgeKey, `number:${callingNumber}`);
}

/** The counters one attempt is counted under: the subject's, when there is a subject key, and the number's, when the host gave one. */
export function counterKeys(workspaceId: string, factor: string, keys: { subjectKey: string | null; numberKey: string | null }): AttemptCounterKey[] {
  const out: AttemptCounterKey[] = [];
  if (keys.subjectKey !== null) out.push({ workspaceId, factor, scope: "subject", key: keys.subjectKey });
  if (keys.numberKey !== null) out.push({ workspaceId, factor, scope: "number", key: keys.numberKey });
  return out;
}

/** The first instant of the window that ends now: a failure exactly one window old has left it, so a hard lock ends at its `until`. */
function windowStart(lockout: Lockout, now: Date): string {
  return new Date(now.getTime() - lockout.windowHours * 3_600_000 + 1).toISOString();
}

/**
 * Whether failures in the window (oldest first) lock the counter now. A hard lock holds until
 * enough of them leave the window; otherwise the wait after the latest failure grows with their
 * number. Null when an attempt may be judged.
 */
export function lockState(lockout: Lockout, failures: readonly string[], now: Date): Omit<Lock, "scope"> | null {
  const times = failures.map((at) => Date.parse(at));
  const n = times.length;
  if (n >= lockout.lockAfterFailures) {
    return { hard: true, until: new Date(times[n - lockout.lockAfterFailures]! + lockout.windowHours * 3_600_000).toISOString() };
  }
  if (n === 0) return null;
  const until = times[n - 1]! + lockout.backoffSeconds[Math.min(n, lockout.backoffSeconds.length) - 1]! * 1000;
  return now.getTime() < until ? { hard: false, until: new Date(until).toISOString() } : null;
}

/** The first counter that locks now, read without writing anything. */
export async function currentLock(counters: AttemptCounters, lockout: Lockout, keys: readonly AttemptCounterKey[], now: Date): Promise<Lock | null> {
  for (const key of keys) {
    const state = lockState(lockout, await counters.get(key, windowStart(lockout, now)), now);
    if (state !== null) return { scope: key.scope, ...state };
  }
  return null;
}

/**
 * Records one failure on every counter, before the entry is judged. `raced` is a lock that
 * another attempt put in place since the counters were read (this one must not be judged);
 * `hard` is the hard lock this failure starts if the entry fails.
 */
export async function recordFailures(
  counters: AttemptCounters,
  lockout: Lockout,
  keys: readonly AttemptCounterKey[],
  now: Date,
): Promise<{ raced: Lock | null; hard: Lock | null }> {
  let raced: Lock | null = null;
  let hard: Lock | null = null;
  for (const key of keys) {
    const failures = await counters.recordFailure(key, now.toISOString(), windowStart(lockout, now));
    const before = lockState(lockout, failures.slice(0, -1), now);
    if (raced === null && before !== null) raced = { scope: key.scope, ...before };
    const after = lockState(lockout, failures, now);
    if (hard === null && after?.hard === true) hard = { scope: key.scope, ...after };
  }
  return { raced, hard };
}

/** Forgets the failures on every counter, after a pass. */
export async function resetCounters(counters: AttemptCounters, keys: readonly AttemptCounterKey[]): Promise<void> {
  for (const key of keys) await counters.reset(key);
}
