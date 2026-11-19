// Failure counters and lockouts across calls (VER-1). A per-call limit alone lets a caller call
// again: a 4-digit PIN with 3 attempts per call falls within about 3,300 calls. So every factor the
// caller enters is also counted per subject and per calling number, in a store every engine of the
// workspace shares, with a growing wait after each failure and a hard lock after too many in a
// window.
//
// A failure is recorded before the entry is judged, like the per-call attempt, so a crash, a
// failing verifier or a second process never gives a free try. A pass forgets the
// subject's failures up to it and its own on the number; the number's others stay until they leave the
// window, so a pass on the caller's own account never clears what the line ran up against others.
// Subjects are counted by subject key whether or not they exist, so a lock never says which
// accounts are real. The calling number is counted as a keyed hash, never as the number.
//
// A counter is keyed by subject or number and factor kind, never by flow or call, so failures in
// one flow count in every other (VER-15): an owner command, then a payment, then a door share one
// count. The same store also counts flow starts (`FLOW_START`): flows that need a money, contact
// or access scope are limited per hour, per number and per subject, whatever their outcome.
// The business is told of each lock and may lift one early (INT-7): see "lock notices" below.
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
  /**
   * How many flows that need a money, contact or access scope may start in an hour, per subject and
   * per calling number (VER-15). Default, and the most a config may allow: 5 per subject, 10 per number.
   */
  flowStartsPerHour?: { subject?: number; number?: number };
}

/** Flow starts allowed in an hour, by counter scope. */
export type FlowStartLimits = Record<AttemptCounterKey["scope"], number>;

export type Lockout = Required<Omit<LockoutSettings, "flowStartsPerHour">> & { flowStartsPerHour: FlowStartLimits };

export const DEFAULT_LOCKOUT: Readonly<Lockout> = Object.freeze({
  backoffSeconds: Object.freeze([5, 15, 60, 300, 900]) as number[],
  lockAfterFailures: 10,
  windowHours: 24,
  flowStartsPerHour: Object.freeze({ subject: 5, number: 10 }),
});

/** The counter kind for flow starts. A factor kind is snake_case and this is not, so no plug-in shares its counters. */
export const FLOW_START = "flow.start";

const LOCKOUT_KEYS = ["backoffSeconds", "lockAfterFailures", "windowHours", "flowStartsPerHour"];
const FLOW_START_SCOPES = ["subject", "number"] as const;
const HOUR_MS = 3_600_000;
const FOREVER = "1970-01-01T00:00:00.000Z";
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
  errors.push(...flowStartErrors(value.flowStartsPerHour));
  return errors;
}

function flowStartErrors(value: unknown): string[] {
  if (value === undefined) return [];
  if (!isObject(value)) return ["lockout.flowStartsPerHour must be an object"];
  const errors = unknownKeys(value, FLOW_START_SCOPES).map((k) => `lockout.flowStartsPerHour.${k} is not a scope: subject or number`);
  for (const scope of FLOW_START_SCOPES) {
    const most = DEFAULT_LOCKOUT.flowStartsPerHour[scope];
    if (value[scope] !== undefined && !isIntegerIn(value[scope], 1, most)) errors.push(`lockout.flowStartsPerHour.${scope} must be 1 to ${most}`);
  }
  return errors;
}

function backoffFloor(index: number): number {
  return DEFAULT_LOCKOUT.backoffSeconds[Math.min(index, DEFAULT_LOCKOUT.backoffSeconds.length - 1)]!;
}

/** Validated settings with the defaults filled in. */
export function lockoutOf(settings: LockoutSettings | undefined): Lockout {
  // Field by field, so a setting given as undefined still gets its default.
  return {
    backoffSeconds: [...(settings?.backoffSeconds ?? DEFAULT_LOCKOUT.backoffSeconds)],
    lockAfterFailures: settings?.lockAfterFailures ?? DEFAULT_LOCKOUT.lockAfterFailures,
    windowHours: settings?.windowHours ?? DEFAULT_LOCKOUT.windowHours,
    flowStartsPerHour: {
      subject: settings?.flowStartsPerHour?.subject ?? DEFAULT_LOCKOUT.flowStartsPerHour.subject,
      number: settings?.flowStartsPerHour?.number ?? DEFAULT_LOCKOUT.flowStartsPerHour.number,
    },
  };
}

/** Whether a string is a calling number the engine counts: E.164. A withheld number is not passed at all. */
export function isCallingNumber(value: string): boolean {
  // A string only: a regex test turns an array or an object into one, which would pass.
  return typeof value === "string" && CALLING_NUMBER.test(value);
}

/** The key a calling number is counted under: `HMAC-SHA256(knowledgeKey, "number:" + number)`, hex. */
export function numberKeyFor(knowledgeKey: string | Uint8Array, callingNumber: string): string {
  return hmacSha256Hex(knowledgeKey, `number:${callingNumber}`);
}

/**
 * The counters one attempt is counted under: the subject's, when there is a subject key, and the
 * number's, when the host gave one. An absent key (a call saved before numbers were kept) is none.
 * Neither the flow nor the call is part of a key.
 */
export function counterKeys(workspaceId: string, factor: string, keys: { subjectKey?: string | null; numberKey?: string | null }): AttemptCounterKey[] {
  const out: AttemptCounterKey[] = [];
  if (typeof keys.subjectKey === "string") out.push({ workspaceId, factor, scope: "subject", key: keys.subjectKey });
  if (typeof keys.numberKey === "string") out.push({ workspaceId, factor, scope: "number", key: keys.numberKey });
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
  const times = failures.map((at) => Date.parse(at)).sort((a, b) => a - b);
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
 * another attempt put in place since the counters were read (this one must not be judged); no
 * counter after it is recorded, so two racing attempts do not also lock each other out on the
 * next counter. `hard` is the hard lock this failure starts if the entry fails.
 *
 * With `resume`, this is a retry of an attempt counted at `now` that may have failed part way: a
 * counter that already holds a failure at `now` is taken as this attempt's, and not counted again.
 */
export async function recordFailures(
  counters: AttemptCounters,
  lockout: Lockout,
  keys: readonly AttemptCounterKey[],
  now: Date,
  resume = false,
): Promise<{ raced: Lock | null; hard: Lock | null }> {
  let hard: Lock | null = null;
  const at = now.toISOString();
  const since = windowStart(lockout, now);
  for (const key of keys) {
    const failures = (resume ? recordedAt(await counters.get(key, since), at) : null) ?? (await counters.recordFailure(key, at, since));
    const before = lockState(lockout, failures.slice(0, -1), now);
    if (before !== null) return { raced: { scope: key.scope, ...before }, hard: null };
    const after = lockState(lockout, failures, now);
    if (hard === null && after?.hard === true) hard = { scope: key.scope, ...after };
  }
  return { raced: null, hard };
}

/**
 * The failures as `recordFailure` returned them when the one at `at` was recorded: up to and
 * including it, in the order they were recorded. Null when none was recorded at `at`.
 */
export function recordedAt(failures: readonly string[], at: string): string[] | null {
  const own = failures.lastIndexOf(at);
  return own === -1 ? null : failures.slice(0, own + 1);
}

/**
 * After a pass whose failure was recorded at `at`, the part safe to run again: forgets the
 * subject's failures up to the pass (`forgetUpTo`). The number's are left to `removeOwnOnNumbers`.
 */
export async function forgetPass(counters: AttemptCounters, keys: readonly AttemptCounterKey[], at: Date): Promise<void> {
  for (const key of keys) if (key.scope === "subject") await forgetUpTo(counters, key, at);
}

/**
 * After a pass whose failure was recorded at `at`: takes only this attempt's own failure off each
 * number's counter, in one atomic step of the store. The number's other failures may be against
 * other accounts, so they stay until they leave the window, and so does any failure another call
 * records meanwhile. Not safe to run twice (it takes off one failure at `at`, whichever it is), so
 * the caller claims it on the call first and runs it at most once.
 */
export async function removeOwnOnNumbers(counters: AttemptCounters, keys: readonly AttemptCounterKey[], at: Date): Promise<void> {
  for (const key of keys) if (key.scope === "number") await counters.removeFailure(key, at.toISOString());
}

/**
 * Forgets a counter's failures recorded at or before `at`, one by one, and keeps every later one: a
 * failure recorded after the pass is not the pass's to forget. So a cleanup run again (its owed
 * marker not cleared) forgets nothing recorded since. Older failures than the window go too, as a
 * reset would, so a longer window set later never brings them back.
 */
export async function forgetUpTo(counters: AttemptCounters, key: AttemptCounterKey, at: Date): Promise<void> {
  for (const failure of await counters.get(key, FOREVER)) {
    if (Date.parse(failure) <= at.getTime()) await counters.removeFailure(key, failure);
  }
}

// ---- lock notices (INT-7) -------------------------------------------------------------------
//
// The business is told of a lock once, however many attempts it refuses and on however many
// engines, and a workspace gets at most NOTICES_PER_HOUR notices, so an attack locking subject after
// subject cannot flood the owner. Both are kept in the AttemptCounters store every engine shares,
// under `notice:` kinds no factor kind can be (kinds are snake_case), so they hold across processes
// and use its one atomic step.

/**
 * Lock notices a workspace gets per hour, at most, for hard locks and, apart, for waits after a
 * failure: waits come cheap to an attacker, so they can never use up the notices of hard locks.
 * Later locks in the hour are in the ledger only.
 */
export const NOTICES_PER_HOUR = 20;

/** Where a counter's notices are kept: its own key, under the `notice:` kind of its factor. */
export function noticeKey(key: AttemptCounterKey): AttemptCounterKey {
  return { ...key, factor: `notice:${key.factor}` };
}

/** Where a workspace's notices of the last hour are counted: hard locks and waits apart. */
function workspaceNoticeKey(workspaceId: string, hard: boolean): AttemptCounterKey {
  return { workspaceId, factor: hard ? "notice:*" : "notice:*wait", scope: "subject", key: "0".repeat(64) };
}

/**
 * Whether a lock gets a notice: null when one went out for it already (or for a later lock of the
 * same counter), or when the workspace had its notices for the hour. A lock is its counter and its
 * end, so its notice counter records the end: of two engines refusing the same lock, one notifies.
 * `capped` is true on the hour's last notice of its kind (hard locks, or waits).
 */
export async function claimNotice(counters: AttemptCounters, key: AttemptCounterKey, until: string, now: Date, hard: boolean): Promise<{ capped: boolean } | null> {
  const seen = await counters.recordFailure(noticeKey(key), until, until);
  if (seen.length > 1) return null;
  const hourAgo = new Date(now.getTime() - 3_600_000 + 1).toISOString();
  const sent = (await counters.recordFailure(workspaceNoticeKey(key.workspaceId, hard), now.toISOString(), hourAgo)).length;
  return sent > NOTICES_PER_HOUR ? null : { capped: sent === NOTICES_PER_HOUR };
}

/**
 * What the ledger's `verification.unlocked` names the counter by: a keyed digest of its factor kind,
 * scope and key, which the business can match with its knowledge key, and no one else can.
 */
export function unlockedCounter(knowledgeKey: string | Uint8Array, key: Pick<AttemptCounterKey, "factor" | "scope" | "key">): string {
  return hmacSha256Hex(knowledgeKey, JSON.stringify(["verification.unlocked", key.factor, key.scope, key.key]));
}

/** Lifts one lock: forgets the counter's failures and its notices, so a later lock is told again. */
export async function unlockCounter(counters: AttemptCounters, key: AttemptCounterKey): Promise<void> {
  await counters.reset(key);
  await counters.reset(noticeKey(key));
}

/** The first instant of the hour that ends now: a start exactly an hour old has left it. */
function hourStart(now: Date): string {
  return new Date(now.getTime() - HOUR_MS + 1).toISOString();
}

/** The scope of the first counter already at its limit of flow starts this hour, read without writing anything. */
export async function flowStartLimited(
  counters: AttemptCounters,
  limits: FlowStartLimits,
  keys: readonly AttemptCounterKey[],
  now: Date,
): Promise<AttemptCounterKey["scope"] | null> {
  for (const key of keys) {
    if ((await counters.get(key, hourStart(now))).length >= limits[key.scope]) return key.scope;
  }
  return null;
}

/**
 * Counts one flow start on every counter. Returns the scope of the first counter it took over its
 * limit (another start, on any call or engine, got in since the counters were read), or null.
 * A write that fails passes its error on, after the starts already counted are taken back (by their
 * time, which takes off the same as taking off these): the flow never attaches, as when the call
 * refuses it. The failed write's own start may or may not have been kept, so it stays as the store
 * left it, and so does one the store refuses to take back (fail closed).
 */
export async function recordFlowStarts(
  counters: AttemptCounters,
  limits: FlowStartLimits,
  keys: readonly AttemptCounterKey[],
  now: Date,
): Promise<AttemptCounterKey["scope"] | null> {
  let over: AttemptCounterKey["scope"] | null = null;
  const at = now.toISOString();
  const counted: AttemptCounterKey[] = [];
  for (const key of keys) {
    let starts: string[];
    try {
      starts = await counters.recordFailure(key, at, hourStart(now));
    } catch (error) {
      for (const done of counted) await counters.removeFailure(done, at).catch(() => undefined);
      throw error;
    }
    counted.push(key);
    if (over === null && starts.length > limits[key.scope]) over = key.scope;
  }
  return over;
}
