// Badge (verify): who is calling, in levels. The factors are plug-ins (factors.ts); a flow's
// `badge.verify` step names the level it needs and the factors that may count toward it.
//
// Every runtime function takes the engine's runtime and works in compare-and-set steps: an attempt
// is counted in one write before it is judged, and a link is reserved in one write before it is
// sent, so two processes running the same call can never get two attempts or two links for one.
import type { SubjectRecord } from "../core/adapters.ts";
import type { JsonValue } from "../core/canonical.ts";
import { EngineError, NotImplementedError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import { isStepLevel } from "../core/config.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import {
  FACTOR_KINDS,
  evaluateAssurance,
  scopesForLevel,
  textCodeTrusted,
  type AssuranceLevel,
  type CarrierSignalReport,
  type FactorKind,
  type ScopeClass,
} from "../core/policy.ts";
import type { CallDraft, CallRecord, EngineRuntime, Locale } from "../core/runtime.ts";
import { canApply, type SessionState } from "../core/session.ts";
import { isIntegerIn, isObject, isStringArray, unknownKeys } from "../core/shape.ts";
import type { IdentityOutcome } from "../webhooks/stripe.ts";
import {
  BUILT_IN_FACTORS,
  KNOWLEDGE_FACTORS,
  checkFactorPlugin,
  judgeKeypad,
  judgePin,
  type BadgeSettings,
  type FactorEntry,
  type FactorPlugin,
  type PinOutcome,
  type PinSettings,
} from "./factors.ts";
import { counterKeys, currentLock, isCallingNumber, lockoutOf, lockoutSettingsErrors, forgetPass, recordFailures, type Lock } from "./counters.ts";
import { clearsSoFar, duressClearedData, duressFlagKey, flagDuress, hiddenCounterKey, hiddenHardLock, hiddenWindowStart, isUnderDuress, recordClear } from "./duress-flag.ts";
import { isKeypadEntry } from "./knowledge.ts";

export const BADGE = "badge";

export interface BadgeVerifyStep extends FlowStep {
  type: "badge.verify";
  level: 1 | 2 | 3;
  factors: string[];
  /** The scopes this step's grant covers. Default: every scope the level reaches. List them, so a grant covers only what the flow is for. */
  scopes?: string[];
}

/** Badge's part of a call record. */
export interface BadgeSlice {
  subjectKey: string | null;
  subject: SubjectRecord | null;
  /** The keyed hash of the calling number the host gave, for the counters across calls; null without one. */
  numberKey: string | null;
  /** Judged attempts per factor kind on this call. */
  attempts: Record<string, number>;
  /** Tries at choosing a PIN on this call (`enrolPin`), counted before each is judged. Absent until the first. */
  pinEnrolments?: number;
  /**
   * The PIN digests this call's tries are storing and have not yet recorded as enrolled
   * (`pin.enrolled`), one entry per try. Never the digits. At most `maxAttemptsPerCall` entries.
   */
  pinPending?: Array<{ subjectKey: string; digest: string; enrolmentId: string }>;
  /**
   * Set once a duress PIN passed on this call (VER-12), and never cleared: the scopes refused on
   * top of money, contact and access, as Badge's settings named them then. The only place the
   * duress state is kept. Absent on every other call.
   */
  duress?: { refuseScopes: string[] };
  /**
   * Duress alerts owed to the host's notifier (VER-12), one per duress entry, written with the
   * entry and removed once `notify` resolved. Never the PIN. Absent until the first.
   */
  duressAlerts?: Array<DuressAlertRecord>;
  /** Duress entries on this call so far, numbering their alerts. Absent until the first. */
  duressEntries?: number;
  /** A keypad or PIN factor matched since verification last started from nothing. */
  knowledgeMatched: boolean;
  carrier: CarrierSignalReport | null;
  /**
   * The one photo ID link a call may have: reserved before it is created, `sent` once its session
   * counts, `texted` once delivered; `void` if the call was tainted or the subject changed first.
   * A reserved or sent link resumes with the same idempotency keys after a failure.
   */
  identityLink: "none" | "reserved" | "sent" | "texted" | "void";
  /** Goes up on every beginVerification, so a result judged for an earlier one is never applied. */
  epoch: number;
  /** Identity sessions whose outcome may still count. */
  identitySessions: string[];
  /** How many verifications finished on this call, and the last one's level and counted methods. */
  finished: number;
  lastLevel: AssuranceLevel;
  lastMethods: FactorKind[];
}

export interface KeypadResult {
  /** One answer for all fields: never which one failed. */
  matched: boolean;
  /** No more attempts for this factor on this call. */
  locked: boolean;
}

export interface VerificationResult {
  level: AssuranceLevel;
  scopes: string[];
}

export type OutcomeResult = { applied: false } | { applied: true; callId: string };

/**
 * Who verification is for, and optionally the number the call came from (E.164, from the carrier,
 * never from the model). The number is never a factor: it only keys a counter across calls, so a
 * caller trying one account after another from one line is locked out too.
 */
export type BeginVerificationInput = ({ accountNumber: string } | { subjectKey: string }) & { callingNumber?: string };

const SETTINGS_KEYS = ["factors", "grantTtlSeconds", "pin", "lockout"];
const PIN_KEYS = ["mode", "minDigits", "maxDigits", "maxAttemptsPerCall", "duress"];

/** The subject whose number links may go to: only once a keypad or PIN factor matched. */
export function matchedSubject(record: CallRecord): SubjectRecord {
  const badge = record.modules[BADGE] as unknown as BadgeSlice | undefined;
  if (badge === undefined || !badge.knowledgeMatched || badge.subject === null) {
    throw new EngineError("precondition_failed", "the keypad or PIN checks have not matched on this call");
  }
  return badge.subject;
}

/** The Badge module, with the built-in factors and any plug-ins the host adds. */
export function badgeModule(options: { factors?: readonly FactorPlugin[] } = {}): BadgeModule {
  return new BadgeModule(options.factors ?? []);
}

export class BadgeModule implements AssuranceModule {
  readonly manifest: AssuranceModule["manifest"];
  readonly #plugins = new Map<string, FactorPlugin>();

  constructor(plugins: readonly FactorPlugin[]) {
    const errors: string[] = [];
    for (const plugin of plugins) {
      const problems = checkFactorPlugin(plugin, [...FACTOR_KINDS, ...this.#plugins.keys()]);
      errors.push(...problems);
      if (problems.length === 0) this.#plugins.set(plugin.kind, plugin);
    }
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    this.manifest = {
      name: BADGE,
      version: "1",
      summary: "Verify the caller to an assurance level with the factors the flow allows.",
      provides: { factors: [...FACTOR_KINDS, ...this.#plugins.keys()], steps: ["badge.verify"], outcomes: ["grant"] },
      scopes: { grants: ["*"], needs: {} },
      adapters: ["records"],
    };
  }

  plugin(kind: string): FactorPlugin | undefined {
    return this.#plugins.get(kind);
  }

  validateSettings(settings: unknown): string[] {
    if (!isObject(settings)) return ["must be an object with the factors that are on"];
    const errors = unknownKeys(settings, SETTINGS_KEYS).map((k) => `${k} is not a badge setting`);
    const known = this.manifest.provides.factors;
    if (!isStringArray(settings.factors) || settings.factors.length === 0) {
      errors.push("factors must list at least one factor");
    } else {
      if (new Set(settings.factors).size !== settings.factors.length) errors.push("factors has duplicates");
      for (const kind of settings.factors) {
        if (!known.includes(kind)) errors.push(`factor ${kind} is not installed`);
        const planned = BUILT_IN_FACTORS[kind as keyof typeof BUILT_IN_FACTORS]?.planned;
        if (planned !== undefined) errors.push(`factor ${kind} is not built yet (${planned})`);
      }
      if (settings.factors.includes("pin")) errors.push(...pinSettingsErrors(settings.pin));
    }
    if (settings.grantTtlSeconds !== undefined && !isIntegerIn(settings.grantTtlSeconds, 1, 3600)) {
      errors.push("grantTtlSeconds must be an integer from 1 to 3600");
    }
    errors.push(...lockoutSettingsErrors(settings.lockout));
    return errors;
  }

  requiredAdapters(settings: unknown): string[] {
    const s = settings as BadgeSettings;
    const adapters = new Set<string>(this.manifest.adapters);
    for (const kind of s.factors) {
      const builtIn = BUILT_IN_FACTORS[kind as keyof typeof BUILT_IN_FACTORS];
      for (const a of builtIn?.adapters ?? this.#plugins.get(kind)!.adapters) adapters.add(a);
      // A factor the caller enters (a plug-in always is) is counted across calls.
      if (builtIn?.entered !== false) adapters.add("counters");
    }
    if (s.pin?.mode === "verifier" && s.factors.includes("pin")) adapters.add("pinVerifier");
    if (s.pin?.duress !== undefined && s.factors.includes("pin")) adapters.add("duressNotifier");
    return [...adapters];
  }

  validateStep(step: FlowStep, ctx: StepContext): string[] {
    const errors = unknownKeys(step, ["type", "level", "factors", "scopes"]).map((k) => `${k} is not a field of this step`);
    if (step.scopes !== undefined) errors.push(...this.#scopeErrors(step, ctx));
    if (!isStepLevel(step.level)) errors.push("level must be 1, 2 or 3");
    if (!isStringArray(step.factors) || step.factors.length === 0) {
      errors.push("factors must list at least one factor");
      return errors;
    }
    if (new Set(step.factors).size !== step.factors.length) errors.push("factors has duplicates");
    const settings = ctx.settings as BadgeSettings | null;
    if (settings !== null) {
      for (const kind of step.factors) if (!settings.factors.includes(kind)) errors.push(`factor ${kind} is turned off in the badge settings`);
    }
    if (ctx.policy !== null && isStepLevel(step.level)) {
      const factors = step.factors;
      const level = step.level;
      const reachable = ctx.policy.levels.some((rule) => rule.level >= level && rule.anyOf.some((set) => set.every((k) => factors.includes(k))));
      if (!reachable) errors.push(`level ${level} cannot be reached with [${factors.join(", ")}] under the policy`);
    }
    return errors;
  }

  #scopeErrors(step: FlowStep, ctx: StepContext): string[] {
    if (!isStringArray(step.scopes) || step.scopes.length === 0) return ["scopes must list at least one scope"];
    const errors = new Set(step.scopes).size === step.scopes.length ? [] : ["scopes has duplicates"];
    if (ctx.policy === null) return errors;
    for (const scope of step.scopes) {
      const min = Object.hasOwn(ctx.policy.scopes, scope) ? ctx.policy.scopes[scope] : undefined;
      if (min === undefined) errors.push(`scope ${scope} is not in the policy`);
      else if (isStepLevel(step.level) && min > step.level) errors.push(`scope ${scope} needs level ${min}, above this step's level ${step.level}`);
    }
    return errors;
  }

  stepLevel(step: FlowStep): number | null {
    return isStepLevel(step.level) ? step.level : null;
  }

  stepGrants(step: FlowStep): string[] | null {
    return isStringArray(step.scopes) ? step.scopes : null;
  }

  initCall(): JsonValue {
    const initial: BadgeSlice = {
      subjectKey: null,
      subject: null,
      numberKey: null,
      attempts: {},
      knowledgeMatched: false,
      carrier: null,
      identityLink: "none",
      epoch: 0,
      identitySessions: [],
      finished: 0,
      lastLevel: 0,
      lastMethods: [],
    };
    return initial as unknown as JsonValue;
  }

  enterStep(_step: FlowStep, s: JsonValue): JsonValue {
    return (s as unknown as BadgeSlice).finished;
  }

  stepStatus(step: FlowStep, view: StepView): StepStatus {
    const s = view.slice as unknown as BadgeSlice;
    if (s.finished <= (view.mark as number)) return "pending";
    return s.lastLevel >= (step.level as number) ? "complete" : "failed";
  }

  onUntrusted(s: JsonValue): JsonValue {
    // A photo ID link sent before the taint no longer counts. One link per call still holds.
    const badge = s as unknown as BadgeSlice;
    return { ...badge, identitySessions: [], identityLink: voided(badge.identityLink) } as unknown as JsonValue;
  }

  receiptPart(s: JsonValue, state: SessionState): { [key: string]: JsonValue } {
    return { verification: { level: state.level, methods: state.level === 0 ? [] : (s as unknown as BadgeSlice).lastMethods } };
  }
}

/** A link not yet delivered can no longer count: it is void. One delivered stays delivered (and stops any other). */
function voided(link: BadgeSlice["identityLink"]): BadgeSlice["identityLink"] {
  return link === "reserved" || link === "sent" ? "void" : link;
}

/** Refuses to apply a result judged for an earlier verification of this call. */
function assertSameVerification(s: BadgeSlice, epoch: number): void {
  if (s.epoch !== epoch) throw new EngineError("precondition_failed", "verification restarted while this result was on its way; it does not count");
}

function pinSettingsErrors(pin: unknown): string[] {
  if (!isObject(pin)) return ["pin settings are required when the pin factor is on"];
  const errors = unknownKeys(pin, PIN_KEYS).map((k) => `pin.${k} is not a pin setting`);
  if (pin.mode !== "keyed_hash" && pin.mode !== "verifier") errors.push("pin.mode must be keyed_hash or verifier");
  if (!isIntegerIn(pin.minDigits, 4, 12)) errors.push("pin.minDigits must be 4 to 12");
  else if (!isIntegerIn(pin.maxDigits, pin.minDigits, 12)) errors.push("pin.maxDigits must be from minDigits to 12");
  if (!isIntegerIn(pin.maxAttemptsPerCall, 1, 5)) errors.push("pin.maxAttemptsPerCall must be 1 to 5");
  if (pin.duress !== undefined) errors.push(...duressSettingsErrors(pin.duress));
  return errors;
}

function duressSettingsErrors(duress: unknown): string[] {
  if (!isObject(duress)) return ["pin.duress must be an object with refuseScopes"];
  const errors = unknownKeys(duress, ["refuseScopes"]).map((k) => `pin.duress.${k} is not a duress setting`);
  if (!isStringArray(duress.refuseScopes)) errors.push("pin.duress.refuseScopes must list scopes (it may be empty)");
  else if (new Set(duress.refuseScopes).size !== duress.refuseScopes.length) errors.push("pin.duress.refuseScopes has duplicates");
  return errors;
}

/**
 * Whether a duress call refuses a scope (VER-12): every scope whose class is not `none` (money,
 * contact, access, or no class at all), and the scopes Badge's settings named. False on any other call.
 */
export function duressRefuses(record: CallRecord, scope: string, cls: ScopeClass | null): boolean {
  const duress = (record.modules[BADGE] as unknown as BadgeSlice | undefined)?.duress;
  return duress !== undefined && (cls !== "none" || duress.refuseScopes.includes(scope));
}

/** The duress alerts a call record owes (VER-12). */
/** An alert a call owes: `clears` is how many clearings the subject had when its entry was judged. */
export interface DuressAlertRecord {
  alertId: string;
  subjectKey: string;
  at: string;
  clears: number;
}

export function owedDuressAlerts(record: CallRecord): DuressAlertRecord[] {
  return (record.modules[BADGE] as unknown as BadgeSlice | undefined)?.duressAlerts ?? [];
}

/** Takes one delivered duress alert off a call record. */
export function acknowledgeDuressAlert(record: CallRecord, alertId: string): void {
  const s = record.modules[BADGE] as unknown as BadgeSlice;
  s.duressAlerts = s.duressAlerts!.filter((a) => a.alertId !== alertId);
}

// ---- runtime -------------------------------------------------------------------------------

/** Refuses a factor that is off, or that the current flow step does not allow. */
function allowFactor(rt: EngineRuntime, record: CallRecord, kind: string): void {
  const settings = rt.settings<BadgeSettings>(BADGE);
  if (!settings.factors.includes(kind)) throw new EngineError("precondition_failed", `the ${kind} factor is turned off`);
  const step = stepOfType<BadgeVerifyStep>(record, "badge.verify");
  if (step !== null && !step.factors.includes(kind)) throw new EngineError("precondition_failed", `the flow step does not use the ${kind} factor`);
}

function maxAttempts(rt: EngineRuntime, module: BadgeModule, kind: string): number {
  if (kind === "keypad_knowledge") return rt.policy.maxKeypadAttemptsPerCall;
  if (kind === "pin") return rt.settings<BadgeSettings>(BADGE).pin!.maxAttemptsPerCall;
  return module.plugin(kind)!.maxAttemptsPerCall;
}

/**
 * Starts (or restarts) verification. The subject is either the account number the caller keyed
 * (hashed under the knowledge key) or a subject key the host's code chose, for example the owner
 * of the line. Choosing the subject is not a factor: only factors raise the level. With a calling
 * number, failures are also counted against that number across calls; a later restart that
 * leaves it out keeps it.
 */
export async function beginVerification(rt: EngineRuntime, callId: string, input: BeginVerificationInput): Promise<void> {
  rt.settings(BADGE);
  let subjectKey: string | null;
  if ("subjectKey" in input) {
    if (!/^[0-9a-f]{64}$/.test(input.subjectKey)) throw new EngineError("invalid_input", "subjectKey must be 64 lower-case hex characters");
    subjectKey = input.subjectKey;
  } else {
    subjectKey = isKeypadEntry(input.accountNumber) ? rt.hmac(`subject:${input.accountNumber}`) : null;
  }
  const number = input.callingNumber;
  if (number !== undefined && !isCallingNumber(number)) throw new EngineError("invalid_input", "callingNumber must be E.164; leave it out when the number is withheld");
  const numberKey = number === undefined ? null : rt.hmac(`number:${number}`);
  const subject = subjectKey === null ? null : await rt.adapter("records").getSubject(rt.workspaceId, subjectKey);
  await rt.update(callId, (draft) => {
    stepOfType(draft.record, "badge.verify");
    const s = draft.slice<BadgeSlice>(BADGE);
    const reset = subjectKey !== s.subjectKey;
    draft.apply({ type: "verification_started", reset });
    s.epoch++;
    if (reset) {
      // Another subject: nothing collected for the previous one can count for this one.
      s.identitySessions = [];
      s.identityLink = voided(s.identityLink);
    }
    if (draft.record.state.factors.length === 0) {
      s.knowledgeMatched = false;
      s.carrier = null;
    }
    s.subjectKey = subjectKey;
    s.subject = subject;
    if (numberKey !== null) s.numberKey = numberKey;
    draft.emit("verification.started", "code", { subject: "subjectKey" in input ? "host" : "account" });
  });
}

/** Refuses an attempt the call cannot take now: a factor that is off or off-step, a phase that is not verifying, a restarted verification. */
function assertAttempt(rt: EngineRuntime, draft: CallDraft, kind: string, epoch: number): BadgeSlice {
  allowFactor(rt, draft.record, kind);
  draft.assertCan({ type: "factor_recorded", factor: { kind, passed: false, at: rt.now() } });
  const s = draft.slice<BadgeSlice>(BADGE);
  assertSameVerification(s, epoch);
  return s;
}

/** Answers `locked` without judging, and says so in the ledger: which counter and the factor, never a value. */
async function refuseLocked(rt: EngineRuntime, callId: string, kind: string, epoch: number, lock: Lock): Promise<KeypadResult> {
  await rt.update(callId, (draft) => {
    assertAttempt(rt, draft, kind, epoch);
    draft.emit("verification.locked", "code", { kind, scope: lock.scope, hard: lock.hard, until: lock.until });
  });
  return { matched: false, locked: true };
}

/**
 * Judges one entered factor: keypad knowledge, the PIN, or a plug-in. The counters across calls
 * are read first, and a locked subject or number is refused without judging or counting. Then the
 * attempt is counted on the call and as a failure across calls, both before it is judged; an
 * accepted pass forgets the subject's failures and its own on the number. After the factor's limit the line stops judging, even the right answer.
 */
export async function submitFactor(rt: EngineRuntime, module: BadgeModule, callId: string, kind: string, entry: FactorEntry): Promise<KeypadResult> {
  const builtIn = BUILT_IN_FACTORS[kind as keyof typeof BUILT_IN_FACTORS];
  const plugin = module.plugin(kind);
  if (builtIn?.entered !== true && plugin === undefined) throw new EngineError("invalid_input", `${kind} is not a factor the caller enters`);
  const before = await rt.read(callId);
  allowFactor(rt, before, kind);
  const current = before.modules[BADGE] as unknown as BadgeSlice | undefined;
  if (current === undefined) throw new EngineError("module_disabled", `${BADGE} was off when this call started`);
  const counters = rt.adapter("counters");
  const lockout = lockoutOf(rt.settings<BadgeSettings>(BADGE).lockout);
  const keys = counterKeys(rt.workspaceId, kind, current);
  const settings = rt.settings<BadgeSettings>(BADGE);
  // With the duress PIN on, a subject's failures are also counted where a duress entry never
  // resets them, and the hard lock they reach holds (duress-flag.ts).
  const duressOn = settings.pin?.duress !== undefined;
  const hidden = duressOn && current.subjectKey !== null ? hiddenCounterKey(rt.workspaceId, kind, current.subjectKey) : null;
  // The flag is read for every subject, the duress PIN on or off: a subject flagged while it was on
  // stays under duress after a config turns it off, until the business clears it.
  const flag = current.subjectKey !== null ? duressFlagKey(rt.workspaceId, current.subjectKey) : null;
  const lock =
    (await currentLock(counters, lockout, keys, rt.clock.now())) ??
    (hidden === null ? null : hiddenHardLock(lockout, await counters.get(hidden, hiddenWindowStart(lockout, rt.clock.now())), rt.clock.now()));
  if (lock !== null) return refuseLocked(rt, callId, kind, current.epoch, lock);
  const reserved = await rt.update(callId, (draft) => {
    const s = assertAttempt(rt, draft, kind, current.epoch);
    const max = maxAttempts(rt, module, kind);
    const used = s.attempts[kind] ?? 0;
    if (used >= max) return null;
    s.attempts[kind] = used + 1;
    return { subjectKey: s.subjectKey, subject: s.subject, last: used + 1 >= max, epoch: s.epoch };
  });
  if (reserved === null) return { matched: false, locked: true };
  const at = rt.clock.now();
  const recorded = await recordFailures(counters, lockout, keys, at);
  // Another attempt, on this call or another, locked the subject or number since they were read.
  // This entry is not judged, so it gives back the call's attempt it reserved, like one refused up front.
  if (recorded.raced !== null) {
    await rt.update(callId, (draft) => {
      const s = draft.slice<BadgeSlice>(BADGE);
      s.attempts[kind] = Math.max(0, s.attempts[kind]! - 1);
    });
    return refuseLocked(rt, callId, kind, reserved.epoch, recorded.raced);
  }
  const hiddenAfter = hidden === null ? null : await counters.recordFailure(hidden, at.toISOString(), hiddenWindowStart(lockout, at));
  const input = { workspaceId: rt.workspaceId, subjectKey: reserved.subjectKey, subject: reserved.subject, entry, hmac: (d: string) => rt.hmac(d) };
  let outcome: PinOutcome;
  if (kind === "pin") outcome = await judgePin(rt, settings.pin as PinSettings, input);
  else outcome = (kind === "keypad_knowledge" ? await judgeKeypad(rt.policy, input) : (await plugin!.judge(input)) === true) ? "pass" : "fail";
  // Only an entry of the duress PIN itself sets the flag. A pass that is a duress entry because the
  // flag was set when it was read never writes it again: a clearing that lands while it is judged
  // stays cleared, and the pass does the same store work as any pass.
  const pinDuress = outcome === "duress";
  // The subject's clearings so far, read before the flag, so a clearing that lands after the flag
  // was read is counted after this entry, and its alert's delivery never sets the flag over it.
  const clears = outcome !== "fail" && current.subjectKey !== null ? await clearsSoFar(counters, rt.workspaceId, current.subjectKey) : 0;
  // A subject under duress stays so: every pass on it, on any call, is a duress entry until the
  // business clears the flag (clearDuress).
  if (outcome === "pass" && flag !== null && (await isUnderDuress(counters, flag))) outcome = "duress";
  // A duress entry is a pass everywhere the caller can reach: the factor, the level, the grant, the
  // events, the receipt and the counters across calls. Only the call record's `duress` and the PIN
  // entry's keyed tag differ.
  const passed = outcome !== "fail";
  const hard = passed ? null : (recorded.hard ?? (hiddenAfter === null ? null : hiddenHardLock(lockout, hiddenAfter, at)));
  const stale = await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    const now = rt.now();
    const factor = { kind, passed, at: now };
    // A duress entry is recorded against the call, not the verification: it stands, and its alert is
    // owed, even if verification restarted or the call moved on while it was judged. The engine sends
    // the alert after this write (and retries it until the notifier answers).
    if (outcome === "duress") {
      // With the duress PIN turned off since the flag was set, its list of scopes to refuse is gone:
      // every scope of the policy is refused (fail closed).
      s.duress ??= { refuseScopes: settings.pin?.duress === undefined ? Object.keys(rt.policy.scopes) : [...settings.pin.duress.refuseScopes] };
      // Every entry of the duress PIN alerts. A pass that is duress only by the flag alerts once a
      // call: the first, so a flagged owner's call always raises one, and a run of passes on one
      // call does not flood the business.
      if (pinDuress || s.duressEntries === undefined) {
        // Unique without the id generator: the call and the number of this alert on it, which the
        // compare-and-set write makes one per entry across every engine.
        s.duressEntries = (s.duressEntries ?? 0) + 1;
        const alert = { alertId: JSON.stringify(["duress", rt.workspaceId, callId, s.duressEntries]), subjectKey: reserved.subjectKey!, at: now, clears };
        s.duressAlerts = [...(s.duressAlerts ?? []), alert];
      }
    }
    // Otherwise the result is applied only to the verification it was judged for, as for any factor;
    // a stale one is refused with the same error either way, after the write.
    if (s.epoch !== reserved.epoch) return new EngineError("precondition_failed", "verification restarted while this result was on its way; it does not count");
    if (!canApply(draft.record.state, { type: "factor_recorded", factor })) return new EngineError("invalid_transition", `factor_recorded is not allowed while ${draft.record.state.phase}`);
    draft.apply({ type: "factor_recorded", factor });
    if (passed && KNOWLEDGE_FACTORS.includes(kind)) s.knowledgeMatched = true;
    draft.emit("verification.factor", "code", { kind, passed }, kind === "pin" ? outcome : undefined);
    if (hard !== null) draft.emit("verification.locked", "code", { kind, scope: hard.scope, hard: true, until: hard.until });
    return null;
  });
  // A duress PIN entry flags its subject, even a stale one: durable and hidden, before the visible reset.
  if (pinDuress) await flagDuress(counters, flag!, at);
  // A stale entry's failure stays counted across calls, as for any entry that was not accepted.
  if (stale !== null) throw stale;
  // Only once the result is accepted. The number keeps its failures but this attempt's own: they
  // may be against other accounts, so a pass on this one must not clear them.
  if (passed) await forgetPass(counters, keys, at);
  // The hidden counter forgets only on a pass that is not under duress; a duress entry takes off its
  // own failure, as a pass does, and keeps the rest.
  if (passed && hidden !== null) {
    if (outcome === "duress") await counters.removeFailure(hidden, at.toISOString());
    else await counters.reset(hidden);
  }
  return { matched: passed, locked: !passed && (reserved.last || hard !== null) };
}

/** An opaque member id: no "@" and no space, so no email address or name reaches the ledger. */
const MEMBER_ID = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * The business lifts a subject's duress flag (VER-12): a host call from its own tools, never on a
 * caller's request, once it knows the subject is safe. `duress.cleared` goes to the ledger with the
 * member before the flag and the hidden counters are cleared, so no clearing goes unrecorded. Until
 * then every pass on the subject is a duress entry.
 */
export async function clearDuress(rt: EngineRuntime, subjectKey: string, memberId: string): Promise<void> {
  const settings = rt.settings<BadgeSettings>(BADGE);
  const errors: string[] = [];
  if (typeof subjectKey !== "string" || !/^[0-9a-f]{64}$/.test(subjectKey)) errors.push("subjectKey must be 64 lower-case hex characters");
  if (typeof memberId !== "string" || !MEMBER_ID.test(memberId)) errors.push("memberId must be an opaque id: 1 to 64 of letters, digits, '.', '_', '-'");
  if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
  const counters = rt.adapter("counters");
  // The ledger never says who was under duress: the subject as a keyed digest only the business can
  // match (duressClearedSubject with its knowledge key), as enrolDuressPin writes nothing at all.
  await rt.adapter("ledger").append({ callId: null, actor: "member", event: "duress.cleared", at: rt.now(), detail: { subject: rt.hmac(duressClearedData(subjectKey)), memberId } });
  // Counted before the flag goes, so an alert of an earlier entry, delivered later, never sets it again.
  await recordClear(counters, rt.workspaceId, subjectKey, rt.clock.now());
  await counters.reset(duressFlagKey(rt.workspaceId, subjectKey));
  for (const kind of settings.factors) await counters.reset(hiddenCounterKey(rt.workspaceId, kind, subjectKey));
}

/** Asks the carrier about the number on file, never the calling number. Only after a keypad or PIN match. */
export async function checkCarrier(rt: EngineRuntime, callId: string): Promise<{ textCodeTrusted: boolean }> {
  const before = await rt.read(callId);
  allowFactor(rt, before, "carrier_identity_match");
  const subject = matchedSubject(before);
  if (!canApply(before.state, { type: "factor_recorded", factor: { kind: "carrier_identity_match", passed: false, at: rt.now() } })) {
    throw new EngineError("invalid_transition", `the carrier is checked while verifying, not while ${before.state.phase}`);
  }
  const epoch = (before.modules[BADGE] as unknown as BadgeSlice).epoch;
  const report = await rt.adapter("carrier").check({ phoneNumber: subject.phoneOnFile });
  const trusted = textCodeTrusted(rt.policy, report);
  await rt.update(callId, (draft) => {
    allowFactor(rt, draft.record, "carrier_identity_match");
    matchedSubject(draft.record);
    const s = draft.slice<BadgeSlice>(BADGE);
    assertSameVerification(s, epoch);
    if (report.identityMatch !== "unavailable") {
      draft.apply({ type: "factor_recorded", factor: { kind: "carrier_identity_match", passed: report.identityMatch === "match", at: rt.now() } });
    } else {
      draft.assertCan({ type: "factor_recorded", factor: { kind: "carrier_identity_match", passed: false, at: rt.now() } });
    }
    s.carrier = report;
    draft.emit("verification.carrier_checked", "code", { checked: report.checked, textCodeTrusted: trusted, identityMatch: report.identityMatch });
  });
  return { textCodeTrusted: trusted };
}

/** The texted one-time code. Planned (VER-2): limits per subject and per number come first. */
export async function sendTextCode(rt: EngineRuntime, callId: string): Promise<never> {
  matchedSubject(await rt.read(callId));
  throw new NotImplementedError("Engine.sendTextCode", "VER-2");
}

/**
 * The strong tier: a photo ID and selfie check by a link texted to the number on file, only after
 * a keypad or PIN match, at most one link per call (reserved before it is created).
 */
export async function startPhotoId(rt: EngineRuntime, callId: string): Promise<{ sent: true }> {
  const { phone, locale } = await rt.update(callId, (draft) => {
    allowFactor(rt, draft.record, "photo_id");
    const subject = matchedSubject(draft.record);
    const s = draft.slice<BadgeSlice>(BADGE);
    if (s.identityLink === "texted" || s.identityLink === "void") throw new EngineError("precondition_failed", "a photo ID link was already sent on this call");
    if (s.identityLink === "none") s.identityLink = "reserved";
    return { phone: subject.phoneOnFile, locale: draft.record.locale };
  });
  // Reserved or sent and not delivered: a retry resumes with the same keys, and the provider
  // returns the same check, so a call never has two links.
  const check = await rt.adapter("identity").createDocumentCheck({ callId, idempotencyKey: rt.idempotencyKey(callId, "identity") });
  const enrolled = await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    if (s.identityLink === "void") return false;
    if (s.identityLink === "reserved") {
      s.identityLink = "sent";
      s.identitySessions.push(check.sessionId);
    }
    return true;
  });
  // Tainted while the check was created: the link would never count, so it is never sent.
  if (!enrolled) throw new EngineError("precondition_failed", "untrusted content entered the call while the photo ID check was created");
  await rt.bindRef(`identity:${check.sessionId}`, callId);
  await rt.adapter("messages").sendText({ to: phone, body: identityText(locale, check.url), purpose: "identity_link", idempotencyKey: rt.idempotencyKey(callId, "identity", "text") });
  await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    if (s.identityLink === "sent") s.identityLink = "texted";
    draft.emit("identity.link_sent", "code", {});
  });
  return { sent: true };
}

/** The identity provider's verified webhook outcome. Unknown, late or tainted sessions are ignored. */
export async function applyIdentityOutcome(rt: EngineRuntime, outcome: IdentityOutcome): Promise<OutcomeResult> {
  const callId = await rt.resolveRef(`identity:${outcome.sessionId}`);
  if (callId === null) return { applied: false };
  return rt.update(callId, (draft): OutcomeResult => {
    const s = draft.slice<BadgeSlice>(BADGE);
    const factor = { kind: "photo_id", passed: outcome.status === "verified", at: rt.now() };
    const step = draft.step();
    // No flow at all, or a running flow on a step that uses photo ID. A flow that ended takes nothing more.
    const stepAllows = step === null ? draft.record.flow === null : step.type === "badge.verify" && (step.factors as string[]).includes("photo_id");
    if (!s.identitySessions.includes(outcome.sessionId) || !canApply(draft.record.state, { type: "factor_recorded", factor }) || !stepAllows) {
      return { applied: false };
    }
    s.identitySessions = s.identitySessions.filter((id) => id !== outcome.sessionId);
    draft.apply({ type: "factor_recorded", factor });
    draft.emit("verification.factor", "system", { kind: factor.kind, passed: factor.passed, status: outcome.status });
    return { applied: true, callId };
  });
}

/** Computes the level from the recorded factors (only the step's, in a flow) and issues the grant. */
export async function finishVerification(rt: EngineRuntime, callId: string): Promise<VerificationResult> {
  const ttlMs = (rt.settings<BadgeSettings>(BADGE).grantTtlSeconds ?? 900) * 1000;
  return rt.update(callId, (draft) => {
    const step = stepOfType<BadgeVerifyStep>(draft.record, "badge.verify");
    const s = draft.slice<BadgeSlice>(BADGE);
    const factors = draft.record.state.factors.filter((f) => step === null || step.factors.includes(f.kind));
    const result = evaluateAssurance(rt.policy, factors, s.carrier);
    const scopes = scopesForLevel(rt.policy, result.level).filter((scope) => step?.scopes === undefined || step.scopes.includes(scope));
    const issuedAt = rt.clock.now();
    const grant =
      result.level === 0
        ? null
        : {
            grantId: rt.ids.next("grant"),
            level: result.level,
            scopes,
            issuedAt: issuedAt.toISOString(),
            expiresAt: new Date(issuedAt.getTime() + ttlMs).toISOString(),
          };
    draft.apply({ type: "verification_finished", level: result.level, grant });
    s.finished++;
    s.lastLevel = result.level;
    s.lastMethods = result.counted;
    draft.emit("verification.finished", "code", { level: result.level, methods: result.counted, discounted: result.discounted.map((d) => d.kind) });
    if (grant !== null) draft.emit("grant.issued", "code", { grantId: grant.grantId, level: grant.level, scopes, expiresAt: grant.expiresAt });
    return { level: result.level, scopes: grant === null ? [] : scopes };
  });
}

function identityText(locale: Locale, url: string): string {
  return locale === "fr" ? `Votre lien de vérification d'identité, à usage unique : ${url}` : `Your one-time identity check link: ${url}`;
}
