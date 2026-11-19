// Badge (verify): who is calling, in levels. The factors are plug-ins (factors.ts); a flow's
// `badge.verify` step names the level it needs and the factors that may count toward it.
//
// Every runtime function takes the engine's runtime and works in compare-and-set steps: an attempt
// is counted in one write before it is judged, and a link is reserved in one write before it is
// sent, so two processes running the same call can never get two attempts or two links for one.
import type { AttemptCounterKey, SubjectRecord } from "../core/adapters.ts";
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import { isStepLevel } from "../core/config.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import {
  FACTOR_KINDS,
  capCallLevel,
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
  snapshotFactorPlugin,
  judgeKeypad,
  judgePin,
  judgeSpoken,
  type BadgeSettings,
  type FactorEntry,
  type FactorPlugin,
  type PinOutcome,
  type PinSettings,
} from "./factors.ts";
import { counterKeys, currentLock, isCallingNumber, lockoutOf, lockoutSettingsErrors, forgetPass, recordFailures, removeOwnOnNumbers, type Lock } from "./counters.ts";
import { clearsSoFar, duressClearedData, duressFlagKey, flagDuress, hiddenCounterKey, hiddenHardLock, hiddenWindowStart, isUnderDuress, recordClear } from "./duress-flag.ts";
import { isKeypadEntry } from "./knowledge.ts";
import type { TextCodeState } from "./text-code.ts";

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
  /** The keyed hash of the calling number the host gave, for the counters and the send limits across calls; null without one. */
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
  /** Goes up on every beginVerification and every taint, so a result judged before either is never applied. */
  epoch: number;
  /** Identity sessions whose outcome may still count. */
  identitySessions: string[];
  /** The texted code this call holds: null before any send, and after a taint or a change of subject. */
  textCode: TextCodeState | null;
  /**
   * The texted code sends whose ledger entries are not written yet (VER-2), one hold per send: the
   * call does not end while any is held, each until its own entry is written or its `until` passes,
   * so no send's entry follows the receipt. Absent until the first send.
   */
  textSends?: Array<{ sendId: string; until: string }>;
  /** How many verifications finished on this call, and the last one's level and counted methods. */
  finished: number;
  lastLevel: AssuranceLevel;
  lastMethods: FactorKind[];
  /** The policy version and config revision that judged the last one; null until one finished. */
  lastJudgedBy: JudgedBy | null;
  /**
   * The epoch of the verification a taint landed in (Sean, 2026-11-19): that verification grants no
   * level, whatever matched before or after the taint, and the caller must start a new one, which
   * bumps the epoch. Absent on a call never tainted, and on a call stored before the rule.
   */
  voidedEpoch?: number;
  /**
   * An accepted pass whose counters are not yet cleaned up (`forgetPass`): saved with the pass, so a
   * write that fails after the pass was saved (its ledger entry) still gets the cleanup, in the same
   * call to `submitFactor` or the call's next. Absent when nothing is owed. `hidden` is the duress
   * PIN's hidden counter (VER-12), when it is on: a pass not under duress resets it, a duress entry
   * takes off only its own failure. Absent on a pass saved before it was kept here. `claimed` is set
   * on the call before the removals that are not safe to run twice (the number's own failure, the
   * hidden counter's) run, so a replay skips them.
   */
  forgetOwed?: { keys: AttemptCounterKey[]; at: string; hidden?: { key: AttemptCounterKey; duress: boolean; shared?: AttemptCounterKey }; claimed?: true };
  /** The callback this call asked for, or the one it is (callback.ts). Absent on calls saved before: read it with `callbackOf`. */
  callback: CallbackState;
  /** Untrusted content seen on this call so far (onUntrusted counts it), so an entry judged across one is known. Absent on calls saved before. */
  taints?: number;
}

/** Which policy and which FlowConfig revision judged a verification. */
export interface JudgedBy {
  policyVersion: string;
  configRevision: string;
}

/** A call's part in a callback (VER-9). One per call. */
export interface CallbackState {
  /**
   * On the call that asks: `none`, `requested` while it is decided, then `placed` or `refused`.
   * On the callback call: `dialing`, `dialed` once the dialer's reference is kept, then `passed` or
   * `failed`; `void` if untrusted content entered it or its subject changed before the outcome.
   */
  status: "none" | "requested" | "placed" | "refused" | "dialing" | "dialed" | "passed" | "failed" | "void";
  /** The other call: the callback call, on the call that asked; the call that asked, on the callback call. */
  callId: string | null;
  /** The dialer's reference, on the callback call. */
  ref: string | null;
  /** The counters a failed callback stays counted under, and a pass forgets. */
  keys: AttemptCounterKey[];
  /** The hard lock this callback's failure starts, written to the ledger if it fails. */
  lock: Lock | null;
  /** The subject the callback is for, kept from the request, so a restart for another subject cannot take it over. */
  subjectKey: string | null;
  subject: SubjectRecord | null;
  /** On the call that asks: its verification (`BadgeSlice.epoch`) when it asked. */
  epoch: number | null;
  /** ISO 8601. When the callback is counted, toward the daily limit and as a failure. A resumed request counts at the same time, and a pass forgets that failure. */
  at: string | null;
  /** On a passed callback call: its failure is still to be forgotten. A replayed outcome retries that. */
  forgetPending: boolean;
  /**
   * Set on the call before the pass's own failure comes off the calling number, which runs at most
   * once (a replay could take off another failure of the same millisecond). Absent until then, and
   * on calls saved before it.
   */
  forgetClaimed?: true;
  /** On the callback call: the number the dial goes to, kept in the write that claims the dial, and the one the carrier check asks about. */
  to?: string;
  /** On the callback call: how often the number on file changed between tries of the dial. Each number gets its own idempotency key. */
  redials?: number;
  /** On the callback call: ISO 8601, when a dial resumed a day or more after `at` was counted toward the daily limit again. */
  countedAt?: string;
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


/** The keypad timeouts of one call, for the host's `KeypadCollector` (VER-11). */
export interface KeypadTiming {
  idleTimeoutMs: number;
  maxIdleTimeoutMs: number;
}

/** How long a caller may pause between tones before the buffer is dropped, by default (VER-11). */
export const DEFAULT_KEYPAD_IDLE_SECONDS = 10;

const SETTINGS_KEYS = ["factors", "grantTtlSeconds", "pin", "lockout", "accessibility"];
const ACCESSIBILITY_KEYS = ["spokenKeypadFields", "keypadIdleSeconds", "maxKeypadIdleSeconds"];
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

/**
 * Badge never changes once built: a factor added later (`withFactor`) or supplied by an outside
 * module (`withOutsideFactors`) gives a new Badge, which the engine swaps into its registry. So a
 * Badge shared by several engines never gains a factor through one of them.
 */
export class BadgeModule implements AssuranceModule {
  readonly manifest: AssuranceModule["manifest"];
  /** The host's plug-ins: Badge provides them, in its manifest. */
  readonly #plugins = new Map<string, FactorPlugin>();
  /** The judges outside modules supply: those modules provide the factors (and the registry checked them); Badge runs them. */
  readonly #outside = new Map<string, FactorPlugin>();

  constructor(plugins: readonly FactorPlugin[], outside: readonly FactorPlugin[] = []) {
    const errors: string[] = [];
    for (const given of plugins) {
      // Read once: the copy that passes the checks is the one Badge keeps and runs.
      const plugin = snapshotFactorPlugin(given);
      const problems = checkFactorPlugin(plugin, [...FACTOR_KINDS, ...this.#plugins.keys()]);
      errors.push(...problems);
      if (problems.length === 0) this.#plugins.set(plugin.kind, plugin);
    }
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    for (const plugin of outside) this.#outside.set(plugin.kind, plugin);
    this.manifest = {
      name: BADGE,
      version: "1",
      summary: "Verify the caller to an assurance level with the factors the flow allows.",
      provides: { factors: [...FACTOR_KINDS, ...this.#plugins.keys()], steps: ["badge.verify"], outcomes: ["grant"] },
      scopes: { grants: ["*"], needs: {} },
      adapters: ["records"],
    };
  }

  /** This Badge with one more plug-in of the host's. Refuses a bad plug-in or a kind Badge already has. */
  withFactor(plugin: FactorPlugin): BadgeModule {
    return new BadgeModule([...this.#plugins.values(), plugin], [...this.#outside.values()]);
  }

  /** This Badge running the judges the installed outside modules supply (all of them, replacing the last set). */
  withOutsideFactors(outside: readonly FactorPlugin[]): BadgeModule {
    return new BadgeModule([...this.#plugins.values()], outside);
  }

  plugin(kind: string): FactorPlugin | undefined {
    return this.#plugins.get(kind) ?? this.#outside.get(kind);
  }

  /** Every factor kind Badge judges, on or off: its own, the host's plug-ins and the outside modules' judges. */
  installedFactors(): string[] {
    return [...this.manifest.provides.factors, ...this.#outside.keys()];
  }

  validateSettings(settings: unknown): string[] {
    if (!isObject(settings)) return ["must be an object with the factors that are on"];
    const errors = unknownKeys(settings, SETTINGS_KEYS).map((k) => `${k} is not a badge setting`);
    const known = this.installedFactors();
    if (!isStringArray(settings.factors) || settings.factors.length === 0) {
      errors.push("factors must list at least one factor");
    } else {
      if (new Set(settings.factors).size !== settings.factors.length) errors.push("factors has duplicates");
      for (const kind of settings.factors) {
        // No built-in factor is planned any more (VER-2 and VER-3 are built), so none is refused as unbuilt.
        if (!known.includes(kind)) errors.push(`factor ${kind} is not installed`);
      }
      if (settings.factors.includes("pin")) errors.push(...pinSettingsErrors(settings.pin));
    }
    if (settings.grantTtlSeconds !== undefined && !isIntegerIn(settings.grantTtlSeconds, 1, 3600)) {
      errors.push("grantTtlSeconds must be an integer from 1 to 3600");
    }
    if (settings.accessibility !== undefined) errors.push(...accessibilityErrors(settings.accessibility, settings.factors));
    errors.push(...lockoutSettingsErrors(settings.lockout));
    return errors;
  }

  requiredAdapters(settings: unknown): string[] {
    const s = settings as BadgeSettings;
    const adapters = new Set<string>(this.manifest.adapters);
    for (const kind of s.factors) {
      const builtIn = BUILT_IN_FACTORS[kind as keyof typeof BUILT_IN_FACTORS];
      for (const a of builtIn?.adapters ?? this.plugin(kind)!.adapters) adapters.add(a);
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
      if (ctx.policy !== null && step.factors.includes("spoken_knowledge")) {
        const keypadFields = ctx.policy.keypadFields;
        for (const field of settings.accessibility?.spokenKeypadFields ?? []) {
          if (!keypadFields.includes(field)) errors.push(`spoken keypad field ${field} is not one of the policy's keypad fields`);
        }
      }
    }
    if (ctx.policy !== null && isStepLevel(step.level)) {
      const factors = step.factors;
      const level = step.level;
      const reachable = ctx.policy.levels.some((rule) => rule.level >= level && rule.anyOf.some((set) => set.every((k) => factors.includes(k))));
      if (!reachable) errors.push(`level ${level} cannot be reached with [${factors.join(", ")}] under the policy`);
      if (factors.includes("text_code") && ctx.policy.textCodeCountryCodes === undefined) {
        errors.push("factor text_code needs the policy's textCodeCountryCodes, or no code is ever texted");
      }
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
      textCode: null,
      finished: 0,
      lastLevel: 0,
      lastMethods: [],
      lastJudgedBy: null,
      callback: noCallback(),
      taints: 0,
    };
    return initial as unknown as JsonValue;
  }

  enterStep(_step: FlowStep, s: JsonValue): JsonValue {
    return (s as unknown as BadgeSlice).finished;
  }

  blocksEnd(s: JsonValue, now: Date): string | null {
    const held = ((s as unknown as BadgeSlice).textSends ?? []).some((send) => now.getTime() < Date.parse(send.until));
    return held ? "a texted code is still being sent; end the call once it is sent" : null;
  }

  stepStatus(step: FlowStep, view: StepView): StepStatus {
    const s = view.slice as unknown as BadgeSlice;
    if (s.finished <= (view.mark as number)) return "pending";
    return s.lastLevel >= (step.level as number) ? "complete" : "failed";
  }

  onUntrusted(s: JsonValue): JsonValue {
    // A photo ID link or a texted code sent before the taint no longer counts, nor does a callback
    // still ringing, nor the keypad or PIN match made before it (it unlocks nothing until a fresh
    // verification matches). One link per call still holds. The epoch moves on too, so a result or a send
    // decided before the taint is not applied after it, and the verification open now (or the last
    // one) is void: it never grants a level. The next beginVerification moves it on again, so a new
    // verification counts as usual.
    const badge = s as unknown as BadgeSlice;
    return { ...badge, epoch: badge.epoch + 1, knowledgeMatched: false, identitySessions: [], identityLink: voided(badge.identityLink), textCode: null, callback: voidedCallback(callbackOf(badge)), voidedEpoch: badge.epoch + 1, taints: (badge.taints ?? 0) + 1 } as unknown as JsonValue;
  }

  receiptPart(s: JsonValue, state: SessionState): { [key: string]: JsonValue } {
    const badge = s as unknown as BadgeSlice;
    // No verification finished (or the record predates `lastJudgedBy`): the receipt names neither
    // field. Only the two fields are taken, after level and methods are set, so nothing stored
    // beside them can change what the receipt says about the verification.
    // Each field only when the store holds it as text: a damaged record that lacks one (or holds
    // something else) drops that field, never an undefined the receipt could not be signed with.
    const judged: unknown = badge.lastJudgedBy;
    const by: { policyVersion?: string; configRevision?: string } = {};
    if (isObject(judged)) {
      if (typeof judged.policyVersion === "string") by.policyVersion = judged.policyVersion;
      if (typeof judged.configRevision === "string") by.configRevision = judged.configRevision;
    }
    return { verification: { ...by, level: state.level, methods: state.level === 0 ? [] : badge.lastMethods } };
  }
}

/** A link not yet delivered can no longer count: it is void. One delivered stays delivered (and stops any other). */
function voided(link: BadgeSlice["identityLink"]): BadgeSlice["identityLink"] {
  return link === "reserved" || link === "sent" ? "void" : link;
}

/** The callback state of a call that asked for none. */
function noCallback(): CallbackState {
  return { status: "none", callId: null, ref: null, keys: [], lock: null, subjectKey: null, subject: null, epoch: null, at: null, forgetPending: false };
}

/** A call's callback state. A slice stored before `callback` existed has none: it reads as a call that asked for none. */
export function callbackOf(s: BadgeSlice): CallbackState {
  return (s as { callback?: CallbackState }).callback ?? noCallback();
}

/** A callback whose outcome has not arrived, or whose request is still being decided, can no longer count: it is void. */
function voidedCallback(callback: CallbackState): CallbackState {
  return callback.status === "requested" || callback.status === "dialing" || callback.status === "dialed" ? { ...callback, status: "void" } : callback;
}

/** Refuses to apply a result judged for an earlier verification of this call. */
export function assertSameVerification(s: BadgeSlice, epoch: number): void {
  if (s.epoch !== epoch) throw new EngineError("precondition_failed", "verification restarted while this result was on its way; it does not count");
}

function accessibilityErrors(a: unknown, factors: unknown): string[] {
  if (!isObject(a)) return ["accessibility must be an object"];
  const errors = unknownKeys(a, ACCESSIBILITY_KEYS).map((k) => `accessibility.${k} is not an accessibility setting`);
  if (a.spokenKeypadFields !== undefined) {
    const fields = a.spokenKeypadFields;
    if (!isStringArray(fields) || fields.length === 0) {
      errors.push("accessibility.spokenKeypadFields must list at least one keypad field");
    } else {
      if (new Set(fields).size !== fields.length) errors.push("accessibility.spokenKeypadFields has duplicates");
      // A spoken PIN reaches speech-to-text, so the PIN is only ever keyed.
      if (fields.includes("pin")) errors.push("accessibility.spokenKeypadFields cannot hold the PIN: a PIN is never taken by speech");
      if (!isStringArray(factors) || !factors.includes("spoken_knowledge")) errors.push("accessibility.spokenKeypadFields needs the spoken_knowledge factor on");
    }
  }
  const idle = a.keypadIdleSeconds ?? DEFAULT_KEYPAD_IDLE_SECONDS;
  if (!isIntegerIn(idle, 5, 60)) errors.push("accessibility.keypadIdleSeconds must be an integer from 5 to 60");
  else if (a.maxKeypadIdleSeconds !== undefined && !isIntegerIn(a.maxKeypadIdleSeconds, idle, 300)) {
    errors.push("accessibility.maxKeypadIdleSeconds must be an integer from keypadIdleSeconds to 300");
  }
  return errors;
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
export function allowFactor(rt: EngineRuntime, record: CallRecord, kind: string): void {
  const settings = rt.settings<BadgeSettings>(BADGE);
  if (!settings.factors.includes(kind)) throw new EngineError("precondition_failed", `the ${kind} factor is turned off`);
  const step = stepOfType<BadgeVerifyStep>(record, "badge.verify");
  if (step !== null && !step.factors.includes(kind)) throw new EngineError("precondition_failed", `the flow step does not use the ${kind} factor`);
}

function maxAttempts(rt: EngineRuntime, module: BadgeModule, kind: string): number {
  if (kind === "keypad_knowledge") return rt.policy.maxKeypadAttemptsPerCall;
  if (kind === "pin") return rt.settings<BadgeSettings>(BADGE).pin!.maxAttemptsPerCall;
  // A policy without spoken fields gives no attempts, so a spoken answer is never judged against nothing.
  if (kind === "spoken_knowledge") return rt.policy.spoken?.maxAttemptsPerCall ?? 0;
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
  // Read once: the key or account number checked is the one used, and the ledger names its source.
  const byHost = "subjectKey" in input;
  const given: unknown = byHost ? input.subjectKey : (input as { accountNumber: string }).accountNumber;
  let subjectKey: string | null;
  if (byHost) {
    // A string only: a regex test turns an array into its text, which would pass, be found by the
    // record store as the subject, and then key no counter, so the PIN could be guessed without a lock.
    if (typeof given !== "string" || !/^[0-9a-f]{64}$/.test(given)) throw new EngineError("invalid_input", "subjectKey must be 64 lower-case hex characters");
    subjectKey = given;
  } else {
    subjectKey = typeof given === "string" && isKeypadEntry(given) ? await rt.hmac(`subject:${given}`) : null;
  }
  const number = input.callingNumber;
  if (number !== undefined && !isCallingNumber(number)) throw new EngineError("invalid_input", "callingNumber must be E.164; leave it out when the number is withheld");
  const numberKey = number === undefined ? null : await rt.hmac(`number:${number}`);
  const onFile = subjectKey === null ? null : await rt.adapter("records").getSubject(rt.workspaceId, subjectKey);
  // The call keeps no copy of the PIN digest: the PIN is judged against the store on every attempt,
  // so a digest erased or reset since verification began never counts, and no call record holds it.
  const subject = onFile === null ? null : structuredClone(onFile);
  // Nor of the duress PIN digest (VER-12), judged against the store the same way: an erase removes both.
  if (subject !== null) {
    delete subject.pinDigest;
    delete subject.duressDigest;
  }
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
      s.callback = voidedCallback(callbackOf(s));
      s.textCode = null;
    }
    if (draft.record.state.factors.length === 0) {
      s.knowledgeMatched = false;
      s.carrier = null;
    }
    s.subjectKey = subjectKey;
    s.subject = subject;
    if (numberKey !== null) s.numberKey = numberKey;
    draft.emit("verification.started", "code", { subject: byHost ? "host" : "account" });
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
 * A judge that throws records no factor and does not refund the attempt.
 */
export async function submitFactor(rt: EngineRuntime, module: BadgeModule, callId: string, kind: string, entry: FactorEntry): Promise<KeypadResult> {
  const builtIn = BUILT_IN_FACTORS[kind as keyof typeof BUILT_IN_FACTORS];
  const plugin = module.plugin(kind);
  if (builtIn?.entered !== true && plugin === undefined) throw new EngineError("invalid_input", `${kind} is not a factor the caller enters`);
  // A spoken PIN has already reached speech-to-text. It is refused before it is counted or judged (VER-11).
  if (kind === "spoken_knowledge" && isObject(entry) && Object.hasOwn(entry, "pin")) {
    throw new EngineError("invalid_input", "a PIN is never taken by speech: it is keyed, with submitPin");
  }
  const before = await rt.read(callId);
  allowFactor(rt, before, kind);
  const current = before.modules[BADGE] as unknown as BadgeSlice | undefined;
  if (current === undefined) throw new EngineError("module_disabled", `${BADGE} was off when this call started`);
  const counters = rt.adapter("counters");
  // A pass this call saved earlier whose cleanup did not run (its write failed after saving it).
  if (current.forgetOwed !== undefined) await settleForget(rt, callId, current.forgetOwed.at);
  const lockout = lockoutOf(rt.settings<BadgeSettings>(BADGE).lockout);
  // A spoken answer that carries keypad fields (VER-11) is a guess at those fields too: it also
  // uses a keypad_knowledge attempt, so the keypad and the voice share one budget per call, and
  // across calls it is counted, locked and forgiven under both factors, so alternating keyed and
  // spoken entries never doubles the guesses before a lock.
  // Read once, for both the budget and the judging: a config changed while this attempt waits
  // never has it judge a keypad field it was not charged for.
  const spokenFields = kind === "spoken_knowledge" ? spokenKeypadFields(rt) : [];
  const shared = spokenFields.length > 0;
  const keys = shared
    ? [...counterKeys(rt.workspaceId, kind, current), ...counterKeys(rt.workspaceId, "keypad_knowledge", current)]
    : counterKeys(rt.workspaceId, kind, current);
  const settings = rt.settings<BadgeSettings>(BADGE);
  // With the duress PIN on, a subject's failures are also counted where a duress entry never
  // resets them, and the hard lock they reach holds (duress-flag.ts).
  const duressOn = settings.pin?.duress !== undefined;
  const hidden = duressOn && current.subjectKey !== null ? hiddenCounterKey(rt.workspaceId, kind, current.subjectKey) : null;
  // A shared spoken answer is a keypad guess under the hidden counter too: held by its hard lock,
  // and a failure counted there, as on the visible counters.
  const hiddenKeypad = hidden !== null && shared ? hiddenCounterKey(rt.workspaceId, "keypad_knowledge", current.subjectKey!) : null;
  // The flag is read for every subject, the duress PIN on or off: a subject flagged while it was on
  // stays under duress after a config turns it off, until the business clears it.
  const flag = current.subjectKey !== null ? duressFlagKey(rt.workspaceId, current.subjectKey) : null;
  // No await for a key that is not there: the round trips stay those of an attempt without it.
  const lock =
    (await currentLock(counters, lockout, keys, rt.clock.now())) ??
    (hidden === null ? null : hiddenHardLock(lockout, await counters.get(hidden, hiddenWindowStart(lockout, rt.clock.now())), rt.clock.now())) ??
    (hiddenKeypad === null ? null : hiddenHardLock(lockout, await counters.get(hiddenKeypad, hiddenWindowStart(lockout, rt.clock.now())), rt.clock.now()));
  if (lock !== null) return refuseLocked(rt, callId, kind, current.epoch, lock);
  const reserved = await rt.update(callId, (draft) => {
    const s = assertAttempt(rt, draft, kind, current.epoch);
    const max = maxAttempts(rt, module, kind);
    // Own keys only: an inherited one (`constructor`) must never stand in for a count.
    const used = Object.hasOwn(s.attempts, kind) ? s.attempts[kind]! : 0;
    const keypadMax = rt.policy.maxKeypadAttemptsPerCall;
    const keypadUsed = Object.hasOwn(s.attempts, "keypad_knowledge") ? s.attempts.keypad_knowledge! : 0;
    if (used >= max || (shared && keypadUsed >= keypadMax)) return null;
    s.attempts[kind] = used + 1;
    if (shared) s.attempts.keypad_knowledge = keypadUsed + 1;
    const last = used + 1 >= max || (shared && keypadUsed + 1 >= keypadMax);
    return { subjectKey: s.subjectKey, subject: s.subject, last, epoch: s.epoch, locale: draft.record.locale, taints: s.taints, shared };
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
      if (reserved.shared) s.attempts.keypad_knowledge = Math.max(0, s.attempts.keypad_knowledge! - 1);
    });
    return refuseLocked(rt, callId, kind, reserved.epoch, recorded.raced);
  }
  const hiddenAfter = hidden === null ? null : await counters.recordFailure(hidden, at.toISOString(), hiddenWindowStart(lockout, at));
  const keypadAfter = hiddenKeypad === null ? null : await counters.recordFailure(hiddenKeypad, at.toISOString(), hiddenWindowStart(lockout, at));
  const input = { workspaceId: rt.workspaceId, subjectKey: reserved.subjectKey, subject: reserved.subject, entry, hmac: (d: string) => rt.hmac(d), locale: reserved.locale };
  let outcome: PinOutcome;
  try {
    if (kind === "pin") outcome = await judgePin(rt, settings.pin as PinSettings, input);
    else {
      const passed =
        kind === "keypad_knowledge"
          ? await judgeKeypad(rt.policy, input)
          : kind === "spoken_knowledge"
            ? await judgeSpoken(rt.policy.spoken!, input, spokenFields)
            : (await plugin!.judge(input)) === true;
      outcome = passed ? "pass" : "fail";
    }
  } catch (error) {
    // A key store, PIN verifier or plug-in that throws is not a wrong answer: no factor is recorded
    // and the error reaches the host. The attempt stays counted, so an entry crafted to make a judge
    // throw never gives a free try. The ledger notes the failure, as the success path would, only on
    // the same verification of a call still open; a note refused or failed never hides the error.
    await rt
      .update(callId, (draft) => {
        assertSameVerification(draft.slice<BadgeSlice>(BADGE), reserved.epoch);
        draft.assertCan({ type: "factor_recorded", factor: { kind, passed: false, at: rt.now() } });
        draft.emit("verification.factor_error", "code", { kind });
      })
      .catch(() => undefined);
    throw error;
  }
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
  const hard =
    passed ? null : (recorded.hard ?? (hiddenAfter === null ? null : hiddenHardLock(lockout, hiddenAfter, at)) ?? (keypadAfter === null ? null : hiddenHardLock(lockout, keypadAfter, at)));
  let stale: EngineError | null = null;
  let failed: { error: unknown } | null = null;
  try {
    stale = await rt.update(callId, (draft) => {
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
      // Untrusted content that entered the call while this entry was judged (any taint, the first or
      // a later one): a pass from before it neither counts toward a grant nor restores the match. The
      // attempt stays used, so this is no free guess; a failure is recorded as any failure is.
      if (passed && s.taints !== reserved.taints) return new EngineError("precondition_failed", "untrusted content entered the call while this entry was judged, so it does not count; verify again");
      // Otherwise the result is applied only to the verification it was judged for, as for any factor;
      // a stale one is refused with the same error either way, after the write.
      if (s.epoch !== reserved.epoch) return new EngineError("precondition_failed", "verification restarted while this result was on its way; it does not count");
      if (!canApply(draft.record.state, { type: "factor_recorded", factor })) return new EngineError("invalid_transition", `factor_recorded is not allowed while ${draft.record.state.phase}`);
      draft.apply({ type: "factor_recorded", factor });
      if (passed && KNOWLEDGE_FACTORS.includes(kind)) s.knowledgeMatched = true;
      // The cleanup is owed with the pass, in the same write: never for a pass that was not saved.
      if (passed) {
        s.forgetOwed = { keys: structuredClone(keys), at: at.toISOString() };
        if (hidden !== null) {
          s.forgetOwed.hidden = { key: structuredClone(hidden), duress: outcome === "duress" };
          if (hiddenKeypad !== null) s.forgetOwed.hidden.shared = structuredClone(hiddenKeypad);
        }
      }
      draft.emit("verification.factor", "code", { kind, passed }, kind === "pin" ? outcome : undefined);
      if (hard !== null) draft.emit("verification.locked", "code", { kind, scope: hard.scope, hard: true, until: hard.until });
      return null;
    });
  } catch (error) {
    // The entry could not be saved, or was saved and its ledger append failed: a duress PIN entry
    // still flags its subject below, and the subject's next pass alerts.
    failed = { error };
  }
  // A duress PIN entry flags its subject, even a stale one: durable and hidden, before the visible reset.
  if (pinDuress) await flagDuress(counters, flag!, at);
  // A stale entry's failure stays counted across calls, as for any entry that was not accepted.
  if (stale !== null) throw stale;
  // Only once the result is saved: a write that failed after saving it (the ledger) still owes the
  // cleanup, a pass refused before saving owes none. The number keeps its failures but this
  // attempt's own: they may be against other accounts, so a pass on this one must not clear them.
  if (passed) await settleForget(rt, callId, at.toISOString());
  if (failed !== null) throw failed.error;
  return { matched: passed, locked: !passed && (reserved.last || hard !== null) };
}

/**
 * Runs the counters cleanup a saved pass owes, if the call still owes the one made at `at`, then
 * takes it off the call; a failure to take it off leaves it owed for the call's next factor. The
 * subject's part is safe to run again. The rest is not (a removal by time can take another
 * failure of the same millisecond, a reset a later failure), so it is claimed on the call first
 * and runs at most once: a claim that is not saved runs none of it, and one that is saved and
 * then fails leaves those failures until they leave the window (fail closed).
 */
async function settleForget(rt: EngineRuntime, callId: string, at: string): Promise<void> {
  const owed = (await rt.read(callId)).modules[BADGE] as unknown as BadgeSlice;
  if (owed.forgetOwed?.at !== at) return;
  const counters = rt.adapter("counters");
  const { keys, hidden } = owed.forgetOwed;
  await forgetPass(counters, keys, new Date(at));
  if (owed.forgetOwed.claimed !== true) {
    // Not claimed (or claimed by another run first): this run leaves the rest to the run that holds it, or the next.
    const take = (s: BadgeSlice): boolean => {
      if (s.forgetOwed?.at !== at || s.forgetOwed.claimed === true) return false;
      s.forgetOwed.claimed = true;
      return true;
    };
    if (!(await claimOnCall(rt, callId, take, (s) => s.forgetOwed?.at === at && s.forgetOwed.claimed === true))) return;
    await removeOwnOnNumbers(counters, keys, new Date(at));
    // The hidden counter forgets only on a pass that is not under duress; a duress entry takes off its
    // own failure, as a pass does, and keeps the rest. One write either way, so the round trips never
    // tell a duress pass from another.
    for (const key of hidden === undefined ? [] : [hidden.key, ...(hidden.shared === undefined ? [] : [hidden.shared])]) {
      if (hidden!.duress) await counters.removeFailure(key, at);
      else await counters.reset(key);
    }
  }
  await rt
    .update(callId, (draft) => {
      const s = draft.slice<BadgeSlice>(BADGE);
      if (s.forgetOwed?.at === at) delete s.forgetOwed;
    })
    .catch(() => undefined);
}

/**
 * Claims a step of a cleanup on the call, so it runs at most once: true when this run's write saved
 * the claim. `take` sets the claim on the slice and says whether it took it (false: not owed, or
 * claimed already); `held` says whether the call holds it. A write that saved and then failed (the
 * ledger, appended after the save) still claimed it, which the call says; one that did not save did not.
 */
export async function claimOnCall(rt: EngineRuntime, callId: string, take: (s: BadgeSlice) => boolean, held: (s: BadgeSlice) => boolean): Promise<boolean> {
  let mine = false;
  try {
    return await rt.update(callId, (draft) => (mine = take(draft.slice<BadgeSlice>(BADGE))));
  } catch {
    if (!mine) return false;
    return held((await rt.read(callId)).modules[BADGE] as unknown as BadgeSlice);
  }
}

/** An opaque member id: no "@" and no space, so no email address or name reaches the ledger. */
const MEMBER_ID = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * The business lifts a subject's duress flag (VER-12): a host call from its own tools, never on a
 * caller's request, once it knows the subject is safe. `duress.cleared` goes to the ledger with the
 * member before the flag and the hidden counters are cleared, so no clearing goes unrecorded. Until
 * then every pass on the subject is a duress entry.
 */
export async function clearDuress(rt: EngineRuntime, module: BadgeModule, subjectKey: string, memberId: string): Promise<void> {
  rt.settings<BadgeSettings>(BADGE);
  const errors: string[] = [];
  if (typeof subjectKey !== "string" || !/^[0-9a-f]{64}$/.test(subjectKey)) errors.push("subjectKey must be 64 lower-case hex characters");
  if (typeof memberId !== "string" || !MEMBER_ID.test(memberId)) errors.push("memberId must be an opaque id: 1 to 64 of letters, digits, '.', '_', '-'");
  if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
  const counters = rt.adapter("counters");
  // The ledger never says who was under duress: the subject as a keyed digest only the business can
  // match (duressClearedSubject with its knowledge key), as enrolDuressPin writes nothing at all.
  await rt.adapter("ledger").append({ callId: null, actor: "member", event: "duress.cleared", at: rt.now(), detail: { subject: await rt.hmac(duressClearedData(subjectKey)), memberId } });
  // Counted before the flag goes, so an alert of an earlier entry, delivered later, never sets it again.
  await recordClear(counters, rt.workspaceId, subjectKey, rt.clock.now());
  await counters.reset(duressFlagKey(rt.workspaceId, subjectKey));
  // Every installed factor's hidden counter, outside modules' included, not only those on now: a
  // factor turned off while the subject is cleared keeps no hidden lock to hold when it is turned on again.
  for (const kind of module.installedFactors()) await counters.reset(hiddenCounterKey(rt.workspaceId, kind, subjectKey));
}

/**
 * The keypad fields Badge's settings let a caller say instead of key (VER-11). One spoken_knowledge
 * answer gives them with the policy's spoken fields; each is read as 1 to 32 digits and compared
 * like the keypad field it is.
 */
function spokenKeypadFields(rt: EngineRuntime): string[] {
  const keypadFields = rt.policy.keypadFields;
  const fields = rt.settings<BadgeSettings>(BADGE).accessibility?.spokenKeypadFields ?? [];
  // A field the policy does not key (a typo, "dobb") is refused, never dropped: dropped, the answer
  // would be judged without the keypad evidence or its shared attempt budget. A config with no flow
  // using spoken_knowledge is not checked against the policy when it is saved, so it is checked here.
  const unknown = fields.find((f) => !keypadFields.includes(f));
  if (unknown !== undefined) throw new EngineError("precondition_failed", `spoken keypad field ${unknown} is not one of the policy's keypad fields`);
  return fields;
}

/**
 * The keypad timeouts of a call, for the host's `KeypadCollector` (INT-1, VER-11): Badge's
 * `keypadIdleSeconds`, or its `maxKeypadIdleSeconds` on a call marked relay or TTY, and that maximum
 * as the limit `lengthenIdleTimeout` may reach. Timeouts only: the mark changes no step, factor or attempt.
 */
export async function keypadTiming(rt: EngineRuntime, callId: string): Promise<KeypadTiming> {
  const a = rt.settings<BadgeSettings>(BADGE).accessibility;
  const idle = a?.keypadIdleSeconds ?? DEFAULT_KEYPAD_IDLE_SECONDS;
  const max = a?.maxKeypadIdleSeconds ?? idle;
  const record = await rt.read(callId);
  return { idleTimeoutMs: (record.access === undefined ? idle : max) * 1000, maxIdleTimeoutMs: max * 1000 };
}

/** Asks the carrier about the number on file, never the calling number. Only after a keypad or PIN match. */
export async function checkCarrier(rt: EngineRuntime, callId: string): Promise<{ textCodeTrusted: boolean }> {
  const before = await rt.read(callId);
  allowFactor(rt, before, "carrier_identity_match");
  const subject = matchedSubject(before);
  if (!canApply(before.state, { type: "factor_recorded", factor: { kind: "carrier_identity_match", passed: false, at: rt.now() } })) {
    throw new EngineError("invalid_transition", `the carrier is checked while verifying, not while ${before.state.phase}`);
  }
  const { epoch, callback } = before.modules[BADGE] as unknown as BadgeSlice;
  // On a callback call, the line the dial rang, which the business may have changed since the
  // subject was copied: never another line's evidence beside possession of this one.
  if (callback.status === "dialing") throw new EngineError("precondition_failed", "the carrier is checked on a callback call once it is dialed");
  const report = await rt.adapter("carrier").check({ phoneNumber: callback.to ?? subject.phoneOnFile });
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
    if (s.identityLink === "reserved") s.identityLink = "sent";
    // Every session whose link is about to be texted must be able to apply its outcome, even when
    // a resume long after a failed text gets a new session (the provider pruned the old key).
    if (!s.identitySessions.includes(check.sessionId)) s.identitySessions.push(check.sessionId);
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
const IDENTITY_STATUSES: readonly unknown[] = ["verified", "requires_input", "canceled"];

export async function applyIdentityOutcome(rt: EngineRuntime, outcome: IdentityOutcome): Promise<OutcomeResult> {
  // Read once: the session looked up is the one consumed, and the status that passed is the one ledgered.
  const { sessionId, status } = outcome;
  // The status goes into the ledger as it is: anything but the provider's three is refused first.
  if (!IDENTITY_STATUSES.includes(status)) throw new EngineError("invalid_input", "status must be verified, requires_input or canceled");
  const callId = await rt.resolveRef(`identity:${sessionId}`);
  if (callId === null) return { applied: false };
  return rt.update(callId, (draft): OutcomeResult => {
    const s = draft.slice<BadgeSlice>(BADGE);
    const factor = { kind: "photo_id", passed: status === "verified", at: rt.now() };
    const step = draft.step();
    // No flow at all, or a running flow on a step that uses photo ID. A flow that ended takes nothing more.
    const stepAllows = step === null ? draft.record.flow === null : step.type === "badge.verify" && (step.factors as string[]).includes("photo_id");
    if (!s.identitySessions.includes(sessionId) || !canApply(draft.record.state, { type: "factor_recorded", factor }) || !stepAllows) {
      return { applied: false };
    }
    s.identitySessions = s.identitySessions.filter((id) => id !== sessionId);
    draft.apply({ type: "factor_recorded", factor });
    draft.emit("verification.factor", "system", { kind: factor.kind, passed: factor.passed, status });
    return { applied: true, callId };
  });
}

/** Computes the level from the recorded factors (only the step's, in a flow) and issues the grant. */
export async function finishVerification(rt: EngineRuntime, callId: string): Promise<VerificationResult> {
  const ttlMs = (rt.settings<BadgeSettings>(BADGE).grantTtlSeconds ?? 900) * 1000;
  return rt.update(callId, (draft) => {
    const step = stepOfType<BadgeVerifyStep>(draft.record, "badge.verify");
    const s = draft.slice<BadgeSlice>(BADGE);
    // A taint landed in this verification: it fails, with no level (Sean, 2026-11-19).
    const voidedByTaint = s.voidedEpoch === s.epoch;
    const factors = voidedByTaint ? [] : draft.record.state.factors.filter((f) => step === null || step.factors.includes(f.kind));
    // The policy and revision in force now judge, read together inside this write.
    const policy = rt.policy;
    const judgedBy: JudgedBy = { policyVersion: policy.version, configRevision: rt.revision };
    const result = evaluateAssurance(policy, factors, s.carrier);
    // The call's caller ID attestation can only lower the level the factors reached, never raise it.
    // A call stored before VER-10 has no attestation, and reads as none; a callback call the engine
    // dialled is never capped (decision 10).
    const level = capCallLevel(policy, result.level, draft.record);
    const scopes = scopesForLevel(policy, level).filter((scope) => step?.scopes === undefined || step.scopes.includes(scope));
    const issuedAt = rt.clock.now();
    const grant =
      level === 0
        ? null
        : {
            grantId: rt.ids.next("grant"),
            level,
            scopes,
            ...judgedBy,
            issuedAt: issuedAt.toISOString(),
            expiresAt: new Date(issuedAt.getTime() + ttlMs).toISOString(),
          };
    draft.apply({ type: "verification_finished", level, grant });
    s.finished++;
    s.lastLevel = level;
    s.lastMethods = result.counted;
    s.lastJudgedBy = judgedBy;
    draft.emit("verification.finished", "code", {
      level,
      methods: result.counted,
      discounted: result.discounted.map((d) => d.kind),
      capped: level < result.level,
      ...judgedBy,
      ...(voidedByTaint ? { voidedByTaint: true } : {}),
    });
    if (grant !== null) draft.emit("grant.issued", "code", { grantId: grant.grantId, level: grant.level, scopes, expiresAt: grant.expiresAt, ...judgedBy });
    return { level, scopes: grant === null ? [] : scopes };
  });
}

/** The identity link text, in every supported locale (SPEC.md section 16). */
export const IDENTITY_TEXT: Record<Locale, (url: string) => string> = {
  en: (url) => `Your one-time identity check link: ${url}`,
  fr: (url) => `Votre lien de vérification d'identité, à usage unique : ${url}`,
  es: (url) => `Su enlace de verificación de identidad, de un solo uso: ${url}`,
};

function identityText(locale: Locale, url: string): string {
  return IDENTITY_TEXT[locale](url);
}
