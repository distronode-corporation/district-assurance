// Badge (verify): who is calling, in levels. The factors are plug-ins (factors.ts); a flow's
// `badge.verify` step names the level it needs and the factors that may count toward it.
//
// Every runtime function takes the engine's runtime and works in compare-and-set steps: an attempt
// is counted in one write before it is judged, and a link is reserved in one write before it is
// sent, so two processes running the same call can never get two attempts or two links for one.
import type { AttemptCounterKey, SubjectRecord } from "../core/adapters.ts";
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
  type PinSettings,
} from "./factors.ts";
import { counterKeys, currentLock, isCallingNumber, lockoutOf, lockoutSettingsErrors, forgetPass, recordFailures, type Lock } from "./counters.ts";
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
   * call to `submitFactor` or the call's next. Absent when nothing is owed.
   */
  forgetOwed?: { keys: AttemptCounterKey[]; at: string };
}

/** Which policy and which FlowConfig revision judged a verification. */
export interface JudgedBy {
  policyVersion: string;
  configRevision: string;
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
const PIN_KEYS = ["mode", "minDigits", "maxDigits", "maxAttemptsPerCall"];

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
      lastJudgedBy: null,
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
    // The verification open now (or the last one) is void: it never grants a level. The next
    // beginVerification bumps the epoch, so a new verification counts as usual.
    const badge = s as unknown as BadgeSlice;
    return { ...badge, identitySessions: [], identityLink: voided(badge.identityLink), voidedEpoch: badge.epoch } as unknown as JsonValue;
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
  return errors;
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
  const before = await rt.read(callId);
  allowFactor(rt, before, kind);
  const current = before.modules[BADGE] as unknown as BadgeSlice | undefined;
  if (current === undefined) throw new EngineError("module_disabled", `${BADGE} was off when this call started`);
  const counters = rt.adapter("counters");
  // A pass this call saved earlier whose cleanup did not run (its write failed after saving it).
  if (current.forgetOwed !== undefined) await settleForget(rt, callId, current.forgetOwed.at);
  const lockout = lockoutOf(rt.settings<BadgeSettings>(BADGE).lockout);
  const keys = counterKeys(rt.workspaceId, kind, current);
  const lock = await currentLock(counters, lockout, keys, rt.clock.now());
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
  const input = { workspaceId: rt.workspaceId, subjectKey: reserved.subjectKey, subject: reserved.subject, entry, hmac: (d: string) => rt.hmac(d) };
  let passed: boolean;
  try {
    passed =
      kind === "keypad_knowledge"
        ? await judgeKeypad(rt.policy, input)
        : kind === "pin"
          ? await judgePin(rt, rt.settings<BadgeSettings>(BADGE).pin as PinSettings, input)
          : (await plugin!.judge(input)) === true;
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
  const hard = passed ? null : recorded.hard;
  let failed: { error: unknown } | null = null;
  try {
    await rt.update(callId, (draft) => {
      const s = draft.slice<BadgeSlice>(BADGE);
      assertSameVerification(s, reserved.epoch);
      const factor = { kind, passed, at: rt.now() };
      draft.apply({ type: "factor_recorded", factor });
      if (passed && KNOWLEDGE_FACTORS.includes(kind)) s.knowledgeMatched = true;
      // The cleanup is owed with the pass, in the same write: never for a pass that was not saved.
      if (passed) s.forgetOwed = { keys: structuredClone(keys), at: at.toISOString() };
      draft.emit("verification.factor", "code", { kind, passed });
      if (hard !== null) draft.emit("verification.locked", "code", { kind, scope: hard.scope, hard: true, until: hard.until });
    });
  } catch (error) {
    failed = { error };
  }
  // Only once the result is saved: a write that failed after saving it (the ledger) still owes the
  // cleanup, a stale pass refused before saving owes none. The number keeps its failures but this
  // attempt's own: they may be against other accounts, so a pass on this one must not clear them.
  if (passed) await settleForget(rt, callId, at.toISOString());
  if (failed !== null) throw failed.error;
  return { matched: passed, locked: !passed && (reserved.last || hard !== null) };
}

/**
 * Runs the counters cleanup a saved pass owes, if the call still owes the one made at `at`, then
 * takes it off the call. The cleanup is idempotent, so running it again after a lost write is safe;
 * a failure to take it off leaves it owed for the call's next factor.
 */
async function settleForget(rt: EngineRuntime, callId: string, at: string): Promise<void> {
  const owed = (await rt.read(callId)).modules[BADGE] as unknown as BadgeSlice;
  if (owed.forgetOwed?.at !== at) return;
  await forgetPass(rt.adapter("counters"), owed.forgetOwed.keys, new Date(at));
  await rt
    .update(callId, (draft) => {
      const s = draft.slice<BadgeSlice>(BADGE);
      if (s.forgetOwed?.at === at) delete s.forgetOwed;
    })
    .catch(() => undefined);
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
    const scopes = scopesForLevel(policy, result.level).filter((scope) => step?.scopes === undefined || step.scopes.includes(scope));
    const issuedAt = rt.clock.now();
    const grant =
      result.level === 0
        ? null
        : {
            grantId: rt.ids.next("grant"),
            level: result.level,
            scopes,
            ...judgedBy,
            issuedAt: issuedAt.toISOString(),
            expiresAt: new Date(issuedAt.getTime() + ttlMs).toISOString(),
          };
    draft.apply({ type: "verification_finished", level: result.level, grant });
    s.finished++;
    s.lastLevel = result.level;
    s.lastMethods = result.counted;
    s.lastJudgedBy = judgedBy;
    draft.emit("verification.finished", "code", {
      level: result.level,
      methods: result.counted,
      discounted: result.discounted.map((d) => d.kind),
      ...judgedBy,
      ...(voidedByTaint ? { voidedByTaint: true } : {}),
    });
    if (grant !== null) draft.emit("grant.issued", "code", { grantId: grant.grantId, level: grant.level, scopes, expiresAt: grant.expiresAt, ...judgedBy });
    return { level: result.level, scopes: grant === null ? [] : scopes };
  });
}

/** The identity link text, in every supported locale (SPEC.md section 16). */
export const IDENTITY_TEXT: Record<Locale, (url: string) => string> = {
  en: (url) => `Your one-time identity check link: ${url}`,
  fr: (url) => `Votre lien de vérification d'identité, à usage unique : ${url}`,
};

function identityText(locale: Locale, url: string): string {
  return IDENTITY_TEXT[locale](url);
}
