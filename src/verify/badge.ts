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
  type VerificationPolicy,
} from "../core/policy.ts";
import type { CallRecord, EngineRuntime, Locale } from "../core/runtime.ts";
import { canApply, higherBand, type SessionState, type SyntheticVoiceBand } from "../core/session.ts";
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
  /**
   * The methods the receipt shows when a synthetic voice band holds the call below what its counted
   * methods reach (VER-14): only those that support the level shown, so a capped receipt reads like
   * an honestly lower one. Null (or absent) otherwise. The ledger keeps every counted method.
   */
  receiptMethods?: FactorKind[] | null;
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
 * One speech vendor's two thresholds, each from 0 to 1 (VER-14). Vendors' scores are not
 * comparable, so each vendor has its own. A score above `spokenKnowledgeAbove` stops
 * `spoken_knowledge` counting toward a level; above `levelOneAbove`, the call is held to level 1.
 */
export interface SyntheticVoiceThresholds {
  spokenKnowledgeAbove: number;
  levelOneAbove: number;
}

/** Badge's settings with the synthetic voice thresholds, by vendor name. No vendor listed: no score is taken. */
export type BadgeVoiceSettings = BadgeSettings & { syntheticVoice?: Record<string, SyntheticVoiceThresholds> };

const SETTINGS_KEYS = ["factors", "grantTtlSeconds", "pin", "syntheticVoice"];
const PIN_KEYS = ["mode", "minDigits", "maxDigits", "maxAttemptsPerCall"];
const THRESHOLD_KEYS = ["spokenKnowledgeAbove", "levelOneAbove"];
const VENDOR_NAME = /^[a-z][a-z0-9_-]{0,31}$/;

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
    if (settings.syntheticVoice !== undefined) errors.push(...syntheticVoiceErrors(settings.syntheticVoice));
    return errors;
  }

  requiredAdapters(settings: unknown): string[] {
    const s = settings as BadgeSettings;
    const adapters = new Set<string>(this.manifest.adapters);
    for (const kind of s.factors) {
      for (const a of BUILT_IN_FACTORS[kind as keyof typeof BUILT_IN_FACTORS]?.adapters ?? this.#plugins.get(kind)!.adapters) adapters.add(a);
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
    const slice = s as unknown as BadgeSlice;
    return { verification: { level: state.level, methods: state.level === 0 ? [] : (slice.receiptMethods ?? slice.lastMethods) } };
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

function syntheticVoiceErrors(vendors: unknown): string[] {
  if (!isObject(vendors)) return ["syntheticVoice must map each vendor's name to its thresholds"];
  const errors: string[] = [];
  for (const [vendor, thresholds] of Object.entries(vendors)) {
    const at = `syntheticVoice.${vendor}`;
    if (!VENDOR_NAME.test(vendor)) errors.push(`syntheticVoice vendor ${JSON.stringify(vendor)} must be 1 to 32 lower-case letters, digits, "-" or "_", starting with a letter`);
    if (!isObject(thresholds)) {
      errors.push(`${at} must be {spokenKnowledgeAbove, levelOneAbove}`);
      continue;
    }
    errors.push(...unknownKeys(thresholds, THRESHOLD_KEYS).map((k) => `${at}.${k} is not a threshold`));
    const bad = THRESHOLD_KEYS.filter((k) => !isScore(thresholds[k]));
    for (const k of bad) errors.push(`${at}.${k} must be a number from 0 to 1`);
    if (bad.length === 0 && (thresholds.levelOneAbove as number) < (thresholds.spokenKnowledgeAbove as number)) {
      errors.push(`${at}.levelOneAbove must not be below spokenKnowledgeAbove`);
    }
  }
  return errors;
}

/** A number from 0 to 1. NaN, infinities and strings are not. */
function isScore(value: unknown): value is number {
  return typeof value === "number" && value >= 0 && value <= 1;
}

/** A call's band. A call stored before VER-14 has none, and no score was reported on it: `clear`. */
function bandOf(state: SessionState): SyntheticVoiceBand {
  return state.syntheticVoice ?? "clear";
}

/** Whether a factor kind still counts toward a level under a call's synthetic voice band. */
function countsUnder(kind: string, band: SyntheticVoiceBand): boolean {
  return kind !== "spoken_knowledge" || band === "clear";
}

/**
 * The methods that support a level: those in a set of the policy, at that level or below, whose
 * every factor is among `methods`. A receipt held below its methods' level lists only these.
 */
function supportingMethods(policy: VerificationPolicy, methods: readonly FactorKind[], level: AssuranceLevel): FactorKind[] {
  const support = new Set<FactorKind>();
  for (const rule of policy.levels) {
    if (rule.level > level) continue;
    for (const set of rule.anyOf) if (set.every((kind) => methods.includes(kind))) for (const kind of set) support.add(kind);
  }
  return methods.filter((kind) => support.has(kind));
}

/** A level held to a band: at most 1 in `level_1`. */
function heldLevel(level: AssuranceLevel, band: SyntheticVoiceBand): AssuranceLevel {
  return band === "level_1" ? (Math.min(level, 1) as AssuranceLevel) : level;
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
 * of the line. Choosing the subject is not a factor: only factors raise the level.
 */
export async function beginVerification(rt: EngineRuntime, callId: string, input: { accountNumber: string } | { subjectKey: string }): Promise<void> {
  rt.settings(BADGE);
  let subjectKey: string | null;
  if ("subjectKey" in input) {
    if (!/^[0-9a-f]{64}$/.test(input.subjectKey)) throw new EngineError("invalid_input", "subjectKey must be 64 lower-case hex characters");
    subjectKey = input.subjectKey;
  } else {
    subjectKey = isKeypadEntry(input.accountNumber) ? rt.hmac(`subject:${input.accountNumber}`) : null;
  }
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
    draft.emit("verification.started", "code", { subject: "subjectKey" in input ? "host" : "account" });
  });
}

/**
 * Judges one entered factor: keypad knowledge, the PIN, or a plug-in. The attempt is counted
 * first; after the factor's limit the line stops judging, even the right answer.
 */
export async function submitFactor(rt: EngineRuntime, module: BadgeModule, callId: string, kind: string, entry: FactorEntry): Promise<KeypadResult> {
  const builtIn = BUILT_IN_FACTORS[kind as keyof typeof BUILT_IN_FACTORS];
  const plugin = module.plugin(kind);
  if (builtIn?.entered !== true && plugin === undefined) throw new EngineError("invalid_input", `${kind} is not a factor the caller enters`);
  const reserved = await rt.update(callId, (draft) => {
    allowFactor(rt, draft.record, kind);
    draft.assertCan({ type: "factor_recorded", factor: { kind, passed: false, at: rt.now() } });
    const s = draft.slice<BadgeSlice>(BADGE);
    const max = maxAttempts(rt, module, kind);
    const used = s.attempts[kind] ?? 0;
    if (used >= max) return null;
    s.attempts[kind] = used + 1;
    return { subjectKey: s.subjectKey, subject: s.subject, last: used + 1 >= max, epoch: s.epoch };
  });
  if (reserved === null) return { matched: false, locked: true };
  const input = { workspaceId: rt.workspaceId, subjectKey: reserved.subjectKey, subject: reserved.subject, entry, hmac: (d: string) => rt.hmac(d) };
  const passed =
    kind === "keypad_knowledge"
      ? await judgeKeypad(rt.policy, input)
      : kind === "pin"
        ? await judgePin(rt, rt.settings<BadgeSettings>(BADGE).pin as PinSettings, input)
        : (await plugin!.judge(input)) === true;
  await rt.update(callId, (draft) => {
    assertSameVerification(draft.slice<BadgeSlice>(BADGE), reserved.epoch);
    const factor = { kind, passed, at: rt.now() };
    draft.apply({ type: "factor_recorded", factor });
    if (passed && KNOWLEDGE_FACTORS.includes(kind)) draft.slice<BadgeSlice>(BADGE).knowledgeMatched = true;
    draft.emit("verification.factor", "code", { kind, passed });
  });
  return { matched: passed, locked: !passed && reserved.last };
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

/**
 * A speech vendor's score of how likely the caller's voice is synthetic (VER-14), at any point in
 * the call, in or out of a flow. It is judged against that vendor's thresholds in Badge's settings
 * and kept only as a band; the call keeps its highest band. It can only lower what the call may do:
 * above the first threshold `spoken_knowledge` stops counting, above the second the call is held to
 * level 1, and a level or grant already issued is lowered at once. The ledger gets the vendor and
 * the band, never the score.
 */
export async function reportSyntheticVoice(rt: EngineRuntime, callId: string, input: { score: number; vendor: string }): Promise<void> {
  // Read the input once, before any wait, so a caller changing it during the update cannot split
  // the vendor whose thresholds set the band from the vendor the ledger names.
  if (!isObject(input)) throw new EngineError("invalid_input", "a synthetic voice report is { score and vendor }");
  const { score, vendor } = input;
  const vendors = rt.settings<BadgeVoiceSettings>(BADGE).syntheticVoice ?? {};
  const thresholds = Object.hasOwn(vendors, vendor) ? vendors[vendor] : undefined;
  if (thresholds === undefined) throw new EngineError("invalid_input", "this vendor has no synthetic voice thresholds in the badge settings");
  if (!isScore(score)) throw new EngineError("invalid_input", "score must be a number from 0 to 1");
  const band: SyntheticVoiceBand = score > thresholds.levelOneAbove ? "level_1" : score > thresholds.spokenKnowledgeAbove ? "spoken_off" : "clear";
  await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    const highest = higherBand(bandOf(draft.record.state), band);
    // What the last verification reaches without the factors the band stops counting. Its other
    // methods are judged again only when one was dropped, so a score never moves a level otherwise.
    const kept = s.lastMethods.filter((kind) => countsUnder(kind, highest));
    const reached = kept.length === s.lastMethods.length ? 3 : evaluateAssurance(rt.policy, kept.map((kind) => ({ kind, passed: true, at: rt.now() })), s.carrier).level;
    const ceiling = heldLevel(reached, highest);
    draft.apply({ type: "synthetic_voice_scored", band, ceiling, scopes: scopesForLevel(rt.policy, ceiling) });
    // Held below what the last verification's methods reach: the receipt shows only those that support the level it shows.
    if (draft.record.state.level < s.lastLevel) s.receiptMethods = supportingMethods(rt.policy, s.lastMethods, draft.record.state.level);
    draft.emit("verification.synthetic_voice", "system", { vendor, band });
  });
}

/** Computes the level from the recorded factors (only the step's, in a flow, and only those the synthetic voice band counts), held to the band, and issues the grant. */
export async function finishVerification(rt: EngineRuntime, callId: string): Promise<VerificationResult> {
  const ttlMs = (rt.settings<BadgeSettings>(BADGE).grantTtlSeconds ?? 900) * 1000;
  return rt.update(callId, (draft) => {
    const step = stepOfType<BadgeVerifyStep>(draft.record, "badge.verify");
    const s = draft.slice<BadgeSlice>(BADGE);
    const band = bandOf(draft.record.state);
    const factors = draft.record.state.factors.filter((f) => (step === null || step.factors.includes(f.kind)) && countsUnder(f.kind, band));
    const result = evaluateAssurance(rt.policy, factors, s.carrier);
    const level = heldLevel(result.level, band);
    const scopes = scopesForLevel(rt.policy, level).filter((scope) => step?.scopes === undefined || step.scopes.includes(scope));
    const issuedAt = rt.clock.now();
    const grant =
      level === 0
        ? null
        : {
            grantId: rt.ids.next("grant"),
            level,
            scopes,
            issuedAt: issuedAt.toISOString(),
            expiresAt: new Date(issuedAt.getTime() + ttlMs).toISOString(),
          };
    draft.apply({ type: "verification_finished", level, grant });
    s.finished++;
    s.lastLevel = level;
    s.lastMethods = result.counted;
    s.receiptMethods = level < result.level ? supportingMethods(rt.policy, result.counted, level) : null;
    draft.emit("verification.finished", "code", { level, methods: result.counted, discounted: result.discounted.map((d) => d.kind) });
    if (grant !== null) draft.emit("grant.issued", "code", { grantId: grant.grantId, level: grant.level, scopes, expiresAt: grant.expiresAt });
    return { level, scopes: grant === null ? [] : scopes };
  });
}

function identityText(locale: Locale, url: string): string {
  return locale === "fr" ? `Votre lien de vérification d'identité, à usage unique : ${url}` : `Your one-time identity check link: ${url}`;
}
