// The engine: one object per workspace. It holds the core (the session state machine on a shared
// SessionStore, the policy and its levels, redaction, the module registry and the audit ledger)
// and runs the modules a workspace's FlowConfig turns on. The host's voice agent and web backend
// call it from code paths (keypad events, tool handlers, webhook routes); the model never calls it
// directly and never sees what it compares.
//
// Every change to a call is one compare-and-set write on the SessionStore, retried from a fresh
// read when another process wrote first, so several processes can run one call. Every step writes
// to the ledger, every refusal is an EngineError with a stable code, and every planned step
// throws NotImplementedError. SPEC.md describes the flow.
import { createPublicKey, type JsonWebKey } from "node:crypto";

import type { AccessController, AttemptCounterKey, AuditEntry, AuditInput, ConsentChannel, ConsentRecord, ConsentRevocation, IntakeRecord, ReceiptSigner, SessionStore } from "./core/adapters.ts";
import { canonicalJson, hasLoneSurrogate, type JsonValue } from "./core/canonical.ts";
import { randomIds, systemClock, type Clock, type IdGenerator } from "./core/clock.ts";
import { ConfigError, assertConfig, moduleEnabled, type FlowConfig } from "./core/config.ts";
import { EngineError, RateLimitedError } from "./core/errors.ts";
import { assertFlowNotEnded, currentStep } from "./core/flow.ts";
import type { Actor, EngineEventName, EventListener } from "./core/events.ts";
import { ModuleRegistry, type AssuranceModule, type FlowStep } from "./core/module.ts";
import { ATTESTATIONS, capCallLevel, raiseMinimum, scopeClass, scopesForLevel, stepAmount, type AssuranceLevel, type Attestation, type ScopeClass, type StepUpAmount, type VerificationPolicy } from "./core/policy.ts";
import { cardNumberRedactor, interruptLine, type RedactionFinding, type Redactor } from "./core/redaction.ts";
import { SUPPORTED_LOCALES, isSupportedLocale, type AdapterName, type CallAccess, type CallDraft, type CallRecord, type EngineAdapters, type EngineRuntime, type FlowStatus, type Locale } from "./core/runtime.ts";
import { MemorySessionStore } from "./core/session-store.ts";
import { canApply, newSession, reduce, snapshot, type SensitiveReason, type SessionState } from "./core/session.ts";
import * as dossier from "./file/dossier.ts";
import * as gate from "./gate/gate.ts";
import * as stepUp from "./gate/step-up.ts";
import type { NormaliseResult } from "./file/intake.ts";
import type { ReadBack } from "./file/readback.ts";
import { BUILT_IN_MODULES, builtInModules, defaultConfig } from "./modules.ts";
import type { AmountReadBack } from "./pay/amount.ts";
import * as paylink from "./pay/paylink.ts";
import type { PaymentOutcome, PaymentStatus } from "./pay/payment.ts";
import * as refunds from "./pay/refunds.ts";
import { detailCarriesCardNumber } from "./prove/ledger.ts";
import { receiptKeySet, type ReceiptBody, type SignedReceipt } from "./prove/receipt.ts";
import * as subject from "./prove/subject.ts";
import * as trace from "./prove/trace.ts";
import * as badge from "./verify/badge.ts";
import * as callback from "./verify/callback.ts";
import type { CallbackOutcome } from "./verify/callback.ts";
import { FLOW_START, claimNotice, counterKeys, flowStartLimited, isCallingNumber, lockoutOf, recordFlowStarts, unlockCounter } from "./verify/counters.ts";
import { pinTag, type BadgeSettings, type FactorEntry, type FactorPlugin, type PinOutcome } from "./verify/factors.ts";
import { clearsSoFar, duressFlagKey, flagDuress } from "./verify/duress-flag.ts";
import { knowledgeHmac, type KnowledgeHmac, type KnowledgeKey } from "./verify/knowledge.ts";
import * as pin from "./verify/pin.ts";
import * as textCode from "./verify/text-code.ts";
import type { IdentityOutcome } from "./webhooks/stripe.ts";

export { SUPPORTED_LOCALES, isSupportedLocale } from "./core/runtime.ts";
export type { CallAccess, EngineAdapters, Locale } from "./core/runtime.ts";
export type { KeypadResult, OutcomeResult, VerificationResult } from "./verify/badge.ts";
export type { DuressEnrolmentResult, PinEnrolmentResult } from "./verify/pin.ts";


/** What an `AttemptCounters` store must have, checked when the engine is built. */
const COUNTER_METHODS = ["get", "recordFailure", "removeFailure", "reset"] as const;

/** Writes per step before the engine gives up with `conflict`. */
export const MAX_WRITE_ATTEMPTS = 5;

/** The scope classes whose flows are limited per hour (VER-15). */
const LIMITED_CLASSES: ReadonlyArray<ScopeClass | null> = ["money", "contact", "access"];

/** A flow start's count: the limit it hit, the counters it is on, and the starts it recorded (keys and time), to take back if the call then refuses it. */
type FlowStart = { over: AttemptCounterKey["scope"] | null; counted: string[] | null; recorded: { keys: readonly AttemptCounterKey[]; at: string } | null };

const UNCOUNTED: FlowStart = { over: null, counted: null, recorded: null };

/**
 * What one `#update` did to the store: nothing (`none`: no compare-and-set ran, or each one
 * answered `ok: false`), `saved`, or `unknown` (a compare-and-set rejected, so it may have written).
 */
type WriteOutcome = { write: "none" | "saved" | "unknown" };

const counterId = (key: AttemptCounterKey): string => `${key.scope}:${key.key}`;

export interface EngineOptions {
  workspaceId: string;
  /**
   * The per-workspace HMAC key for knowledge factors and PINs: at least 16 bytes, or an opaque,
   * asynchronous HMAC-SHA256 function that calls the host's key management service, so the key
   * never enters this process.
   */
  knowledgeKey: KnowledgeKey;
  adapters: EngineAdapters;
  /** The workspace's FlowConfig. Default: `defaultConfig()`. Checked with `validateConfig`; any problem throws a ConfigError. */
  config?: unknown;
  /** Badge with the host's factor plug-ins. Default: `badgeModule()`. */
  badge?: badge.BadgeModule;
  /** Outside modules, installed before the config is checked (or later with `use`). */
  modules?: readonly AssuranceModule[];
  clock?: Clock;
  ids?: IdGenerator;
  /** Default: card numbers. */
  redactor?: Redactor;
  onEvent?: EventListener;
}

export interface FlowPosition {
  flow: string;
  revision: string;
  status: FlowStatus;
  /** The index of the current step; equal to the number of steps once completed. */
  index: number;
  /** The current step, or null once the flow is not running. */
  step: FlowStep | null;
}

/** What an outside module's update function sees of the call. */
export interface ModuleCallView {
  state: SessionState;
  /** The flow step the call is on (a copy), or null when no flow is running. */
  step: FlowStep | null;
  /** The engine's clock for this attempt, ISO 8601. */
  now: string;
  /** A new id from the engine's id source, `prefix_...`. A retried attempt draws a new one. */
  newId(prefix: string): string;
  authorized(scope: string): boolean;
  /** A ledger entry `module.event` with `{ module, event, detail }`. Never put a value the caller keyed in it. */
  emit(event: string, detail: { [key: string]: JsonValue }): void;
  /**
   * Call this in the same change that changes the matched subject's contact details, in a flow or
   * outside one: the call then owes the security notice (PRV-10) to the number on file before the
   * change, saved by this same write and sent right after it. Refused (`precondition_failed`, the
   * whole change with it) when no keypad or PIN match stands, since there is no number to alert.
   */
  contactChanged(): void;
}

interface QueuedEvent {
  name: EngineEventName;
  actor: Actor;
  at: string;
  detail: { [key: string]: JsonValue };
  /** On `verification.locked`: the counter that locked, for the lock notice. Never in the ledger. */
  counter?: AttemptCounterKey;
  /** A PIN outcome to tag the entry with (VER-12). Never saved. */
  tag?: string | undefined;
}

/** A member of the business lifting one lock early: the counter a lock notice named, and who did it. */
export interface UnlockInput {
  workspaceId: string;
  /** The factor kind the notice named. */
  factor: string;
  scope: AttemptCounterKey["scope"];
  /** The notice's key: the subject key or the keyed hash of the calling number. */
  key: string;
  /** The host's opaque id for the member, written in the ledger. 1 to 64 of letters, digits, `.`, `_`, `-`: no `@` and no space, so no email address or name reaches the ledger (as for `clearDuress`). */
  memberId: string;
}

const MEMBER_ID = /^[A-Za-z0-9._-]{1,64}$/;
const COUNTER_KEY = /^[0-9a-f]{64}$/;

export class Engine {
  readonly workspaceId: string;
  readonly registry: ModuleRegistry;
  /** HMAC-SHA256 under the knowledge key, the one keyed hash the engine and every factor use. */
  readonly #hmac: KnowledgeHmac;
  readonly #adapters: EngineAdapters;
  readonly #sessions: SessionStore;
  readonly #clock: Clock;
  readonly #ids: IdGenerator;
  readonly #redactor: Redactor;
  readonly #onEvent: EventListener | undefined;
  /** Badge as installed now: a new build replaces it when a factor is added (`useFactor`, `use`). */
  #badge: badge.BadgeModule;
  readonly #rt: EngineRuntime;
  /** Duress alerts this engine is sending now, by id, with when it started: one send at a time, retried after a while. */
  readonly #sending = new Map<string, number>();
  /** Per call, the owed alerts of the duress alert send scheduled and not yet started (`#sendDuressAlertsSoon`). */
  readonly #sendScheduled = new Map<string, string>();
  #receiptModules: readonly AssuranceModule[];
  #config: FlowConfig;
  /** The draft of each record being changed, so a scope check inside a change can write its step-up rules to the ledger (VER-13). */
  readonly #drafts = new WeakMap<CallRecord, CallDraft>();

  constructor(options: EngineOptions) {
    const errors: string[] = [];
    const key: unknown = options.knowledgeKey;
    // An HMAC function keeps its key in the key store: only bytes can be measured here. Anything that
    // is not a string, a Uint8Array or a function (a number, an object with a byteLength) is refused
    // now, not at the first hash.
    if (typeof key === "string" || key instanceof Uint8Array) {
      if ((typeof key === "string" ? Buffer.byteLength(key) : key.byteLength) < 16) errors.push("knowledgeKey must be at least 16 bytes");
    } else if (typeof key !== "function") {
      errors.push("knowledgeKey must be at least 16 bytes (a string or a Uint8Array), or an HMAC function");
    }
    if (typeof options.workspaceId !== "string" || options.workspaceId === "" || hasLoneSurrogate(options.workspaceId)) {
      errors.push("workspaceId must be a non-empty string the ledger can carry (no lone surrogate)");
    }
    if ((options.adapters as Partial<EngineAdapters>).ledger === undefined) errors.push("the ledger adapter is required: the ledger is always on");
    errors.push(...distinctSigners(options.adapters));
    for (const module of options.modules ?? []) {
      if ((BUILT_IN_MODULES as readonly string[]).includes(module.manifest.name)) errors.push(`${module.manifest.name} is the name of a built-in module`);
    }
    // A store missing a method would fail only later, after a pass or a failure: refused now. A
    // store written before removeFailure existed would leave a failure on the line after every pass.
    const counters = options.adapters.counters as unknown as Record<string, unknown> | null | undefined;
    if (counters !== undefined) {
      // null, anything that is not an object, or an object whose reads throw, has none of them.
      const missing = COUNTER_METHODS.filter((name) => {
        try {
          return typeof counters?.[name] !== "function";
        } catch {
          return true;
        }
      });
      if (missing.length > 0) errors.push(`the counters adapter is missing ${missing.join(", ")}`);
    }
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    this.workspaceId = options.workspaceId;
    this.#hmac = knowledgeHmac(options.knowledgeKey);
    this.#sessions = options.adapters.sessions ?? new MemorySessionStore();
    this.#adapters = { ...options.adapters, sessions: this.#sessions };
    this.#clock = options.clock ?? systemClock;
    this.#ids = options.ids ?? randomIds;
    this.#redactor = options.redactor ?? cardNumberRedactor;
    this.#onEvent = options.onEvent;
    this.#badge = options.badge ?? badge.badgeModule();
    const present = Object.entries(this.#adapters).filter(([, value]) => value !== undefined).map(([name]) => name);
    // What each adapter declares it can do, so a config it cannot serve is refused when saved.
    const capabilities: Record<string, unknown> = {};
    // Every adapter the engine has gets an entry, undefined when it declares nothing, so the
    // validator can tell "declared nothing" (refused where capabilities are required) from "unknown".
    for (const [name, value] of Object.entries(this.#adapters)) {
      if (value === undefined) continue;
      // The access adapter is a map of controllers: what it declares is the names of those it can use
      // (an `unlock` function, own or from a class), so a target naming anything else is refused at save.
      capabilities[name] =
        name === "access"
          ? { controllers: Object.entries(value as Record<string, { unlock?: unknown } | undefined>).filter(([, c]) => typeof c?.unlock === "function").map(([n]) => n) }
          : (value as { capabilities?: unknown }).capabilities;
    }
    this.#receiptModules = builtInModules(this.#badge);
    this.registry = new ModuleRegistry({ adapters: present, capabilities, reserved: BUILT_IN_MODULES, modules: [...this.#receiptModules, ...(options.modules ?? [])] });
    // This engine's own build of Badge, running the judges the outside modules given here supply.
    // A Badge shared by several engines never gains a factor through one of them.
    this.#swapBadge(this.#badge.withOutsideFactors(this.registry.factorPlugins()));
    this.#config = this.#prepare(options.config === undefined ? defaultConfig() : options.config);
    this.#rt = this.#runtime();
  }

  // ---- modules and config ------------------------------------------------------------------

  /** The config in force, as a copy. */
  get config(): FlowConfig {
    return structuredClone(this.#config);
  }

  get policy(): VerificationPolicy {
    return structuredClone(this.#config.policy);
  }

  /** Replaces the config, after checking it. Calls in progress keep the flow steps they started with. */
  configure(config: unknown): void {
    this.#config = this.#prepare(config);
  }

  /**
   * Installs an outside module. It stays off until a config turns it on. The factors its manifest
   * provides, with the judges it supplies, are run by Badge and stay off until Badge's settings
   * in a config turn them on.
   */
  use(module: AssuranceModule): this {
    // A built-in module's name stays the engine's, even after the module was removed: a host's
    // module can never stand in for Gate's grants or Paylink's payments.
    if ((BUILT_IN_MODULES as readonly string[]).includes(module.manifest.name)) {
      throw new EngineError("invalid_input", `${module.manifest.name} is the name of a built-in module`);
    }
    this.registry.use(module);
    this.#swapBadge(this.#badge.withOutsideFactors(this.registry.factorPlugins()));
    return this;
  }

  /**
   * Adds a Badge factor plug-in after the engine was built, as `badge: badgeModule({ factors })`
   * does at construction. The registry refuses a bad kind, a name for caller ID, or a kind another
   * module provides. The factor stays off until a config turns it on in Badge's settings; the
   * config in force is unchanged, and `validateConfig` with this engine's registry knows the kind.
   */
  useFactor(plugin: FactorPlugin): this {
    if (this.registry.get(badge.BADGE) !== this.#badge) throw new EngineError("precondition_failed", "the badge module is not installed");
    this.#swapBadge(this.#badge.withFactor(plugin));
    return this;
  }

  /**
   * Uninstalls a module that the config has turned off. The ledger's module cannot be removed, nor
   * a module supplying a factor the config in force names (in the policy or Badge's settings).
   */
  remove(name: string): void {
    if (moduleEnabled(this.#config, this.registry, name) && this.registry.get(name)?.manifest.alwaysOn !== true) {
      throw new EngineError("precondition_failed", `${name} is on in the config; turn it off first`);
    }
    const named = new Set(this.#config.policy.levels.flatMap((rule) => rule.anyOf.flat()));
    if (this.isEnabled(badge.BADGE)) for (const kind of this.#rt.settings<BadgeSettings>(badge.BADGE).factors) named.add(kind);
    const inUse = this.registry.judgesOf(name).filter((plugin) => named.has(plugin.kind));
    if (inUse.length > 0) throw new EngineError("precondition_failed", `${name} supplies the factor ${inUse[0]!.kind}, which the config uses; take it out first`);
    this.registry.remove(name);
    this.#swapBadge(this.#badge.withOutsideFactors(this.registry.factorPlugins()));
  }

  /** Puts a new build of Badge in place of the old, in the registry (when Badge is installed) and for the runtime. */
  #swapBadge(next: badge.BadgeModule): void {
    if (this.registry.get(badge.BADGE) === this.#badge) this.registry.replace(next);
    this.#receiptModules = this.#receiptModules.map((m) => (m === this.#badge ? next : m));
    this.#badge = next;
  }

  isEnabled(name: string): boolean {
    return moduleEnabled(this.#config, this.registry, name);
  }

  // ---- sessions ----------------------------------------------------------------------------

  /**
   * Opens a call. With `flow`, the call runs that flow from its first step. `callingNumber` (E.164,
   * from the carrier, left out when withheld) keys the counters across calls and flows, never a factor.
   * A flow over its hourly limit is refused with `rate_limited`, and the call is still opened, with
   * that flow failed: the host speaks its fixed line and ends it. `attestation` is the caller ID
   * attestation the host's carrier reported (default `none`), set once here: it can only cap the
   * call's level under the policy's `attestationCaps`, never raise it.
   */
  async startCall(input: { callId?: string; locale?: Locale; flow?: string; callingNumber?: string; attestation?: Attestation; access?: CallAccess } = {}): Promise<SessionState> {
    // Each read once: a getter read again (the flow, after an await) could change a value after it was checked or counted.
    const {
      callId: givenId,
      locale,
      flow,
      callingNumber,
      attestation: givenAttestation,
      access,
    }: { callId?: unknown; locale?: unknown; flow?: unknown; callingNumber?: unknown; attestation?: unknown; access?: unknown } = input;
    // A relay or TTY mark (VER-11) lengthens keypad timeouts only, and stays out of the ledger.
    if (access !== undefined && access !== "relay" && access !== "tty") throw new EngineError("invalid_input", "access must be relay or tty");
    // Everything the host gives here enters the ledger as it is, not through emit's checks: checked
    // now, before anything is saved, so no call's ledger can be blocked by a value it cannot hash.
    if (givenId !== undefined && (typeof givenId !== "string" || givenId === "" || givenId.length > 200 || hasLoneSurrogate(givenId))) {
      throw new EngineError("invalid_input", "callId must be 1 to 200 characters the ledger can carry (no lone surrogate)");
    }
    // null is taken as absent, as undefined is (#122): the default locale, never an unchecked one.
    if (locale !== undefined && locale !== null && !isSupportedLocale(locale)) throw new EngineError("invalid_input", `locale must be one of ${SUPPORTED_LOCALES.join(", ")}`);
    if (flow !== undefined && typeof flow !== "string") throw new EngineError("invalid_input", "flow must name a flow");
    const attestation = givenAttestation === undefined ? "none" : givenAttestation;
    if (!(ATTESTATIONS as readonly unknown[]).includes(attestation)) throw new EngineError("invalid_input", "attestation must be A, B, C, failed or none");
    const callId = (givenId as string | undefined) ?? this.#ids.next("call");
    const numberKey = await this.#numberKey(callingNumber as string | undefined);
    const flowName = flow as string | undefined;
    const attached = flowName === undefined ? null : { name: flowName, steps: this.#flowDefinition(flowName).steps, revision: this.#config.revision };
    const start = await this.#create(callId, (locale as Locale | undefined) ?? "en", this.#config.revision, attached, () => undefined, { numberKey, countStart: true, attestation: attestation as Attestation, ...(access === undefined ? {} : { access: access as CallAccess }) });
    if (start === null) throw new EngineError("invalid_input", "a call with that id exists");
    // With the call's id: the call is open, its flow failed, and the host ends it.
    if (start.over !== null) throw new RateLimitedError(callId);
    return this.state(callId);
  }

  /**
   * Creates a call at version 1, with its flow attached and `then` applied in the same write, so no
   * other process can change it in between. Null, and nothing written, when the id exists. With
   * `countStart`, a flow that needs a money, contact or access scope counts its start first (VER-15);
   * the answer says whether it was over a limit. A start a racing duplicate beat is taken back.
   * `attestation` defaults to `none`; `attestationExempt` (a callback the engine dialled) is never capped by it.
   */
  async #create(
    callId: string,
    locale: Locale,
    revision: string,
    flow: { name: string; steps: FlowStep[]; revision: string } | null,
    then: (draft: CallDraft) => void,
    options: { numberKey?: string | null; countStart?: boolean; attestation?: Attestation; attestationExempt?: true; access?: CallAccess } = {},
  ): Promise<FlowStart | null> {
    const modules: Record<string, JsonValue> = {};
    for (const module of this.registry.list()) {
      const name = module.manifest.name;
      if (this.isEnabled(name)) modules[name] = module.initCall(this.#config.modules[name]?.settings);
    }
    const record: CallRecord = {
      v: 1,
      state: newSession(callId, this.workspaceId, this.#now()),
      locale,
      revision,
      attestation: options.attestation ?? "none",
      ...(options.attestationExempt === true ? { attestationExempt: true as const } : {}),
      ...(options.access === undefined ? {} : { access: options.access }),
      flow: null,
      modules,
      outbox: [],
      ledgerWrites: 1,
    };
    this.#keepNumber(record, options.numberKey ?? null);
    const events: QueuedEvent[] = [{ name: "call.started", actor: "system", at: this.#now(), detail: { locale: record.locale, revision: record.revision, attestation: record.attestation! } }];
    let start: FlowStart = UNCOUNTED;
    if (flow !== null && options.countStart === true) {
      // A duplicate id is refused before its start is counted.
      if ((await this.#sessions.get(this.workspaceId, callId)) !== null) return null;
      start = await this.#countFlowStart(record, flow.name, { steps: flow.steps });
    }
    const draft = this.#draft(record, events);
    if (flow !== null) this.#attachFlow(draft, flow.name, { steps: flow.steps }, flow.revision, start);
    then(draft);
    this.#advance(draft);
    record.outbox = await Promise.all(events.map((event, i) => this.#outboxEntry(callId, 1, i, event)));
    let created: boolean;
    try {
      created = await this.#sessions.create(this.workspaceId, callId, record as unknown as JsonValue);
    } catch (error) {
      // No answer, so the store may have written: read back, and a start the call does not hold is given back.
      if (!(await this.#holdsFlow(callId, flow?.name, start))) await this.#uncount(start);
      throw error;
    }
    if (!created) {
      // Another start took the id first (a duplicate delivery racing this one): this start is not counted.
      await this.#uncount(start);
      return null;
    }
    await this.#flush(callId, 1, record);
    return start;
  }

  /** The keyed hash of a calling number, or null when the host gave none (withheld). */
  async #numberKey(callingNumber: string | undefined): Promise<string | null> {
    if (callingNumber === undefined) return null;
    if (!isCallingNumber(callingNumber)) throw new EngineError("invalid_input", "callingNumber must be E.164; leave it out when the number is withheld");
    // The same keyed hash as `numberKeyFor`, through the knowledge key's store (it may be a key store's HMAC, #72).
    return this.#hmac(`number:${callingNumber}`);
  }

  /** Keeps the calling number's key in Badge's part of the call, for the counters; a later restart without one keeps it. */
  #keepNumber(record: CallRecord, numberKey: string | null): void {
    const slice = record.modules[badge.BADGE] as unknown as badge.BadgeSlice | undefined;
    if (numberKey !== null && slice !== undefined) slice.numberKey = numberKey;
  }

  async state(callId: string): Promise<SessionState> {
    return snapshot((await this.#read(callId)).state);
  }

  /** Untrusted text (a business webhook reply, a document) entered the conversation. */
  async markUntrusted(callId: string, source: string): Promise<void> {
    // The taint always lands: a label that is not Unicode text is repaired, never a reason to refuse.
    source = untrustedLabel(source);
    // A grant that may still be acted on when the taint lands is written down with it, and its
    // controller is asked to withdraw it where it can (Gate, SPEC.md section 17).
    let tainted: gate.AccessRecord[] = [];
    await this.#update(callId, (draft) => {
      draft.apply({ type: "untrusted_content", source });
      for (const module of this.registry.list()) {
        const name = module.manifest.name;
        const slice = draft.record.modules[name];
        if (module.onUntrusted !== undefined && slice !== undefined) draft.record.modules[name] = module.onUntrusted(slice);
      }
      draft.emit("session.tainted", "code", { source });
      tainted = gate.noteTaintedGrants(this.#rt, draft);
    });
    await gate.revokeTainted(this.#rt, callId, tainted);
  }

  /** Keypad entry is open: the host pauses transcripts, cuts audio to the model and holds listen-in. */
  async openSensitive(callId: string, reason: SensitiveReason): Promise<void> {
    await this.#update(callId, (draft) => {
      draft.apply({ type: "sensitive_opened", reason });
      draft.emit("sensitive.opened", "code", { reason });
    });
  }

  async closeSensitive(callId: string): Promise<void> {
    await this.#update(callId, (draft) => {
      draft.apply({ type: "sensitive_closed" });
      draft.emit("sensitive.closed", "code", {});
    });
  }

  /**
   * Redacts text before the host stores or forwards it. `interrupt` tells the host to speak `line`,
   * the fixed line for what was found (a card number, a health card number, a SIN or banking
   * details), in the call's language; `line` is null when nothing was found.
   */
  async redact(callId: string, text: string): Promise<{ text: string; findings: RedactionFinding[]; interrupt: boolean; line: string | null }> {
    // The call's language decides whose number words are read: English and French always, Spanish
    // only on a Spanish call ("once" is a number only in Spanish), and the line's language.
    let { locale } = await this.#read(callId);
    const result = this.#redactor.redact(text, { locale });
    if (result.findings.length > 0) {
      const kinds: Record<string, number> = {};
      for (const f of result.findings) kinds[f.kind] = (kinds[f.kind] ?? 0) + 1;
      locale = await this.#update(callId, (draft) => {
        draft.emit("redaction.applied", "code", { kinds });
        return draft.record.locale;
      });
    }
    return { ...result, interrupt: result.findings.length > 0, line: interruptLine(result.findings, locale) };
  }

  /**
   * Whether the call's grant covers a scope now. A scope the policy does not list is refused. The
   * scope's minimum is raised by the policy's step-up rules that hold (VER-13): pass the amount a
   * money scope is for (in a flow, the current step's amount is the default; an amount not known
   * counts as over every amount rule). A rule that applies for the first time on the call is
   * written to the ledger by name, so this can write.
   */
  async authorize(callId: string, scope: string, given?: StepUpAmount): Promise<boolean> {
    // Read once, before the wait: both checks judge the amount the host passed at the call, as a
    // plain copy, so a getter or a change to the object meanwhile cannot answer each differently.
    // A null from the host is no amount (over every amount rule), never the internal "not asked yet".
    const amount = typeof given === "object" && given !== null ? { amountMinor: given.amountMinor, currency: given.currency } : (given ?? undefined);
    const record = await this.#read(callId);
    const check = this.#cover(record, scope, amount);
    // A rule in `applied` was walked by #cover, which set `stepUps` on this read copy (`??=`).
    if (check.applied.every((name) => record.stepUps!.includes(name))) return check.ok;
    return this.#update(callId, (draft) => this.#authorized(draft.record, scope, amount));
  }

  /**
   * Raises a named signal on the call (for example `fraud_suspected`), for the policy's step-up
   * rules. The host's code raises it; a signal stays raised for the rest of the call. In a flow, a
   * current step whose scope it raises above the call's verification fails, naming the rule.
   */
  async raiseSignal(callId: string, signal: string): Promise<void> {
    if (!(this.#config.policy.stepUp ?? []).some((rule) => rule.signal === signal)) throw new EngineError("invalid_input", "no step-up rule uses that signal");
    await this.#update(callId, (draft) => {
      if (draft.record.state.phase === "ended") throw new EngineError("invalid_transition", "the call has ended");
      const signals = (draft.record.signals ??= []);
      if (signals.includes(signal)) return;
      signals.push(signal);
      draft.emit("signal.raised", "code", { signal });
      this.#holdStep(draft);
    });
  }

  // ---- flows -------------------------------------------------------------------------------

  /**
   * Starts a named flow on an open call. A call runs at most one flow; its steps are copied in now.
   * A flow over its hourly limit is refused with `rate_limited` and stays on the call, failed.
   */
  async startFlow(callId: string, name: string, input: { callingNumber?: string } = {}): Promise<FlowPosition> {
    const definition = this.#flowDefinition(name);
    const revision = this.#config.revision;
    const numberKey = await this.#numberKey(input.callingNumber);
    const before = await this.#read(callId);
    this.#keepNumber(before, numberKey);
    const start = await this.#countFlowStart(before, name, definition);
    // The start is taken back when nothing was written (the write's own check refused the flow, every
    // compare-and-set found the call moved, or a read failed first), or when a write with no answer
    // is read back without this flow. A write that saved and then failed (the ledger down) keeps it.
    const outcome: WriteOutcome = { write: "none" };
    try {
      await this.#update(
        callId,
        (draft) => {
          this.#keepNumber(draft.record, numberKey);
          this.#attachFlow(draft, name, definition, revision, start);
        },
        outcome,
      );
    } catch (error) {
      if (outcome.write === "none" || (outcome.write === "unknown" && !(await this.#holdsFlow(callId, name, start)))) await this.#uncount(start);
      throw error;
    }
    if (start.over !== null) throw new RateLimitedError(callId);
    return (await this.flowPosition(callId))!;
  }

  /**
   * Checks that a flow can start on the call, then, when it needs a money, contact or access scope,
   * counts its start on the number's and the subject's counters, whichever the call has. A start
   * found over a limit is not counted; one that a concurrent start took over a limit is.
   */
  async #countFlowStart(record: CallRecord, name: string, definition: Pick<FlowConfig["flows"][string], "steps">): Promise<FlowStart> {
    // Checked first on a copy, so a start the call would refuse anyway is never counted.
    this.#attachFlow(this.#draft(structuredClone(record), []), name, definition, this.#config.revision, UNCOUNTED);
    if (!this.#limited(definition.steps, this.#config.policy)) return UNCOUNTED;
    const keys = counterKeys(this.workspaceId, FLOW_START, record.modules[badge.BADGE] as unknown as badge.BadgeSlice);
    const { over, at } = await this.#countStarts(keys);
    return { over, counted: keys.map(counterId), recorded: at === null ? null : { keys, at } };
  }

  /**
   * Whether the stored call holds this start's flow, read back after a write that gave no answer.
   * A read that fails too answers true: the start stays counted, the safe side.
   */
  async #holdsFlow(callId: string, name: string | undefined, start: FlowStart): Promise<boolean> {
    try {
      const stored = await this.#sessions.get(this.workspaceId, callId);
      const flow = (stored?.record as unknown as CallRecord | undefined)?.flow ?? null;
      return flow !== null && flow.name === name && JSON.stringify(flow.counted) === JSON.stringify(start.counted);
    } catch {
      return true;
    }
  }

  /** Takes back the starts a start recorded, once the call refused it: one entry per counter, at the time it was recorded. */
  async #uncount(start: FlowStart): Promise<void> {
    if (start.recorded === null) return;
    for (const key of start.recorded.keys) await this.#adapters.counters!.removeFailure(key, start.recorded.at);
  }

  /**
   * Counts one flow start on each counter, unless one is already at its limit. `over`: the scope of
   * the limit hit, or null; `at`: when the starts were recorded, or null when none was.
   */
  async #countStarts(keys: readonly AttemptCounterKey[]): Promise<{ over: AttemptCounterKey["scope"] | null; at: string | null }> {
    const limits = lockoutOf(this.#rt.settings<BadgeSettings>(badge.BADGE).lockout).flowStartsPerHour;
    const counters = this.#adapters.counters!;
    const now = this.#clock.now();
    const limited = await flowStartLimited(counters, limits, keys, now);
    if (limited !== null) return { over: limited, at: null };
    return { over: await recordFlowStarts(counters, limits, keys, now), at: now.toISOString() };
  }

  /**
   * Whether a flow's starts are limited: a step needs a money, contact or access scope, or a
   * verification step can grant one (its listed scopes, or every scope its level reaches).
   */
  #limited(steps: readonly FlowStep[], policy: VerificationPolicy): boolean {
    const declared = this.registry.scopeClasses();
    return steps.some((step) => {
      const owner = this.registry.stepOwner(step.type)!;
      const level = owner.stepLevel?.(step) ?? null;
      // A copy: the list a module returns may be its own, shared or frozen.
      const scopes = [...(level === null ? [] : (owner.stepGrants?.(step) ?? scopesForLevel(policy, level as AssuranceLevel)))];
      const need = owner.manifest.scopes.needs[step.type];
      if (need !== undefined) scopes.push(need);
      return scopes.some((scope) => LIMITED_CLASSES.includes(scopeClass(scope, policy.scopeClasses, declared)));
    });
  }

  #attachFlow(draft: CallDraft, name: string, definition: Pick<FlowConfig["flows"][string], "steps">, revision: string, start: FlowStart): void {
    {
      const record = draft.record;
      if (record.flow !== null) throw new EngineError("precondition_failed", "this call already ran a flow");
      if (record.state.phase !== "open") throw new EngineError("invalid_transition", `a flow starts on an open call, not while ${record.state.phase}`);
      const steps = structuredClone(definition.steps);
      // Checked inside the write, against the registry and the call as they are now: a module can
      // be removed, or the call can lack what a newer config's step needs, while this runs.
      for (const step of steps) {
        const module = this.registry.stepOwner(step.type);
        if (module === undefined) throw new EngineError("module_disabled", `no installed module provides ${step.type}`);
        const owner = module.manifest.name;
        const slice = record.modules[owner];
        if (slice === undefined) throw new EngineError("module_disabled", `${owner} was off when this call started`);
        if (!this.isEnabled(owner)) throw new EngineError("module_disabled", `the ${owner} module is turned off`);
        const reason = module.cannotRunStep?.(step, slice, record.locale) ?? null;
        if (reason !== null) throw new EngineError("precondition_failed", `${step.type} cannot run on this call: ${reason}`);
      }
      if (start.over !== null) {
        // Over an hourly limit: the call keeps the flow, failed, so nothing else starts on it.
        record.flow = { name, revision, steps, index: 0, mark: null, status: "failed", counted: start.counted };
        draft.emit("flow.rate_limited", "code", { flow: name, scope: start.over });
        return;
      }
      const first = steps[0]!;
      const firstOwner = this.registry.stepOwner(first.type)!;
      const mark = firstOwner.enterStep(first, record.modules[firstOwner.manifest.name]!);
      record.flow = { name, revision, steps, index: 0, mark, status: "running", counted: start.counted };
      draft.emit("flow.started", "code", { flow: name, revision, steps: steps.length });
      this.#holdStep(draft);
    }
  }

  /** Where the call is in its flow, or null when it runs none. */
  async flowPosition(callId: string): Promise<FlowPosition | null> {
    const record = await this.#read(callId);
    const flow = record.flow;
    if (flow === null) return null;
    return { flow: flow.name, revision: flow.revision, status: flow.status, index: flow.index, step: currentStep(record) };
  }

  // ---- Badge (verify) ----------------------------------------------------------------------

  /**
   * Starts (or restarts) verification, with the account number the caller keyed or a subject key
   * the host's code chose, and the calling number when it is not withheld (counted, never a factor).
   */
  async beginVerification(callId: string, input: badge.BeginVerificationInput): Promise<void> {
    await badge.beginVerification(this.#rt, callId, input);
    // Once verification names a subject (or brings a number), a flow with an hourly limit is
    // counted on that counter too, once per call; over the limit, the flow fails and the host gets
    // the same `rate_limited` as a refused start.
    const record = await this.#read(callId);
    const flow = record.flow;
    // A flow started before `counted` existed (undefined) was never counted: it stays as it was. [] is a new limited flow.
    if (flow === null || flow.counted === null || flow.counted === undefined) return;
    const keys = counterKeys(this.workspaceId, FLOW_START, record.modules[badge.BADGE] as unknown as badge.BadgeSlice).filter((key) => !flow.counted!.includes(counterId(key)));
    if (keys.length === 0) return;
    const { over } = await this.#countStarts(keys);
    await this.#update(callId, (draft) => {
      const current = draft.record.flow!;
      if (over === null) {
        current.counted!.push(...keys.map(counterId));
        return;
      }
      // Fails closed, whatever another process did to the flow meanwhile.
      current.status = "failed";
      draft.emit("flow.rate_limited", "code", { flow: current.name, scope: over });
    });
    if (over !== null) throw new RateLimitedError(callId);
  }

  /** Judges every keypad field at once. The answer is the same for an unknown account and a wrong value. */
  submitKeypad(callId: string, entries: Readonly<Record<string, string>>): Promise<badge.KeypadResult> {
    return badge.submitFactor(this.#rt, this.#badge, callId, "keypad_knowledge", entries);
  }

  /** Judges a PIN, against the keyed hash on file or the host's verifier. Attempts are limited per call. */
  submitPin(callId: string, pin: string): Promise<badge.KeypadResult> {
    return badge.submitFactor(this.#rt, this.#badge, callId, "pin", pin);
  }

  /** Judges an entry for any factor the caller enters, a host's plug-in included. */
  submitFactor(callId: string, kind: string, entry: FactorEntry): Promise<badge.KeypadResult> {
    return badge.submitFactor(this.#rt, this.#badge, callId, kind, entry);
  }

  /**
   * The call's keypad timeouts, for a `KeypadCollector` (VER-11): longer on a call marked relay or
   * TTY, and the limit to which the host may lengthen them when the caller asks to slow down.
   */
  keypadTiming(callId: string): Promise<badge.KeypadTiming> {
    return badge.keypadTiming(this.#rt, callId);
  }

  checkCarrier(callId: string): Promise<{ textCodeTrusted: boolean }> {
    return badge.checkCarrier(this.#rt, callId);
  }

  /**
   * Where a code text for this call goes: the subject Badge matched by keypad or PIN, its number
   * on file and the call's locale, for a module that texts it (Gate's access codes). Throws
   * `precondition_failed` before a match. Never the calling number.
   */
  async numberOnFile(callId: string): Promise<{ subjectKey: string; phoneOnFile: string; locale: Locale }> {
    const record = await this.#read(callId);
    const subject = badge.matchedSubject(record);
    return { subjectKey: subject.subjectKey, phoneOnFile: subject.phoneOnFile, locale: record.locale };
  }

  /**
   * Texts a one-time code to the number on file, after a keypad or PIN match. Always `{ sent: true }`:
   * a send refused by the country allow-list or a limit looks the same, so the host speaks one line.
   */
  sendTextCode(callId: string): Promise<{ sent: true }> {
    return textCode.sendTextCode(this.#rt, callId);
  }

  /** Judges a texted code and records a `text_code` factor. 5 tries per code, 10 minutes, used once. */
  checkTextCode(callId: string, code: string): Promise<badge.KeypadResult> {
    return textCode.checkTextCode(this.#rt, callId, code);
  }

  startPhotoId(callId: string): Promise<{ sent: true }> {
    return badge.startPhotoId(this.#rt, callId);
  }

  applyIdentityOutcome(outcome: IdentityOutcome): Promise<badge.OutcomeResult> {
    return badge.applyIdentityOutcome(this.#rt, outcome);
  }

  /**
   * Asks for a callback to the number on file (VER-9) and ends this call, which never gains a
   * level from it. When the request is allowed, the engine creates the callback call for the
   * subject this call matched, in verification, and has the `dialer` ring the number on file; the
   * dialer's outcome arrives at `applyCallbackOutcome`. A refused request (no keypad or PIN match,
   * no number on file, a lock, the daily limit) returns the same, so the caller hears the same.
   * Calling it again after a failure resumes a placed callback without ringing twice.
   */
  async requestCallback(callId: string): Promise<void> {
    const plan = await callback.requestCallback(this.#rt, callId);
    const first = await this.#read(callId);
    if (first.state.phase !== "ended") {
      try {
        await this.endCall(callId);
      } catch (e) {
        // Two requests at once both reach here: the one that ended the call second is not an error.
        if (!(e instanceof EngineError && e.code === "invalid_transition" && (await this.#read(callId)).state.phase === "ended")) throw e;
      }
    }
    if (plan === null) return;
    const flow = first.flow === null ? null : { name: first.flow.name, steps: first.flow.steps, revision: first.flow.revision };
    // Already created when this resumes: then only the dial is retried.
    await this.#create(plan.callbackCallId, first.locale, first.revision, flow, (draft) => callback.beginCallbackCall(draft, plan, callId), { attestationExempt: true });
    try {
      await callback.dialCallback(this.#rt, plan.callbackCallId);
    } catch {
      // A dial that failed answers as a refusal does, so the result never says whether the subject
      // has a number on file. The callback stays dialing, never passed (fail closed); requesting
      // again resumes it, and the dialer, the host's own adapter, reports its failure to the host.
    }
  }

  /** The dialer's outcome for a callback. Unknown, late, repeated or voided outcomes are ignored. */
  applyCallbackOutcome(outcome: CallbackOutcome): Promise<badge.OutcomeResult> {
    return callback.applyCallbackOutcome(this.#rt, outcome);
  }

  finishVerification(callId: string): Promise<badge.VerificationResult> {
    return badge.finishVerification(this.#rt, callId);
  }

  /**
   * Lets a caller verified to level 2 or above on this call choose a PIN, keyed twice. Outside a
   * flow, in `keyed_hash` mode, and only when the subject has no PIN on file.
   */
  enrolPin(callId: string, input: { pin: string; confirm: string }): Promise<pin.PinEnrolmentResult> {
    return pin.enrolPin(this.#rt, callId, input);
  }

  /**
   * The business lifts a subject's duress flag (VER-12) once it knows the subject is safe: a host
   * call, never a caller's, written to the ledger with the member (`duress.cleared`).
   */
  clearDuress(subjectKey: string, memberId: string): Promise<void> {
    return badge.clearDuress(this.#rt, this.#badge, subjectKey, memberId);
  }

  /** The business resets a subject's PIN (and removes any duress PIN). A host call from the business's own tools, never on a caller's request. */
  resetPin(subjectKey: string): Promise<void> {
    return pin.resetPin(this.#rt, subjectKey, this.#adapters.counters);
  }

  /**
   * Lifts one lock early, for a member of the business who knows the caller is real (INT-7): the
   * counter a lock notice named, and nothing else. A host call from the business's own tools: it
   * takes no call, so nothing on a call reaches it. It grants nothing: the caller still verifies
   * from nothing. The ledger entry `verification.unlocked` names the member, and is written before
   * the counter is cleared, so no unlock goes unrecorded.
   */
  async unlock(input: UnlockInput): Promise<void> {
    if (typeof input !== "object" || input === null) throw new EngineError("invalid_input", "unlock takes the counter a lock notice named and the member");
    // Each field read once, and only the plain copy passed on: a getter read again could change a
    // value after it was checked (the card-number check, the ledger, the digest, the counter cleared).
    const { workspaceId, factor, scope, key, memberId }: { [K in keyof UnlockInput]: unknown } = input;
    const errors: string[] = [];
    if (workspaceId !== this.workspaceId) errors.push("workspaceId is not this engine's workspace");
    if (typeof factor !== "string" || !this.#badge.installedFactors().includes(factor)) errors.push("factor is not an installed factor kind");
    if (scope !== "subject" && scope !== "number") errors.push("scope must be subject or number");
    // Strings only: a regex test turns an array or an object into a string, which would pass here,
    // be recorded, and then clear no counter.
    if (typeof key !== "string" || !COUNTER_KEY.test(key)) errors.push("key must be 64 lower-case hex characters");
    if (typeof memberId !== "string" || !MEMBER_ID.test(memberId)) errors.push("memberId must be an opaque id: 1 to 64 of letters, digits, '.', '_', '-'");
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    const counter: AttemptCounterKey = { workspaceId: this.workspaceId, factor: factor as string, scope: scope as AttemptCounterKey["scope"], key: key as string };
    const counters = this.#adapters.counters;
    if (counters === undefined) throw new EngineError("precondition_failed", "the engine has no counters adapter, so nothing is locked");
    // Checked before the digest goes in: the digest is the engine's own hex, never card data.
    if (detailCarriesCardNumber({ memberId: memberId as string })) throw new EngineError("invalid_input", "audit detail must never carry a card number");
    // The counter by a keyed digest only the business can match (unlockedCounter with its knowledge
    // key), never the key itself, as duress.cleared names its subject.
    const detail = { kind: counter.factor, scope: counter.scope, counter: await this.#hmac(JSON.stringify(["verification.unlocked", counter.factor, counter.scope, counter.key])), memberId: memberId as string };
    // No event id: one from the id generator repeats when a host's generator does (a restart, a
    // second process), and the ledger would take the repeat for an append already done, leaving this
    // unlock unrecorded. Each unlock is its own entry, as a PIN reset is.
    await this.#adapters.ledger.append({ callId: null, actor: "member", event: "verification.unlocked", at: this.#now(), detail });
    await unlockCounter(counters, counter);
  }

  /**
   * The business enrols or replaces a subject's duress PIN (VER-12). A host call from its own tools,
   * never on a caller's request; `keyed_hash` mode with `pin.duress` on, for a subject with a PIN.
   */
  enrolDuressPin(subjectKey: string, duressPin: string): Promise<pin.DuressEnrolmentResult> {
    return pin.enrolDuressPin(this.#rt, subjectKey, duressPin);
  }

  /** The business removes a subject's duress PIN (VER-12). A host call. */
  removeDuressPin(subjectKey: string): Promise<void> {
    return pin.removeDuressPin(this.#rt, subjectKey);
  }

  /** What a `pin` factor ledger entry's keyed `tag` says (VER-12), or null. Only this key's holder can read it. */
  readPinTag(entry: Pick<AuditEntry, "eventId" | "event" | "detail">): Promise<PinOutcome | null> {
    return pin.readPinTagWith(this.#hmac, entry);
  }

  // ---- Dossier (file) ----------------------------------------------------------------------

  startIntake(callId: string, formId: string): Promise<void> {
    return dossier.startIntake(this.#rt, callId, formId);
  }

  setIntakeField(callId: string, key: string, raw: string): Promise<NormaliseResult> {
    return dossier.setIntakeField(this.#rt, callId, key, raw);
  }

  /** The read-back of the open draft in the call's locale: speak `text`, then pass `digest` to `confirmIntake`. */
  intakeReadBack(callId: string): Promise<ReadBack> {
    return dossier.intakeReadBack(this.#rt, callId);
  }

  /** Files the draft the caller confirmed. `readBack` is the digest of the read-back they heard; a draft changed since is refused. */
  confirmIntake(callId: string, input: { confirmedBy: "voice" | "keypad"; readBack: string }): Promise<IntakeRecord> {
    return dossier.confirmIntake(this.#rt, callId, input, matchedSubjectKey);
  }

  abandonIntake(callId: string): Promise<void> {
    return dossier.abandonIntake(this.#rt, callId);
  }

  // ---- Paylink (pay) -----------------------------------------------------------------------

  /** Builds the amount read-back the host speaks before a link: the step's (or host's) amount, or the one the AmountSource resolves (PAY-2). */
  readBackPayment(callId: string, input?: paylink.PaymentInput): Promise<AmountReadBack> {
    return paylink.readBackPayment(this.#rt, callId, input);
  }

  /** The caller confirmed the amount read back; `digest` is the read-back's. */
  confirmPaymentAmount(callId: string, input: { digest: string; confirmedBy: "voice" | "keypad" }): Promise<void> {
    return paylink.confirmPaymentAmount(this.#rt, callId, input);
  }

  /** Texts a payment link. `expiresAt` is the engine's deadline for it: call `expirePaymentLinks` then. */
  requestPayment(callId: string, input?: paylink.PaymentInput): Promise<{ paymentId: string; status: PaymentStatus; expiresAt: string | null }> {
    return paylink.requestPayment(this.#rt, callId, input);
  }

  /** Expires a call's texted links that are still open past their deadline (Paylink's link life). */
  expirePaymentLinks(callId: string): Promise<{ expired: string[] }> {
    return paylink.expirePaymentLinks(this.#rt, callId);
  }

  /** Cancels a payment's link (the caller changed their mind). It settles `expired`; a payment no longer open is left as it is. */
  cancelPaymentLink(callId: string, paymentId: string): Promise<{ paymentId: string; status: PaymentStatus }> {
    return paylink.cancelPaymentLink(this.#rt, callId, paymentId);
  }

  /**
   * A provider's verified outcome. A payment the engine closed that is paid after all is recorded
   * paid, flagged `late`. A platform payment's `paymentIntentId` is bound to the call, for its disputes.
   * `unbound`: no call holds the link (yet); have the event delivered again.
   */
  applyPaymentOutcome(outcome: PaymentOutcome & { paymentIntentId?: string }): Promise<{ applied: false; unbound?: true } | { applied: true; callId: string; status: PaymentStatus }> {
    return paylink.applyPaymentOutcome(this.#rt, outcome);
  }

  /**
   * Refunds a paid platform payment, in full or in part, for the business. A host call from the
   * business's side (its back office or staff), never from a call's tool path: no grant reaches
   * it, and the model must never be given it. Works after the call ended.
   */
  refundPayment(input: refunds.RefundInput): Promise<refunds.RefundResult> {
    return refunds.refundPayment(this.#rt, input);
  }

  /** A verified dispute event (`charge.dispute.*`), recorded against the platform payment it names. */
  applyDisputeOutcome(outcome: refunds.DisputeOutcome): Promise<refunds.DisputeApplied> {
    return refunds.applyDisputeOutcome(this.#rt, outcome);
  }

  // ---- Gate (entry) ------------------------------------------------------------------------

  /** Issues an access grant and sends it to its door controller, once (SPEC.md, section 17). */
  grantAccess(callId: string, input?: { target: string; lifetimeSeconds?: number }, only?: { controller: AccessController }): Promise<gate.AccessResult> {
    return gate.grantAccess(this.#rt, callId, input, only);
  }

  /**
   * Has every access controller that owes the ledger something write it (`AccessController.flush`:
   * a spent access code's entry whose append failed), for the whole workspace. Call it on a
   * schedule. `failed`: the controllers that could not, to try again on the next sweep.
   */
  async sweepAccess(): Promise<{ failed: string[] }> {
    const failed: string[] = [];
    for (const [name, controller] of Object.entries(this.#adapters.access ?? {})) {
      if (typeof controller.flush !== "function") continue;
      await controller.flush({ workspaceId: this.workspaceId }).catch(() => failed.push(name));
    }
    return { failed };
  }

  /** A call's access grants, as the engine recorded them. Never the signed grants themselves. */
  async accessGrants(callId: string): Promise<gate.AccessRecord[]> {
    const slice = (await this.#read(callId)).modules[gate.GATE] as unknown as gate.GateSlice | undefined;
    return slice === undefined ? [] : structuredClone(slice.grants);
  }

  /** The key set door relays verify access grants with (empty without an access signer). */
  accessKeys(): JsonWebKey[] {
    const signer = this.#adapters.accessSigner;
    // The published `kid` is the one every grant carries (the signer's keyId), whatever its JWK says:
    // relays select the key by it, so a JWK without one would leave every grant unverifiable.
    return signer === undefined ? [] : [{ ...publicMembers(signer.publicJwk()), kid: signer.keyId } as JsonWebKey];
  }

  // ---- Step-up (web sign-in) ---------------------------------------------------------------

  /** Issues a web sign-in step-up token for the nonce the caller keyed (SPEC.md, section 18). Hand it to the waiting sign-in only. */
  issueStepUpToken(callId: string, input: { nonce: string; site?: string; lifetimeSeconds?: number }): Promise<stepUp.StepUpToken> {
    return stepUp.issueStepUpToken(this.#rt, callId, input);
  }

  /** The host's web sign-in exchanges a step-up token, once. Never throws for a bad token. */
  exchangeStepUpToken(token: unknown, expect: { audience: string; subjectKey: string; nonce: string }): Promise<stepUp.StepUpExchange> {
    return stepUp.exchangeStepUpToken(this.#rt, token, expect);
  }

  /** A call's step-up tokens, as the engine recorded them. Never the tokens or the nonces. */
  async stepUpTokens(callId: string): Promise<stepUp.StepUpRecord[]> {
    const slice = (await this.#read(callId)).modules[stepUp.STEP_UP] as unknown as stepUp.StepUpSlice | undefined;
    return slice === undefined ? [] : structuredClone(slice.tokens);
  }

  /** The JWKS document for the step-up issuer's `/.well-known/jwks.json` (no keys without a step-up signer). */
  stepUpKeys(): { keys: JsonWebKey[] } {
    const signer = this.#adapters.stepUpSigner;
    // The published `kid` is the one the tokens' header carries, whatever the signer's JWK says.
    return { keys: signer === undefined ? [] : [{ ...publicMembers(signer.publicJwk()), kid: signer.keyId } as JsonWebKey] };
  }

  // ---- Trace (prove) -----------------------------------------------------------------------

  recordConsent(callId: string, input: { purpose: string; answer: "yes" | "no"; channel?: ConsentChannel }): Promise<ConsentRecord> {
    return trace.recordConsent(this.#rt, callId, input, matchedSubjectKey);
  }

  /**
   * Revokes a consent by voice (`call`), text or dashboard (`web`), during its call or after it.
   * Needs the `consents` adapter. Returns the revocation in force: a second one changes nothing.
   */
  revokeConsent(input: { consentId: string; via: ConsentChannel }): Promise<ConsentRevocation> {
    return trace.revokeConsent(this.#rt, input);
  }

  /**
   * Ends the call. A running flow is abandoned, and every payment link still open is expired, at
   * the provider first, so the receipt shows it `expired`. Returns the signed receipt when the call
   * gets one, else null. A call that changed contact details first texts its security notice to the
   * number on file before the change; if that text fails, `endCall` again sends it, without ending again.
   */
  async endCall(callId: string): Promise<SignedReceipt | null> {
    // A call that ended without its receipt (the signer failed), with a link left open (the provider
    // failed) or with its notice owed gets them now, without ending again.
    const before = await this.#read(callId);
    const receiptPending = trace.wantsReceipt(this.#rt, before) && trace.receiptOf(before) === null;
    // Ledger entries a failed append left behind (a notice or receipt saved, then not logged) count too.
    const pending = before.state.phase === "ended" && (receiptPending || paylink.openPayments(before).length > 0 || trace.noticeDue(before) || before.outbox.length > 0);
    if (pending) await this.flushLedger(callId);
    const ended = pending ? before : await this.#update(callId, (draft) => {
      // The built-in modules' guards run even after a module was removed, as their receipt parts do.
      const guards = [...this.#receiptModules, ...this.registry.list().filter((m) => !this.#receiptModules.includes(m))];
      for (const module of guards) {
        const slice = draft.record.modules[module.manifest.name];
        const reason = slice === undefined ? null : (module.blocksEnd?.(slice, this.#clock.now()) ?? null);
        if (reason !== null) throw new EngineError("precondition_failed", `the call cannot end yet: ${reason}`);
      }
      // Refused while a signed grant may still be acted on at its door; a grant reserved but not yet
      // signed (or past its expiry) is settled now, as unknown, before the receipt's ledger head is
      // taken: no access outcome can ever follow the receipt.
      gate.settleInFlight(this.#rt, draft, "call_ended");
      // Likewise a step-up token still being signed: it is failed, never handed out after the end.
      stepUp.settleStepUpInFlight(draft);
      // Likewise a payment link being texted: the call ends once its text is recorded, so no text
      // goes out after the call ended.
      paylink.assertNoSendInFlight(this.#rt, draft.record);
      // The engine, not a module hook, drops Dossier's open draft, so its sensitive values never
      // outlive the call in the clear. It runs before call.ended and before the receipt's ledger
      // head is taken, and writes no event and no outcome.
      const files = draft.record.modules[dossier.DOSSIER];
      if (files !== undefined) draft.record.modules[dossier.DOSSIER] = dossier.withoutOpenDraft(files);
      // A consent whose store write is still reserved is settled as not recorded, before call.ended.
      trace.settleUnrecorded(draft);
      draft.apply({ type: "call_ended", at: this.#now() });
      const flow = draft.record.flow;
      if (flow !== null && flow.status === "running") {
        flow.status = "abandoned";
        draft.emit("flow.abandoned", "system", { flow: flow.name, step: flow.index });
      }
      draft.emit("call.ended", "system", {});
      return structuredClone(draft.record);
    });
    await this.#deliverAlerts(callId);
    // What an access controller still owes the ledger for this call is written now, before the
    // receipt's head is taken; one that fails is left to the next sweep (it opens nothing).
    for (const controller of Object.values(this.#adapters.access ?? {})) {
      if (typeof controller.flush === "function") await controller.flush({ workspaceId: this.workspaceId, callId }).catch(() => undefined);
    }
    // No new payment can start once the call ended, so this closes every link the call will have.
    await paylink.expireOpenPayments(this.#rt, ended);
    const record = paylink.openPayments(ended).length === 0 ? ended : await this.#read(callId);
    if (!trace.wantsReceipt(this.#rt, record)) return null;
    const issued = trace.receiptOf(record);
    if (issued !== null) return structuredClone(issued);
    // The head must cover every entry the end wrote, an expired link's among them, even one left
    // pending by an earlier append that failed: they are appended first, or the receipt waits.
    await this.flushLedger(callId);
    const head = await trace.endedHead(this.#rt, record, () => this.#adapters.ledger.head());
    const parts: Pick<ReceiptBody, "verification" | "records" | "payments" | "stepUp"> = { verification: { level: 0, methods: [] }, records: [], payments: [] };
    // The built-in contributors, not the registry: a module removed after this call filed or paid still appears on its receipt.
    for (const module of this.#receiptModules) {
      const slice = record.modules[module.manifest.name];
      if (module.receiptPart !== undefined && slice !== undefined) Object.assign(parts, module.receiptPart(slice, record.state));
    }
    return trace.issueReceipt(this.#rt, record, head, parts);
  }

  /**
   * Texts the link to an ended call's receipt (`url`: the host's capability link, SRV-3) to the
   * number on file, when the flow's `trace.receipt` step has `textLink`, a money, contact or access
   * step completed, the caller consented and a keypad or PIN factor matched. At most once per call.
   */
  textReceiptLink(callId: string, url: string): Promise<{ texted: boolean }> {
    return trace.textReceiptLink(this.#rt, callId, url, (record) => this.#currentSubject(record));
  }

  async receipt(callId: string): Promise<SignedReceipt | null> {
    const slice = (await this.#read(callId)).modules[trace.TRACE] as unknown as trace.TraceSlice;
    return slice.receipt === null ? null : structuredClone(slice.receipt);
  }

  // ---- subject requests (the business's, never a call's) -----------------------------------

  /**
   * An access request: what the engine stored about one subject, signed as a subject export
   * (never verifiable as a receipt). `kept` lists what the business must keep by law, with why.
   */
  exportSubject(input: subject.SubjectRequest & { kept?: subject.KeptItem[] }): Promise<subject.SignedSubjectExport> {
    return subject.exportSubject(this.#rt, input);
  }

  /**
   * A deletion request: the subject's intake records, PIN and duress PIN digests and the counters
   * kept under their key go; the ledger and receipts stay whole.
   */
  eraseSubject(input: subject.SubjectRequest): Promise<subject.ErasureResult> {
    const counters = { counters: this.#adapters.counters, factors: this.#badge.manifest.provides.factors };
    return subject.eraseSubject(this.#rt, input, (callId, recordIds) => dossier.forgetRecords(this.#rt, callId, recordIds), counters);
  }

  /** The key set for verifying this engine's receipts: with a key ring, the retired keys too (empty without a signer). */
  receiptKeys(): JsonWebKey[] {
    const signer = this.#adapters.signer;
    if (signer === undefined) return [];
    // A single signer: the published `kid` is the one every receipt carries (its keyId), whatever its JWK says.
    if (typeof (signer as { keySet?: unknown }).keySet !== "function") return [{ ...publicMembers(signer.publicJwk()), kid: signer.keyId } as JsonWebKey];
    // A key ring's whole history, each key under its own kid: only public members (#47's check), and a retired key's retiredAt.
    return receiptKeySet(signer).map((jwk) => ({ ...publicMembers(jwk), ...((jwk as { retiredAt?: string }).retiredAt === undefined ? {} : { retiredAt: (jwk as { retiredAt?: string }).retiredAt }) }) as JsonWebKey);
  }

  // ---- outside modules ---------------------------------------------------------------------

  /** An outside module's part of a call. */
  async moduleState(callId: string, name: string): Promise<JsonValue> {
    this.#outsideModule(name);
    return structuredClone(this.#slice((await this.#read(callId)).modules, name));
  }

  /**
   * Changes an outside module's part of a call, in one compare-and-set write (retried on conflict,
   * so `fn` must be pure). A running flow moves on when the module's step completes. The engine
   * holds every call to the module's scopes, so a module that forgets to ask `authorized` still
   * fails closed: in a flow, the scope its current step needs; outside a flow, every scope its
   * manifest names. Built-in modules (Gate's grants included) are never reachable here.
   */
  async updateModule(callId: string, name: string, fn: (slice: JsonValue, call: ModuleCallView) => JsonValue): Promise<JsonValue> {
    this.#outsideModule(name);
    const module = this.registry.get(name)!;
    const out = await this.#update(callId, (draft): { refused: EngineError } | { next: JsonValue } => {
      assertFlowNotEnded(draft.record);
      const step = draft.step();
      if (step !== null && !module.manifest.provides.steps.includes(step.type)) {
        throw new EngineError("precondition_failed", `the flow is on step ${step.type}, not a step of ${name}`);
      }
      const needs = step === null ? Object.values(module.manifest.scopes.needs) : [module.manifest.scopes.needs[step.type]].filter((n) => n !== undefined);
      // Held at the minimum the step-up rules raise each scope to for the step's amount (VER-13).
      for (const scope of needs) {
        const refused = this.#requireScope(draft, scope, stepAmount(step));
        if (refused !== null) return { refused };
      }
      return { next: this.#applyModule(draft, name, fn) };
    });
    if ("refused" in out) throw out.refused;
    return out.next;
  }

  #applyModule(draft: CallDraft, name: string, fn: (slice: JsonValue, call: ModuleCallView) => JsonValue): JsonValue {
    const step = draft.step();
    const view: ModuleCallView = {
      state: snapshot(draft.record.state),
      step: step === null ? null : structuredClone(step),
      now: this.#now(),
      newId: (prefix) => this.#ids.next(prefix),
      authorized: (scope) => this.#authorized(draft.record, scope),
      emit: (event, detail) => draft.emit("module.event", "code", { module: name, event, detail }),
      contactChanged: () => trace.noteAction(draft, "contact", badge.matchedSubject(draft.record)),
    };
    const next = fn(structuredClone(this.#slice(draft.record.modules, name)), view);
    draft.record.modules[name] = structuredClone(next);
    return structuredClone(next);
  }

  // ---- internals ---------------------------------------------------------------------------

  #runtime(): EngineRuntime {
    const config = (): FlowConfig => this.#config;
    return {
      workspaceId: this.workspaceId,
      clock: this.#clock,
      ids: this.#ids,
      get policy() {
        return config().policy;
      },
      get revision() {
        return config().revision;
      },
      now: () => this.#now(),
      hmac: this.#hmac,
      settings: <T>(name: string): T => {
        if (!this.isEnabled(name)) throw new EngineError("module_disabled", `the ${name} module is turned off`);
        return this.#config.modules[name]?.settings as T;
      },
      // validateConfig refused any config whose modules need an adapter the engine lacks.
      adapter: <K extends AdapterName>(name: K) => this.#adapters[name]!,
      update: (callId, fn) => this.#update(callId, fn),
      read: (callId) => this.#read(callId),
      append: (entry) => this.#append(entry),
      flushLedger: (callId) => this.flushLedger(callId),
      authorized: (record, scope, amount) => this.#authorized(record, scope, amount),
      requireScope: (draft, scope, amount) => this.#requireScope(draft, scope, amount),
      bindRef: async (ref, callId) => {
        await this.#sessions.bindRef(this.workspaceId, ref, callId);
      },
      resolveRef: (ref) => this.#sessions.resolveRef(this.workspaceId, ref),
      idempotencyKey: (callId, ...parts) => JSON.stringify([this.workspaceId, callId, ...parts]),
    };
  }

  /** A copy of a config, checked. A value that is not plain data is a config problem too. */
  #prepare(config: unknown): FlowConfig {
    let copy: unknown;
    try {
      copy = structuredClone(config);
    } catch {
      throw new ConfigError(["the config must be plain JSON data"]);
    }
    const checked = assertConfig(copy, this.registry);
    // The starts of flows that need a money, contact or access scope are counted (VER-15), even
    // when no factor the caller enters is on to make Badge ask for the counters itself.
    if (this.#adapters.counters === undefined) {
      const problems = Object.entries(checked.flows)
        .filter(([, flow]) => this.#limited(flow.steps, checked.policy))
        .map(([name]) => `flows.${name}: needs the counters adapter: it needs a money, contact or access scope, so its starts are limited`);
      if (problems.length > 0) throw new ConfigError(problems);
    }
    return checked;
  }

  #outsideModule(name: string): void {
    if ((BUILT_IN_MODULES as readonly string[]).includes(name)) throw new EngineError("precondition_failed", `${name} is built in; use its own methods`);
    if (!this.isEnabled(name)) throw new EngineError("module_disabled", `the ${name} module is turned off`);
  }

  #slice(modules: Record<string, JsonValue>, name: string): JsonValue {
    const slice = modules[name];
    if (slice === undefined) throw new EngineError("module_disabled", `${name} was off when this call started`);
    return slice;
  }

  #flowDefinition(name: string): FlowConfig["flows"][string] {
    const definition = Object.hasOwn(this.#config.flows, name) ? this.#config.flows[name] : undefined;
    if (definition === undefined) throw new EngineError("invalid_input", `no flow named ${name} in the config`);
    return definition;
  }

  #now(): string {
    return this.#clock.now().toISOString();
  }

  #authorized(record: CallRecord, scope: string, amount?: StepUpAmount | null): boolean {
    return this.#cover(record, scope, amount).ok;
  }

  /**
   * Whether the call's grant covers a scope now (`ok`), the step-up rules that raised its minimum
   * (`applied`), and, when not covered, the rules the grant falls short of (`rules`; empty when
   * the grant would not cover the scope anyway). Inside a change, a rule applied for the first time
   * on the call is written to the ledger by name, never with the amount, the time or the signal.
   * `amount` left out is the current step's; null skips amount rules (nothing is asked yet).
   */
  #cover(record: CallRecord, scope: string, amount: StepUpAmount | undefined | null = stepAmount(currentStep(record))): { ok: boolean; applied: string[]; rules: string[] } {
    const policy = this.#config.policy;
    const min: AssuranceLevel | undefined = Object.hasOwn(policy.scopes, scope) ? policy.scopes[scope] : undefined;
    if (min === undefined || record.state.phase === "ended") return { ok: false, applied: [], rules: [] };
    // A duress call (VER-12) refuses money, contact and access, and the scopes Badge's settings named, as if ungranted.
    if (badge.duressRefuses(record, scope, scopeClass(scope, policy.scopeClasses, this.registry.scopeClasses()))) return { ok: false, applied: [], rules: [] };
    const now = this.#clock.now();
    const raised = raiseMinimum(policy, scope, { amount, at: now, signals: record.signals ?? [] });
    const draft = this.#drafts.get(record);
    for (const rule of raised.rules) {
      const ledgered = (record.stepUps ??= []);
      if (draft === undefined || ledgered.includes(rule.name)) continue;
      ledgered.push(rule.name);
      draft.emit("policy.step_up", "code", { rule: rule.name, scope, level: rule.level });
    }
    const applied = raised.rules.map((rule) => rule.name);
    if (raised.level === 0) return { ok: true, applied, rules: [] };
    const grant = record.state.grant;
    // The grant's level is checked against today's minimum, raised for this request, and today's
    // attestation cap, so a stricter config or a step-up rule applies to grants already issued.
    const reached = grant !== null && grant.scopes.includes(scope) && now.getTime() < Date.parse(grant.expiresAt) ? capCallLevel(policy, grant.level, record) : 0;
    if (reached >= raised.level) return { ok: true, applied, rules: [] };
    return { ok: false, applied, rules: reached < min ? [] : raised.rules.filter((rule) => rule.level > reached).map((rule) => rule.name) };
  }

  async #read(callId: string): Promise<CallRecord> {
    const stored = await this.#sessions.get(this.workspaceId, callId);
    if (stored === null) throw new EngineError("unknown_call", "no such call");
    return structuredClone(stored.record) as unknown as CallRecord;
  }

  async #update<R>(callId: string, fn: (draft: CallDraft) => R, outcome: WriteOutcome = { write: "none" }): Promise<R> {
    for (let attempt = 0; attempt < MAX_WRITE_ATTEMPTS; attempt++) {
      const stored = await this.#sessions.get(this.workspaceId, callId);
      if (stored === null) throw new EngineError("unknown_call", "no such call");
      const record = structuredClone(stored.record) as unknown as CallRecord;
      const events: QueuedEvent[] = [];
      const draft = this.#draft(record, events);
      const result = fn(draft);
      this.#advance(draft);
      // The step's ledger entries are saved with the step, then appended: a ledger that fails
      // leaves them in the record, and the next write (or flushLedger) appends them, once each.
      const version = stored.version + 1;
      // Entries are numbered by the writes that queue them, not by the store's version, so a write
      // with none (a duress alert's acknowledgement, VER-12) leaves no gap a ledger reader could see.
      // A record from before the count continues from its version (its ids are tagged, so they
      // could not meet the older ones anyway; continuing keeps the numbers going up).
      if (events.length > 0) record.ledgerWrites = (record.ledgerWrites ?? stored.version) + 1;
      record.outbox.push(...(await Promise.all(events.map((event, i) => this.#outboxEntry(callId, record.ledgerWrites!, i, event)))));
      markOwedAlerts(record);
      outcome.write = "unknown";
      const saved = await this.#sessions.compareAndSet(this.workspaceId, callId, stored.version, record as unknown as JsonValue);
      outcome.write = saved.ok ? "saved" : "none";
      if (saved.ok) {
        // Saved, so owed duress alerts go out before the ledger is tried: one down or stalled never holds them.
        this.#sendDuressAlertsSoon(callId, record);
        await this.#flush(callId, version, record);
        // An alert owed (a contact change notice) is sent once its debt is saved, on this write or
        // the next one on the call; a failure leaves it owed for the next write, endCall or sweepAlerts.
        if (trace.noticeDue(record)) await this.#deliverAlerts(callId).catch(() => false);
        return result;
      }
    }
    throw new EngineError("conflict", `the call changed under every one of ${MAX_WRITE_ATTEMPTS} attempts`);
  }

  #draft(record: CallRecord, events: QueuedEvent[]): CallDraft {
    const draft: CallDraft = {
      record,
      slice: <T>(name: string): T => this.#slice(record.modules, name) as unknown as T,
      apply: (event) => {
        record.state = reduce(record.state, event);
      },
      assertCan: (event) => {
        if (!canApply(record.state, event)) throw new EngineError("invalid_transition", `${event.type} is not allowed while ${record.state.phase}`);
      },
      emit: (name, actor, detail, tag) => {
        // A copy, checked here, inside the step, so an entry the ledger would refuse is never saved
        // to be appended later, and a caller changing its object afterwards changes nothing.
        const copy = structuredClone(detail);
        if (detailCarriesCardNumber(copy)) throw new EngineError("invalid_input", "audit detail must never carry a card number");
        // The ledger hashes the entry as canonical JSON after the step is saved: a detail it would
        // refuse (a lone surrogate, a Date) is refused here, or it would block every later write.
        try {
          canonicalJson(copy);
        } catch {
          throw new EngineError("invalid_input", "audit detail must be canonical JSON: plain data, no lone surrogate");
        }
        const event: QueuedEvent = { name, actor, at: this.#now(), detail: copy, tag };
        if (name === "verification.locked") event.counter = this.#lockedCounter(record, copy);
        events.push(event);
      },
      step: () => currentStep(record),
    };
    this.#drafts.set(record, draft);
    return draft;
  }

  /** Moves a running flow past every step that is now complete, and stops it on a failed one. */
  #advance(draft: CallDraft): void {
    const record = draft.record;
    const flow = record.flow;
    while (flow !== null && flow.status === "running") {
      const step = flow.steps[flow.index]!;
      // A module removed while the call ran fails its step. Slices exist for every module a flow uses (startFlow).
      const owner = this.registry.stepOwner(step.type);
      const status = owner === undefined ? "failed" : owner.stepStatus(step, { state: record.state, slice: record.modules[owner.manifest.name]!, mark: flow.mark });
      if (status === "pending") return;
      const detail = { flow: flow.name, step: flow.index, type: step.type };
      if (status === "failed") {
        flow.status = "failed";
        draft.emit("flow.failed", "code", detail);
        return;
      }
      draft.emit("flow.step_completed", "code", detail);
      // A money, contact or access step is what a receipt text names, and a contact one owes a notice.
      // Such a step follows a level 2 verification, which a keypad or PIN match always unlocked:
      // matchedSubject fails closed if that ever did not hold.
      const action = this.#actionClass(owner!, step.type);
      if (action !== null) trace.noteAction(draft, action, badge.matchedSubject(record));
      flow.index++;
      const next = flow.steps[flow.index];
      if (next === undefined) {
        flow.status = "completed";
        draft.emit("flow.completed", "code", { flow: flow.name, steps: flow.steps.length });
        return;
      }
      const nextOwner = this.registry.stepOwner(next.type);
      flow.mark = nextOwner === undefined ? null : nextOwner.enterStep(next, record.modules[nextOwner.manifest.name]!);
      this.#holdStep(draft);
    }
  }

  /**
   * Fails the running flow's current step when step-up rules raise the scope it needs above what
   * the call's verification reached (VER-13). A flow cannot branch to ask for more (ADR-14), so it
   * stops there, naming the rules. Checked when a step is entered and when a signal is raised; the
   * step's own work checks again (`#requireScope`), for the time of day.
   */
  #holdStep(draft: CallDraft): void {
    const step = draft.step();
    if (step === null) return;
    const scope = this.registry.stepOwner(step.type)?.manifest.scopes.needs[step.type];
    if (scope === undefined) return;
    const { rules } = this.#cover(draft.record, scope, stepAmount(step));
    if (rules.length > 0) this.#failStep(draft, rules);
  }

  #failStep(draft: CallDraft, rules: string[]): void {
    const flow = draft.record.flow!;
    // Only a running flow has a current step to fail (both callers checked it is on one).
    flow.status = "failed";
    draft.emit("flow.failed", "code", { flow: flow.name, step: flow.index, type: flow.steps[flow.index]!.type, rules });
  }

  /** See `EngineRuntime.requireScope`. */
  #requireScope(draft: CallDraft, scope: string, amount: StepUpAmount | undefined | null): EngineError | null {
    const { ok, applied, rules } = this.#cover(draft.record, scope, amount);
    if (ok) return null;
    if (rules.length === 0) {
      // A denial no rule affects throws at once. When a rule applies, the refusal is returned, so
      // the change is saved and a rule applied for the first time stays on the ledger. The flow is
      // not failed: without the rule the grant would not cover the scope either.
      if (applied.length === 0) throw new EngineError("scope_denied", `the grant does not cover ${scope}`);
      return new EngineError("scope_denied", `the grant does not cover ${scope}; the step-up rule(s) ${applied.join(", ")} also apply`);
    }
    if (currentStep(draft.record) !== null) this.#failStep(draft, rules);
    return new EngineError("scope_denied", `the grant does not cover ${scope} at the level the step-up rule(s) ${rules.join(", ")} require`);
  }

  /** Calls whose alerts are being sent by this engine now, so sending (which writes) does not send again. */
  readonly #delivering = new Set<string>();

  /** Sends the call's owed alerts; false when this engine is already sending them (that send finishes them). */
  async #deliverAlerts(callId: string): Promise<boolean> {
    if (this.#delivering.has(callId)) return false;
    this.#delivering.add(callId);
    try {
      await trace.sendContactNotice(this.#rt, callId);
      return true;
    } finally {
      this.#delivering.delete(callId);
    }
  }

  /** The class of the scope a step needs when it is money, contact or access, else null. */
  #actionClass(owner: AssuranceModule, type: string): trace.ActionClass | null {
    const scope = owner.manifest.scopes.needs[type];
    if (scope === undefined) return null;
    const cls = scopeClass(scope, this.#config.policy.scopeClasses, this.registry.scopeClasses());
    return cls === "none" || cls === null ? null : cls;
  }

  /**
   * The subject Badge holds now, and the number texts may go to: its number on file, as Badge read
   * it when verification started, or null when no keypad or PIN match stands (a later verification
   * started from nothing). Only asked about a call whose flow completed a scoped step, so Badge's
   * part exists.
   */
  #currentSubject(record: CallRecord): { subjectKey: string | null; numberOnFile: string | null } {
    const s = record.modules[badge.BADGE] as unknown as badge.BadgeSlice;
    return { subjectKey: s.subject?.subjectKey ?? null, numberOnFile: s.knowledgeMatched ? s.subject!.phoneOnFile : null };
  }

  /**
   * Appends a call's pending ledger entries in order, each with its event id (a ledger appends an
   * id once), then clears them from the record if nobody wrote since. A failed append throws and
   * leaves the rest pending; a lost clear leaves them for the next write, which appends nothing twice.
   */
  async #flush(callId: string, version: number, record: CallRecord): Promise<void> {
    if (record.outbox.length === 0) return;
    for (const queued of record.outbox) {
      await this.#append({ eventId: queued.eventId, callId, actor: queued.actor, event: queued.name, at: queued.at, detail: queued.detail });
      // Not awaited: a notice store that stalls holds up neither the rest of the outbox nor the call. It never rejects.
      if (queued.counter !== undefined) void this.#notifyLock(queued.counter, queued.detail);
    }
    await this.#sessions.compareAndSet(this.workspaceId, callId, version, { ...record, outbox: [] } as unknown as JsonValue);
  }

  /** Appends one entry, then tells the listener. */
  async #append(entry: AuditInput & { callId: string }): Promise<void> {
    await this.#adapters.ledger.append(entry);
    // A listener is told, at least once and best effort; its failure, thrown or rejected, never stops the ledger (INT-5).
    try {
      const told: unknown = this.#onEvent?.({ name: entry.event, callId: entry.callId, actor: entry.actor, at: entry.at, detail: entry.detail });
      if (told instanceof Promise) told.catch(() => undefined);
    } catch {
      // Ignored by design: the ledger is the record.
    }
  }

  /**
   * The counter a `verification.locked` entry is about, read from the call as the entry is saved,
   * so the notice names the subject or number of that verification. Badge writes the entry only
   * for a counter it counted, so the key for its scope is set.
   */
  #lockedCounter(record: CallRecord, detail: { [key: string]: JsonValue }): AttemptCounterKey {
    const s = record.modules[badge.BADGE] as unknown as badge.BadgeSlice;
    const scope = detail.scope as AttemptCounterKey["scope"];
    return { workspaceId: this.workspaceId, factor: detail.kind as string, scope, key: (scope === "subject" ? s.subjectKey : s.numberKey)! };
  }

  /**
   * Tells the host's notifier of a lock whose ledger entry was just appended: once per lock and
   * capped per workspace (`claimNotice`, before the notifier). Best effort, like the listener: neither
   * it nor the notifier is awaited, and nothing either does, thrown or rejected, stops the call or the ledger.
   */
  async #notifyLock(counter: AttemptCounterKey, detail: { [key: string]: JsonValue }): Promise<void> {
    const notifier = this.#adapters.notifier;
    if (notifier === undefined) return;
    try {
      const until = detail.until as string;
      const hard = detail.hard as boolean;
      const claim = await claimNotice(this.#adapters.counters!, counter, until, this.#clock.now(), hard);
      if (claim === null) return;
      const notice = { ...counter, hard, until, capped: claim.capped };
      // An async wrapper turns a notifier that throws at once into a rejection, caught like the rest.
      void (async () => notifier.lockout(notice))().catch(() => undefined);
    } catch {
      // Ignored by design: the ledger is the record.
    }
  }

  /**
   * A queued event as the outbox keeps it, with its event id. A tagged event (a PIN factor, VER-12)
   * gets its keyed `tag` here, now that its id is known; the outcome itself is never kept.
   */
  async #outboxEntry(callId: string, version: number, index: number, queued: QueuedEvent): Promise<CallRecord["outbox"][number]> {
    const { tag, ...event } = queued;
    const eventId = this.#eventId(callId, version, index);
    if (tag !== undefined) event.detail = { ...event.detail, tag: await pinTag(this.#hmac, eventId, tag as PinOutcome) };
    return { eventId, ...event };
  }

  /**
   * A ledger event id, unique across workspaces sharing one ledger: a JSON tuple, so no two ids
   * collide. `write` counts the call's writes that queued entries (VER-12); the tag "w" gives these
   * ids a shape of their own, so they never equal the `[workspaceId, callId, version, index]` ids an
   * older build writes on the same call during a rolling deploy (the ledger would drop one as a replay).
   */
  #eventId(callId: string, write: number, index: number): string {
    return JSON.stringify([this.workspaceId, callId, "w", write, index]);
  }

  /** Appends any ledger entries a call still has pending (after a ledger outage), and sends any owed duress alert. Every write does this too. */
  async flushLedger(callId: string): Promise<void> {
    const stored = await this.#sessions.get(this.workspaceId, callId);
    if (stored === null) throw new EngineError("unknown_call", "no such call");
    const record = structuredClone(stored.record) as unknown as CallRecord;
    this.#sendDuressAlertsSoon(callId, record);
    await this.#flush(callId, stored.version, record);
  }

  /**
   * Sends a call's owed duress alerts (VER-12) and waits for them: the host's sweep, for calls whose
   * alert may still be owed (a notifier that was down, a process that stopped). Answers how many the
   * notifier acknowledged now. An alert another send of this engine has in hand is left to it.
   */
  async deliverDuressAlerts(callId: string): Promise<number> {
    return this.#sendDuressAlerts(callId);
  }

  /**
   * Sends the alerts every call of this workspace still owes (VER-12 duress alerts, PRV-10 contact
   * change notices), ended or not, for a host after a crash or on a schedule, without knowing the
   * call ids: the session store lists them
   * (`listCallsOwingAlerts`). `sent`: calls that owe nothing now; `failed`: calls that still owe one.
   */
  async sweepAlerts(): Promise<{ sent: string[]; failed: string[] }> {
    const list = this.#sessions.listCallsOwingAlerts?.bind(this.#sessions);
    if (list === undefined) throw new EngineError("precondition_failed", "the session store cannot list the calls that owe alerts (listCallsOwingAlerts)");
    const callIds = await list(this.workspaceId);
    // Every call's send starts at once, so a notifier that never answers for one does not hold up the rest.
    const owed = await Promise.all(
      callIds.map(async (callId) => {
        try {
          // One outbox for both kinds (#112's contact notices, #124's duress alerts): the index lists a
          // call while it owes either (decision 8).
          await this.#deliverAlerts(callId);
          await this.#sendDuressAlerts(callId);
          const now = await this.#read(callId);
          return badge.owedDuressAlerts(now).length > 0 || trace.noticeDue(now);
        } catch {
          // A call the store cannot read now, or no longer holds, is reported, and the sweep goes on.
          return true;
        }
      }),
    );
    return { sent: callIds.filter((_, i) => !owed[i]), failed: callIds.filter((_, i) => owed[i]) };
  }

  /** Off the caller's response path: after the reply, so neither the notifier's time nor its failure reaches the caller. */
  #sendDuressAlertsSoon(callId: string, record: CallRecord): void {
    if (badge.owedDuressAlerts(record).length === 0) return;
    // A write that owes the same alerts as a send already scheduled and not yet started (a pass's
    // counters cleanup right after the entry, VER-1) shares that send, which reads the call's owed
    // alerts again when it runs; a write that owes a new alert schedules its own.
    const owed = JSON.stringify(badge.owedDuressAlerts(record).map((alert) => alert.alertId));
    if (this.#sendScheduled.get(callId) === owed) return;
    this.#sendScheduled.set(callId, owed);
    setImmediate(() => {
      if (this.#sendScheduled.get(callId) === owed) this.#sendScheduled.delete(callId);
      void this.#sendDuressAlerts(callId).catch(() => undefined);
    });
  }

  /**
   * Each alert the stored call owes now (read again, so an alert already acknowledged is not sent
   * twice), one send at a time per engine (again after 30 seconds without an answer), taken off the
   * record once acknowledged.
   */
  async #sendDuressAlerts(callId: string): Promise<number> {
    const notifier = this.#adapters.duressNotifier;
    let delivered = 0;
    for (const alert of badge.owedDuressAlerts(await this.#read(callId))) {
      const now = this.#clock.now().getTime();
      const since = this.#sending.get(alert.alertId);
      if (notifier === undefined || (since !== undefined && now - since < 30_000)) continue;
      this.#sending.set(alert.alertId, now);
      try {
        // The flag goes with the alert: set again here, before the notifier, in case the entry's own
        // write of it was lost (a failed store, a crash), unless the business cleared the subject
        // after the entry was judged. An engine that judged an entry has counters (Badge requires
        // them for every entered factor), and one without them fails here, leaving the alert owed.
        const counters = this.#adapters.counters!;
        if ((await clearsSoFar(counters, this.workspaceId, alert.subjectKey)) === alert.clears) {
          await flagDuress(counters, duressFlagKey(this.workspaceId, alert.subjectKey), new Date(alert.at));
        }
        await notifier.notify({ alertId: alert.alertId, workspaceId: this.workspaceId, subjectKey: alert.subjectKey, callId, at: alert.at });
        await this.#acknowledgeDuressAlert(callId, alert.alertId);
        delivered++;
      } catch {
        // Still owed: the next write, flushLedger or deliverDuressAlerts sends it again.
      } finally {
        this.#sending.delete(alert.alertId);
      }
    }
    return delivered;
  }

  /** Takes a delivered alert off the call record, in its own compare-and-set write, with no ledger entry. */
  async #acknowledgeDuressAlert(callId: string, alertId: string): Promise<void> {
    for (let attempt = 0; attempt < MAX_WRITE_ATTEMPTS; attempt++) {
      const stored = (await this.#sessions.get(this.workspaceId, callId))!;
      const record = structuredClone(stored.record) as unknown as CallRecord;
      badge.acknowledgeDuressAlert(record, alertId);
      markOwedAlerts(record);
      if ((await this.#sessions.compareAndSet(this.workspaceId, callId, stored.version, record as unknown as JsonValue)).ok) return;
    }
    throw new EngineError("conflict", `the call changed under every one of ${MAX_WRITE_ATTEMPTS} attempts`);
  }
}

/**
 * The receipt, access and step-up signers must each be their own key: a receipt must never verify
 * as an access grant or a step-up token, nor any of them as another. Refused by key id and by
 * public key, for every pair the engine has.
 */
function distinctSigners(adapters: EngineAdapters): string[] {
  // Compared as key material, not text: one key can be written with or without padding, in either
  // base64 alphabet. A key that does not import is left for its signer to fail on.
  const der = (jwk: JsonWebKey) => {
    try {
      return createPublicKey({ key: jwk, format: "jwk" }).export({ type: "spki", format: "der" });
    } catch {
      return null;
    }
  };
  const named: Array<[string, ReceiptSigner | undefined]> = [
    ["receipt signer", adapters.signer],
    ["accessSigner", adapters.accessSigner],
    ["stepUpSigner", adapters.stepUpSigner],
  ];
  const present = named.filter((n): n is [string, ReceiptSigner] => n[1] !== undefined);
  const errors: string[] = [];
  present.forEach(([later, b], j) => {
    for (const [earlier, a] of present.slice(0, j)) {
      if (a.keyId === b.keyId) {
        errors.push(`${later} must have its own key id, not the ${earlier}'s`);
        continue;
      }
      const x = der(a.publicJwk());
      const y = der(b.publicJwk());
      if (x !== null && y !== null && x.equals(y)) errors.push(`${later} must be its own key, not the ${earlier}'s`);
    }
  });
  return errors;
}

/**
 * Only the public members of an EC key, whatever a signer's `publicJwk` returns: a signer that
 * hands back its private `d` (or anything else) never has it published in a key set.
 */
function publicMembers(jwk: JsonWebKey & { kid?: string }): JsonWebKey {
  const kept: Record<string, unknown> = {};
  for (const name of ["kty", "crv", "x", "y", "kid", "alg", "use"] as const) {
    if (jwk[name as keyof typeof jwk] !== undefined) kept[name] = jwk[name as keyof typeof jwk];
  }
  return kept as JsonWebKey;
}

/** The subject Badge matched on a call (a keypad or PIN match), or null: what an intake record or a consent is filed under. */
function matchedSubjectKey(record: CallRecord): string | null {
  const slice = record.modules[badge.BADGE] as unknown as badge.BadgeSlice | undefined;
  // A keypad or PIN factor passes only against a subject on file, so a match always has one.
  return slice?.knowledgeMatched === true ? slice.subject!.subjectKey : null;
}

export function createEngine(options: EngineOptions): Engine {
  return new Engine(options);
}

/**
 * markUntrusted's label as Unicode text with any card number removed (the ledger refuses detail
 * that carries one, and the taint must land); a value that will not turn into a string is labelled
 * "unlabelled".
 */
function untrustedLabel(source: unknown): string {
  let text: string;
  try {
    text = String(source).toWellFormed();
  } catch {
    return "unlabelled";
  }
  return cardNumberRedactor.redact(text).text;
}

/** Marks a record that owes an alert, so a session store can list it for a sweep, and unmarks one that does not. */
function markOwedAlerts(record: CallRecord): void {
  if (badge.owedDuressAlerts(record).length > 0 || trace.noticeDue(record)) record.owesAlerts = true;
  else delete record.owesAlerts;
}
