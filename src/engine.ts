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

import type { IntakeRecord, ReceiptSigner, SessionStore } from "./core/adapters.ts";
import type { JsonValue } from "./core/canonical.ts";
import { randomIds, systemClock, type Clock, type IdGenerator } from "./core/clock.ts";
import { ConfigError, assertConfig, moduleEnabled, type FlowConfig } from "./core/config.ts";
import { EngineError, NotImplementedError } from "./core/errors.ts";
import { assertFlowNotEnded, currentStep } from "./core/flow.ts";
import type { Actor, EngineEventName, EventListener } from "./core/events.ts";
import { hmacSha256Hex } from "./core/hash.ts";
import { ModuleRegistry, type AssuranceModule, type FlowStep } from "./core/module.ts";
import type { AssuranceLevel, VerificationPolicy } from "./core/policy.ts";
import { cardNumberRedactor, type RedactionFinding, type Redactor } from "./core/redaction.ts";
import type { AdapterName, CallDraft, CallRecord, EngineAdapters, EngineRuntime, FlowStatus, Locale } from "./core/runtime.ts";
import { MemorySessionStore } from "./core/session-store.ts";
import { canApply, newSession, reduce, snapshot, type SensitiveReason, type SessionState } from "./core/session.ts";
import * as dossier from "./file/dossier.ts";
import * as gate from "./gate/gate.ts";
import * as stepUp from "./gate/step-up.ts";
import type { NormaliseResult } from "./file/intake.ts";
import { BUILT_IN_MODULES, builtInModules, defaultConfig } from "./modules.ts";
import * as paylink from "./pay/paylink.ts";
import type { PaymentOutcome, PaymentStatus } from "./pay/payment.ts";
import type { ConsentRecord } from "./prove/consent.ts";
import { detailCarriesCardNumber } from "./prove/ledger.ts";
import type { ReceiptBody, SignedReceipt } from "./prove/receipt.ts";
import * as trace from "./prove/trace.ts";
import * as badge from "./verify/badge.ts";
import type { FactorEntry, FactorPlugin } from "./verify/factors.ts";
import type { IdentityOutcome } from "./webhooks/stripe.ts";

export type { EngineAdapters, Locale } from "./core/runtime.ts";
export type { KeypadResult, OutcomeResult, VerificationResult } from "./verify/badge.ts";


/** Writes per step before the engine gives up with `conflict`. */
export const MAX_WRITE_ATTEMPTS = 5;

export interface EngineOptions {
  workspaceId: string;
  /** The per-workspace HMAC key for knowledge factors and PINs. At least 16 bytes. */
  knowledgeKey: string | Uint8Array;
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
}

interface QueuedEvent {
  name: EngineEventName;
  actor: Actor;
  at: string;
  detail: { [key: string]: JsonValue };
}

export class Engine {
  readonly workspaceId: string;
  readonly registry: ModuleRegistry;
  readonly #key: string | Uint8Array;
  readonly #adapters: EngineAdapters;
  readonly #sessions: SessionStore;
  readonly #clock: Clock;
  readonly #ids: IdGenerator;
  readonly #redactor: Redactor;
  readonly #onEvent: EventListener | undefined;
  readonly #badge: badge.BadgeModule;
  readonly #rt: EngineRuntime;
  readonly #receiptModules: readonly AssuranceModule[];
  #config: FlowConfig;

  constructor(options: EngineOptions) {
    const errors: string[] = [];
    const keyLength = typeof options.knowledgeKey === "string" ? Buffer.byteLength(options.knowledgeKey) : options.knowledgeKey.byteLength;
    if (keyLength < 16) errors.push("knowledgeKey must be at least 16 bytes");
    if (options.workspaceId === "") errors.push("workspaceId is empty");
    if ((options.adapters as Partial<EngineAdapters>).ledger === undefined) errors.push("the ledger adapter is required: the ledger is always on");
    errors.push(...distinctSigners(options.adapters));
    for (const module of options.modules ?? []) {
      if ((BUILT_IN_MODULES as readonly string[]).includes(module.manifest.name)) errors.push(`${module.manifest.name} is the name of a built-in module`);
    }
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    this.workspaceId = options.workspaceId;
    this.#key = options.knowledgeKey;
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
    this.registry = new ModuleRegistry({ adapters: present, capabilities, modules: [...this.#receiptModules, ...(options.modules ?? [])] });
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

  /** Installs an outside module. It stays off until a config turns it on. */
  use(module: AssuranceModule): this {
    // A built-in module's name stays the engine's, even after the module was removed: a host's
    // module can never stand in for Gate's grants or Paylink's payments.
    if ((BUILT_IN_MODULES as readonly string[]).includes(module.manifest.name)) {
      throw new EngineError("invalid_input", `${module.manifest.name} is the name of a built-in module`);
    }
    this.registry.use(module);
    return this;
  }

  /**
   * Adds a Badge factor plug-in after the engine was built. Planned (MOD-3): today plug-ins are
   * given at construction, with `badge: badgeModule({ factors })`.
   */
  useFactor(_plugin: FactorPlugin): never {
    throw new NotImplementedError("Engine.useFactor", "MOD-3");
  }

  /** Uninstalls a module that the config has turned off. The ledger's module cannot be removed. */
  remove(name: string): void {
    if (moduleEnabled(this.#config, this.registry, name) && this.registry.get(name)?.manifest.alwaysOn !== true) {
      throw new EngineError("precondition_failed", `${name} is on in the config; turn it off first`);
    }
    this.registry.remove(name);
  }

  isEnabled(name: string): boolean {
    return moduleEnabled(this.#config, this.registry, name);
  }

  // ---- sessions ----------------------------------------------------------------------------

  /** Opens a call. With `flow`, the call runs that flow from its first step. */
  async startCall(input: { callId?: string; locale?: Locale; flow?: string } = {}): Promise<SessionState> {
    const callId = input.callId ?? this.#ids.next("call");
    const modules: Record<string, JsonValue> = {};
    for (const module of this.registry.list()) {
      const name = module.manifest.name;
      if (this.isEnabled(name)) modules[name] = module.initCall(this.#config.modules[name]?.settings);
    }
    const record: CallRecord = {
      v: 1,
      state: newSession(callId, this.workspaceId, this.#now()),
      locale: input.locale ?? "en",
      revision: this.#config.revision,
      flow: null,
      modules,
      outbox: [],
    };
    // A call started with a flow is created with it attached, so no other process can start a
    // different flow on the same id in between.
    const events: QueuedEvent[] = [{ name: "call.started", actor: "system", at: this.#now(), detail: { locale: record.locale, revision: record.revision } }];
    if (input.flow !== undefined) {
      const draft = this.#draft(record, events);
      this.#attachFlow(draft, input.flow, this.#flowDefinition(input.flow), this.#config.revision);
      this.#advance(draft);
    }
    record.outbox = events.map((event, i) => ({ eventId: this.#eventId(callId, 1, i), ...event }));
    const created = await this.#sessions.create(this.workspaceId, callId, record as unknown as JsonValue);
    if (!created) throw new EngineError("invalid_input", "a call with that id exists");
    await this.#flush(callId, 1, record);
    return this.state(callId);
  }

  async state(callId: string): Promise<SessionState> {
    return snapshot((await this.#read(callId)).state);
  }

  /** Untrusted text (a business webhook reply, a document) entered the conversation. */
  async markUntrusted(callId: string, source: string): Promise<void> {
    await this.#update(callId, (draft) => {
      draft.apply({ type: "untrusted_content", source });
      for (const module of this.registry.list()) {
        const name = module.manifest.name;
        const slice = draft.record.modules[name];
        if (module.onUntrusted !== undefined && slice !== undefined) draft.record.modules[name] = module.onUntrusted(slice);
      }
      draft.emit("session.tainted", "code", { source });
    });
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
   * Redacts text before the host stores or forwards it. `interrupt` tells the host to speak its
   * fixed "please don't read card numbers" line.
   */
  async redact(callId: string, text: string): Promise<{ text: string; findings: RedactionFinding[]; interrupt: boolean }> {
    const result = this.#redactor.redact(text);
    if (result.findings.length === 0) {
      await this.#read(callId);
    } else {
      const kinds: Record<string, number> = {};
      for (const f of result.findings) kinds[f.kind] = (kinds[f.kind] ?? 0) + 1;
      await this.#update(callId, (draft) => draft.emit("redaction.applied", "code", { kinds }));
    }
    return { ...result, interrupt: result.findings.length > 0 };
  }

  /** Whether the call's grant covers a scope now. A scope the policy does not list is refused. */
  async authorize(callId: string, scope: string): Promise<boolean> {
    return this.#authorized(await this.#read(callId), scope);
  }

  // ---- flows -------------------------------------------------------------------------------

  /** Starts a named flow on an open call. A call runs at most one flow; its steps are copied in now. */
  async startFlow(callId: string, name: string): Promise<FlowPosition> {
    const definition = this.#flowDefinition(name);
    const revision = this.#config.revision;
    await this.#update(callId, (draft) => this.#attachFlow(draft, name, definition, revision));
    return (await this.flowPosition(callId))!;
  }

  #attachFlow(draft: CallDraft, name: string, definition: FlowConfig["flows"][string], revision: string): void {
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
        const reason = module.cannotRunStep?.(step, slice) ?? null;
        if (reason !== null) throw new EngineError("precondition_failed", `${step.type} cannot run on this call: ${reason}`);
      }
      const first = steps[0]!;
      const firstOwner = this.registry.stepOwner(first.type)!;
      const mark = firstOwner.enterStep(first, record.modules[firstOwner.manifest.name]!);
      record.flow = { name, revision, steps, index: 0, mark, status: "running" };
      draft.emit("flow.started", "code", { flow: name, revision, steps: steps.length });
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

  /** Starts (or restarts) verification, with the account number the caller keyed or a subject key the host's code chose. */
  beginVerification(callId: string, input: { accountNumber: string } | { subjectKey: string }): Promise<void> {
    return badge.beginVerification(this.#rt, callId, input);
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

  checkCarrier(callId: string): Promise<{ textCodeTrusted: boolean }> {
    return badge.checkCarrier(this.#rt, callId);
  }

  sendTextCode(callId: string): Promise<never> {
    return badge.sendTextCode(this.#rt, callId);
  }

  startPhotoId(callId: string): Promise<{ sent: true }> {
    return badge.startPhotoId(this.#rt, callId);
  }

  applyIdentityOutcome(outcome: IdentityOutcome): Promise<badge.OutcomeResult> {
    return badge.applyIdentityOutcome(this.#rt, outcome);
  }

  finishVerification(callId: string): Promise<badge.VerificationResult> {
    return badge.finishVerification(this.#rt, callId);
  }

  // ---- Dossier (file) ----------------------------------------------------------------------

  startIntake(callId: string, formId: string): Promise<void> {
    return dossier.startIntake(this.#rt, callId, formId);
  }

  setIntakeField(callId: string, key: string, raw: string): Promise<NormaliseResult> {
    return dossier.setIntakeField(this.#rt, callId, key, raw);
  }

  confirmIntake(callId: string, input: { confirmedBy: "voice" | "keypad" }): Promise<IntakeRecord> {
    return dossier.confirmIntake(this.#rt, callId, input);
  }

  abandonIntake(callId: string): Promise<void> {
    return dossier.abandonIntake(this.#rt, callId);
  }

  // ---- Paylink (pay) -----------------------------------------------------------------------

  /** Texts a payment link. `expiresAt` is the engine's deadline for it: call `expirePaymentLinks` then. */
  requestPayment(callId: string, input?: paylink.PaymentInput): Promise<{ paymentId: string; status: PaymentStatus; expiresAt: string | null }> {
    return paylink.requestPayment(this.#rt, callId, input);
  }

  /** Expires a call's texted links that are still open past their deadline (Paylink's link life). */
  expirePaymentLinks(callId: string): Promise<{ expired: string[] }> {
    return paylink.expirePaymentLinks(this.#rt, callId);
  }

  applyPaymentOutcome(outcome: PaymentOutcome): Promise<{ applied: false } | { applied: true; callId: string; status: PaymentStatus }> {
    return paylink.applyPaymentOutcome(this.#rt, outcome);
  }

  // ---- Gate (entry) ------------------------------------------------------------------------

  /** Issues an access grant and sends it to its door controller, once (SPEC.md, section 17). */
  grantAccess(callId: string, input?: { target: string; lifetimeSeconds?: number }): Promise<gate.AccessResult> {
    return gate.grantAccess(this.#rt, callId, input);
  }

  /** A call's access grants, as the engine recorded them. Never the signed grants themselves. */
  async accessGrants(callId: string): Promise<gate.AccessRecord[]> {
    const slice = (await this.#read(callId)).modules[gate.GATE] as unknown as gate.GateSlice | undefined;
    return slice === undefined ? [] : structuredClone(slice.grants);
  }

  /** The key set door relays verify access grants with (empty without an access signer). */
  accessKeys(): JsonWebKey[] {
    return this.#adapters.accessSigner === undefined ? [] : [this.#adapters.accessSigner.publicJwk()];
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
    return { keys: this.#adapters.stepUpSigner === undefined ? [] : [this.#adapters.stepUpSigner.publicJwk()] };
  }

  // ---- Trace (prove) -----------------------------------------------------------------------

  recordConsent(callId: string, input: { purpose: string; answer: "yes" | "no"; channel?: ConsentRecord["channel"] }): Promise<ConsentRecord> {
    return trace.recordConsent(this.#rt, callId, input);
  }

  /** Ends the call. A running flow is abandoned. Returns the signed receipt when the call gets one, else null. */
  async endCall(callId: string): Promise<SignedReceipt | null> {
    // A call that ended without its receipt (the signer failed) gets it now, without ending again.
    const before = await this.#read(callId);
    const pending = before.state.phase === "ended" && trace.wantsReceipt(this.#rt, before) && trace.receiptOf(before) === null;
    const record = pending ? before : await this.#update(callId, (draft) => {
      // The built-in modules' guards run even after a module was removed, as their receipt parts do.
      const guards = [...this.#receiptModules, ...this.registry.list().filter((m) => !this.#receiptModules.includes(m))];
      for (const module of guards) {
        const slice = draft.record.modules[module.manifest.name];
        const reason = slice === undefined ? null : (module.blocksEnd?.(slice) ?? null);
        if (reason !== null) throw new EngineError("precondition_failed", `the call cannot end yet: ${reason}`);
      }
      // A grant still at its door when the call ends is settled now, as unknown, before the receipt's
      // ledger head is taken: no access outcome can ever follow the receipt.
      gate.settleInFlight(this.#rt, draft, "call_ended");
      // Likewise a step-up token still being signed: it is failed, never handed out after the end.
      stepUp.settleStepUpInFlight(draft);
      draft.apply({ type: "call_ended", at: this.#now() });
      const flow = draft.record.flow;
      if (flow !== null && flow.status === "running") {
        flow.status = "abandoned";
        draft.emit("flow.abandoned", "system", { flow: flow.name, step: flow.index });
      }
      draft.emit("call.ended", "system", {});
      return structuredClone(draft.record);
    });
    if (!trace.wantsReceipt(this.#rt, record)) return null;
    const head = await trace.endedHead(this.#rt, record, () => this.#adapters.ledger.head());
    const parts: Pick<ReceiptBody, "verification" | "records" | "payments"> = { verification: { level: 0, methods: [] }, records: [], payments: [] };
    // The built-in contributors, not the registry: a module removed after this call filed or paid still appears on its receipt.
    for (const module of this.#receiptModules) {
      const slice = record.modules[module.manifest.name];
      if (module.receiptPart !== undefined && slice !== undefined) Object.assign(parts, module.receiptPart(slice, record.state));
    }
    return trace.issueReceipt(this.#rt, record, head, parts);
  }

  async receipt(callId: string): Promise<SignedReceipt | null> {
    const slice = (await this.#read(callId)).modules[trace.TRACE] as unknown as trace.TraceSlice;
    return slice.receipt === null ? null : structuredClone(slice.receipt);
  }

  /** The key set for verifying this engine's receipts (empty without a signer). */
  receiptKeys(): JsonWebKey[] {
    return this.#adapters.signer === undefined ? [] : [this.#adapters.signer.publicJwk()];
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
    return this.#update(callId, (draft) => {
      assertFlowNotEnded(draft.record);
      const step = draft.step();
      if (step !== null && !module.manifest.provides.steps.includes(step.type)) {
        throw new EngineError("precondition_failed", `the flow is on step ${step.type}, not a step of ${name}`);
      }
      const needs = step === null ? Object.values(module.manifest.scopes.needs) : [module.manifest.scopes.needs[step.type]].filter((n) => n !== undefined);
      for (const scope of needs) if (!this.#authorized(draft.record, scope)) throw new EngineError("scope_denied", `the grant does not cover ${scope}`);
      return this.#applyModule(draft, name, fn);
    });
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
      now: () => this.#now(),
      hmac: (data) => hmacSha256Hex(this.#key, data),
      settings: <T>(name: string): T => {
        if (!this.isEnabled(name)) throw new EngineError("module_disabled", `the ${name} module is turned off`);
        return this.#config.modules[name]?.settings as T;
      },
      // validateConfig refused any config whose modules need an adapter the engine lacks.
      adapter: <K extends AdapterName>(name: K) => this.#adapters[name]!,
      update: (callId, fn) => this.#update(callId, fn),
      read: (callId) => this.#read(callId),
      authorized: (record, scope) => this.#authorized(record, scope),
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
    return assertConfig(copy, this.registry);
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

  #authorized(record: CallRecord, scope: string): boolean {
    const min: AssuranceLevel | undefined = Object.hasOwn(this.#config.policy.scopes, scope) ? this.#config.policy.scopes[scope] : undefined;
    if (min === undefined || record.state.phase === "ended") return false;
    if (min === 0) return true;
    const grant = record.state.grant;
    // The grant's level is checked against today's minimum too, so a stricter config applies to grants already issued.
    return grant !== null && grant.scopes.includes(scope) && grant.level >= min && this.#clock.now().getTime() < Date.parse(grant.expiresAt);
  }

  async #read(callId: string): Promise<CallRecord> {
    const stored = await this.#sessions.get(this.workspaceId, callId);
    if (stored === null) throw new EngineError("unknown_call", "no such call");
    return structuredClone(stored.record) as unknown as CallRecord;
  }

  async #update<R>(callId: string, fn: (draft: CallDraft) => R): Promise<R> {
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
      events.forEach((event, i) => record.outbox.push({ eventId: this.#eventId(callId, version, i), ...event }));
      const saved = await this.#sessions.compareAndSet(this.workspaceId, callId, stored.version, record as unknown as JsonValue);
      if (saved.ok) {
        await this.#flush(callId, version, record);
        return result;
      }
    }
    throw new EngineError("conflict", `the call changed under every one of ${MAX_WRITE_ATTEMPTS} attempts`);
  }

  #draft(record: CallRecord, events: QueuedEvent[]): CallDraft {
    return {
      record,
      slice: <T>(name: string): T => this.#slice(record.modules, name) as unknown as T,
      apply: (event) => {
        record.state = reduce(record.state, event);
      },
      assertCan: (event) => {
        if (!canApply(record.state, event)) throw new EngineError("invalid_transition", `${event.type} is not allowed while ${record.state.phase}`);
      },
      emit: (name, actor, detail) => {
        // A copy, checked here, inside the step, so an entry the ledger would refuse is never saved
        // to be appended later, and a caller changing its object afterwards changes nothing.
        const copy = structuredClone(detail);
        if (detailCarriesCardNumber(copy)) throw new EngineError("invalid_input", "audit detail must never carry a card number");
        events.push({ name, actor, at: this.#now(), detail: copy });
      },
      step: () => currentStep(record),
    };
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
      flow.index++;
      const next = flow.steps[flow.index];
      if (next === undefined) {
        flow.status = "completed";
        draft.emit("flow.completed", "code", { flow: flow.name, steps: flow.steps.length });
        return;
      }
      const nextOwner = this.registry.stepOwner(next.type);
      flow.mark = nextOwner === undefined ? null : nextOwner.enterStep(next, record.modules[nextOwner.manifest.name]!);
    }
  }

  /**
   * Appends a call's pending ledger entries in order, each with its event id (a ledger appends an
   * id once), then clears them from the record if nobody wrote since. A failed append throws and
   * leaves the rest pending; a lost clear leaves them for the next write, which appends nothing twice.
   */
  async #flush(callId: string, version: number, record: CallRecord): Promise<void> {
    if (record.outbox.length === 0) return;
    for (const queued of record.outbox) {
      await this.#adapters.ledger.append({ eventId: queued.eventId, callId, actor: queued.actor, event: queued.name, at: queued.at, detail: queued.detail });
        // A listener is told, at least once and best effort; its failure, thrown or rejected, never stops the ledger (INT-5).
      try {
        const told: unknown = this.#onEvent?.({ name: queued.name, callId, actor: queued.actor, at: queued.at, detail: queued.detail });
        if (told instanceof Promise) told.catch(() => undefined);
      } catch {
        // Ignored by design: the ledger is the record.
      }
    }
    await this.#sessions.compareAndSet(this.workspaceId, callId, version, { ...record, outbox: [] } as unknown as JsonValue);
  }

  /** A ledger event id, unique across workspaces sharing one ledger: a JSON tuple, so no two ids collide. */
  #eventId(callId: string, version: number, index: number): string {
    return JSON.stringify([this.workspaceId, callId, version, index]);
  }

  /** Appends any ledger entries a call still has pending (after a ledger outage). Every write does this too. */
  async flushLedger(callId: string): Promise<void> {
    const stored = await this.#sessions.get(this.workspaceId, callId);
    if (stored === null) throw new EngineError("unknown_call", "no such call");
    await this.#flush(callId, stored.version, structuredClone(stored.record) as unknown as CallRecord);
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

export function createEngine(options: EngineOptions): Engine {
  return new Engine(options);
}
