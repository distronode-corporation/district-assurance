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
import type { JsonWebKey } from "node:crypto";

import type { IntakeRecord, SessionStore } from "./core/adapters.ts";
import type { JsonValue } from "./core/canonical.ts";
import { randomIds, systemClock, type Clock, type IdGenerator } from "./core/clock.ts";
import { ConfigError, assertConfig, moduleEnabled, type FlowConfig } from "./core/config.ts";
import { EngineError, NotImplementedError } from "./core/errors.ts";
import { assertFlowNotEnded, currentStep } from "./core/flow.ts";
import type { Actor, EngineEventName, EventListener } from "./core/events.ts";
import { hmacSha256Hex } from "./core/hash.ts";
import { ModuleRegistry, type AssuranceModule, type FlowStep } from "./core/module.ts";
import { raiseMinimum, stepAmount, type StepUpAmount, type VerificationPolicy } from "./core/policy.ts";
import { cardNumberRedactor, type RedactionFinding, type Redactor } from "./core/redaction.ts";
import type { AdapterName, CallDraft, CallRecord, EngineAdapters, EngineRuntime, FlowStatus, Locale } from "./core/runtime.ts";
import { MemorySessionStore } from "./core/session-store.ts";
import { canApply, newSession, reduce, snapshot, type SensitiveReason, type SessionState } from "./core/session.ts";
import * as dossier from "./file/dossier.ts";
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
  /** The draft of each record being changed, so a scope check inside a change can write its step-up rules to the ledger. */
  readonly #drafts = new WeakMap<CallRecord, CallDraft>();
  #config: FlowConfig;

  constructor(options: EngineOptions) {
    const errors: string[] = [];
    const keyLength = typeof options.knowledgeKey === "string" ? Buffer.byteLength(options.knowledgeKey) : options.knowledgeKey.byteLength;
    if (keyLength < 16) errors.push("knowledgeKey must be at least 16 bytes");
    if (options.workspaceId === "") errors.push("workspaceId is empty");
    if ((options.adapters as Partial<EngineAdapters>).ledger === undefined) errors.push("the ledger adapter is required: the ledger is always on");
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
    this.#receiptModules = builtInModules(this.#badge);
    this.registry = new ModuleRegistry({ adapters: present, modules: [...this.#receiptModules, ...(options.modules ?? [])] });
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
      signals: [],
      stepUps: [],
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

  /**
   * Whether the call's grant covers a scope now. A scope the policy does not list is refused. The
   * scope's minimum is raised by the policy's step-up rules that hold: pass the amount a money
   * scope is for (in a flow, the current step's amount is the default; an amount not known counts
   * as over every amount rule). A rule that applies for the first time on the call is written to
   * the ledger by name, so this can write.
   */
  async authorize(callId: string, scope: string, given?: StepUpAmount): Promise<boolean> {
    // Read once, before the wait: both checks judge the amount the host passed at the call, as a
    // plain copy, so a getter or a change to the object meanwhile cannot answer each differently.
    const amount = typeof given === "object" && given !== null ? { amountMinor: given.amountMinor, currency: given.currency } : given;
    const record = await this.#read(callId);
    const check = this.#cover(record, scope, amount);
    if (check.applied.every((name) => record.stepUps.includes(name))) return check.ok;
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
      if (draft.record.signals.includes(signal)) return;
      draft.record.signals.push(signal);
      draft.emit("signal.raised", "code", { signal });
      this.#holdStep(draft);
    });
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

  requestPayment(callId: string, input?: paylink.PaymentInput): Promise<{ paymentId: string; status: PaymentStatus }> {
    return paylink.requestPayment(this.#rt, callId, input);
  }

  applyPaymentOutcome(outcome: PaymentOutcome): Promise<{ applied: false } | { applied: true; callId: string; status: PaymentStatus }> {
    return paylink.applyPaymentOutcome(this.#rt, outcome);
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
   * so `fn` must be pure). A running flow moves on when the module's step completes.
   */
  async updateModule(callId: string, name: string, fn: (slice: JsonValue, call: ModuleCallView) => JsonValue): Promise<JsonValue> {
    this.#outsideModule(name);
    const module = this.registry.get(name)!;
    const out = await this.#update(callId, (draft) => {
      // An outside module does only its current step's work, and the engine itself holds that step
      // to the scope its manifest needs (raised by step-up rules for the step's amount): a module
      // that forgets to ask `authorized` still fails closed.
      assertFlowNotEnded(draft.record);
      const step = draft.step();
      if (step !== null) {
        if (!module.manifest.provides.steps.includes(step.type)) throw new EngineError("precondition_failed", `the flow is on step ${step.type}, not a step of ${name}`);
        const scope = module.manifest.scopes.needs[step.type];
        const refused = scope === undefined ? null : this.#requireScope(draft, scope, stepAmount(step));
        if (refused !== null) return { refused };
      }
      const view: ModuleCallView = {
        state: snapshot(draft.record.state),
        authorized: (scope) => this.#authorized(draft.record, scope),
        emit: (event, detail) => draft.emit("module.event", "code", { module: name, event, detail }),
      };
      const next = fn(structuredClone(this.#slice(draft.record.modules, name)), view);
      draft.record.modules[name] = structuredClone(next);
      return { next: structuredClone(next) };
    });
    if ("refused" in out) throw out.refused;
    return out.next;
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

  #authorized(record: CallRecord, scope: string, amount?: StepUpAmount): boolean {
    return this.#cover(record, scope, amount).ok;
  }

  /**
   * Whether the call's grant covers a scope now (`ok`), the step-up rules that raised its minimum
   * (`applied`), and, when not covered, the rules the grant falls short of (`rules`; empty when
   * the grant would not cover the scope anyway). Inside a change, a rule applied for the first time
   * on the call is written to the ledger by name, never with the amount, the time or the signal.
   */
  #cover(record: CallRecord, scope: string, amount = stepAmount(currentStep(record))): { ok: boolean; applied: string[]; rules: string[] } {
    const policy = this.#config.policy;
    const min = Object.hasOwn(policy.scopes, scope) ? policy.scopes[scope] : undefined;
    if (min === undefined || record.state.phase === "ended") return { ok: false, applied: [], rules: [] };
    const now = this.#clock.now();
    const raised = raiseMinimum(policy, scope, { amount, at: now, signals: record.signals });
    const draft = this.#drafts.get(record);
    for (const rule of raised.rules) {
      if (draft === undefined || record.stepUps.includes(rule.name)) continue;
      record.stepUps.push(rule.name);
      draft.emit("policy.step_up", "code", { rule: rule.name, scope, level: rule.level });
    }
    const grant = record.state.grant;
    // The grant's level is checked against today's minimum, raised for this request, so a stricter
    // config or a step-up rule applies to grants already issued.
    const reached = grant !== null && grant.scopes.includes(scope) && now.getTime() < Date.parse(grant.expiresAt) ? grant.level : 0;
    const applied = raised.rules.map((rule) => rule.name);
    if (reached >= raised.level) return { ok: true, applied, rules: [] };
    return { ok: false, applied, rules: reached < min ? [] : raised.rules.filter((rule) => rule.level > reached).map((rule) => rule.name) };
  }

  async #read(callId: string): Promise<CallRecord> {
    const stored = await this.#sessions.get(this.workspaceId, callId);
    if (stored === null) throw new EngineError("unknown_call", "no such call");
    return loadRecord(stored.record);
  }

  async #update<R>(callId: string, fn: (draft: CallDraft) => R): Promise<R> {
    for (let attempt = 0; attempt < MAX_WRITE_ATTEMPTS; attempt++) {
      const stored = await this.#sessions.get(this.workspaceId, callId);
      if (stored === null) throw new EngineError("unknown_call", "no such call");
      const record = loadRecord(stored.record);
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
    const draft: CallDraft = {
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
   * the call's verification reached. A flow cannot branch to ask for more (ADR-14), so it stops
   * there, naming the rules. Checked when a step is entered and when a signal is raised; the
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
    const flow = draft.record.flow;
    if (flow === null || flow.status !== "running") return;
    flow.status = "failed";
    draft.emit("flow.failed", "code", { flow: flow.name, step: flow.index, type: flow.steps[flow.index]!.type, rules });
  }

  /** See `EngineRuntime.requireScope`. */
  #requireScope(draft: CallDraft, scope: string, amount: StepUpAmount | undefined): EngineError | null {
    const { ok, applied, rules } = this.#cover(draft.record, scope, amount);
    if (ok) return null;
    if (rules.length === 0) {
      // A denial no rule affects throws at once. When a rule applies, the refusal is returned, so
      // the change is saved and a rule applied for the first time stays on the ledger. The flow is
      // not failed: without the rule the grant would not cover the scope either.
      if (applied.length === 0) throw new EngineError("scope_denied", `the grant does not cover ${scope}`);
      return new EngineError("scope_denied", `the grant does not cover ${scope}; the step-up rule(s) ${applied.join(", ")} also apply`);
    }
    this.#failStep(draft, rules);
    return new EngineError("scope_denied", `the grant does not cover ${scope} at the level the step-up rule(s) ${rules.join(", ")} require`);
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
    await this.#flush(callId, stored.version, loadRecord(stored.record));
  }
}

/**
 * A stored call, copied, with the fields later changes added filled in: a record saved before
 * step-up rules (VER-13) has no `signals` or `stepUps`, and loads with both empty.
 */
function loadRecord(stored: JsonValue): CallRecord {
  const record = structuredClone(stored) as unknown as CallRecord;
  record.signals ??= [];
  record.stepUps ??= [];
  return record;
}

export function createEngine(options: EngineOptions): Engine {
  return new Engine(options);
}
