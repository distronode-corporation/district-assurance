// Modules. The core holds the session state machine, the policy and its levels, redaction, this
// registry and the audit ledger; everything else is a module: Badge (verify), Dossier (file),
// Paylink (pay), Trace (prove), and any outside module a host adds with `engine.use(module)`.
//
// A module declares four things in code: what it provides (factors, flow steps, outcomes), the
// scopes it grants or needs, the adapters it requires, and a validator for its settings. The
// registry holds the installed modules; a workspace's FlowConfig turns each one on or off.
import type { JsonValue } from "./canonical.ts";
import { EngineError } from "./errors.ts";
import { scopeClass, type ScopeClass, type VerificationPolicy } from "./policy.ts";
import type { SessionState } from "./session.ts";

/** One step of a flow, as stored in a FlowConfig: `type` is `<module>.<step>`, the rest is the step's own. */
export interface FlowStep {
  readonly type: string;
  readonly [key: string]: JsonValue;
}

export interface ModuleManifest {
  /** Lower case letters, digits and hyphens, 2 to 32 characters, starting with a letter. */
  name: string;
  version: string;
  summary: string;
  provides: {
    /** Factor kinds (Badge only). */
    factors: readonly string[];
    /** Flow step types, each `<name>.<step>`. */
    steps: readonly string[];
    /** What the module produces for the host: a record, a payment, a receipt, an access grant. */
    outcomes: readonly string[];
  };
  scopes: {
    /** Scopes this module issues grants for (Badge issues every scope the policy lists: "*"). */
    grants: readonly string[];
    /** Step type to the scope the call's grant must cover before that step can run. */
    needs: Readonly<Record<string, string>>;
    /** The class of the scopes this module acts on (money, contact, access or none), which sets their floor. */
    classes?: Readonly<Record<string, ScopeClass>>;
  };
  /** Adapter names this module always needs (see `EngineAdapters`). Settings can add more. */
  adapters: readonly string[];
  /** True only for the module that holds the audit ledger: it cannot be turned off or removed. */
  alwaysOn?: boolean;
}

export interface StepContext {
  /** This module's settings, or null when they did not validate (cross-checks are then skipped). */
  settings: unknown;
  /** The config's policy, or null when it did not validate. */
  policy: VerificationPolicy | null;
  /** The adapters the engine has. */
  adapters: ReadonlySet<string>;
}

/** What a module sees of a call when it judges its current step. */
export interface StepView {
  state: SessionState;
  /** The module's own part of the call record. */
  slice: JsonValue;
  /** What `enterStep` returned when the step started. */
  mark: JsonValue;
}

export type StepStatus = "pending" | "complete" | "failed";

export interface AssuranceModule {
  readonly manifest: ModuleManifest;
  /** Every problem with this module's settings, as sentences. Settings come from storage: check every type. */
  validateSettings(settings: unknown): string[];
  /** Every adapter valid settings need, the manifest's included. */
  requiredAdapters(settings: unknown): string[];
  /** Every problem with one flow step whose type this module provides. */
  validateStep(step: FlowStep, ctx: StepContext): string[];
  /** The level a step verifies to, so later steps can be checked against their scope floors. */
  stepLevel?(step: FlowStep): number | null;
  /** The scopes a step's grant is limited to, when it names them (null: every scope its level reaches). */
  stepGrants?(step: FlowStep): string[] | null;
  /**
   * The module's part of a new call record, given the module's (valid) settings. A module copies in
   * what a call must keep using if the config changes mid-call (Dossier its forms, Trace its wordings).
   */
  initCall(settings: unknown): JsonValue;
  /** A step of this module starts. The value returned is the step's mark, handed back to `stepStatus`. */
  enterStep(step: FlowStep, slice: JsonValue): JsonValue;
  /** Where the current step stands. Pure: called after every change to the call. */
  stepStatus(step: FlowStep, view: StepView): StepStatus;
  /**
   * Why a step cannot run on this call, given what the call kept when it started (a form or a
   * wording it does not have), or null. Checked when a flow is attached to a running call.
   */
  cannotRunStep?(step: FlowStep, slice: JsonValue): string | null;
  /** Why the call cannot end now (work in progress that would be lost), or null. */
  blocksEnd?(slice: JsonValue): string | null;
  /** The call is ending (after every `blocksEnd` allowed it): drop what must not outlive the call. Returns the new slice. */
  onEnd?(slice: JsonValue): JsonValue;
  /** Untrusted text entered the call: drop anything that relied on trust. Returns the new slice. */
  onUntrusted?(slice: JsonValue): JsonValue;
  /** What this module puts in the call's receipt (built-in modules only: `verification`, `records`, `payments`). */
  receiptPart?(slice: JsonValue, state: SessionState): { [key: string]: JsonValue };
}

const MODULE_NAME = /^[a-z][a-z0-9-]{1,31}$/;
const STEP_NAME = /^[a-z][a-z0-9_]{0,31}$/;

/** Names the package keeps for itself: its own modules, and words that would read as the core. */
export const RESERVED_MODULE_NAMES: readonly string[] = ["core", "engine", "flow", "module"];

/** Every problem with a manifest, given the modules already installed. */
export function checkManifest(manifest: ModuleManifest, installed: readonly AssuranceModule[]): string[] {
  const errors: string[] = [];
  const { name } = manifest;
  if (!MODULE_NAME.test(name)) errors.push(`module name ${JSON.stringify(name)} must be 2 to 32 lower-case letters, digits or hyphens`);
  if (RESERVED_MODULE_NAMES.includes(name)) errors.push(`module name ${name} is reserved`);
  if (installed.some((m) => m.manifest.name === name)) errors.push(`a module named ${name} is already installed`);
  if (manifest.version.trim() === "") errors.push(`module ${name} needs a version`);
  for (const step of manifest.provides.steps) {
    const [prefix, rest, extra] = step.split(".");
    if (prefix !== name || rest === undefined || extra !== undefined || !STEP_NAME.test(rest)) {
      errors.push(`module ${name}: step ${JSON.stringify(step)} must be ${name}.<snake_case name>`);
    }
  }
  for (const step of Object.keys(manifest.scopes.needs)) {
    if (!manifest.provides.steps.includes(step)) errors.push(`module ${name}: needs a scope for ${step}, which it does not provide`);
  }
  for (const factor of manifest.provides.factors) {
    const owner = installed.find((m) => m.manifest.provides.factors.includes(factor));
    if (owner !== undefined) errors.push(`module ${name}: factor ${factor} is already provided by ${owner.manifest.name}`);
  }
  if (manifest.alwaysOn === true && installed.some((m) => m.manifest.alwaysOn === true)) {
    errors.push(`module ${name}: only one module can hold the audit ledger`);
  }
  return errors;
}

/**
 * The installed modules of one engine, and the adapters that engine has. Installing is code
 * (`use`, `remove`); turning an installed module on or off is config.
 */
export class ModuleRegistry {
  readonly adapters: ReadonlySet<string>;
  readonly #modules = new Map<string, AssuranceModule>();

  constructor(options: { adapters?: Iterable<string>; modules?: readonly AssuranceModule[] } = {}) {
    this.adapters = new Set(options.adapters ?? []);
    for (const module of options.modules ?? []) this.use(module);
  }

  /** Installs a module. Refuses a bad or clashing manifest with every problem. */
  use(module: AssuranceModule): this {
    const errors = checkManifest(module.manifest, this.list());
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    this.#modules.set(module.manifest.name, module);
    return this;
  }

  /** Uninstalls a module. The ledger's module cannot be removed. */
  remove(name: string): void {
    const module = this.#modules.get(name);
    if (module === undefined) throw new EngineError("invalid_input", `no module named ${name} is installed`);
    if (module.manifest.alwaysOn === true) throw new EngineError("precondition_failed", `${name} holds the audit ledger and cannot be removed`);
    this.#modules.delete(name);
  }

  get(name: string): AssuranceModule | undefined {
    return this.#modules.get(name);
  }

  /** Installed modules, in the order they were installed. */
  list(): AssuranceModule[] {
    return [...this.#modules.values()];
  }

  /** The installed module that provides a step type. */
  stepOwner(type: string): AssuranceModule | undefined {
    return this.list().find((m) => m.manifest.provides.steps.includes(type));
  }

  /** The scope classes the installed modules declare; the strictest wins when two disagree. */
  scopeClasses(): Record<string, ScopeClass> {
    const merged: Record<string, ScopeClass> = {};
    for (const module of this.list()) {
      for (const [scope, cls] of Object.entries(module.manifest.scopes.classes ?? {})) merged[scope] = scopeClass(scope, { [scope]: cls }, merged)!;
    }
    return merged;
  }

  /** Every factor kind the installed modules provide. */
  factorKinds(): string[] {
    return this.list().flatMap((m) => [...m.manifest.provides.factors]);
  }
}
