// Modules. The core holds the session state machine, the policy and its levels, redaction, this
// registry and the audit ledger; everything else is a module: Badge (verify), Dossier (file),
// Paylink (pay), Trace (prove), and any outside module a host adds with `engine.use(module)`.
//
// A module declares four things in code: what it provides (factors, flow steps, outcomes), the
// scopes it grants or needs, the adapters it requires, and a validator for its settings. The
// registry holds the installed modules; a workspace's FlowConfig turns each one on or off.
//
// Factor plug-ins are described here too, because the registry checks them: a host adds one to
// Badge (at construction, or later with `engine.useFactor`), or an outside module supplies the
// judges for the factors its manifest provides. Badge runs them all.
import type { SubjectRecord } from "./adapters.ts";
import type { JsonValue } from "./canonical.ts";
import { EngineError } from "./errors.ts";
import { FORBIDDEN_FACTOR_KINDS, scopeClass, type ScopeClass, type VerificationPolicy } from "./policy.ts";
import type { AdapterName, Locale } from "./runtime.ts";
import type { SessionState } from "./session.ts";
import { isIntegerIn, isStringArray } from "./shape.ts";

/** What the caller entered: one string (a PIN), or one value per field (keypad knowledge). */
export type FactorEntry = string | Readonly<Record<string, string>>;

export interface FactorJudgeInput {
  workspaceId: string;
  /** Null when the account number was not something a keypad can produce. */
  subjectKey: string | null;
  /** Null for an unknown subject. Judge it the same way, and give the same answer as a wrong entry. */
  subject: SubjectRecord | null;
  /** From a code path, never from the model. Discarded after judging. */
  entry: FactorEntry;
  /** HMAC-SHA256 under the workspace's knowledge key, hex. Asynchronous: the key may live in a key management service. */
  hmac(data: string): Promise<string>;
  /** The call's language, which decides how a spoken answer is read. */
  locale: Locale;
}

/** A factor the caller enters and code judges. The engine counts each attempt before judging it. */
export interface FactorPlugin {
  /** snake_case, 3 to 32 characters. Never a name for caller ID. */
  kind: string;
  summary: string;
  /** Attempts per call, 1 to 5. */
  maxAttemptsPerCall: number;
  /** Adapter names the judge needs. */
  adapters: readonly AdapterName[];
  judge(input: FactorJudgeInput): Promise<boolean>;
}

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
  /** What adapters declare they can do (`capabilities` on the adapter), by adapter name, when known. */
  capabilities: Readonly<Record<string, unknown>>;
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
  /**
   * The judges for the factors this module's manifest provides, one per factor, when an outside
   * module brings its own factors. Badge runs them like its own plug-ins, and Badge's settings turn
   * them on. Badge leaves this out: its own code judges its factors.
   */
  readonly factorPlugins?: readonly FactorPlugin[];
  /** Every problem with this module's settings, as sentences. Settings come from storage: check every type. */
  validateSettings(settings: unknown): string[];
  /** Every adapter valid settings need, the manifest's included. */
  requiredAdapters(settings: unknown): string[];
  /** Every problem between valid settings and what the adapters declare they can do. */
  checkAdapters?(settings: unknown, capabilities: Readonly<Record<string, unknown>>): string[];
  /** Every problem with one flow step whose type this module provides. */
  validateStep(step: FlowStep, ctx: StepContext): string[];
  /**
   * Every problem with a whole flow, given its steps in order, for what one step cannot show (a
   * per-call limit the flow's steps would exceed). Called once per flow that has a step of this module.
   */
  validateFlow?(steps: readonly FlowStep[], ctx: StepContext): string[];
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
   * wording it does not have, or one with no text in the call's locale), or null. Checked when a
   * flow is attached to a call.
   */
  cannotRunStep?(step: FlowStep, slice: JsonValue, locale: Locale): string | null;
  /** Why the call cannot end now (work in progress that would be lost, or still to be recorded), or null. `now` is the engine's clock. */
  blocksEnd?(slice: JsonValue, now: Date): string | null;
  /** Untrusted text entered the call: drop anything that relied on trust. Returns the new slice. */
  onUntrusted?(slice: JsonValue): JsonValue;
  /** What this module puts in the call's receipt (built-in modules only: `verification`, `records`, `payments`). */
  receiptPart?(slice: JsonValue, state: SessionState): { [key: string]: JsonValue };
}

const MODULE_NAME = /^[a-z][a-z0-9-]{1,31}$/;
const STEP_NAME = /^[a-z][a-z0-9_]{0,31}$/;
const FACTOR_KIND = /^[a-z][a-z0-9_]{2,31}$/;

/** Every problem with a factor kind's name: snake_case, 3 to 32 characters, and never caller ID. */
export function checkFactorKind(kind: string): string[] {
  const errors: string[] = [];
  if (!FACTOR_KIND.test(kind)) errors.push(`factor kind ${JSON.stringify(kind)} must be snake_case, 3 to 32 characters`);
  if (FORBIDDEN_FACTOR_KINDS.includes(kind)) errors.push(`factor kind ${kind} would make caller ID a factor, which it never is`);
  return errors;
}

/**
 * A plug-in as it is when it is registered: its fields read once into a frozen copy, and its judge
 * called on the original. What is checked is what runs: a host that changes the object later (a
 * higher attempt limit, another kind) changes nothing, and a getter answers once.
 */
export function snapshotFactorPlugin(plugin: FactorPlugin): FactorPlugin {
  const { kind, summary, maxAttemptsPerCall, adapters, judge } = plugin;
  return Object.freeze({
    kind,
    summary,
    maxAttemptsPerCall,
    adapters: Array.isArray(adapters) ? Object.freeze([...adapters]) : adapters,
    judge: typeof judge === "function" ? (input: FactorJudgeInput) => judge.call(plugin, input) : judge,
  });
}

/** Every problem with a factor plug-in, given the kinds already taken. */
export function checkFactorPlugin(plugin: FactorPlugin, taken: readonly string[]): string[] {
  // A kind that is not a string (an object whose toString passes the pattern) would never match
  // the name a config uses, so it is refused before anything compares it.
  if (typeof plugin.kind !== "string") return ["factor kind must be a string"];
  const errors = checkFactorKind(plugin.kind);
  if (taken.includes(plugin.kind)) errors.push(`factor kind ${plugin.kind} already exists`);
  errors.push(...judgeErrors(plugin).map((e) => `factor ${plugin.kind}: ${e}`));
  return errors;
}

function judgeErrors(plugin: FactorPlugin): string[] {
  const errors: string[] = [];
  if (!isIntegerIn(plugin.maxAttemptsPerCall, 1, 5)) errors.push("maxAttemptsPerCall must be 1 to 5");
  if (typeof plugin.judge !== "function") errors.push("judge must be a function");
  // A string here would be read one character at a time as adapter names.
  if (!isStringArray(plugin.adapters)) errors.push("adapters must be a list of adapter names");
  return errors;
}

/** The one module whose own code judges the factors it provides, so it supplies no judges. */
const SELF_JUDGING_MODULE = "badge";

/**
 * Every problem with the judges a module supplies: exactly one for each factor its manifest
 * provides, whether or not it gives a list (only Badge judges its own). The kinds' names and
 * clashes are checked with the manifest.
 */
export function checkFactorPlugins(module: AssuranceModule, given: readonly FactorPlugin[] | undefined = module.factorPlugins): string[] {
  return judgeListErrors(module.manifest, given);
}

/** The same check on a list already read: `undefined` is a module that gave none, never a cue to read it again. */
function judgeListErrors(manifest: ModuleManifest, given: readonly FactorPlugin[] | undefined): string[] {
  const { name, provides } = manifest;
  if (given === undefined && name === SELF_JUDGING_MODULE) return [];
  const plugins = given ?? [];
  const errors: string[] = [];
  const judged: string[] = [];
  for (const plugin of plugins) {
    if (!provides.factors.includes(plugin.kind)) errors.push(`module ${name}: judges ${plugin.kind}, a factor its manifest does not provide`);
    if (judged.includes(plugin.kind)) errors.push(`module ${name}: judges ${plugin.kind} twice`);
    errors.push(...judgeErrors(plugin).map((e) => `module ${name}: factor ${plugin.kind}: ${e}`));
    judged.push(plugin.kind);
  }
  for (const kind of provides.factors) if (!judged.includes(kind)) errors.push(`module ${name}: factor ${kind} has no judge`);
  return errors;
}

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
    errors.push(...checkFactorKind(factor).map((e) => `module ${name}: ${e}`));
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
  /** Adapter name to what that adapter declares it can do (its `capabilities`), for the validator. */
  readonly capabilities: Readonly<Record<string, unknown>>;
  readonly #modules = new Map<string, AssuranceModule>();
  /** Names only the constructor may install (an engine's built-in modules): refused later, even after a removal. */
  readonly #reserved: ReadonlySet<string>;
  #sealed = false;
  /** The judges each module supplied, as they were checked when it was installed. */
  readonly #judges = new Map<string, readonly FactorPlugin[]>();

  constructor(options: { adapters?: Iterable<string>; capabilities?: Readonly<Record<string, unknown>>; modules?: readonly AssuranceModule[]; reserved?: readonly string[] } = {}) {
    this.adapters = new Set(options.adapters ?? []);
    this.capabilities = structuredClone(options.capabilities ?? {});
    this.#reserved = new Set(options.reserved ?? []);
    for (const module of options.modules ?? []) this.use(module);
    this.#sealed = true;
  }

  /** Installs a module. Refuses a bad or clashing manifest, or bad factor judges, with every problem. */
  use(module: AssuranceModule): this {
    if (this.#sealed && this.#reserved.has(module.manifest.name)) throw new EngineError("invalid_input", `${module.manifest.name} is the name of a built-in module`);
    const judges = this.#check(module, this.list());
    this.#modules.set(module.manifest.name, module);
    this.#judges.set(module.manifest.name, judges);
    return this;
  }

  /**
   * Swaps an installed module for a new build of it under the same name (Badge with one more
   * factor), checked against the other modules as a new one would be. It keeps its place in the order.
   */
  replace(module: AssuranceModule): void {
    const name = module.manifest.name;
    const current = this.#modules.get(name);
    if (current === undefined) throw new EngineError("invalid_input", `no module named ${name} is installed`);
    // Otherwise a build without the flag would make the ledger's module removable.
    if ((module.manifest.alwaysOn === true) !== (current.manifest.alwaysOn === true)) throw new EngineError("invalid_input", `a new build of ${name} cannot change alwaysOn`);
    const judges = this.#check(module, this.list().filter((m) => m.manifest.name !== name));
    this.#modules.set(name, module);
    this.#judges.set(name, judges);
  }

  /** Checks a module and returns the judges it supplies, copied once: a list changed later is never read again. */
  #check(module: AssuranceModule, others: readonly AssuranceModule[]): readonly FactorPlugin[] {
    const given = module.factorPlugins;
    const judges = given === undefined ? undefined : Array.from(given, snapshotFactorPlugin);
    const errors = [...checkManifest(module.manifest, others), ...judgeListErrors(module.manifest, judges)];
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    return judges ?? [];
  }

  /** Uninstalls a module. The ledger's module cannot be removed. */
  remove(name: string): void {
    const module = this.#modules.get(name);
    if (module === undefined) throw new EngineError("invalid_input", `no module named ${name} is installed`);
    if (module.manifest.alwaysOn === true) throw new EngineError("precondition_failed", `${name} holds the audit ledger and cannot be removed`);
    this.#modules.delete(name);
    this.#judges.delete(name);
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

  /** The judges a module supplied, as installed (none for a module not installed). */
  judgesOf(name: string): readonly FactorPlugin[] {
    return this.#judges.get(name) ?? [];
  }

  /** The judges outside modules supply for their factors. Badge's own plug-ins are inside Badge. */
  factorPlugins(): FactorPlugin[] {
    // Every installed module has its entry: use() and replace() set it with the module.
    return this.list().flatMap((m) => [...this.#judges.get(m.manifest.name)!]);
  }
}
