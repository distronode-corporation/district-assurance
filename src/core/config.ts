// FlowConfig: one versioned JSON document per workspace that says which modules are on, their
// settings, the assurance policy, and the named flows a call can run. Flows are config, not code.
//
// `validateConfig(config, registry)` returns every problem at once (an unknown or disabled module,
// a level below a scope's floor, a missing adapter, a bad step), so a host refuses a config when
// it is saved, never in the middle of a call. The engine refuses to run on a config with problems.
import type { JsonValue } from "./canonical.ts";
import { EngineError } from "./errors.ts";
import { problemMessage, type AssuranceModule, type FlowStep, type ModuleRegistry, type StepContext, type ValidationProblem } from "./module.ts";
import { amountOver, scopeClass, stepAmount, validatePolicy, type VerificationPolicy } from "./policy.ts";
import { isIntegerIn, isObject, unknownKeys } from "./shape.ts";

export const FLOW_CONFIG_VERSION = 1;

export interface ModuleConfig {
  /** Default true. The module that holds the audit ledger cannot be turned off. */
  enabled?: boolean;
  settings?: JsonValue;
}

export interface FlowDefinition {
  summary?: string;
  /** In order. A call runs them one at a time; each step's module must be on. */
  steps: FlowStep[];
}

export interface FlowConfig {
  /** The document format: 1. */
  version: typeof FLOW_CONFIG_VERSION;
  /** The host's own label for this revision of the document. Written to the ledger with every call. */
  revision: string;
  policy: VerificationPolicy;
  /** Module name to its switch and settings. An installed module not listed here is off (the ledger's is always on). */
  modules: Record<string, ModuleConfig>;
  /** Flow name to its steps. */
  flows: Record<string, FlowDefinition>;
}

/** A problem with a config, in the structured form a dashboard localizes: where, what, with which values. */
export interface ConfigProblem {
  /** The path of what is wrong, as the sentence starts: "flows.deposit.steps[2] (badge.verify)". */
  path: string;
  /** A stable code for this problem, for a dashboard's own template. */
  code: string;
  /** The values the sentence interpolates, for that template. */
  params: Readonly<Record<string, string | number>>;
  /** The sentence a person reads: the same message `validateConfig` answers. */
  message: string;
}

/** Thrown when an engine is given a config with problems. `problems` is the full list. */
export class ConfigError extends EngineError {
  readonly problems: readonly string[];
  /** The same problems in the structured form (`configProblems`): path, code, params, message. */
  readonly details: readonly ConfigProblem[];

  constructor(details: readonly (ConfigProblem | string)[]) {
    const problems = details.map((d) => (typeof d === "string" ? d : d.message));
    // A plain string (the 0.3.0 constructor) carries no path or code: it lands in `details` with
    // both empty, its sentence its message.
    const structured = details.map((d): ConfigProblem => (typeof d === "string" ? { path: "", code: "", params: {}, message: d } : d));
    super("invalid_input", `the config has ${problems.length} problem(s): ${problems.join("; ")}`);
    this.name = "ConfigError";
    this.problems = problems;
    this.details = structured;
  }
}

const REVISION = /^[A-Za-z0-9._:-]{1,64}$/;
const FLOW_NAME = /^[a-z][a-z0-9-]{0,63}$/;

/** Whether a module is on in a config: listed and not switched off, or the ledger's module. */
export function moduleEnabled(config: FlowConfig, registry: ModuleRegistry, name: string): boolean {
  const module = registry.get(name);
  if (module === undefined) return false;
  if (module.manifest.alwaysOn === true) return true;
  const entry = Object.hasOwn(config.modules, name) ? config.modules[name] : undefined;
  return entry !== undefined && entry.enabled !== false;
}

/**
 * Every problem with a config, as sentences that start with the path of what is wrong. An empty
 * list means an engine with this registry can run it. Never throws, whatever the input. The same
 * problems in the structured form are `configProblems`.
 */
export function validateConfig(config: unknown, registry: ModuleRegistry): string[] {
  return configProblems(config, registry).map((p) => p.message);
}

/** A module validator's problem, wrapped with the path and prefix composed here: the code and sentence stay its own. */
function at(path: string, prefix: string, value: ValidationProblem, code: string): ConfigProblem {
  const message = problemMessage(value);
  return { path, code: typeof value === "string" ? code : value.code, params: typeof value === "string" ? {} : (value.params ?? {}), message: `${prefix}${message}` };
}

/**
 * Every problem with a config, in the structured form: the path of what is wrong, a stable code,
 * the values the sentence interpolates, and the sentence itself (`validateConfig`'s message, so a
 * caller can localize by code and point at the field). A module that answers plain sentences (an
 * outside module) keeps them, under a code that says which validator spoke. Never throws.
 */
export function configProblems(config: unknown, registry: ModuleRegistry): ConfigProblem[] {
  if (!isObject(config)) return [{ path: "", code: "config.not_an_object", params: {}, message: "the config must be an object" }];
  // Config text reaches ledger entries, receipts and digests, all canonical JSON, which refuses a
  // lone surrogate: a config holding one is refused here, not in the middle of a call.
  const problems: ConfigProblem[] = loneSurrogates(config, "").map((p) => ({ path: p, code: "config.lone_surrogate", params: {}, message: `${p}: holds a lone surrogate, which is not Unicode text` }));
  for (const key of unknownKeys(config, ["version", "revision", "policy", "modules", "flows"])) problems.push({ path: key, code: "config.unknown_field", params: { key }, message: `${key}: not a config field` });
  if (config.version !== FLOW_CONFIG_VERSION) problems.push({ path: "version", code: "config.version", params: { version: FLOW_CONFIG_VERSION }, message: `version: must be ${FLOW_CONFIG_VERSION}` });
  if (typeof config.revision !== "string" || !REVISION.test(config.revision)) {
    problems.push({ path: "revision", code: "config.revision", params: {}, message: "revision: must be 1 to 64 letters, digits, dots, colons, hyphens or underscores" });
  }

  // The policy belongs to the core: levels, scopes and their floors, checked in one pass.
  const rules = validatePolicy(config.policy, registry.factorKinds(), registry.scopeClasses());
  problems.push(...rules.map((e) => at("policy", "policy: ", e, "policy.invalid")));
  const policy = rules.length === 0 ? (config.policy as VerificationPolicy) : null;

  // Modules: installed, switched, and with valid settings and the adapters those settings need.
  const settingsOf = new Map<string, unknown>();
  const enabled = new Set<string>();
  const modules = isObject(config.modules) ? config.modules : null;
  if (modules === null) problems.push({ path: "modules", code: "config.modules", params: {}, message: "modules: must be an object" });
  for (const [name, entry] of Object.entries(modules ?? {})) {
    const path = `modules.${name}`;
    const module = registry.get(name);
    if (module === undefined) {
      problems.push({ path, code: "module.unknown", params: { module: name }, message: `${path}: no module named ${name} is installed` });
      continue;
    }
    if (!isObject(entry)) {
      problems.push({ path, code: "module.not_an_object", params: { module: name }, message: `${path}: must be an object` });
      continue;
    }
    for (const key of unknownKeys(entry, ["enabled", "settings"])) problems.push({ path: `${path}.${key}`, code: "module.unknown_field", params: { module: name, key }, message: `${path}.${key}: not a module config field` });
    if (entry.enabled !== undefined && typeof entry.enabled !== "boolean") problems.push({ path: `${path}.enabled`, code: "module.enabled", params: { module: name }, message: `${path}.enabled: must be true or false` });
    if (entry.enabled === false && module.manifest.alwaysOn === true) problems.push({ path, code: "module.always_on", params: { module: name }, message: `${path}: ${name} holds the audit ledger and cannot be turned off` });
    if (entry.enabled !== false || module.manifest.alwaysOn === true) {
      enabled.add(name);
      settingsOf.set(name, entry.settings);
    }
  }
  const ledgerModule = registry.list().find((m) => m.manifest.alwaysOn === true);
  if (ledgerModule === undefined) problems.push({ path: "modules", code: "config.no_ledger_module", params: {}, message: "modules: no installed module holds the audit ledger (trace)" });
  else enabled.add(ledgerModule.manifest.name);
  const validSettings = new Map<string, unknown>();
  for (const name of enabled) {
    const module = registry.get(name)!;
    const settings = settingsOf.get(name);
    const path = `modules.${name}.settings`;
    const errors = module.validateSettings(settings);
    problems.push(...errors.map((e) => at(path, `modules.${name}.settings: `, e, "module.settings_invalid")));
    if (errors.length > 0) continue;
    validSettings.set(name, settings);
    for (const adapter of module.requiredAdapters(settings)) {
      if (!registry.adapters.has(adapter)) problems.push({ path: `modules.${name}`, code: "module.adapter_missing", params: { module: name, adapter }, message: `modules.${name}: needs the ${adapter} adapter, which the engine does not have` });
    }
    problems.push(...(module.checkAdapters?.(settings, registry.capabilities) ?? []).map((e) => at(`modules.${name}`, `modules.${name}: `, e, "module.adapters_invalid")));
  }

  // Another module's settings, for a step that relies on them: null when that module is off or its settings did not validate.
  const otherSettings = (module: string): unknown => (validSettings.has(module) ? validSettings.get(module) : null);

  // Flows: every step's module on, every step valid, and every scope a step needs reached before it.
  const flows = isObject(config.flows) ? config.flows : null;
  if (flows === null) problems.push({ path: "flows", code: "config.flows", params: {}, message: "flows: must be an object" });
  for (const [name, flow] of Object.entries(flows ?? {})) {
    const path = `flows.${name}`;
    if (!FLOW_NAME.test(name)) problems.push({ path, code: "flow.name", params: { flow: name }, message: `${path}: a flow name is lower-case letters, digits and hyphens, at most 64` });
    if (!isObject(flow) || !Array.isArray(flow.steps) || flow.steps.length === 0) {
      problems.push({ path, code: "flow.empty", params: { flow: name }, message: `${path}: must be an object with at least one step` });
      continue;
    }
    for (const key of unknownKeys(flow, ["summary", "steps"])) problems.push({ path: `${path}.${key}`, code: "flow.unknown_field", params: { flow: name, key }, message: `${path}.${key}: not a flow field` });
    if (flow.summary !== undefined && typeof flow.summary !== "string") problems.push({ path: `${path}.summary`, code: "flow.summary", params: { flow: name }, message: `${path}.summary: must be a string` });
    let level = 0;
    let granted: string[] | null = null;
    const owners = new Set<AssuranceModule>();
    flow.steps.forEach((step: unknown, index: number) => {
      const stepPath = `${path}.steps[${index}]`;
      if (!isObject(step) || typeof step.type !== "string") {
        problems.push({ path: stepPath, code: "step.no_type", params: { flow: name, index }, message: `${stepPath}: a step is an object with a type` });
        return;
      }
      const type = step.type;
      const owner = registry.stepOwner(type);
      if (owner === undefined) {
        problems.push({ path: stepPath, code: "step.unknown_type", params: { flow: name, index, type }, message: `${stepPath}: no installed module provides the step ${type}` });
        return;
      }
      const ownerName = owner.manifest.name;
      if (!enabled.has(ownerName)) {
        problems.push({ path: `${stepPath} (${type})`, code: "step.module_off", params: { flow: name, index, module: ownerName, type }, message: `${stepPath} (${type}): the ${ownerName} module is turned off` });
        return;
      }
      owners.add(owner);
      const ctx: StepContext = { settings: validSettings.has(ownerName) ? validSettings.get(ownerName) : null, policy, adapters: registry.adapters, capabilities: registry.capabilities, settingsOf: otherSettings };
      problems.push(...owner.validateStep(step as FlowStep, ctx).map((e) => at(`${stepPath} (${type})`, `${stepPath} (${type}): `, e, "step.invalid")));
      const scope = owner.manifest.scopes.needs[type];
      if (scope !== undefined && policy !== null) {
        const min = policy.scopes[scope];
        // A flow cannot branch to ask for more (ADR-14): a step whose amount is sure to raise its
        // scope's minimum (VER-13) must come after a verification that reaches the raised level. An
        // amount not known when the config is saved (an amountRef, PAY-2) counts as over.
        const amount = stepAmount(step);
        const raisedBy = (policy.stepUp ?? []).filter((rule) => rule.scope === scope && rule.amountOverMinor !== undefined && rule.level > level && amountOver(rule.amountOverMinor, amount));
        if (min === undefined) problems.push({ path: `${stepPath} (${type})`, code: "step.scope_unlisted", params: { flow: name, index, type, scope }, message: `${stepPath} (${type}): needs the scope ${scope}, which the policy does not list` });
        else if (min > level) problems.push({ path: `${stepPath} (${type})`, code: "step.scope_level", params: { flow: name, index, type, scope, level: min, verified: level }, message: `${stepPath} (${type}): needs the scope ${scope} at level ${min}, but the flow has verified to level ${level} at this point` });
        else if (granted !== null && !granted.includes(scope)) problems.push({ path: `${stepPath} (${type})`, code: "step.scope_not_granted", params: { flow: name, index, type, scope }, message: `${stepPath} (${type}): needs the scope ${scope}, which the last verification step does not grant` });
        else {
          for (const rule of raisedBy) {
            problems.push({ path: `${stepPath} (${type})`, code: "step.stepup_rule", params: { flow: name, index, type, rule: rule.name, scope, level: rule.level, verified: level }, message: `${stepPath} (${type}): its amount triggers the step-up rule ${rule.name}, which raises ${scope} to level ${rule.level}, but the flow has verified to level ${level} at this point` });
          }
        }
        // A contact change always texts a security notice to the number on file (PRV-10).
        if (scopeClass(scope, policy.scopeClasses, registry.scopeClasses()) === "contact" && !registry.adapters.has("messages")) {
          problems.push({ path: `${stepPath} (${type})`, code: "step.contact_notice_adapter", params: { flow: name, index, type }, message: `${stepPath} (${type}): changes contact details, so it needs the messages adapter for the security notice, which the engine does not have` });
        }
      }
      const reached = owner.stepLevel?.(step as FlowStep) ?? null;
      if (reached !== null) {
        level = reached;
        granted = owner.stepGrants?.(step as FlowStep) ?? null;
      }
    });
    // Whole-flow checks, for modules whose settings validated: a limit no single step can show.
    for (const owner of owners) {
      const ownerName = owner.manifest.name;
      if (owner.validateFlow === undefined || !validSettings.has(ownerName)) continue;
      const ctx: StepContext = { settings: validSettings.get(ownerName), policy, adapters: registry.adapters, capabilities: registry.capabilities, settingsOf: otherSettings };
      problems.push(...owner.validateFlow(flow.steps as FlowStep[], ctx).map((e) => at(`${path} (${ownerName})`, `${path} (${ownerName}): `, e, "flow.invalid")));
    }
  }
  return problems;
}

/** The path of every string or key holding a lone surrogate, in a config's plain data. */
function loneSurrogates(value: unknown, path: string): string[] {
  if (typeof value === "string") return value.isWellFormed() ? [] : [path];
  if (Array.isArray(value)) return value.flatMap((item, i) => loneSurrogates(item, `${path}[${i}]`));
  if (!isObject(value)) return [];
  return Object.entries(value).flatMap(([key, item]) => {
    const at = path === "" ? key.toWellFormed() : `${path}.${key.toWellFormed()}`;
    return [...(key.isWellFormed() ? [] : [at]), ...loneSurrogates(item, at)];
  });
}

/** Throws a ConfigError with every problem, or returns the config typed. */
export function assertConfig(config: unknown, registry: ModuleRegistry): FlowConfig {
  const details = configProblems(config, registry);
  if (details.length > 0) throw new ConfigError(details);
  return config as FlowConfig;
}

/** Whether a value is a 1 to 3 assurance level, as a step's `level` must be. */
export function isStepLevel(value: unknown): value is 1 | 2 | 3 {
  return isIntegerIn(value, 1, 3);
}
