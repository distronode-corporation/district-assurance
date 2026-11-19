// FlowConfig: one versioned JSON document per workspace that says which modules are on, their
// settings, the assurance policy, and the named flows a call can run. Flows are config, not code.
//
// `validateConfig(config, registry)` returns every problem at once (an unknown or disabled module,
// a level below a scope's floor, a missing adapter, a bad step), so a host refuses a config when
// it is saved, never in the middle of a call. The engine refuses to run on a config with problems.
import type { JsonValue } from "./canonical.ts";
import { EngineError } from "./errors.ts";
import type { AssuranceModule, FlowStep, ModuleRegistry, StepContext } from "./module.ts";
import { validatePolicy, type VerificationPolicy } from "./policy.ts";
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

/** Thrown when an engine is given a config with problems. `problems` is the full list. */
export class ConfigError extends EngineError {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super("invalid_input", `the config has ${problems.length} problem(s): ${problems.join("; ")}`);
    this.name = "ConfigError";
    this.problems = problems;
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
 * list means an engine with this registry can run it. Never throws, whatever the input.
 */
export function validateConfig(config: unknown, registry: ModuleRegistry): string[] {
  if (!isObject(config)) return ["the config must be an object"];
  const problems: string[] = [];
  for (const key of unknownKeys(config, ["version", "revision", "policy", "modules", "flows"])) problems.push(`${key}: not a config field`);
  if (config.version !== FLOW_CONFIG_VERSION) problems.push(`version: must be ${FLOW_CONFIG_VERSION}`);
  if (typeof config.revision !== "string" || !REVISION.test(config.revision)) {
    problems.push("revision: must be 1 to 64 letters, digits, dots, colons, hyphens or underscores");
  }

  // The policy belongs to the core: levels, scopes and their floors, checked in one pass.
  const rules = validatePolicy(config.policy, registry.factorKinds(), registry.scopeClasses());
  problems.push(...rules.map((e) => `policy: ${e}`));
  const policy = rules.length === 0 ? (config.policy as VerificationPolicy) : null;

  // Modules: installed, switched, and with valid settings and the adapters those settings need.
  const settingsOf = new Map<string, unknown>();
  const enabled = new Set<string>();
  const modules = isObject(config.modules) ? config.modules : null;
  if (modules === null) problems.push("modules: must be an object");
  for (const [name, entry] of Object.entries(modules ?? {})) {
    const at = `modules.${name}`;
    const module = registry.get(name);
    if (module === undefined) {
      problems.push(`${at}: no module named ${name} is installed`);
      continue;
    }
    if (!isObject(entry)) {
      problems.push(`${at}: must be an object`);
      continue;
    }
    for (const key of unknownKeys(entry, ["enabled", "settings"])) problems.push(`${at}.${key}: not a module config field`);
    if (entry.enabled !== undefined && typeof entry.enabled !== "boolean") problems.push(`${at}.enabled: must be true or false`);
    if (entry.enabled === false && module.manifest.alwaysOn === true) problems.push(`${at}: ${name} holds the audit ledger and cannot be turned off`);
    if (entry.enabled !== false || module.manifest.alwaysOn === true) {
      enabled.add(name);
      settingsOf.set(name, entry.settings);
    }
  }
  const ledgerModule = registry.list().find((m) => m.manifest.alwaysOn === true);
  if (ledgerModule === undefined) problems.push("modules: no installed module holds the audit ledger (trace)");
  else enabled.add(ledgerModule.manifest.name);
  const validSettings = new Map<string, unknown>();
  for (const name of enabled) {
    const module = registry.get(name)!;
    const settings = settingsOf.get(name);
    const errors = module.validateSettings(settings);
    problems.push(...errors.map((e) => `modules.${name}.settings: ${e}`));
    if (errors.length > 0) continue;
    validSettings.set(name, settings);
    for (const adapter of module.requiredAdapters(settings)) {
      if (!registry.adapters.has(adapter)) problems.push(`modules.${name}: needs the ${adapter} adapter, which the engine does not have`);
    }
    problems.push(...(module.checkAdapters?.(settings, registry.capabilities) ?? []).map((e) => `modules.${name}: ${e}`));
  }

  // Flows: every step's module on, every step valid, and every scope a step needs reached before it.
  const flows = isObject(config.flows) ? config.flows : null;
  if (flows === null) problems.push("flows: must be an object");
  for (const [name, flow] of Object.entries(flows ?? {})) {
    const at = `flows.${name}`;
    if (!FLOW_NAME.test(name)) problems.push(`${at}: a flow name is lower-case letters, digits and hyphens, at most 64`);
    if (!isObject(flow) || !Array.isArray(flow.steps) || flow.steps.length === 0) {
      problems.push(`${at}: must be an object with at least one step`);
      continue;
    }
    for (const key of unknownKeys(flow, ["summary", "steps"])) problems.push(`${at}.${key}: not a flow field`);
    if (flow.summary !== undefined && typeof flow.summary !== "string") problems.push(`${at}.summary: must be a string`);
    let level = 0;
    let granted: string[] | null = null;
    const owners = new Set<AssuranceModule>();
    flow.steps.forEach((step: unknown, index: number) => {
      const stepAt = `${at}.steps[${index}]`;
      if (!isObject(step) || typeof step.type !== "string") {
        problems.push(`${stepAt}: a step is an object with a type`);
        return;
      }
      const type = step.type;
      const owner = registry.stepOwner(type);
      if (owner === undefined) {
        problems.push(`${stepAt}: no installed module provides the step ${type}`);
        return;
      }
      const ownerName = owner.manifest.name;
      if (!enabled.has(ownerName)) {
        problems.push(`${stepAt} (${type}): the ${ownerName} module is turned off`);
        return;
      }
      owners.add(owner);
      const ctx: StepContext = { settings: validSettings.has(ownerName) ? validSettings.get(ownerName) : null, policy, adapters: registry.adapters, capabilities: registry.capabilities };
      problems.push(...owner.validateStep(step as FlowStep, ctx).map((e) => `${stepAt} (${type}): ${e}`));
      const scope = owner.manifest.scopes.needs[type];
      if (scope !== undefined && policy !== null) {
        const min = policy.scopes[scope];
        if (min === undefined) problems.push(`${stepAt} (${type}): needs the scope ${scope}, which the policy does not list`);
        else if (min > level) problems.push(`${stepAt} (${type}): needs the scope ${scope} at level ${min}, but the flow has verified to level ${level} at this point`);
        else if (granted !== null && !granted.includes(scope)) problems.push(`${stepAt} (${type}): needs the scope ${scope}, which the last verification step does not grant`);
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
      const ctx: StepContext = { settings: validSettings.get(ownerName), policy, adapters: registry.adapters, capabilities: registry.capabilities };
      problems.push(...owner.validateFlow(flow.steps as FlowStep[], ctx).map((e) => `${at} (${ownerName}): ${e}`));
    }
  }
  return problems;
}

/** Throws a ConfigError with every problem, or returns the config typed. */
export function assertConfig(config: unknown, registry: ModuleRegistry): FlowConfig {
  const problems = validateConfig(config, registry);
  if (problems.length > 0) throw new ConfigError(problems);
  return config as FlowConfig;
}

/** Whether a value is a 1 to 3 assurance level, as a step's `level` must be. */
export function isStepLevel(value: unknown): value is 1 | 2 | 3 {
  return isIntegerIn(value, 1, 3);
}
