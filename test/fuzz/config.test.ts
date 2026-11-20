// SRV-7: validateConfig on garbage and on valid configs broken in a few random places. It never
// throws, never changes its input, answers the same twice, and lists problems as sentences.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import fc from "fast-check";

import { demoConfig } from "../../examples/reference-server/src/flows.ts";
import { ConfigError, assertConfig, validateConfig } from "../../src/core/config.ts";
import { ModuleRegistry } from "../../src/core/module.ts";
import type { AdapterName } from "../../src/core/runtime.ts";
import { builtInModules, defaultConfig } from "../../src/modules.ts";
import { testConfig } from "../helpers.ts";
import { fuzz, int, jsonValue, mutate, pick } from "./harness.ts";

// Every adapter the engine takes: the Record type fails to compile when one is added and not listed.
const ADAPTERS: Record<AdapterName, true> = {
  ledger: true,
  sessions: true,
  records: true,
  identity: true,
  carrier: true,
  messages: true,
  payments: true,
  signer: true,
  pinVerifier: true,
  amounts: true,
  access: true,
  accessSigner: true,
  stepUpSigner: true,
  codes: true,
  counters: true,
  dialer: true,
  notifier: true,
  duressNotifier: true,
  fieldCipher: true,
  consents: true,
  anchor: true,
};
const ALL_ADAPTERS = Object.keys(ADAPTERS) as AdapterName[];

/** Valid configs to start from: the default, the tests' full one, and the demo's flows. */
const BASES = [defaultConfig, testConfig, demoConfig];

// Sometimes without a few adapters, so "needs the ... adapter" problems come up too.
const registry: fc.Arbitrary<ModuleRegistry> = fc
  .subarray(ALL_ADAPTERS.filter((name) => name !== "ledger" && name !== "sessions"))
  .map((optional) => new ModuleRegistry({ adapters: ["ledger", "sessions", ...optional], modules: builtInModules() }));

/** Garbage now and then; otherwise a valid config broken in one to four places. */
function input(g: fc.GeneratorValue): unknown {
  if (int(g, 0, 9) === 0) return g(jsonValue, 4);
  let config: unknown = pick(g, BASES)();
  for (let n = int(g, 1, 4); n > 0; n--) config = mutate(g, config);
  return config;
}

/** Checks one answer of validateConfig: sentences with paths, the input untouched, the same twice. */
function checkProblems(config: unknown, registry: ModuleRegistry): string[] {
  const before = structuredClone(config);
  const problems = validateConfig(config, registry);
  assert.ok(Array.isArray(problems));
  for (const problem of problems) {
    assert.equal(typeof problem, "string");
    // A path, then the sentence. The path is the config's own keys as written, so a key that is
    // empty or holds ": " is shown as is.
    assert.match(problem, /^(the config must be an object|.*: .+)$/su, problem);
  }
  assert.deepEqual(config, before, "the config is not changed");
  assert.deepEqual(validateConfig(config, registry), problems, "the same answer twice");
  if (problems.length === 0) assert.equal(assertConfig(config, registry), config);
  else assert.throws(() => assertConfig(config, registry), (e: unknown) => e instanceof ConfigError && e.code === "invalid_input" && e.problems.length === problems.length);
  return problems;
}

describe("fuzz: validateConfig", () => {
  for (const base of BASES) {
    it(`accepts the valid ${base.name}`, () => {
      assert.deepEqual(validateConfig(base(), new ModuleRegistry({ adapters: ALL_ADAPTERS, modules: builtInModules() })), []);
    });
  }

  it("never throws, never changes its input, and lists every problem as a sentence with its path", async () => {
    await fuzz(fc.property(registry, fc.gen(), (registry, g) => void checkProblems(input(g), registry)));
  });

  it("shows an empty key as an empty path (found by fuzzing)", () => {
    const all = new ModuleRegistry({ adapters: ALL_ADAPTERS, modules: builtInModules() });
    const config = defaultConfig();
    assert.deepEqual(checkProblems({ ...config, "": 1 }, all), [": not a config field"]);
    const flows = { ...config.flows, "": Object.values(config.flows)[0]! };
    assert.deepEqual(checkProblems({ ...config, flows }, all), ["flows.: a flow name is lower-case letters, digits and hyphens, at most 64", "flows.: must be an object with at least one step"]);
  });
});
