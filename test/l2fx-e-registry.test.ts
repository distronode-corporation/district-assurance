// L2 review fixes (worker e), the registry: a module's judges are read once, removal checks the
// judges installed, and a new build of a module never changes alwaysOn.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AssuranceModule, FactorPlugin } from "../src/core/module.ts";
import { rejects, setup, testConfig } from "./helpers.ts";

const token = (): FactorPlugin => ({ kind: "hardware_token", summary: "a code from a token", maxAttemptsPerCall: 2, adapters: [], judge: async () => false });
const tokenModule = (plugins: readonly FactorPlugin[]): AssuranceModule => ({
  manifest: { name: "token-check", version: "1", summary: "tokens", provides: { factors: ["hardware_token"], steps: [], outcomes: [] }, scopes: { grants: [], needs: {} }, adapters: [] },
  factorPlugins: plugins,
  validateSettings: () => [],
  requiredAdapters: () => [],
  validateStep: () => [],
  initCall: () => null,
  enterStep: () => null,
  stepStatus: () => "pending",
});
const tokenConfig = () =>
  testConfig((c) => {
    c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["hardware_token"]] };
    (c.modules.badge!.settings as { factors: string[] }).factors.push("hardware_token");
  });

describe("l2fx-e T0: a module's judges are read once", () => {
  it("refuses a module whose factorPlugins getter answers undefined, then a valid list", () => {
    const t = setup();
    let reads = 0;
    const module = tokenModule([]);
    Object.defineProperty(module, "factorPlugins", {
      get() {
        reads += 1;
        return reads === 1 ? undefined : [token()];
      },
    });
    assert.throws(() => t.engine.use(module), rejects("invalid_input", /factor hardware_token has no judge/));
    assert.equal(reads, 1);
    assert.equal(t.engine.registry.get("token-check"), undefined);
  });

  it("still lets Badge leave its list out", () => {
    const t = setup();
    assert.doesNotThrow(() => t.engine.useFactor(token()));
  });
});

describe("l2fx-e T1: removal checks the judges the registry installed", () => {
  it("refuses to remove a module whose installed judge the config names, though the host emptied its list", () => {
    const t = setup();
    const list = [token()];
    t.engine.use(tokenModule(list));
    t.engine.configure(tokenConfig());
    list.length = 0;
    assert.throws(() => t.engine.remove("token-check"), rejects("precondition_failed", /supplies the factor hardware_token/));
    assert.ok(t.engine.registry.get("token-check") !== undefined);
  });

  it("removes it once the config no longer names the factor", () => {
    const t = setup();
    t.engine.use(tokenModule([token()]));
    t.engine.remove("token-check");
    assert.equal(t.engine.registry.get("token-check"), undefined);
    assert.deepEqual(t.engine.registry.judgesOf("token-check"), []);
  });
});

describe("l2fx-e: replace keeps alwaysOn", () => {
  it("refuses a same-name build of the ledger module without alwaysOn, so it can never be removed after", () => {
    const t = setup();
    const trace = t.engine.registry.get("trace")!;
    const { alwaysOn: _dropped, ...manifest } = trace.manifest;
    assert.throws(() => t.engine.registry.replace({ ...trace, manifest }), rejects("invalid_input", /alwaysOn/));
    assert.throws(() => t.engine.registry.remove("trace"), rejects("precondition_failed"));
  });

  it("refuses a build that would make another module hold the ledger", () => {
    const t = setup();
    const badge = t.engine.registry.get("badge")!;
    assert.throws(() => t.engine.registry.replace({ ...badge, manifest: { ...badge.manifest, alwaysOn: true } }), rejects("invalid_input"));
  });

  it("keeps Badge's place in the order when it is swapped", () => {
    const t = setup();
    const before = t.engine.registry.list().map((m) => m.manifest.name);
    t.engine.useFactor(token());
    assert.deepEqual(
      t.engine.registry.list().map((m) => m.manifest.name),
      before,
    );
  });
});
