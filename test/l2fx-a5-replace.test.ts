// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// L2 review fix V1 (worker a5): on an engine's registry a module supplying factors is not replaced
// from outside, so the judge the registry lists is always the one Badge runs.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { ModuleRegistry, type AssuranceModule, type FactorPlugin } from "../src/core/module.ts";
import { rejects, setup } from "./helpers.ts";

const token = (answer: boolean): FactorPlugin => ({ kind: "hardware_token", summary: "a code from a token", maxAttemptsPerCall: 2, adapters: [], judge: async () => answer });
const moduleOf = (factors: string[], plugins: readonly FactorPlugin[], version = "1"): AssuranceModule => ({
  manifest: { name: "desk-code", version, summary: "desk codes", provides: { factors, steps: [], outcomes: [] }, scopes: { grants: [], needs: {} }, adapters: [] },
  factorPlugins: plugins,
  validateSettings: () => [],
  requiredAdapters: () => [],
  validateStep: () => [],
  initCall: () => null,
  enterStep: () => null,
  stepStatus: () => "pending",
});

describe("l2fx-a5 V1: an engine's registry keeps factor suppliers in step with Badge", () => {
  it("refuses a new build of an installed factor supplier, and keeps the installed judge", () => {
    const t = setup();
    const installed = moduleOf(["hardware_token"], [token(true)]);
    t.engine.use(installed);
    const judges = t.engine.registry.judgesOf("desk-code");
    assert.throws(() => t.engine.registry.replace(moduleOf(["hardware_token"], [token(false)], "2")), rejects("invalid_input", /supplies factors/));
    assert.equal(t.engine.registry.get("desk-code"), installed);
    assert.equal(t.engine.registry.judgesOf("desk-code"), judges);
  });

  it("refuses a new build that would start supplying a factor", () => {
    const t = setup();
    const installed = moduleOf([], []);
    t.engine.use(installed);
    assert.throws(() => t.engine.registry.replace(moduleOf(["hardware_token"], [token(true)], "2")), rejects("invalid_input", /supplies factors/));
    assert.equal(t.engine.registry.get("desk-code"), installed);
    assert.deepEqual(t.engine.registry.factorPlugins(), []);
  });

  it("refuses a build without factors in place of a factor supplier", () => {
    const t = setup();
    t.engine.use(moduleOf(["hardware_token"], [token(true)]));
    assert.throws(() => t.engine.registry.replace(moduleOf([], [], "2")), rejects("invalid_input", /supplies factors/));
    assert.equal(t.engine.registry.judgesOf("desk-code").length, 1);
  });

  it("refuses a module that is not installed, as before", () => {
    const t = setup();
    assert.throws(() => t.engine.registry.replace(moduleOf([], [])), rejects("invalid_input", /no module named desk-code/));
  });

  it("still replaces an outside module without factors on an engine's registry", () => {
    const t = setup();
    t.engine.use(moduleOf([], []));
    const next = moduleOf([], [], "2");
    t.engine.registry.replace(next);
    assert.equal(t.engine.registry.get("desk-code"), next);
  });

  it("still replaces a factor supplier on a registry no engine owns", () => {
    const registry = new ModuleRegistry({ modules: [moduleOf(["hardware_token"], [token(true)])] });
    const next = moduleOf(["hardware_token"], [token(false)], "2");
    registry.replace(next);
    assert.equal(registry.get("desk-code"), next);
    assert.equal(registry.judgesOf("desk-code").length, 1);
  });
});
