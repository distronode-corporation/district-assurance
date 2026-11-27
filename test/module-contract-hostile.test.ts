// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile-pass regressions for #98 (MOD-1, the module contract): modules that must fail it. C1
// failed before the contract held stepLevel to 0 to 3 (it took any integer); the rest held.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { callbackModule, callbackSettings } from "../examples/modules/callback.ts";
import type { AssuranceModule, FlowStep } from "../src/core/module.ts";
import { moduleContract } from "../src/testing/index.ts";

const STEPS: FlowStep[] = [{ type: "callback.book" }, { type: "callback.book", window: "today" }];
const broken = (patch: Partial<AssuranceModule>): AssuranceModule => ({ ...callbackModule, ...patch });

async function failures(module: AssuranceModule): Promise<string[]> {
  const failed: string[] = [];
  for (const c of moduleContract(module, { settings: callbackSettings, steps: STEPS })) await c.run().catch(() => failed.push(c.name));
  return failed;
}

describe("hostile #98: the module contract catches", () => {
  it("C1: a stepLevel that is not a level from 0 to 3", async () => {
    for (const level of [7, -1, 4, 2.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.notDeepEqual(await failures(broken({ stepLevel: () => level })), [], String(level));
    }
    assert.deepEqual(await failures(broken({ stepLevel: () => 2 })), [], "a real level passes");
  });

  it("C2: a validateStep that adds to, or empties, the adapter set it is given", async () => {
    assert.notDeepEqual(await failures(broken({ validateStep: (s, ctx) => ((ctx.adapters as Set<string>).add("payments"), callbackModule.validateStep(s, ctx)) })), []);
    const withRecords = { requiredAdapters: () => ["records"] };
    assert.notDeepEqual(await failures(broken({ ...withRecords, validateStep: (s, ctx) => ((ctx.adapters as Set<string>).clear(), callbackModule.validateStep(s, ctx)) })), []);
  });

  it("C3: a stepStatus that keeps state between calls", async () => {
    let calls = 0;
    assert.notDeepEqual(await failures(broken({ stepStatus: () => (calls++ % 2 === 0 ? "pending" : "complete") })), []);
  });

  it("C4: initCall, enterStep or receiptPart answers that are not JSON, or not the shape promised", async () => {
    for (const patch of [
      { initCall: () => ({ at: new Date(0) }) as never },
      { initCall: () => ({ n: Number.NaN }) as never },
      { initCall: () => undefined as never },
      { enterStep: () => (() => 1) as never },
      { receiptPart: () => [] as never },
      { receiptPart: () => null as never },
      { blocksEnd: () => 1 as never },
      { cannotRunStep: () => false as never },
    ] as Array<Partial<AssuranceModule>>) {
      assert.notDeepEqual(await failures(broken(patch)), [], Object.keys(patch)[0]);
    }
  });

  it("C5: validators that throw on what storage can hold: a lone surrogate, a prototype key, deep nesting", async () => {
    const strings = (v: unknown): string[] => (typeof v === "string" ? [v] : typeof v === "object" && v !== null ? Object.values(v).flatMap(strings) : []);
    for (const validateSettings of [
      // encodeURIComponent throws on a lone surrogate.
      (v: unknown) => (strings(v).forEach((x) => encodeURIComponent(x)), callbackModule.validateSettings(v)),
      // Reads a field of what may not be an object.
      (v: unknown) => ((v as { windows: Array<{ id: string }> }).windows.map((w) => w.id.length), callbackModule.validateSettings(v)),
      // A depth limit written as a throw: 100 nested arrays reach it.
      (v: unknown) => {
        let depth = 0;
        for (let x = v; Array.isArray(x); x = x[0]) if (++depth > 50) throw new RangeError("too deep");
        return callbackModule.validateSettings(v);
      },
    ]) {
      assert.notDeepEqual(await failures(broken({ validateSettings })), [], String(validateSettings).slice(0, 60));
    }
  });

  it("C6: a manifest that takes a built-in step or factor name", async () => {
    for (const provides of [
      { factors: [], steps: ["badge.verify"], outcomes: [] },
      { factors: ["pin"], steps: ["callback.book"], outcomes: [] },
    ]) {
      assert.notDeepEqual(await failures(broken({ manifest: { ...callbackModule.manifest, provides } })), [], JSON.stringify(provides));
    }
  });
});
