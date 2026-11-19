// MOD-1: the module contract, the built-in modules and the example Callback module against it, and
// what the suite catches in a broken module.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { bookCallback, callbackModule, callbackSettings, declineCallback } from "../examples/modules/callback.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import type { AssuranceModule, FlowStep } from "../src/core/module.ts";
import { builtInModules } from "../src/modules.ts";
import { moduleContract, type ModuleContractOptions } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig } from "./helpers.ts";

const config = testConfig();
const settingsOf = (name: string) => config.modules[name]!.settings;
const BUILT_IN_SAMPLES: Record<string, FlowStep[]> = {
  badge: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"], scopes: ["status.read"] }],
  dossier: [{ type: "dossier.collect", form: "repair" }],
  paylink: [{ type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" }],
  trace: [{ type: "trace.consent", purpose: "texts", require: "answer" }, { type: "trace.receipt" }],
};

for (const module of builtInModules()) {
  const name = module.manifest.name;
  describe(`the built-in ${name} module passes the module contract`, () => {
    // The built-in modules are the modules an outside one joins, so each is checked on its own.
    for (const c of moduleContract(module, { settings: settingsOf(name), steps: BUILT_IN_SAMPLES[name]!, installed: [] })) it(c.name, c.run);
  });
}

const CALLBACK_STEPS: FlowStep[] = [{ type: "callback.book" }, { type: "callback.book", window: "today" }];

describe("the example Callback module passes the module contract", () => {
  for (const c of moduleContract(callbackModule, { settings: callbackSettings, steps: CALLBACK_STEPS })) it(c.name, c.run);
});

/** A module with no settings, the smallest an author can write. */
const minimal: AssuranceModule = {
  manifest: {
    name: "minimal",
    version: "1",
    summary: "Waits for the host to say done.",
    provides: { factors: [], steps: ["minimal.wait"], outcomes: [] },
    scopes: { grants: [], needs: {} },
    adapters: [],
  },
  validateSettings: (settings) => (settings === undefined ? [] : ["takes no settings"]),
  requiredAdapters: () => [],
  validateStep: (step) => Object.keys(step).filter((k) => k !== "type").map((k) => `${k} is not a field of this step`),
  initCall: () => ({ done: false }),
  enterStep: () => null,
  stepStatus: (_step, view) => ((view.slice as { done: boolean }).done ? "complete" : "pending"),
};

describe("a module with no settings and no optional hooks passes the module contract with every default", () => {
  for (const c of moduleContract(minimal)) it(c.name, c.run);
});

describe("the example Callback module in a flow", () => {
  function callbackSetup() {
    const t = setup();
    t.engine.use(callbackModule);
    t.engine.configure(
      testConfig((c) => {
        c.policy.scopes["callback.book"] = 1;
        c.modules.callback = { settings: structuredClone(callbackSettings) as unknown as JsonValue };
        c.flows.callback = { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "callback.book", window: "tomorrow_morning" }] };
      }),
    );
    return t;
  }

  async function onCallbackStep(t: ReturnType<typeof setup>): Promise<string> {
    const { callId } = await t.engine.startCall({ flow: "callback" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    assert.deepEqual((await t.engine.flowPosition(callId))!.step, { type: "callback.book", window: "tomorrow_morning" });
    return callId;
  }

  it("books the step's window and completes the flow; another window does not count", async () => {
    const t = callbackSetup();
    const callId = await onCallbackStep(t);
    await t.engine.updateModule(callId, "callback", (slice) => bookCallback(slice, "today"));
    assert.equal((await t.engine.flowPosition(callId))!.status, "running");
    await t.engine.updateModule(callId, "callback", (slice, call) => {
      call.emit("booked", { window: "tomorrow_morning" });
      return bookCallback(slice, "tomorrow_morning");
    });
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");
    const entry = (await t.ledger.list()).find((e) => e.event === "module.event")!;
    assert.deepEqual(entry.detail, { module: "callback", event: "booked", detail: { window: "tomorrow_morning" } });
  });

  it("fails the flow when the caller declines, and refuses a window the call does not have", async () => {
    const t = callbackSetup();
    const callId = await onCallbackStep(t);
    await assert.rejects(t.engine.updateModule(callId, "callback", (slice) => bookCallback(slice, "never")), rejects("invalid_input", /no such callback window/));
    await t.engine.updateModule(callId, "callback", declineCallback);
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
  });

  it("needs its scope: a flow that books before verifying is refused when it is saved", () => {
    const t = callbackSetup();
    const unverified = testConfig((c) => {
      c.policy.scopes["callback.book"] = 1;
      c.modules.callback = { settings: structuredClone(callbackSettings) as unknown as JsonValue };
      c.flows.callback = { steps: [{ type: "callback.book" }] };
    });
    assert.throws(() => t.engine.configure(unverified), /needs the scope callback.book at level 1, but the flow has verified to level 0/);
  });

  it("explains every problem with its settings and steps", () => {
    assert.deepEqual(callbackModule.validateSettings({ windows: [], extra: 1 }), ["extra is not a callback setting", "windows must list at least one window"]);
    assert.deepEqual(callbackModule.validateSettings({ windows: [1, { id: "Bad", label: { en: "a" }, x: 1 }, { id: "a", label: { en: "a", fr: "b" } }, { id: "a", label: { en: "a", fr: "b" } }] }), [
      "windows[0] must be an object",
      "windows[1].x is not a window field",
      "windows[1].id must be snake_case",
      "windows[1].label needs English and French",
      "two windows have the same id",
    ]);
    const ctx = { settings: callbackSettings, policy: null, adapters: new Set<string>() };
    assert.deepEqual(callbackModule.validateStep({ type: "callback.book", window: 3, x: 1 }, ctx), ["x is not a field of this step", "window must name a window"]);
    assert.deepEqual(callbackModule.validateStep({ type: "callback.book", window: "never" }, ctx), ["no window never in the callback settings"]);
    assert.deepEqual(callbackModule.validateStep({ type: "callback.book", window: "never" }, { ...ctx, settings: null }), []);
    const slice = callbackModule.initCall(callbackSettings);
    assert.equal(callbackModule.cannotRunStep!({ type: "callback.book", window: "never" }, slice), "this call has no callback window never");
    assert.equal(callbackModule.cannotRunStep!({ type: "callback.book" }, slice), null);
  });
});

/** The names and messages of the cases a module fails. */
async function failures(module: AssuranceModule, options: ModuleContractOptions = { settings: callbackSettings, steps: CALLBACK_STEPS }): Promise<string[]> {
  const failed: string[] = [];
  for (const c of moduleContract(module, options)) await c.run().catch((e: unknown) => failed.push(`${c.name}: ${(e as Error).message}`));
  return failed;
}

const broken = (patch: Partial<AssuranceModule>): AssuranceModule => ({ ...callbackModule, ...patch });

/** A function that answers differently each time it is called. */
function counter<T>(make: (n: number) => T): () => T {
  let n = 0;
  return () => make(n++);
}

describe("the module contract catches", () => {
  const CATCHES: Array<[string, AssuranceModule, RegExp, ModuleContractOptions?]> = [
    ["a name a built-in module has", broken({ manifest: { ...callbackModule.manifest, name: "badge" } }), /^the manifest[\s\S]*a module named badge is already installed/],
    ["a manifest that is not JSON", broken({ manifest: { ...callbackModule.manifest, summary: undefined as unknown as string } }), /^the manifest.*must return JSON/],
    ["settings it refuses", broken({ validateSettings: () => ["no"] }), /^accepts its sample settings.*the sample settings/],
    ["requiredAdapters without the manifest's adapters", broken({ manifest: { ...callbackModule.manifest, adapters: ["records"] } }), /requiredAdapters must include the manifest's records/],
    ["requiredAdapters that is not a list", broken({ requiredAdapters: () => "records" as unknown as string[] }), /requiredAdapters must return a list of strings/],
    ["a step type with no sample", callbackModule, /no sample step of type callback.book/, { settings: callbackSettings, steps: [] }],
    ["a sample step it does not provide", callbackModule, /the sample step loyalty.lookup is not one the module provides/, { settings: callbackSettings, steps: [...CALLBACK_STEPS, { type: "loyalty.lookup" }] }],
    ["a sample step it refuses", callbackModule, /the sample step/, { settings: callbackSettings, steps: [{ type: "callback.book", window: "never" }] }],
    [
      "settings validation that throws on garbage",
      broken({ validateSettings: (s) => ((s as { windows: unknown[] }).windows.length === 0 ? ["empty"] : []) }),
      /^validateSettings never throws.*validateSettings with settings spoiled, as undefined, threw/,
    ],
    [
      "settings validation that throws on a lone surrogate",
      broken({
        validateSettings: (s) => {
          const windows = (s as { windows?: unknown } | null | undefined)?.windows;
          if (Array.isArray(windows)) for (const w of windows) if (typeof (w as { id?: unknown })?.id === "string") encodeURIComponent((w as { id: string }).id);
          return callbackModule.validateSettings(s);
        },
      }),
      /validateSettings with settings\.windows\[0\]\.id spoiled, as .*\\ud800.* threw: URI malformed/i,
    ],
    ["settings validation that throws something that is not an Error", broken({ validateSettings: (s) => { if (s === null) throw "nope"; return []; } }), /threw: 'nope'/],
    ["settings validation that answers with something else", broken({ validateSettings: (s) => (s === null ? (true as unknown as string[]) : []) }), /validateSettings with settings spoiled, as null, must return a list of strings/],
    ["settings validation that changes the settings", broken({ validateSettings: (s) => { (s as { windows: unknown[] }).windows.push(1); return []; } }), /Cannot add property|object is not extensible/],
    [
      "step validation that throws on garbage",
      broken({ validateStep: (step) => (step.window === undefined || (step.window as string).length > 0 ? [] : []) }),
      /^validateStep, stepLevel.*validateStep with callback.book.window spoiled, as .*window: null.*, threw/,
    ],
    ["step validation that changes the context", broken({ validateStep: (_step, ctx) => { (ctx as { settings: unknown }).settings = null; return []; } }), /^accepts its sample settings.*validateStep\(callback.book\) threw: Cannot assign to read only property 'settings'/],
    ["step validation that adds an adapter", broken({ validateStep: (_step, ctx) => { (ctx.adapters as Set<string>).add("records"); return []; } }), /^accepts its sample settings.*must not change the adapters it is given/],
    [
      "step validation that changes the adapters on garbage",
      broken({ validateStep: (step, ctx) => { if (step.window === null) (ctx.adapters as Set<string>).add("records"); return []; } }),
      /^validateStep, stepLevel.*validateStep with callback.book.window spoiled.*must not change the adapters it is given/,
    ],
    ["stepLevel that throws on garbage", broken({ stepLevel: (step) => (step.window === undefined ? null : (step.window as string).length) }), /stepLevel with callback.book.window spoiled, as .*window: null.*, threw/],
    ["stepLevel that is not a level", broken({ stepLevel: () => 0.5 }), /stepLevel with .* must return a level or null/],
    ["stepGrants that is not a list", broken({ stepGrants: () => "status.read" as unknown as string[] }), /stepGrants with .* must return a list of strings/],
    ["an initCall that throws", broken({ initCall: () => { throw new Error("boom"); } }), /^initCall and enterStep.*initCall threw: boom/],
    ["an initCall that is not JSON", broken({ initCall: () => ({ at: new Date(0) }) as unknown as JsonValue }), /initCall must return JSON/],
    ["an initCall that changes", broken({ initCall: counter((n) => ({ windows: [], answers: [], n })) }), /initCall must return the same part each time/],
    ["an enterStep that is not JSON", broken({ enterStep: () => undefined as unknown as JsonValue }), /enterStep\(callback.book\) must return JSON/],
    ["an enterStep that changes", broken({ enterStep: counter((n) => n) }), /enterStep\(callback.book\) must return the same mark each time/],
    ["an enterStep that changes the slice", broken({ enterStep: (_s, slice) => (slice as { answers: unknown[] }).answers.push(1) }), /enterStep\(callback.book\) threw/],
    ["a stepStatus that is not a status", broken({ stepStatus: () => "done" as unknown as "complete" }), /stepStatus\(callback.book\) returned 'done'/],
    ["a stepStatus that changes the view", broken({ stepStatus: (_s, view) => { (view.slice as { answers: unknown[] }).answers.push(1); return "pending"; } }), /stepStatus\(callback.book\) threw/],
    ["a stepStatus that answers differently each time", broken({ stepStatus: counter((n) => (n < 8 ? "pending" : "complete")) }), /must give the same answer each time/],
    [
      "a stepStatus that remembers the last call",
      (() => {
        let last: "pending" | "failed" = "pending";
        return broken({
          stepStatus: (_s, view) => {
            const answer = last;
            last = view.state.phase === "ended" ? "failed" : "pending";
            return answer;
          },
        });
      })(),
      /must not depend on earlier calls/,
    ],
    ["a cannotRunStep that answers with a number", broken({ cannotRunStep: () => 1 as unknown as string }), /cannotRunStep must return null or a sentence/],
    ["a blocksEnd that answers undefined", broken({ blocksEnd: () => undefined as unknown as null }), /blocksEnd must return null or a sentence/],
    ["an onUntrusted that throws", broken({ onUntrusted: () => { throw new Error("boom"); } }), /onUntrusted threw: boom/],
    ["an onUntrusted that is not JSON", broken({ onUntrusted: () => new Map() as unknown as JsonValue }), /onUntrusted must return JSON/],
    ["a receiptPart that is not an object", broken({ receiptPart: () => [] as unknown as { [key: string]: JsonValue } }), /receiptPart must return an object/],
    ["a receiptPart that is not JSON", broken({ receiptPart: () => ({ x: undefined }) as unknown as { [key: string]: JsonValue } }), /receiptPart must return JSON/],
  ];

  for (const [name, module, expected, options] of CATCHES) {
    it(name, async () => {
      const failed = await failures(module, options);
      assert.ok(failed.some((f) => expected.test(f)), `expected a failure matching ${expected}, got:\n${failed.join("\n")}`);
    });
  }

  it("nothing in the example module or the smallest module", async () => {
    assert.deepEqual(await failures(callbackModule), []);
    assert.deepEqual(await failures(minimal, {}), []);
  });
});
