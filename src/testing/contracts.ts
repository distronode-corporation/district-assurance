// Contract suites: the guarantees a host's durable adapter must keep, written once and run
// against any implementation. Each suite returns its cases as plain async functions, so a host
// runs them under whatever test runner it uses (node:test, vitest, jest):
//
//   for (const c of sessionStoreContract(() => new MyDatabaseSessionStore(...))) it(c.name, c.run);
//
// `moduleContract` is the same idea for the author of an outside module (MOD-1).
import { strict as assert } from "node:assert";
import { inspect } from "node:util";

import type { SessionStore } from "../core/adapters.ts";
import { canonicalJson } from "../core/canonical.ts";
import { checkManifest, type AssuranceModule, type FlowStep, type StepContext, type StepView } from "../core/module.ts";
import { defaultVerificationPolicy, type VerificationPolicy } from "../core/policy.ts";
import { newSession, type Grant, type SessionState } from "../core/session.ts";
import { isObject } from "../core/shape.ts";
import { builtInModules } from "../modules.ts";

export interface ContractCase {
  name: string;
  run(): Promise<void>;
}

/** The SessionStore contract (INT-3). `factory` returns a new, empty store for each case. */
export function sessionStoreContract(factory: () => SessionStore | Promise<SessionStore>): ContractCase[] {
  const cases: Array<[string, (store: SessionStore) => Promise<void>]> = [
    [
      "creates a session at version 1 and returns copies",
      async (store) => {
        const record = { phase: "open", items: [1] };
        assert.equal(await store.create("w", "c1", record), true);
        record.items.push(2);
        const got = await store.get("w", "c1");
        assert.deepEqual(got, { version: 1, record: { phase: "open", items: [1] } });
        (got!.record as { items: number[] }).items.push(3);
        assert.deepEqual((await store.get("w", "c1"))!.record, { phase: "open", items: [1] });
      },
    ],
    [
      "refuses to create a session that exists, and keeps the first",
      async (store) => {
        await store.create("w", "c1", { n: 1 });
        assert.equal(await store.create("w", "c1", { n: 2 }), false);
        assert.deepEqual(await store.get("w", "c1"), { version: 1, record: { n: 1 } });
      },
    ],
    [
      "keeps workspaces apart and answers null for an unknown session",
      async (store) => {
        await store.create("w1", "c1", { n: 1 });
        assert.equal(await store.get("w2", "c1"), null);
        assert.equal(await store.get("w1", "c2"), null);
        assert.equal(await store.create("w2", "c1", { n: 2 }), true);
        assert.deepEqual((await store.get("w1", "c1"))!.record, { n: 1 });
      },
    ],
    [
      "writes only on the expected version, one version at a time",
      async (store) => {
        await store.create("w", "c1", { n: 1 });
        assert.deepEqual(await store.compareAndSet("w", "c1", 1, { n: 2 }), { ok: true, version: 2 });
        assert.deepEqual(await store.compareAndSet("w", "c1", 1, { n: 3 }), { ok: false });
        assert.deepEqual(await store.get("w", "c1"), { version: 2, record: { n: 2 } });
        assert.deepEqual(await store.compareAndSet("w", "c1", 2, { n: 3 }), { ok: true, version: 3 });
        assert.deepEqual(await store.compareAndSet("w", "missing", 1, { n: 1 }), { ok: false });
        assert.deepEqual(await store.compareAndSet("w2", "c1", 3, { n: 9 }), { ok: false });
      },
    ],
    [
      "lets exactly one of two concurrent writers on the same version win",
      async (store) => {
        await store.create("w", "c1", { n: 0 });
        const results = await Promise.all([store.compareAndSet("w", "c1", 1, { n: 1 }), store.compareAndSet("w", "c1", 1, { n: 2 })]);
        assert.equal(results.filter((r) => r.ok).length, 1);
        const stored = await store.get("w", "c1");
        assert.equal(stored!.version, 2);
        assert.equal((stored!.record as { n: number }).n, results.findIndex((r) => r.ok) + 1, "the stored record is the winner's");
      },
    ],
    [
      "never lets two workspace and call id pairs share a key",
      async (store) => {
        assert.equal(await store.create("north", "branch/c1", { n: 1 }), true);
        assert.equal(await store.create("north/branch", "c1", { n: 2 }), true);
        assert.deepEqual((await store.get("north", "branch/c1"))!.record, { n: 1 });
        assert.deepEqual((await store.get("north/branch", "c1"))!.record, { n: 2 });
        assert.equal(await store.bindRef("a", "b/c", "c1"), true);
        assert.equal(await store.resolveRef("a/b", "c"), null);
      },
    ],
    [
      "binds a reference once, per workspace, and resolves it",
      async (store) => {
        assert.equal(await store.resolveRef("w", "payment:cs_1"), null);
        assert.equal(await store.bindRef("w", "payment:cs_1", "c1"), true);
        assert.equal(await store.bindRef("w", "payment:cs_1", "c2"), false);
        assert.equal(await store.resolveRef("w", "payment:cs_1"), "c1");
        assert.equal(await store.resolveRef("w2", "payment:cs_1"), null);
      },
    ],
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body(await factory()) }));
}

export interface ModuleContractOptions {
  /** Valid settings for the module, as a FlowConfig would hold them. Default: none (undefined). */
  settings?: unknown;
  /** Valid flow steps, at least one of each step type the module provides. Default: `{ type }` for each. */
  steps?: readonly FlowStep[];
  /** The policy the steps are checked under. Default: `defaultVerificationPolicy()`. */
  policy?: VerificationPolicy;
  /** The modules the manifest must not clash with. Default: the built-in modules. */
  installed?: readonly AssuranceModule[];
}

/**
 * Values settings and steps can hold when they come from storage or an operator's editor: every
 * JSON type, keys that read as JavaScript internals, keys named like methods, a long string, deep
 * nesting, and a missing value. A validator answers each with sentences, never a crash.
 */
function garbage(): unknown[] {
  const sparse: unknown[] = [];
  sparse.length = 2;
  let deep: unknown = "x";
  for (let i = 0; i < 100; i++) deep = [deep];
  return [
    undefined,
    null,
    true,
    false,
    0,
    -1,
    0.5,
    1e308,
    "",
    " ",
    "x",
    "x".repeat(100_000),
    "__proto__",
    "constructor",
    [],
    [null],
    ["x", 1],
    sparse,
    {},
    { x: null },
    JSON.parse('{"__proto__": {"polluted": true}}'),
    JSON.parse('{"toString": 1, "valueOf": 1, "constructor": 1, "hasOwnProperty": 1}'),
    deep,
  ];
}

/** Each way to spoil a value: replace it, or anything inside it, with garbage; drop a key; add one. */
function* spoiled(value: unknown, path: string): Generator<[path: string, value: unknown]> {
  for (const g of garbage()) yield [path, g];
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      for (const [at, inner] of spoiled(value[i], `${path}[${i}]`)) yield [at, value.with(i, inner)];
    }
  } else if (isObject(value)) {
    yield* spoiledFields(value, path, []);
  }
}

/** Spoils each field of an object but the `keep` ones, drops each, and adds an unknown one. */
function* spoiledFields(value: Record<string, unknown>, path: string, keep: readonly string[]): Generator<[path: string, value: unknown]> {
  for (const key of Object.keys(value).filter((k) => !keep.includes(k))) {
    for (const [at, inner] of spoiled(value[key], `${path}.${key}`)) yield [at, { ...value, [key]: inner }];
    const rest = { ...value };
    delete rest[key];
    yield [`${path}.${key} (missing)`, rest];
  }
  yield [`${path}.unexpected_field`, { ...value, unexpected_field: 1 }];
}

/** A deep copy that nothing can change: a module that writes to what it is given throws. */
function frozen<T>(value: T): T {
  const copy = structuredClone(value);
  const freeze = (v: unknown): void => {
    if (typeof v !== "object" || v === null) return;
    Object.freeze(v);
    for (const inner of Object.values(v)) freeze(inner);
  };
  freeze(copy);
  return copy;
}

const show = (value: unknown) => inspect(value, { depth: 2, maxArrayLength: 3, maxStringLength: 20, breakLength: Infinity });

/** Runs `fn`, and fails the case naming what it was given if it throws. */
function mustNotThrow<T>(what: string, fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    assert.fail(`${what} threw: ${e instanceof Error ? e.message : show(e)}`);
  }
}

function assertSentences(value: unknown, what: string): void {
  assert.ok(Array.isArray(value) && value.every((s) => typeof s === "string"), `${what} must return a list of strings, got ${show(value)}`);
}

function assertJson(value: unknown, what: string): string {
  return mustNotThrow(`${what} must return JSON: canonicalJson`, () => canonicalJson(value));
}

function assertNullOrString(value: unknown, what: string): void {
  assert.ok(value === null || typeof value === "string", `${what} must return null or a sentence, got ${show(value)}`);
}

/** Calls a module's step is judged on: a new call, a verified one, a tainted one, an ended one. */
function sampleStates(): SessionState[] {
  const at = "2026-01-01T00:00:00.000Z";
  const open = newSession("call_contract", "ws_contract", at);
  const grant: Grant = { grantId: "grant_contract", level: 2, scopes: ["status.read"], issuedAt: at, expiresAt: "2026-01-01T00:15:00.000Z" };
  const verified: SessionState = { ...open, level: 2, grant, factors: [{ kind: "keypad_knowledge", passed: true, at }] };
  return [open, verified, { ...verified, tainted: true, level: 0, grant: null }, { ...open, phase: "ended", endedAt: at }];
}

const STEP_STATUSES: readonly unknown[] = ["pending", "complete", "failed"];

/**
 * The module contract (MOD-1): what an outside module must keep before a host installs it with
 * `engine.use(module)`. The manifest passes `checkManifest` against the modules it joins; the
 * validators answer garbage with sentences and never throw; `initCall`, `enterStep` and the
 * optional hooks return JSON and change nothing they are given; `stepStatus` is pure.
 *
 *   for (const c of moduleContract(myModule, { settings, steps })) it(c.name, c.run);
 */
export function moduleContract(module: AssuranceModule, options: ModuleContractOptions = {}): ContractCase[] {
  const { manifest } = module;
  const settings = options.settings;
  const steps = options.steps ?? manifest.provides.steps.map((type) => ({ type }));
  const policy = options.policy ?? defaultVerificationPolicy();
  const installed = options.installed ?? builtInModules();
  const goodContext = (): StepContext =>
    Object.freeze({ settings: frozen(settings), policy: frozen(policy), adapters: new Set(module.requiredAdapters(frozen(settings))) });
  const emptyContext = (): StepContext => Object.freeze({ settings: null, policy: null, adapters: new Set<string>() });
  /** validateStep on a frozen context. A host shares its adapter set, so a change to it fails the case. */
  const validateStep = (step: FlowStep, ctx: StepContext, what: string): string[] => {
    const before = [...ctx.adapters];
    const problems = mustNotThrow(what, () => module.validateStep(frozen(step), ctx));
    assert.deepEqual([...ctx.adapters], before, `${what} must not change the adapters it is given`);
    return problems;
  };

  const cases: Array<[string, () => void]> = [
    [
      "the manifest passes checkManifest against the modules it joins, and is JSON",
      () => {
        assert.deepEqual(checkManifest(manifest, installed), []);
        assertJson(manifest, "the manifest");
      },
    ],
    [
      "accepts its sample settings and a sample of every step it provides",
      () => {
        assert.deepEqual(module.validateSettings(frozen(settings)), [], "the sample settings");
        const adapters = module.requiredAdapters(frozen(settings));
        assertSentences(adapters, "requiredAdapters");
        for (const adapter of manifest.adapters) assert.ok(adapters.includes(adapter), `requiredAdapters must include the manifest's ${adapter}`);
        for (const type of manifest.provides.steps) assert.ok(steps.some((s) => s.type === type), `no sample step of type ${type}`);
        for (const step of steps) {
          assert.ok(manifest.provides.steps.includes(step.type), `the sample step ${step.type} is not one the module provides`);
          assert.deepEqual(validateStep(step, goodContext(), `validateStep(${step.type})`), [],`the sample step ${show(step)}`);
        }
      },
    ],
    [
      "validateSettings never throws on garbage, and answers with sentences",
      () => {
        for (const [at, value] of spoiled(settings, "settings")) {
          const what = `validateSettings with ${at} spoiled, as ${show(value)},`;
          assertSentences(mustNotThrow(what, () => module.validateSettings(frozen(value))), what);
        }
      },
    ],
    [
      "validateStep, stepLevel and stepGrants never throw on a garbage step",
      () => {
        for (const step of steps) {
          for (const [at, value] of spoiledFields(step, step.type, ["type"])) {
            const bad = value as FlowStep;
            const what = `with ${at} spoiled, as ${show(value)},`;
            for (const ctx of [goodContext(), emptyContext()]) {
              assertSentences(validateStep(bad, ctx, `validateStep ${what}`), `validateStep ${what}`);
            }
            // validateConfig asks for a step's level and grants even when the step has problems.
            const level = mustNotThrow(`stepLevel ${what}`, () => module.stepLevel?.(frozen(bad)) ?? null);
            assert.ok(level === null || Number.isInteger(level), `stepLevel ${what} must return a level or null`);
            const grants = mustNotThrow(`stepGrants ${what}`, () => module.stepGrants?.(frozen(bad)) ?? null);
            if (grants !== null) assertSentences(grants, `stepGrants ${what}`);
          }
        }
      },
    ],
    [
      "initCall and enterStep return JSON, the same each time, and change nothing they are given",
      () => {
        const slice = mustNotThrow("initCall", () => module.initCall(frozen(settings)));
        const json = assertJson(slice, "initCall");
        assert.equal(canonicalJson(module.initCall(frozen(settings))), json, "initCall must return the same part each time");
        for (const step of steps) {
          const what = `enterStep(${step.type})`;
          const mark = assertJson(mustNotThrow(what, () => module.enterStep(frozen(step), frozen(slice))), what);
          assert.equal(canonicalJson(module.enterStep(frozen(step), frozen(slice))), mark, `${what} must return the same mark each time`);
        }
      },
    ],
    [
      "stepStatus is pure: the same view gets the same answer, in any order, and nothing changes",
      () => {
        const slice = module.initCall(frozen(settings));
        for (const step of steps) {
          const mark = module.enterStep(frozen(step), frozen(slice));
          const views: StepView[] = sampleStates().map((state) => frozen({ state, slice, mark }));
          const judge = (view: StepView) => mustNotThrow(`stepStatus(${step.type})`, () => module.stepStatus(frozen(step), view));
          const first = views.map(judge);
          for (const status of first) assert.ok(STEP_STATUSES.includes(status), `stepStatus(${step.type}) returned ${show(status)}`);
          assert.deepEqual([...views].reverse().map(judge).reverse(), first, `stepStatus(${step.type}) must not depend on earlier calls`);
          assert.deepEqual(views.map(judge), first, `stepStatus(${step.type}) must give the same answer each time`);
        }
      },
    ],
    [
      "the optional hooks it has return what they promise, and change nothing they are given",
      () => {
        const slice = module.initCall(frozen(settings));
        if (module.cannotRunStep !== undefined) {
          for (const step of steps) assertNullOrString(mustNotThrow("cannotRunStep", () => module.cannotRunStep!(frozen(step), frozen(slice))), "cannotRunStep");
        }
        if (module.blocksEnd !== undefined) assertNullOrString(mustNotThrow("blocksEnd", () => module.blocksEnd!(frozen(slice))), "blocksEnd");
        if (module.onUntrusted !== undefined) assertJson(mustNotThrow("onUntrusted", () => module.onUntrusted!(frozen(slice))), "onUntrusted");
        if (module.receiptPart !== undefined) {
          for (const state of sampleStates()) {
            const part = mustNotThrow("receiptPart", () => module.receiptPart!(frozen(slice), frozen(state)));
            assert.ok(isObject(part), "receiptPart must return an object");
            assertJson(part, "receiptPart");
          }
        }
      },
    ],
  ];
  return cases.map(([name, body]) => ({ name, run: async () => body() }));
}
