// The JSON Schema for FlowConfig (schema/flow-config.v1.json): published with the package, in step
// with the TypeScript types, and never stricter than validateConfig, which stays the authority.
//
// There is no schema library here (no dependencies), so this file carries a small validator for
// the 2020-12 keywords the schema uses, and refuses a schema that uses any other.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { isDeepStrictEqual } from "node:util";

import { demoConfig } from "../examples/reference-server/src/flows.ts";
import { validateConfig, type FlowConfig, type FlowDefinition, type ModuleConfig } from "../src/core/config.ts";
import { ModuleRegistry, type AssuranceModule } from "../src/core/module.ts";
import { SCOPE_CLASSES, type LevelRule, type VerificationPolicy } from "../src/core/policy.ts";
import type { DossierCollectStep, DossierSettings } from "../src/file/dossier.ts";
import type { FieldType, IntakeField, IntakeForm } from "../src/file/intake.ts";
import { builtInModules, defaultConfig } from "../src/modules.ts";
import { PAYMENT_MODES, type PaylinkRequestStep, type PaylinkSettings } from "../src/pay/paylink.ts";
import type { AmountSource } from "../src/pay/payment.ts";
import type { ConsentWording } from "../src/prove/consent.ts";
import type { TraceConsentStep, TraceSettings } from "../src/prove/trace.ts";
import type { BadgeVerifyStep } from "../src/verify/badge.ts";
import type { BadgeSettings, PinMode, PinSettings } from "../src/verify/factors.ts";
import { testConfig } from "./helpers.ts";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Schema = boolean | { [key: string]: Json };

const SCHEMA_URL = new URL("../schema/flow-config.v1.json", import.meta.url);
const SCHEMA = JSON.parse(readFileSync(SCHEMA_URL, "utf8")) as { [key: string]: Json };

// ---- a validator for the keywords the schema uses ------------------------------------------

const KEYWORDS = new Set([
  "$schema", "$id", "$defs", "$ref", "title", "description",
  "type", "const", "enum", "not", "allOf", "if", "then", "else",
  "properties", "required", "additionalProperties", "propertyNames",
  "items", "minItems", "uniqueItems", "contains",
  "pattern", "minLength", "minimum", "maximum", "exclusiveMinimum",
]);

function isObject(value: unknown): value is { [key: string]: Json } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Every subschema, with its JSON pointer. */
function* subschemas(schema: Json, at = "#"): Generator<[string, Json]> {
  yield [at, schema];
  if (!isObject(schema)) return;
  for (const key of ["properties", "$defs"]) {
    if (isObject(schema[key])) for (const [name, sub] of Object.entries(schema[key])) yield* subschemas(sub, `${at}/${key}/${name}`);
  }
  for (const key of ["additionalProperties", "propertyNames", "items", "contains", "not", "if", "then", "else"]) {
    if (schema[key] !== undefined) yield* subschemas(schema[key], `${at}/${key}`);
  }
  if (Array.isArray(schema.allOf)) for (const [i, sub] of schema.allOf.entries()) yield* subschemas(sub, `${at}/allOf/${i}`);
}

function resolve(ref: string): Schema {
  assert.ok(ref === "#" || ref.startsWith("#/"), `only local references: ${ref}`);
  let node: Json = SCHEMA;
  for (const part of ref.split("/").slice(1)) {
    assert.ok(isObject(node) && Object.hasOwn(node, part), `the reference ${ref} resolves`);
    node = node[part]!;
  }
  return node as Schema;
}

function hasType(value: unknown, type: Json): boolean {
  switch (type) {
    case "object":
      return isObject(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number";
    case "integer":
      return Number.isInteger(value);
    case "boolean":
      return typeof value === "boolean";
    default:
      throw new Error(`type ${String(type)} is not supported here`);
  }
}

/** Where a value fails the schema, as JSON pointers with the keyword. Empty when it passes. */
function schemaErrors(schema: Schema, value: unknown, at = ""): string[] {
  if (schema === true) return [];
  if (schema === false) return [`${at}: false`];
  const errors: string[] = [];
  const fail = (keyword: string) => errors.push(`${at || "/"}: ${keyword}`);
  const sub = (key: string) => schema[key] as Schema;
  if (schema.$ref !== undefined) errors.push(...schemaErrors(resolve(schema.$ref as string), value, at));
  if (schema.type !== undefined && !hasType(value, schema.type)) fail("type");
  if (schema.const !== undefined && !isDeepStrictEqual(value, schema.const)) fail("const");
  if (Array.isArray(schema.enum) && !schema.enum.some((option) => isDeepStrictEqual(value, option))) fail("enum");
  if (schema.not !== undefined && schemaErrors(sub("not"), value, at).length === 0) fail("not");
  for (const part of (schema.allOf ?? []) as Schema[]) errors.push(...schemaErrors(part, value, at));
  if (schema.if !== undefined) {
    const branch = schemaErrors(sub("if"), value, at).length === 0 ? "then" : "else";
    if (schema[branch] !== undefined) errors.push(...schemaErrors(sub(branch), value, at));
  }
  if (isObject(value)) {
    const properties = (schema.properties ?? {}) as { [key: string]: Schema };
    for (const key of (schema.required ?? []) as string[]) if (!Object.hasOwn(value, key)) fail(`required ${key}`);
    for (const [key, item] of Object.entries(value)) {
      if (Object.hasOwn(properties, key)) errors.push(...schemaErrors(properties[key]!, item, `${at}/${key}`));
      else if (schema.additionalProperties !== undefined) errors.push(...schemaErrors(sub("additionalProperties"), item, `${at}/${key}`));
      if (schema.propertyNames !== undefined) errors.push(...schemaErrors(sub("propertyNames"), key, `${at}/${key} (name)`));
    }
  }
  if (Array.isArray(value)) {
    if (schema.items !== undefined) value.forEach((item, i) => errors.push(...schemaErrors(sub("items"), item, `${at}/${i}`)));
    if (typeof schema.minItems === "number" && value.length < schema.minItems) fail("minItems");
    if (schema.uniqueItems === true && value.some((a, i) => value.slice(i + 1).some((b) => isDeepStrictEqual(a, b)))) fail("uniqueItems");
    if (schema.contains !== undefined && !value.some((item) => schemaErrors(sub("contains"), item, at).length === 0)) fail("contains");
  }
  if (typeof value === "string") {
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) fail("pattern");
    if (typeof schema.minLength === "number" && [...value].length < schema.minLength) fail("minLength");
  }
  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) fail("minimum");
    if (typeof schema.maximum === "number" && value > schema.maximum) fail("maximum");
    if (typeof schema.exclusiveMinimum === "number" && value <= schema.exclusiveMinimum) fail("exclusiveMinimum");
  }
  return errors;
}

const passes = (value: unknown) => schemaErrors(SCHEMA, value);

// ---- the TypeScript types the schema describes ---------------------------------------------

/** The named keys of T, without an index signature (a FlowStep has one). */
type Known<T> = keyof { [K in keyof T as string extends K ? never : number extends K ? never : K]: T[K] };
type Missing<All, Listed> = [Exclude<All, Listed>] extends [never] ? unknown : { missing: Exclude<All, Listed> };

/** Every named key of T, each listed: the compiler refuses a list that misses one or names one T lacks. */
const keysOf =
  <T>() =>
  <const L extends readonly Known<T>[]>(list: L & Missing<Known<T>, L[number]>): readonly string[] =>
    list as readonly string[];

/** Every member of a union of literals, listed. */
const membersOf =
  <T extends string | number>() =>
  <const L extends readonly T[]>(list: L & Missing<T, L[number]>): readonly Json[] =>
    list as readonly Json[];

/** Each object in the schema and the keys of the type it describes. A change to a type fails typecheck here first. */
const OBJECTS: ReadonlyArray<readonly [pointer: string, keys: readonly string[]]> = [
  ["#", keysOf<FlowConfig>()(["version", "revision", "policy", "modules", "flows"])],
  ["#/$defs/policy", keysOf<VerificationPolicy>()(["version", "levels", "scopes", "scopeClasses", "keypadFields", "maxKeypadAttemptsPerCall", "simSwapWindowHours", "trustTextCodeWithoutCarrierCheck"])],
  ["#/$defs/levelRule", keysOf<LevelRule>()(["level", "anyOf"])],
  ["#/$defs/moduleConfig", keysOf<ModuleConfig>()(["enabled", "settings"])],
  ["#/$defs/traceModule", keysOf<ModuleConfig>()(["enabled", "settings"])],
  ["#/$defs/badgeSettings", keysOf<BadgeSettings>()(["factors", "grantTtlSeconds", "pin"])],
  ["#/$defs/pinSettings", keysOf<PinSettings>()(["mode", "minDigits", "maxDigits", "maxAttemptsPerCall"])],
  ["#/$defs/dossierSettings", keysOf<DossierSettings>()(["forms"])],
  ["#/$defs/form", keysOf<IntakeForm>()(["formId", "version", "fields"])],
  ["#/$defs/field", keysOf<IntakeField>()(["key", "label", "type", "required", "sensitive", "maxLength"])],
  ["#/$defs/bilingual", keysOf<IntakeField["label"]>()(["en", "fr"])],
  ["#/$defs/paylinkSettings", keysOf<PaylinkSettings>()(["maxAmountMinor"])],
  ["#/$defs/traceSettings", keysOf<TraceSettings>()(["receipts", "wordings"])],
  ["#/$defs/wording", keysOf<ConsentWording>()(["purpose", "version", "text"])],
  ["#/$defs/flow", keysOf<FlowDefinition>()(["summary", "steps"])],
  ["#/$defs/badgeVerifyStep", keysOf<BadgeVerifyStep>()(["type", "level", "factors", "scopes"])],
  ["#/$defs/dossierCollectStep", keysOf<DossierCollectStep>()(["type", "form"])],
  ["#/$defs/paylinkRequestStep", keysOf<PaylinkRequestStep>()(["type", "amountMinor", "currency", "description", "amountSource", "mode"])],
  ["#/$defs/traceConsentStep", keysOf<TraceConsentStep>()(["type", "purpose", "require"])],
  ["#/$defs/traceReceiptStep", ["type"]],
];

/** Each closed list in the schema and the union or constant it comes from. */
const ENUMS: ReadonlyArray<readonly [pointer: string, members: readonly Json[]]> = [
  ["#/$defs/policy/properties/scopes/additionalProperties", membersOf<VerificationPolicy["scopes"][string]>()([0, 1, 2, 3])],
  ["#/$defs/policy/properties/scopeClasses/additionalProperties", [...SCOPE_CLASSES]],
  ["#/$defs/levelRule/properties/level", membersOf<LevelRule["level"]>()([1, 2, 3])],
  ["#/$defs/pinSettings/properties/mode", membersOf<PinMode>()(["keyed_hash", "verifier"])],
  ["#/$defs/field/properties/type", membersOf<FieldType>()(["text", "number", "date", "yes_no"])],
  ["#/$defs/badgeVerifyStep/properties/level", membersOf<BadgeVerifyStep["level"]>()([1, 2, 3])],
  ["#/$defs/paylinkRequestStep/properties/amountSource", membersOf<AmountSource>()(["intake_record", "business_endpoint", "price_list"])],
  ["#/$defs/paylinkRequestStep/properties/mode", [...PAYMENT_MODES]],
  ["#/$defs/traceConsentStep/properties/require", membersOf<NonNullable<TraceConsentStep["require"]>>()(["yes", "answer"])],
];

// ---- the corpus ----------------------------------------------------------------------------

const ALL_ADAPTERS = ["ledger", "sessions", "records", "identity", "carrier", "messages", "payments", "signer", "pinVerifier"];

/** An outside module whose settings and steps take anything: the schema cannot know them. */
const crm: AssuranceModule = {
  manifest: {
    name: "crm",
    version: "1",
    summary: "test",
    provides: { factors: [], steps: ["crm.lookup"], outcomes: [] },
    scopes: { grants: [], needs: {} },
    adapters: [],
  },
  validateSettings: () => [],
  requiredAdapters: () => [],
  validateStep: () => [],
  initCall: () => null,
  enterStep: () => null,
  stepStatus: () => "complete",
};

function registry(adapters: readonly string[] = ALL_ADAPTERS): ModuleRegistry {
  return new ModuleRegistry({ adapters, modules: [...builtInModules(), crm] });
}

const json = (value: unknown) => JSON.parse(JSON.stringify(value)) as { [key: string]: any };

/** Configs validateConfig accepts, each with the adapters its engine has. */
const GOOD: ReadonlyArray<readonly [name: string, config: { [key: string]: any }, adapters?: readonly string[]]> = [
  ["the default config", json(defaultConfig())],
  ["the test config", json(testConfig())],
  ["the demo config, with owner-command and deposit", json(demoConfig())],
  ["the PIN in verifier mode, a grant lifetime, a consent that only needs an answer", (() => {
    const c = json(demoConfig());
    c.modules.badge.settings.pin.mode = "verifier";
    c.modules.badge.settings.grantTtlSeconds = 3600;
    c.flows.deposit.steps[3].require = "answer";
    return c;
  })()],
  ["modules switched off, whose settings are not checked", (() => {
    const c = json(defaultConfig());
    c.modules.badge = { enabled: false, settings: "anything" };
    c.modules.dossier = { enabled: false };
    c.modules.paylink = { enabled: false, settings: [1, 2] };
    c.modules.trace = { enabled: true };
    return c;
  })()],
  ["an outside module with its own settings and step fields", (() => {
    const c = json(defaultConfig());
    c.modules.crm = { settings: { url: "https://crm.example.test" } };
    c.flows.lookup = { steps: [{ type: "crm.lookup", anything: [1, { two: 2 }] }] };
    return c;
  })()],
  ["the pin settings, ignored while the pin factor is off", (() => {
    const c = json(defaultConfig());
    c.modules.badge.settings.pin = "ignored";
    return c;
  })()],
  ["receipts off, on an engine without a signer", (() => {
    const c = json(defaultConfig());
    c.modules.trace.settings.receipts = false;
    return c;
  })(), ALL_ADAPTERS.filter((a) => a !== "signer")],
  ["fields that are not sensitive, a description padded with spaces, a policy with an extra field", (() => {
    const c = json(demoConfig());
    c.modules.dossier.settings.forms[0].fields[0].sensitive = false;
    c.modules.dossier.settings.forms[0].fields[0].maxLength = 200;
    c.flows.deposit.steps[2].description = `  ${"x".repeat(200)}  `;
    c.policy.note = "validatePolicy does not refuse fields it does not know";
    return c;
  })()],
];

type Patch = (c: { [key: string]: any }) => void;

/**
 * Configs validateConfig refuses. `shape`: the schema refuses it too. `rule`: only validateConfig
 * can see the problem (an installed module or factor, an adapter, a floor, a name a step points to,
 * planned work), so the schema accepts it.
 */
const BAD: ReadonlyArray<readonly [name: string, kind: "shape" | "rule", patch: Patch]> = [
  ["version 2", "shape", (c) => (c.version = 2)],
  ["a revision with a space", "shape", (c) => (c.revision = "has space")],
  ["an unknown top-level field", "shape", (c) => (c.extra = true)],
  ["no policy", "shape", (c) => delete c.policy],
  ["a scope at level 4", "shape", (c) => (c.policy.scopes["status.read"] = 4)],
  ["a scope class that does not exist", "shape", (c) => (c.policy.scopeClasses["owner.command"] = "trivial")],
  ["no keypad fields", "shape", (c) => (c.policy.keypadFields = [])],
  ["six keypad attempts", "shape", (c) => (c.policy.maxKeypadAttemptsPerCall = 6)],
  ["a SIM swap window of 0 hours", "shape", (c) => (c.policy.simSwapWindowHours = 0)],
  ["an empty factor set", "shape", (c) => (c.policy.levels[0].anyOf = [[]])],
  ["level 4", "shape", (c) => (c.policy.levels[0].level = 4)],
  ["a reserved module name", "shape", (c) => (c.modules.core = {})],
  ["a module config field that does not exist", "shape", (c) => (c.modules.paylink.on = true)],
  ["Trace switched off", "shape", (c) => (c.modules.trace.enabled = false)],
  ["Badge on without settings", "shape", (c) => delete c.modules.badge.settings],
  ["no factors", "shape", (c) => (c.modules.badge.settings.factors = [])],
  ["a factor twice", "shape", (c) => c.modules.badge.settings.factors.push("pin")],
  ["the pin factor without pin settings", "shape", (c) => delete c.modules.badge.settings.pin],
  ["a PIN of 3 digits", "shape", (c) => (c.modules.badge.settings.pin.minDigits = 3)],
  ["a PIN mode that does not exist", "shape", (c) => (c.modules.badge.settings.pin.mode = "plain")],
  ["a grant for two hours", "shape", (c) => (c.modules.badge.settings.grantTtlSeconds = 7200)],
  ["a badge setting that does not exist", "shape", (c) => (c.modules.badge.settings.lockout = true)],
  ["a form without fields", "shape", (c) => (c.modules.dossier.settings.forms[0].fields = [])],
  ["a form id in capitals", "shape", (c) => (c.modules.dossier.settings.forms[0].formId = "Maintenance")],
  ["a field key in camel case", "shape", (c) => (c.modules.dossier.settings.forms[0].fields[0].key = "isUrgent")],
  ["a field with a blank French label", "shape", (c) => (c.modules.dossier.settings.forms[0].fields[0].label.fr = "  ")],
  ["a field type that does not exist", "shape", (c) => (c.modules.dossier.settings.forms[0].fields[0].type = "photo")],
  ["a sensitive field (FIL-2)", "shape", (c) => (c.modules.dossier.settings.forms[0].fields[0].sensitive = true)],
  ["a payment limit above 1,000,000", "shape", (c) => (c.modules.paylink.settings.maxAmountMinor = 1_000_001)],
  ["receipts as a string", "shape", (c) => (c.modules.trace.settings.receipts = "yes")],
  ["a wording purpose with a hyphen", "shape", (c) => (c.modules.trace.settings.wordings[0].purpose = "repair-texts")],
  ["a wording without French", "shape", (c) => delete c.modules.trace.settings.wordings[0].text.fr],
  ["a flow name in capitals", "shape", (c) => (c.flows.Deposit = c.flows.deposit)],
  ["a flow without steps", "shape", (c) => (c.flows.deposit.steps = [])],
  ["a flow field that does not exist", "shape", (c) => (c.flows.deposit.owner = "ops")],
  ["a step without a type", "shape", (c) => delete c.flows.deposit.steps[0].type],
  ["a verify step at level 0", "shape", (c) => (c.flows.deposit.steps[0].level = 0)],
  ["a verify step with an empty scope list", "shape", (c) => (c.flows.deposit.steps[0].scopes = [])],
  ["a verify step field that does not exist", "shape", (c) => (c.flows.deposit.steps[0].retries = 2)],
  ["a collect step without a form", "shape", (c) => delete c.flows.deposit.steps[1].form],
  ["an amount of 0", "shape", (c) => (c.flows.deposit.steps[2].amountMinor = 0)],
  ["an amount of 1.5", "shape", (c) => (c.flows.deposit.steps[2].amountMinor = 1.5)],
  ["a currency in capitals", "shape", (c) => (c.flows.deposit.steps[2].currency = "CAD")],
  ["a blank description", "shape", (c) => (c.flows.deposit.steps[2].description = "   ")],
  ["a description of 201 characters", "shape", (c) => (c.flows.deposit.steps[2].description = "x".repeat(201))],
  ["an amount from the model", "shape", (c) => (c.flows.deposit.steps[2].amountSource = "model")],
  ["a consent that requires maybe", "shape", (c) => (c.flows.deposit.steps[3].require = "maybe")],
  ["a receipt step with a field", "shape", (c) => (c.flows.deposit.steps[4].sign = true)],
  ["a module that is not installed", "rule", (c) => (c.modules.gate = {})],
  ["a step whose module is not installed", "rule", (c) => (c.flows.deposit.steps[0].type = "gate.grant")],
  ["a step whose module is off", "rule", (c) => (c.modules.paylink.enabled = false)],
  ["an unknown factor in the policy", "rule", (c) => c.policy.levels[0].anyOf.push(["voice_print"])],
  ["a money scope below level 2", "rule", (c) => (c.policy.scopes["payment.request"] = 1)],
  ["a scope with no class", "rule", (c) => (c.policy.scopes["owner.reboot"] = 1)],
  ["a planned factor turned on (VER-2)", "rule", (c) => c.modules.badge.settings.factors.push("text_code")],
  ["a PIN with more minimum than maximum digits", "rule", (c) => (c.modules.badge.settings.pin.minDigits = 10)],
  ["two forms with one id", "rule", (c) => c.modules.dossier.settings.forms.push(c.modules.dossier.settings.forms[0])],
  ["a step for a form that does not exist", "rule", (c) => (c.flows.deposit.steps[1].form = "plumbing")],
  ["a step for a wording that does not exist", "rule", (c) => (c.flows.deposit.steps[3].purpose = "marketing")],
  ["a factor turned off in the badge settings", "rule", (c) => (c.flows.deposit.steps[0].factors = ["keypad_knowledge", "voice_print"])],
  ["an amount above the workspace's limit", "rule", (c) => (c.flows.deposit.steps[2].amountMinor = 60_000)],
  ["a payment mode (PAY-7)", "rule", (c) => (c.flows.deposit.steps[2].mode = "connect")],
  ["a payment before verification", "rule", (c) => c.flows.deposit.steps.shift()],
];

// ---- a sweep of near-miss configs ----------------------------------------------------------

/** A seeded generator, so every run tries the same configs. */
function lcg(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    return state / 2 ** 32;
  };
}

const POOL: readonly Json[] = [
  null, true, false, 0, 1, 2, 3, 4, 5, 12, 13, -1, 1.5, 3600, 3601, 1_000_000, 1_000_001,
  "", " ", "x", "pin", "keypad_knowledge", "photo_id", "text_code", "keyed_hash", "verifier", "cad", "CAD",
  "price_list", "model", "yes", "answer", "none", "money", "badge.verify", "trace.receipt", "crm.lookup", "gate.grant",
  "Bad Name", "deposit", "repair_texts", "maintenance", "x".repeat(65), [], [""], ["pin"], ["pin", "pin"], [[]],
  {}, { enabled: false }, { enabled: true }, { en: " ", fr: "x" }, { en: "Yes", fr: "Oui" },
];

/** Every path into a JSON value. */
function paths(value: Json, at: (string | number)[] = []): (string | number)[][] {
  const out = [at];
  if (Array.isArray(value)) value.forEach((item, i) => out.push(...paths(item, [...at, i])));
  else if (isObject(value)) for (const [key, item] of Object.entries(value)) out.push(...paths(item, [...at, key]));
  return out;
}

function mutate(base: Json, random: () => number): Json {
  const copy = structuredClone(base);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
  for (let n = 1 + Math.floor(random() * 2); n > 0; n--) {
    const path = pick(paths(copy).filter((p) => p.length > 0));
    let parent = copy as any;
    for (const part of path.slice(0, -1)) parent = parent[part];
    const last = path.at(-1)!;
    const op = random();
    if (op < 0.6) parent[last] = structuredClone(pick(POOL));
    else if (op < 0.75 && !Array.isArray(parent)) delete parent[last];
    else if (op < 0.85 && isObject(parent[last])) parent[last][pick(["extra", "enabled", "settings", "summary", "scopes", "require", "mode", "pin", "sensitive"])] = structuredClone(pick(POOL));
    else if (Array.isArray(parent[last]) && parent[last].length > 0) parent[last].push(structuredClone(parent[last][0]));
    else parent[last] = structuredClone(pick(POOL));
  }
  return copy;
}

// ---- tests ---------------------------------------------------------------------------------

describe("the FlowConfig schema: the document", () => {
  it("is JSON Schema 2020-12, and uses only keywords this test can check", () => {
    assert.equal(SCHEMA.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(SCHEMA.$id, "urn:district-assurance:flow-config:v1");
    for (const [at, schema] of subschemas(SCHEMA)) {
      if (typeof schema === "boolean" || at.endsWith("/$defs")) continue;
      assert.ok(isObject(schema), `${at} is a schema`);
      for (const key of Object.keys(schema)) assert.ok(KEYWORDS.has(key), `${at} uses ${key}, which this test does not check`);
      if (typeof schema.$ref === "string") resolve(schema.$ref);
      if (typeof schema.pattern === "string") new RegExp(schema.pattern, "u");
    }
  });

  it("is published with the package", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    assert.ok(pkg.files.includes("schema/"));
    assert.equal(pkg.exports["./schema/flow-config.v1.json"], "./schema/flow-config.v1.json");
    // The exports map resolves the published name to this very file, and nothing else under schema/.
    assert.equal(import.meta.resolve("district-assurance/schema/flow-config.v1.json"), SCHEMA_URL.href);
    assert.throws(() => import.meta.resolve("district-assurance/schema/"), /ERR_PACKAGE_PATH_NOT_EXPORTED|not exported/i);
  });

  it("describes every field of the TypeScript types, and no other", () => {
    for (const [pointer, keys] of OBJECTS) {
      const schema = resolve(pointer);
      assert.ok(isObject(schema) && isObject(schema.properties), `${pointer} lists its properties`);
      assert.deepEqual(Object.keys(schema.properties).sort(), [...keys].sort(), pointer);
    }
  });

  it("lists every member of each closed set, from the types and the constants", () => {
    for (const [pointer, members] of ENUMS) {
      const schema = resolve(pointer);
      assert.ok(isObject(schema) && Array.isArray(schema.enum), `${pointer} is an enum`);
      assert.deepEqual([...schema.enum].sort(), [...members].sort(), pointer);
    }
  });
});

describe("the FlowConfig schema against validateConfig", () => {
  for (const [name, config, adapters] of GOOD) {
    it(`accepts what validateConfig accepts: ${name}`, () => {
      assert.deepEqual(validateConfig(config, registry(adapters)), []);
      assert.deepEqual(passes(config), []);
    });
  }

  for (const [name, kind, patch] of BAD) {
    it(`${kind === "shape" ? "refuses" : "leaves to validateConfig"}: ${name}`, () => {
      const config = json(demoConfig());
      patch(config);
      assert.notDeepEqual(validateConfig(config, registry()), [], "validateConfig refuses it");
      if (kind === "shape") assert.notDeepEqual(passes(config), [], "the schema refuses it");
      else assert.deepEqual(passes(config), [], "the schema cannot see this problem");
    });
  }

  it("is never stricter than validateConfig, over thousands of near-miss configs", () => {
    const random = lcg(20261118);
    const bases = [json(demoConfig()), json(testConfig()), GOOD[5]![1]] as Json[];
    let accepted = 0;
    let refusedByBoth = 0;
    for (let i = 0; i < 4000; i++) {
      const config = mutate(bases[i % bases.length]!, random);
      const problems = validateConfig(config, registry());
      const errors = passes(config);
      if (problems.length === 0) {
        accepted++;
        assert.deepEqual(errors, [], `validateConfig accepts ${JSON.stringify(config)}`);
      } else if (errors.length > 0) refusedByBoth++;
    }
    // The sweep is only evidence if it reaches both sides.
    assert.ok(accepted >= 200, `only ${accepted} accepted configs`);
    assert.ok(refusedByBoth >= 1000, `only ${refusedByBoth} configs refused by both`);
  });
});

// ---- boundaries: the schema's patterns and ranges, held to validateConfig's own ------------

/**
 * Each pattern and range the schema copies from a validator, tried on both sides of its edge. The
 * schema and validateConfig must answer alike, so a change to either one alone fails here: the
 * sweep above is random and rarely lands on an edge.
 */
const rename = (c: { [key: string]: any }, from: string, to: string) => {
  c.flows[to] = c.flows[from];
  delete c.flows[from];
};
const formId = (c: { [key: string]: any }, id: string) => {
  c.modules.dossier.settings.forms[0].formId = id;
  c.flows.deposit.steps[1].form = id;
};
const purpose = (c: { [key: string]: any }, p: string) => {
  c.modules.trace.settings.wordings[0].purpose = p;
  c.flows.deposit.steps[3].purpose = p;
};
const EDGES: ReadonlyArray<readonly [name: string, accepted: boolean, patch: Patch]> = [
  ["a revision of 64 characters", true, (c) => (c.revision = "r".repeat(64))],
  ["a revision of 65 characters", false, (c) => (c.revision = "r".repeat(65))],
  ["a revision with every allowed character", true, (c) => (c.revision = "aZ09._:-")],
  ["a revision with a slash", false, (c) => (c.revision = "a/b")],
  ["an empty revision", false, (c) => (c.revision = "")],
  ["a flow name of 64 characters", true, (c) => rename(c, "deposit", `d${"-".repeat(63)}`)],
  ["a flow name of 65 characters", false, (c) => rename(c, "deposit", `d${"-".repeat(64)}`)],
  ["a flow name that starts with a digit", false, (c) => rename(c, "deposit", "1deposit")],
  ["a form id of 64 characters", true, (c) => formId(c, `m${"_".repeat(63)}`)],
  ["a form id of 65 characters", false, (c) => formId(c, `m${"_".repeat(64)}`)],
  ["a form id with a hyphen", true, (c) => formId(c, "repair-form")],
  ["a field key of 64 characters", true, (c) => (c.modules.dossier.settings.forms[0].fields[0].key = `k${"_".repeat(63)}`)],
  ["a field key of 65 characters", false, (c) => (c.modules.dossier.settings.forms[0].fields[0].key = `k${"_".repeat(64)}`)],
  ["a wording purpose of 64 characters", true, (c) => purpose(c, `p${"_".repeat(63)}`)],
  ["a wording purpose of 65 characters", false, (c) => purpose(c, `p${"_".repeat(64)}`)],
  ["one keypad attempt", true, (c) => (c.policy.maxKeypadAttemptsPerCall = 1)],
  ["no keypad attempt", false, (c) => (c.policy.maxKeypadAttemptsPerCall = 0)],
  ["a grant of 1 second", true, (c) => (c.modules.badge.settings.grantTtlSeconds = 1)],
  ["a grant of 3600 seconds", true, (c) => (c.modules.badge.settings.grantTtlSeconds = 3600)],
  ["a grant of 3601 seconds", false, (c) => (c.modules.badge.settings.grantTtlSeconds = 3601)],
  ["a PIN of 12 digits", true, (c) => Object.assign(c.modules.badge.settings.pin, { minDigits: 12, maxDigits: 12 })],
  ["a PIN of 13 digits", false, (c) => Object.assign(c.modules.badge.settings.pin, { minDigits: 12, maxDigits: 13 })],
  ["five PIN attempts", true, (c) => (c.modules.badge.settings.pin.maxAttemptsPerCall = 5)],
  ["six PIN attempts", false, (c) => (c.modules.badge.settings.pin.maxAttemptsPerCall = 6)],
  ["a payment limit of 1,000,000", true, (c) => (c.modules.paylink.settings.maxAmountMinor = 1_000_000)],
  ["a payment limit of 0", false, (c) => (c.modules.paylink.settings.maxAmountMinor = 0)],
  ["an amount of 1", true, (c) => (c.flows.deposit.steps[2].amountMinor = 1)],
  ["a description of 1 character", true, (c) => (c.flows.deposit.steps[2].description = "x")],
  ["a description of 200 characters", true, (c) => (c.flows.deposit.steps[2].description = "x".repeat(200))],
  ["a description of 200 characters with spaces inside", true, (c) => (c.flows.deposit.steps[2].description = `x${" ".repeat(198)}x`)],
  ["a description with a line break inside", true, (c) => (c.flows.deposit.steps[2].description = "Repair\ndeposit")],
  ["a currency of 2 letters", false, (c) => (c.flows.deposit.steps[2].currency = "ca")],
  ["a SIM swap window of half an hour", true, (c) => (c.policy.simSwapWindowHours = 0.5)],
  ["an empty policy version", false, (c) => (c.policy.version = "")],
  ["an empty form version", true, (c) => (c.modules.dossier.settings.forms[0].version = "")],
  ["an empty wording version", false, (c) => (c.modules.trace.settings.wordings[0].version = "")],
  ["a flow summary that is not a string", false, (c) => (c.flows.deposit.summary = 1)],
];

describe("the FlowConfig schema at the edges of each pattern and range", () => {
  for (const [name, accepted, patch] of EDGES) {
    it(`${accepted ? "accepts" : "refuses"}, as validateConfig does: ${name}`, () => {
      const config = json(demoConfig());
      patch(config);
      assert.equal(validateConfig(config, registry()).length === 0, accepted, "validateConfig");
      assert.equal(passes(config).length === 0, accepted, "the schema");
    });
  }
});
