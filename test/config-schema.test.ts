// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

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
import { ATTESTATIONS, SCOPE_CLASSES, SPOKEN_FORMATS, type LevelRule, type StepUpRule, type VerificationPolicy } from "../src/core/policy.ts";
import type { DossierCollectStep, DossierSettings } from "../src/file/dossier.ts";
import type { GateGrantStep, GateSettings, GateTarget } from "../src/gate/gate.ts";
import type { StepUpIssueStep, StepUpSettings, StepUpSite } from "../src/gate/step-up.ts";
import type { FieldType, IntakeField, IntakeForm } from "../src/file/intake.ts";
import { builtInModules, defaultConfig } from "../src/modules.ts";
import { PAYMENT_CHANNELS, type PaylinkChannelStep, type PaylinkRequestStep, type PaylinkSettings } from "../src/pay/paylink.ts";
import { INSTANT_PAYMENT_METHODS, PAYMENT_MODES, type AmountSourceKind } from "../src/pay/payment.ts";
import type { ConsentWording } from "../src/prove/consent.ts";
import type { TraceConsentStep, TraceReceiptStep, TraceSettings } from "../src/prove/trace.ts";
import type { BadgeVerifyStep, BadgeVoiceSettings } from "../src/verify/badge.ts";
import type { LockoutSettings } from "../src/verify/counters.ts";
import type { AccessibilitySettings, PinMode, PinSettings } from "../src/verify/factors.ts";
import { testConfig } from "./helpers.ts";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Schema = boolean | { [key: string]: Json };

const SCHEMA_URL = new URL("../schema/flow-config.v1.json", import.meta.url);
const SCHEMA = JSON.parse(readFileSync(SCHEMA_URL, "utf8")) as { [key: string]: Json };

// ---- a validator for the keywords the schema uses ------------------------------------------

const KEYWORDS = new Set([
  "$schema", "$id", "$defs", "$ref", "title", "description",
  "type", "const", "enum", "not", "allOf", "oneOf", "if", "then", "else",
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
  for (const key of ["allOf", "oneOf"]) {
    const list = schema[key];
    if (Array.isArray(list)) for (const [i, sub] of list.entries()) yield* subschemas(sub, `${at}/${key}/${i}`);
  }
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
  if (Array.isArray(schema.oneOf) && (schema.oneOf as Schema[]).filter((part) => schemaErrors(part, value, at).length === 0).length !== 1) fail("oneOf");
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
  ["#/$defs/policy", keysOf<VerificationPolicy>()(["version", "levels", "scopes", "scopeClasses", "keypadFields", "maxKeypadAttemptsPerCall", "simSwapWindowHours", "trustTextCodeWithoutCarrierCheck", "textCodeCountryCodes", "spoken", "attestationCaps", "timeZone", "stepUp"])],
  ["#/$defs/stepUpRule", keysOf<StepUpRule>()(["name", "scope", "level", "amountOverMinor", "localTime", "signal"])],
  ["#/$defs/levelRule", keysOf<LevelRule>()(["level", "anyOf"])],
  ["#/$defs/moduleConfig", keysOf<ModuleConfig>()(["enabled", "settings"])],
  ["#/$defs/traceModule", keysOf<ModuleConfig>()(["enabled", "settings"])],
  // BadgeVoiceSettings is BadgeSettings with the synthetic voice thresholds (VER-14), so it names every key.
  ["#/$defs/badgeSettings", keysOf<BadgeVoiceSettings>()(["factors", "grantTtlSeconds", "pin", "lockout", "syntheticVoice", "accessibility"])],
  ["#/$defs/accessibilitySettings", keysOf<AccessibilitySettings>()(["spokenKeypadFields", "keypadIdleSeconds", "maxKeypadIdleSeconds"])],
  ["#/$defs/lockoutSettings", keysOf<LockoutSettings>()(["backoffSeconds", "lockAfterFailures", "windowHours", "flowStartsPerHour"])],
  ["#/$defs/pinSettings", keysOf<PinSettings>()(["mode", "minDigits", "maxDigits", "maxAttemptsPerCall", "duress", "reuse"])],
  ["#/$defs/dossierSettings", keysOf<DossierSettings>()(["forms"])],
  ["#/$defs/form", keysOf<IntakeForm>()(["formId", "version", "fields"])],
  ["#/$defs/field", keysOf<IntakeField>()(["key", "label", "type", "required", "sensitive", "maxLength", "showIf", "min", "max", "pattern"])],
  ["#/$defs/bilingual", keysOf<IntakeField["label"]>()(["en", "fr", "es"])],
  ["#/$defs/paylinkSettings", keysOf<PaylinkSettings>()(["maxAmountMinor", "mode", "connectedAccountId", "linkLifeMinutes", "paymentMethods", "channels", "savedCardCharges"])],
  ["#/$defs/traceSettings", keysOf<TraceSettings>()(["receipts", "wordings", "businessName", "channels"])],
  ["#/$defs/wording", keysOf<ConsentWording>()(["purpose", "version", "text"])],
  ["#/$defs/flow", keysOf<FlowDefinition>()(["summary", "steps"])],
  ["#/$defs/badgeVerifyStep", keysOf<BadgeVerifyStep>()(["type", "level", "factors", "scopes"])],
  ["#/$defs/dossierCollectStep", keysOf<DossierCollectStep>()(["type", "form"])],
  ["#/$defs/paylinkChannelStep", keysOf<PaylinkChannelStep>()(["type"])],
  ["#/$defs/pinSettings/properties/reuse", keysOf<NonNullable<PinSettings["reuse"]>>()(["maxAgeSeconds"])],
  ["#/$defs/paylinkRequestStep", keysOf<PaylinkRequestStep>()(["type", "amountMinor", "currency", "amountRef", "description", "amountSource", "mode", "linkLifeMinutes", "paymentMethods"])],
  ["#/$defs/traceConsentStep", keysOf<TraceConsentStep>()(["type", "purpose", "require", "when"])],
  ["#/$defs/traceReceiptStep", keysOf<TraceReceiptStep>()(["type", "textLink"])],
  ["#/$defs/traceReceiptStep/properties/textLink", keysOf<NonNullable<TraceReceiptStep["textLink"]>>()(["consent"])],
  ["#/$defs/gateSettings", keysOf<GateSettings>()(["targets", "maxGrantsPerCall"])],
  ["#/$defs/gateTarget", keysOf<GateTarget>()(["id", "controller", "ref"])],
  ["#/$defs/gateGrantStep", keysOf<GateGrantStep>()(["type", "target", "lifetimeSeconds"])],
  ["#/$defs/stepUpSettings", keysOf<StepUpSettings>()(["issuer", "sites", "maxTokensPerCall"])],
  ["#/$defs/stepUpSite", keysOf<StepUpSite>()(["id", "audience"])],
  ["#/$defs/stepUpIssueStep", keysOf<StepUpIssueStep>()(["type", "site", "lifetimeSeconds"])],
];

/** Each closed list in the schema and the union or constant it comes from. */
const ENUMS: ReadonlyArray<readonly [pointer: string, members: readonly Json[]]> = [
  ["#/$defs/policy/properties/scopes/additionalProperties", membersOf<VerificationPolicy["scopes"][string]>()([0, 1, 2, 3])],
  ["#/$defs/policy/properties/scopeClasses/additionalProperties", [...SCOPE_CLASSES]],
  ["#/$defs/levelRule/properties/level", membersOf<LevelRule["level"]>()([1, 2, 3])],
  ["#/$defs/pinSettings/properties/mode", membersOf<PinMode>()(["keyed_hash", "verifier"])],
  ["#/$defs/field/properties/type", membersOf<FieldType>()(["text", "number", "date", "yes_no"])],
  ["#/$defs/badgeVerifyStep/properties/level", membersOf<BadgeVerifyStep["level"]>()([1, 2, 3])],
  ["#/$defs/paylinkRequestStep/properties/amountSource", membersOf<AmountSourceKind>()(["intake_record", "business_endpoint", "price_list"])],
  ["#/$defs/paylinkRequestStep/properties/mode", [...PAYMENT_MODES]],
  ["#/$defs/paylinkSettings/properties/mode", [...PAYMENT_MODES]],
  ["#/$defs/paymentMethods/items", [...INSTANT_PAYMENT_METHODS]],
  ["#/$defs/paylinkSettings/properties/channels/items", [...PAYMENT_CHANNELS]],
  ["#/$defs/policy/properties/attestationCaps/propertyNames", [...ATTESTATIONS]],
  ["#/$defs/policy/properties/spoken/properties/fields/additionalProperties", [...SPOKEN_FORMATS]],
  ["#/$defs/traceConsentStep/properties/require", membersOf<NonNullable<TraceConsentStep["require"]>>()(["yes", "answer"])],
];

// ---- the corpus ----------------------------------------------------------------------------

// Every adapter an engine can have (EngineAdapters), so a config's modules never fail for want of one.
const ALL_ADAPTERS = [
  "ledger", "sessions", "records", "identity", "carrier", "messages", "emails", "payments", "signer", "pinVerifier", "amounts",
  "access", "accessSigner", "stepUpSigner", "codes", "counters", "dialer", "notifier", "duressNotifier", "fieldCipher", "consents", "anchor",
];

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

/**
 * Gate and step-up on, each with a flow that verifies to the scope its step needs (the settings and
 * levels test/gate.test.ts and test/gate-step-up-hostile.test.ts use), and a receipt that texts its
 * link (PRV-10).
 */
function gateAndStepUpConfig(): { [key: string]: any } {
  const c = json(testConfig());
  c.policy.scopes["entry.open"] = 2;
  c.policy.scopes["entry.sign_in"] = 2;
  c.modules.trace.settings.businessName = "Maple Property Management";
  c.modules.gate = { settings: { targets: [{ id: "front-door", controller: "lobby", ref: "door-1" }, { id: "garage", controller: "lobby", ref: "door 2" }], maxGrantsPerCall: 5 } };
  c.modules["step-up"] = { settings: { issuer: "https://verify.example.test", sites: [{ id: "portal", audience: "https://portal.example.test" }], maxTokensPerCall: 1 } };
  const verify = (scope: string) => ({ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: [scope] });
  c.flows.entry = { steps: [verify("entry.open"), { type: "gate.grant", target: "front-door", lifetimeSeconds: 900 }, { type: "trace.receipt", textLink: { consent: c.modules.trace.settings.wordings[0].purpose } }] };
  c.flows.web = { steps: [verify("entry.sign_in"), { type: "step-up.issue", site: "portal", lifetimeSeconds: 300 }] };
  return c;
}

/** A conditioned consent question after the channel choice it reads (issue #179). */
function conditionedConsentConfig(): { [key: string]: any } {
  const c = json(testConfig());
  c.modules.paylink = { settings: { mode: "platform", channels: ["text", "email"] } };
  c.modules.trace.settings.businessName = "Maple Property Management";
  c.modules.trace.settings.wordings.push(
    { purpose: "payment_link_text", version: "1", text: { en: "By text?", fr: "Par texto ?" } },
    { purpose: "payment_link_email", version: "1", text: { en: "By email?", fr: "Par courriel ?" } },
  );
  const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] };
  c.flows.conditioned = {
    steps: [verify, { type: "paylink.channel" }, { type: "paylink.request", amountMinor: 5000, currency: "cad", description: "Deposit", amountSource: "price_list" }, { type: "trace.consent", purpose: c.modules.trace.settings.wordings[0].purpose, when: { paymentChannel: "email" } }, { type: "trace.receipt" }],
  };
  return c;
}

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
  ["Gate and step-up on, and a receipt that texts its link", gateAndStepUpConfig()],
  ["a consent step that runs only for the caller's payment channel", conditionedConsentConfig(), ["ledger", "sessions", "records", "identity", "carrier", "messages", "payments", "signer", "pinVerifier", "counters", "codes", "emails"]],
  ["a step-up rule on an amount, and a keypad idle timeout left to its default with null", (() => {
    const c = json(demoConfig());
    c.policy.stepUp = [{ name: "big", scope: "payment.request", level: 3, amountOverMinor: { cad: 100_000 } }];
    c.modules.badge.settings.accessibility = { keypadIdleSeconds: null };
    return c;
  })()],
  ["Gate and step-up listed but switched off, whose settings are not checked", (() => {
    const c = json(defaultConfig());
    c.modules.gate = { enabled: false, settings: "anything" };
    c.modules["step-up"] = { enabled: false };
    return c;
  })()],
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
  ["an empty field pattern", "shape", (c) => (c.modules.dossier.settings.forms[0].fields[0].pattern = "")],
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
  ["a consent condition that is not an object", "shape", (c) => (c.flows.deposit.steps[3].when = "email")],
  ["a consent condition with an extra field", "shape", (c) => (c.flows.deposit.steps[3].when = { paymentChannel: "email", extra: true })],
  ["a consent condition for an unknown channel", "shape", (c) => (c.flows.deposit.steps[3].when = { paymentChannel: "fax" })],
  ["a receipt step with a field", "shape", (c) => (c.flows.deposit.steps[4].sign = true)],
  ["a module that is not installed", "rule", (c) => (c.modules.crm2 = {})],
  ["Gate on without settings", "shape", (c) => (c.modules.gate = {})],
  ["a step-up rule that is not an object", "shape", (c) => (c.policy.stepUp = [null])],
  ["a step-up rule with no condition", "shape", (c) => (c.policy.stepUp = [{ name: "big", scope: "payment.request", level: 3 }])],
  ["a step-up rule with two conditions", "shape", (c) => (c.policy.stepUp = [{ name: "big", scope: "payment.request", level: 3, amountOverMinor: { cad: 1 }, signal: "x" }])],
  ["Gate with no targets", "shape", (c) => (c.modules.gate = { settings: { targets: [] } })],
  ["a Gate target id in capitals", "shape", (c) => (c.modules.gate = { settings: { targets: [{ id: "Front", controller: "lobby", ref: "d" }] } })],
  ["a Gate target without a controller", "shape", (c) => (c.modules.gate = { settings: { targets: [{ id: "front", controller: "", ref: "d" }] } })],
  ["a Gate setting that does not exist", "shape", (c) => (c.modules.gate = { settings: { targets: [{ id: "front", controller: "lobby", ref: "d" }], doors: 1 } })],
  ["step-up on without sites", "shape", (c) => (c.modules["step-up"] = { settings: { issuer: "https://verify.example.test", sites: [] } })],
  ["a step-up issuer with a query", "shape", (c) => (c.modules["step-up"] = { settings: { issuer: "https://verify.example.test/?a=1", sites: [{ id: "portal", audience: "p" }] } })],
  ["a step-up audience with a space", "shape", (c) => (c.modules["step-up"] = { settings: { issuer: "https://verify.example.test", sites: [{ id: "portal", audience: "a b" }] } })],
  ["a gate.grant step without a target", "shape", (c) => c.flows.deposit.steps.splice(1, 0, { type: "gate.grant" })],
  ["a gate.grant step with a field", "shape", (c) => c.flows.deposit.steps.splice(1, 0, { type: "gate.grant", target: "front", door: 1 })],
  ["a step-up.issue step without a site", "shape", (c) => c.flows.deposit.steps.splice(1, 0, { type: "step-up.issue" })],
  ["a receipt link without a consent", "shape", (c) => (c.flows.deposit.steps[4].textLink = {})],
  ["a receipt link with a field", "shape", (c) => (c.flows.deposit.steps[4].textLink = { consent: "repair_texts", to: "x" })],
  ["a step-up issuer that is not https", "rule", (c) => (c.modules["step-up"] = { settings: { issuer: "http://verify.example.test", sites: [{ id: "portal", audience: "p" }] } })],
  ["two Gate targets with one id", "rule", (c) => (c.modules.gate = { settings: { targets: [{ id: "front", controller: "lobby", ref: "d" }, { id: "front", controller: "lobby", ref: "e" }] } })],
  ["a gate.grant step for a target that does not exist", "rule", (c) => {
    const g = gateAndStepUpConfig();
    Object.assign(c, g);
    c.flows.entry.steps[1].target = "attic";
  }],
  ["a receipt link for a consent that does not exist", "rule", (c) => (c.flows.deposit.steps[4].textLink = { consent: "marketing" })],
  ["a step whose module is not installed", "rule", (c) => (c.flows.deposit.steps[0].type = "crm2.lookup")],
  ["a step whose module is off", "rule", (c) => (c.modules.paylink.enabled = false)],
  ["an unknown factor in the policy", "rule", (c) => c.policy.levels[0].anyOf.push(["voice_print"])],
  ["a money scope below level 2", "rule", (c) => (c.policy.scopes["payment.request"] = 1)],
  ["a scope with no class", "rule", (c) => (c.policy.scopes["owner.reboot"] = 1)],
  ["a texted code in a step without the policy's textCodeCountryCodes", "rule", (c) => {
    c.modules.badge.settings.factors.push("text_code");
    c.flows.deposit.steps[0].factors.push("text_code");
  }],
  ["a PIN with more minimum than maximum digits", "rule", (c) => (c.modules.badge.settings.pin.minDigits = 10)],
  ["two forms with one id", "rule", (c) => c.modules.dossier.settings.forms.push(c.modules.dossier.settings.forms[0])],
  ["a step for a form that does not exist", "rule", (c) => (c.flows.deposit.steps[1].form = "plumbing")],
  ["a step for a wording that does not exist", "rule", (c) => (c.flows.deposit.steps[3].purpose = "marketing")],
  ["a factor turned off in the badge settings", "rule", (c) => (c.flows.deposit.steps[0].factors = ["keypad_knowledge", "voice_print"])],
  ["an amount above the workspace's limit", "rule", (c) => (c.flows.deposit.steps[2].amountMinor = 60_000)],
  ["connect mode with no connected account", "rule", (c) => {
    c.modules.paylink.settings.mode = "connect";
    delete c.modules.paylink.settings.connectedAccountId;
  }],
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
    const bases = [json(demoConfig()), json(testConfig()), GOOD[5]![1], gateAndStepUpConfig()] as Json[];
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
/** The Gate and step-up config, with one change: the edges below start from it. */
const gate = (c: { [key: string]: any }, change: (s: { [key: string]: any }) => void) => {
  Object.assign(c, gateAndStepUpConfig());
  change(c.modules.gate.settings);
};
const gateStep = (c: { [key: string]: any }, seconds: number) => {
  Object.assign(c, gateAndStepUpConfig());
  c.flows.entry.steps[1].lifetimeSeconds = seconds;
};
const stepUp = (c: { [key: string]: any }, change: (s: { [key: string]: any }) => void) => {
  Object.assign(c, gateAndStepUpConfig());
  change(c.modules["step-up"].settings);
};
const stepUpStep = (c: { [key: string]: any }, seconds: number) => {
  Object.assign(c, gateAndStepUpConfig());
  c.flows.web.steps[1].lifetimeSeconds = seconds;
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
  ["synthetic voice thresholds at 0 and 1", true, (c) => (c.modules.badge.settings.syntheticVoice = { acme: { spokenKnowledgeAbove: 0, levelOneAbove: 1 } })],
  ["a synthetic voice threshold above 1", false, (c) => (c.modules.badge.settings.syntheticVoice = { acme: { spokenKnowledgeAbove: 0.5, levelOneAbove: 1.01 } })],
  ["a synthetic voice threshold below 0", false, (c) => (c.modules.badge.settings.syntheticVoice = { acme: { spokenKnowledgeAbove: -0.01, levelOneAbove: 0.5 } })],
  ["a synthetic voice vendor of 32 characters", true, (c) => (c.modules.badge.settings.syntheticVoice = { [`v${"_".repeat(31)}`]: { spokenKnowledgeAbove: 0.5, levelOneAbove: 0.9 } })],
  ["a synthetic voice vendor of 33 characters", false, (c) => (c.modules.badge.settings.syntheticVoice = { [`v${"_".repeat(32)}`]: { spokenKnowledgeAbove: 0.5, levelOneAbove: 0.9 } })],
  ["a synthetic voice vendor in capitals", false, (c) => (c.modules.badge.settings.syntheticVoice = { Acme: { spokenKnowledgeAbove: 0.5, levelOneAbove: 0.9 } })],
  ["a Gate target id of 64 characters", true, (c) => {
    gate(c, (s) => (s.targets[0].id = `f${"-".repeat(63)}`));
    c.flows.entry.steps[1].target = c.modules.gate.settings.targets[0].id;
  }],
  ["a Gate target id of 65 characters", false, (c) => {
    gate(c, (s) => (s.targets[0].id = `f${"-".repeat(64)}`));
    c.flows.entry.steps[1].target = c.modules.gate.settings.targets[0].id;
  }],
  ["a Gate target ref of 200 characters", true, (c) => gate(c, (s) => (s.targets[0].ref = "r".repeat(200)))],
  ["a Gate target ref of 201 characters", false, (c) => gate(c, (s) => (s.targets[0].ref = "r".repeat(201)))],
  ["a Gate target ref of spaces", false, (c) => gate(c, (s) => (s.targets[0].ref = " \t "))],
  ["a Gate target ref with spaces around", true, (c) => gate(c, (s) => (s.targets[0].ref = " d 1 "))],
  ["five access grants a call", true, (c) => gate(c, (s) => (s.maxGrantsPerCall = 5))],
  ["six access grants a call", false, (c) => gate(c, (s) => (s.maxGrantsPerCall = 6))],
  ["no access grant a call", false, (c) => gate(c, (s) => (s.maxGrantsPerCall = 0))],
  ["an access grant of 10 seconds", true, (c) => gateStep(c, 10)],
  ["an access grant of 9 seconds", false, (c) => gateStep(c, 9)],
  ["an access grant of 900 seconds", true, (c) => gateStep(c, 900)],
  ["an access grant of 901 seconds", false, (c) => gateStep(c, 901)],
  ["a step-up audience of 200 characters", true, (c) => stepUp(c, (s) => (s.sites[0].audience = "a".repeat(200)))],
  ["a step-up audience of 201 characters", false, (c) => stepUp(c, (s) => (s.sites[0].audience = "a".repeat(201)))],
  ["a step-up issuer with a fragment", false, (c) => stepUp(c, (s) => (s.issuer = "https://verify.example.test/#x"))],
  ["a step-up issuer with a path", true, (c) => stepUp(c, (s) => (s.issuer = "https://verify.example.test/tenant-1"))],
  ["five step-up tokens a call", true, (c) => stepUp(c, (s) => (s.maxTokensPerCall = 5))],
  ["six step-up tokens a call", false, (c) => stepUp(c, (s) => (s.maxTokensPerCall = 6))],
  ["a step-up token of 120 seconds", true, (c) => stepUpStep(c, 120)],
  ["a step-up token of 119 seconds", false, (c) => stepUpStep(c, 119)],
  ["a step-up token of 300 seconds", true, (c) => stepUpStep(c, 300)],
  ["a step-up token of 301 seconds", false, (c) => stepUpStep(c, 301)],
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

// ---- hostile-pass regressions (#82): text and number forms an editor or another language writes; all held

describe("hostile #82: the schema is never stricter on text and numbers", () => {
  /** Each candidate that validateConfig accepts must pass the schema; returns how many it accepted. */
  function holds(candidates: ReadonlyArray<readonly [string, FlowConfig]>): number {
    let accepted = 0;
    for (const [name, config] of candidates) {
      if (validateConfig(config, registry()).length > 0) continue;
      accepted++;
      assert.deepEqual(passes(config), [], name);
    }
    return accepted;
  }
  const withLabel = (label: string): FlowConfig =>
    testConfig((c) => ((c.modules.dossier!.settings as unknown as DossierSettings).forms[0]!.fields[0]!.label = { en: label, fr: label }));
  const withDescription = (description: string): FlowConfig => {
    const c = json(demoConfig());
    c.flows.deposit.steps[2].description = description;
    return c as unknown as FlowConfig;
  };

  it("S1: labels in every Unicode shape validateConfig takes", () => {
    const labels = ["\u{1F527}", "Re\u0301paration", "\u200b", "\u00a0x\u00a0", "\u3000x", "x\ufeff", "\u202eabc", "a".repeat(500), "\u{1F527}".repeat(200)];
    const blanks = ["\ufeff", "\u00a0", "\u3000", "\u2028", " \t\n"];
    assert.ok(holds(labels.map((l) => [JSON.stringify(l).slice(0, 30), withLabel(l)] as const)) >= 7);
    for (const blank of blanks) {
      assert.notDeepEqual(validateConfig(withLabel(blank), registry()), [], `validateConfig refuses ${JSON.stringify(blank)}`);
      assert.notDeepEqual(passes(withLabel(blank)), [], `so does the schema: ${JSON.stringify(blank)}`);
    }
  });

  it("S2: payment descriptions at the edge, counted in UTF-16 units and in code points", () => {
    const candidates = [199, 200, 201].flatMap((n) => [
      [`${n} ascii`, withDescription("d".repeat(n))] as const,
      [`${n} units of emoji`, withDescription("\u{1F4B3}".repeat(Math.floor(n / 2)) + (n % 2 === 1 ? "d" : ""))] as const,
      [`${n} padded`, withDescription(`  ${"d".repeat(n)}\t`)] as const,
    ]);
    assert.ok(holds(candidates) >= 4);
  });

  it("S3: numbers written with a zero fraction or an exponent, as another language's JSON writer may", () => {
    const text = JSON.stringify(demoConfig());
    assert.match(text, /"amountMinor":15000,/);
    const variants = [
      ["15000.0", text.replace('"amountMinor":15000', '"amountMinor":15000.0')],
      ["1.5e4", text.replace('"amountMinor":15000', '"amountMinor":1.5e4')],
      ["150E2", text.replace('"amountMinor":15000', '"amountMinor":150E2')],
      ["2.0 attempts", text.replace('"maxKeypadAttemptsPerCall":2', '"maxKeypadAttemptsPerCall":2.0')],
    ].map(([name, json]) => [name!, JSON.parse(json!) as FlowConfig] as const);
    assert.equal(holds(variants), variants.length);
  });

  it("S4: keys that JSON.parse makes own properties (__proto__, constructor) are judged the same way by both", () => {
    for (const json of [
      JSON.stringify(demoConfig()).replace('"flows":{', '"flows":{"__proto__":{"steps":[{"type":"trace.receipt"}]},'),
      JSON.stringify(demoConfig()).replace('"flows":{', '"flows":{"constructor":{"steps":[{"type":"trace.receipt"}]},'),
    ]) {
      const config = JSON.parse(json) as FlowConfig;
      if (validateConfig(config, registry()).length === 0) assert.deepEqual(passes(config), [], json.slice(0, 60));
    }
  });
});
