// FlowConfig, validateConfig and the module registry: every problem, at save time.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { JsonValue } from "../src/core/canonical.ts";
import { ConfigError, assertConfig, moduleEnabled, validateConfig, type FlowConfig } from "../src/core/config.ts";
import { EngineError } from "../src/core/errors.ts";
import { ModuleRegistry, checkFactorPlugin, checkFactorPlugins, checkManifest, type AssuranceModule, type FactorPlugin, type ModuleManifest } from "../src/core/module.ts";
import { isBilingual } from "../src/core/shape.ts";
import { builtInModules, defaultConfig } from "../src/modules.ts";
import { badgeModule } from "../src/verify/badge.ts";
import { testConfig } from "./helpers.ts";

/** A sparse array of length 1: one hole, no element. */
function hole(): unknown[] {
  const list: unknown[] = [];
  list.length = 1;
  return list;
}

const ALL_ADAPTERS = ["ledger", "sessions", "records", "identity", "carrier", "messages", "payments", "signer", "pinVerifier", "counters", "codes"];

function registry(adapters: readonly string[] = ALL_ADAPTERS, extra: AssuranceModule[] = []): ModuleRegistry {
  return new ModuleRegistry({ adapters, modules: [...builtInModules(), ...extra] });
}

/** A config to break one piece at a time. */
function config(patch: (c: Record<string, any>) => void = () => undefined): Record<string, any> {
  const c = testConfig() as unknown as Record<string, any>;
  patch(c);
  return c;
}

function outside(name: string, manifest: Partial<ModuleManifest> = {}): AssuranceModule {
  return {
    manifest: {
      name,
      version: "1",
      summary: "test",
      provides: { factors: [], steps: [`${name}.lookup`], outcomes: [] },
      scopes: { grants: [], needs: { [`${name}.lookup`]: "status.read" } },
      adapters: [],
      ...manifest,
    },
    validateSettings: (settings) => (settings === "bad" ? ["bad settings"] : []),
    requiredAdapters: () => ["crm"],
    validateStep: (step) => (step.bad === true ? ["bad step"] : []),
    initCall: () => ({ looked: false }),
    enterStep: () => null,
    stepStatus: (_step, view) => ((view.slice as { looked: boolean }).looked ? "complete" : "pending"),
  };
}

describe("validateConfig: the document", () => {
  it("accepts the default and the test configs", () => {
    assert.deepEqual(validateConfig(defaultConfig(), registry()), []);
    assert.deepEqual(validateConfig(testConfig(), registry()), []);
  });

  it("never throws on garbage, and names every problem with its path", () => {
    assert.deepEqual(validateConfig(null, registry()), ["the config must be an object"]);
    assert.deepEqual(validateConfig([], registry()), ["the config must be an object"]);
    assert.deepEqual(validateConfig({ extra: 1 }, registry()), [
      "extra: not a config field",
      "version: must be 1",
      "revision: must be 1 to 64 letters, digits, dots, colons, hyphens or underscores",
      "policy: must be an object",
      "modules: must be an object",
      "flows: must be an object",
    ]);
    assert.ok(validateConfig(config((c) => (c.revision = "has space")), registry()).includes("revision: must be 1 to 64 letters, digits, dots, colons, hyphens or underscores"));
  });

  it("checks the policy's shape and its rules in one pass, against the installed factors", () => {
    assert.deepEqual(
      validateConfig(
        config((c) => {
          c.policy = { version: "", levels: [{ level: 1 }], scopes: { a: "1" }, keypadFields: "dob", maxKeypadAttemptsPerCall: "2", simSwapWindowHours: null, trustTextCodeWithoutCarrierCheck: 1 };
        }),
        registry(),
      ),
      [
        "policy: version must be a non-empty string",
        "policy: levels[0] must be { level, anyOf: [[factor, ...], ...] }",
        "policy: scope a has level of type string, not 0 to 3",
        "policy: scope a has no class: name it in scopeClasses (money, contact, access or none)",
        "policy: keypadFields must be a list of field names",
        "policy: maxKeypadAttemptsPerCall must be an integer from 1 to 5",
        "policy: simSwapWindowHours must be a positive number",
        "policy: trustTextCodeWithoutCarrierCheck must be true or false",
      ],
    );
    const problems = validateConfig(
      config((c) => {
        c.policy.levels[0].anyOf.push(["voiceprint"]);
        c.policy.scopes["payment.request"] = 1;
      }),
      registry(),
    );
    assert.deepEqual(problems, ["policy: level 1 set [voiceprint]: unknown factor voiceprint", "policy: scope payment.request is money, and below its floor of level 2"]);
    // A plug-in's kind is a known factor.
    const plugin = { kind: "voiceprint", summary: "x", maxAttemptsPerCall: 1, adapters: [], judge: async () => false };
    const withPlugin = new ModuleRegistry({ adapters: ALL_ADAPTERS, modules: builtInModules(badgeModule({ factors: [plugin] })) });
    assert.deepEqual(validateConfig(config((c) => c.policy.levels[0].anyOf.push(["voiceprint"])), withPlugin), []);
  });
});

describe("validateConfig: modules", () => {
  it("refuses unknown modules, malformed entries, unknown fields, and turning the ledger off", () => {
    const problems = validateConfig(
      config((c) => {
        c.modules.vault = { enabled: true };
        c.modules.paylink = "on";
        c.modules.dossier = { enabled: "yes", settings: { forms: [] }, extra: 1 };
        c.modules.trace = { enabled: false };
      }),
      registry(),
    );
    assert.deepEqual(problems, [
      "modules.dossier.extra: not a module config field",
      "modules.dossier.enabled: must be true or false",
      "modules.paylink: must be an object",
      "modules.trace: trace holds the audit ledger and cannot be turned off",
      "modules.vault: no module named vault is installed",
    ]);
  });

  it("keeps the ledger on when the config does not list trace, and asks for a ledger module", () => {
    const c = config((x) => delete x.modules.trace);
    assert.deepEqual(validateConfig(c, registry()), []);
    assert.equal(moduleEnabled(c as unknown as FlowConfig, registry(), "trace"), true);
    assert.equal(moduleEnabled(c as unknown as FlowConfig, registry(), "nope"), false);
    const inherited = registry(ALL_ADAPTERS, [outside("constructor-x")]);
    assert.equal(moduleEnabled(c as unknown as FlowConfig, inherited, "constructor-x"), false);
    const off = config((x) => (x.modules.paylink.enabled = false));
    assert.equal(moduleEnabled(off as unknown as FlowConfig, registry(), "paylink"), false);
    const bare = new ModuleRegistry({ adapters: ALL_ADAPTERS, modules: builtInModules().slice(0, 3) });
    assert.deepEqual(validateConfig(config((x) => delete x.modules.trace), bare), ["modules: no installed module holds the audit ledger (trace)"]);
  });

  it("reports every adapter the modules on need and the engine lacks", () => {
    const problems = validateConfig(
      config((c) => {
        c.modules.badge.settings.pin.mode = "verifier";
      }),
      registry(["ledger", "sessions"]),
    );
    assert.deepEqual(problems, [
      "modules.badge: needs the records adapter, which the engine does not have",
      "modules.badge: needs the counters adapter, which the engine does not have",
      "modules.badge: needs the carrier adapter, which the engine does not have",
      "modules.badge: needs the identity adapter, which the engine does not have",
      "modules.badge: needs the messages adapter, which the engine does not have",
      "modules.badge: needs the pinVerifier adapter, which the engine does not have",
      "modules.dossier: needs the records adapter, which the engine does not have",
      "modules.paylink: needs the payments adapter, which the engine does not have",
      "modules.paylink: needs the messages adapter, which the engine does not have",
      "modules.trace: needs the signer adapter, which the engine does not have",
    ]);
    assert.deepEqual(validateConfig(config((c) => (c.modules.badge.settings.pin.mode = "verifier")), registry()), []);
  });

  it("checks badge settings", () => {
    const at = (settings: unknown) => validateConfig(config((c) => (c.modules.badge.settings = settings)), registry());
    assert.deepEqual(at(undefined), ["modules.badge.settings: must be an object with the factors that are on"]);
    assert.deepEqual(at({ factors: [], extra: 1 }), ["modules.badge.settings: extra is not a badge setting", "modules.badge.settings: factors must list at least one factor"]);
    assert.deepEqual(at({ factors: ["pin", "pin", "caller_id", "text_code", "spoken_knowledge"], grantTtlSeconds: 0 }), [
      "modules.badge.settings: factors has duplicates",
      "modules.badge.settings: factor caller_id is not installed",
      "modules.badge.settings: pin settings are required when the pin factor is on",
      "modules.badge.settings: grantTtlSeconds must be an integer from 1 to 3600",
    ]);
    assert.deepEqual(at({ factors: ["pin"], pin: { mode: "plain", minDigits: 3, maxDigits: 4, maxAttemptsPerCall: 6, x: 1 } }), [
      "modules.badge.settings: pin.x is not a pin setting",
      "modules.badge.settings: pin.mode must be keyed_hash or verifier",
      "modules.badge.settings: pin.minDigits must be 4 to 12",
      "modules.badge.settings: pin.maxAttemptsPerCall must be 1 to 5",
    ]);
    assert.deepEqual(at({ factors: ["pin"], pin: { mode: "keyed_hash", minDigits: 6, maxDigits: 5, maxAttemptsPerCall: 0 } }), [
      "modules.badge.settings: pin.maxDigits must be from minDigits to 12",
      "modules.badge.settings: pin.maxAttemptsPerCall must be 1 to 5",
    ]);
    assert.deepEqual(at({ factors: ["keypad_knowledge"], grantTtlSeconds: 3600 }), []);
    assert.deepEqual(at({ factors: ["keypad_knowledge", 3] }), ["modules.badge.settings: factors must list at least one factor"]);
    assert.deepEqual(at({ factors: hole() }), ["modules.badge.settings: factors must list at least one factor"], "a hole is not a factor");
  });

  it("checks badge lockout settings, whose defaults are floors (VER-1)", () => {
    const at = (lockout: unknown) => validateConfig(config((c) => (c.modules.badge.settings.lockout = lockout)), registry());
    assert.deepEqual(at({}), []);
    assert.deepEqual(at({ backoffSeconds: [10, 30, 120, 600, 1800, 3600, 3600], lockAfterFailures: 3, windowHours: 168 }), [], "stricter is fine");
    assert.deepEqual(at({ backoffSeconds: [5, 15, 60, 300, 900, 900, 900, 900, 900, 900], lockAfterFailures: 1, windowHours: 24 }), [], "the floors themselves");
    assert.deepEqual(at("strict"), ["modules.badge.settings: lockout must be an object"]);
    assert.deepEqual(at({ backoffSeconds: [5, 15, 60, 300], lockAfterFailures: 11, windowHours: 23, after: 1 }), [
      "modules.badge.settings: lockout.after is not a lockout setting",
      "modules.badge.settings: lockout.backoffSeconds must list 5 to 10 whole seconds, each at most 86400",
      "modules.badge.settings: lockout.lockAfterFailures must be 1 to 10",
      "modules.badge.settings: lockout.windowHours must be 24 to 168",
    ]);
    const tooLong = "modules.badge.settings: lockout.backoffSeconds must list 5 to 10 whole seconds, each at most 86400";
    assert.deepEqual(at({ backoffSeconds: Array(11).fill(900) }), [tooLong]);
    assert.deepEqual(at({ backoffSeconds: [5, 15, 60, 300, 86_401] }), [tooLong]);
    assert.deepEqual(at({ backoffSeconds: [5, 15, 60, 300, 1.5] }), [tooLong]);
    assert.deepEqual(at({ backoffSeconds: "5,15" }), [tooLong]);
    assert.deepEqual(at({ backoffSeconds: [5, 15, 60, 300, ...hole()] }), [tooLong]);
    const below = "modules.badge.settings: lockout.backoffSeconds must not go below 5, 15, 60, 300, 900 (900 after that)";
    assert.deepEqual(at({ backoffSeconds: [4, 15, 60, 300, 900] }), [below]);
    assert.deepEqual(at({ backoffSeconds: [5, 15, 60, 300, 899] }), [below]);
    assert.deepEqual(at({ backoffSeconds: [5, 15, 60, 300, 900, 899] }), [below], "900 after the fifth");
    assert.deepEqual(at({ lockAfterFailures: 0 }), ["modules.badge.settings: lockout.lockAfterFailures must be 1 to 10"]);
    assert.deepEqual(at({ windowHours: 169 }), ["modules.badge.settings: lockout.windowHours must be 24 to 168"]);
  });

  it("needs the counters adapter whenever a factor the caller enters is on", () => {
    const needs = (factors: string[]) =>
      validateConfig(
        config((c) => (c.modules.badge.settings.factors = factors)),
        registry(ALL_ADAPTERS.filter((a) => a !== "counters")),
      ).filter((p) => p.includes("counters"));
    const missing = ["modules.badge: needs the counters adapter, which the engine does not have"];
    assert.deepEqual(needs(["keypad_knowledge"]), missing);
    assert.deepEqual(needs(["pin"]), missing);
    assert.deepEqual(needs(["carrier_identity_match", "photo_id"]), [], "factors the caller does not enter are not counted");
  });

  it("checks dossier settings", () => {
    const at = (settings: unknown) => validateConfig(config((c) => (c.modules.dossier.settings = settings)), registry());
    assert.deepEqual(at(null), ["modules.dossier.settings: must be an object with a list of forms"]);
    assert.deepEqual(at({ forms: "x" }), ["modules.dossier.settings: must be an object with a list of forms"]);
    assert.deepEqual(at({ forms: hole() }), ["modules.dossier.settings: must be an object with a list of forms"]);
    assert.deepEqual(at({ forms: [{ formId: "a", version: "1", fields: hole() }] }), ["modules.dossier.settings: forms[0] must be { formId, version, fields }"]);
    const field = { key: "issue", label: { en: "Issue", fr: "Problème" }, type: "text", required: true };
    assert.deepEqual(
      at({
        extra: 1,
        forms: [
          "x",
          { formId: "a", version: "1", fields: [{ key: "k" }] },
          { formId: "Bad Id", version: "1", fields: [{ ...field, type: "photo" }, { ...field, key: "sin", sensitive: true }] },
          { formId: "b", version: "1", fields: [] },
          { formId: "b", version: "1", fields: [field] },
        ],
      }),
      [
        "modules.dossier.settings: extra is not a dossier setting",
        "modules.dossier.settings: forms[0] must be { formId, version, fields }",
        "modules.dossier.settings: forms[1] (a): every field needs a key and an English and French label",
        "modules.dossier.settings: forms[2] (Bad Id): field sin names a card or a Social Insurance Number, which intake never collects",
        "modules.dossier.settings: forms[2]: formId must be lower-case letters, digits, hyphens or underscores",
        "modules.dossier.settings: forms[2] (Bad Id): field issue has an unknown type",
        "modules.dossier.settings: forms[3] (b): the form has no fields",
        "modules.dossier.settings: two forms have the same formId",
      ],
    );
  });

  it("reports every bad field rule: showIf, bounds, patterns, forbidden names and cycles", () => {
    const at = (settings: unknown) => validateConfig(config((c) => (c.modules.dossier.settings = settings)), registry());
    const f = (key: string, type: string, extra: object = {}) => ({ key, label: { en: key, fr: key }, type, required: false, ...extra });
    const fields = [
      f("issue", "text", { pattern: "[a-z ]{1,40}" }),
      f("units", "number", { min: 1, max: 10 }),
      f("since", "date", { min: "2020-01-01", max: "2030-12-31" }),
      f("urgent", "yes_no"),
      f("when", "date", { showIf: { field: "urgent", equals: true } }),
      f("ok_chain", "text", { showIf: { field: "when", equals: "2026-01-01" } }),
      f("note", "text", { showIf: { field: "units", equals: 2 } }),
      f("other", "text", { showIf: { field: "issue", equals: "leak" } }),
      f("email", "text", { maxLength: 100, pattern: "[^@\\s]+@[^@\\s]+" }),
      f("lazy", "text", { pattern: "\\u{1F600}+?x??y{2,5}?z{600,}" }),
      f("bounded", "text", { pattern: "\\P{L}{1,64}@\\p{L}{1,100}\\.[a-z]{2,10}" }),
    ];
    assert.deepEqual(at({ forms: [{ formId: "good", version: "1", fields }] }), [], "every rule a form may use");
    const bad = [
      f("a1", "text", { colour: "red" }),
      f("card_number", "text"),
      f("ref", "text", { label: { en: "Credit Card", fr: "Carte" } }),
      f("ref2", "text", { label: { en: "Your S.I.N.", fr: "Référence" } }),
      f("ref3", "text", { label: { en: "Reference", fr: "Numéro d'assurance sociale" } }),
      f("n1", "number", { min: "1" }),
      f("n2", "number", { max: Number.POSITIVE_INFINITY }),
      f("n3", "number", { min: 5, max: 4 }),
      f("d1", "date", { min: "2026-02-30" }),
      f("d2", "date", { min: "2027-01-01", max: "2026-01-01" }),
      f("t1", "text", { min: 1 }),
      f("y1", "yes_no", { pattern: "x" }),
      f("p1", "text", { pattern: "" }),
      f("p2", "text", { pattern: "x".repeat(201) }),
      f("p3", "text", { pattern: 5 }),
      f("p4", "text", { pattern: "(" }),
      f("p5", "text", { pattern: "(a)\\1" }),
      f("p6", "text", { pattern: "(?<x>a)\\k<x>" }),
      f("p7", "text", { pattern: "(a+)+" }),
      f("p8", "text", { pattern: "(?:a|b)*c" }),
      f("p9", "text", { pattern: "((a)?b)+" }),
      f("p10", "text", { pattern: "(\\d{3}-){2}" }),
      f("p11", "text", { pattern: "[^@\\s]+@[^@\\s]+" }),
      f("p12", "text", { pattern: "a?".repeat(17) + "a".repeat(17) }),
      f("p13", "text", { pattern: "x|y|z|w|v|u|t|s|r|q|p|o|n|m|l|k|j|i" }),
      f("s1", "text", { showIf: "a1" }),
      f("s2", "text", { showIf: { field: "a1" } }),
      f("s3", "text", { showIf: { field: "a1", equals: "x", also: 1 } }),
      f("s4", "text", { showIf: { field: "ghost", equals: true } }),
      f("s5", "text", { showIf: { field: "n1", equals: "1" } }),
      f("s6", "text", { showIf: { field: "d1", equals: "2026-02-30" } }),
      f("s7", "text", { showIf: { field: "a1", equals: " x" } }),
      f("s8", "text", { showIf: { field: "a1", equals: "" } }),
      f("s9", "text", { showIf: { field: "y1", equals: "yes" } }),
      f("s10", "text", { showIf: { field: "secret", equals: "x" } }),
      f("secret", "text", { sensitive: true }),
      f("c1", "text", { showIf: { field: "c2", equals: "x" } }),
      f("c2", "text", { showIf: { field: "c3", equals: "x" } }),
      f("c3", "text", { showIf: { field: "c1", equals: "x" } }),
      f("self", "yes_no", { showIf: { field: "self", equals: true } }),
      f("into", "text", { showIf: { field: "c1", equals: "x" } }),
    ];
    const at0 = (e: string) => `modules.dossier.settings: forms[0] (bad): ${e}`;
    assert.deepEqual(at({ forms: [{ formId: "bad", version: "1", fields: bad }] }), [
      at0("field a1: colour is not a field setting"),
      at0("field card_number names a card or a Social Insurance Number, which intake never collects"),
      at0("field ref names a card or a Social Insurance Number, which intake never collects"),
      at0("field ref2 names a card or a Social Insurance Number, which intake never collects"),
      at0("field ref3 names a card or a Social Insurance Number, which intake never collects"),
      at0("field n1: min must be a number"),
      at0("field n2: max must be a number"),
      at0("field n3: min is above max"),
      at0("field d1: min must be a YYYY-MM-DD date"),
      at0("field d2: min is above max"),
      at0("field t1: min and max are for number and date fields only"),
      at0("field y1: pattern is for text fields only"),
      at0("field p1: pattern must be 1 to 200 characters"),
      at0("field p2: pattern must be 1 to 200 characters"),
      at0("field p3: pattern must be 1 to 200 characters"),
      at0("field p4: pattern is not a valid regular expression"),
      at0("field p5: pattern must not use a backreference"),
      at0("field p6: pattern must not use a backreference"),
      at0("field p7: pattern repeats a group that repeats or alternates, which can take too long to check"),
      at0("field p8: pattern repeats a group that repeats or alternates, which can take too long to check"),
      at0("field p9: pattern repeats a group that repeats or alternates, which can take too long to check"),
      at0("field p10: pattern repeats a group that repeats or alternates, which can take too long to check"),
      ...["p11", "p12", "p13"].map((k) => at0(`field ${k}: pattern can match in too many ways to check quickly; bound its repetitions, for example {1,40} for +`)),
      at0("field s1: showIf must be { field, equals }"),
      at0("field s2: showIf must be { field, equals }"),
      at0("field s3: showIf must be { field, equals }"),
      at0("field s4: showIf names no field ghost"),
      at0("field s5: showIf.equals is not a value field n1 can take"),
      at0("field s6: showIf.equals is not a value field d1 can take"),
      at0("field s7: showIf.equals is not a value field a1 can take"),
      at0("field s8: showIf.equals is not a value field a1 can take"),
      at0("field s9: showIf.equals is not a value field y1 can take"),
      at0("field s10: showIf depends on secret, which is sensitive, so the questions asked would tell its value"),
      at0("field c1: showIf goes round in a cycle: c1 > c2 > c3 > c1"),
      at0("field c2: showIf goes round in a cycle: c2 > c3 > c1 > c2"),
      at0("field c3: showIf goes round in a cycle: c3 > c1 > c2 > c3"),
      at0("field self: showIf goes round in a cycle: self > self"),
    ]);
  });

  it("needs the fieldCipher adapter once a form has a sensitive field (FIL-2)", () => {
    const sin = { key: "sin", label: { en: "SIN", fr: "NAS" }, type: "text", required: true, sensitive: true };
    const sensitive = config((c) => c.modules.dossier.settings.forms[0].fields.push(sin));
    assert.deepEqual(validateConfig(sensitive, registry()), ["modules.dossier: needs the fieldCipher adapter, which the engine does not have"]);
    assert.deepEqual(validateConfig(sensitive, registry([...ALL_ADAPTERS, "fieldCipher"])), []);
    const marked = config((c) => c.modules.dossier.settings.forms[0].fields.push({ ...sin, sensitive: false }));
    assert.deepEqual(validateConfig(marked, registry()), [], "sensitive: false needs no cipher");
  });

  it("checks paylink settings", () => {
    const at = (settings: unknown) => validateConfig(config((c) => (c.modules.paylink.settings = settings)), registry());
    assert.deepEqual(at(undefined), []);
    assert.deepEqual(at(5), ["modules.paylink.settings: must be an object"]);
    assert.deepEqual(at({ maxAmountMinor: 0, cap: 1 }), ["modules.paylink.settings: cap is not a paylink setting", "modules.paylink.settings: maxAmountMinor must be an integer from 1 to 1000000"]);
    assert.deepEqual(at({ maxAmountMinor: 1_000_000 }), []);
  });

  it("checks trace settings, and needs a signer only while receipts are on", () => {
    const at = (settings: unknown, adapters = ALL_ADAPTERS) => validateConfig(config((c) => (c.modules.trace.settings = settings)), registry(adapters));
    assert.deepEqual(at([]), ["modules.trace.settings: must be an object"]);
    assert.deepEqual(at({ receipts: "yes", x: 1, wordings: {} }), [
      "modules.trace.settings: x is not a trace setting",
      "modules.trace.settings: receipts must be true or false",
      "modules.trace.settings: wordings must be a list",
    ]);
    assert.deepEqual(
      at({
        wordings: [
          "x",
          { purpose: "Bad", version: "", text: { en: "", fr: "y" } },
          { purpose: "a", version: "1", text: { en: "x", fr: 1 } },
          { purpose: "a", version: "1", text: { en: "x", fr: "y" } },
          { purpose: "b", version: "1", text: { en: "x", fr: "y", es: " " } },
          { purpose: "c", version: "1", text: { en: "x", fr: "y", es: 1, de: "z" } },
          { purpose: "d", version: "1", text: { en: "x", fr: "y", es: "z" } },
        ],
      }),
      [
        "modules.trace.settings: wordings[0] must be { purpose, version, text: { en, fr, es? } }",
        "modules.trace.settings: wordings[1]: purpose must be snake_case",
        "modules.trace.settings: wordings[1]: version is empty",
        "modules.trace.settings: wordings[1]: needs an English and a French text",
        "modules.trace.settings: wordings[2]: needs an English and a French text",
        "modules.trace.settings: wordings[4]: the Spanish text (es), when given, must not be empty",
        "modules.trace.settings: wordings[5]: the Spanish text (es), when given, must not be empty",
        "modules.trace.settings: wordings[5]: de is not a locale (en, fr or es)",
        "modules.trace.settings: two wordings have the same purpose",
      ],
    );
    const noSigner = ALL_ADAPTERS.filter((a) => a !== "signer");
    assert.deepEqual(at({ receipts: false }, noSigner), []);
    assert.deepEqual(at({}, noSigner), ["modules.trace: needs the signer adapter, which the engine does not have"]);
  });
});

describe("validateConfig: flows", () => {
  const flows = (value: unknown, reg = registry()) => validateConfig(config((c) => (c.flows = value)), reg);

  it("accepts a valid flow of every built-in step", () => {
    assert.deepEqual(
      flows({
        deposit: {
          summary: "all of it",
          steps: [
            { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["intake.file", "payment.request"] },
            { type: "dossier.collect", form: "repair" },
            { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" },
            { type: "trace.consent", purpose: "texts" },
            { type: "trace.receipt" },
          ],
        },
      }),
      [],
    );
  });

  it("refuses malformed flows and steps, unknown step types and steps of modules that are off", () => {
    assert.deepEqual(
      flows({
        "Bad Name": { steps: [{ type: "trace.receipt" }] },
        empty: { steps: [] },
        nosteps: "x",
        odd: { summary: 1, extra: true, steps: ["x", { type: 1 }, { type: "vault.open" }, { type: "paylink.request" }] },
      }, new ModuleRegistry({ adapters: ALL_ADAPTERS, modules: builtInModules() })) .slice(0, 6),
      [
        "flows.Bad Name: a flow name is lower-case letters, digits and hyphens, at most 64",
        "flows.empty: must be an object with at least one step",
        "flows.nosteps: must be an object with at least one step",
        "flows.odd.extra: not a flow field",
        "flows.odd.summary: must be a string",
        "flows.odd.steps[0]: a step is an object with a type",
      ],
    );
    const off = validateConfig(
      config((c) => {
        c.modules.paylink.enabled = false;
        c.flows = { odd: { steps: [{ type: 1 }, { type: "vault.open" }, { type: "gate.grant" }, { type: "paylink.request" }] } };
      }),
      registry(),
    );
    assert.deepEqual(off, [
      "flows.odd.steps[0]: a step is an object with a type",
      "flows.odd.steps[1]: no installed module provides the step vault.open",
      "flows.odd.steps[2] (gate.grant): the gate module is turned off",
      "flows.odd.steps[3] (paylink.request): the paylink module is turned off",
    ]);
  });

  it("checks badge.verify: level, factors that are on, reachability and scopes", () => {
    const step = (s: Record<string, unknown>) => flows({ f: { steps: [{ type: "badge.verify", ...s }] } });
    assert.deepEqual(step({ level: 4, factors: "pin", x: 1 }), ["flows.f.steps[0] (badge.verify): x is not a field of this step", "flows.f.steps[0] (badge.verify): level must be 1, 2 or 3", "flows.f.steps[0] (badge.verify): factors must list at least one factor"]);
    assert.deepEqual(step({ level: 2, factors: ["pin", "pin", "text_code"] }), [
      "flows.f.steps[0] (badge.verify): factors has duplicates",
      "flows.f.steps[0] (badge.verify): factor text_code is turned off in the badge settings",
      "flows.f.steps[0] (badge.verify): factor text_code needs the policy's textCodeCountryCodes, or no code is ever texted",
    ]);
    const withCodes = (countries: string[] | undefined) =>
      validateConfig(
        config((c) => {
          c.modules.badge.settings.factors.push("text_code");
          if (countries !== undefined) c.policy.textCodeCountryCodes = countries;
          c.flows = { f: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "text_code"] }] } };
        }),
        registry(),
      );
    assert.deepEqual(withCodes(["1", "33"]), []);
    assert.deepEqual(withCodes(undefined), ["flows.f.steps[0] (badge.verify): factor text_code needs the policy's textCodeCountryCodes, or no code is ever texted"]);
    assert.deepEqual(step({ level: 3, factors: ["keypad_knowledge", "carrier_identity_match"] }), [
      "flows.f.steps[0] (badge.verify): level 3 cannot be reached with [keypad_knowledge, carrier_identity_match] under the policy",
    ]);
    assert.deepEqual(step({ level: 1, factors: ["pin"] }), ["flows.f.steps[0] (badge.verify): level 1 cannot be reached with [pin] under the policy"]);
    assert.deepEqual(step({ level: 1, factors: ["keypad_knowledge"], scopes: [] }), ["flows.f.steps[0] (badge.verify): scopes must list at least one scope"]);
    assert.deepEqual(step({ level: 1, factors: ["keypad_knowledge"], scopes: ["status.read", "status.read", "made.up", "payment.request"] }), [
      "flows.f.steps[0] (badge.verify): scopes has duplicates",
      "flows.f.steps[0] (badge.verify): scope made.up is not in the policy",
      "flows.f.steps[0] (badge.verify): scope payment.request needs level 2, above this step's level 1",
    ]);
    // With a broken policy or broken badge settings, the cross-checks are skipped (the other problems are reported).
    const broken = validateConfig(
      config((c) => {
        c.policy.keypadFields = [];
        c.modules.badge.settings.grantTtlSeconds = -1;
        c.flows = { f: { steps: [{ type: "badge.verify", level: 3, factors: ["text_code"], scopes: ["nope"] }] } };
      }),
      registry(),
    );
    assert.deepEqual(broken, ["policy: keypadFields is empty", "modules.badge.settings: grantTtlSeconds must be an integer from 1 to 3600"]);
  });

  it("holds every step to its scope's floor and to the scopes the verification granted", () => {
    const steps = (list: unknown[]) => flows({ f: { steps: list } });
    assert.deepEqual(steps([{ type: "paylink.request", amountMinor: 100, currency: "cad", description: "x", amountSource: "price_list" }]), [
      "flows.f.steps[0] (paylink.request): needs the scope payment.request at level 2, but the flow has verified to level 0 at this point",
    ]);
    assert.deepEqual(
      steps([
        { type: "badge.verify", level: 1, factors: ["keypad_knowledge"] },
        { type: "paylink.request", amountMinor: 100, currency: "cad", description: "x", amountSource: "price_list" },
      ]),
      ["flows.f.steps[1] (paylink.request): needs the scope payment.request at level 2, but the flow has verified to level 1 at this point"],
    );
    assert.deepEqual(
      steps([
        { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] },
        { type: "dossier.collect", form: "repair" },
      ]),
      ["flows.f.steps[1] (dossier.collect): needs the scope intake.file, which the last verification step does not grant"],
    );
    const noScope = validateConfig(
      config((c) => {
        delete c.policy.scopes["intake.file"];
        c.flows = { f: { steps: [{ type: "dossier.collect", form: "repair" }] } };
      }),
      registry(),
    );
    assert.deepEqual(noScope, ["flows.f.steps[0] (dossier.collect): needs the scope intake.file, which the policy does not list"]);
  });

  it("checks dossier, paylink and trace steps", () => {
    const one = (step: Record<string, unknown>) => flows({ f: { steps: [{ type: "badge.verify", level: 3, factors: ["keypad_knowledge", "photo_id"] }, step] } }).map((p) => p.replace(/^flows\.f\.steps\[1\] /, ""));
    assert.deepEqual(one({ type: "dossier.collect", x: 1 }), ["(dossier.collect): x is not a field of this step", "(dossier.collect): form must name a form"]);
    assert.deepEqual(one({ type: "dossier.collect", form: "nope" }), ["(dossier.collect): no form nope in the dossier settings"]);
    assert.deepEqual(one({ type: "paylink.request", currency: "CAD", description: "", amountSource: "model", x: 1 }), [
      "(paylink.request): x is not a field of this step",
      "(paylink.request): amountMinor and currency are required",
      "(paylink.request): description must be 1 to 200 characters",
      "(paylink.request): amountSource must be one of intake_record, business_endpoint, price_list",
    ]);
    const pay = { type: "paylink.request", amountMinor: 100, currency: "cad", description: "x", amountSource: "price_list" };
    assert.deepEqual(one({ ...pay, mode: "cash" }), ["(paylink.request): mode must be connect or platform"]);
    assert.deepEqual(one({ ...pay, mode: "connect" }), ["(paylink.request): connect mode needs connectedAccountId in the paylink settings"]);
    assert.deepEqual(one({ ...pay, amountMinor: 1_000_001 }), ["(paylink.request): amountMinor is above the limit"]);
    // PAY-2: a reference the AmountSource resolves, instead of a fixed amount, never both.
    const byRef = { type: "paylink.request", amountRef: "deposit.standard", description: "x", amountSource: "price_list" };
    const withAmounts = registry([...ALL_ADAPTERS, "amounts"]);
    const verify = { type: "badge.verify", level: 3, factors: ["keypad_knowledge", "photo_id"] };
    assert.deepEqual(flows({ f: { steps: [verify, byRef] } }, withAmounts), []);
    assert.deepEqual(one(byRef), ["(paylink.request): an amountRef needs the amounts adapter, which the engine does not have"]);
    assert.deepEqual(
      flows({ f: { steps: [verify, { ...byRef, amountMinor: 100, currency: "cad" }, { ...byRef, amountRef: "no spaces" }, { ...byRef, amountRef: 7 }, { ...byRef, amountRef: "x".repeat(65) }] } }, withAmounts),
      [
        "flows.f.steps[1] (paylink.request): name amountMinor and currency, or amountRef, not both",
        "flows.f.steps[2] (paylink.request): amountRef must be 1 to 64 letters, digits, '.', ':', '-' or '_'",
        "flows.f.steps[3] (paylink.request): amountRef must be 1 to 64 letters, digits, '.', ':', '-' or '_'",
        "flows.f.steps[4] (paylink.request): amountRef must be 1 to 64 letters, digits, '.', ':', '-' or '_'",
      ],
    );
    assert.deepEqual(flows({ f: { steps: [verify, { ...byRef, currency: "cad" }] } }, withAmounts), ["flows.f.steps[1] (paylink.request): name amountMinor and currency, or amountRef, not both"]);
    assert.deepEqual(one({ type: "trace.consent", x: 1 }), ["(trace.consent): x is not a field of this step", "(trace.consent): purpose must name a wording"]);
    assert.deepEqual(one({ type: "trace.consent", purpose: "nope" }), ["(trace.consent): no wording for nope in the trace settings"]);
    assert.deepEqual(one({ type: "trace.receipt", x: 1 }), ["(trace.receipt): x is not a field of this step"]);
    const noSigner = validateConfig(
      config((c) => {
        c.modules.trace.settings = { receipts: false };
        c.flows = { f: { steps: [{ type: "trace.receipt" }, { type: "trace.consent", purpose: "texts" }] } };
      }),
      registry(ALL_ADAPTERS.filter((a) => a !== "signer")),
    );
    assert.deepEqual(noSigner, [
      "flows.f.steps[0] (trace.receipt): a receipt needs the signer adapter, which the engine does not have",
      "flows.f.steps[1] (trace.consent): no wording for texts in the trace settings",
    ]);
    const traceUnlisted = validateConfig(
      config((c) => {
        delete c.modules.trace;
        c.flows = { f: { steps: [{ type: "trace.consent", purpose: "texts" }] } };
      }),
      registry(),
    );
    assert.deepEqual(traceUnlisted, ["flows.f.steps[0] (trace.consent): no wording for texts in the trace settings"]);
    const badDossier = validateConfig(
      config((c) => {
        c.modules.dossier.settings = { forms: 1 };
        c.flows = { f: { steps: [{ type: "dossier.collect", form: "nope" }] } };
      }),
      registry(),
    );
    assert.deepEqual(badDossier, ["modules.dossier.settings: must be an object with a list of forms", "flows.f.steps[0] (dossier.collect): needs the scope intake.file at level 1, but the flow has verified to level 0 at this point"]);
  });

  it("takes scope classes from module manifests, and keeps the strictest", () => {
    const door = outside("door", { scopes: { grants: [], needs: { "door.lookup": "door.open" }, classes: { "door.open": "access" } }, provides: { factors: [], steps: ["door.lookup"], outcomes: [] } });
    const lax = outside("lax", { scopes: { grants: [], needs: {}, classes: { "door.open": "none" } }, provides: { factors: [], steps: ["lax.lookup"], outcomes: [] } });
    const reg = registry(ALL_ADAPTERS, [door, lax]);
    assert.deepEqual(reg.scopeClasses(), { "payment.request": "money", "intake.file": "none", "entry.open": "access", "entry.sign_in": "access", "door.open": "access" });
    const problems = validateConfig(config((c) => (c.policy.scopes["door.open"] = 1)), reg);
    assert.deepEqual(problems, ["policy: scope door.open is access, and below its floor of level 2"]);
  });

  it("runs an outside module's own validators", () => {
    const loyalty = outside("loyalty");
    const reg = registry(ALL_ADAPTERS, [loyalty]);
    const problems = validateConfig(
      config((c) => {
        c.modules.loyalty = { settings: "bad" };
        c.flows = { f: { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "loyalty.lookup", bad: true }] } };
      }),
      reg,
    );
    assert.deepEqual(problems, ["modules.loyalty.settings: bad settings", "flows.f.steps[1] (loyalty.lookup): bad step"]);
    const missing = validateConfig(
      config((c) => {
        c.modules.loyalty = {};
        c.flows = { f: { steps: [{ type: "loyalty.lookup", bad: true }] } };
      }),
      reg,
    );
    assert.deepEqual(missing, [
      "modules.loyalty: needs the crm adapter, which the engine does not have",
      "flows.f.steps[0] (loyalty.lookup): bad step",
      "flows.f.steps[0] (loyalty.lookup): needs the scope status.read at level 1, but the flow has verified to level 0 at this point",
    ]);
  });

  it("throws a ConfigError with every problem from assertConfig", () => {
    assert.throws(
      () => assertConfig({ version: 2 }, registry()),
      (e: unknown) => e instanceof ConfigError && e instanceof EngineError && e.problems.length === 5 && /5 problem/.test(e.message),
    );
    const good = testConfig();
    assert.equal(assertConfig(good, registry()), good);
  });
});

describe("module registry", () => {
  it("installs, lists, finds and removes modules", () => {
    const reg = registry(["ledger"], [outside("loyalty")]);
    assert.deepEqual(reg.list().map((m) => m.manifest.name), ["badge", "dossier", "paylink", "trace", "gate", "step-up", "loyalty"]);
    assert.equal(reg.stepOwner("loyalty.lookup")?.manifest.name, "loyalty");
    assert.equal(reg.stepOwner("nope.step"), undefined);
    assert.ok(reg.factorKinds().includes("pin"));
    assert.ok(reg.adapters.has("ledger"));
    reg.remove("loyalty");
    assert.equal(reg.get("loyalty"), undefined);
    assert.throws(() => reg.remove("loyalty"), (e: unknown) => e instanceof EngineError && e.code === "invalid_input");
    assert.throws(() => reg.remove("trace"), (e: unknown) => e instanceof EngineError && e.code === "precondition_failed");
    assert.equal(reg.use(outside("crm2")), reg);
    assert.deepEqual(new ModuleRegistry().list(), []);
  });

  it("refuses bad and clashing manifests, with every problem", () => {
    const installed = builtInModules();
    const manifest = (patch: Partial<ModuleManifest>) => ({ ...outside("x1").manifest, ...patch });
    assert.deepEqual(checkManifest(manifest({ name: "Badge!" , version: " ", provides: { factors: ["pin"], steps: ["other.step", "Badge!.x.y", "Badge!"], outcomes: [] }, scopes: { grants: [], needs: { "Badge!.z": "a" } } }), installed), [
      'module name "Badge!" must be 2 to 32 lower-case letters, digits or hyphens',
      "module Badge! needs a version",
      'module Badge!: step "other.step" must be Badge!.<snake_case name>',
      'module Badge!: step "Badge!.x.y" must be Badge!.<snake_case name>',
      'module Badge!: step "Badge!" must be Badge!.<snake_case name>',
      "module Badge!: needs a scope for Badge!.z, which it does not provide",
      "module Badge!: factor pin is already provided by badge",
    ]);
    assert.deepEqual(checkManifest(manifest({ name: "core" }), installed), ["module name core is reserved", 'module core: step "x1.lookup" must be core.<snake_case name>']);
    assert.deepEqual(checkManifest(manifest({ name: "trace", alwaysOn: true, provides: { factors: [], steps: [], outcomes: [] }, scopes: { grants: [], needs: {} } }), installed), [
      "a module named trace is already installed",
      "module trace: only one module can hold the audit ledger",
    ]);
    assert.throws(() => registry().use(outside("badge")), /a module named badge is already installed/);
  });

  it("refuses bad factor plug-ins", () => {
    const plugin = { summary: "x", adapters: [], judge: async () => true };
    assert.throws(
      () =>
        badgeModule({
          factors: [
            { ...plugin, kind: "ab", maxAttemptsPerCall: 0 },
            { ...plugin, kind: "caller_id", maxAttemptsPerCall: 1 },
            { ...plugin, kind: "pin", maxAttemptsPerCall: 1 },
            { ...plugin, kind: "voice_x", maxAttemptsPerCall: 1 },
            { ...plugin, kind: "voice_x", maxAttemptsPerCall: 1 },
          ],
        }),
      (e: unknown) =>
        e instanceof EngineError &&
        e.message ===
          [
            'factor kind "ab" must be snake_case, 3 to 32 characters',
            "factor ab: maxAttemptsPerCall must be 1 to 5",
            "factor kind caller_id would make caller ID a factor, which it never is",
            "factor kind pin already exists",
            "factor kind voice_x already exists",
          ].join("; "),
    );
  });

  it("checks the factors a manifest provides, and the judges a module supplies for them (MOD-3)", () => {
    const installed = builtInModules();
    const judge = async () => true;
    const manifest = (factors: string[]) => ({ ...outside("x1").manifest, provides: { factors, steps: [], outcomes: [] }, scopes: { grants: [], needs: {} } });
    assert.deepEqual(checkManifest(manifest(["caller_id", "ab", "pin"]), installed), [
      "module x1: factor kind caller_id would make caller ID a factor, which it never is",
      'module x1: factor kind "ab" must be snake_case, 3 to 32 characters',
      "module x1: factor pin is already provided by badge",
    ]);
    const supplying = (factors: string[], factorPlugins: FactorPlugin[]): AssuranceModule => ({ ...outside("x1"), manifest: manifest(factors), factorPlugins });
    const plugin = (kind: string, patch: Partial<FactorPlugin> = {}): FactorPlugin => ({ kind, summary: "x", maxAttemptsPerCall: 1, adapters: [], judge, ...patch });
    assert.deepEqual(checkFactorPlugins(outside("x1")), [], "a module without factors needs no judges");
    assert.deepEqual(checkFactorPlugins({ ...outside("x1"), manifest: manifest(["desk_code"]) }), ["module x1: factor desk_code has no judge"], "a missing list judges nothing");
    assert.deepEqual(checkFactorPlugins(installed.find((m) => m.manifest.name === "badge")!), [], "Badge judges its own factors");
    assert.deepEqual(checkFactorPlugins(supplying(["desk_code"], [plugin("desk_code")])), []);
    assert.deepEqual(
      checkFactorPlugins(supplying(["desk_code", "token_code"], [plugin("desk_code"), plugin("desk_code", { maxAttemptsPerCall: 6 }), plugin("other_code", { judge: "yes" as unknown as FactorPlugin["judge"] })])),
      [
        "module x1: judges desk_code twice",
        "module x1: factor desk_code: maxAttemptsPerCall must be 1 to 5",
        "module x1: judges other_code, a factor its manifest does not provide",
        "module x1: factor other_code: judge must be a function",
        "module x1: factor token_code has no judge",
      ],
    );
    assert.throws(() => registry().use(supplying(["desk_code"], [])), /module x1: factor desk_code has no judge/);
    assert.deepEqual(checkFactorPlugin(plugin("desk_code", { judge: undefined as unknown as FactorPlugin["judge"] }), []), ["factor desk_code: judge must be a function"]);
  });

  it("lists the judges outside modules supply, and replaces a module in its place (MOD-3)", () => {
    const reg = registry(ALL_ADAPTERS, [{ ...outside("x1"), manifest: { ...outside("x1").manifest, provides: { factors: ["desk_code"], steps: ["x1.lookup"], outcomes: [] } }, factorPlugins: [{ kind: "desk_code", summary: "x", maxAttemptsPerCall: 1, adapters: [], judge: async () => true }] }]);
    assert.deepEqual(reg.factorPlugins().map((p) => p.kind), ["desk_code"]);
    const plugin = { kind: "desk_code", summary: "x", maxAttemptsPerCall: 1, adapters: [], judge: async () => true };
    assert.throws(() => reg.replace(badgeModule({ factors: [plugin] })), /factor desk_code is already provided by x1/);
    const next = badgeModule({ factors: [{ ...plugin, kind: "lobby_code" }] });
    reg.replace(next);
    assert.equal(reg.get("badge"), next);
    assert.deepEqual(reg.list().map((m) => m.manifest.name), ["badge", "dossier", "paylink", "trace", "gate", "step-up", "x1"]);
    assert.ok(reg.factorKinds().includes("lobby_code"));
    assert.throws(() => reg.replace(outside("loyalty")), (e: unknown) => e instanceof EngineError && e.code === "invalid_input" && /no module named loyalty/.test(e.message));
  });

  it("has small shape helpers", () => {
    assert.equal(isBilingual({ en: "a", fr: "b" }), true);
    assert.equal(isBilingual({ en: "a", fr: " " }), false);
    assert.equal(isBilingual({ en: 1, fr: "b" }), false);
    assert.equal(isBilingual("x" as JsonValue), false);
  });
});
