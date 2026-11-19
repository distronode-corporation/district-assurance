import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  defaultVerificationPolicy,
  evaluateAssurance,
  raiseMinimum,
  scopeFloor,
  scopesForLevel,
  stepAmount,
  textCodeTrusted,
  validatePolicy,
  type CarrierSignalReport,
  type FactorKind,
  type FactorResult,
  type StepUpRule,
  type VerificationPolicy,
} from "../src/core/policy.ts";

const at = "2026-01-01T00:00:00.000Z";
const pass = (...kinds: FactorKind[]): FactorResult[] => kinds.map((kind) => ({ kind, passed: true, at }));
const clean: CarrierSignalReport = { checked: true, lastSimSwapHoursAgo: null, lastPortHoursAgo: null, identityMatch: "unavailable" };

function policy(patch: Partial<VerificationPolicy> = {}): VerificationPolicy {
  return { ...defaultVerificationPolicy(), ...patch };
}

describe("validatePolicy", () => {
  it("accepts the default policy", () => {
    assert.deepEqual(validatePolicy(defaultVerificationPolicy()), []);
  });

  it("refuses levels that are out of range, repeated or empty", () => {
    const errors = validatePolicy(
      policy({
        levels: [
          { level: 4 as 1, anyOf: [["keypad_knowledge"]] },
          { level: 1, anyOf: [["keypad_knowledge"]] },
          { level: 1, anyOf: [] },
          { level: 2, anyOf: [[]] },
        ],
      }),
    );
    assert.deepEqual(errors, [
      "level 4 is not 1, 2 or 3",
      "level 4 set [keypad_knowledge]: level 2 and above need two different factors",
      "level 4 set [keypad_knowledge]: level 2 and above need a factor that is not something the caller knows (text_code, carrier_identity_match, photo_id)",
      "level 1 is defined twice",
      "level 1 has no factor sets",
      "level 2 has an empty factor set",
    ]);
  });

  it("refuses weak or malformed factor sets", () => {
    const errors = validatePolicy(
      policy({
        levels: [
          { level: 1, anyOf: [["text_code"], ["caller_id" as FactorKind]] },
          { level: 2, anyOf: [["keypad_knowledge", "keypad_knowledge"], ["photo_id"]] },
          { level: 3, anyOf: [["keypad_knowledge", "text_code"]] },
        ],
      }),
    );
    assert.deepEqual(errors, [
      "level 1 set [text_code]: a texted code is never a factor on its own",
      "level 1 set [caller_id]: unknown factor caller_id",
      "level 2 set [keypad_knowledge, keypad_knowledge]: a factor is repeated",
      "level 2 set [keypad_knowledge, keypad_knowledge]: level 2 and above need two different factors",
      "level 2 set [keypad_knowledge, keypad_knowledge]: level 2 and above need a factor that is not something the caller knows (text_code, carrier_identity_match, photo_id)",
      "level 2 set [photo_id]: level 2 and above need two different factors",
      "level 3 set [keypad_knowledge, text_code]: level 3 needs photo_id",
    ]);
  });

  it("holds money and contact scopes at their floor", () => {
    const errors = validatePolicy(policy({ scopes: { "payment.request": 1, "contact.update": 0, "status.read": 5 as 1, "payout.x": 2 } }));
    assert.deepEqual(errors, [
      "scope payment.request is money, and below its floor of level 2",
      "scope contact.update is contact, and below its floor of level 2",
      "scope status.read has level 5, not 0 to 3",
    ]);
  });

  it("checks the keypad fields and limits", () => {
    assert.deepEqual(validatePolicy(policy({ keypadFields: [], maxKeypadAttemptsPerCall: 0, simSwapWindowHours: 0 })), [
      "keypadFields is empty",
      "maxKeypadAttemptsPerCall must be an integer from 1 to 5",
      "simSwapWindowHours must be a positive number",
    ]);
    assert.deepEqual(validatePolicy(policy({ keypadFields: ["dob", "dob"], maxKeypadAttemptsPerCall: 1.5, simSwapWindowHours: Number.NaN })), [
      "keypadFields has duplicates",
      "maxKeypadAttemptsPerCall must be an integer from 1 to 5",
      "simSwapWindowHours must be a positive number",
    ]);
  });
});

describe("validatePolicy: the review's hostile cases", () => {
  it("refuses level 2 from two things the caller knows (keypad and PIN)", () => {
    assert.deepEqual(validatePolicy(policy({ levels: [{ level: 1, anyOf: [["keypad_knowledge"]] }, { level: 2, anyOf: [["keypad_knowledge", "pin"]] }] })), [
      "level 2 set [keypad_knowledge, pin]: level 2 and above need a factor that is not something the caller knows (text_code, carrier_identity_match, photo_id)",
    ]);
  });

  it("holds money scopes at level 2 whatever they are called, and refuses a scope with no class", () => {
    assert.deepEqual(validatePolicy(policy({ scopes: { "refund.issue": 0, "transfer.funds": 1, "owner.command": 1, "wire.out": 2 } })), [
      "scope refund.issue is money, and below its floor of level 2",
      "scope transfer.funds is money, and below its floor of level 2",
      "scope owner.command has no class: name it in scopeClasses (money, contact, access or none)",
      "scope wire.out has no class: name it in scopeClasses (money, contact, access or none)",
    ]);
    assert.deepEqual(validatePolicy(policy({ scopes: { "owner.command": 1, "wire.out": 1 }, scopeClasses: { "owner.command": "none", "wire.out": "money" } })), [
      "scope wire.out is money, and below its floor of level 2",
    ]);
  });

  it("never lets a class loosen what a name or a module says", () => {
    assert.deepEqual(validatePolicy(policy({ scopes: { "payment.small": 1 }, scopeClasses: { "payment.small": "none" } })), ["scope payment.small is money, and below its floor of level 2"]);
    assert.deepEqual(validatePolicy(policy({ scopes: { "door.open": 1 }, scopeClasses: { "door.open": "none" } }), undefined, { "door.open": "access" }), ["scope door.open is access, and below its floor of level 2"]);
    assert.deepEqual(validatePolicy(policy({ scopes: { "entry.front": 1 } })), ["scope entry.front is access, and below its floor of level 2"]);
    assert.deepEqual(validatePolicy(policy({ scopes: { "status.balance_move": 1 }, scopeClasses: { "status.balance_move": "money" } })), ["scope status.balance_move is money, and below its floor of level 2"], "a class can make a scope stricter");
    assert.deepEqual(validatePolicy(policy({ scopeClasses: ["money"] as never })), ["scopeClasses must map scope names to money, contact, access or none"]);
    assert.deepEqual(validatePolicy(policy({ scopeClasses: { x: "cash" } as never })), ["scopeClasses.x must be money, contact, access or none"]);
  });

  it("caps keypad attempts like the PIN", () => {
    assert.deepEqual(validatePolicy(policy({ maxKeypadAttemptsPerCall: 1_000_000 })), ["maxKeypadAttemptsPerCall must be an integer from 1 to 5"]);
    assert.deepEqual(validatePolicy(policy({ maxKeypadAttemptsPerCall: 5 })), []);
  });

  it("reports every problem in one pass, a malformed part included", () => {
    assert.deepEqual(validatePolicy(null), ["must be an object"]);
    assert.deepEqual(
      validatePolicy({ version: "", levels: [{ level: 1 }, "x", { level: 2, anyOf: [["pin"]] }], scopes: { "payment.request": 1 }, keypadFields: "dob", maxKeypadAttemptsPerCall: "2", simSwapWindowHours: null, trustTextCodeWithoutCarrierCheck: 1 }),
      [
        "version must be a non-empty string",
        "levels[0] must be { level, anyOf: [[factor, ...], ...] }",
        "levels[1] must be { level, anyOf: [[factor, ...], ...] }",
        "level 2 set [pin]: level 2 and above need two different factors",
        "level 2 set [pin]: level 2 and above need a factor that is not something the caller knows (text_code, carrier_identity_match, photo_id)",
        "scope payment.request is money, and below its floor of level 2",
        "keypadFields must be a list of field names",
        "maxKeypadAttemptsPerCall must be an integer from 1 to 5",
        "simSwapWindowHours must be a positive number",
        "trustTextCodeWithoutCarrierCheck must be true or false",
      ],
    );
    assert.deepEqual(validatePolicy(policy({ scopes: { "status.read": { toString: null } as never, "status.x": null as never } })), [
      "scope status.read has level of type object, not 0 to 3",
      "scope status.x has level of type null, not 0 to 3",
    ], "never coerced to a string");
    assert.deepEqual(validatePolicy({ ...defaultVerificationPolicy(), levels: "x", scopes: [] }), ["levels must be a list of { level, anyOf: [[factor, ...], ...] }", "scopes must map scope names to levels"]);
  });
});

describe("scopeFloor", () => {
  it("is the highest matching floor, or 0", () => {
    assert.equal(scopeFloor("payment.request"), 2);
    assert.equal(scopeFloor("contact.update"), 2);
    assert.equal(scopeFloor("payout.update"), 2);
    assert.equal(scopeFloor("status.read"), 0);
    assert.equal(scopeFloor("paymentx"), 0);
    assert.equal(scopeFloor("refund.issue"), 2);
    assert.equal(scopeFloor("entry.front"), 2);
    assert.equal(scopeFloor("owner.command"), 0, "no class from the name alone");
  });
});

describe("textCodeTrusted", () => {
  const p = defaultVerificationPolicy();

  it("needs a carrier answer by default", () => {
    assert.equal(textCodeTrusted(p, null), false);
    assert.equal(textCodeTrusted(p, { ...clean, checked: false }), false);
    assert.equal(textCodeTrusted({ ...p, trustTextCodeWithoutCarrierCheck: true }, null), true);
  });

  it("refuses a recent SIM swap or port, inside the window", () => {
    assert.equal(textCodeTrusted(p, clean), true);
    assert.equal(textCodeTrusted(p, { ...clean, lastSimSwapHoursAgo: 72 }), false);
    assert.equal(textCodeTrusted(p, { ...clean, lastSimSwapHoursAgo: 73 }), true);
    assert.equal(textCodeTrusted(p, { ...clean, lastPortHoursAgo: 1 }), false);
  });
});

describe("evaluateAssurance", () => {
  const p = defaultVerificationPolicy();

  it("is level 0 without passed factors", () => {
    assert.deepEqual(evaluateAssurance(p, [], null), { level: 0, counted: [], discounted: [] });
    assert.equal(evaluateAssurance(p, [{ kind: "keypad_knowledge", passed: false, at }], clean).level, 0);
  });

  it("reaches the highest level whose factor set has passed", () => {
    assert.equal(evaluateAssurance(p, pass("keypad_knowledge"), null).level, 1);
    assert.equal(evaluateAssurance(p, pass("keypad_knowledge", "carrier_identity_match"), null).level, 2);
    assert.equal(evaluateAssurance(p, pass("keypad_knowledge", "text_code"), clean).level, 2);
    const strong = evaluateAssurance(p, pass("photo_id", "keypad_knowledge"), null);
    assert.deepEqual(strong, { level: 3, counted: ["keypad_knowledge", "photo_id"], discounted: [] });
  });

  it("does not count a texted code the carrier signals discredit", () => {
    const result = evaluateAssurance(p, pass("keypad_knowledge", "text_code"), { ...clean, lastSimSwapHoursAgo: 2 });
    assert.deepEqual(result, { level: 1, counted: ["keypad_knowledge"], discounted: [{ kind: "text_code", reason: "carrier_signal" }] });
  });

  it("ignores rule order", () => {
    const reversed = { ...p, levels: [...p.levels].reverse() };
    assert.equal(evaluateAssurance(reversed, pass("keypad_knowledge", "photo_id"), null).level, 3);
  });
});

describe("scopesForLevel", () => {
  it("lists the scopes a level unlocks, sorted", () => {
    const p = policy({ scopes: { "hours.read": 0, "status.read": 1, "payment.request": 2, "contact.update": 3 } });
    assert.deepEqual(scopesForLevel(p, 0), ["hours.read"]);
    assert.deepEqual(scopesForLevel(p, 2), ["hours.read", "payment.request", "status.read"]);
    assert.deepEqual(scopesForLevel(p, 3), ["contact.update", "hours.read", "payment.request", "status.read"]);
  });
});

describe("validatePolicy: step-up rules", () => {
  const rules = (stepUp: unknown, patch: Partial<VerificationPolicy> = {}) => validatePolicy({ ...policy({ timeZone: "America/Toronto", ...patch }), stepUp });

  it("accepts a rule of each kind, each above its scope's minimum", () => {
    const stepUp: StepUpRule[] = [
      { name: "large_payment", scope: "payment.request", level: 3, amountOverMinor: { cad: 50000, usd: 40000 } },
      { name: "after_hours", scope: "intake.file", level: 2, localTime: { from: "18:00", to: "08:00" } },
      { name: "flagged", scope: "status.read", level: 3, signal: "fraud_suspected" },
    ];
    assert.deepEqual(rules(stepUp), []);
  });

  it("refuses a rule that does not raise, or whose level is outside 1 to 3", () => {
    assert.deepEqual(
      rules([
        { name: "same", scope: "payment.request", level: 2, signal: "s" },
        { name: "lower", scope: "contact.update", level: 1, signal: "s" },
        { name: "four", scope: "status.read", level: 4, signal: "s" },
        { name: "zero", scope: "status.read", level: 0, signal: "s" },
      ]),
      [
        "stepUp same: level 2 does not raise payment.request above its minimum of 2; a rule only raises",
        "stepUp lower: level 1 does not raise contact.update above its minimum of 3; a rule only raises",
        "stepUp four: level must be 1, 2 or 3",
        "stepUp zero: level must be 1, 2 or 3",
      ],
    );
  });

  it("refuses malformed rules, each problem in one pass", () => {
    assert.deepEqual(rules("all of them"), ["stepUp must be a list of rules"]);
    assert.deepEqual(
      rules([
        null,
        { scope: "status.read", level: 2, signal: "s" },
        { name: "twice", scope: "status.read", level: 2, signal: "s" },
        { name: "twice", scope: "status.read", level: 2, signal: "s", extra: true },
        { name: "nowhere", scope: "refund.issue", level: 3, signal: "s" },
        { name: "none", scope: "status.read", level: 2 },
        { name: "both", scope: "status.read", level: 2, signal: "s", localTime: { from: "18:00", to: "08:00" } },
        { name: "bad_signal", scope: "status.read", level: 2, signal: "Not-Snake" },
      ]),
      [
        "stepUp[0] must be { name, scope, level } and one of amountOverMinor, localTime or signal",
        "stepUp[1]: name must be 1 to 64 of a-z, 0-9 and _, starting with a letter",
        "stepUp twice is defined twice",
        "stepUp twice: extra is not a step-up rule field",
        "stepUp nowhere: scope must be a scope the policy lists",
        "stepUp none: needs exactly one of amountOverMinor, localTime or signal",
        "stepUp both: needs exactly one of amountOverMinor, localTime or signal",
        "stepUp bad_signal: signal must be 1 to 64 of a-z, 0-9 and _, starting with a letter",
      ],
    );
  });

  it("refuses bad thresholds, and an amount rule on a scope that moves no money", () => {
    assert.deepEqual(
      rules([
        { name: "empty", scope: "payment.request", level: 3, amountOverMinor: {} },
        { name: "upper", scope: "payment.request", level: 3, amountOverMinor: { CAD: 100 } },
        { name: "negative", scope: "payment.request", level: 3, amountOverMinor: { cad: -1 } },
        { name: "list", scope: "payment.request", level: 3, amountOverMinor: [100] },
        { name: "intake", scope: "intake.file", level: 2, amountOverMinor: { cad: 100 } },
      ]),
      [
        "stepUp empty: amountOverMinor must map lower-case currency codes to whole amounts in minor units",
        "stepUp upper: amountOverMinor must map lower-case currency codes to whole amounts in minor units",
        "stepUp negative: amountOverMinor must map lower-case currency codes to whole amounts in minor units",
        "stepUp list: amountOverMinor must map lower-case currency codes to whole amounts in minor units",
        "stepUp intake: an amount rule applies only to a money scope",
      ],
    );
  });

  it("refuses bad windows, a time rule without a time zone, and a zone that does not exist", () => {
    const window = (name: string, localTime: unknown) => ({ name, scope: "status.read", level: 2, localTime });
    const bad = (name: string) => `stepUp ${name}: localTime must be { from: "HH:MM", to: "HH:MM" }, two different times`;
    assert.deepEqual(
      rules([window("same", { from: "18:00", to: "18:00" }), window("late", { from: "24:00", to: "08:00" }), window("days", { from: "18:00", to: "08:00", days: 5 }), window("word", "night")]),
      [bad("same"), bad("late"), bad("days"), bad("word")],
    );
    assert.deepEqual(validatePolicy({ ...policy(), stepUp: [window("w", { from: "18:00", to: "08:00" })] }), ["stepUp w: a localTime rule needs the policy's timeZone"]);
    assert.deepEqual(validatePolicy(policy({ timeZone: "Mars/Olympus_Mons" })), ["timeZone must be an IANA time zone, for example America/Toronto"]);
    assert.deepEqual(validatePolicy({ ...policy(), timeZone: 5 }), ["timeZone must be an IANA time zone, for example America/Toronto"]);
  });

  it("checks rules against what it can when the scopes are malformed", () => {
    const errors = validatePolicy({ ...policy({ timeZone: "UTC" }), scopes: null, stepUp: [{ name: "r", scope: "status.read", level: 2, signal: "s" }] });
    assert.deepEqual(errors, ["scopes must map scope names to levels", "stepUp r: scope must be a scope the policy lists"]);
  });
});

describe("raiseMinimum", () => {
  const p = policy({
    timeZone: "America/Toronto",
    stepUp: [
      { name: "large", scope: "payment.request", level: 3, amountOverMinor: { cad: 50000 } },
      { name: "morning", scope: "status.read", level: 2, localTime: { from: "08:00", to: "12:00" } },
      { name: "flagged", scope: "status.read", level: 3, signal: "flagged" },
    ],
  });
  const noon = new Date("2026-01-01T17:00:00Z"); // 12:00 in Toronto

  it("keeps the policy's minimum when no rule holds", () => {
    assert.deepEqual(raiseMinimum(p, "payment.request", { amount: { amountMinor: 50000, currency: "cad" }, at: noon, signals: [] }), { level: 2, rules: [] });
    assert.deepEqual(raiseMinimum(p, "status.read", { at: noon, signals: ["other"] }), { level: 1, rules: [] });
    assert.deepEqual(raiseMinimum(policy(), "status.read", { at: noon, signals: [] }), { level: 1, rules: [] });
  });

  it("raises to the highest rule that holds, and names every one", () => {
    assert.deepEqual(raiseMinimum(p, "payment.request", { amount: { amountMinor: 50001, currency: "cad" }, at: noon, signals: [] }), { level: 3, rules: [{ name: "large", level: 3 }] });
    assert.equal(raiseMinimum(p, "payment.request", { at: noon, signals: [] }).level, 3, "an amount not known counts as over");
    const morning = new Date("2026-01-01T16:59:00Z"); // 11:59 in Toronto
    assert.deepEqual(raiseMinimum(p, "status.read", { at: morning, signals: ["flagged"] }), {
      level: 3,
      rules: [
        { name: "morning", level: 2 },
        { name: "flagged", level: 3 },
      ],
    });
    const reversed = { ...p, stepUp: [...p.stepUp!].reverse() };
    assert.equal(raiseMinimum(reversed, "status.read", { at: morning, signals: ["flagged"] }).level, 3, "in any order");
  });

  it("reads a step's amount only when it names one", () => {
    assert.deepEqual(stepAmount({ type: "paylink.request", amountMinor: 100, currency: "cad" }), { amountMinor: 100, currency: "cad" });
    assert.equal(stepAmount({ type: "paylink.request", amountMinor: 100 }), undefined);
    assert.equal(stepAmount({ type: "badge.verify" }), undefined);
    assert.equal(stepAmount(null), undefined);
  });
});
