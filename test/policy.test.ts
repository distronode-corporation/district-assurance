import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  capLevel,
  defaultVerificationPolicy,
  evaluateAssurance,
  scopeFloor,
  scopesForLevel,
  textCodeTrusted,
  validatePolicy,
  type CarrierSignalReport,
  type FactorKind,
  type FactorResult,
  type VerificationPolicy,
} from "../src/core/policy.ts";

const at = "2026-01-01T00:00:00.000Z";
const pass = (...kinds: FactorKind[]): FactorResult[] => kinds.map((kind) => ({ kind, passed: true, at }));
const clean: CarrierSignalReport = { checked: true, simSwapChecked: true, lastSimSwapHoursAgo: null, lastPortHoursAgo: null, identityMatch: "unavailable" };

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
      "level 4 set [keypad_knowledge]: level 2 and above need a factor that is not something the caller knows (text_code, carrier_identity_match, photo_id, callback)",
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
      "level 1 set [text_code]: possession of the number on file (text_code, callback) is never a factor on its own",
      "level 1 set [caller_id]: unknown factor caller_id",
      "level 2 set [keypad_knowledge, keypad_knowledge]: a factor is repeated",
      "level 2 set [keypad_knowledge, keypad_knowledge]: level 2 and above need two different factors",
      "level 2 set [keypad_knowledge, keypad_knowledge]: level 2 and above need a factor that is not something the caller knows (text_code, carrier_identity_match, photo_id, callback)",
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
      "level 2 set [keypad_knowledge, pin]: level 2 and above need a factor that is not something the caller knows (text_code, carrier_identity_match, photo_id, callback)",
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

  it("refuses a callback alone, or with only a texted code, and holds level 3 to photo ID (VER-9)", () => {
    const levels = (anyOf: FactorKind[][], level: 1 | 2 | 3 = 1) => policy({ levels: [{ level, anyOf }] });
    assert.deepEqual(validatePolicy(levels([["callback"]])), ["level 1 set [callback]: possession of the number on file (text_code, callback) is never a factor on its own"]);
    assert.deepEqual(validatePolicy(levels([["callback", "text_code"]], 2)), [
      "level 2 set [callback, text_code]: possession of the number on file (text_code, callback) is never a factor on its own",
    ]);
    assert.deepEqual(validatePolicy(levels([["pin", "callback"]], 3)), ["level 3 set [pin, callback]: level 3 needs photo_id"]);
    assert.deepEqual(validatePolicy(levels([["pin", "callback"], ["keypad_knowledge", "callback"]], 2)), [], "possession plus knowledge is level 2");
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
        "level 2 set [pin]: level 2 and above need a factor that is not something the caller knows (text_code, carrier_identity_match, photo_id, callback)",
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

describe("attestationCaps", () => {
  it("accepts caps from 0 to 3 for any attestation, and no caps at all", () => {
    assert.deepEqual(validatePolicy(policy({ attestationCaps: { A: 3, B: 2, C: 2, none: 2, failed: 0 } })), []);
    assert.deepEqual(validatePolicy(policy({ attestationCaps: {} })), []);
    assert.equal(defaultVerificationPolicy().attestationCaps, undefined, "no caps by default");
  });

  it("refuses a cap outside 0 to 3, a value that is not an attestation, and a malformed map", () => {
    const errors = validatePolicy(policy({ attestationCaps: { C: 4, none: -1, failed: 1.5, B: "2" as unknown as 2, D: 1 } as never }));
    assert.deepEqual(errors, [
      "attestationCaps.C must be a level from 0 to 3",
      "attestationCaps.none must be a level from 0 to 3",
      "attestationCaps.failed must be a level from 0 to 3",
      "attestationCaps.B must be a level from 0 to 3",
      "attestationCaps.D is not an attestation (A, B, C, failed or none)",
    ]);
    for (const caps of [null, [2], 2]) {
      assert.deepEqual(validatePolicy(policy({ attestationCaps: caps as never })), ["attestationCaps must map A, B, C, failed or none to a level from 0 to 3"]);
    }
  });

  it("only ever lowers a level", () => {
    const p = policy({ attestationCaps: { C: 2, failed: 0 } });
    assert.equal(capLevel(p, 3, "C"), 2);
    assert.equal(capLevel(p, 1, "C"), 1, "a cap above the level never raises it");
    assert.equal(capLevel(p, 2, "failed"), 0);
    assert.equal(capLevel(p, 3, "A"), 3, "no cap for the value");
    assert.equal(capLevel(defaultVerificationPolicy(), 2, "none"), 2, "no caps at all");
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

  it("never trusts a texted code on a carrier answer that did not cover SIM changes, whatever the policy", () => {
    // Telnyx Number Lookup answers about ports only: lastSimSwapHoursAgo null there is not "none".
    const portsOnly: CarrierSignalReport = { ...clean, simSwapChecked: false };
    assert.equal(textCodeTrusted(p, portsOnly), false);
    assert.equal(textCodeTrusted({ ...p, trustTextCodeWithoutCarrierCheck: true }, portsOnly), false, "the opt-in covers no answer at all, not half of one");
    assert.equal(textCodeTrusted(p, { ...portsOnly, lastPortHoursAgo: 1000 }), false, "an old port does not stand in for SIM changes");
    const { simSwapChecked: _omitted, ...withoutField } = clean;
    assert.equal(textCodeTrusted(p, withoutField as CarrierSignalReport), false, "an adapter that leaves the field out fails closed");
    assert.equal(textCodeTrusted(p, clean), true);
    assert.equal(evaluateAssurance(p, pass("keypad_knowledge", "text_code"), portsOnly).level, 1, "the texted code is discounted");
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

  it("does not count a callback the carrier signals discredit, like a texted code (VER-9)", () => {
    // The callback pair joins the default level-2 rule: a second level-2 rule would not load.
    const withCallback = policy({
      levels: p.levels.map((rule) => (rule.level === 2 ? { ...rule, anyOf: [...rule.anyOf, ["pin", "callback"]] } : rule)),
    });
    assert.deepEqual(validatePolicy(withCallback), [], "a policy a host can load");
    assert.equal(evaluateAssurance(withCallback, pass("pin", "callback"), clean).level, 2);
    for (const report of [{ ...clean, lastSimSwapHoursAgo: 2 }, { ...clean, lastPortHoursAgo: 72 }, { ...clean, checked: false }, null]) {
      assert.deepEqual(evaluateAssurance(withCallback, pass("pin", "callback"), report), { level: 0, counted: ["pin"], discounted: [{ kind: "callback", reason: "carrier_signal" }] });
    }
    const both = evaluateAssurance(withCallback, pass("keypad_knowledge", "text_code", "callback"), { ...clean, lastPortHoursAgo: 1 });
    assert.deepEqual(both.discounted.map((d) => d.kind), ["text_code", "callback"]);
    assert.equal(both.level, 1);
    assert.equal(evaluateAssurance({ ...withCallback, trustTextCodeWithoutCarrierCheck: true }, pass("pin", "callback"), null).level, 2, "only when the policy opts in");
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
