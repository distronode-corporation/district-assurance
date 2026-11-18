import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
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
      "level 2 set [photo_id]: level 2 and above need two different factors",
      "level 3 set [keypad_knowledge, text_code]: level 3 needs photo_id",
    ]);
  });

  it("holds money and contact scopes at their floor", () => {
    const errors = validatePolicy(policy({ scopes: { "payment.request": 1, "contact.update": 0, "status.read": 5 as 1, "payout.x": 2 } }));
    assert.deepEqual(errors, [
      "scope payment.request is below its floor of level 2",
      "scope contact.update is below its floor of level 2",
      "scope status.read has level 5, not 0 to 3",
    ]);
  });

  it("checks the keypad fields and limits", () => {
    assert.deepEqual(validatePolicy(policy({ keypadFields: [], maxKeypadAttemptsPerCall: 0, simSwapWindowHours: 0 })), [
      "keypadFields is empty",
      "maxKeypadAttemptsPerCall must be a positive integer",
      "simSwapWindowHours must be positive",
    ]);
    assert.deepEqual(validatePolicy(policy({ keypadFields: ["dob", "dob"], maxKeypadAttemptsPerCall: 1.5, simSwapWindowHours: Number.NaN })), [
      "keypadFields has duplicates",
      "maxKeypadAttemptsPerCall must be a positive integer",
      "simSwapWindowHours must be positive",
    ]);
  });
});

describe("scopeFloor", () => {
  it("is the highest matching floor, or 0", () => {
    assert.equal(scopeFloor("payment.request"), 2);
    assert.equal(scopeFloor("contact.update"), 2);
    assert.equal(scopeFloor("payout.update"), 2);
    assert.equal(scopeFloor("status.read"), 0);
    assert.equal(scopeFloor("paymentx"), 0);
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
