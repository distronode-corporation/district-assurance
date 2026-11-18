// The pure pieces of the verify, file and pay modules.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  intakeDigest,
  isCalendarDate,
  missingRequired,
  normaliseFieldValue,
  validateForm,
  type IntakeField,
  type IntakeForm,
} from "../src/file/intake.ts";
import { MAX_LINK_AMOUNT_MINOR, settlementFor, validateAmount } from "../src/pay/payment.ts";
import { isKeypadEntry, judgeKeypadFactors, knowledgeDigest, subjectKeyFor } from "../src/verify/knowledge.ts";

const KEY = "0123456789abcdef-test";

describe("verify: keypad knowledge", () => {
  const subject = {
    subjectKey: subjectKeyFor(KEY, "12345678"),
    phoneOnFile: "+15555550100",
    knowledge: { dob: knowledgeDigest(KEY, "dob", "19850214"), zip: knowledgeDigest(KEY, "zip", "90210") },
  };

  it("derives stable keyed digests that differ per key, field and value", () => {
    assert.equal(subjectKeyFor(KEY, "1"), subjectKeyFor(KEY, "1"));
    assert.notEqual(subjectKeyFor(KEY, "1"), subjectKeyFor(`${KEY}x`, "1"));
    assert.notEqual(knowledgeDigest(KEY, "a", "1"), knowledgeDigest(KEY, "b", "1"));
    assert.match(subjectKeyFor(KEY, "1"), /^[0-9a-f]{64}$/);
  });

  it("knows what a keypad can produce", () => {
    assert.equal(isKeypadEntry("0123"), true);
    for (const v of ["", "12a", "1 2", "*1", "1".repeat(33)]) assert.equal(isKeypadEntry(v), false, v);
  });

  it("passes only when the subject exists and every field matches", () => {
    assert.equal(judgeKeypadFactors(KEY, subject, ["dob", "zip"], { dob: "19850214", zip: "90210" }), true);
    assert.equal(judgeKeypadFactors(KEY, subject, ["dob", "zip"], { dob: "19850214", zip: "90211" }), false);
    assert.equal(judgeKeypadFactors(KEY, subject, ["dob", "zip"], { dob: "19850214" }), false);
    assert.equal(judgeKeypadFactors(KEY, subject, ["dob", "pin"], { dob: "19850214", pin: "1" }), false);
    assert.equal(judgeKeypadFactors(KEY, null, ["dob"], { dob: "19850214" }), false);
  });

  it("never passes a non-keypad entry, even one whose digest is on file", () => {
    const odd = { ...subject, knowledge: { dob: knowledgeDigest(KEY, "dob", "") } };
    assert.equal(judgeKeypadFactors(KEY, odd, ["dob"], { dob: "abc" }), false);
    assert.equal(judgeKeypadFactors(KEY, odd, ["dob"], {}), false);
  });
});

const form: IntakeForm = {
  formId: "repair",
  version: "1",
  fields: [
    { key: "issue", label: { en: "Issue", fr: "Problème" }, type: "text", required: true, maxLength: 20 },
    { key: "units", label: { en: "Units", fr: "Unités" }, type: "number", required: false },
    { key: "since", label: { en: "Since", fr: "Depuis" }, type: "date", required: true },
    { key: "urgent", label: { en: "Urgent", fr: "Urgent" }, type: "yes_no", required: false },
  ],
};
const field = (key: string): IntakeField => form.fields.find((f) => f.key === key)!;

describe("file: intake forms", () => {
  it("accepts a well-formed form and lists every problem with a bad one", () => {
    assert.deepEqual(validateForm(form), []);
    const bad: IntakeForm = {
      formId: "x",
      version: "1",
      fields: [
        { key: "Bad Key", label: { en: "a", fr: "b" }, type: "text", required: false },
        { key: "a", label: { en: "a", fr: " " }, type: "text", required: false },
        { key: "a", label: { en: "", fr: "b" }, type: "text", required: false },
      ],
    };
    assert.deepEqual(validateForm(bad), [
      'field key "Bad Key" is not snake_case',
      "field a needs an English and a French label",
      "field a is defined twice",
      "field a needs an English and a French label",
    ]);
    assert.deepEqual(validateForm({ formId: "x", version: "1", fields: [] }), ["the form has no fields"]);
  });

  it("normalises each field type", () => {
    assert.deepEqual(normaliseFieldValue(field("issue"), "  leak "), { ok: true, value: "leak" });
    assert.deepEqual(normaliseFieldValue(field("issue"), "x".repeat(21)), { ok: false, reason: "too_long" });
    assert.deepEqual(normaliseFieldValue({ ...field("issue"), maxLength: undefined } as unknown as IntakeField, "x".repeat(500)).ok, true);
    assert.deepEqual(normaliseFieldValue({ key: "t", label: { en: "t", fr: "t" }, type: "text", required: false }, "x".repeat(501)), { ok: false, reason: "too_long" });
    assert.deepEqual(normaliseFieldValue(field("issue"), "4242424242424242"), { ok: false, reason: "card_number" });
    assert.deepEqual(normaliseFieldValue(field("issue"), "   "), { ok: false, reason: "empty" });
    assert.deepEqual(normaliseFieldValue(field("units"), "-2.5"), { ok: true, value: -2.5 });
    assert.deepEqual(normaliseFieldValue(field("units"), "two"), { ok: false, reason: "not_a_number" });
    assert.deepEqual(normaliseFieldValue(field("since"), "2026-09-01"), { ok: true, value: "2026-09-01" });
    assert.deepEqual(normaliseFieldValue(field("since"), "2026-02-30"), { ok: false, reason: "not_a_date" });
    assert.deepEqual(normaliseFieldValue(field("urgent"), "Oui"), { ok: true, value: true });
    assert.deepEqual(normaliseFieldValue(field("urgent"), "no"), { ok: true, value: false });
    assert.deepEqual(normaliseFieldValue(field("urgent"), "maybe"), { ok: false, reason: "not_yes_or_no" });
  });

  it("checks calendar dates", () => {
    assert.equal(isCalendarDate("2024-02-29"), true);
    assert.equal(isCalendarDate("2023-02-29"), false);
    assert.equal(isCalendarDate("2023-13-01"), false);
    assert.equal(isCalendarDate("2023-1-01"), false);
    assert.equal(isCalendarDate("0000-00-00"), false);
  });

  it("lists missing required fields and fingerprints values independent of key order", () => {
    assert.deepEqual(missingRequired(form, { issue: "leak" }), ["since"]);
    assert.deepEqual(missingRequired(form, { issue: "leak", since: "2026-09-01" }), []);
    const a = intakeDigest(form, { issue: "leak", since: "2026-09-01" });
    assert.equal(a, intakeDigest(form, { since: "2026-09-01", issue: "leak" }));
    assert.notEqual(a, intakeDigest({ ...form, version: "2" }, { issue: "leak", since: "2026-09-01" }));
  });
});

describe("pay: amounts and settlement", () => {
  it("validates amounts and currencies", () => {
    assert.deepEqual(validateAmount(15000, "cad"), []);
    assert.deepEqual(validateAmount(0, "CAD"), ["amountMinor must be a positive integer", "currency must be a lower-case ISO 4217 code"]);
    assert.deepEqual(validateAmount(1.5, "cad"), ["amountMinor must be a positive integer"]);
    assert.deepEqual(validateAmount(MAX_LINK_AMOUNT_MINOR + 1, "cad"), ["amountMinor is above the limit"]);
    assert.deepEqual(validateAmount(MAX_LINK_AMOUNT_MINOR, "cad", Number.MAX_SAFE_INTEGER), []);
    assert.deepEqual(validateAmount(101, "cad", 100), ["amountMinor is above the limit"]);
  });

  it("settles as paid only when the provider says paid", () => {
    assert.equal(settlementFor({ kind: "completed", linkId: "l", paymentStatus: "paid" }), "paid");
    assert.equal(settlementFor({ kind: "completed", linkId: "l", paymentStatus: "unpaid" }), null);
    assert.equal(settlementFor({ kind: "completed", linkId: "l", paymentStatus: "no_payment_required" }), "failed");
    assert.equal(settlementFor({ kind: "async_succeeded", linkId: "l" }), "paid");
    assert.equal(settlementFor({ kind: "async_failed", linkId: "l" }), "failed");
    assert.equal(settlementFor({ kind: "expired", linkId: "l" }), "expired");
  });
});
