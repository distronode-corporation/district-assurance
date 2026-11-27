// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The pure pieces of the verify, file and pay modules.
import { strict as assert } from "node:assert";
import { createHmac } from "node:crypto";
import { describe, it } from "node:test";

import { EngineError } from "../src/core/errors.ts";
import {
  intakeDigest,
  isCalendarDate,
  isShown,
  missingRequired,
  normaliseFieldValue,
  shownValues,
  validateForm as validateFormProblems,
  type IntakeField,
  type IntakeForm } from "../src/file/intake.ts";
import { problemMessage } from "../src/core/module.ts";
import { MAX_LINK_AMOUNT_MINOR, settlementFor, validateAmount as validateAmountProblems } from "../src/pay/payment.ts";

/** The sentences of the shared intake and payment validators, as the tests read them. */
const validateForm = (form: IntakeForm): string[] => validateFormProblems(form).map(problemMessage);
const validateAmount = (amountMinor: number, currency: string, maxMinor?: number): string[] => validateAmountProblems(amountMinor, currency, maxMinor).map(problemMessage);
import { isKeypadEntry, judgeKeypadFactors, knowledgeDigest, knowledgeHmac, pinDigest, subjectKeyFor } from "../src/verify/knowledge.ts";
import { pinOnFile } from "./helpers.ts";

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

  it("takes the key as an asynchronous HMAC function, with the same digests as the bytes", async () => {
    const kms = async (data: string): Promise<string> => createHmac("sha256", KEY).update(data).digest("hex");
    assert.equal(await subjectKeyFor(kms, "12345678"), subject.subjectKey);
    assert.equal(await knowledgeDigest(kms, "dob", "19850214"), subject.knowledge.dob);
    // A PIN record is salted afresh each time: both forms give records of the same PIN.
    for (const stored of [await pinDigest(kms, subject.subjectKey, "4826"), pinDigest(KEY, subject.subjectKey, "4826")]) assert.ok(await pinOnFile(stored, subject.subjectKey, "4826", "pin", KEY));
    assert.equal(await judgeKeypadFactors(kms, subject, ["dob", "zip"], { dob: "19850214", zip: "90210" }), true);
    assert.equal(await judgeKeypadFactors(kms, subject, ["dob", "zip"], { dob: "19850214", zip: "90211" }), false);
    assert.equal(await judgeKeypadFactors(kms, subject, ["dob"], { dob: "abc" }), false);
    assert.equal(await knowledgeHmac(kms)("x"), await knowledgeHmac(KEY)("x"));
    await assert.rejects(subjectKeyFor(async () => "not hex", "1"), (e: unknown) => e instanceof EngineError && e.code === "invalid_input");
    await assert.rejects(judgeKeypadFactors(async () => Promise.reject(new Error("down")), subject, ["dob"], { dob: "19850214" }), /down/);
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
    assert.deepEqual(normaliseFieldValue(field("issue"), "leak \ud800"), { ok: false, reason: "not_text" });
    assert.deepEqual(normaliseFieldValue(field("units"), "-2.5"), { ok: true, value: -2.5 });
    assert.deepEqual(normaliseFieldValue(field("units"), "two"), { ok: false, reason: "not_a_number" });
    assert.deepEqual(normaliseFieldValue(field("since"), "2026-09-01"), { ok: true, value: "2026-09-01" });
    assert.deepEqual(normaliseFieldValue(field("since"), "2026-02-30"), { ok: false, reason: "not_a_date" });
    assert.deepEqual(normaliseFieldValue(field("urgent"), "Oui"), { ok: true, value: true });
    assert.deepEqual(normaliseFieldValue(field("urgent"), "no"), { ok: true, value: false });
    assert.deepEqual(normaliseFieldValue(field("urgent"), "maybe"), { ok: false, reason: "not_yes_or_no" });
  });

  it("refuses sí and si (no reviewed Spanish vocabulary yet), and takes no, any case", () => {
    for (const yes of ["sí", "si", "Sí", "SÍ", "SI", " si ", "sí"]) assert.deepEqual(normaliseFieldValue(field("urgent"), yes), { ok: false, reason: "not_yes_or_no" }, JSON.stringify(yes));
    for (const no of ["no", "No", "NO"]) assert.deepEqual(normaliseFieldValue(field("urgent"), no), { ok: true, value: false }, no);
    for (const other of ["sí sí", "sip", "s", "nó", "tal vez"]) assert.deepEqual(normaliseFieldValue(field("urgent"), other), { ok: false, reason: "not_yes_or_no" }, other);
  });

  it("takes an optional Spanish label, and refuses an empty one or a label in another language", () => {
    const labelled = (label: unknown) =>
      validateForm({ formId: "x", version: "1", fields: [{ key: "issue", label, type: "text", required: false } as unknown as IntakeField] });
    assert.deepEqual(labelled({ en: "Issue", fr: "Problème" }), []);
    assert.deepEqual(labelled({ en: "Issue", fr: "Problème", es: "Problema" }), []);
    assert.deepEqual(labelled({ en: "Issue", fr: "Problème", es: " " }), ["field issue: the Spanish label (es), when given, must not be empty"]);
    assert.deepEqual(labelled({ en: "Issue", fr: "Problème", es: 1 }), ["field issue: the Spanish label (es), when given, must not be empty"]);
    assert.deepEqual(labelled({ en: "Issue", fr: "Problème", de: "Problem" }), ["field issue: label de is not a locale (en, fr or es)"]);
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

describe("file: field rules and conditional fields", () => {
  it("refuses a card, a PAN, a SIN or an SSN named in one word or as a camelCase, snake or kebab part, and keeps words that only contain the letters", () => {
    const named = (key: string, en: string, fr = "Référence") => validateForm({ formId: "f", version: "1", fields: [{ key, label: { en, fr }, type: "text", required: false }] }).length;
    for (const [key, en, fr] of [
      ["creditcard", "Number"],
      ["cardno", "Number"],
      ["card_num", "Number"],
      ["debitcards", "Number"],
      ["sinnumber", "Number"],
      ["nas_no", "Number"],
      ["ref", "Creditcard number"],
      ["ref", "Cardholder name"],
      ["ref", "Reference", "Numérocarte"],
      ["pan", "Number"],
      ["ssn", "Number"],
      ["cc_number", "Number"],
      ["ref", "Your P.A.N."],
      ["ref", "panNumber"],
      ["ref", "ssnValue"],
      ["ref", "card-holder-name"],
      ["ref", "SSNumber"],
      ["pannumber", "Number"],
      ["ccno", "Number"],
      ["ref", "Social Security"],
      ["ref", "Reference", "Votre NAS"],
    ] as const) {
      assert.equal(named(key, en, fr), 1, `${key} / ${en} / ${fr ?? ""}`);
    }
    for (const [key, en] of [["cardiology", "Department"], ["discard_reason", "Why it was discarded"], ["ref", "Cartel"], ["business", "Business name"], ["casino", "Using"], ["account", "Account"], ["accept_terms", "Accept"], ["pancake", "Pancakes"], ["company", "Company name"], ["panel", "Panel"], ["nasal", "Nasal spray"], ["ref", "companyName"], ["ref", "accountNumber"], ["occupation", "Occupation"], ["ssd_size", "Disk"]] as const) {
      assert.equal(named(key, en), 0, `${key} / ${en}`);
    }
  });

  const f = (key: string, type: IntakeField["type"], extra: Partial<IntakeField> = {}): IntakeField => ({ key, label: { en: key, fr: key }, type, required: false, ...extra });

  it("holds numbers and dates to min and max, inclusive", () => {
    const units = f("units", "number", { min: -1, max: 10.5 });
    assert.deepEqual(normaliseFieldValue(units, "-1"), { ok: true, value: -1 });
    assert.deepEqual(normaliseFieldValue(units, "10.5"), { ok: true, value: 10.5 });
    assert.deepEqual(normaliseFieldValue(units, "-1.5"), { ok: false, reason: "below_min" });
    assert.deepEqual(normaliseFieldValue(units, "11"), { ok: false, reason: "above_max" });
    assert.deepEqual(normaliseFieldValue(f("floor", "number", { min: 0 }), "99999"), { ok: true, value: 99999 });
    const since = f("since", "date", { min: "2026-01-01", max: "2026-12-31" });
    assert.deepEqual(normaliseFieldValue(since, "2026-01-01"), { ok: true, value: "2026-01-01" });
    assert.deepEqual(normaliseFieldValue(since, "2025-12-31"), { ok: false, reason: "below_min" });
    assert.deepEqual(normaliseFieldValue(since, "2027-01-01"), { ok: false, reason: "above_max" });
    assert.deepEqual(normaliseFieldValue(f("until", "date", { max: "2026-12-31" }), "2020-02-29"), { ok: true, value: "2020-02-29" });
  });

  it("matches a text pattern against the whole value, in Unicode mode", () => {
    const postal = f("postal", "text", { pattern: "[A-Z]\\d[A-Z] ?\\d[A-Z]\\d" });
    assert.deepEqual(normaliseFieldValue(postal, " H2X 1Y4 "), { ok: true, value: "H2X 1Y4" });
    assert.deepEqual(normaliseFieldValue(postal, "H2X 1Y4 extra"), { ok: false, reason: "no_match" });
    assert.deepEqual(normaliseFieldValue(f("either", "text", { pattern: "oui|non" }), "ouinon"), { ok: false, reason: "no_match" }, "anchored around alternatives");
    assert.deepEqual(normaliseFieldValue(f("name", "text", { pattern: "\\p{L}+" }), "Éloïse"), { ok: true, value: "Éloïse" });
    assert.deepEqual(validateForm({ formId: "x", version: "1", fields: [f("a", "text", { pattern: "[(]+(?:ab)?(?=c)[\\]]c{2}" })] }), [], "brackets in a class and lookarounds are fine");
  });

  it("refuses fields that name a card or a Social Insurance Number, in either language, and nothing else", () => {
    const named = (key: string, en: string, fr: string) => validateForm({ formId: "x", version: "1", fields: [{ key, label: { en, fr }, type: "text", required: false }] }).length;
    for (const [key, en, fr] of [
      ["sin", "Number", "Numéro"],
      ["nas", "Number", "Numéro"],
      ["cvv", "Code", "Code"],
      ["ref", "Card number", "Numéro"],
      ["ref", "Number", "Numéro de carte de crédit"],
      ["ref", "Social Insurance Number", "Numéro"],
      ["ref", "Number", "NUMÉRO D’ASSURANCE-SOCIALE"],
      ["ref", "Cardholder name", "Nom"],
    ]) assert.equal(named(key!, en!, fr!), 1, `${key} / ${en} / ${fr}`);
    for (const [key, en, fr] of [
      ["since", "Since", "Depuis"],
      ["business_name", "Business name", "Nom de l'entreprise"],
      ["discard", "Discarded items", "Articles jetés"],
      ["insurance", "Insurance provider", "Assureur"],
    ]) assert.equal(named(key!, en!, fr!), 0, `${key} / ${en} / ${fr}`);
  });

  it("refuses a Spanish label that names a card or a social security number, and nothing else", () => {
    const named = (es: string) => validateForm({ formId: "x", version: "1", fields: [{ key: "ref", label: { en: "Number", fr: "Numéro", es }, type: "text", required: false }] });
    for (const es of ["Número de tarjeta", "TARJETAS", "Número de Seguro Social", "Código CVV"]) {
      assert.deepEqual(named(es), ["field ref names a card or a Social Insurance Number, which intake never collects"], es);
    }
    for (const es of ["Número de cuenta", "Seguro de la casa", "Tarjetero roto", "Fecha"]) assert.deepEqual(named(es), [], es);
  });

  const branching: IntakeForm = {
    formId: "repair",
    version: "1",
    fields: [
      f("issue", "text", { required: true }),
      f("urgent", "yes_no", { required: true }),
      f("since", "date", { required: true, showIf: { field: "urgent", equals: true } }),
      f("access", "yes_no", { showIf: { field: "urgent", equals: true } }),
      f("code", "number", { required: true, showIf: { field: "access", equals: true } }),
    ],
  };
  const shown = (values: Record<string, string | number | boolean>) => branching.fields.filter((x) => isShown(branching, values, x)).map((x) => x.key);

  it("shows a field only while the field it names holds its value and is shown itself", () => {
    assert.deepEqual(validateForm(branching), []);
    assert.deepEqual(shown({}), ["issue", "urgent"]);
    assert.deepEqual(shown({ urgent: false, access: true }), ["issue", "urgent"], "a chain through a hidden field stays hidden");
    assert.deepEqual(shown({ urgent: true }), ["issue", "urgent", "since", "access"]);
    assert.deepEqual(shown({ urgent: true, access: true }), ["issue", "urgent", "since", "access", "code"]);
  });

  it("files and requires only shown fields", () => {
    assert.deepEqual(missingRequired(branching, { urgent: false }), ["issue"]);
    assert.deepEqual(missingRequired(branching, { urgent: true, access: true }), ["issue", "since", "code"]);
    const values = { code: 42, issue: "leak", urgent: false, since: "2026-09-01", stray: "x" };
    assert.deepEqual(shownValues(branching, values), { issue: "leak", urgent: false });
    assert.deepEqual(Object.keys(shownValues(branching, { ...values, urgent: true, access: true })), ["issue", "urgent", "since", "access", "code"], "in form order");
  });

  it("hides a field whose chain comes back on itself, and follows a chain off the form as far as it goes", () => {
    const cyclic: IntakeForm = { formId: "x", version: "1", fields: [f("a", "yes_no", { showIf: { field: "b", equals: true } }), f("b", "yes_no", { showIf: { field: "a", equals: true } })] };
    assert.equal(isShown(cyclic, { a: true, b: true }, cyclic.fields[0]!), false);
    const dangling = f("c", "text", { showIf: { field: "ghost", equals: true } });
    assert.equal(isShown({ formId: "x", version: "1", fields: [dangling] }, { ghost: true }, dangling), true);
    assert.equal(isShown({ formId: "x", version: "1", fields: [dangling] }, {}, dangling), false);
  });

  it("refuses a showIf value its target's rules would refuse, and keeps the endpoints", () => {
    const on = (target: IntakeField, equals: string | number | boolean) =>
      validateForm({ formId: "x", version: "1", fields: [target, f("dep", "text", { showIf: { field: target.key, equals } })] }).map(problemMessage).filter((e) => e.startsWith("field dep"));
    const refused = (key: string) => [`field dep: showIf.equals is not a value field ${key} can take`];
    const count = f("count", "number", { min: 1, max: 10 });
    assert.deepEqual(on(count, 10), []);
    assert.deepEqual(on(count, 1), []);
    assert.deepEqual(on(count, 11), refused("count"));
    assert.deepEqual(on(count, 0), refused("count"));
    const when = f("when", "date", { min: "2026-01-01", max: "2026-12-31" });
    assert.deepEqual(on(when, "2026-12-31"), []);
    assert.deepEqual(on(when, "2027-01-01"), refused("when"));
    const code = f("code", "text", { maxLength: 3, pattern: "[A-Z]+" });
    assert.deepEqual(on(code, "ABC"), []);
    assert.deepEqual(on(code, "ABCD"), refused("code"));
    assert.deepEqual(on(code, "abc"), refused("code"));
    assert.deepEqual(on(f("note", "text"), "4242424242424242"), refused("note"));
    // Rules the form gets wrong are reported on the target and not applied to the value.
    assert.deepEqual(on(f("bad_pattern", "text", { pattern: "(" }), "x"), []);
    assert.deepEqual(on(f("bad_range", "number", { min: 5, max: 4 }), 7), []);
  });

  it("refuses a number too large to hold", () => {
    assert.deepEqual(normaliseFieldValue(f("units", "number"), "9".repeat(309)), { ok: false, reason: "not_a_number" });
    assert.deepEqual(normaliseFieldValue(f("units", "number"), `-${"9".repeat(309)}`), { ok: false, reason: "not_a_number" });
    assert.deepEqual(normaliseFieldValue(f("units", "number"), "9".repeat(300)).ok, true);
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
