// The read-back library (FIL-1): what the caller hears before confirming, snapshot per field type and locale.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { canonicalJson } from "../src/core/canonical.ts";
import { sha256Hex } from "../src/core/hash.ts";
import { intakeDigest, type IntakeField, type IntakeForm } from "../src/file/intake.ts";
import { buildReadBack } from "../src/file/readback.ts";
import { rejects } from "./helpers.ts";

const field = (key: string, type: IntakeField["type"], en: string, fr: string, extra: Partial<IntakeField> = {}): IntakeField => ({
  key,
  label: { en, fr },
  type,
  required: false,
  ...extra,
});

const form: IntakeForm = {
  formId: "repair",
  version: "1",
  fields: [
    field("issue", "text", "Issue", "Problème"),
    field("units", "number", "Units", "Unités"),
    field("since", "date", "Since", "Depuis"),
    field("urgent", "yes_no", "Urgent", "Urgent"),
    field("account", "text", " Account reference ", " Référence du compte ", { sensitive: true }),
  ],
};

/** Each field type alone, so a snapshot shows one line. */
const one = (key: string, value: string | number | boolean) => ({
  en: buildReadBack(form, { [key]: value }, "en").lines,
  fr: buildReadBack(form, { [key]: value }, "fr").lines,
});

describe("file: read-back", () => {
  it("reads text as given, with one full stop", () => {
    assert.deepEqual(one("issue", "Leak under the sink"), { en: ["Issue: Leak under the sink."], fr: ["Problème : Leak under the sink."] });
    assert.deepEqual(one("issue", "Is it the pipe?"), { en: ["Issue: Is it the pipe?"], fr: ["Problème : Is it the pipe?"] });
  });

  it("reads numbers grouped in the locale's way, the sign as a word, never in exponent form", () => {
    assert.deepEqual(one("units", 3), { en: ["Units: 3."], fr: ["Unités : 3."] });
    assert.deepEqual(one("units", 1234567.25), { en: ["Units: 1,234,567.25."], fr: ["Unités : 1 234 567,25."] });
    assert.deepEqual(one("units", -2.5), { en: ["Units: minus 2.5."], fr: ["Unités : moins 2,5."] });
    assert.deepEqual(one("units", 0.0000001), { en: ["Units: 0.0000001."], fr: ["Unités : 0,0000001."] });
    assert.deepEqual(one("units", 1e21), { en: ["Units: 1,000,000,000,000,000,000,000."], fr: [`Unités : 1${" 000".repeat(7)}.`] });
    assert.deepEqual(one("units", -0), { en: ["Units: 0."], fr: ["Unités : 0."] });
    const tiny = `0.${"0".repeat(20)}1`;
    assert.deepEqual(one("units", 1e-21), { en: [`Units: ${tiny}.`], fr: [`Unités : ${tiny.replace(".", ",")}.`] });
    assert.deepEqual(one("units", -1e-21), { en: [`Units: minus ${tiny}.`], fr: [`Unités : moins ${tiny.replace(".", ",")}.`] });
    assert.deepEqual(one("units", 1.5e-7), { en: ["Units: 0.00000015."], fr: ["Unités : 0,00000015."] });
    assert.deepEqual(one("units", 1.25e22), { en: ["Units: 12,500,000,000,000,000,000,000."], fr: [`Unités : 12 500${" 000".repeat(6)}.`] });
  });

  it("reads dates in full, with the weekday", () => {
    assert.deepEqual(one("since", "2026-09-01"), { en: ["Since: Tuesday, September 1, 2026."], fr: ["Depuis : le mardi 1er septembre 2026."] });
    assert.deepEqual(one("since", "2024-02-29"), { en: ["Since: Thursday, February 29, 2024."], fr: ["Depuis : le jeudi 29 février 2024."] });
    assert.deepEqual(one("since", "2025-08-17"), { en: ["Since: Sunday, August 17, 2025."], fr: ["Depuis : le dimanche 17 août 2025."] });
  });

  it("reads yes and no", () => {
    assert.deepEqual(one("urgent", true), { en: ["Urgent: yes."], fr: ["Urgent : oui."] });
    assert.deepEqual(one("urgent", false), { en: ["Urgent: no."], fr: ["Urgent : non."] });
  });

  it("never reads a sensitive value back, only that it was given", () => {
    const secret = "AB-99231";
    assert.deepEqual(one("account", secret), {
      en: ["Account reference: given, and not read aloud for your security."],
      fr: ["Référence du compte : fourni, mais pas lu à voix haute, pour votre sécurité."],
    });
    for (const locale of ["en", "fr"] as const) assert.ok(!JSON.stringify(buildReadBack(form, { account: secret }, locale)).includes(secret));
  });

  it("builds the whole line in form order, skips fields without a value, and ends with the fixed prompt", () => {
    const values = { urgent: true, issue: "Leak", since: "2026-09-01" };
    const en = buildReadBack(form, values, "en");
    assert.equal(en.text, "Here is what will be filed. Issue: Leak. Since: Tuesday, September 1, 2026. Urgent: yes. Is that correct? Say yes or press 1 to confirm.");
    assert.equal(en.prompt, "Is that correct? Say yes or press 1 to confirm.");
    assert.equal(en.locale, "en");
    const fr = buildReadBack(form, values, "fr");
    assert.equal(
      fr.text,
      "Voici ce que nous allons enregistrer. Problème : Leak. Depuis : le mardi 1er septembre 2026. Urgent : oui. Est-ce exact? Dites oui ou appuyez sur le 1 pour confirmer.",
    );
    assert.equal(fr.prompt, "Est-ce exact? Dites oui ou appuyez sur le 1 pour confirmer.");
    assert.deepEqual(buildReadBack(form, {}, "en").lines, []);
  });

  it("digests the text with the record digest, so any change shows, a sensitive one included", () => {
    const values = { issue: "Leak", account: "AB-1" };
    const rb = buildReadBack(form, values, "en");
    assert.equal(rb.digest, sha256Hex(canonicalJson({ v: 1, locale: "en", text: rb.text, record: intakeDigest(form, values) })));
    assert.equal(rb.digest, buildReadBack(form, { account: "AB-1", issue: "Leak" }, "en").digest, "independent of key order");
    assert.notEqual(rb.digest, buildReadBack(form, { ...values, account: "AB-2" }, "en").digest, "the text is the same, the digest is not");
    assert.notEqual(rb.digest, buildReadBack(form, values, "fr").digest);
    assert.notEqual(rb.digest, buildReadBack({ ...form, version: "2" }, values, "en").digest);
  });

  it("refuses a locale it cannot speak", () => {
    assert.throws(() => buildReadBack(form, {}, "de" as "en"), rejects("invalid_input", /English \(en\) or French \(fr\)/));
  });
});
