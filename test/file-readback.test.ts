// The read-back library (FIL-1, FIL-6): what the caller hears before confirming, snapshot per field
// type and locale, and the parity of every string code builds across locales.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { canonicalJson } from "../src/core/canonical.ts";
import { sha256Hex } from "../src/core/hash.ts";
import { LOCALES, type Locale } from "../src/core/runtime.ts";
import { formSpeaks, intakeDigest, normaliseFieldValue, type IntakeField, type IntakeForm } from "../src/file/intake.ts";
import { READBACK_WORDING, buildReadBack } from "../src/file/readback.ts";
import { AMOUNT_REGION, PAYMENT_TEXT, formatAmount } from "../src/pay/paylink.ts";
import { IDENTITY_TEXT } from "../src/verify/badge.ts";
import { rejects } from "./helpers.ts";

const field = (key: string, type: IntakeField["type"], en: string, fr: string, es: string, extra: Partial<IntakeField> = {}): IntakeField => ({
  key,
  label: { en, fr, es },
  type,
  required: false,
  ...extra,
});

const form: IntakeForm = {
  formId: "repair",
  version: "1",
  fields: [
    field("issue", "text", "Issue", "Problème", "Problema"),
    field("units", "number", "Units", "Unités", "Unidades"),
    field("since", "date", "Since", "Depuis", "Desde"),
    field("urgent", "yes_no", "Urgent", "Urgent", "Urgente"),
    field("account", "text", " Account reference ", " Référence du compte ", " Referencia de la cuenta ", { sensitive: true }),
  ],
};

/** Each field type alone, so a snapshot shows one line. */
const one = (key: string, value: string | number | boolean) => ({
  en: buildReadBack(form, { [key]: value }, "en").lines,
  fr: buildReadBack(form, { [key]: value }, "fr").lines,
  es: buildReadBack(form, { [key]: value }, "es").lines,
});

describe("file: read-back", () => {
  it("reads text as given, with one full stop", () => {
    assert.deepEqual(one("issue", "Leak under the sink"), {
      en: ["Issue: Leak under the sink."],
      fr: ["Problème : Leak under the sink."],
      es: ["Problema: Leak under the sink."],
    });
    assert.deepEqual(one("issue", "Is it the pipe?"), { en: ["Issue: Is it the pipe?"], fr: ["Problème : Is it the pipe?"], es: ["Problema: Is it the pipe?"] });
  });

  it("reads numbers grouped in the locale's way, the sign as a word, never in exponent form", () => {
    assert.deepEqual(one("units", 3), { en: ["Units: 3."], fr: ["Unités : 3."], es: ["Unidades: 3."] });
    // Spanish in the United States groups and marks decimals as English does.
    assert.deepEqual(one("units", 1234567.25), { en: ["Units: 1,234,567.25."], fr: ["Unités : 1 234 567,25."], es: ["Unidades: 1,234,567.25."] });
    assert.deepEqual(one("units", -2.5), { en: ["Units: minus 2.5."], fr: ["Unités : moins 2,5."], es: ["Unidades: menos 2.5."] });
    assert.deepEqual(one("units", 0.0000001), { en: ["Units: 0.0000001."], fr: ["Unités : 0,0000001."], es: ["Unidades: 0.0000001."] });
    assert.deepEqual(one("units", 1e21), {
      en: ["Units: 1,000,000,000,000,000,000,000."],
      fr: [`Unités : 1${" 000".repeat(7)}.`],
      es: ["Unidades: 1,000,000,000,000,000,000,000."],
    });
    assert.deepEqual(one("units", -0), { en: ["Units: 0."], fr: ["Unités : 0."], es: ["Unidades: 0."] });
    const tiny = `0.${"0".repeat(20)}1`;
    assert.deepEqual(one("units", 1e-21), { en: [`Units: ${tiny}.`], fr: [`Unités : ${tiny.replace(".", ",")}.`], es: [`Unidades: ${tiny}.`] });
    assert.deepEqual(one("units", -1e-21), { en: [`Units: minus ${tiny}.`], fr: [`Unités : moins ${tiny.replace(".", ",")}.`], es: [`Unidades: menos ${tiny}.`] });
    assert.deepEqual(one("units", 1.5e-7), { en: ["Units: 0.00000015."], fr: ["Unités : 0,00000015."], es: ["Unidades: 0.00000015."] });
    assert.deepEqual(one("units", 1.25e22), {
      en: ["Units: 12,500,000,000,000,000,000,000."],
      fr: [`Unités : 12 500${" 000".repeat(6)}.`],
      es: ["Unidades: 12,500,000,000,000,000,000,000."],
    });
  });

  it("reads dates in full, with the weekday", () => {
    assert.deepEqual(one("since", "2026-09-01"), {
      en: ["Since: Tuesday, September 1, 2026."],
      fr: ["Depuis : le mardi 1er septembre 2026."],
      es: ["Desde: el martes primero de septiembre de 2026."],
    });
    assert.deepEqual(one("since", "2024-02-29"), {
      en: ["Since: Thursday, February 29, 2024."],
      fr: ["Depuis : le jeudi 29 février 2024."],
      es: ["Desde: el jueves 29 de febrero de 2024."],
    });
    assert.deepEqual(one("since", "2025-08-17"), {
      en: ["Since: Sunday, August 17, 2025."],
      fr: ["Depuis : le dimanche 17 août 2025."],
      es: ["Desde: el domingo 17 de agosto de 2025."],
    });
    assert.deepEqual(one("since", "2026-11-18").es, ["Desde: el miércoles 18 de noviembre de 2026."]);
    assert.deepEqual(one("since", "2026-11-21").es, ["Desde: el sábado 21 de noviembre de 2026."]);
  });

  it("reads yes and no", () => {
    assert.deepEqual(one("urgent", true), { en: ["Urgent: yes."], fr: ["Urgent : oui."], es: ["Urgente: sí."] });
    assert.deepEqual(one("urgent", false), { en: ["Urgent: no."], fr: ["Urgent : non."], es: ["Urgente: no."] });
  });

  it("never reads a sensitive value back, only that it was given", () => {
    const secret = "AB-99231";
    assert.deepEqual(one("account", secret), {
      en: ["Account reference: given, and not read aloud for your security."],
      fr: ["Référence du compte : fourni, mais pas lu à voix haute, pour votre sécurité."],
      es: ["Referencia de la cuenta: se proporcionó, pero no se lee en voz alta por su seguridad."],
    });
    for (const locale of LOCALES) assert.ok(!JSON.stringify(buildReadBack(form, { account: secret }, locale)).includes(secret), locale);
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
    const es = buildReadBack(form, values, "es");
    assert.equal(
      es.text,
      "Esto es lo que vamos a registrar. Problema: Leak. Desde: el martes primero de septiembre de 2026. Urgente: sí. ¿Es correcto? Oprima el 1 para confirmar.",
    );
    assert.equal(es.prompt, "¿Es correcto? Oprima el 1 para confirmar.");
    assert.equal(es.locale, "es");
    assert.deepEqual(buildReadBack(form, {}, "en").lines, []);
  });

  it("digests the text with the record digest, so any change shows, a sensitive one included", () => {
    const values = { issue: "Leak", account: "AB-1" };
    const rb = buildReadBack(form, values, "en");
    assert.equal(rb.digest, sha256Hex(canonicalJson({ v: 1, locale: "en", text: rb.text, record: intakeDigest(form, values) })));
    assert.equal(rb.digest, buildReadBack(form, { account: "AB-1", issue: "Leak" }, "en").digest, "independent of key order");
    assert.notEqual(rb.digest, buildReadBack(form, { ...values, account: "AB-2" }, "en").digest, "the text is the same, the digest is not");
    assert.notEqual(rb.digest, buildReadBack(form, values, "fr").digest);
    assert.notEqual(rb.digest, buildReadBack(form, values, "es").digest);
    assert.notEqual(rb.digest, buildReadBack({ ...form, version: "2" }, values, "en").digest);
  });

  it("refuses a locale it cannot speak", () => {
    assert.throws(() => buildReadBack(form, {}, "de" as "en"), rejects("invalid_input", /English \(en\), French \(fr\) or Spanish \(es\)/));
  });

  it("refuses Spanish for a form with any field that has no Spanish label, and keeps English and French", () => {
    const partly: IntakeForm = {
      ...form,
      fields: [form.fields[0]!, { key: "note", label: { en: "Note", fr: "Note" }, type: "text", required: false }],
    };
    assert.equal(formSpeaks(form, "es"), true);
    assert.equal(formSpeaks(partly, "es"), false);
    assert.equal(formSpeaks(partly, "en") && formSpeaks(partly, "fr"), true);
    // Refused even when the field without a label has no value: the caller would be asked for it.
    assert.throws(() => buildReadBack(partly, { issue: "Leak" }, "es"), rejects("precondition_failed", /form repair has no es label for every field/));
    assert.equal(buildReadBack(partly, { issue: "Leak", note: "Back door" }, "fr").lines.length, 2);
  });
});

describe("locales: parity of every string code builds", () => {
  const SAMPLE_URL = "https://example.test/x";

  it("has every table in every locale, and nothing else", () => {
    const tables: Record<string, Record<string, unknown>> = { READBACK_WORDING, IDENTITY_TEXT, PAYMENT_TEXT, AMOUNT_REGION };
    for (const [name, table] of Object.entries(tables)) assert.deepEqual(Object.keys(table).sort(), [...LOCALES].sort(), name);
  });

  it("has every read-back string in every locale, non-empty, with as many weekdays and months", () => {
    const keys = Object.keys(READBACK_WORDING.en).sort();
    for (const locale of LOCALES) {
      const w = READBACK_WORDING[locale];
      assert.deepEqual(Object.keys(w).sort(), keys, locale);
      for (const key of keys) {
        const value: unknown = w[key as keyof typeof w];
        if (typeof value === "string") assert.ok(value.length > 0, `${locale}.${key}`);
        else if (Array.isArray(value)) {
          assert.equal(value.length, (READBACK_WORDING.en[key as keyof typeof w] as readonly string[]).length, `${locale}.${key}`);
          for (const item of value) assert.ok(typeof item === "string" && item.trim() !== "", `${locale}.${key}`);
        } else assert.equal(typeof value, "function", `${locale}.${key}`);
      }
      assert.ok(w.line("LABEL", "VALUE").includes("LABEL") && w.line("LABEL", "VALUE").includes("VALUE"), locale);
      assert.ok(w.withheld("LABEL").includes("LABEL"), locale);
      for (const day of [1, 2, 31]) assert.match(w.date("WEEKDAY", day, "MONTH", 2026), /WEEKDAY.*MONTH.*2026/, `${locale} ${day}`);
    }
  });

  it("translates every sentence: no locale reuses another's opening, prompt, withheld line or text", () => {
    const sentences = (locale: Locale) => [
      READBACK_WORDING[locale].opening,
      READBACK_WORDING[locale].prompt,
      READBACK_WORDING[locale].withheld("L"),
      READBACK_WORDING[locale].date("W", 1, "M", 2026),
      IDENTITY_TEXT[locale](SAMPLE_URL),
      PAYMENT_TEXT[locale]("AMOUNT", SAMPLE_URL),
    ];
    for (const a of LOCALES) {
      for (const b of LOCALES) {
        if (a === b) continue;
        sentences(a).forEach((s, i) => assert.notEqual(s, sentences(b)[i], `${a} and ${b}, sentence ${i}`));
      }
    }
  });

  it("puts the link, and the amount, in every text", () => {
    for (const locale of LOCALES) {
      assert.ok(IDENTITY_TEXT[locale](SAMPLE_URL).endsWith(SAMPLE_URL), locale);
      const text = PAYMENT_TEXT[locale](formatAmount(locale, 15000, "usd"), SAMPLE_URL);
      assert.ok(text.includes(formatAmount(locale, 15000, "usd")) && text.endsWith(SAMPLE_URL), locale);
    }
  });

  it("reads yes and no with words intake accepts back, and the prompt asks for its own yes; Spanish asks for the keypad", () => {
    const yesNo: IntakeField = { key: "ok", label: { en: "OK", fr: "OK", es: "OK" }, type: "yes_no", required: false };
    for (const locale of LOCALES) {
      const w = READBACK_WORDING[locale];
      if (locale === "es") {
        // Spanish spoken answers are refused until a reviewed vocabulary exists: no spoken yes is asked for or taken.
        assert.deepEqual(normaliseFieldValue(yesNo, w.yes), { ok: false, reason: "not_yes_or_no" });
        assert.equal(w.prompt.includes(w.yes), false);
        assert.match(w.prompt, /Oprima el 1/);
        continue;
      }
      assert.deepEqual(normaliseFieldValue(yesNo, w.yes), { ok: true, value: true }, locale);
      assert.deepEqual(normaliseFieldValue(yesNo, w.no), { ok: true, value: false }, locale);
      assert.ok(w.prompt.includes(` ${w.yes} `), locale);
    }
  });

  it("formats amounts the way each locale says them", () => {
    assert.equal(formatAmount("es", 150050, "usd"), "$1,500.50");
    assert.equal(formatAmount("en", 150050, "usd"), "US$1,500.50");
    assert.match(formatAmount("es", 150, "jpy"), /^¥150$/u);
  });
});
