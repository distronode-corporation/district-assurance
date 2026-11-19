// The read-back: what will be filed, built by code in English, French or Spanish, which the host
// speaks before the caller confirms. Its digest goes back to `confirmIntake`, which files the draft
// only while it still reads back the same, so a value changed after the caller heard it is never
// filed. A sensitive value is never read back: its line says only that it was given.
import { canonicalJson } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { sha256Hex } from "../core/hash.ts";
import { LOCALES, type Locale } from "../core/runtime.ts";
import { formSpeaks, intakeDigest, shownValues, type FieldValue, type IntakeField, type IntakeForm } from "./intake.ts";

export interface ReadBack {
  locale: Locale;
  /** One sentence per field that has a value, in form order. */
  lines: string[];
  /** The fixed confirm prompt. */
  prompt: string;
  /** What the host speaks: the opening, the lines and the prompt, one space apart. */
  text: string;
  /**
   * SHA-256 over the text and the record digest of the values, so a change to any value, a
   * sensitive one included, changes it. It tells no more about the values than the record digest
   * a receipt carries.
   */
  digest: string;
}

export interface ReadBackWording {
  opening: string;
  /** A label and its value, as one sentence. */
  line(label: string, value: string): string;
  /** A sensitive field's line. */
  withheld(label: string): string;
  prompt: string;
  yes: string;
  no: string;
  minus: string;
  group: string;
  decimal: string;
  date(weekday: string, day: number, month: string, year: number): string;
  weekdays: readonly string[];
  months: readonly string[];
}

/** What code says in each locale. A locale missing here does not build (and the parity test fails). */
export const READBACK_WORDING: Record<Locale, ReadBackWording> = {
  en: {
    opening: "Here is what will be filed.",
    line: (label, value) => `${label}: ${value}`,
    withheld: (label) => `${label}: given, and not read aloud for your security.`,
    prompt: "Is that correct? Say yes or press 1 to confirm.",
    yes: "yes",
    no: "no",
    minus: "minus ",
    group: ",",
    decimal: ".",
    date: (weekday, day, month, year) => `${weekday}, ${month} ${day}, ${year}`,
    weekdays: ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"],
    months: ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"],
  },
  fr: {
    opening: "Voici ce que nous allons enregistrer.",
    line: (label, value) => `${label} : ${value}`,
    withheld: (label) => `${label} : fourni, mais pas lu à voix haute, pour votre sécurité.`,
    prompt: "Est-ce exact? Dites oui ou appuyez sur le 1 pour confirmer.",
    yes: "oui",
    no: "non",
    minus: "moins ",
    // A non-breaking space, so a speech engine reads 1 234 as one number.
    group: " ",
    decimal: ",",
    date: (weekday, day, month, year) => `le ${weekday} ${day === 1 ? "1er" : day} ${month} ${year}`,
    weekdays: ["dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"],
    months: ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"],
  },
  // Spanish as spoken in the United States: 1,234.5 as in English, and the first of a month as
  // "primero", the way a speech engine should say it.
  es: {
    opening: "Esto es lo que vamos a registrar.",
    line: (label, value) => `${label}: ${value}`,
    // "se proporcionó" agrees with any label, where "proporcionado" would not.
    withheld: (label) => `${label}: se proporcionó, pero no se lee en voz alta por su seguridad.`,
    // The keypad only: Spanish spoken answers are refused until a reviewed vocabulary exists.
    prompt: "¿Es correcto? Oprima el 1 para confirmar.",
    yes: "sí",
    no: "no",
    minus: "menos ",
    group: ",",
    decimal: ".",
    date: (weekday, day, month, year) => `el ${weekday} ${day === 1 ? "primero" : day} de ${month} de ${year}`,
    weekdays: ["domingo", "lunes", "martes", "miércoles", "jueves", "viernes", "sábado"],
    months: ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"],
  },
};

/**
 * The read-back of a draft: every shown field with a value, in form order, then the fixed confirm
 * prompt. A field hidden by its `showIf` is neither read nor counted in the digest, as it is not filed.
 */
export function buildReadBack(form: IntakeForm, values: Readonly<Record<string, FieldValue>>, locale: Locale): ReadBack {
  if (!LOCALES.includes(locale)) throw new EngineError("invalid_input", "a read-back is in English (en), French (fr) or Spanish (es)");
  // Spanish labels are optional: a form without them is never read back, even in part, in Spanish.
  if (!formSpeaks(form, locale)) throw new EngineError("precondition_failed", `form ${form.formId} has no ${locale} label for every field`);
  const w = READBACK_WORDING[locale];
  const filed = shownValues(form, values);
  const lines: string[] = [];
  for (const field of form.fields) {
    if (!Object.hasOwn(filed, field.key)) continue;
    const label = field.label[locale]!.trim();
    lines.push(field.sensitive === true ? w.withheld(label) : sentence(w.line(label, spoken(field, filed[field.key]!, w))));
  }
  const text = [w.opening, ...lines, w.prompt].join(" ");
  const digest = sha256Hex(canonicalJson({ v: 1, locale, text, record: intakeDigest(form, filed) }));
  return { locale, lines, prompt: w.prompt, text, digest };
}

/** Ends a line with a full stop, unless the caller's own text already ends a sentence. */
function sentence(line: string): string {
  return /[.!?]$/.test(line) ? line : `${line}.`;
}

function spoken(field: IntakeField, value: FieldValue, w: ReadBackWording): string {
  switch (field.type) {
    case "number":
      return spokenNumber(value as number, w);
    case "date":
      return spokenDate(value as string, w);
    case "yes_no":
      return value === true ? w.yes : w.no;
    case "text":
      return String(value);
  }
}

/** Digits grouped by thousands in the locale's way, never in exponent form, with the sign as a word. */
function spokenNumber(value: number, w: ReadBackWording): string {
  const [whole, fraction] = plainDecimal(Math.abs(value)).split(".") as [string, string | undefined];
  const grouped = whole.replace(/\B(?=(\d{3})+$)/g, w.group);
  return `${value < 0 ? w.minus : ""}${grouped}${fraction === undefined ? "" : `${w.decimal}${fraction}`}`;
}

/**
 * A non-negative finite number's shortest round-trip digits written out in full, without
 * rounding: 1e-21 is 0.000000000000000000001, and 1e21 is 1 followed by 21 zeros.
 */
function plainDecimal(value: number): string {
  const [mantissa, exponent] = String(value).split("e") as [string, string | undefined];
  if (exponent === undefined) return mantissa;
  const [int, frac = ""] = mantissa.split(".") as [string, string | undefined];
  const digits = int + frac;
  const point = int.length + Number(exponent);
  return point <= 0 ? `0.${"0".repeat(-point)}${digits}` : digits.padEnd(point, "0");
}

/** A YYYY-MM-DD date in full: weekday, day, month and year. */
function spokenDate(value: string, w: ReadBackWording): string {
  const date = new Date(`${value}T00:00:00Z`);
  return w.date(w.weekdays[date.getUTCDay()]!, date.getUTCDate(), w.months[date.getUTCMonth()]!, date.getUTCFullYear());
}
