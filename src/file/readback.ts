// The read-back: what will be filed, built by code in English or French, which the host speaks
// before the caller confirms. Its digest goes back to `confirmIntake`, which files the draft only
// while it still reads back the same, so a value changed after the caller heard it is never filed.
// A sensitive value is never read back: its line says only that it was given.
import { canonicalJson } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { sha256Hex } from "../core/hash.ts";
import type { Locale } from "../core/runtime.ts";
import { intakeDigest, shownValues, type FieldValue, type IntakeField, type IntakeForm } from "./intake.ts";

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

interface Wording {
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

const WORDING: Record<Locale, Wording> = {
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
};

/**
 * The read-back of a draft: every shown field with a value, in form order, then the fixed confirm
 * prompt. A field hidden by its `showIf` is neither read nor counted in the digest, as it is not filed.
 */
export function buildReadBack(form: IntakeForm, values: Readonly<Record<string, FieldValue>>, locale: Locale): ReadBack {
  if (locale !== "en" && locale !== "fr") throw new EngineError("invalid_input", "a read-back is in English (en) or French (fr)");
  const w = WORDING[locale];
  const filed = shownValues(form, values);
  const lines: string[] = [];
  for (const field of form.fields) {
    if (!Object.hasOwn(filed, field.key)) continue;
    const label = field.label[locale].trim();
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

function spoken(field: IntakeField, value: FieldValue, w: Wording): string {
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
function spokenNumber(value: number, w: Wording): string {
  const plain = Math.abs(value).toLocaleString("en-US", { useGrouping: false, maximumFractionDigits: 20 });
  const [whole, fraction] = plain.split(".") as [string, string | undefined];
  const grouped = whole.replace(/\B(?=(\d{3})+$)/g, w.group);
  return `${value < 0 ? w.minus : ""}${grouped}${fraction === undefined ? "" : `${w.decimal}${fraction}`}`;
}

/** A YYYY-MM-DD date in full: weekday, day, month and year. */
function spokenDate(value: string, w: Wording): string {
  const date = new Date(`${value}T00:00:00Z`);
  return w.date(w.weekdays[date.getUTCDay()]!, date.getUTCDate(), w.months[date.getUTCMonth()]!, date.getUTCFullYear());
}
