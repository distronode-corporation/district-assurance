// Intake forms: the fields a business defines, and the values a caller gives during the call. A
// value is normalised by code before it reaches the draft, and a text or number value that carries a
// card number is refused, so intake can never become a way to store one. A form cannot ask for a
// card or a Social Insurance Number at all, and a field can be asked only when another field's
// value says so (`showIf`).
import { canonicalJson } from "../core/canonical.ts";
import { sha256Hex } from "../core/hash.ts";
import { findCardNumbers } from "../core/redaction.ts";
import { LOCALES, type Locale, type LocalisedText } from "../core/runtime.ts";
import { problem, type StructuredProblem } from "../core/module.ts";
import { isObject, unknownKeys } from "../core/shape.ts";

export type FieldType = "text" | "number" | "date" | "yes_no";

export interface IntakeField {
  key: string;
  /** English and French always; Spanish when the workspace offers it. */
  label: LocalisedText;
  type: FieldType;
  /** Required while the field is shown. */
  required: boolean;
  /** Stored encrypted by the host's `FieldCipher`; a form with one needs that adapter. */
  sensitive?: boolean;
  /** Text fields only. Default 500. */
  maxLength?: number;
  /**
   * The field is asked, read back and filed only while another field's value equals `equals`,
   * and that field is shown itself. Otherwise its value, if any, stays out of the record.
   */
  showIf?: { field: string; equals: FieldValue };
  /** The smallest value allowed: a number for number fields, a YYYY-MM-DD date for date fields. */
  min?: number | string;
  /** The largest value allowed, as `min`. */
  max?: number | string;
  /** Text fields only: a regular expression (Unicode mode) the whole value must match. */
  pattern?: string;
}

export interface IntakeForm {
  formId: string;
  version: string;
  fields: IntakeField[];
}

export type FieldValue = string | number | boolean;

export type NormaliseResult =
  | { ok: true; value: FieldValue }
  | {
      ok: false;
      reason: "empty" | "too_long" | "not_a_number" | "not_a_date" | "not_yes_or_no" | "card_number" | "below_min" | "above_max" | "no_match" | "not_text";
    };

const FIELD_KEY = /^[a-z][a-z0-9_]{0,63}$/;
// Spoken answers in English or French, whatever the call's language. Spanish spoken answers are
// refused until a reviewed Spanish vocabulary exists (Sean, 2026-11-19): "sí" is not a yes, and a
// Spanish call answers on the keypad. ("no" is the English word.)
const YES = new Set(["yes", "y", "oui"]);
const NO = new Set(["no", "n", "non"]);
const FIELD_SETTINGS = ["key", "label", "type", "required", "sensitive", "maxLength", "showIf", "min", "max", "pattern"];
const DEFAULT_MAX_LENGTH = 500;
/** Longest pattern a form may set. */
export const MAX_PATTERN_LENGTH = 200;
/** The most ways a pattern may have to try a value: about 100,000 paths of at most a value's length each. */
export const MAX_PATTERN_WORK = 100_000;
/**
 * Words that name a card or a national identity number, in English, French or Spanish, in a key or
 * a label (accents and case ignored): a card, its number (PAN, cc), a Social Insurance Number (SIN,
 * NAS), a Social Security Number (SSN) or a Spanish social security number (NSS, "número de
 * seguro social" or "de seguridad social"). Each is a whole word of the name split at spaces, `_`,
 * `-` and camelCase humps, never a piece of one, so "account", "pancake" and "nasal" pass.
 */
const FORBIDDEN_NAME =
  /\b(?:cards?|cartes?|tarjetas?|cardholder|cvv2?|cvc|sin|nas|ssn|nss|pan|cc|social insurance|assurance sociale|social security|seguro social|seguridad social)\b/;
/**
 * The same names run together into one word, as snake_case keys and labels often write them
 * ("creditcard", "cardno", "sinnumber", "numerocarte", "numerotarjeta"), without catching words
 * that merely hold the letters ("cardiology", "discard", "cartel", "business").
 */
const FORBIDDEN_COMPOUND = [
  /^(?:credit|debit|bank|gift|payment|pay)?cards?(?:no|num|number|numbers|holders?|name)?$/,
  /^(?:no|num|numero)?cartes?(?:no|num|numero)?$/,
  /^(?:no|num|numero)?tarjetas?(?:no|num|numero)?$/,
  /^(?:sin|nas|ssn|nss|ss|pan|cc)(?:no|num|number|numero)$/,
];

/** Every problem with a form, as sentences. */
/** Every problem with one intake form, with the field it is about in `params`. */
export function validateForm(form: IntakeForm): StructuredProblem[] {
  const errors: StructuredProblem[] = [];
  if (form.fields.length === 0) errors.push(problem("intake.form_empty", "the form has no fields"));
  const keys = new Set<string>();
  for (const field of form.fields) {
    const at = { field: field.key };
    if (!FIELD_KEY.test(field.key)) errors.push(problem("intake.field_key", `field key ${JSON.stringify(field.key)} is not snake_case`, at));
    if (keys.has(field.key)) errors.push(problem("intake.field_duplicate", `field ${field.key} is defined twice`, at));
    keys.add(field.key);
    if (field.label.en.trim() === "" || field.label.fr.trim() === "") errors.push(problem("intake.field_labels", `field ${field.key} needs an English and a French label`, at));
    // Spanish is optional; when given it is a label like the others.
    const es: unknown = field.label.es;
    if (es !== undefined && (typeof es !== "string" || es.trim() === "")) errors.push(problem("intake.field_spanish", `field ${field.key}: the Spanish label (es), when given, must not be empty`, at));
    for (const k of unknownKeys(field.label as unknown as Record<string, unknown>, LOCALES)) errors.push(problem("intake.field_locale", `field ${field.key}: label ${k} is not a locale (en, fr or es)`, { ...at, key: k }));
    for (const k of unknownKeys(field as unknown as Record<string, unknown>, FIELD_SETTINGS)) errors.push(problem("intake.field_setting", `field ${field.key}: ${k} is not a field setting`, { ...at, key: k }));
    // Only `true` marks a field sensitive: any other value ("true", 1) would file it in the clear.
    const sensitive: unknown = field.sensitive;
    if (sensitive !== undefined && typeof sensitive !== "boolean") errors.push(problem("intake.field_sensitive", `field ${field.key}: sensitive must be true or false`, at));
    if ([field.key.replaceAll("_", " "), field.label.en, field.label.fr, typeof es === "string" ? es : ""].some(namesForbidden)) {
      errors.push(problem("intake.field_forbidden", `field ${field.key} names a card or a Social Insurance Number, which intake never collects`, at));
    }
    errors.push(...rangeErrors(field).map((e) => problem(e.code, `field ${field.key}: ${e.message}`, { ...at, ...e.params })));
    // The length cap and the pattern's work bound both read it: NaN, 0, a fraction or a string would
    // lift the cap, make the field impossible to fill, or give the two checks different limits.
    const maxLength: unknown = field.maxLength;
    if (maxLength !== undefined && (!Number.isInteger(maxLength) || (maxLength as number) < 1)) {
      errors.push(problem("intake.field_max_length", `field ${field.key}: maxLength must be a positive whole number`, at));
    }
    if (field.pattern !== undefined) {
      const longest = typeof field.maxLength === "number" ? field.maxLength : DEFAULT_MAX_LENGTH;
      const pattern = field.type === "text" ? patternProblem(field.pattern, longest) : "pattern is for text fields only";
      if (pattern !== null) errors.push(problem("intake.field_pattern", `field ${field.key}: ${pattern}`, { ...at, reason: pattern }));
    }
    if (field.showIf !== undefined) {
      const showIf = showIfProblem(form, field);
      if (showIf !== null) errors.push(problem(showIf.code, `field ${field.key}: ${showIf.message}`, { ...at, ...showIf.params }));
    }
  }
  return errors;
}

function namesForbidden(name: string): boolean {
  // Accents and dots go first, so "S.I.N." and "Numéro d'assurance sociale" are caught; a camelCase
  // hump splits a word ("panNumber" is "pan number") before case goes.
  const plain = name
    .normalize("NFD")
    .replace(/[\p{M}.]/gu, "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ");
  return FORBIDDEN_NAME.test(plain) || plain.split(" ").some((word) => FORBIDDEN_COMPOUND.some((compound) => compound.test(word)));
}

function rangeErrors(field: IntakeField): StructuredProblem[] {
  if (field.min === undefined && field.max === undefined) return [];
  if (field.type !== "number" && field.type !== "date") return [problem("intake.field_range_shape", "min and max are for number and date fields only")];
  const ok = field.type === "number" ? (v: unknown) => typeof v === "number" && Number.isFinite(v) : (v: unknown) => typeof v === "string" && isCalendarDate(v);
  const what = field.type === "number" ? "a number" : "a YYYY-MM-DD date";
  const errors: StructuredProblem[] = [];
  for (const bound of ["min", "max"] as const) {
    if (field[bound] !== undefined && !ok(field[bound])) errors.push(problem("intake.field_range_bound", `${bound} must be ${what}`, { bound, type: field.type }));
  }
  if (errors.length === 0 && field.min !== undefined && field.max !== undefined && (field.min as number) > (field.max as number)) errors.push(problem("intake.field_range_order", "min is above max"));
  return errors;
}

/**
 * Why a text pattern is refused, or null. A config must not be able to stall the engine on a
 * caller's value, so besides being a valid regular expression, a pattern must not use a
 * backreference or repeat a group that itself repeats or alternates (`(a+)+`, `(a|b)*`), and the
 * number of ways it can try to match a value of the field's longest length (the product of the
 * choices each repetition and alternative gives) must stay within `MAX_PATTERN_WORK`.
 */
function patternProblem(pattern: unknown, longest: number): string | null {
  if (typeof pattern !== "string" || pattern.length === 0 || pattern.length > MAX_PATTERN_LENGTH) return `pattern must be 1 to ${MAX_PATTERN_LENGTH} characters`;
  try {
    new RegExp(pattern, "u");
  } catch {
    return "pattern is not a valid regular expression";
  }
  // One flag per open group: whether it holds a repetition or an alternation.
  const groups: boolean[] = [];
  let inClass = false;
  let work = 1;
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern.charAt(i);
    let choices = 0;
    if (c === "\\") {
      const next = pattern.charAt(i + 1);
      if (/[1-9k]/.test(next)) return "pattern must not use a backreference";
      // The braces of \p{...}, \P{...} and \u{...} belong to the escape.
      i = /[pPu]/.test(next) && pattern.charAt(i + 2) === "{" ? pattern.indexOf("}", i) : i + 1;
    } else if (inClass) {
      inClass = c !== "]";
    } else if (c === "[") {
      inClass = true;
    } else if (c === "(") {
      groups.push(false);
      if (pattern.charAt(i + 1) === "?") i++;
    } else if (c === ")") {
      if (groups.pop() === true && /[*+{]/.test(pattern.charAt(i + 1))) return "pattern repeats a group that repeats or alternates, which can take too long to check";
    } else if (c === "|" || c === "?") {
      choices = 2;
    } else if (c === "*" || c === "+") {
      choices = longest + 1;
    } else if (c === "{") {
      // In Unicode mode an unescaped brace outside a class is always a valid {m}, {m,} or {m,n}.
      const [whole, lo, comma, hi] = /^\{(\d+)(,?)(\d*)\}/.exec(pattern.slice(i))!;
      choices = Math.max((comma === "" ? Number(lo) : hi === "" ? longest : Number(hi)) - Number(lo), 0) + 1;
      i += whole.length - 1;
    }
    if (choices > 0) {
      groups.fill(true);
      work *= choices;
      // A lazy quantifier's ? is part of it.
      if (c !== "|" && pattern.charAt(i + 1) === "?") i++;
    }
  }
  return work > MAX_PATTERN_WORK ? "pattern can match in too many ways to check quickly; bound its repetitions, for example {1,40} for +" : null;
}

function showIfProblem(form: IntakeForm, field: IntakeField): StructuredProblem | null {
  const rule: unknown = field.showIf;
  if (!isObject(rule) || typeof rule.field !== "string" || !("equals" in rule) || unknownKeys(rule, ["field", "equals"]).length > 0) {
    return problem("intake.show_if_shape", "showIf must be { field, equals }");
  }
  const target = form.fields.find((f) => f.key === rule.field);
  if (target === undefined) return problem("intake.show_if_no_field", `showIf names no field ${rule.field}`, { field: rule.field });
  if (target.sensitive === true) return problem("intake.show_if_sensitive", `showIf depends on ${target.key}, which is sensitive, so the questions asked would tell its value`, { field: target.key });
  if (!acceptsValue(target, rule.equals)) return problem("intake.show_if_value", `showIf.equals is not a value field ${target.key} can take`, { field: target.key });
  // Follow the chain: a field that comes back to itself is never shown.
  const chain = [field.key];
  for (let next: IntakeField | undefined = target; next !== undefined; next = form.fields.find((f) => f.key === next!.showIf?.field)) {
    if (next.key === field.key) return problem("intake.show_if_cycle", `showIf goes round in a cycle: ${[...chain, field.key].join(" > ")}`, { cycle: [...chain, field.key].join(" > ") });
    if (chain.includes(next.key)) return null;
    chain.push(next.key);
  }
  return null;
}

/**
 * Whether a stored value is one the field could hold after normalisation: its type, and its
 * bounds, length, pattern and card check (text and number fields). A rule the form gets wrong is reported on its own and
 * not applied here.
 */
function acceptsValue(field: IntakeField, value: unknown): boolean {
  switch (field.type) {
    case "text": {
      if (typeof value !== "string" || value.trim() !== value) return false;
      const longest = typeof field.maxLength === "number" ? field.maxLength : DEFAULT_MAX_LENGTH;
      const { pattern, ...rest } = field;
      const checked = pattern !== undefined && patternProblem(pattern, longest) === null ? field : rest;
      return normaliseFieldValue(checked, value).ok;
    }
    case "number":
      return typeof value === "number" && Number.isFinite(value) && findCardNumbers(String(value)).length === 0 && withinBounds(field, value);
    case "date":
      return typeof value === "string" && isCalendarDate(value) && withinBounds(field, value);
    default:
      return typeof value === "boolean";
  }
}

/** Whether a value is within the field's bounds; bounds the form gets wrong are not applied. */
function withinBounds(field: IntakeField, value: number | string): boolean {
  return rangeErrors(field).length > 0 || inRange(field, value).ok;
}

export function normaliseFieldValue(field: IntakeField, raw: string): NormaliseResult {
  const value = raw.trim();
  if (value === "") return { ok: false, reason: "empty" };
  switch (field.type) {
    case "text":
      // A lone surrogate is not Unicode text: no record, digest or read-back can hold it faithfully.
      if (!value.isWellFormed()) return { ok: false, reason: "not_text" };
      if (findCardNumbers(value).length > 0) return { ok: false, reason: "card_number" };
      if (value.length > (field.maxLength ?? DEFAULT_MAX_LENGTH)) return { ok: false, reason: "too_long" };
      if (field.pattern !== undefined && !new RegExp(`^(?:${field.pattern})$`, "u").test(value)) return { ok: false, reason: "no_match" };
      return { ok: true, value };
    case "number":
      // A card number is refused as in a text field, whatever its form ("4111 1111 1111 1111"
      // included), so a number field cannot become a way to store one either.
      if (findCardNumbers(value).length > 0) return { ok: false, reason: "card_number" };
      // Hundreds of digits overflow to Infinity, which no record can hold.
      if (!/^-?\d+(\.\d+)?$/.test(value) || !Number.isFinite(Number(value))) return { ok: false, reason: "not_a_number" };
      // The number stored is checked too: Number() drops leading zeros, so "00004111111111111111"
      // (one numeral too long to be a card) would be stored as one.
      if (findCardNumbers(String(Number(value))).length > 0) return { ok: false, reason: "card_number" };
      return inRange(field, Number(value));
    case "date":
      return isCalendarDate(value) ? inRange(field, value) : { ok: false, reason: "not_a_date" };
    case "yes_no": {
      // NFC, so an answer whose accent arrives as a separate mark reads as the same word.
      const word = value.normalize("NFC").toLowerCase();
      if (YES.has(word)) return { ok: true, value: true };
      if (NO.has(word)) return { ok: true, value: false };
      return { ok: false, reason: "not_yes_or_no" };
    }
  }
}

/** Bounds are inclusive. YYYY-MM-DD dates compare in calendar order as strings. */
function inRange(field: IntakeField, value: number | string): NormaliseResult {
  // A validated form's bounds have the field's own type, so these compare numbers or dates.
  if (field.min !== undefined && (value as number) < (field.min as number)) return { ok: false, reason: "below_min" };
  if (field.max !== undefined && (value as number) > (field.max as number)) return { ok: false, reason: "above_max" };
  return { ok: true, value };
}

/** YYYY-MM-DD that names a real day. */
export function isCalendarDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

/**
 * Whether a field is shown, given the draft's values: it has no `showIf`, or the field it names
 * holds the value it waits for and is shown itself. A chain that comes back on itself is hidden.
 */
export function isShown(form: IntakeForm, values: Readonly<Record<string, FieldValue>>, field: IntakeField): boolean {
  const seen = new Set<string>();
  for (let rule = field.showIf; rule !== undefined; rule = form.fields.find((f) => f.key === rule!.field)?.showIf) {
    if (seen.has(rule.field) || values[rule.field] !== rule.equals) return false;
    seen.add(rule.field);
  }
  return true;
}

/** The values that will be filed: those of shown fields, in form order. A hidden field's value stays out. */
export function shownValues(form: IntakeForm, values: Readonly<Record<string, FieldValue>>): Record<string, FieldValue> {
  const shown: Record<string, FieldValue> = {};
  for (const field of form.fields) {
    if (Object.hasOwn(values, field.key) && isShown(form, values, field)) shown[field.key] = values[field.key]!;
  }
  return shown;
}

/** Required fields that are shown and have no value, in form order. */
export function missingRequired(form: IntakeForm, values: Readonly<Record<string, FieldValue>>): string[] {
  // Own keys only: `in` would count a field named like an Object.prototype member (`constructor`) as given.
  return form.fields.filter((f) => f.required && !Object.hasOwn(values, f.key) && isShown(form, values, f)).map((f) => f.key);
}

/**
 * Whether every field of a form has a label in a locale, so a call in that language can ask and
 * read back any of them. English and French always do; Spanish only where the workspace wrote it.
 */
export function formSpeaks(form: IntakeForm, locale: Locale): boolean {
  return form.fields.every((field) => typeof field.label[locale] === "string");
}

/** The fingerprint a receipt carries for a confirmed record. */
export function intakeDigest(form: IntakeForm, values: Readonly<Record<string, FieldValue>>): string {
  return sha256Hex(canonicalJson({ formId: form.formId, version: form.version, values }));
}
