// Intake forms: the fields a business defines, and the values a caller gives during the call. A
// value is normalised by code before it reaches the draft, and a free-text value that carries a
// card number is refused, so intake can never become a way to store one.
import { canonicalJson } from "../core/canonical.ts";
import { sha256Hex } from "../core/hash.ts";
import { findCardNumbers } from "../core/redaction.ts";

export type FieldType = "text" | "number" | "date" | "yes_no";

export interface IntakeField {
  key: string;
  label: { en: string; fr: string };
  type: FieldType;
  required: boolean;
  /** Stored encrypted (FIL-2). Forms with sensitive fields are refused until that is built. */
  sensitive?: boolean;
  /** Text fields only. Default 500. */
  maxLength?: number;
}

export interface IntakeForm {
  formId: string;
  version: string;
  fields: IntakeField[];
}

export type FieldValue = string | number | boolean;

export type NormaliseResult =
  | { ok: true; value: FieldValue }
  | { ok: false; reason: "empty" | "too_long" | "not_a_number" | "not_a_date" | "not_yes_or_no" | "card_number" | "not_text" };

const FIELD_KEY = /^[a-z][a-z0-9_]{0,63}$/;
const YES = new Set(["yes", "y", "oui"]);
const NO = new Set(["no", "n", "non"]);

/** Every problem with a form, as sentences. */
export function validateForm(form: IntakeForm): string[] {
  const errors: string[] = [];
  if (form.fields.length === 0) errors.push("the form has no fields");
  const keys = new Set<string>();
  for (const field of form.fields) {
    if (!FIELD_KEY.test(field.key)) errors.push(`field key ${JSON.stringify(field.key)} is not snake_case`);
    if (keys.has(field.key)) errors.push(`field ${field.key} is defined twice`);
    keys.add(field.key);
    if (field.label.en.trim() === "" || field.label.fr.trim() === "") errors.push(`field ${field.key} needs an English and a French label`);
  }
  return errors;
}

export function normaliseFieldValue(field: IntakeField, raw: string): NormaliseResult {
  const value = raw.trim();
  if (value === "") return { ok: false, reason: "empty" };
  switch (field.type) {
    case "text":
      // A lone surrogate is not Unicode text, and canonical JSON (the record digest) refuses it.
      if (!value.isWellFormed()) return { ok: false, reason: "not_text" };
      if (findCardNumbers(value).length > 0) return { ok: false, reason: "card_number" };
      if (value.length > (field.maxLength ?? 500)) return { ok: false, reason: "too_long" };
      return { ok: true, value };
    case "number":
      return /^-?\d+(\.\d+)?$/.test(value) ? { ok: true, value: Number(value) } : { ok: false, reason: "not_a_number" };
    case "date":
      return isCalendarDate(value) ? { ok: true, value } : { ok: false, reason: "not_a_date" };
    case "yes_no": {
      const word = value.toLowerCase();
      if (YES.has(word)) return { ok: true, value: true };
      if (NO.has(word)) return { ok: true, value: false };
      return { ok: false, reason: "not_yes_or_no" };
    }
  }
}

/** YYYY-MM-DD that names a real day. */
export function isCalendarDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

/** Required fields without a value, in form order. */
export function missingRequired(form: IntakeForm, values: Readonly<Record<string, FieldValue>>): string[] {
  return form.fields.filter((f) => f.required && !(f.key in values)).map((f) => f.key);
}

/** The fingerprint a receipt carries for a confirmed record. */
export function intakeDigest(form: IntakeForm, values: Readonly<Record<string, FieldValue>>): string {
  return sha256Hex(canonicalJson({ formId: form.formId, version: form.version, values }));
}
