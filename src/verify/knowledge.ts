// Keypad knowledge factors: compare, then discard.
//
// Reference values are stored as HMACs under a per-workspace key, because a plain hash of a date
// of birth is reversed by trying every date. The caller's digits are hashed the same way, compared
// in constant time, and never kept. All keypad fields are judged together and give one answer, so
// the line never says which one failed and an unknown account looks the same as a wrong answer.
import { hexDigestsEqual, hmacSha256Hex } from "../core/hash.ts";
import type { SubjectRecord } from "../core/adapters.ts";

const KEYPAD_DIGITS = /^\d{1,32}$/;

/** The subject key for an account number keyed on the keypad. */
export function subjectKeyFor(knowledgeKey: string | Uint8Array, accountNumber: string): string {
  return hmacSha256Hex(knowledgeKey, `subject:${accountNumber}`);
}

/** The stored digest of one knowledge field, for loading reference records. */
export function knowledgeDigest(knowledgeKey: string | Uint8Array, field: string, value: string): string {
  return hmacSha256Hex(knowledgeKey, `field:${field}:${value}`);
}

/**
 * The stored digest of a subject's PIN, for the PIN factor in `keyed_hash` mode. Bound to the
 * subject, so two subjects with the same PIN have different digests.
 */
export function pinDigest(knowledgeKey: string | Uint8Array, subjectKey: string, pin: string): string {
  return hmacSha256Hex(knowledgeKey, `pin:${subjectKey}:${pin}`);
}

/** Whether a string is something a keypad could have produced. */
export function isKeypadEntry(value: string): boolean {
  return KEYPAD_DIGITS.test(value);
}

/**
 * Judges every keypad field at once. Pass only when the subject exists and every field matches.
 * Every field is compared even after a mismatch, so timing does not tell which one failed.
 */
export function judgeKeypadFactors(
  knowledgeKey: string | Uint8Array,
  subject: SubjectRecord | null,
  fields: readonly string[],
  entries: Readonly<Record<string, string>>,
): boolean {
  return judgeKeypadWith((data) => hmacSha256Hex(knowledgeKey, data), subject, fields, entries);
}

/** `judgeKeypadFactors` with the keyed hash as a function, so the key can stay where it is. */
export function judgeKeypadWith(
  hmac: (data: string) => string,
  subject: SubjectRecord | null,
  fields: readonly string[],
  entries: Readonly<Record<string, string>>,
): boolean {
  let ok = subject !== null;
  for (const field of fields) {
    const entry = entries[field] ?? "";
    const stored = subject?.knowledge[field] ?? "";
    const digest = hmac(`field:${field}:${isKeypadEntry(entry) ? entry : ""}`);
    const match = hexDigestsEqual(digest, stored);
    ok = ok && match && isKeypadEntry(entry);
  }
  return ok;
}
