// Keypad knowledge factors: compare, then discard.
//
// Reference values are stored as HMACs under a per-workspace key, because a plain hash of a date
// of birth is reversed by trying every date. The caller's digits are hashed the same way, compared
// in constant time, and never kept. All keypad fields are judged together and give one answer, so
// the line never says which one failed and an unknown account looks the same as a wrong answer.
//
// The knowledge key is either bytes the host holds or an opaque HMAC function that runs where the
// key lives (a key store), so the key itself need never enter the engine's process.
import { EngineError } from "../core/errors.ts";
import { hexDigestsEqual, hmacSha256Hex } from "../core/hash.ts";
import type { SubjectRecord } from "../core/adapters.ts";

const KEYPAD_DIGITS = /^\d{1,32}$/;
const HMAC_HEX = /^[0-9a-f]{64}$/;

/**
 * HMAC-SHA256 under the workspace's knowledge key of the UTF-8 bytes of `data`, as 64 lower-case
 * hex characters. The same answer for the same input, every time. Synchronous, the same shape as
 * the `hmac` a factor plug-in receives.
 */
export type KnowledgeHmac = (data: string) => string;

/** The knowledge key: its bytes (at least 16), or an opaque HMAC function that keeps them in the key store. */
export type KnowledgeKey = string | Uint8Array | KnowledgeHmac;

/**
 * The keyed hash for a knowledge key. Bytes are used with `node:crypto`; a function is called as
 * it is, and an answer that is not 64 lower-case hex characters is refused (`invalid_input`), so
 * a misbehaving key store fails loudly instead of failing every comparison.
 */
export function knowledgeHmac(knowledgeKey: KnowledgeKey): KnowledgeHmac {
  if (typeof knowledgeKey !== "function") return (data) => hmacSha256Hex(knowledgeKey, data);
  return (data) => {
    const digest = knowledgeKey(data);
    if (typeof digest !== "string" || !HMAC_HEX.test(digest)) throw new EngineError("invalid_input", "the knowledge HMAC function must return 64 lower-case hex characters");
    return digest;
  };
}

/** The subject key for an account number keyed on the keypad. */
export function subjectKeyFor(knowledgeKey: KnowledgeKey, accountNumber: string): string {
  return knowledgeHmac(knowledgeKey)(`subject:${accountNumber}`);
}

/** The stored digest of one knowledge field, for loading reference records. */
export function knowledgeDigest(knowledgeKey: KnowledgeKey, field: string, value: string): string {
  return knowledgeHmac(knowledgeKey)(`field:${field}:${value}`);
}

/**
 * The stored digest of a subject's PIN, for the PIN factor in `keyed_hash` mode. Bound to the
 * subject, so two subjects with the same PIN have different digests.
 */
export function pinDigest(knowledgeKey: KnowledgeKey, subjectKey: string, pin: string): string {
  return knowledgeHmac(knowledgeKey)(`pin:${subjectKey}:${pin}`);
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
  knowledgeKey: KnowledgeKey,
  subject: SubjectRecord | null,
  fields: readonly string[],
  entries: Readonly<Record<string, string>>,
): boolean {
  return judgeKeypadWith(knowledgeHmac(knowledgeKey), subject, fields, entries);
}

/** `judgeKeypadFactors` with the keyed hash as a function, so the key can stay where it is. */
export function judgeKeypadWith(
  hmac: KnowledgeHmac,
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
