// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Keypad knowledge factors: compare, then discard.
//
// Reference values are stored as HMACs under a per-workspace key, because a plain hash of a date
// of birth is reversed by trying every date. The caller's digits are hashed the same way, compared
// in constant time, and never kept. All keypad fields are judged together and give one answer, so
// the line never says which one failed and an unknown account looks the same as a wrong answer.
//
// The knowledge key is either bytes the host holds or an opaque, asynchronous HMAC function that
// runs where the key lives (a key management service), so the key itself need never enter the
// engine's process.
import { EngineError } from "../core/errors.ts";
import { hexDigestsEqual, hmacSha256Hex } from "../core/hash.ts";
import type { SubjectRecord } from "../core/adapters.ts";
import { hashPinRecord, hashPinRecordSync } from "./pin-hash.ts";

const KEYPAD_DIGITS = /^\d{1,32}$/;
const HMAC_HEX = /^[0-9a-f]{64}$/;

/**
 * HMAC-SHA256 under the workspace's knowledge key of the UTF-8 bytes of `data`, as 64 lower-case
 * hex characters. The same answer for the same input, every time. Asynchronous, so it can be a
 * call to a key management service; the same shape as the `hmac` a factor plug-in receives.
 */
export type KnowledgeHmac = (data: string) => Promise<string>;

/** Knowledge key bytes the host holds: at least 16. */
export type KnowledgeKeyBytes = string | Uint8Array;

/** The knowledge key: its bytes, or an opaque HMAC function that keeps them in the key store. */
export type KnowledgeKey = KnowledgeKeyBytes | KnowledgeHmac;

/**
 * The keyed hash for a knowledge key, always asynchronous. Bytes are used with `node:crypto`; a
 * function is awaited, and an answer that is not 64 lower-case hex characters is refused
 * (`invalid_input`, a message that never quotes the answer), so a misbehaving key store fails
 * loudly instead of failing every comparison. A function that throws or rejects passes its error on.
 */
export function knowledgeHmac(knowledgeKey: KnowledgeKey): KnowledgeHmac {
  if (typeof knowledgeKey !== "function") return async (data) => hmacSha256Hex(knowledgeKey, data);
  return async (data) => {
    const digest: unknown = await knowledgeKey(data);
    if (typeof digest !== "string" || !HMAC_HEX.test(digest)) throw new EngineError("invalid_input", "the knowledge HMAC function must return 64 lower-case hex characters");
    return digest;
  };
}

/** HMAC under a knowledge key: at once for bytes, through the key store for a function. */
function keyed(knowledgeKey: KnowledgeKey, data: string): string | Promise<string> {
  return typeof knowledgeKey === "function" ? knowledgeHmac(knowledgeKey)(data) : hmacSha256Hex(knowledgeKey, data);
}

/** The subject key for an account number keyed on the keypad. Asynchronous with an HMAC function. */
export function subjectKeyFor(knowledgeKey: KnowledgeKeyBytes, accountNumber: string): string;
export function subjectKeyFor(knowledgeKey: KnowledgeHmac, accountNumber: string): Promise<string>;
export function subjectKeyFor(knowledgeKey: KnowledgeKey, accountNumber: string): string | Promise<string> {
  return keyed(knowledgeKey, `subject:${accountNumber}`);
}

/** The stored digest of one knowledge field, for loading reference records. Asynchronous with an HMAC function. */
export function knowledgeDigest(knowledgeKey: KnowledgeKeyBytes, field: string, value: string): string;
export function knowledgeDigest(knowledgeKey: KnowledgeHmac, field: string, value: string): Promise<string>;
export function knowledgeDigest(knowledgeKey: KnowledgeKey, field: string, value: string): string | Promise<string> {
  return keyed(knowledgeKey, `field:${field}:${value}`);
}

/**
 * The stored record of a subject's PIN, for the PIN factor in `keyed_hash` mode: Argon2id over the
 * keyed HMAC of `pin:<subjectKey>:<pin>`, with a fresh random salt (pin-hash.ts, ADR-29). Bound to
 * the subject and salted, so the same PIN gives a new record each time. With bytes it returns at
 * once after one Argon2id run on this thread; with an HMAC function it is asynchronous.
 */
export function pinDigest(knowledgeKey: KnowledgeKeyBytes, subjectKey: string, pin: string): string;
export function pinDigest(knowledgeKey: KnowledgeHmac, subjectKey: string, pin: string): Promise<string>;
export function pinDigest(knowledgeKey: KnowledgeKey, subjectKey: string, pin: string): string | Promise<string> {
  const keyedPin = keyed(knowledgeKey, `pin:${subjectKey}:${pin}`);
  return typeof keyedPin === "string" ? hashPinRecordSync(keyedPin) : keyedPin.then(hashPinRecord);
}

/** Whether a string is something a keypad could have produced. */
export function isKeypadEntry(value: string): boolean {
  return KEYPAD_DIGITS.test(value);
}

/**
 * Judges every keypad field at once. Pass only when the subject exists and every field matches.
 * Every field is hashed and compared even after a mismatch, so timing does not tell which one
 * failed. Asynchronous with an HMAC function.
 */
export function judgeKeypadFactors(knowledgeKey: KnowledgeKeyBytes, subject: SubjectRecord | null, fields: readonly string[], entries: Readonly<Record<string, string>>): boolean;
export function judgeKeypadFactors(knowledgeKey: KnowledgeHmac, subject: SubjectRecord | null, fields: readonly string[], entries: Readonly<Record<string, string>>): Promise<boolean>;
export function judgeKeypadFactors(
  knowledgeKey: KnowledgeKey,
  subject: SubjectRecord | null,
  fields: readonly string[],
  entries: Readonly<Record<string, string>>,
): boolean | Promise<boolean> {
  if (typeof knowledgeKey === "function") return judgeKeypadWith(knowledgeKey, subject, fields, entries);
  const candidates = keypadCandidates(fields, entries);
  return keypadMatches(subject, fields, candidates, candidates.map((c) => hmacSha256Hex(knowledgeKey, c.data)));
}

/** `judgeKeypadFactors` with the keyed hash as a function, so the key can stay where it is. */
export async function judgeKeypadWith(
  hmac: KnowledgeHmac,
  subject: SubjectRecord | null,
  fields: readonly string[],
  entries: Readonly<Record<string, string>>,
): Promise<boolean> {
  // Read once: a field the caller adds while the hashes are pending is neither hashed nor compared.
  const asked = [...fields];
  const candidates = keypadCandidates(asked, entries);
  // Every field is hashed before any is compared; one that fails fails the whole judgement.
  return keypadMatches(subject, asked, candidates, await Promise.all(candidates.map((c) => knowledgeHmac(hmac)(c.data))));
}

/** What each field's entry is hashed as: a malformed entry as an empty one, which never matches. */
function keypadCandidates(fields: readonly string[], entries: Readonly<Record<string, string>>): { wellFormed: boolean; data: string }[] {
  return fields.map((field) => {
    const entry = entries[field] ?? "";
    const wellFormed = isKeypadEntry(entry);
    return { wellFormed, data: `field:${field}:${wellFormed ? entry : ""}` };
  });
}

function keypadMatches(subject: SubjectRecord | null, fields: readonly string[], candidates: readonly { wellFormed: boolean }[], digests: readonly string[]): boolean {
  let ok = subject !== null;
  fields.forEach((field, i) => {
    const match = hexDigestsEqual(digests[i]!, subject?.knowledge[field] ?? "");
    ok = ok && match && candidates[i]!.wellFormed;
  });
  return ok;
}
