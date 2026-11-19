// Consent captured by code: the exact wording read, its version, and the answer. The wording is
// fingerprinted, so a receipt proves which words the caller heard without carrying them. A consent
// is revoked by voice, text or dashboard through the host's `ConsentStore` (`Engine.revokeConsent`).
import { canonicalJson } from "../core/canonical.ts";
import { sha256Hex } from "../core/hash.ts";

export interface ConsentWording {
  purpose: string;
  version: string;
  text: { en: string; fr: string };
}

export function wordingDigest(wording: ConsentWording): string {
  return sha256Hex(canonicalJson({ purpose: wording.purpose, version: wording.version, text: wording.text }));
}

/** The words that mean "stop" on their own, in English and French, without accents or case. */
const STOP_WORDS: ReadonlySet<string> = new Set(["stop", "arret", "arrete", "arreter"]);

/**
 * Whether a text or a spoken answer asks to stop: STOP, or its French forms ARRÊT, ARRÊTE and
 * ARRÊTER, in any case, with or without accents, alone apart from spaces and closing punctuation.
 * The host maps a match to `Engine.revokeConsent`. A word inside a longer message is not a match,
 * so "don't stop" never revokes anything.
 */
export function isStopRequest(text: string): boolean {
  // A host passes what its carrier's webhook carried: anything that is not text is never a stop.
  if (typeof text !== "string") return false;
  const word = text
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[\s.!]+$/u, "")
    .trim();
  return STOP_WORDS.has(word);
}
