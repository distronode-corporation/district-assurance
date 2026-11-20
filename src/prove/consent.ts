// Consent captured by code: the exact wording read, its version, and the answer. The wording is
// fingerprinted, so a receipt proves which words the caller heard without carrying them. A consent
// is revoked by voice, text or dashboard through the host's `ConsentStore` (`Engine.revokeConsent`).
import { canonicalJson } from "../core/canonical.ts";
import { sha256Hex } from "../core/hash.ts";
import type { LocalisedText } from "../core/runtime.ts";

export interface ConsentWording {
  purpose: string;
  version: string;
  /** English and French always; Spanish when the workspace offers it. */
  text: LocalisedText;
}

/** Kept in the ConsentStore's types (#80); re-exported for code that imported it from here. */
export type { ConsentRecord } from "../core/adapters.ts";

/**
 * The wording's fingerprint over its purpose, version and every text it has. A wording without a
 * Spanish text is digested over `{en, fr}` exactly as before Spanish existed, so its digest, and
 * every receipt that carries it, stays the same.
 */
export function wordingDigest(wording: ConsentWording): string {
  const { en, fr, es } = wording.text;
  const text = es === undefined ? { en, fr } : { en, fr, es };
  return sha256Hex(canonicalJson({ purpose: wording.purpose, version: wording.version, text }));
}

/**
 * The words that mean "stop" on their own, without accents or case: the standard carrier opt-out
 * set (STOP, STOPALL, UNSUBSCRIBE, CANCEL, END, QUIT) and the French ARRET, ARRETE, ARRETER.
 */
const STOP_WORDS: ReadonlySet<string> = new Set(["stop", "stopall", "unsubscribe", "cancel", "end", "quit", "arret", "arrete", "arreter"]);

/**
 * Whether a text or a spoken answer asks to stop: one of the standard opt-out words (STOP,
 * STOPALL, UNSUBSCRIBE, CANCEL, END, QUIT) or the French ARRÊT, ARRÊTE and ARRÊTER, in any case,
 * with or without accents, as the whole message apart from spaces and closing punctuation. The
 * host maps a match to `Engine.revokeConsent`, and may treat more words as a stop on its own. A
 * word inside a longer message is not a match, so "don't stop" never revokes anything.
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
