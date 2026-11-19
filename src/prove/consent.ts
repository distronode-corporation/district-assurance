// Consent captured by code: the exact wording read, its version, and the answer. The wording is
// fingerprinted, so a receipt proves which words the caller heard without carrying them.
import { canonicalJson } from "../core/canonical.ts";
import { NotImplementedError } from "../core/errors.ts";
import { sha256Hex } from "../core/hash.ts";
import type { Locale, LocalisedText } from "../core/runtime.ts";

export interface ConsentWording {
  purpose: string;
  version: string;
  /** English and French always; Spanish when the workspace offers it. */
  text: LocalisedText;
}

export interface ConsentRecord {
  consentId: string;
  callId: string;
  purpose: string;
  wordingVersion: string;
  wordingDigest: string;
  locale: Locale;
  answer: "yes" | "no";
  channel: "call" | "text" | "web";
  at: string;
}

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

/** Revokes a consent by voice, text or dashboard. */
export function revokeConsent(_input: { consentId: string; via: "call" | "text" | "web" }): never {
  throw new NotImplementedError("revokeConsent", "PRV-3");
}
