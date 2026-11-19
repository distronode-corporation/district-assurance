// Consent captured by code: the exact wording read, its version, and the answer. The wording is
// fingerprinted, so a receipt proves which words the caller heard without carrying them.
import { canonicalJson } from "../core/canonical.ts";
import { NotImplementedError } from "../core/errors.ts";
import { sha256Hex } from "../core/hash.ts";

export interface ConsentWording {
  purpose: string;
  version: string;
  text: { en: string; fr: string };
}

export interface ConsentRecord {
  consentId: string;
  callId: string;
  /**
   * The subject Badge matched on the call (a keypad or PIN match) when the consent was recorded, or
   * null when none had. A subject's export lists only the consents recorded under its key.
   */
  subjectKey: string | null;
  purpose: string;
  wordingVersion: string;
  wordingDigest: string;
  locale: "en" | "fr";
  answer: "yes" | "no";
  channel: "call" | "text" | "web";
  at: string;
}

export function wordingDigest(wording: ConsentWording): string {
  return sha256Hex(canonicalJson({ purpose: wording.purpose, version: wording.version, text: wording.text }));
}

/** Revokes a consent by voice, text or dashboard. */
export function revokeConsent(_input: { consentId: string; via: "call" | "text" | "web" }): never {
  throw new NotImplementedError("revokeConsent", "PRV-3");
}
