// Badge factors are plug-ins. Each factor kind says how it is entered, how many attempts a call
// gets, and which adapters it needs; Badge's settings turn each one on or off, and a flow step
// says which of them may count. A host adds its own factor (one the caller enters and code judges)
// with `badgeModule({ factors: [...] })` or, after the engine is built, `engine.useFactor`. The
// plug-in types and their checks live in the core (core/module.ts), where the registry uses them.
import { hexDigestsEqual, hmacSha256Hex } from "../core/hash.ts";
import type { FactorJudgeInput } from "../core/module.ts";
import { FACTOR_KINDS, type SpokenFormat, type SpokenPolicy, type VerificationPolicy } from "../core/policy.ts";
import { isObject } from "../core/shape.ts";
import type { AdapterName, EngineRuntime } from "../core/runtime.ts";
import type { LockoutSettings } from "./counters.ts";
import { isKeypadEntry, judgeKeypadWith } from "./knowledge.ts";
import { checkPinRecord, hashPinRecord, hashPinRecordSync } from "./pin-hash.ts";
import { normaliseSpokenAnswer, normaliseSpokenKeypadEntry } from "./spoken.ts";

export { checkFactorPlugin, snapshotFactorPlugin, type FactorEntry, type FactorJudgeInput, type FactorPlugin } from "../core/module.ts";

export type PinMode = "keyed_hash" | "verifier";

export interface PinSettings {
  /** `keyed_hash`: compare with `SubjectRecord.pinDigest`. `verifier`: ask the host's `PinVerifier`. */
  mode: PinMode;
  /** At least 4. */
  minDigits: number;
  /** At most 12. */
  maxDigits: number;
  /** 1 to 5. */
  maxAttemptsPerCall: number;
  /**
   * The duress PIN (VER-12), off unless set. `refuseScopes`: scopes refused on a duress call on top
   * of every money, contact and access scope (for example `owner.command`); it may be empty.
   */
  duress?: { refuseScopes: string[] };
}

/**
 * What a PIN entry was: not a match, the PIN, or the duress PIN. Only the call record and the
 * ledger's keyed `tag` know which pass it was; to the caller a duress entry is a pass.
 */
export type PinOutcome = "fail" | "pass" | "duress";

export const PIN_OUTCOMES: readonly PinOutcome[] = ["fail", "pass", "duress"];

/**
 * The stored record of a subject's duress PIN: Argon2id over `HMAC(key, "duress:" + subjectKey +
 * ":" + pin)`, with a fresh salt (pin-hash.ts, ADR-29), so the same PIN gives a new record each time.
 */
export function duressDigest(knowledgeKey: string | Uint8Array, subjectKey: string, pin: string): string {
  return hashPinRecordSync(hmacSha256Hex(knowledgeKey, `duress:${subjectKey}:${pin}`));
}

/**
 * The `tag` every `pin` factor entry carries: an HMAC under the knowledge key of the entry's event
 * id and its outcome. The same shape for every outcome, so only the key holder can tell them apart.
 */
export function pinTag<R extends string | Promise<string>>(hmac: (data: string) => R, eventId: string, outcome: PinOutcome): R {
  return hmac(JSON.stringify(["pin.tag", eventId, outcome]));
}

export interface BadgeSettings {
  /** The factors turned on. A factor that is off is refused everywhere, in flows and outside them. */
  factors: string[];
  /** Grant lifetime. Default 900 (15 minutes), at most 3600. */
  grantTtlSeconds?: number;
  /** Required when `pin` is on. */
  pin?: PinSettings;
  /** Waits and locks across calls for the factors the caller enters (counters.ts). Default: the floors. */
  lockout?: LockoutSettings;
  /** The accessible path (VER-11): keypad fields said instead of keyed, and keypad timeouts. */
  accessibility?: AccessibilitySettings;
}

export interface AccessibilitySettings {
  /**
   * Keypad fields a caller may say instead of key. They are judged in the spoken_knowledge factor,
   * with the policy's spoken fields, and each spoken try also uses a keypad_knowledge attempt. Never the PIN.
   */
  spokenKeypadFields?: string[];
  /** The keypad idle timeout a call starts with, 5 to 60 seconds. Default 10. */
  keypadIdleSeconds?: number;
  /** The longest a call's idle timeout may be lengthened to, `keypadIdleSeconds` to 300. A relay or TTY call starts at it. Default: `keypadIdleSeconds`. */
  maxKeypadIdleSeconds?: number;
}

/** How each built-in factor reaches the engine. Planned factors cannot be turned on yet. */
export const BUILT_IN_FACTORS: Readonly<Record<(typeof FACTOR_KINDS)[number], { entered: boolean; adapters: readonly AdapterName[]; planned?: string }>> = {
  keypad_knowledge: { entered: true, adapters: [] },
  pin: { entered: true, adapters: [] },
  carrier_identity_match: { entered: false, adapters: ["carrier"] },
  photo_id: { entered: false, adapters: ["identity", "messages"] },
  text_code: { entered: false, adapters: ["messages", "codes"] },
  // Built in, not a plug-in: a plug-in is entered by the caller and counts as knowledge. Failed
  // callbacks and the daily limit are counted across calls.
  callback: { entered: false, adapters: ["dialer", "counters"] },
  spoken_knowledge: { entered: true, adapters: [] },
};

/**
 * Factors whose match lets the engine text or call back the number on file (a link or a callback
 * only goes out after one). A spoken answer does not: speech-to-text hears it, and a postal code is
 * known to more people.
 */
export const KNOWLEDGE_FACTORS: readonly string[] = ["keypad_knowledge", "pin"];

/**
 * The PIN factor's judge: a record on file, or the host's verifier. Unknown subjects do the same
 * work. Every entry is compared with the PIN and the duress PIN records alike, whether or not a
 * duress PIN is on file or turned on, so the work and the time never say which it was. A record of
 * the earlier format (a bare keyed HMAC) that matches is replaced by an Argon2id one (ADR-29).
 */
export async function judgePin(rt: EngineRuntime, settings: PinSettings, input: FactorJudgeInput): Promise<PinOutcome> {
  const pin = typeof input.entry === "string" ? input.entry : "";
  const wellFormed = isKeypadEntry(pin) && pin.length >= settings.minDigits && pin.length <= settings.maxDigits;
  let match: boolean;
  let duress: boolean;
  let brokenSubject = false;
  let upgrade: (outcome: PinOutcome) => Promise<void> = async () => {};
  if (settings.mode === "verifier") {
    // The verifier is asked every time, with a stand-in for a malformed entry or a non-keypad
    // account, so the answer's timing never says which it was. The stand-in's answer is ignored.
    const subjectKey = input.subjectKey ?? (await input.hmac("subject:"));
    const answer = await rt.adapter("pinVerifier").verify({ workspaceId: input.workspaceId, subjectKey, pin: wellFormed ? pin : "0".repeat(settings.minDigits) });
    duress = answer.duress === true;
    match = answer.matched;
  } else {
    // Both digests on file are read from the store now, not from the call's copy of the subject, so
    // a reset (which removes both) since verification began counts. An unknown subject is looked up
    // the same way.
    const records = rt.adapter("records");
    const subjectKey = input.subjectKey ?? (await input.hmac("subject:"));
    const onFile = await records.getSubject(input.workspaceId, subjectKey);
    const entry = wellFormed ? pin : "";
    const keyed = { pinDigest: await input.hmac(`pin:${input.subjectKey ?? ""}:${entry}`), duressDigest: await input.hmac(`duress:${input.subjectKey ?? ""}:${entry}`) };
    // Both records are run at once, each one Argon2id run, whatever is on file.
    const [pinCheck, duressCheck] = await Promise.all([checkPinRecord(onFile?.pinDigest, keyed.pinDigest), checkPinRecord(onFile?.duressDigest, keyed.duressDigest)]);
    match = pinCheck.match;
    duress = duressCheck.match;
    // The two are keyed apart and salted apart, so they are equal only on a subject imported wrongly.
    brokenSubject = onFile?.pinDigest !== undefined && onFile.pinDigest === onFile.duressDigest;
    // Rehash on a match (ADR-29): the record that matched, if it is of the earlier format, becomes an
    // Argon2id record, only while it is still the one on file. A miss changes nothing. The upgrade is
    // best effort: a write that fails leaves the earlier record, which still verifies, for the next
    // match to upgrade, and never changes the outcome of an entry already judged.
    upgrade = async (outcome) => {
      const field = outcome === "duress" ? "duressDigest" : "pinDigest";
      const check = outcome === "duress" ? duressCheck : pinCheck;
      if (outcome === "fail" || !check.upgrade) return;
      try {
        await records.upgradePinDigest(input.workspaceId, subjectKey, field, onFile![field]!, await hashPinRecord(keyed[field]));
      } catch {
        // Hashing the new record or writing it failed: the earlier record stays, and still verifies.
      }
    };
  }
  // A subject on file implies a keypad-shaped account or a host's subject key, never the stand-in.
  if (!wellFormed || input.subject === null) return "fail";
  // An entry that is both the PIN and the duress PIN, in either mode, and a subject imported with
  // the two digests equal, are refused like a wrong PIN, with no alarm: neither a login nor an alarm.
  if ((match && duress) || brokenSubject) return "fail";
  const outcome: PinOutcome = duress && settings.duress !== undefined ? "duress" : match ? "pass" : "fail";
  await upgrade(outcome);
  return outcome;
}

/** The keypad knowledge factor's judge: every configured field at once, one answer. */
export async function judgeKeypad(policy: VerificationPolicy, input: FactorJudgeInput): Promise<boolean> {
  const entries = typeof input.entry === "string" ? {} : input.entry;
  return judgeKeypadWith(input.hmac, input.subject, policy.keypadFields, entries);
}

/**
 * The spoken knowledge factor's judge: every spoken field at once, one answer. Each transcript is
 * normalised exactly (spoken.ts) and compared like a keypad field, as the keyed digest of
 * `field:<name>:<value>` in constant time; an unusable answer does the same work and fails.
 */
export async function judgeSpoken(spoken: SpokenPolicy, input: FactorJudgeInput, keypadFields: readonly string[] = []): Promise<boolean> {
  // Anything but a set of answers (a string, null, a number from a host's bug) answers nothing.
  const entries: Readonly<Record<string, unknown>> = isObject(input.entry) ? input.entry : {};
  // Keypad fields said instead of keyed (VER-11) are read as 1 to 32 digits, every value a keypad field can hold.
  const fields: Array<readonly [string, SpokenFormat | null]> = [...Object.entries(spoken.fields), ...keypadFields.map((f) => [f, null] as const)];
  let ok = input.subject !== null && fields.length > 0;
  for (const [field, format] of fields) {
    // Not coerced: a non-string transcript is unusable (normalise checks it), never read as its digits.
    const transcript = (Object.hasOwn(entries, field) ? entries[field] : "") as string;
    const answer = format === null ? normaliseSpokenKeypadEntry({ transcript, locale: input.locale }) : normaliseSpokenAnswer({ field: format, transcript, locale: input.locale });
    const value = answer.status === "normalised" ? answer.value : "";
    const match = hexDigestsEqual(await input.hmac(`field:${field}:${value}`), input.subject?.knowledge[field] ?? "");
    ok = ok && match && answer.status === "normalised";
  }
  return ok;
}
