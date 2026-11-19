// Badge factors are plug-ins. Each factor kind says how it is entered, how many attempts a call
// gets, and which adapters it needs; Badge's settings turn each one on or off, and a flow step
// says which of them may count. A host adds its own factor (one the caller enters and code judges)
// with `badgeModule({ factors: [...] })`.
import type { SubjectRecord } from "../core/adapters.ts";
import { hexDigestsEqual, hmacSha256Hex } from "../core/hash.ts";
import { FACTOR_KINDS, FORBIDDEN_FACTOR_KINDS, type VerificationPolicy } from "../core/policy.ts";
import { isIntegerIn } from "../core/shape.ts";
import type { AdapterName, EngineRuntime } from "../core/runtime.ts";
import { isKeypadEntry, judgeKeypadWith } from "./knowledge.ts";

/** What the caller entered: one string (a PIN), or one value per field (keypad knowledge). */
export type FactorEntry = string | Readonly<Record<string, string>>;

export interface FactorJudgeInput {
  workspaceId: string;
  /** Null when the account number was not something a keypad can produce. */
  subjectKey: string | null;
  /** Null for an unknown subject. Judge it the same way, and give the same answer as a wrong entry. */
  subject: SubjectRecord | null;
  /** From a code path, never from the model. Discarded after judging. */
  entry: FactorEntry;
  /** HMAC-SHA256 under the workspace's knowledge key, hex. */
  hmac(data: string): string;
}

/** A factor the caller enters and code judges. The engine counts each attempt before judging it. */
export interface FactorPlugin {
  /** snake_case, 3 to 32 characters. Never a name for caller ID. */
  kind: string;
  summary: string;
  /** Attempts per call, 1 to 5. */
  maxAttemptsPerCall: number;
  /** Adapter names the judge needs. */
  adapters: readonly AdapterName[];
  judge(input: FactorJudgeInput): Promise<boolean>;
}

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

/** The stored digest of a subject's duress PIN: `HMAC(key, "duress:" + subjectKey + ":" + pin)`. */
export function duressDigest(knowledgeKey: string | Uint8Array, subjectKey: string, pin: string): string {
  return hmacSha256Hex(knowledgeKey, `duress:${subjectKey}:${pin}`);
}

/**
 * The `tag` every `pin` factor entry carries: an HMAC under the knowledge key of the entry's event
 * id and its outcome. The same shape for every outcome, so only the key holder can tell them apart.
 */
export function pinTag(hmac: (data: string) => string, eventId: string, outcome: PinOutcome): string {
  return hmac(JSON.stringify(["pin.tag", eventId, outcome]));
}

export interface BadgeSettings {
  /** The factors turned on. A factor that is off is refused everywhere, in flows and outside them. */
  factors: string[];
  /** Grant lifetime. Default 900 (15 minutes), at most 3600. */
  grantTtlSeconds?: number;
  /** Required when `pin` is on. */
  pin?: PinSettings;
}

/** How each built-in factor reaches the engine. Planned factors cannot be turned on yet. */
export const BUILT_IN_FACTORS: Readonly<Record<(typeof FACTOR_KINDS)[number], { entered: boolean; adapters: readonly AdapterName[]; planned?: string }>> = {
  keypad_knowledge: { entered: true, adapters: [] },
  pin: { entered: true, adapters: [] },
  carrier_identity_match: { entered: false, adapters: ["carrier"] },
  photo_id: { entered: false, adapters: ["identity", "messages"] },
  text_code: { entered: false, adapters: ["messages"], planned: "VER-2" },
  spoken_knowledge: { entered: true, adapters: [], planned: "VER-3" },
};

/** Factors whose match lets the engine text the number on file (a link only goes out after one). */
export const KNOWLEDGE_FACTORS: readonly string[] = ["keypad_knowledge", "pin"];

const PLUGIN_KIND = /^[a-z][a-z0-9_]{2,31}$/;

/** Every problem with a factor plug-in. */
export function checkFactorPlugin(plugin: FactorPlugin, taken: readonly string[]): string[] {
  const errors: string[] = [];
  if (!PLUGIN_KIND.test(plugin.kind)) errors.push(`factor kind ${JSON.stringify(plugin.kind)} must be snake_case, 3 to 32 characters`);
  if (FORBIDDEN_FACTOR_KINDS.includes(plugin.kind)) errors.push(`factor kind ${plugin.kind} would make caller ID a factor, which it never is`);
  if (taken.includes(plugin.kind)) errors.push(`factor kind ${plugin.kind} already exists`);
  if (!isIntegerIn(plugin.maxAttemptsPerCall, 1, 5)) errors.push(`factor ${plugin.kind}: maxAttemptsPerCall must be 1 to 5`);
  return errors;
}

/**
 * The PIN factor's judge: a keyed hash on file, or the host's verifier. Unknown subjects do the same
 * work. Every entry is compared with the PIN and the duress PIN digests alike, whether or not a
 * duress PIN is on file or turned on, so the work and the time never say which it was.
 */
export async function judgePin(rt: EngineRuntime, settings: PinSettings, input: FactorJudgeInput): Promise<PinOutcome> {
  const pin = typeof input.entry === "string" ? input.entry : "";
  const wellFormed = isKeypadEntry(pin) && pin.length >= settings.minDigits && pin.length <= settings.maxDigits;
  let match: boolean;
  let duress: boolean;
  let brokenSubject = false;
  if (settings.mode === "verifier") {
    // The verifier is asked every time, with a stand-in for a malformed entry or a non-keypad
    // account, so the answer's timing never says which it was. The stand-in's answer is ignored.
    const subjectKey = input.subjectKey ?? input.hmac("subject:");
    const answer = await rt.adapter("pinVerifier").verify({ workspaceId: input.workspaceId, subjectKey, pin: wellFormed ? pin : "0".repeat(settings.minDigits) });
    duress = answer.duress === true;
    match = answer.matched;
  } else {
    // Both digests on file are read from the store now, not from the call's copy of the subject, so
    // a reset (which removes both) since verification began counts. An unknown subject is looked up
    // the same way.
    const onFile = await rt.adapter("records").getSubject(input.workspaceId, input.subjectKey ?? input.hmac("subject:"));
    const entry = wellFormed ? pin : "";
    match = hexDigestsEqual(input.hmac(`pin:${input.subjectKey ?? ""}:${entry}`), onFile?.pinDigest ?? "");
    duress = hexDigestsEqual(input.hmac(`duress:${input.subjectKey ?? ""}:${entry}`), onFile?.duressDigest ?? "");
    // The two digests are keyed apart, so they are equal only on a subject imported wrongly.
    brokenSubject = hexDigestsEqual(onFile?.pinDigest ?? "", onFile?.duressDigest ?? "") && onFile?.pinDigest !== undefined;
  }
  // A subject on file implies a keypad-shaped account or a host's subject key, never the stand-in.
  if (!wellFormed || input.subject === null) return "fail";
  // An entry that is both the PIN and the duress PIN, in either mode, and a subject imported with
  // the two digests equal, are refused like a wrong PIN, with no alarm: neither a login nor an alarm.
  if ((match && duress) || brokenSubject) return "fail";
  if (duress && settings.duress !== undefined) return "duress";
  return match ? "pass" : "fail";
}

/** The keypad knowledge factor's judge: every configured field at once, one answer. */
export async function judgeKeypad(policy: VerificationPolicy, input: FactorJudgeInput): Promise<boolean> {
  const entries = typeof input.entry === "string" ? {} : input.entry;
  return judgeKeypadWith(input.hmac, input.subject, policy.keypadFields, entries);
}
