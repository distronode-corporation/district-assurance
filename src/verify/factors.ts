// Badge factors are plug-ins. Each factor kind says how it is entered, how many attempts a call
// gets, and which adapters it needs; Badge's settings turn each one on or off, and a flow step
// says which of them may count. A host adds its own factor (one the caller enters and code judges)
// with `badgeModule({ factors: [...] })` or, after the engine is built, `engine.useFactor`. The
// plug-in types and their checks live in the core (core/module.ts), where the registry uses them.
import { hexDigestsEqual } from "../core/hash.ts";
import type { FactorJudgeInput } from "../core/module.ts";
import { FACTOR_KINDS, type VerificationPolicy } from "../core/policy.ts";
import type { AdapterName, EngineRuntime } from "../core/runtime.ts";
import { isKeypadEntry, judgeKeypadWith } from "./knowledge.ts";

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

/** The PIN factor's judge: a keyed hash on file, or the host's verifier. Unknown subjects do the same work. */
export async function judgePin(rt: EngineRuntime, settings: PinSettings, input: FactorJudgeInput): Promise<boolean> {
  const pin = typeof input.entry === "string" ? input.entry : "";
  const wellFormed = isKeypadEntry(pin) && pin.length >= settings.minDigits && pin.length <= settings.maxDigits;
  if (settings.mode === "verifier") {
    // The verifier is asked every time, with a stand-in for a malformed entry or a non-keypad
    // account, so the answer's timing never says which it was. The stand-in's answer is ignored.
    const usable = input.subjectKey !== null && wellFormed;
    const subjectKey = input.subjectKey ?? input.hmac("subject:");
    const { matched } = await rt.adapter("pinVerifier").verify({ workspaceId: input.workspaceId, subjectKey, pin: wellFormed ? pin : "0".repeat(settings.minDigits) });
    return matched && usable && input.subject !== null;
  }
  const digest = input.hmac(`pin:${input.subjectKey ?? ""}:${wellFormed ? pin : ""}`);
  const match = hexDigestsEqual(digest, input.subject?.pinDigest ?? "");
  return match && wellFormed && input.subject !== null;
}

/** The keypad knowledge factor's judge: every configured field at once, one answer. */
export async function judgeKeypad(policy: VerificationPolicy, input: FactorJudgeInput): Promise<boolean> {
  const entries = typeof input.entry === "string" ? {} : input.entry;
  return judgeKeypadWith(input.hmac, input.subject, policy.keypadFields, entries);
}
