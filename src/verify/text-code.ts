// Texted one-time codes (VER-2): the second factor for level 2, and the easiest way to abuse a
// phone line, so the limits ship with the feature.
//
// A code goes only to the subject's number on file, only after a keypad or PIN match, and only to
// a country the policy allows. Sends are limited per subject and per calling number across calls
// (the CodeStore), and a refused send looks exactly like a sent one to the caller: the host hears
// `{ sent: true }` either way, and the call holds a code that never matches, with the same expiry
// and the same tries. The code is kept only as an HMAC bound to the call, expires after 10
// minutes, allows 5 tries and is used once. Whether a passed code counts is the policy's carrier
// rule (`textCodeTrusted`), as for any texted code.
import { randomInt } from "node:crypto";

import type { CodeSendKey, SubjectRecord } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import { hexDigestsEqual } from "../core/hash.ts";
import type { VerificationPolicy } from "../core/policy.ts";
import type { CallRecord, EngineRuntime, Locale } from "../core/runtime.ts";
import { canApply } from "../core/session.ts";
import { BADGE, allowFactor, assertSameVerification, matchedSubject, type BadgeSlice, type KeypadResult } from "./badge.ts";

/** Digits in a code. */
export const TEXT_CODE_DIGITS = 6;

/** How long a code may be used. */
export const TEXT_CODE_TTL_SECONDS = 600;

/** Tries per code; after the last, the code is not judged, even the right one. */
export const TEXT_CODE_MAX_TRIES = 5;

/** Sends allowed across calls: per subject, and per calling number when the host gave one. */
export const TEXT_CODE_LIMITS: Readonly<Record<CodeSendKey["scope"], { max: number; windowSeconds: number; minIntervalSeconds: number }>> = {
  subject: { max: 5, windowSeconds: 86_400, minIntervalSeconds: 60 },
  number: { max: 10, windowSeconds: 86_400, minIntervalSeconds: 60 },
};

/** Why a send was refused. Written to the ledger only; the caller is never told. */
export type TextCodeRefusal = "country" | "subject_limit" | "number_limit";

/** The code a call holds, in Badge's part of the call record. */
export interface TextCodeState {
  /** HMAC of the code, bound to the call. Null when the send was refused: a code that never matches. */
  digest: string | null;
  /** ISO 8601. */
  expiresAt: string;
  /** Judged tries. A used code is set to the limit, so it is never judged again. */
  tries: number;
}

/** Whether the policy lets a code go to this number on file. No list means nowhere. */
export function textCodeDestinationAllowed(policy: VerificationPolicy, phoneOnFile: string): boolean {
  return (policy.textCodeCountryCodes ?? []).some((prefix) => phoneOnFile.startsWith(`+${prefix}`));
}

/** The text, built by code in the call's locale. */
export function textCodeText(locale: Locale, code: string): string {
  return locale === "fr"
    ? `Votre code de vérification à usage unique : ${code}. Il expire dans 10 minutes. Ne le communiquez à personne.`
    : `Your one-time verification code: ${code}. It expires in 10 minutes. Do not share it.`;
}

/** A code's HMAC under the knowledge key, bound to the call: the same digits on another call never match. */
function codeDigest(rt: EngineRuntime, callId: string, code: string): string {
  return rt.hmac(`text_code:${callId}:${code}`);
}

function newCode(): string {
  return randomInt(0, 10 ** TEXT_CODE_DIGITS)
    .toString()
    .padStart(TEXT_CODE_DIGITS, "0");
}

/** What a send needs: the text_code factor on and allowed by the step, a keypad or PIN match, and a call that is verifying. */
function assertCanSend(rt: EngineRuntime, record: CallRecord): SubjectRecord {
  allowFactor(rt, record, "text_code");
  const subject = matchedSubject(record);
  if (!canApply(record.state, { type: "factor_recorded", factor: { kind: "text_code", passed: false, at: rt.now() } })) {
    throw new EngineError("invalid_transition", `a code is sent while verifying, not while ${record.state.phase}`);
  }
  return subject;
}

/** Counts the send against each limit in turn, and says why it was refused, or null. */
async function refusalFor(rt: EngineRuntime, phoneOnFile: string, subjectKey: string, numberKey: string | null, at: string): Promise<TextCodeRefusal | null> {
  if (!textCodeDestinationAllowed(rt.policy, phoneOnFile)) return "country";
  const codes = rt.adapter("codes");
  const take = (key: CodeSendKey) => codes.take({ workspaceId: rt.workspaceId, key, at, ...TEXT_CODE_LIMITS[key.scope] });
  if (!(await take({ scope: "subject", key: subjectKey }))) return "subject_limit";
  if (numberKey !== null && !(await take({ scope: "number", key: numberKey }))) return "number_limit";
  return null;
}

/**
 * Sends a code to the number on file. Always answers `{ sent: true }`: a send refused by the
 * country allow-list or a limit leaves the call holding a code that never matches (or the code
 * still live from an earlier send), so the caller hears the same thing and gets the same tries.
 * Each send is counted against the limits before the text goes out; a send that fails after that
 * stays counted.
 */
export async function sendTextCode(rt: EngineRuntime, callId: string): Promise<{ sent: true }> {
  const before = await rt.read(callId);
  const subject = assertCanSend(rt, before);
  const s = before.modules[BADGE] as unknown as BadgeSlice;
  const now = rt.clock.now();
  const refusal = await refusalFor(rt, subject.phoneOnFile, subject.subjectKey, s.numberKey, now.toISOString());
  const code = refusal === null ? newCode() : null;
  const sendId = rt.ids.next("code");
  await rt.update(callId, (draft) => {
    assertCanSend(rt, draft.record);
    const slice = draft.slice<BadgeSlice>(BADGE);
    assertSameVerification(slice, s.epoch);
    // A refused send never replaces a code still live, so a send that lost a race cannot void the one that won.
    if (code !== null || !isLive(slice.textCode, now)) {
      const expiresAt = new Date(now.getTime() + TEXT_CODE_TTL_SECONDS * 1000).toISOString();
      slice.textCode = { digest: code === null ? null : codeDigest(rt, callId, code), expiresAt, tries: 0 };
    }
  });
  if (code !== null) {
    const body = textCodeText(before.locale, code);
    await rt.adapter("messages").sendText({ to: subject.phoneOnFile, body, purpose: "one_time_code", idempotencyKey: rt.idempotencyKey(callId, "text_code", sendId) });
  }
  await rt.update(callId, (draft) => {
    if (refusal === null) draft.emit("verification.code_sent", "code", {});
    else draft.emit("verification.code_refused", "code", { reason: refusal });
  });
  return { sent: true };
}

function isLive(held: TextCodeState | null, now: Date): boolean {
  return held !== null && held.tries < TEXT_CODE_MAX_TRIES && now.getTime() < Date.parse(held.expiresAt);
}

/**
 * Judges a code the caller keyed and records a `text_code` factor. A try is counted and judged in
 * one write. An expired, used or exhausted code is not judged (`locked`). A malformed entry is a
 * try, and fails. A refused send's code fails every try, as a wrong code does.
 */
export async function checkTextCode(rt: EngineRuntime, callId: string, code: string): Promise<KeypadResult> {
  const entry = codeDigest(rt, callId, /^[0-9]{6}$/.test(code) ? code : "");
  const now = rt.clock.now();
  return rt.update(callId, (draft) => {
    allowFactor(rt, draft.record, "text_code");
    draft.assertCan({ type: "factor_recorded", factor: { kind: "text_code", passed: false, at: rt.now() } });
    const s = draft.slice<BadgeSlice>(BADGE);
    const held = s.textCode;
    if (held === null) throw new EngineError("precondition_failed", "no code was sent for this verification");
    if (!isLive(held, now)) return { matched: false, locked: true };
    held.tries++;
    // A refused send has no digest; an empty one never equals an HMAC.
    const passed = hexDigestsEqual(entry, held.digest ?? "");
    if (passed) held.tries = TEXT_CODE_MAX_TRIES;
    draft.apply({ type: "factor_recorded", factor: { kind: "text_code", passed, at: rt.now() } });
    draft.emit("verification.factor", "code", { kind: "text_code", passed });
    return { matched: passed, locked: !passed && held.tries >= TEXT_CODE_MAX_TRIES };
  });
}
