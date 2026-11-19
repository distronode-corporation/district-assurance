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

/**
 * How long a send may hold the end of the call (VER-2): the SMS adapter's answer and the ledger
 * entry after it are waited for this long, then the call may end, and a later answer writes nothing.
 */
export const TEXT_SEND_HOLD_SECONDS = 30;

/** Tries per code; after the last, the code is not judged, even the right one. */
export const TEXT_CODE_MAX_TRIES = 5;

/** Sends allowed across calls: per subject, and per calling number when the host gave one. */
export const TEXT_CODE_LIMITS: Readonly<Record<CodeSendKey["scope"], { max: number; windowSeconds: number; minIntervalSeconds: number }>> = {
  subject: { max: 5, windowSeconds: 86_400, minIntervalSeconds: 60 },
  number: { max: 10, windowSeconds: 86_400, minIntervalSeconds: 60 },
};

/** Why a send was refused, or that the SMS adapter failed it. Written to the ledger only; the caller is never told. */
export type TextCodeRefusal = "country" | "subject_limit" | "number_limit" | "send_failed";

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

/**
 * Counts the send against every limit, and says why it was refused, or null. Both limits are asked
 * every time, so a send the subject's limit refuses makes the same store calls before the reply as
 * one that goes out (the time never says a limit applied); it then counts on the number too.
 */
async function refusalFor(rt: EngineRuntime, phoneOnFile: string, subjectKey: string, numberKey: string | null, at: string): Promise<TextCodeRefusal | null> {
  if (!textCodeDestinationAllowed(rt.policy, phoneOnFile)) return "country";
  const codes = rt.adapter("codes");
  const take = (key: CodeSendKey) => codes.take({ workspaceId: rt.workspaceId, key, at, ...TEXT_CODE_LIMITS[key.scope] });
  const subjectTaken = await take({ scope: "subject", key: subjectKey });
  const numberTaken = numberKey === null ? true : await take({ scope: "number", key: numberKey });
  return !subjectTaken ? "subject_limit" : !numberTaken ? "number_limit" : null;
}

/**
 * Sends a code to the number on file. Always answers `{ sent: true }`: a send refused by the
 * country allow-list or a limit leaves the call holding a code that never matches (or the code
 * still live from an earlier send), so the caller hears the same thing and gets the same tries.
 * Each send is counted against the limits before the text goes out; a send that fails after that
 * stays counted. The answer never waits for the SMS adapter: a sent code and a refused one take the
 * same steps up to the reply, and the text goes out, and the ledger entry is written, after it.
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
    // Sent or refused alike, so the steps are the same: the call ends only once its entry is written.
    slice.textSend = { sendId, until: new Date(now.getTime() + TEXT_SEND_HOLD_SECONDS * 1000).toISOString() };
  });
  // After the reply, for a sent code and a refused one alike, so the SMS adapter's time never says which.
  setImmediate(() => void finishSend(rt, callId, code, refusal, { to: subject.phoneOnFile, locale: before.locale, sendId }).catch(() => undefined));
  return { sent: true };
}

/** Texts the code, if the send was not refused, then writes what happened to the ledger. */
async function finishSend(rt: EngineRuntime, callId: string, code: string | null, refusal: TextCodeRefusal | null, send: { to: string; locale: Locale; sendId: string }): Promise<void> {
  let outcome = refusal;
  if (code !== null) {
    const body = textCodeText(send.locale, code);
    await rt
      .adapter("messages")
      .sendText({ to: send.to, body, purpose: "one_time_code", idempotencyKey: rt.idempotencyKey(callId, "text_code", send.sendId) })
      .catch(() => (outcome = "send_failed"));
  }
  await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    if (s.textSend?.sendId === send.sendId) delete s.textSend;
    // Past the hold the call may have ended: its receipt is the last entry, so nothing follows it.
    if (draft.record.state.phase === "ended") return;
    if (outcome === null) draft.emit("verification.code_sent", "code", {});
    else draft.emit("verification.code_refused", "code", { reason: outcome });
  });
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
  return rt.update(callId, (draft) => {
    // Read the clock on each attempt, so a slow read or a retry cannot judge a code that has expired.
    const now = rt.clock.now();
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
