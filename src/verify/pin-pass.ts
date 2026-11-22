// PIN passes: one caller, one phone call, two engine calls. A host that runs a sign-in (an owner's
// PIN on the business's line) on one engine call and then a flow on another call of the same
// phone call can carry the PIN factor across, once, within 5 minutes of the PIN's pass, instead of
// asking for the PIN again. The PIN factor only: every other factor the second call's policy asks
// for (a texted or emailed code, a carrier match) is still needed there.
//
// The call that saw the PIN pass issues a token (`issuePinPass`): 32 random bytes, of which it
// keeps only the SHA-256, bound to it as a session store reference, so any process of the
// workspace can find it and nothing stored can be replayed as the token. The host hands the token
// to the second call in memory (it is a bearer secret, like an upload link), never through the
// model, and that call redeems it (`reusePin`), once: its redemption is a reference the first
// redeemer binds, so of two at once exactly one wins. The engine checks everything else against the
// first call's own record: same subject, same calling number, no taint, a voice score that did not
// hold it to level 1, and the PIN not locked since.
import { randomBytes } from "node:crypto";

import type { AttemptCounterKey } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import { hexDigestsEqual, sha256Hex } from "../core/hash.ts";
import type { CallRecord, EngineRuntime } from "../core/runtime.ts";
import { BADGE, PIN_PASS_MAX_SECONDS, allowFactor, assertSameVerification, type BadgeSlice, type PinPassRecord } from "./badge.ts";
import { counterKeys, currentLock, lockoutOf } from "./counters.ts";
import { duressFlagKey, hiddenCounterKey, hiddenHardLock, hiddenWindowStart, isUnderDuress } from "./duress-flag.ts";
import type { BadgeSettings } from "./factors.ts";

/** A PIN pass token: 32 random bytes in unpadded base64url. */
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

/** Why a PIN pass was not reused, as the ledger names it. Never which value differed. */
export type PinReuseRefusal = "unknown" | "same_call" | "expired" | "used" | "tainted" | "voice" | "subject" | "number" | "locked";

/** What the session store binds a PIN pass under: its token's SHA-256, never the token. */
function passRef(tokenHash: string): string {
  return `pin_pass:${tokenHash}`;
}

/** What the call that redeemed a PIN pass binds, first redeemer wins. */
function usedRef(tokenHash: string): string {
  return `pin_pass_used:${tokenHash}`;
}

/**
 * Issues the PIN pass of a call whose PIN factor passed in its current verification, at most 5
 * minutes ago, on a call that has not ended and was never tainted. One per call, and never for a
 * PIN this call itself reused. A duress entry (VER-12) gets a pass like any other, so the caller
 * cannot tell, and the call that reuses it becomes a duress call. The token is returned once and
 * kept nowhere; the ledger gets `verification.pin_pass_issued` with its expiry.
 */
export async function issuePinPass(rt: EngineRuntime, callId: string): Promise<{ token: string; expiresAt: string }> {
  rt.settings(BADGE);
  const token = randomBytes(32).toString("base64url");
  const tokenHash = sha256Hex(token);
  // Bound first: a bind that fails leaves nothing on the call, so the host may ask again. A
  // reference left bound to a call whose write then failed finds no pass there ("unknown").
  await rt.bindRef(passRef(tokenHash), callId);
  const { expiresAt } = await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    const state = draft.record.state;
    if (state.phase === "ended") throw new EngineError("invalid_transition", "the call has ended");
    if (state.tainted) throw new EngineError("precondition_failed", "untrusted content entered the call: its PIN is not passed on");
    if (s.pinPass !== undefined) throw new EngineError("precondition_failed", "this call has issued its PIN pass already");
    if (s.pinReuse !== undefined) throw new EngineError("precondition_failed", "a PIN reused from another call is not passed on again");
    const pin = state.factors.filter((f) => f.kind === "pin").at(-1);
    if (pin === undefined || !pin.passed || !s.knowledgeMatched) throw new EngineError("precondition_failed", "no PIN passed in this call's verification");
    const until = new Date(Date.parse(pin.at) + PIN_PASS_MAX_SECONDS * 1000).toISOString();
    if (rt.clock.now().getTime() >= Date.parse(until)) throw new EngineError("precondition_failed", "the PIN passed more than 5 minutes ago");
    s.pinPass = { tokenHash, subjectKey: s.subjectKey!, numberKey: s.numberKey, passedAt: pin.at, expiresAt: until, taints: s.taints ?? 0, duress: s.duress !== undefined };
    draft.emit("verification.pin_pass_issued", "code", { expiresAt: until });
    return { expiresAt: until };
  });
  return { token, expiresAt };
}

/**
 * Takes a PIN pass another call issued as this call's PIN factor (Badge's `pin.reuse` on, the
 * `pin` factor allowed by the current `badge.verify` step, a verification running for a subject).
 * `{reused: true}` records a passed `pin` factor, marked as reused, which also counts as the keypad
 * or PIN match that lets a code or a link go to the subject on file. `{reused: false}` records
 * nothing but `verification.pin_reuse_refused` with the reason, and the host asks for the PIN as
 * usual. A token that is not one is `invalid_input`. Redeeming the same token again on the call
 * that redeemed it answers `{reused: true}` and records nothing more.
 */
export async function reusePin(rt: EngineRuntime, callId: string, token: string): Promise<{ reused: boolean }> {
  const settings = rt.settings<BadgeSettings>(BADGE);
  if (typeof token !== "string" || !TOKEN.test(token)) throw new EngineError("invalid_input", "token must be a PIN pass token");
  const before = await rt.read(callId);
  allowFactor(rt, before, "pin");
  const reuse = settings.pin!.reuse;
  if (reuse === undefined) throw new EngineError("precondition_failed", "PIN reuse is off: Badge's pin.reuse is not set");
  const current = before.modules[BADGE] as unknown as BadgeSlice | undefined;
  if (current === undefined) throw new EngineError("module_disabled", `${BADGE} was off when this call started`);
  if (before.state.phase !== "verifying" || current.subjectKey === null) throw new EngineError("invalid_transition", "a PIN pass is reused in a running verification, for a subject");
  const tokenHash = sha256Hex(token);
  if (current.pinReuse !== undefined && hexDigestsEqual(current.pinReuse.tokenHash, tokenHash)) return { reused: true };
  // A pass this call recorded once, whose factor a restart dropped since, is never recorded again.
  const judged = (current.pinPassesSpent ?? []).includes(tokenHash) ? "used" : await judge(rt, callId, current, tokenHash, Math.min(reuse.maxAgeSeconds, PIN_PASS_MAX_SECONDS));
  if (typeof judged === "string") {
    await rt.update(callId, (draft) => draft.emit("verification.pin_reuse_refused", "code", { reason: judged }));
    return { reused: false };
  }
  const { fromCallId, passedAt, duress } = judged;
  await rt.update(callId, (draft) => {
    const s = draft.slice<BadgeSlice>(BADGE);
    allowFactor(rt, draft.record, "pin");
    // The verification it was judged for, untouched since: a restart and a taint each move the epoch on.
    assertSameVerification(s, current.epoch);
    // A concurrent redemption of the same pass on this call recorded it first: this one is that one.
    if ((s.pinPassesSpent ?? []).includes(tokenHash)) return;
    const factor = { kind: "pin", passed: true, at: rt.now() };
    draft.assertCan({ type: "factor_recorded", factor });
    draft.apply({ type: "factor_recorded", factor });
    s.knowledgeMatched = true;
    // With the duress PIN turned off on this config, its list of scopes to refuse is unknown: every scope is refused (fail closed).
    if (duress) s.duress ??= { refuseScopes: settings.pin!.duress === undefined ? Object.keys(rt.policy.scopes) : [...settings.pin!.duress.refuseScopes] };
    s.pinReuse = { tokenHash, fromCallId, passedAt };
    s.pinPassesSpent = [...(s.pinPassesSpent ?? []), tokenHash];
    draft.emit("verification.factor", "code", { kind: "pin", passed: true, reused: true, fromCallId }, duress ? "duress" : "pass");
  });
  return { reused: true };
}

/**
 * Checks a PIN pass against the call that issued it and spends it, or names why not. Spent last,
 * after every other check, so a refused pass stays usable for the call it was meant for.
 */
async function judge(
  rt: EngineRuntime,
  callId: string,
  current: BadgeSlice,
  tokenHash: string,
  maxAgeSeconds: number,
): Promise<PinReuseRefusal | { fromCallId: string; passedAt: string; duress: boolean }> {
  const fromCallId = await rt.resolveRef(passRef(tokenHash));
  if (fromCallId === null) return "unknown";
  if (fromCallId === callId) return "same_call";
  const first = await issuer(rt, fromCallId, tokenHash);
  if (typeof first === "string") return first;
  const pass = first.pass;
  const now = rt.clock.now();
  if (now.getTime() - Date.parse(pass.passedAt) > maxAgeSeconds * 1000) return "expired";
  const untrusted = distrusted(first.record, first.badge, pass);
  if (untrusted !== null) return untrusted;
  if (pass.subjectKey !== current.subjectKey) return "subject";
  if (pass.numberKey !== current.numberKey) return "number";
  if ((await pinLock(rt, current)) !== null) return "locked";
  const duress = pass.duress || (await isUnderDuress(rt.adapter("counters"), duressFlagKey(rt.workspaceId, pass.subjectKey)));
  const spent = usedRef(tokenHash);
  await rt.bindRef(spent, callId);
  if ((await rt.resolveRef(spent)) !== callId) return "used";
  // Read again once spent, right before the factor is written: a taint or a voice band that landed
  // on the issuing call while the counters and the binding were asked refuses it (the pass stays spent).
  const again = await issuer(rt, fromCallId, tokenHash);
  if (typeof again === "string") return again;
  const late = distrusted(again.record, again.badge, again.pass);
  if (late !== null) return late;
  return { fromCallId, passedAt: pass.passedAt, duress };
}

/** The issuing call's record and its pass, or `unknown` for a call removed since or a record that no longer holds the pass. */
async function issuer(rt: EngineRuntime, fromCallId: string, tokenHash: string): Promise<"unknown" | { record: CallRecord; badge: BadgeSlice; pass: PinPassRecord }> {
  let record: CallRecord;
  try {
    record = await rt.read(fromCallId);
  } catch (error) {
    // The issuing call was removed since (its session retention): nothing is left to check against.
    if (error instanceof EngineError && error.code === "unknown_call") return "unknown";
    throw error;
  }
  const badge = record.modules[BADGE] as unknown as BadgeSlice | undefined;
  const pass = badge?.pinPass;
  if (pass === undefined || !hexDigestsEqual(pass.tokenHash, tokenHash)) return "unknown";
  return { record, badge: badge!, pass };
}

/** Why the issuing call no longer passes its PIN on: a taint since the pass was issued, or a level 1 voice band (VER-14). */
function distrusted(record: CallRecord, badge: BadgeSlice, pass: PinPassRecord): "tainted" | "voice" | null {
  if (record.state.tainted || (badge.taints ?? 0) !== pass.taints) return "tainted";
  // A call a synthetic voice score held to level 1 passes nothing on: the voice is not trusted.
  return (record.state.syntheticVoice ?? "clear") === "level_1" ? "voice" : null;
}

/** A lock on the PIN now, for this call's subject or calling number, as a PIN entry would meet it (hidden counter included). */
async function pinLock(rt: EngineRuntime, current: BadgeSlice): Promise<unknown> {
  const settings = rt.settings<BadgeSettings>(BADGE);
  const counters = rt.adapter("counters");
  const lockout = lockoutOf(settings.lockout);
  const now = rt.clock.now();
  const keys: AttemptCounterKey[] = counterKeys(rt.workspaceId, "pin", current);
  const visible = await currentLock(counters, lockout, keys, now);
  if (visible !== null || settings.pin!.duress === undefined) return visible;
  const hidden = hiddenCounterKey(rt.workspaceId, "pin", current.subjectKey!);
  return hiddenHardLock(lockout, await counters.get(hidden, hiddenWindowStart(lockout, now)), now);
}
