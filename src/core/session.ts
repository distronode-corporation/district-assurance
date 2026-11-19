// The call session and its state machine. Pure: `reduce` takes a state and an event and returns
// the next state, or throws `invalid_transition`. SPEC.md draws the same machine.
import { EngineError } from "./errors.ts";
import type { AssuranceLevel, FactorResult } from "./policy.ts";

export type SessionPhase = "open" | "verifying" | "filing" | "paying" | "ended";

export type SensitiveReason = "keypad" | "payment";

/**
 * How likely the caller's voice is synthetic, as the host's speech vendor scored it, in bands set
 * per vendor in Badge's settings (VER-14). `clear`: at or below the vendor's first threshold.
 * `spoken_off`: above it, `spoken_knowledge` stops counting toward a level. `level_1`: above the
 * second, the call is held to level 1. A call's band only ever goes up.
 */
export const SYNTHETIC_VOICE_BANDS = ["clear", "spoken_off", "level_1"] as const;

export type SyntheticVoiceBand = (typeof SYNTHETIC_VOICE_BANDS)[number];

/** The stricter of two bands: a later, lower score never lifts a cap. */
export function higherBand(a: SyntheticVoiceBand, b: SyntheticVoiceBand): SyntheticVoiceBand {
  return SYNTHETIC_VOICE_BANDS.indexOf(b) > SYNTHETIC_VOICE_BANDS.indexOf(a) ? b : a;
}

export interface Grant {
  grantId: string;
  level: AssuranceLevel;
  scopes: string[];
  /** ISO 8601. */
  issuedAt: string;
  expiresAt: string;
}

export interface SessionState {
  callId: string;
  workspaceId: string;
  phase: SessionPhase;
  /** The level of the last finished verification. Reset to 0 when the session is tainted. */
  level: AssuranceLevel;
  factors: FactorResult[];
  grant: Grant | null;
  /** Open while keypad entry or a payment is in progress: the host pauses transcripts and listen-in. */
  sensitive: SensitiveReason | null;
  /** Set once untrusted text (a webhook reply, a document) has entered the conversation. Sticky. */
  tainted: boolean;
  /** The highest synthetic voice band any score reached on this call: `clear` when none was reported. Sticky. */
  syntheticVoice: SyntheticVoiceBand;
  recordIds: string[];
  paymentIds: string[];
  startedAt: string;
  endedAt: string | null;
}

export type SessionEvent =
  /** `reset` drops earlier factors, for example when the caller keys a different account number. */
  | { type: "verification_started"; reset: boolean }
  | { type: "factor_recorded"; factor: FactorResult }
  | { type: "verification_finished"; level: AssuranceLevel; grant: Grant | null }
  | { type: "intake_started" }
  | { type: "intake_confirmed"; recordId: string }
  | { type: "intake_abandoned" }
  | { type: "sensitive_opened"; reason: SensitiveReason }
  | { type: "sensitive_closed" }
  | { type: "payment_requested"; paymentId: string }
  | { type: "payment_settled"; paymentId: string }
  | { type: "untrusted_content"; source: string }
  /**
   * A synthetic voice score, as its band. Badge computes `ceiling`, the highest level the call may
   * hold under its highest band, and `scopes`, the policy's scopes at that level. A level or grant
   * above the ceiling is lowered to it at once; nothing is ever raised.
   */
  | { type: "synthetic_voice_scored"; band: SyntheticVoiceBand; ceiling: AssuranceLevel; scopes: string[] }
  | { type: "call_ended"; at: string };

/** The phases each event may arrive in. Anything else is `invalid_transition`. */
export const ALLOWED_PHASES: Record<SessionEvent["type"], readonly SessionPhase[]> = {
  verification_started: ["open"],
  factor_recorded: ["verifying"],
  verification_finished: ["verifying"],
  intake_started: ["open"],
  intake_confirmed: ["filing"],
  intake_abandoned: ["filing"],
  sensitive_opened: ["verifying"],
  sensitive_closed: ["verifying", "paying"],
  payment_requested: ["open"],
  payment_settled: ["paying"],
  untrusted_content: ["open", "verifying", "filing", "paying"],
  synthetic_voice_scored: ["open", "verifying", "filing", "paying"],
  call_ended: ["open", "verifying", "filing", "paying"],
};

export function newSession(callId: string, workspaceId: string, startedAt: string): SessionState {
  return {
    callId,
    workspaceId,
    phase: "open",
    level: 0,
    factors: [],
    grant: null,
    sensitive: null,
    tainted: false,
    syntheticVoice: "clear",
    recordIds: [],
    paymentIds: [],
    startedAt,
    endedAt: null,
  };
}

export function canApply(state: SessionState, event: SessionEvent): boolean {
  return ALLOWED_PHASES[event.type].includes(state.phase);
}

export function reduce(state: SessionState, event: SessionEvent): SessionState {
  if (!canApply(state, event)) {
    throw new EngineError("invalid_transition", `${event.type} is not allowed while ${state.phase}`);
  }
  switch (event.type) {
    case "verification_started":
      // A tainted session starts over too: earlier factors were collected before the untrusted text.
      return { ...state, phase: "verifying", factors: event.reset || state.tainted ? [] : state.factors };
    case "factor_recorded":
      return { ...state, factors: [...state.factors, event.factor] };
    case "verification_finished":
      return { ...state, phase: "open", sensitive: null, level: event.level, grant: event.grant };
    case "intake_started":
      return { ...state, phase: "filing" };
    case "intake_confirmed":
      return { ...state, phase: "open", recordIds: [...state.recordIds, event.recordId] };
    case "intake_abandoned":
      return { ...state, phase: "open" };
    case "sensitive_opened":
      return { ...state, sensitive: event.reason };
    case "sensitive_closed":
      return { ...state, sensitive: null };
    case "payment_requested":
      return { ...state, phase: "paying", sensitive: "payment", paymentIds: [...state.paymentIds, event.paymentId] };
    case "payment_settled":
      return { ...state, phase: "open", sensitive: null };
    case "untrusted_content":
      return { ...state, tainted: true, level: 0, grant: null };
    case "synthetic_voice_scored":
      return {
        ...state,
        syntheticVoice: higherBand(state.syntheticVoice, event.band),
        level: Math.min(state.level, event.ceiling) as AssuranceLevel,
        grant: heldTo(state.grant, event.ceiling, event.scopes),
      };
    case "call_ended":
      return { ...state, phase: "ended", sensitive: null, grant: null, endedAt: event.at };
  }
}

/** A grant held to a ceiling: unchanged at or below it, else lowered to it with only the scopes it reaches, or dropped at 0. */
function heldTo(grant: Grant | null, ceiling: AssuranceLevel, scopes: readonly string[]): Grant | null {
  if (grant === null || grant.level <= ceiling) return grant;
  return ceiling === 0 ? null : { ...grant, level: ceiling, scopes: grant.scopes.filter((scope) => scopes.includes(scope)) };
}

/** A JSON-safe copy of a state, for hosts and logs. Holds no secrets by construction. */
export function snapshot(state: SessionState): SessionState {
  return structuredClone(state);
}
