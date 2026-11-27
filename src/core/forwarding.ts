// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// What the host may forward for a call right now. This is the single place a host asks: it reads
// the session state and answers for the transcript, audio to speech-to-text, audio to the model and
// staff listen-in together, so no host code path judges the `sensitive` flag on its own. Pure.
import type { SensitiveReason, SessionState } from "./session.ts";

export interface Forwarding {
  /** The live transcript and the stored transcript. */
  transcript: boolean;
  /** Call audio sent to speech-to-text. */
  speechToText: boolean;
  /** Call audio sent to the model. */
  model: boolean;
  /** Staff listening in on the call. */
  listenIn: boolean;
  /**
   * Why forwarding is held: the open sensitive segment, `ended` once the call is over, or `unknown`
   * when there is no state to read or it is not one the engine writes. Null when everything may be
   * forwarded.
   */
  heldFor: SensitiveReason | "ended" | "unknown" | null;
}

const LIVE_PHASES: readonly unknown[] = ["open", "verifying", "filing", "paying"];
const REASONS: readonly unknown[] = ["keypad", "payment"];

/**
 * What the host may forward for the call in `state`. While `sensitive` is set (keypad entry, a
 * payment) and once the call has ended, nothing is forwarded; otherwise everything may be. A host
 * asks again after every engine call that can change the state. With no state (null, when the host
 * could not read it) or a state the engine never writes (an unknown phase, a missing or unknown
 * `sensitive`, say from an old or damaged store), nothing is forwarded either: it fails closed.
 */
export function forwardingFor(state: SessionState | null | undefined): Forwarding {
  const heldFor = heldReason(state);
  const allowed = heldFor === null;
  return { transcript: allowed, speechToText: allowed, model: allowed, listenIn: allowed, heldFor };
}

function heldReason(state: SessionState | null | undefined): Forwarding["heldFor"] {
  if (typeof state !== "object" || state === null) return "unknown";
  // Each field read once, and only as the state's own: the answer rests on the values it judged.
  const phase: unknown = Object.hasOwn(state, "phase") ? state.phase : undefined;
  const sensitive: unknown = Object.hasOwn(state, "sensitive") ? state.sensitive : undefined;
  if (phase === "ended") return "ended";
  if (!LIVE_PHASES.includes(phase)) return "unknown";
  // A payment always holds: a paying call without the hold (a call stored before the hold could no
  // longer be lifted) is not a state the engine writes, so it fails closed.
  if (phase === "paying") return sensitive === "payment" ? "payment" : "unknown";
  if (sensitive === null) return null;
  return REASONS.includes(sensitive) ? (sensitive as SensitiveReason) : "unknown";
}
