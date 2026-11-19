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
   * Why forwarding is held: the open sensitive segment, or `ended` once the call is over. Null when
   * everything may be forwarded.
   */
  heldFor: SensitiveReason | "ended" | null;
}

/**
 * What the host may forward for the call in `state`. While `sensitive` is set (keypad entry, a
 * payment) and once the call has ended, nothing is forwarded; otherwise everything may be. A host
 * asks again after every engine call that can change the state, and fails closed (forwards
 * nothing) when it cannot read the state.
 */
export function forwardingFor(state: SessionState): Forwarding {
  const heldFor = state.phase === "ended" ? "ended" : state.sensitive;
  const allowed = heldFor === null;
  return { transcript: allowed, speechToText: allowed, model: allowed, listenIn: allowed, heldFor };
}
