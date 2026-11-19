// Errors the engine throws. Two kinds only: work that is planned but not built yet, and a refusal
// with a stable code a host can branch on.

/**
 * Thrown by every entry point whose logic is later work. `issue` names the ROADMAP.md issue that
 * builds it, so a host that reaches one knows where the work is tracked.
 */
export class NotImplementedError extends Error {
  readonly feature: string;
  readonly issue: string;

  constructor(feature: string, issue: string) {
    super(`${feature} is not implemented yet (ROADMAP.md, ${issue})`);
    this.name = "NotImplementedError";
    this.feature = feature;
    this.issue = issue;
  }
}

export type EngineErrorCode =
  /** No call with that id is open on this engine. */
  | "unknown_call"
  /** The event is not allowed in the session's current phase (SPEC.md, the state machine). */
  | "invalid_transition"
  /** The caller's grant does not cover the scope. */
  | "scope_denied"
  /** An argument failed validation: a policy, a form, an amount, a field value. */
  | "invalid_input"
  /** A precondition of the step is not met, for example a link before the keypad checks pass. */
  | "precondition_failed"
  /** The module is installed but turned off in the workspace's config, or not installed. */
  | "module_disabled"
  /** Too many flows that need a money, contact or access scope started this hour; the same answer whichever limit was hit (VER-15). */
  | "rate_limited"
  /** Another process changed the call at the same time, every retry included (SessionStore). */
  | "conflict";

/** A refusal. The message is for logs; hosts branch on `code`, never on the message. */
export class EngineError extends Error {
  readonly code: EngineErrorCode;

  constructor(code: EngineErrorCode, message: string) {
    super(message);
    this.name = "EngineError";
    this.code = code;
  }
}

/**
 * A flow start refused by its hourly limit (VER-15), with the call it was refused on: `startCall`
 * still opens the call, with the flow failed, so the host needs its id to end it. The message is the
 * same whichever limit was hit.
 */
export class RateLimitedError extends EngineError {
  readonly callId: string;

  constructor(callId: string) {
    super("rate_limited", "too many flows of this kind started in the last hour; try again later");
    this.callId = callId;
  }
}
