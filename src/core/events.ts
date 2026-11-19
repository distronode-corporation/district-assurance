// The audit events the engine writes. Each one names what happened and how, never a value: no
// digits keyed, no answers on file, no card data, no phone numbers.
import type { JsonValue } from "./canonical.ts";

export const ENGINE_EVENTS = [
  "call.started",
  "flow.started",
  "flow.step_completed",
  "flow.completed",
  "flow.failed",
  "flow.abandoned",
  "verification.started",
  "verification.factor",
  "verification.carrier_checked",
  "verification.finished",
  "identity.link_sent",
  "grant.issued",
  "session.tainted",
  "sensitive.opened",
  "sensitive.closed",
  "intake.started",
  "intake.confirmed",
  "intake.abandoned",
  "redaction.applied",
  "payment.link_sent",
  "payment.link_expired",
  "payment.outcome_ignored",
  "payment.settled",
  "consent.recorded",
  "access.issued",
  "access.delivered",
  "access.refused",
  "access.unknown",
  "access.failed",
  "access.code_spent",
  "stepup.issued",
  "stepup.exchanged",
  "stepup.refused",
  "stepup.failed",
  "call.ended",
  "receipt.issued",
  "module.event",
] as const;

export type EngineEventName = (typeof ENGINE_EVENTS)[number];

export type Actor = "caller" | "ai" | "code" | "member" | "system";

export interface EngineEvent {
  name: EngineEventName;
  callId: string;
  actor: Actor;
  /** ISO 8601. */
  at: string;
  detail: { [key: string]: JsonValue };
}

export type EventListener = (event: EngineEvent) => void;
