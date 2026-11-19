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
  "flow.rate_limited",
  "verification.started",
  "verification.factor",
  "verification.factor_error",
  "verification.carrier_checked",
  "verification.locked",
  "verification.callback_started",
  "verification.callback_finished",
  "verification.unlocked",
  "verification.finished",
  "identity.link_sent",
  "verification.code_sent",
  "verification.code_refused",
  "grant.issued",
  "pin.enrolled",
  "pin.reset",
  "duress.cleared",
  "session.tainted",
  "sensitive.opened",
  "sensitive.closed",
  "intake.started",
  "intake.confirmed",
  "intake.abandoned",
  "record.filing_failed",
  "delivery.attempted",
  "redaction.applied",
  "payment.amount_read_back",
  "payment.amount_confirmed",
  "payment.link_sent",
  "payment.link_expired",
  "payment.outcome_ignored",
  "payment.settled",
  "payment.refunded",
  "payment.disputed",
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
  "consent.revoked",
  "consent.unrecorded",
  "call.ended",
  "receipt.issued",
  "receipt.link_texted",
  "contact.notice_owed",
  "contact.notice_sent",
  "module.event",
  "subject.erased",
  "subject.erasure_completed",
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
