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
  "payment.settled",
  "consent.recorded",
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

/** An event as the listener sees it: after its ledger entry was appended, with that entry's id and seq. */
export interface DeliveredEvent extends EngineEvent {
  /** The ledger entry's event id. The same event can be delivered more than once; this id says so. */
  eventId: string;
  /** The ledger entry's seq. */
  seq: number;
}

/**
 * Told of each event after its ledger entry is appended (INT-5). The ledger is the record; the
 * listener is a notification, at least once and best effort: the same event can come again (after
 * a ledger outage, or from another process's flush), and one is missed if the process stops right
 * after the append. The engine calls it inline and never awaits it, so a listener with slow work
 * returns a promise instead of blocking. A throw or a rejection goes to `onListenerError` and never
 * stops the call or the ledger. The return type is `void` so any function fits, an async one too.
 */
export type EventListener = (event: DeliveredEvent) => void;

/** Told when the listener throws or its promise rejects. A failure of this hook is ignored. */
export type ListenerErrorHandler = (error: unknown, event: DeliveredEvent) => void;
