// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

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
  "verification.synthetic_voice",
  "verification.pin_pass_issued",
  "verification.pin_reuse_refused",
  "identity.link_sent",
  "verification.code_sent",
  "verification.code_refused",
  "grant.issued",
  "signal.raised",
  "policy.step_up",
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
  "payment.channel_chosen",
  "payment.link_sent",
  "payment.link_expired",
  "payment.outcome_ignored",
  "payment.settled",
  "payment.refunded",
  "payment.refund_updated",
  "payment.disputed",
  "payment.card_charge_requested",
  "payment.card_charged",
  "payment.card_declined",
  "payment.card_not_sent",
  "payment.card_unknown",
  "consent.recorded",
  "access.issued",
  "access.delivered",
  "access.refused",
  "access.unknown",
  "access.failed",
  "access.code_spent",
  "access.tainted",
  "access.revoked",
  "stepup.issued",
  "stepup.exchanged",
  "stepup.refused",
  "stepup.failed",
  "consent.revoked",
  "consent.unrecorded",
  "call.ended",
  "receipt.issued",
  "receipt.link_texted",
  "receipt.link_emailed",
  "contact.notice_owed",
  "contact.notice_sent",
  "module.event",
  "subject.erased",
  "subject.erasure_completed",
  "ledger.anchored",
] as const;

export type EngineEventName = (typeof ENGINE_EVENTS)[number];

export type Actor = "caller" | "ai" | "code" | "member" | "system";

export interface EngineEvent {
  name: EngineEventName;
  /** Null for an engine-wide event (`ledger.anchored`). */
  callId: string | null;
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
 * listener is a notification, best effort and possibly repeated: the same event can come again (after
 * a ledger outage, or from another process's flush), and one is missed if the process stops right
 * after the append. The engine calls it inline and never awaits it, so a listener with slow work
 * returns a promise instead of blocking. A throw or a rejection goes to `onListenerError` and never
 * stops the call or the ledger. The return type is `void` so any function fits, an async one too.
 */
export type EventListener = (event: DeliveredEvent) => void;

/** Told when the listener throws or its promise rejects. A failure of this hook is ignored. */
export type ListenerErrorHandler = (error: unknown, event: DeliveredEvent) => void;
