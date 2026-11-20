// Refunds and disputes in platform mode. In `platform` mode the money lands on the platform's own
// account at the provider, so the platform, not the business, refunds it and answers its disputes.
// A refund is a host call made for the business (its back office, its support staff): no call's
// grant reaches it and the model never does. Disputes arrive through the signed payments webhook.
// Both work after the call ended, and both are ledger entries against the payment, with amounts and
// statuses, never card data. The receipt issued at the end of the call is never changed.
//
// In `connect` mode the payment is a direct charge on the business's own account, so its refunds
// and disputes are the business's, at the provider: the engine refuses to refund one and never
// binds its disputes.
//
// A refund is reserved in one write (one in flight per payment, the total never above what was
// paid), its intent and idempotency key saved before the provider is asked, sent, and committed in
// another write. Each refund of a payment has a sequence number (1 for its first refund, 2 for the
// next), which the host must name, and its key is made of the payment and that number. A failed send
// leaves it reserved, and asking again with its number resumes it with the same key, or gives the
// saved result back when the host lost the answer after the commit: a payment is never refunded twice.
import type { PaymentRefundRequest } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import type { CallDraft, EngineRuntime } from "../core/runtime.ts";
import { isObject } from "../core/shape.ts";
import { PAYLINK, paymentIntentRef, type PaylinkSlice } from "./paylink.ts";
import type { PaymentRequest } from "./payment.ts";

/** Why the business refunds, in the provider's own words (Stripe's refund reasons). */
export type RefundReason = PaymentRefundRequest["reason"];

const REFUND_REASONS: readonly RefundReason[] = ["requested_by_customer", "duplicate", "fraudulent"];

/** `requested` while the provider has not answered; then what it said. */
export type RefundStatus = "requested" | "pending" | "succeeded" | "failed";

export interface RefundRecord {
  refundId: string;
  amountMinor: number;
  reason: RefundReason;
  status: RefundStatus;
  /** The provider's id for the refund (for example `re_...`); null until it answered. */
  providerRef: string | null;
  requestedAt: string;
  settledAt: string | null;
}

/** A dispute's status, in Stripe's words. `won` and `lost` are final. */
export type DisputeStatus = "warning_needs_response" | "warning_under_review" | "warning_closed" | "needs_response" | "under_review" | "won" | "lost";

export const DISPUTE_STATUSES: readonly DisputeStatus[] = ["warning_needs_response", "warning_under_review", "warning_closed", "needs_response", "under_review", "won", "lost"];

export interface DisputeRecord {
  disputeId: string;
  status: DisputeStatus;
  amountMinor: number;
  currency: string;
  updatedAt: string;
  /** When the provider produced the event this status came from (Stripe's event `created`), when it said. */
  occurredAt?: string;
}

/**
 * Where each status stands in a dispute's life, in Stripe's order: an inquiry (`warning_*`) is
 * answered, reviewed and closed, or becomes a dispute, which is answered, reviewed, then won or lost.
 */
const DISPUTE_STAGE: Readonly<Record<DisputeStatus, number>> = {
  warning_needs_response: 0,
  warning_under_review: 1,
  warning_closed: 2,
  needs_response: 3,
  under_review: 4,
  won: 5,
  lost: 5,
};

/**
 * What a platform payment gains once paid: the provider's payment intent (which its disputes
 * name, not the hosted page), its refunds and its disputes. Absent on a payment that has none.
 */
export interface PaymentAfterwards {
  paymentIntentId?: string;
  refunds?: RefundRecord[];
  disputes?: DisputeRecord[];
}

/**
 * A dispute event, already parsed from a verified webhook (Stripe's `charge.dispute.*`). It names
 * the charge and the payment intent, never the hosted page; the engine finds the payment by the
 * payment intent it bound when the payment was paid. `account` is set on a connected account's event.
 */
export interface DisputeOutcome {
  disputeId: string;
  chargeId: string;
  paymentIntentId: string | null;
  status: DisputeStatus;
  amountMinor: number;
  currency: string;
  account?: string;
  /**
   * When the provider produced the event (ISO 8601; Stripe's event `created`). Webhooks arrive in
   * any order: an event older than the one recorded is ignored. Without it on either side, a status
   * earlier in the dispute's life than the one recorded is ignored instead.
   */
  occurredAt?: string;
}

/** A dispute event's result. `unbound`: no payment is bound to its payment intent yet; deliver it again later. */
export type DisputeApplied = { applied: false; unbound?: true } | { applied: true; callId: string; status: DisputeStatus };

export interface RefundInput {
  callId: string;
  paymentId: string;
  /** In minor units. Default: everything not yet refunded. */
  amountMinor?: number;
  reason: RefundReason;
  /**
   * Required: which refund of this payment this is, 1 for its first, 2 for the next. Asking again
   * with the same number (an answer the host lost) resumes that refund with its key, or gives its
   * saved result back, and never refunds again; a different amount is refused. The next number
   * starts a new refund (refused while another is in flight), and any other is refused.
   */
  sequence: number;
}

export interface RefundResult {
  refundId: string;
  status: RefundStatus;
  amountMinor: number;
  /** Every refund of the payment that did not fail, this one included. */
  refundedMinor: number;
}

type Payment = PaymentRequest & PaymentAfterwards;

/**
 * Whether a dispute event is older than the status recorded, so it must not replace it (a late
 * `warning_needs_response` after `warning_closed` would block refunds again). By the provider's
 * times when both are known and differ; otherwise by where the statuses stand in a dispute's life.
 */
function stale(known: DisputeRecord, status: DisputeStatus, occurredAt: string | undefined): boolean {
  if (known.occurredAt !== undefined && occurredAt !== undefined && known.occurredAt !== occurredAt) return Date.parse(occurredAt) < Date.parse(known.occurredAt);
  return DISPUTE_STAGE[status] < DISPUTE_STAGE[known.status];
}

/** Whether a dispute stops a refund: while it is open, and once it was lost (the money went back already). */
function blocksRefund(dispute: DisputeRecord): boolean {
  return dispute.status !== "won" && dispute.status !== "warning_closed";
}

/** What a payment's refunds that did not fail add up to. */
function refunded(refunds: readonly RefundRecord[]): number {
  return refunds.filter((r) => r.status !== "failed").reduce((sum, r) => sum + r.amountMinor, 0);
}

function findPayment(draft: CallDraft, paymentId: string): Payment | undefined {
  const slice = draft.record.modules[PAYLINK] as unknown as PaylinkSlice | undefined;
  if (slice === undefined) throw new EngineError("module_disabled", `${PAYLINK} was off when this call started`);
  return slice.payments.find((p) => p.paymentId === paymentId);
}

/**
 * Refunds a paid platform payment, in full or in part, never more in total than was paid. Refused
 * while a dispute is open (the provider refuses too), for a payment not paid, and for a connect
 * payment (the business refunds those on its own account). `sequence` is required, checked before
 * any write. One refund is in flight per payment: asking again with its number resumes it with the
 * same idempotency key (a different amount is refused), and a new number waits for it. Works after
 * the call ended; the receipt is never changed.
 */
export async function refundPayment(rt: EngineRuntime, input: RefundInput): Promise<RefundResult> {
  // Read once: the amount and reason checked here are the ones refunded and recorded, so a getter
  // (or a host changing the object while the update waits) cannot swap in a negative amount.
  const { callId, paymentId, reason, amountMinor: asked, sequence } = input;
  if (!REFUND_REASONS.includes(reason)) throw new EngineError("invalid_input", `reason must be one of ${REFUND_REASONS.join(", ")}`);
  if (asked !== undefined && (!Number.isSafeInteger(asked) || asked <= 0)) {
    throw new EngineError("invalid_input", "amountMinor must be a positive integer");
  }
  // Required, so a host that retries cannot refund twice: checked before any write.
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new EngineError("invalid_input", "sequence must be an integer of 1 or more: the refund's number for this payment");
  const payments = rt.adapter("payments");
  // Optional for the adapter (no flow step needs it): a refund without it is refused here.
  if (payments.refund === undefined) throw new EngineError("precondition_failed", "the payments adapter cannot refund");
  const reserved = await rt.update(callId, (draft) => {
    const payment = findPayment(draft, paymentId);
    if (payment === undefined) throw new EngineError("invalid_input", "no such payment on this call");
    if (payment.mode !== "platform") throw new EngineError("precondition_failed", "a connect payment is the business's: it refunds it on its own account");
    if (payment.status !== "paid") throw new EngineError("precondition_failed", "only a paid payment can be refunded");
    const refunds = (payment.refunds ??= []);
    // A refund the host names by its number, made already: the same one, never a second. Its saved
    // result is given back once committed (the host lost the first answer), and resumed while in flight.
    if (sequence <= refunds.length) {
      const known = refunds[sequence - 1]!;
      if (asked !== undefined && asked !== known.amountMinor) throw new EngineError("invalid_input", "that refund was made for another amount");
      return { refund: known, payment, sequence };
    }
    if (sequence !== refunds.length + 1) throw new EngineError("invalid_input", `the next refund of this payment is number ${refunds.length + 1}`);
    // A new refund waits for the one in flight: it may have been made, and only its own number
    // (with its key) learns that. The dispute guard is for new refunds.
    const open = refunds.findIndex((r) => r.status === "requested");
    if (open !== -1) throw new EngineError("precondition_failed", `refund number ${open + 1} of this payment is still being sent; resume it first`);
    if ((payment.disputes ?? []).some(blocksRefund)) throw new EngineError("precondition_failed", "the payment is disputed: it cannot be refunded while its dispute is open or after it was lost");
    const left = payment.amountMinor - refunded(refunds);
    if (left === 0) throw new EngineError("precondition_failed", "the payment is refunded in full");
    const amountMinor = asked ?? left;
    if (amountMinor > left) throw new EngineError("invalid_input", "the refunds would add up to more than was paid");
    const refund: RefundRecord = { refundId: rt.ids.next("ref"), amountMinor, reason, status: "requested", providerRef: null, requestedAt: rt.now(), settledAt: null };
    refunds.push(refund);
    return { refund, payment, sequence: refunds.length };
  });
  const { refund, payment } = reserved;
  if (refund.status !== "requested") return { refundId: refund.refundId, status: refund.status, amountMinor: refund.amountMinor, refundedMinor: refunded(payment.refunds!) };
  const answer = await payments.refund({
    linkId: payment.linkId,
    ...(payment.paymentIntentId === undefined ? {} : { paymentIntentId: payment.paymentIntentId }),
    mode: "platform",
    amountMinor: refund.amountMinor,
    currency: payment.currency,
    reason: refund.reason,
    // One key per refund, saved before this call as the payment and the refund's number: a resumed
    // refund replays the first, a new refund is a new one.
    idempotencyKey: rt.idempotencyKey(callId, paymentId, "refund", String(reserved.sequence)),
  });
  // The provider's answer goes into the record and the ledger: anything but its three answers is a
  // provider fault, like an answer that was lost, so the refund stays in flight and resumes with its key.
  const status: unknown = isObject(answer) ? answer.status : undefined;
  const providerRef: unknown = isObject(answer) ? answer.refundId : undefined;
  if ((status !== "pending" && status !== "succeeded" && status !== "failed") || typeof providerRef !== "string" || providerRef === "") {
    throw new EngineError("precondition_failed", "the payment provider's refund answer is not one it gives; the refund stays in flight");
  }
  return rt.update(callId, (draft) => {
    const settled = findPayment(draft, paymentId)!;
    const refunds = settled.refunds!;
    const record = refunds.find((r) => r.refundId === refund.refundId)!;
    // Two resumes of one refund can both get here: the first records the answer, once.
    if (record.status === "requested") {
      record.status = status;
      record.providerRef = providerRef;
      record.settledAt = rt.now();
      draft.emit("payment.refunded", "code", {
        paymentId,
        refundId: record.refundId,
        providerRef,
        amountMinor: record.amountMinor,
        currency: settled.currency,
        reason: record.reason,
        status,
      });
    }
    return { refundId: record.refundId, status: record.status, amountMinor: record.amountMinor, refundedMinor: refunded(refunds) };
  });
}

/**
 * A dispute event from the verified payments webhook, recorded against the payment its payment
 * intent was bound to, after the call ended too. A connected account's event is ignored and written
 * down (a platform payment's disputes come from the platform's own account). A dispute that was won
 * or lost is final; an event that changes nothing is not written again.
 */
export async function applyDisputeOutcome(rt: EngineRuntime, outcome: DisputeOutcome): Promise<DisputeApplied> {
  // Read once: the payment intent looked up is the one searched, and the status compared is the one recorded.
  const { paymentIntentId, account, disputeId, status, amountMinor, currency, occurredAt } = outcome;
  // What the parser would never produce from a provider's event is refused before any lookup: the
  // status decides whether refunds are blocked, and every field goes into the ledger.
  if (
    typeof disputeId !== "string" ||
    disputeId === "" ||
    (paymentIntentId !== null && typeof paymentIntentId !== "string") ||
    !(DISPUTE_STATUSES as readonly unknown[]).includes(status) ||
    !Number.isSafeInteger(amountMinor) ||
    amountMinor < 0 ||
    typeof currency !== "string" ||
    !/^[a-z]{3}$/.test(currency) ||
    (occurredAt !== undefined && (typeof occurredAt !== "string" || !Number.isFinite(Date.parse(occurredAt))))
  ) {
    throw new EngineError("invalid_input", "a dispute outcome is a dispute id, a payment intent or null, a known status, a whole amount, a lower-case currency and, if any, a time");
  }
  if (paymentIntentId === null) return { applied: false };
  const callId = await rt.resolveRef(paymentIntentRef(paymentIntentId));
  // Not bound yet: the payment's own outcome may still be on its way (webhooks come in any order).
  // `unbound` tells the host to have the event delivered again rather than drop it.
  // A connected account's event is never the platform's to wait for: acknowledged, not retried.
  if (callId === null) return account === undefined ? { applied: false, unbound: true } : { applied: false };
  return rt.update(callId, (draft) => {
    const slice = draft.slice<PaylinkSlice>(PAYLINK);
    const payment = slice.payments.find((p) => p.paymentIntentId === paymentIntentId)!;
    if (account !== undefined) {
      draft.emit("payment.outcome_ignored", "system", { paymentId: payment.paymentId, reason: "account" });
      return { applied: false } as const;
    }
    const disputes = (payment.disputes ??= []);
    const known = disputes.find((d) => d.disputeId === disputeId);
    if (known !== undefined && (known.status === "won" || known.status === "lost" || stale(known, status, occurredAt))) {
      return { applied: false } as const;
    }
    if (known !== undefined && known.status === status && known.amountMinor === amountMinor) {
      // A newer snapshot that changes nothing still moves the dispute's time on, with no entry: an
      // older event that arrives after it (an inquiry reopened at t20 after closed at t10 and t30)
      // must be judged against t30, not t10.
      if (occurredAt !== undefined && (known.occurredAt === undefined || Date.parse(occurredAt) > Date.parse(known.occurredAt))) known.occurredAt = occurredAt;
      return { applied: false } as const;
    }
    const dispute: DisputeRecord = { disputeId, status, amountMinor, currency, updatedAt: rt.now(), ...(occurredAt === undefined ? {} : { occurredAt }) };
    if (known === undefined) disputes.push(dispute);
    else Object.assign(known, dispute);
    draft.emit("payment.disputed", "system", { paymentId: payment.paymentId, disputeId, status, amountMinor, currency });
    return { applied: true, callId, status } as const;
  });
}

/** A refund's status in Stripe's words, as its update events give it. */
export type ProviderRefundStatus = "pending" | "requires_action" | "succeeded" | "failed" | "canceled";

export const PROVIDER_REFUND_STATUSES: readonly ProviderRefundStatus[] = ["pending", "requires_action", "succeeded", "failed", "canceled"];

/**
 * A refund update event, already parsed from a verified webhook (Stripe's `refund.updated`,
 * `refund.failed`, `charge.refund.updated`). The engine finds the payment by the payment intent it
 * bound when the payment was paid, then the refund by the provider's refund id it recorded
 * (`providerRef`). `account` is set on a connected account's event.
 */
export interface RefundOutcome {
  /** The provider's refund id (for example `re_...`). */
  providerRef: string;
  paymentIntentId: string | null;
  status: ProviderRefundStatus;
  amountMinor: number;
  currency: string;
  account?: string;
}

/** A refund update's result. `unbound`: its payment, or the engine's own answer for it, is not recorded yet; deliver it again later. */
export type RefundApplied = { applied: false; unbound?: true } | { applied: true; callId: string; status: "succeeded" | "failed" };

/**
 * A refund update from the verified payments webhook, recorded against the refund the engine made,
 * after the call ended too. A `pending` refund moves to `succeeded`, or to `failed` (Stripe's
 * `failed` or `canceled`), which stops counting toward the refunded total so that amount can be
 * refunded again; a `succeeded` one can still move to `failed` (Stripe documents card refunds that
 * fail after succeeding). A `failed` refund is final, and an event that changes nothing is not
 * written again. A refund the engine did not make (one made by hand at the
 * provider), or one whose amount or currency differs from what the engine asked, is not applied.
 * The receipt is never changed.
 */
export async function applyRefundOutcome(rt: EngineRuntime, outcome: RefundOutcome): Promise<RefundApplied> {
  // Read once: the ids looked up are the ones searched, and the status compared is the one recorded.
  const { providerRef, paymentIntentId, status, amountMinor, currency, account } = outcome;
  if (
    typeof providerRef !== "string" ||
    providerRef === "" ||
    (paymentIntentId !== null && typeof paymentIntentId !== "string") ||
    !(PROVIDER_REFUND_STATUSES as readonly unknown[]).includes(status) ||
    !Number.isSafeInteger(amountMinor) ||
    amountMinor < 0 ||
    typeof currency !== "string" ||
    !/^[a-z]{3}$/.test(currency) ||
    (account !== undefined && typeof account !== "string")
  ) {
    throw new EngineError("invalid_input", "a refund outcome is a refund id, a payment intent or null, a known status, a whole amount, a lower-case currency and, if any, an account");
  }
  if (paymentIntentId === null) return { applied: false };
  const callId = await rt.resolveRef(paymentIntentRef(paymentIntentId));
  if (callId === null) return { applied: false, unbound: true };
  return rt.update(callId, (draft) => {
    const slice = draft.slice<PaylinkSlice>(PAYLINK);
    const payment = slice.payments.find((p) => p.paymentIntentId === paymentIntentId)!;
    if (account !== undefined) {
      draft.emit("payment.outcome_ignored", "system", { paymentId: payment.paymentId, reason: "account" });
      return { applied: false } as const;
    }
    const refunds = payment.refunds ?? [];
    const record = refunds.find((r) => r.providerRef === providerRef);
    if (record === undefined) {
      // The engine's own refund may have been made with its answer still on its way (or lost): the
      // update waits for the resume that records it. Otherwise this refund is not the engine's.
      return refunds.some((r) => r.status === "requested") ? ({ applied: false, unbound: true } as const) : ({ applied: false } as const);
    }
    const next = status === "succeeded" ? "succeeded" : status === "failed" || status === "canceled" ? "failed" : null;
    // A pending refund moves to either; a succeeded one can still fail (Stripe documents card
    // refunds that do); a failed one is final.
    const moves = record.status === "pending" || (record.status === "succeeded" && next === "failed");
    if (next === null || !moves || record.amountMinor !== amountMinor || payment.currency !== currency) return { applied: false } as const;
    record.status = next;
    record.settledAt = rt.now();
    draft.emit("payment.refund_updated", "system", { paymentId: payment.paymentId, refundId: record.refundId, providerRef, amountMinor, currency, status: next });
    return { applied: true, callId, status: next } as const;
  });
}
