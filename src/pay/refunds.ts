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
// paid), sent to the provider with an idempotency key of its own, and committed in another. A
// failed send leaves it reserved, and asking again resumes it with the same key, so a payment is
// never refunded twice.
import type { PaymentRefundRequest } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import type { CallDraft, EngineRuntime } from "../core/runtime.ts";
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
}

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
}

/** A dispute event's result. `unbound`: no payment is bound to its payment intent yet; deliver it again later. */
export type DisputeApplied = { applied: false; unbound?: true } | { applied: true; callId: string; status: DisputeStatus };

export interface RefundInput {
  callId: string;
  paymentId: string;
  /** In minor units. Default: everything not yet refunded. */
  amountMinor?: number;
  reason: RefundReason;
}

export interface RefundResult {
  refundId: string;
  status: RefundStatus;
  amountMinor: number;
  /** Every refund of the payment that did not fail, this one included. */
  refundedMinor: number;
}

type Payment = PaymentRequest & PaymentAfterwards;

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
 * payment (the business refunds those on its own account). One refund is in flight per payment:
 * asking again while it is resumes it with the same idempotency key, and a different amount is
 * refused. Works after the call ended; the receipt is never changed.
 */
export async function refundPayment(rt: EngineRuntime, input: RefundInput): Promise<RefundResult> {
  // Read once: the amount and reason checked here are the ones refunded and recorded, so a getter
  // (or a host changing the object while the update waits) cannot swap in a negative amount.
  const { callId, paymentId, reason, amountMinor: asked } = input;
  if (!REFUND_REASONS.includes(reason)) throw new EngineError("invalid_input", `reason must be one of ${REFUND_REASONS.join(", ")}`);
  if (asked !== undefined && (!Number.isSafeInteger(asked) || asked <= 0)) {
    throw new EngineError("invalid_input", "amountMinor must be a positive integer");
  }
  const payments = rt.adapter("payments");
  // Optional for the adapter (no flow step needs it): a refund without it is refused here.
  if (payments.refund === undefined) throw new EngineError("precondition_failed", "the payments adapter cannot refund");
  const reserved = await rt.update(callId, (draft) => {
    const payment = findPayment(draft, paymentId);
    if (payment === undefined) throw new EngineError("invalid_input", "no such payment on this call");
    if (payment.mode !== "platform") throw new EngineError("precondition_failed", "a connect payment is the business's: it refunds it on its own account");
    if (payment.status !== "paid") throw new EngineError("precondition_failed", "only a paid payment can be refunded");
    const refunds = (payment.refunds ??= []);
    // A refund already sent (its answer lost) is resumed with its own key whatever happened since:
    // the provider may have made it, and only the same key learns that. The dispute guard is for
    // new refunds.
    const open = refunds.find((r) => r.status === "requested");
    if (open !== undefined) {
      if (asked !== undefined && asked !== open.amountMinor) {
        throw new EngineError("invalid_input", "a refund of this payment is still being sent; resume it with the same amount");
      }
      return { refund: open, payment };
    }
    if ((payment.disputes ?? []).some(blocksRefund)) throw new EngineError("precondition_failed", "the payment is disputed: it cannot be refunded while its dispute is open or after it was lost");
    const left = payment.amountMinor - refunded(refunds);
    if (left === 0) throw new EngineError("precondition_failed", "the payment is refunded in full");
    const amountMinor = asked ?? left;
    if (amountMinor > left) throw new EngineError("invalid_input", "the refunds would add up to more than was paid");
    const refund: RefundRecord = { refundId: rt.ids.next("ref"), amountMinor, reason, status: "requested", providerRef: null, requestedAt: rt.now(), settledAt: null };
    refunds.push(refund);
    return { refund, payment };
  });
  const { refund, payment } = reserved;
  const answer = await payments.refund({
    linkId: payment.linkId,
    ...(payment.paymentIntentId === undefined ? {} : { paymentIntentId: payment.paymentIntentId }),
    mode: "platform",
    amountMinor: refund.amountMinor,
    currency: payment.currency,
    reason: refund.reason,
    // One key per refund: a resumed refund replays the first, a new refund is a new one.
    idempotencyKey: rt.idempotencyKey(callId, paymentId, "refund", refund.refundId),
  });
  return rt.update(callId, (draft) => {
    const settled = findPayment(draft, paymentId)!;
    const refunds = settled.refunds!;
    const record = refunds.find((r) => r.refundId === refund.refundId)!;
    // Two resumes of one refund can both get here: the first records the answer, once.
    if (record.status === "requested") {
      record.status = answer.status;
      record.providerRef = answer.refundId;
      record.settledAt = rt.now();
      draft.emit("payment.refunded", "code", {
        paymentId,
        refundId: record.refundId,
        providerRef: answer.refundId,
        amountMinor: record.amountMinor,
        currency: settled.currency,
        reason: record.reason,
        status: answer.status,
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
  const { paymentIntentId, account, disputeId, status, amountMinor, currency } = outcome;
  if (paymentIntentId === null) return { applied: false };
  const callId = await rt.resolveRef(paymentIntentRef(paymentIntentId));
  // Not bound yet: the payment's own outcome may still be on its way (webhooks come in any order).
  // `unbound` tells the host to have the event delivered again rather than drop it.
  if (callId === null) return { applied: false, unbound: true };
  return rt.update(callId, (draft) => {
    const slice = draft.slice<PaylinkSlice>(PAYLINK);
    const payment = slice.payments.find((p) => p.paymentIntentId === paymentIntentId)!;
    if (account !== undefined) {
      draft.emit("payment.outcome_ignored", "system", { paymentId: payment.paymentId, reason: "account" });
      return { applied: false } as const;
    }
    const disputes = (payment.disputes ??= []);
    const known = disputes.find((d) => d.disputeId === disputeId);
    if (known !== undefined && (known.status === "won" || known.status === "lost" || (known.status === status && known.amountMinor === amountMinor))) {
      return { applied: false } as const;
    }
    const dispute: DisputeRecord = { disputeId, status, amountMinor, currency, updatedAt: rt.now() };
    if (known === undefined) disputes.push(dispute);
    else Object.assign(known, dispute);
    draft.emit("payment.disputed", "system", { paymentId: payment.paymentId, disputeId, status, amountMinor, currency });
    return { applied: true, callId, status } as const;
  });
}
