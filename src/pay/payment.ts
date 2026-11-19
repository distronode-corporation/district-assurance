// Pay by link. The engine never sees a card: it asks the payment provider for a hosted page,
// texts the link to the number on file, and learns the result from a signed webhook. The amount
// comes from code (a record, the business's endpoint, a price list), never from the model.

/** Where an amount comes from. The `AmountSource` adapter (PAY-2) resolves a reference from one of them. */
export type AmountSourceKind = "intake_record" | "business_endpoint" | "price_list";

export type PaymentStatus = "open" | "paid" | "failed" | "expired";

export interface PaymentRequest {
  paymentId: string;
  callId: string;
  amountMinor: number;
  currency: string;
  description: string;
  amountSource: AmountSourceKind;
  /** The provider's id for the hosted page (for example a Checkout Session id). */
  linkId: string;
  status: PaymentStatus;
  requestedAt: string;
  settledAt: string | null;
  /** When the link was texted; null while it is still being created or sent (and can be resumed). */
  textedAt: string | null;
  /** What the request was made for (PAY-2), so a resume can name the same amountRef. Absent on older calls. */
  requestKey?: string;
}

/** What the provider reported, already parsed from a verified webhook. */
export type PaymentOutcome =
  | { kind: "completed"; linkId: string; paymentStatus: "paid" | "unpaid" | "no_payment_required" }
  | { kind: "async_succeeded"; linkId: string }
  | { kind: "async_failed"; linkId: string }
  | { kind: "expired"; linkId: string };

/** Upper bound for one in-call link, in minor units. A host can lower it, never raise it here. */
export const MAX_LINK_AMOUNT_MINOR = 1_000_000;

/** Every problem with an amount and currency, as sentences. */
export function validateAmount(amountMinor: number, currency: string, maxMinor = MAX_LINK_AMOUNT_MINOR): string[] {
  const errors: string[] = [];
  if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) errors.push("amountMinor must be a positive integer");
  else if (amountMinor > Math.min(maxMinor, MAX_LINK_AMOUNT_MINOR)) errors.push("amountMinor is above the limit");
  if (!/^[a-z]{3}$/.test(currency)) errors.push("currency must be a lower-case ISO 4217 code");
  return errors;
}

/**
 * The status an outcome settles a request at, or null when it settles nothing yet. A completed
 * page is a payment only when the provider says paid; an unpaid completion waits for the
 * asynchronous result. `no_payment_required` never counts as paid.
 */
export function settlementFor(outcome: PaymentOutcome): Exclude<PaymentStatus, "open"> | null {
  switch (outcome.kind) {
    case "completed":
      return outcome.paymentStatus === "paid" ? "paid" : outcome.paymentStatus === "unpaid" ? null : "failed";
    case "async_succeeded":
      return "paid";
    case "async_failed":
      return "failed";
    case "expired":
      return "expired";
  }
}
