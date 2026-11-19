// Pay by link. The engine never sees a card: it asks the payment provider for a hosted page,
// texts the link to the number on file, and learns the result from a signed webhook. The amount
// comes from code (a record, the business's endpoint, a price list), never from the model.
import type { InstantPaymentMethod, PaymentMode } from "../core/adapters.ts";

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
  /** Whose account takes the money. */
  mode: PaymentMode;
  /** The business's account at the provider, in `connect` mode; null in `platform` mode. */
  connectedAccountId: string | null;
  paymentMethods: InstantPaymentMethod[];
  /** How long the link lives once texted, in minutes (5 to 60). */
  linkLifeMinutes: number;
  /** The engine's deadline: `linkLifeMinutes` after the link was texted. Null until it is texted. */
  expiresAt: string | null;
  /** What the provider was asked for when the link was created; the engine's deadline never passes it. */
  providerExpiresAt: string;
  /** When a process last claimed the text of this link (a short lease), so another never expires it mid-send. */
  sendingSince: string | null;
}

/** Whose account takes the money, per flow step. */
export const PAYMENT_MODES: readonly PaymentMode[] = ["connect", "platform"];

/**
 * The payment methods a link may offer: those that settle while the caller is on the call. Cards
 * include Visa and Mastercard debit. Pre-authorized debit (`acss_debit`) settles in days, and
 * Interac is not offered for online payments, so neither is allowed.
 */
export const INSTANT_PAYMENT_METHODS: readonly InstantPaymentMethod[] = ["card", "apple_pay", "google_pay", "link"];

/** Methods people ask for that are refused, and why. */
const REFUSED_METHODS: Readonly<Record<string, string>> = {
  acss_debit: "pre-authorized debit settles in days, not during the call",
  us_bank_account: "bank debits settle in days, not during the call",
  interac: "Interac is not offered for online payments",
  interac_present: "Interac is not offered for online payments",
};

export const DEFAULT_LINK_LIFE_MINUTES = 15;
export const MIN_LINK_LIFE_MINUTES = 5;
export const MAX_LINK_LIFE_MINUTES = 60;

/** Every problem with a list of payment methods, as sentences. */
export function paymentMethodErrors(value: unknown): string[] {
  if (!Array.isArray(value) || Object.keys(value).length !== value.length || value.length === 0 || !value.every((m) => typeof m === "string")) {
    return ["paymentMethods must list at least one payment method"];
  }
  const errors = new Set(value).size === value.length ? [] : ["paymentMethods has duplicates"];
  for (const method of value as string[]) {
    if ((INSTANT_PAYMENT_METHODS as readonly string[]).includes(method)) continue;
    const why = Object.hasOwn(REFUSED_METHODS, method) ? REFUSED_METHODS[method] : "it is not an instant payment method";
    errors.push(`payment method ${method} is refused: ${why} (allowed: ${INSTANT_PAYMENT_METHODS.join(", ")})`);
  }
  return errors;
}

/**
 * What the provider reported, already parsed from a verified webhook. `account` is the connected
 * account the event came from (Stripe's top-level `account` on Connect events), absent for an
 * event on the platform's own account. It must match the payment's mode and account, or the
 * outcome is ignored.
 */
export type PaymentOutcome = (
  | { kind: "completed"; linkId: string; paymentStatus: "paid" | "unpaid" | "no_payment_required" }
  | { kind: "async_succeeded"; linkId: string }
  | { kind: "async_failed"; linkId: string }
  | { kind: "expired"; linkId: string }
) & { account?: string };

/** Whether an outcome came from the account the payment was taken on. */
export function outcomeAccountMatches(request: Pick<PaymentRequest, "mode" | "connectedAccountId">, outcome: PaymentOutcome): boolean {
  return request.mode === "connect" ? outcome.account === request.connectedAccountId : outcome.account === undefined;
}

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
