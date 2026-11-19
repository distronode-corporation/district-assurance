// Amounts from code (PAY-2). A `paylink.request` step carries a fixed amount, or names a reference
// that the host's `AmountSource` adapter resolves (a record, the business's endpoint, a price
// list). Either way code builds the read-back, the caller hears the amount and confirms it, and
// only then is the link texted. The read-back's digest binds the confirmation to what was heard.
import { canonicalJson } from "../core/canonical.ts";
import { sha256Hex } from "../core/hash.ts";
import type { AmountLookup, AmountSource, Locale } from "../core/runtime.ts";
import type { AmountSourceKind } from "./payment.ts";

/** A reference an `AmountSource` resolves: 1 to 64 of letters, digits, `.`, `:`, `-`, `_`. */
export const AMOUNT_REF = /^[A-Za-z0-9.:_-]{1,64}$/;

/** An amount read back to the caller on this call, waiting for (or holding) their confirmation. */
export interface AmountQuote {
  /** What the amount was read back for (the step's or the host's request), so a different request cannot use it. */
  spec: string;
  amountMinor: number;
  currency: string;
  description: string;
  amountSource: AmountSourceKind;
  /** SHA-256 over the read-back the caller heard. */
  digest: string;
  readAt: string;
  confirmedAt: string | null;
}

export interface AmountReadBack {
  /** The line the host speaks, built by code in the call's locale, with the fixed confirm prompt. */
  text: string;
  /** What the host passes back to `confirmPaymentAmount` once the caller said yes. */
  digest: string;
  amountMinor: number;
  currency: string;
  description: string;
}

/** Formats an amount in minor units with the currency's own number of decimals. */
export function formatAmount(locale: Locale, amountMinor: number, currency: string): string {
  const format = new Intl.NumberFormat(locale === "fr" ? "fr-CA" : "en-CA", { style: "currency", currency: currency.toUpperCase() });
  const digits = format.resolvedOptions().maximumFractionDigits as number;
  return format.format(amountMinor / 10 ** digits);
}

/**
 * The amount read-back, in English or French, ending with the fixed confirm prompt, and its digest:
 * `SHA-256(canonicalJson({amountMinor, currency, description, locale, text}))`.
 */
export function buildAmountReadBack(locale: Locale, amount: { amountMinor: number; currency: string; description: string }): AmountReadBack {
  const spoken = formatAmount(locale, amount.amountMinor, amount.currency);
  const text =
    locale === "fr"
      ? `Le montant à payer est de ${spoken}, pour ${amount.description}. Est-ce exact ?`
      : `The amount to pay is ${spoken}, for ${amount.description}. Is that correct?`;
  const digest = sha256Hex(canonicalJson({ amountMinor: amount.amountMinor, currency: amount.currency, description: amount.description, locale, text }));
  return { text, digest, amountMinor: amount.amountMinor, currency: amount.currency, description: amount.description };
}

/**
 * The reference `AmountSource`: a fixed price list, by reference. It answers `price_list` lookups
 * only; a host's own source reads its records or calls the business's endpoint.
 */
export class PriceListAmounts implements AmountSource {
  readonly #prices: Map<string, { amountMinor: number; currency: string }>;

  constructor(prices: Readonly<Record<string, { amountMinor: number; currency: string }>>) {
    this.#prices = new Map(Object.entries(prices).map(([ref, { amountMinor, currency }]) => [ref, { amountMinor, currency }]));
  }

  async resolve(input: AmountLookup): Promise<{ amountMinor: number; currency: string } | null> {
    const price = input.source === "price_list" ? this.#prices.get(input.reference) : undefined;
    return price === undefined ? null : { ...price };
  }
}
