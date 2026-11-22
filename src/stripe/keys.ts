// Stripe modes, keys and API versions. A key is checked against the mode it is used in before any
// client exists, and nothing here ever puts any part of a key in a message.

/** Test mode (a sandbox) or live mode (real money). Every answer must carry the mode's `livemode`. */
export type StripeMode = "test" | "live";

/** The API version every adapter sends: create, read and expire keep one contract whatever the account's default. */
export const STRIPE_API_VERSION = "2026-09-30.endive";

/**
 * The older version the recorded test-mode runs were made on (test/fixtures/stripe-real/), kept
 * only so they replay. It names Checkout's methods `payment_method_types`, which endive removed
 * (endive takes `allowed_payment_method_types`). Test mode only: refused in live mode.
 */
export const STRIPE_BASIL_API_VERSION = "2025-03-31.basil";

export type StripeApiVersion = typeof STRIPE_API_VERSION | typeof STRIPE_BASIL_API_VERSION;

/** Thrown for a key, or a mode and version, an adapter will not use. The message never contains the key. */
export class StripeKeyRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StripeKeyRefused";
  }
}

/** A secret (`sk_`) or restricted (`rk_`) key and the key's characters. */
const SERVER_KEY = /^(?:sk|rk)_(test|live)_[A-Za-z0-9]{8,255}$/;

/**
 * Accepts a secret (`sk_`) or restricted (`rk_`) key of `mode` only: `sk_test_`/`rk_test_` in test
 * mode, `sk_live_`/`rk_live_` in live mode. A key of the other mode, a publishable key (`pk_`), a
 * webhook secret, a short key, one with whitespace or any other character, and anything that is not
 * a string are refused with a fixed message that never quotes the value. Prefer a restricted key:
 * it can do only what its scopes allow.
 */
export function assertStripeKey(key: unknown, mode: StripeMode): asserts key is string {
  if (mode !== "test" && mode !== "live") throw new StripeKeyRefused("the Stripe mode must be test or live");
  if (typeof key !== "string" || key === "") throw new StripeKeyRefused(`no Stripe key: give a ${mode}-mode secret or restricted key`);
  const match = SERVER_KEY.exec(key);
  if (match === null) throw new StripeKeyRefused(`refused: not a Stripe ${mode}-mode secret or restricted key (sk_${mode}_ or rk_${mode}_)`);
  if (match[1] !== mode) {
    throw new StripeKeyRefused(mode === "test" ? "refused a LIVE Stripe key in test mode" : "refused a TEST Stripe key in live mode");
  }
}

/** The version to send: endive by default; basil only in test mode. */
export function checkedApiVersion(mode: StripeMode, apiVersion: StripeApiVersion | undefined): StripeApiVersion {
  if (mode !== "test" && mode !== "live") throw new StripeKeyRefused("the Stripe mode must be test or live");
  if (apiVersion === undefined || apiVersion === STRIPE_API_VERSION) return STRIPE_API_VERSION;
  if (apiVersion !== STRIPE_BASIL_API_VERSION) throw new StripeKeyRefused(`refused: the Stripe API version must be ${STRIPE_API_VERSION}`);
  if (mode !== "test") throw new StripeKeyRefused(`refused: ${STRIPE_BASIL_API_VERSION} replays test-mode recordings only; live mode runs on ${STRIPE_API_VERSION}`);
  return apiVersion;
}
