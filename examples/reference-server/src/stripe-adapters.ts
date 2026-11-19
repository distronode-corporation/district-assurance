// Stripe adapters for the reference server, so people can try it with their OWN Stripe test-mode
// keys. They call Stripe's REST API with fetch (no SDK dependency) and a restricted key from the
// environment. Stripe Identity is built (VER-5); Checkout still throws NotImplementedError (PAY-1).
//
// Nothing here logs. The identity check's URL is single-use and goes back to the engine only,
// which texts it to the number on file; it is never written to a log, an error or the ledger.
import { createHash } from "node:crypto";

import { NotImplementedError, type IdentityProvider, type PaymentLinks } from "../../../src/index.ts";

/** The Stripe API version every request pins, so the response shape cannot change under us. */
export const STRIPE_API_VERSION = "2025-03-31.basil";

/** A restricted key, live or test. A secret key (`sk_`) can do anything on the account, so it is refused. */
const RESTRICTED_KEY = /^rk_(?:test|live)_[A-Za-z0-9]{1,255}$/;

/** What Stripe accepts as an `Idempotency-Key` as is: printable ASCII without spaces, 255 at most. */
const PLAIN_IDEMPOTENCY_KEY = /^[\x21-\x7e]{1,255}$/;

/** An error type or code from Stripe, echoed only when it is a plain identifier. */
const STRIPE_IDENTIFIER = /^[a-z0-9_]{1,64}$/;

export interface StripeAdapterOptions {
  /** Default `https://api.stripe.com`. Tests point it at a local fake. */
  apiBase?: string;
  /** Default the global `fetch`. */
  fetch?: typeof fetch;
  /** Default 10 seconds per request. */
  timeoutMs?: number;
}

/**
 * Stripe refused a request, or answered something that is not what was asked for. The message
 * carries the HTTP status and Stripe's error type and code only, never a value from the request
 * or the response (a URL, a key, Stripe's free-text message).
 */
export class StripeApiError extends Error {
  readonly status: number;
  readonly type: string;
  readonly code: string | null;

  constructor(status: number, type: string, code: string | null) {
    super(`Stripe answered ${status} (${code === null ? type : `${type}/${code}`})`);
    this.name = "StripeApiError";
    this.status = status;
    this.type = type;
    this.code = code;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function identifier(value: unknown): string | null {
  return typeof value === "string" && STRIPE_IDENTIFIER.test(value) ? value : null;
}

/**
 * The engine's idempotency key as Stripe's `Idempotency-Key`: as is when Stripe accepts it, else
 * its SHA-256 (a workspace or call id with spaces, non-ASCII or a great length). Either way the
 * same engine key always gives the same header, so a retry returns the same check.
 */
export function stripeIdempotencyKey(engineKey: string): string {
  return PLAIN_IDEMPOTENCY_KEY.test(engineKey) ? engineKey : `sha256:${createHash("sha256").update(engineKey, "utf8").digest("hex")}`;
}

/** One form-encoded POST to Stripe. Answers the parsed JSON object, or throws StripeApiError. */
async function stripePost(
  key: string,
  options: StripeAdapterOptions,
  path: string,
  form: URLSearchParams,
  idempotencyKey: string,
): Promise<Record<string, unknown>> {
  const doFetch = options.fetch ?? fetch;
  const res = await doFetch(`${options.apiBase ?? "https://api.stripe.com"}${path}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${key}`,
      "content-type": "application/x-www-form-urlencoded",
      "idempotency-key": stripeIdempotencyKey(idempotencyKey),
      "stripe-version": STRIPE_API_VERSION,
    },
    body: form.toString(),
    // A redirect would carry the key elsewhere; Stripe's API never redirects.
    redirect: "error",
    signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
  });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    // Not JSON: judged below as a malformed answer.
  }
  if (!res.ok) {
    const error = isRecord(body) && isRecord(body.error) ? body.error : {};
    throw new StripeApiError(res.status, identifier(error.type) ?? "unknown", identifier(error.code));
  }
  if (!isRecord(body)) throw new StripeApiError(res.status, "malformed_response", null);
  return body;
}

/** Stripe Identity: a VerificationSession of type document with a matching selfie required. */
export class StripeIdentityProvider implements IdentityProvider {
  readonly #apiKey: string;
  readonly #options: StripeAdapterOptions;

  /** `apiKey` is a restricted key with write access to Identity VerificationSessions and nothing else. */
  constructor(apiKey: string, options: StripeAdapterOptions = {}) {
    if (!RESTRICTED_KEY.test(apiKey)) throw new Error("StripeIdentityProvider needs a restricted key (rk_test_... or rk_live_...)");
    this.#apiKey = apiKey;
    this.#options = options;
  }

  /**
   * Creates the check, with the call id in its metadata and the engine's idempotency key, so a
   * retry after a failure returns the same session and the same link. Answers the session id,
   * which the outcome webhook names, and the single-use URL.
   */
  async createDocumentCheck(input: { callId: string; idempotencyKey: string }): Promise<{ sessionId: string; url: string }> {
    const form = new URLSearchParams();
    form.set("type", "document");
    form.set("options[document][require_matching_selfie]", "true");
    form.set("metadata[call_id]", input.callId);
    const session = await stripePost(this.#apiKey, this.#options, "/v1/identity/verification_sessions", form, input.idempotencyKey);
    const { id, url } = session;
    if (typeof id !== "string" || !/^vs_[A-Za-z0-9]{1,255}$/.test(id) || typeof url !== "string" || !url.startsWith("https://")) {
      throw new StripeApiError(200, "malformed_response", null);
    }
    return { sessionId: id, url };
  }
}

/** Stripe Checkout: a Session in payment mode, cards only, on the business's own account. */
export class StripeCheckoutLinks implements PaymentLinks {
  readonly #apiKey: string;

  constructor(apiKey: string) {
    this.#apiKey = apiKey;
  }

  async createLink(_input: {
    callId: string;
    paymentId: string;
    amountMinor: number;
    currency: string;
    description: string;
    idempotencyKey: string;
  }): Promise<{ linkId: string; url: string }> {
    void this.#apiKey;
    throw new NotImplementedError("StripeCheckoutLinks.createLink", "PAY-1");
  }
}
