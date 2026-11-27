// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Stripe adapters for the reference server, so people can try it with their OWN Stripe test-mode
// keys. They call Stripe's REST API with Node's built-in fetch (no SDK, no dependency).
//
// StripeIdentityProvider (VER-5): a restricted key from the environment. Nothing here logs. The
// identity check's URL is single-use and goes back to the engine only, which texts it to the number
// on file; it is never written to a log, an error or the ledger.
//
// Checkout (PAY-1) is the package's own `StripeCheckoutLinks` (district-assurance/stripe) over
// `fetchStripeClient`; `testModeCheckout` below builds it for the demo, in test mode only.
import { type IdentityProvider } from "../../../src/index.ts";
import {
  STRIPE_BASIL_API_VERSION,
  StripeCheckoutLinks,
  StripeKeyRefused,
  assertStripeKey,
  fetchStripeClient,
  stripeIdempotencyKey,
  stripeMetadataCallId,
} from "../../../src/stripe/index.ts";

export { StripeKeyRefused, stripeIdempotencyKey, stripeMetadataCallId };

/** Whether a link a payer is texted is an https URL that opens: one with no host (`https://:443`) does not parse. */
function opensAsHttps(value: string): boolean {
  return URL.canParse(value) && new URL(value).protocol === "https:";
}

/**
 * The version Identity requests pin, so the response shape cannot change under us. It is the
 * version the Identity run was recorded on (test/fixtures/stripe-real/identity.json).
 */
export const STRIPE_API_VERSION = STRIPE_BASIL_API_VERSION;

/** A restricted key, live or test. A secret key (`sk_`) can do anything on the account, so it is refused. */
const RESTRICTED_KEY = /^rk_(?:test|live)_[A-Za-z0-9]{1,255}$/;


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
 * Stripe answered, and the answer was a refusal or not one this adapter can trust. `status` is
 * the HTTP status (200 for an answer of the wrong shape). The message names the status and
 * Stripe's error type and code, never Stripe's own message, which can quote part of a key.
 * `type` and `code` are set on the Identity adapter's refusals (`refused`), else null.
 */
export class StripeApiError extends Error {
  readonly status: number;
  readonly type: string | null;
  readonly code: string | null;
  constructor(status: number, message: string, detail: { type: string; code: string | null } | null = null) {
    super(message);
    this.name = "StripeApiError";
    this.status = status;
    this.type = detail?.type ?? null;
    this.code = detail?.code ?? null;
  }

  /** A refusal named by Stripe's error type and code only. */
  static refused(status: number, type: string, code: string | null): StripeApiError {
    return new StripeApiError(status, `Stripe answered ${status} (${code === null ? type : `${type}/${code}`})`, { type, code });
  }

  /** Worth asking again: Stripe was busy or failed on its side. */
  get retryable(): boolean {
    return this.status === 429 || this.status >= 500;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function identifier(value: unknown): string | null {
  return typeof value === "string" && STRIPE_IDENTIFIER.test(value) ? value : null;
}

/** Hosts that never leave the machine, the only ones a key may reach over plain `http:`. */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

/**
 * The key goes in a bearer header, so the API base must be `https:`, or `http:` on a loopback
 * host only (a local fake). Anything else fails here, before a request is sent. The message never
 * echoes the value.
 */
function checkApiBase(apiBase: string): void {
  let url: URL;
  try {
    url = new URL(apiBase);
  } catch {
    throw new Error("StripeIdentityProvider needs an https: apiBase (http: only on a loopback host)");
  }
  // No credentials in it: fetch refuses such a URL and quotes it, password and all, in its error.
  if (url.username !== "" || url.password !== "") throw new Error("StripeIdentityProvider's apiBase carries no credentials");
  if (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))) return;
  throw new Error("StripeIdentityProvider needs an https: apiBase (http: only on a loopback host)");
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
    throw StripeApiError.refused(res.status, identifier(error.type) ?? "unknown", identifier(error.code));
  }
  if (!isRecord(body)) throw StripeApiError.refused(res.status, "malformed_response", null);
  return body;
}

/** Stripe Identity: a VerificationSession of type document with a matching selfie required. */
export class StripeIdentityProvider implements IdentityProvider {
  readonly #apiKey: string;
  readonly #options: StripeAdapterOptions;

  /** `apiKey` is a restricted key with write access to Identity VerificationSessions and nothing else. */
  constructor(apiKey: string, options: StripeAdapterOptions = {}) {
    if (!RESTRICTED_KEY.test(apiKey)) throw new Error("StripeIdentityProvider needs a restricted key (rk_test_... or rk_live_...)");
    // Each option read once, into a copy of our own: a caller changing its object later, or a
    // getter answering differently, can never move the key to an apiBase that was not checked.
    const { apiBase, fetch: doFetch, timeoutMs } = options;
    if (apiBase !== undefined) checkApiBase(apiBase);
    // AbortSignal.timeout throws on anything else, at every request instead of here.
    if (timeoutMs !== undefined && !(Number.isInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 60_000)) {
      throw new Error("StripeIdentityProvider timeoutMs must be a whole number of milliseconds from 1 to 60000");
    }
    this.#apiKey = apiKey;
    this.#options = Object.freeze({
      ...(apiBase === undefined ? {} : { apiBase }),
      ...(doFetch === undefined ? {} : { fetch: doFetch }),
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
    });
  }

  /**
   * Creates the check, with the call id in its metadata (hashed when over Stripe's limit,
   * `stripeMetadataCallId`) and the engine's idempotency key, so a
   * retry after a failure returns the same session and the same link. Answers the session id,
   * which the outcome webhook names, and the single-use URL.
   */
  async createDocumentCheck(input: { callId: string; idempotencyKey: string }): Promise<{ sessionId: string; url: string }> {
    const form = new URLSearchParams();
    form.set("type", "document");
    form.set("options[document][require_matching_selfie]", "true");
    form.set("metadata[call_id]", stripeMetadataCallId(input.callId));
    const session = await stripePost(this.#apiKey, this.#options, "/v1/identity/verification_sessions", form, input.idempotencyKey);
    const { id, url } = session;
    // The URL goes into a text message as is: an https link of printable ASCII and nothing else (no
    // space, line break or control character that would put more than a link into the SMS).
    if (typeof id !== "string" || !/^vs_[A-Za-z0-9]{1,255}$/.test(id) || typeof url !== "string" || !/^https:\/\/[\x21-\x7e]{1,2040}$/.test(url) || !opensAsHttps(url)) {
      throw StripeApiError.refused(200, "malformed_response", null);
    }
    return { sessionId: id, url };
  }
}

/**
 * The demo's key check: a Stripe secret or restricted key for TEST mode only (`assertStripeKey`);
 * a live key, a publishable key and anything else are refused, without the key in the message.
 */
export function assertTestModeSecretKey(key: unknown): asserts key is string {
  if (typeof key !== "string" || key === "") throw new StripeKeyRefused("no Stripe key: set STRIPE_TEST_SECRET_KEY to a test-mode secret key (sk_test_...)");
  assertStripeKey(key, "test");
}

/**
 * The demo's Checkout payment links: the package's `StripeCheckoutLinks` in test mode, both payment
 * modes, over `fetchStripeClient`. `apiVersion` basil replays the recorded runs. `now` is the
 * engine's clock, against which a link's `expiresAt` is kept inside Checkout's window.
 */
export function testModeCheckout(
  apiKey: string,
  options: { successUrl: string; apiBase?: string; timeoutMs?: number; apiVersion?: typeof STRIPE_BASIL_API_VERSION; now?: () => Date },
): StripeCheckoutLinks {
  assertTestModeSecretKey(apiKey);
  const client = fetchStripeClient(apiKey, {
    mode: "test",
    timeoutMs: options.timeoutMs ?? 15_000,
    ...(options.apiBase === undefined ? {} : { apiBase: options.apiBase }),
    ...(options.apiVersion === undefined ? {} : { apiVersion: options.apiVersion }),
  });
  return new StripeCheckoutLinks(client, {
    mode: "test",
    successUrl: options.successUrl,
    ...(options.apiVersion === undefined ? {} : { apiVersion: options.apiVersion }),
    ...(options.now === undefined ? {} : { now: options.now }),
  });
}
