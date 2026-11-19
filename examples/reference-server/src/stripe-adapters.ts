// Stripe adapters for the reference server, so people can try it with their OWN Stripe test-mode
// keys. They call Stripe's REST API with Node's built-in fetch (no SDK, no dependency).
//
// StripeIdentityProvider (VER-5): a restricted key from the environment. Nothing here logs. The
// identity check's URL is single-use and goes back to the engine only, which texts it to the number
// on file; it is never written to a log, an error or the ledger.
//
// StripeCheckoutLinks (PAY-1, minimal): Checkout Sessions in TEST MODE ONLY. The constructor
// refuses any key that is not a secret test key (`sk_test_`), live and restricted keys included,
// and never puts a key, or Stripe's own error message (which can quote part of one), in an error.
// The Checkout URL is returned to the engine and never logged here.
import { createHash } from "node:crypto";

import {
  type IdentityProvider,
  type InstantPaymentMethod,
  type PaymentLinkCapabilities,
  type PaymentLinkRequest,
  type PaymentLinks,
  type PaymentMode,
} from "../../../src/index.ts";

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

/**
 * The engine's idempotency key as Stripe's `Idempotency-Key`: as is when Stripe accepts it, else
 * its SHA-256 (a workspace or call id with spaces, non-ASCII or a great length). Either way the
 * same engine key always gives the same header, so a retry returns the same check.
 */
export function stripeIdempotencyKey(engineKey: string): string {
  return PLAIN_IDEMPOTENCY_KEY.test(engineKey) ? engineKey : `sha256:${createHash("sha256").update(engineKey, "utf8").digest("hex")}`;
}

/** Stripe's limit on a metadata value, in characters. */
const METADATA_VALUE_LIMIT = 500;

/**
 * The call id as Stripe metadata: as is when it fits Stripe's 500-character limit, else `sha256:`
 * and its hex SHA-256, so a long host call id still gets a check (Stripe refuses the whole request
 * with a 400 otherwise) and the same call id always sends the same value. It is measured in UTF-8
 * bytes, which is never fewer than characters, so the value fits however Stripe counts.
 */
export function stripeMetadataCallId(callId: string): string {
  return Buffer.byteLength(callId, "utf8") <= METADATA_VALUE_LIMIT ? callId : `sha256:${createHash("sha256").update(callId, "utf8").digest("hex")}`;
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
    if (typeof id !== "string" || !/^vs_[A-Za-z0-9]{1,255}$/.test(id) || typeof url !== "string" || !/^https:\/\/[\x21-\x7e]{1,2040}$/.test(url)) {
      throw StripeApiError.refused(200, "malformed_response", null);
    }
    return { sessionId: id, url };
  }
}

/** Thrown for a key this adapter will not use. The message never contains the key. */
export class StripeKeyRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StripeKeyRefused";
  }
}

/**
 * Accepts only a Stripe secret key for test mode (`sk_test_` and the key's characters). A live
 * secret key (`sk_live_`), a restricted key (`rk_live_`, `rk_test_`), a publishable key and
 * anything else are refused, without the key in the message.
 */
export function assertTestModeSecretKey(key: unknown): asserts key is string {
  if (typeof key !== "string" || key === "") throw new StripeKeyRefused("no Stripe key: set STRIPE_TEST_SECRET_KEY to a test-mode secret key (sk_test_...)");
  if (key.startsWith("sk_live_") || key.startsWith("rk_live_")) throw new StripeKeyRefused("refused a LIVE Stripe key: this demo runs in test mode only (sk_test_...)");
  if (!/^sk_test_[A-Za-z0-9]{8,}$/.test(key)) throw new StripeKeyRefused("refused: not a Stripe test-mode secret key (sk_test_...)");
}

export interface StripeCheckoutOptions {
  /** Default `https://api.stripe.com`. https only; http only to the loopback (a test's fake). */
  apiBase?: string;
  /**
   * Where Checkout sends the payer once paid (Stripe requires it for a hosted page). https, or
   * http to the loopback (the demo page).
   */
  successUrl: string;
  /** Per request, default 15000 ms. */
  timeoutMs?: number;
}

/** A Checkout Session as read back from Stripe, read only. */
export interface CheckoutSessionStatus {
  linkId: string;
  status: "open" | "complete" | "expired";
  paymentStatus: "paid" | "unpaid" | "no_payment_required";
  /** Always false: a live-mode answer is refused. */
  livemode: false;
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);
const SESSION_ID = /^cs_test_[A-Za-z0-9]{1,200}$/;

function checkedUrl(value: string, what: string): URL {
  const url = new URL(value);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname))) throw new TypeError(`${what} must be https (http only to the loopback)`);
  if (url.username !== "" || url.password !== "") throw new TypeError(`${what} carries no credentials`);
  return url;
}

/** How the engine's instant methods map to Checkout: Apple Pay and Google Pay are wallets of `card`. */
export function checkoutPaymentMethodTypes(methods: readonly InstantPaymentMethod[]): string[] {
  const types = new Set<string>();
  for (const method of methods) types.add(method === "link" ? "link" : "card");
  return [...types];
}

/**
 * Stripe Checkout: a Session in payment mode with the engine's instant payment methods, on the
 * platform's own account (`platform`), or with the `Stripe-Account` header when a request names a
 * connected account. `expires_at` is the engine's own `expiresAt`, unchanged, so a retry under the
 * same idempotency key sends the same parameters; the engine keeps it inside the declared
 * capabilities. `expireLink` calls `/v1/checkout/sessions/{id}/expire` when the engine's own
 * deadline comes.
 */
export class StripeCheckoutLinks implements PaymentLinks {
  /**
   * Platform mode only, the one this minimal adapter has proven against Stripe test mode (the
   * `Stripe-Account` header for connect mode is sent, but not yet proven live). Checkout's
   * `expires_at` runs from 30 minutes to 24 hours after creation; the engine asks for at least the
   * minimum plus 5 minutes (35), which covers the time between its request and Stripe's arrival.
   */
  readonly capabilities: PaymentLinkCapabilities = { modes: ["platform"], minLinkMinutes: 30, maxLinkMinutes: 1440 };
  readonly #apiKey: string;
  readonly #base: URL;
  readonly #successUrl: string;
  readonly #timeoutMs: number;

  constructor(apiKey: string, options: StripeCheckoutOptions) {
    assertTestModeSecretKey(apiKey);
    this.#apiKey = apiKey;
    this.#base = checkedUrl(options.apiBase ?? "https://api.stripe.com", "apiBase");
    this.#successUrl = checkedUrl(options.successUrl, "successUrl").href;
    this.#timeoutMs = options.timeoutMs ?? 15_000;
  }

  async createLink(input: PaymentLinkRequest): Promise<{ linkId: string; url: string }> {
    const expiresAt = Math.floor(Date.parse(input.expiresAt) / 1000);
    const form: Array<[string, string]> = [
      ["mode", "payment"],
      ["line_items[0][quantity]", "1"],
      ["line_items[0][price_data][currency]", input.currency],
      ["line_items[0][price_data][unit_amount]", String(input.amountMinor)],
      ["line_items[0][price_data][product_data][name]", input.description],
      ...checkoutPaymentMethodTypes(input.paymentMethods).map((type, i): [string, string] => [`payment_method_types[${i}]`, type]),
      ["expires_at", String(expiresAt)],
      ["client_reference_id", input.paymentId],
      ["metadata[payment_id]", input.paymentId],
      ["metadata[call_id]", input.callId],
      ["success_url", this.#successUrl],
    ];
    const session = await this.#call("POST", "/v1/checkout/sessions", { form, idempotencyKey: input.idempotencyKey, account: input.connectedAccountId });
    const id = session.body.id;
    const url = session.body.url;
    if (session.status !== 200 || typeof id !== "string" || !SESSION_ID.test(id) || typeof url !== "string" || !url.startsWith("https://")) {
      throw new StripeApiError(session.status, `Stripe did not create the Checkout Session (${describeError(session)})`);
    }
    if (session.body.livemode !== false) throw new StripeApiError(session.status, "Stripe answered a live-mode session to a test-mode key; refusing it");
    return { linkId: id, url };
  }

  async expireLink(input: { linkId: string; mode: PaymentMode; connectedAccountId?: string; idempotencyKey: string }): Promise<{ state: "expired" | "not_open" }> {
    const id = checkedSessionId(input.linkId);
    const res = await this.#call("POST", `/v1/checkout/sessions/${id}/expire`, { form: [], idempotencyKey: input.idempotencyKey, account: input.connectedAccountId });
    if (res.status === 200) return { state: "expired" };
    if (res.status === 400) {
      // Stripe refuses to expire a session that is not open; read it to tell that from a bad request.
      const now = await this.readLink(id, input.connectedAccountId);
      if (now.status !== "open") return { state: "not_open" };
    }
    throw new StripeApiError(res.status, `Stripe did not expire the Checkout Session (${describeError(res)})`);
  }

  /** Reads a Checkout Session's status from Stripe. Read only: it changes nothing. `signal` cancels the read. */
  async readLink(linkId: string, connectedAccountId?: string, signal?: AbortSignal): Promise<CheckoutSessionStatus> {
    const id = checkedSessionId(linkId);
    const res = await this.#call("GET", `/v1/checkout/sessions/${id}`, { account: connectedAccountId, signal });
    const { status, payment_status: paymentStatus, livemode } = res.body;
    if (
      res.status !== 200 ||
      res.body.id !== id ||
      !(status === "open" || status === "complete" || status === "expired") ||
      !(paymentStatus === "paid" || paymentStatus === "unpaid" || paymentStatus === "no_payment_required") ||
      livemode !== false
    ) {
      throw new StripeApiError(res.status, `Stripe did not answer the Checkout Session (${describeError(res)})`);
    }
    return { linkId: id, status, paymentStatus, livemode };
  }

  async #call(
    method: "GET" | "POST",
    path: string,
    options: { form?: Array<[string, string]>; idempotencyKey?: string; account?: string | undefined; signal?: AbortSignal | undefined },
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.#apiKey}` };
    if (options.idempotencyKey !== undefined) headers["idempotency-key"] = stripeIdempotencyKey(options.idempotencyKey);
    if (options.account !== undefined) headers["stripe-account"] = options.account;
    const timeout = AbortSignal.timeout(this.#timeoutMs);
    const init: RequestInit = { method, headers, redirect: "error", signal: options.signal === undefined ? timeout : AbortSignal.any([timeout, options.signal]) };
    if (options.form !== undefined) {
      headers["content-type"] = "application/x-www-form-urlencoded";
      init.body = new URLSearchParams(options.form).toString();
    }
    const response = await fetch(new URL(path, this.#base), init);
    // A body lost on the way (a dropped connection, a timeout) throws as it is: a transport
    // failure, worth asking again. A body that arrived but is not JSON is Stripe's answer.
    const text = await response.text();
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
    return { status: response.status, body: typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {} };
  }
}


/** Stripe's error types and codes are short snake_case words; anything else, a key above all, is left out. */
const ERROR_WORD = /^[a-z][a-z0-9_]{0,79}$/;
const KEY_PREFIX = /^(sk|rk|pk)_/;

function checkedSessionId(linkId: string): string {
  if (!SESSION_ID.test(linkId)) throw new TypeError("not a test-mode Checkout Session id");
  return linkId;
}

/** The HTTP status and Stripe's error type and code, when they are plain words: never its message, which can quote a key. */
function describeError(res: { status: number; body: Record<string, unknown> }): string {
  const error = res.body.error;
  const e = typeof error === "object" && error !== null ? (error as Record<string, unknown>) : {};
  const parts = [`HTTP ${res.status}`];
  for (const key of ["type", "code"]) {
    const word = e[key];
    if (typeof word === "string" && ERROR_WORD.test(word) && !KEY_PREFIX.test(word)) parts.push(`${key} ${word}`);
  }
  return parts.join(", ");
}
