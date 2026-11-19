// Stripe adapters for the reference server, so people can try it with their OWN Stripe test-mode
// keys. They call Stripe's REST API with Node's built-in fetch (no SDK, no dependency).
//
// StripeCheckoutLinks (PAY-1, minimal): Checkout Sessions in TEST MODE ONLY. The constructor
// refuses any key that is not a secret test key (`sk_test_`), live and restricted keys included,
// and never puts a key, or Stripe's own error message (which can quote part of one), in an error.
// The Checkout URL is returned to the engine and never logged here.
//
// StripeIdentityProvider (VER-5) is not built yet and throws NotImplementedError.
import {
  NotImplementedError,
  type IdentityProvider,
  type InstantPaymentMethod,
  type PaymentLinkCapabilities,
  type PaymentLinkRequest,
  type PaymentLinks,
  type PaymentMode,
} from "../../../src/index.ts";

/** Stripe Identity: a VerificationSession of type document with a selfie check. */
export class StripeIdentityProvider implements IdentityProvider {
  readonly #apiKey: string;

  constructor(apiKey: string) {
    this.#apiKey = apiKey;
  }

  async createDocumentCheck(_input: { callId: string; idempotencyKey: string }): Promise<{ sessionId: string; url: string }> {
    void this.#apiKey;
    throw new NotImplementedError("StripeIdentityProvider.createDocumentCheck", "VER-5");
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

/**
 * Stripe answered, and the answer was a refusal or not one this adapter can trust. `status` is
 * the HTTP status (200 for an answer of the wrong shape). The message names the status and
 * Stripe's error type and code, never Stripe's own message, which can quote part of a key.
 */
export class StripeApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "StripeApiError";
    this.status = status;
  }

  /** Worth asking again: Stripe was busy or failed on its side. */
  get retryable(): boolean {
    return this.status === 429 || this.status >= 500;
  }
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
   * `expires_at` runs from 30 minutes to 24 hours after creation; the declared window keeps a
   * minute of margin at each end, since the engine counts from the request and Stripe from its
   * arrival.
   */
  readonly capabilities: PaymentLinkCapabilities = { modes: ["platform"], minLinkMinutes: 31, maxLinkMinutes: 1439 };
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

  /** Reads a Checkout Session's status from Stripe. Read only: it changes nothing. */
  async readLink(linkId: string, connectedAccountId?: string): Promise<CheckoutSessionStatus> {
    const id = checkedSessionId(linkId);
    const res = await this.#call("GET", `/v1/checkout/sessions/${id}`, { account: connectedAccountId });
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
    options: { form?: Array<[string, string]>; idempotencyKey?: string; account?: string | undefined },
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.#apiKey}` };
    if (options.idempotencyKey !== undefined) headers["idempotency-key"] = options.idempotencyKey;
    if (options.account !== undefined) headers["stripe-account"] = options.account;
    const init: RequestInit = { method, headers, redirect: "error", signal: AbortSignal.timeout(this.#timeoutMs) };
    if (options.form !== undefined) {
      headers["content-type"] = "application/x-www-form-urlencoded";
      init.body = new URLSearchParams(options.form).toString();
    }
    const response = await fetch(new URL(path, this.#base), init);
    const parsed: unknown = await response.json().catch(() => null);
    return { status: response.status, body: typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {} };
  }
}

function checkedSessionId(linkId: string): string {
  if (!SESSION_ID.test(linkId)) throw new TypeError("not a test-mode Checkout Session id");
  return linkId;
}

/** The HTTP status and Stripe's error type and code: never its message, which can quote a key. */
function describeError(res: { status: number; body: Record<string, unknown> }): string {
  const error = res.body.error;
  const e = typeof error === "object" && error !== null ? (error as Record<string, unknown>) : {};
  const parts = [`HTTP ${res.status}`];
  for (const key of ["type", "code"]) if (typeof e[key] === "string") parts.push(`${key} ${String(e[key]).slice(0, 80)}`);
  return parts.join(", ");
}
