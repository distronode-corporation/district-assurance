// Stripe Checkout as the engine's PaymentLinks, in one Stripe mode per instance. A session is made
// on the platform's own account (`platform`) or as a direct charge on the business's connected
// account (`connect`: the `Stripe-Account` header and nothing else; no `on_behalf_of` or
// `transfer_data`, which are for destination charges where the platform is the merchant).
import { createHash } from "node:crypto";

import type {
  InstantPaymentMethod,
  PaymentLinkCapabilities,
  PaymentLinkClose,
  PaymentLinkRequest,
  PaymentLinks,
  PaymentMode,
} from "../core/adapters.ts";
import type { CheckoutSessionCreateParams, StripeClientLike } from "./client.ts";
import { StripeAdapterError } from "./errors.ts";
import { checkedApiVersion, STRIPE_BASIL_API_VERSION, type StripeApiVersion, type StripeMode } from "./keys.ts";

/** What Stripe accepts as an `Idempotency-Key` as is: printable ASCII without spaces, 255 at most. */
const PLAIN_IDEMPOTENCY_KEY = /^[\x21-\x7e]{1,255}$/;
/** Stripe's limit on a metadata value, in characters. */
const METADATA_VALUE_LIMIT = 500;
const CONNECTED_ACCOUNT = /^acct_[A-Za-z0-9]{1,255}$/;
const SESSION_ID: Readonly<Record<StripeMode, RegExp>> = {
  test: /^cs_test_[A-Za-z0-9]{1,200}$/,
  live: /^cs_live_[A-Za-z0-9]{1,200}$/,
};
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** Checkout's `expires_at` runs from 30 minutes to 24 hours after creation. */
export const CHECKOUT_MIN_LINK_MINUTES = 30;
export const CHECKOUT_MAX_LINK_MINUTES = 1440;
/**
 * The default link life: Stripe's 30-minute minimum plus 5 minutes for the time between this
 * reading of the clock and Stripe receiving the create (the engine asks for the same margin), so the
 * default never falls under the minimum Stripe measures from its own arrival.
 */
export const CHECKOUT_DEFAULT_LINK_MINUTES = 35;
const MINUTE_MS = 60_000;

/**
 * What Stripe Checkout can do, as the engine's `PaymentLinkCapabilities`: both payment modes, and a
 * link life from Checkout's 30 minutes to 24 hours. A `StripeCheckoutLinks` built without `modes`
 * declares exactly this; one built with `modes` declares those modes with the same limits
 * (`stripeCheckoutCapabilities`). Frozen, so a host can hand it to a config check as it is.
 */
export const STRIPE_CHECKOUT_CAPABILITIES: Readonly<PaymentLinkCapabilities> = stripeCheckoutCapabilities(["platform", "connect"]);

/** Checkout's capabilities for `modes` (each once, in order), frozen. */
export function stripeCheckoutCapabilities(modes: readonly PaymentMode[]): Readonly<PaymentLinkCapabilities> {
  if (modes.length === 0 || modes.some((m) => m !== "platform" && m !== "connect")) throw new TypeError("modes is platform, connect or both");
  return Object.freeze({ modes: Object.freeze([...new Set(modes)]), minLinkMinutes: CHECKOUT_MIN_LINK_MINUTES, maxLinkMinutes: CHECKOUT_MAX_LINK_MINUTES });
}

/**
 * The engine's idempotency key as Stripe's `Idempotency-Key`: as is when Stripe accepts it, else
 * its SHA-256. The same engine key always gives the same header, so a retry returns the same object.
 */
export function stripeIdempotencyKey(engineKey: string): string {
  return PLAIN_IDEMPOTENCY_KEY.test(engineKey) ? engineKey : `sha256:${createHash("sha256").update(engineKey, "utf8").digest("hex")}`;
}

/**
 * The call id as Stripe metadata: as is within 500 UTF-8 bytes (never fewer than characters, so it
 * fits however Stripe counts), else `sha256:` and its hex SHA-256.
 */
export function stripeMetadataCallId(callId: string): string {
  return Buffer.byteLength(callId, "utf8") <= METADATA_VALUE_LIMIT ? callId : `sha256:${createHash("sha256").update(callId, "utf8").digest("hex")}`;
}

/**
 * The engine's instant methods as Checkout names them, as Stripe answered in test mode: Apple Pay
 * and Google Pay are wallets of `card` (Stripe refuses them as method types); Link goes as `link`,
 * which Checkout takes only beside `card`, so Link alone is refused before anything is sent.
 */
export function checkoutPaymentMethodTypes(methods: readonly InstantPaymentMethod[]): Array<"card" | "link"> {
  const types = new Set<"card" | "link">();
  for (const method of methods) types.add(method === "link" ? "link" : "card");
  // No types would be no filter: Stripe would offer any method it deems eligible, not only instant ones.
  if (types.size === 0) throw new TypeError("Checkout needs at least one payment method type");
  if (types.has("link") && !types.has("card")) throw new TypeError("Checkout offers Link only beside cards: add card, apple_pay or google_pay to the step's paymentMethods");
  return [...types];
}

/** A link's end, `minutes` from `now`: by default Stripe's minimum plus the dispatch margin (35). */
export function checkoutExpiresAt(now: Date, minutes: number = CHECKOUT_DEFAULT_LINK_MINUTES): string {
  if (!Number.isInteger(minutes) || minutes < CHECKOUT_MIN_LINK_MINUTES || minutes > CHECKOUT_MAX_LINK_MINUTES) {
    throw new TypeError(`a Checkout link lives from ${CHECKOUT_MIN_LINK_MINUTES} to ${CHECKOUT_MAX_LINK_MINUTES} minutes`);
  }
  return new Date(now.getTime() + minutes * MINUTE_MS).toISOString();
}

/** A Checkout Session as read back from Stripe, read only. */
export interface CheckoutSessionStatus {
  linkId: string;
  status: "open" | "complete" | "expired";
  paymentStatus: "paid" | "unpaid" | "no_payment_required";
  livemode: boolean;
}

/**
 * What an expire found, read back from Stripe:
 *  - `expired`: this call's own answer shows it closed the open session;
 *  - `already_expired`: the session is expired, but not shown closed by this call (an earlier
 *    expire, Stripe's own deadline, or an answer that was lost or did not show the close);
 *  - `complete`: the payer finished first (paid won the race), nothing was closed;
 *  - `open`: Stripe answered but the session still reads open (only `expire` answers this;
 *    `expireLink` throws a retryable error for it).
 */
export interface CheckoutExpireResult {
  outcome: "expired" | "already_expired" | "complete" | "open";
  session: CheckoutSessionStatus;
}

export interface StripeCheckoutLinksOptions {
  /** The client's mode: ids and every answer's `livemode` must be this mode's. */
  mode: StripeMode;
  /** Where Checkout sends the payer once paid: https, or http to the loopback (a demo page). */
  successUrl: string;
  /** Default both. A host taking connect payments only says `["connect"]`. */
  modes?: readonly PaymentMode[];
  /** The version the client sends; default endive. Basil (recorded test runs) is refused in live mode. */
  apiVersion?: StripeApiVersion;
  /**
   * Default the system clock (wall time). `createLink` keeps `expiresAt` inside Checkout's window by
   * THIS clock, so a host whose engine runs on another clock (a fixed or a shifted one) passes the
   * engine's clock here, or links it asks for are refused as too short or too long.
   */
  now?: () => Date;
}

const SESSION_STATUS: Readonly<Record<string, CheckoutSessionStatus["status"]>> = { open: "open", complete: "complete", expired: "expired" };
const PAYMENT_STATUS: Readonly<Record<string, CheckoutSessionStatus["paymentStatus"]>> = {
  paid: "paid",
  unpaid: "unpaid",
  no_payment_required: "no_payment_required",
};

function lookup<T>(table: Readonly<Record<string, T>>, value: unknown): T | undefined {
  return typeof value === "string" && Object.hasOwn(table, value) ? table[value] : undefined;
}

function opensAsHttps(value: unknown): value is string {
  return typeof value === "string" && URL.canParse(value) && new URL(value).protocol === "https:";
}

function checkedSuccessUrl(value: unknown): string {
  if (typeof value !== "string" || !URL.canParse(value)) throw new TypeError("successUrl must be https (http only to the loopback)");
  const url = new URL(value);
  if (url.username !== "" || url.password !== "") throw new TypeError("successUrl carries no credentials");
  if (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname))) return url.href;
  throw new TypeError("successUrl must be https (http only to the loopback)");
}

export class StripeCheckoutLinks implements PaymentLinks {
  readonly capabilities: PaymentLinkCapabilities;
  readonly mode: StripeMode;
  readonly apiVersion: StripeApiVersion;
  readonly successUrl: string;
  readonly #client: StripeClientLike;
  readonly #now: () => Date;

  constructor(client: StripeClientLike, options: StripeCheckoutLinksOptions) {
    const { mode, successUrl, modes, apiVersion, now } = options;
    this.apiVersion = checkedApiVersion(mode, apiVersion);
    this.mode = mode;
    this.successUrl = checkedSuccessUrl(successUrl);
    this.capabilities = modes === undefined ? STRIPE_CHECKOUT_CAPABILITIES : stripeCheckoutCapabilities(modes);
    this.#client = client;
    this.#now = now ?? (() => new Date());
  }

  /**
   * The account a request is made on: none in platform mode, the connected account in connect mode.
   * A mode this instance does not take, a connect request without a well-formed `acct_` id, or a
   * platform request naming one, is refused before anything is sent.
   */
  #account(mode: PaymentMode, connectedAccountId: string | undefined): string | undefined {
    if (!this.capabilities.modes.includes(mode)) throw new TypeError(`these payment links do not take ${String(mode)} mode`);
    if (mode === "platform") {
      if (connectedAccountId !== undefined) throw new TypeError("platform mode takes no connected account");
      return undefined;
    }
    if (connectedAccountId === undefined || !CONNECTED_ACCOUNT.test(connectedAccountId)) throw new TypeError("connect mode needs a connected account id (acct_...)");
    return connectedAccountId;
  }

  #sessionId(linkId: string): string {
    if (typeof linkId !== "string" || !SESSION_ID[this.mode].test(linkId)) throw new TypeError(`not a ${this.mode}-mode Checkout Session id (cs_${this.mode}_...)`);
    return linkId;
  }

  #expiresAt(iso: string): number {
    const at = Date.parse(iso);
    if (!Number.isFinite(at)) throw new TypeError("expiresAt must be an ISO 8601 time");
    const now = this.#now().getTime();
    if (at < now + CHECKOUT_MIN_LINK_MINUTES * MINUTE_MS || at > now + CHECKOUT_MAX_LINK_MINUTES * MINUTE_MS) {
      throw new TypeError(`expiresAt must be ${CHECKOUT_MIN_LINK_MINUTES} minutes to 24 hours from now`);
    }
    return Math.floor(at / 1000);
  }

  async createLink(input: PaymentLinkRequest): Promise<{ linkId: string; url: string }> {
    const account = this.#account(input.mode, input.connectedAccountId);
    const types = checkoutPaymentMethodTypes(input.paymentMethods);
    const params: CheckoutSessionCreateParams = {
      mode: "payment",
      line_items: [{ quantity: 1, price_data: { currency: input.currency, unit_amount: input.amountMinor, product_data: { name: input.description } } }],
      ...(this.apiVersion === STRIPE_BASIL_API_VERSION ? { payment_method_types: types } : { allowed_payment_method_types: types }),
      expires_at: this.#expiresAt(input.expiresAt),
      client_reference_id: input.paymentId,
      metadata: { payment_id: input.paymentId, call_id: stripeMetadataCallId(input.callId) },
      success_url: this.successUrl,
    };
    let answer: unknown;
    try {
      answer = await this.#client.checkout.sessions.create(params, {
        ...(account === undefined ? {} : { stripeAccount: account }),
        idempotencyKey: stripeIdempotencyKey(input.idempotencyKey),
      });
    } catch (err) {
      throw StripeAdapterError.from("create the Checkout Session", err);
    }
    const session = isRecord(answer) ? answer : {};
    if (typeof session.id !== "string" || !SESSION_ID[this.mode].test(session.id) || !opensAsHttps(session.url) || session.livemode !== (this.mode === "live")) {
      throw StripeAdapterError.answer(`answer a ${this.mode}-mode Checkout Session`);
    }
    return { linkId: session.id, url: session.url };
  }

  /**
   * Expires a session now and reads back what it is, so a caller can tell a close it made from one
   * already made and from a payment that won the race. Idempotent: expiring an expired session
   * answers `already_expired`.
   *
   * ⛔ NO IDEMPOTENCY KEY IS SENT. Stripe saves a key's first result, a 500 included, and answers
   * every retry under that key with it for a day, so a keyed expire that failed once could never be
   * retried into an answer. An expire needs no key: a second expire of a closed session is Stripe's
   * 400, which this reads back. `input.idempotencyKey` is accepted for the `PaymentLinks` contract
   * and not sent.
   *
   * Any failure is followed by a read of the session: Stripe's 400 (the session is not open) and a
   * 429, a 5xx or a lost answer alike. A session the read shows closed answers its outcome; one still
   * open, or a read that fails too, throws the expire's own error, retryable for a 429, a 5xx or a
   * lost answer and not for another refusal.
   */
  async expire(input: PaymentLinkClose): Promise<CheckoutExpireResult> {
    const id = this.#sessionId(input.linkId);
    const account = this.#account(input.mode, input.connectedAccountId);
    let answer: unknown;
    try {
      answer = await this.#client.checkout.sessions.expire(id, {}, account === undefined ? {} : { stripeAccount: account });
    } catch (err) {
      const failure = StripeAdapterError.from("expire the Checkout Session", err);
      let now: CheckoutSessionStatus;
      try {
        now = await this.readLink(id, account);
      } catch {
        throw failure;
      }
      if (now.status === "open") {
        // Still open after an answer that arrived but could not be trusted (a 2xx of the wrong shape):
        // the same as a 200 that did not show the close, asking again may close it.
        if (failure.status !== null && failure.status < 300) throw stillOpen();
        // Still open after a refusal or no answer: the refusal is the answer, retryable or not as it says.
        throw failure;
      }
      return { outcome: now.status === "expired" ? "already_expired" : now.status, session: now };
    }
    const direct = this.#status(id, answer);
    if (direct?.status === "expired") return { outcome: "expired", session: direct };
    // An answer that does not show this session expired establishes nothing: read it back, and
    // never claim the close for this call.
    const now = await this.readLink(id, account);
    return { outcome: now.status === "expired" ? "already_expired" : now.status, session: now };
  }

  async expireLink(input: PaymentLinkClose): Promise<{ state: "expired" | "not_open" }> {
    const { outcome } = await this.expire(input);
    if (outcome === "open") throw stillOpen();
    return { state: outcome === "expired" ? "expired" : "not_open" };
  }

  /** A session's status, on the connected account when one is named. Read only. `signal` cancels the read on a client that supports it. */
  async readLink(linkId: string, connectedAccountId?: string, signal?: AbortSignal): Promise<CheckoutSessionStatus> {
    const id = this.#sessionId(linkId);
    if (connectedAccountId !== undefined && !CONNECTED_ACCOUNT.test(connectedAccountId)) throw new TypeError("connect mode needs a connected account id (acct_...)");
    let answer: unknown;
    try {
      answer = await this.#client.checkout.sessions.retrieve(id, {}, {
        ...(connectedAccountId === undefined ? {} : { stripeAccount: connectedAccountId }),
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (err) {
      throw StripeAdapterError.from("read the Checkout Session", err);
    }
    const status = this.#status(id, answer);
    if (status === null) throw StripeAdapterError.answer(`answer the ${this.mode}-mode Checkout Session`);
    return status;
  }

  /** The session's status when the answer is this session, in this mode, with known statuses; else null. */
  #status(id: string, answer: unknown): CheckoutSessionStatus | null {
    const session = isRecord(answer) ? answer : {};
    const status = lookup(SESSION_STATUS, session.status);
    const paymentStatus = lookup(PAYMENT_STATUS, session.payment_status);
    if (session.id !== id || session.livemode !== (this.mode === "live") || status === undefined || paymentStatus === undefined) return null;
    return { linkId: id, status, paymentStatus, livemode: this.mode === "live" };
  }
}

/** A session that still reads open after a close was asked for: always worth asking again. */
function stillOpen(): StripeAdapterError {
  return new StripeAdapterError("expire the Checkout Session (still open)", { status: null, type: null, code: null }, { retryable: true });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
