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
const MINUTE_MS = 60_000;

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
  if (types.has("link") && !types.has("card")) throw new TypeError("Checkout offers Link only beside cards: add card, apple_pay or google_pay to the step's paymentMethods");
  return [...types];
}

/** The default link life: Stripe's minimum, from `now`. */
export function checkoutExpiresAt(now: Date, minutes: number = CHECKOUT_MIN_LINK_MINUTES): string {
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
 *  - `expired`: this call closed the open session;
 *  - `already_expired`: it was already closed by an earlier expire or by Stripe (idempotent);
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
  /** Default the system clock. Used only to keep `expiresAt` inside Checkout's window. */
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
    const allowed = modes ?? ["platform", "connect"];
    if (allowed.length === 0 || allowed.some((m) => m !== "platform" && m !== "connect")) throw new TypeError("modes is platform, connect or both");
    this.capabilities = Object.freeze({ modes: Object.freeze([...new Set(allowed)]), minLinkMinutes: CHECKOUT_MIN_LINK_MINUTES, maxLinkMinutes: CHECKOUT_MAX_LINK_MINUTES });
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
   * answers `already_expired`. A 429, a 5xx or a lost answer throws a retryable
   * `StripeAdapterError`; any other refusal throws one that is not.
   */
  async expire(input: PaymentLinkClose): Promise<CheckoutExpireResult> {
    const id = this.#sessionId(input.linkId);
    const account = this.#account(input.mode, input.connectedAccountId);
    const options = { ...(account === undefined ? {} : { stripeAccount: account }), idempotencyKey: stripeIdempotencyKey(input.idempotencyKey) };
    let answer: unknown;
    try {
      answer = await this.#client.checkout.sessions.expire(id, {}, options);
    } catch (err) {
      const failure = StripeAdapterError.from("expire the Checkout Session", err);
      // Stripe refuses (400) to expire a session that is not open: read it to learn what it is.
      if (failure.status !== 400) throw failure;
      const now = await this.readLink(id, account);
      return { outcome: now.status === "expired" ? "already_expired" : now.status, session: now };
    }
    const direct = this.#status(id, answer);
    if (direct?.status === "expired") return { outcome: "expired", session: direct };
    // An answer that does not show this session expired establishes nothing: read it back.
    const now = await this.readLink(id, account);
    return { outcome: now.status, session: now };
  }

  async expireLink(input: PaymentLinkClose): Promise<{ state: "expired" | "not_open" }> {
    const { outcome } = await this.expire(input);
    if (outcome === "open") throw new StripeAdapterError("expire the Checkout Session (still open)", { status: null, type: null, code: null }, { retryable: true });
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
