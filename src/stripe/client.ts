// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The Stripe calls the adapters make, as a structural type. A stripe-node `Stripe` instance fits it
// unchanged (test/stripe-client-types.test.ts proves that at compile time), and `fetchStripeClient`
// is the same surface over Node's own fetch, for a host without the SDK. No runtime dependency
// either way (ADR-3, ADR-30).
import { assertStripeKey, checkedApiVersion, type StripeApiVersion, type StripeMode } from "./keys.ts";

/** Per-request options, named as stripe-node names them. */
export interface StripeRequestOptions {
  /** The connected account the request is made on (the `Stripe-Account` header). */
  stripeAccount?: string;
  idempotencyKey?: string;
  /** Milliseconds. */
  timeout?: number;
  maxNetworkRetries?: number;
  /** Cancels the request. Honoured by `fetchStripeClient`; pass it only to a client that supports it. */
  signal?: AbortSignal;
}

/** The parameters the Checkout adapter sends to create a session. */
export interface CheckoutSessionCreateParams {
  mode: "payment";
  line_items: Array<{ quantity: number; price_data: { currency: string; unit_amount: number; product_data: { name: string } } }>;
  /** Endive's name for the methods a session offers. */
  allowed_payment_method_types?: Array<"card" | "link">;
  /** Basil's name (test-mode recordings only). */
  payment_method_types?: Array<"card" | "link">;
  expires_at: number;
  client_reference_id: string;
  metadata: Record<string, string>;
  success_url: string;
}

export interface ConnectAccountCreateParams {
  identity: { country: string };
  dashboard: "full";
  configuration: { merchant: Record<string, never> };
  defaults: { responsibilities: { fees_collector: "stripe"; losses_collector: "stripe" } };
  metadata: Record<string, string>;
  include: Array<"configuration.merchant" | "requirements">;
}

export interface AccountLinkCreateParams {
  account: string;
  use_case: { type: "account_onboarding"; account_onboarding: { return_url: string; refresh_url: string } };
}

export interface ConnectAccountRetrieveParams {
  include: Array<"configuration.merchant" | "requirements">;
}

/**
 * Exactly the Stripe calls the adapters make: Checkout Sessions (create, retrieve, expire) and
 * Accounts v2 (create, retrieve, an account link). Answers are read as `unknown` and checked field
 * by field, so an answer of any other shape is refused rather than trusted.
 */
export interface StripeClientLike {
  checkout: {
    sessions: {
      create(params: CheckoutSessionCreateParams, options?: StripeRequestOptions): Promise<unknown>;
      retrieve(id: string, params?: Record<string, never>, options?: StripeRequestOptions): Promise<unknown>;
      expire(id: string, params?: Record<string, never>, options?: StripeRequestOptions): Promise<unknown>;
    };
  };
  v2: {
    core: {
      accounts: {
        create(params: ConnectAccountCreateParams, options?: StripeRequestOptions): Promise<unknown>;
        retrieve(id: string, params?: ConnectAccountRetrieveParams, options?: StripeRequestOptions): Promise<unknown>;
      };
      accountLinks: {
        create(params: AccountLinkCreateParams, options?: StripeRequestOptions): Promise<unknown>;
      };
    };
  };
}

/**
 * Stripe's form encoding, as stripe-node sends it: nested keys in brackets, arrays indexed from 0,
 * values percent-encoded as `qs` does (RFC 3986), brackets left readable. The SDK and this client
 * therefore send byte-identical bodies (test/stripe-client-bytes.test.ts).
 */
export function stripeFormEncode(data: Record<string, unknown>): string {
  const pairs: string[] = [];
  const encode = (key: string, value: unknown): void => {
    if (value === undefined) return;
    if (value === null || typeof value !== "object") {
      pairs.push(`${encodePart(key)}=${encodePart(value === null ? "" : String(value))}`);
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, i) => encode(`${key}[${i}]`, item));
      return;
    }
    for (const [k, v] of Object.entries(value)) encode(`${key}[${k}]`, v);
  };
  for (const [key, value] of Object.entries(data)) encode(key, value);
  return pairs.join("&");
}

function encodePart(value: string): string {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/%5B/g, "[")
    .replace(/%5D/g, "]");
}

/** What `fetchStripeClient` throws: the status, Stripe's error type and code, never Stripe's message. */
export class StripeHttpError extends Error {
  readonly statusCode: number | null;
  readonly rawType: string | null;
  readonly code: string | null;
  constructor(statusCode: number | null, rawType: string | null, code: string | null) {
    super(statusCode === null ? "no answer from Stripe" : `Stripe answered HTTP ${statusCode}`);
    this.name = "StripeHttpError";
    this.statusCode = statusCode;
    this.rawType = rawType;
    this.code = code;
  }
}

export interface FetchStripeClientOptions {
  /** The key's mode; the key must be this mode's (`assertStripeKey`). */
  mode: StripeMode;
  /** Default `STRIPE_API_VERSION`; basil in test mode only. */
  apiVersion?: StripeApiVersion;
  /** Default `https://api.stripe.com`. https only; http only on a loopback host (a test's fake). */
  apiBase?: string;
  /** Default the global `fetch`. */
  fetch?: typeof fetch;
  /** Per request, default 15,000 ms, from 1 to 60,000. */
  timeoutMs?: number;
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);
const PATH_ID = /^[A-Za-z0-9_]{1,255}$/;
const STRIPE_WORD = /^[a-z0-9_]{1,64}$/;
/** Anything shaped like a key or a webhook secret is never kept, in any field. */
const KEY_LIKE = /^(?:sk|rk|pk|whsec)_/i;
/** The most network retries a read honours. */
const MAX_READ_RETRIES = 2;

/** The base the key is sent to: https, or http on a loopback host; no credentials in it. */
function checkedBase(apiBase: string): URL {
  if (!URL.canParse(apiBase)) throw new TypeError("apiBase must be https (http only on a loopback host)");
  const url = new URL(apiBase);
  // No credentials in it: fetch refuses such a URL and quotes it, password and all, in its error.
  if (url.username !== "" || url.password !== "") throw new TypeError("apiBase carries no credentials");
  if (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname))) return url;
  throw new TypeError("apiBase must be https (http only on a loopback host)");
}

function pathId(id: string): string {
  if (!PATH_ID.test(id)) throw new TypeError("a Stripe object id is letters, digits and underscores only");
  return id;
}

/**
 * `StripeClientLike` over Node's fetch. The key is checked against `mode` first, then kept in a
 * closure and sent only in the `Authorization` header to the checked base, never redirected. A
 * refusal throws `StripeHttpError` with Stripe's status, type and code; a lost answer throws it
 * with a null status. v1 bodies are form-encoded as the SDK encodes them, v2 bodies are JSON.
 */
export function fetchStripeClient(key: string, options: FetchStripeClientOptions): StripeClientLike {
  // Each option read once: a getter answering differently later cannot move the key elsewhere.
  const { mode, apiVersion, apiBase, fetch: doFetch, timeoutMs } = options;
  assertStripeKey(key, mode);
  const version = checkedApiVersion(mode, apiVersion);
  const base = checkedBase(apiBase ?? "https://api.stripe.com");
  if (timeoutMs !== undefined && !(Number.isInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 60_000)) {
    throw new TypeError("timeoutMs must be a whole number of milliseconds from 1 to 60000");
  }
  const send = doFetch ?? fetch;

  async function call(
    method: "GET" | "POST",
    path: string,
    body: { kind: "form" | "json" | "query"; data: Record<string, unknown> },
    requestOptions: StripeRequestOptions | undefined,
  ): Promise<unknown> {
    const headers: Record<string, string> = { authorization: `Bearer ${key}`, "stripe-version": version };
    const { stripeAccount, idempotencyKey, timeout, signal, maxNetworkRetries } = requestOptions ?? {};
    if (stripeAccount !== undefined) headers["stripe-account"] = stripeAccount;
    if (idempotencyKey !== undefined) headers["idempotency-key"] = idempotencyKey;
    const url = new URL(path, base);
    const init: RequestInit = { method, headers, redirect: "error" };
    if (body.kind === "query") {
      const query = stripeFormEncode(body.data);
      if (query !== "") url.search = query;
    } else if (body.kind === "json") {
      headers["content-type"] = "application/json";
      init.body = JSON.stringify(body.data);
    } else {
      headers["content-type"] = "application/x-www-form-urlencoded";
      init.body = stripeFormEncode(body.data);
    }
    // A read may be asked again after a lost answer, as stripe-node does, when the caller asks for it;
    // a write never is here (it has its own idempotency rules). Each attempt has its own deadline, so
    // the whole read is bounded by (retries + 1) deadlines, and a cancelled caller is never retried.
    const retries = method === "GET" && typeof maxNetworkRetries === "number" && Number.isInteger(maxNetworkRetries) ? Math.min(Math.max(maxNetworkRetries, 0), MAX_READ_RETRIES) : 0;
    let response: Response | undefined;
    let text = "";
    for (let attempt = 0; response === undefined; attempt++) {
      const deadline = AbortSignal.timeout(timeout ?? timeoutMs ?? 15_000);
      try {
        const answered = await send(url, { ...init, signal: signal === undefined ? deadline : AbortSignal.any([deadline, signal]) });
        text = await answered.text();
        response = answered;
      } catch {
        // A transport failure: no answer, worth asking again. Its own error can quote the URL.
        if (attempt >= retries || signal?.aborted === true) throw new StripeHttpError(null, null, null);
      }
    }
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
    if (!response.ok) {
      const error = isRecord(parsed) && isRecord(parsed.error) ? parsed.error : {};
      throw new StripeHttpError(response.status, wordOrNull(error.type), wordOrNull(error.code));
    }
    if (!isRecord(parsed)) throw new StripeHttpError(response.status, "malformed_response", null);
    return parsed;
  }

  return {
    checkout: {
      sessions: {
        create: async (params, o) => call("POST", "/v1/checkout/sessions", { kind: "form", data: { ...params } }, o),
        // async, so a refused id rejects the returned promise rather than throwing at the call.
        retrieve: async (id, params, o) => call("GET", `/v1/checkout/sessions/${pathId(id)}`, { kind: "query", data: { ...params } }, o),
        expire: async (id, params, o) => call("POST", `/v1/checkout/sessions/${pathId(id)}/expire`, { kind: "form", data: { ...params } }, o),
      },
    },
    v2: {
      core: {
        accounts: {
          create: async (params, o) => call("POST", "/v2/core/accounts", { kind: "json", data: { ...params } }, o),
          retrieve: async (id, params, o) => call("GET", `/v2/core/accounts/${pathId(id)}`, { kind: "query", data: { ...params } }, o),
        },
        accountLinks: {
          create: async (params, o) => call("POST", "/v2/core/account_links", { kind: "json", data: { ...params } }, o),
        },
      },
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function wordOrNull(value: unknown): string | null {
  return typeof value === "string" && STRIPE_WORD.test(value) && !KEY_LIKE.test(value) ? value : null;
}
