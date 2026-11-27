// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The Stripe adapters' errors. Neither ever carries Stripe's own message or any part of a key:
// Stripe's message can quote part of the key a request was made with.

/** Stripe's error types and codes are short words; anything else, a key above all, is left out. */
const ERROR_WORD = /^[A-Za-z][A-Za-z0-9_]{0,79}$/;
const KEY_LIKE = /^(?:sk|rk|pk|whsec)_/i;

function word(value: unknown): string | null {
  return typeof value === "string" && ERROR_WORD.test(value) && !KEY_LIKE.test(value) ? value : null;
}

function statusOf(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 100 && value <= 599 ? value : null;
}

/**
 * What a failure is made of: Stripe's HTTP status, error type and code. The SDK's errors carry
 * them as `statusCode`, `rawType` (the API's own type) or `type`, and `code`; so do the errors
 * `fetchStripeClient` throws. Anything else is read as no detail.
 */
export interface StripeErrorDetail {
  /** The HTTP status Stripe answered, or null when no answer arrived (a timeout, a dropped connection). */
  status: number | null;
  type: string | null;
  code: string | null;
}

/** The status, type and code of an error from the SDK or from `fetchStripeClient`, and nothing else. */
export function stripeErrorDetail(cause: unknown): StripeErrorDetail {
  const detail = typeof cause === "object" && cause !== null ? (cause as Record<string, unknown>) : {};
  // A rejection from a structural client may be any object, a getter that throws included: reading
  // it never throws here, and an unreadable error is one with no detail.
  try {
    return { status: statusOf(detail.statusCode), type: word(detail.rawType) ?? word(detail.type), code: word(detail.code) };
  } catch {
    return { status: null, type: null, code: null };
  }
}

/**
 * A Stripe call that failed, or an answer this adapter will not trust. The message names the step,
 * the HTTP status and Stripe's error type and code when they are plain words: never Stripe's
 * message. `retryable` is true when asking again may succeed: no answer arrived, Stripe was busy
 * (429) or failed on its side (5xx), or the step says so (a session still open after an expire).
 */
export class StripeAdapterError extends Error {
  readonly step: string;
  readonly status: number | null;
  readonly type: string | null;
  readonly code: string | null;
  readonly retryable: boolean;

  constructor(step: string, detail: StripeErrorDetail, options: { retryable?: boolean } = {}) {
    const parts = [detail.status === null ? "no answer" : `HTTP ${detail.status}`];
    if (detail.type !== null) parts.push(detail.type);
    if (detail.code !== null) parts.push(detail.code);
    super(`Stripe did not ${step} (${parts.join(", ")})`);
    this.name = "StripeAdapterError";
    this.step = step;
    this.status = detail.status;
    this.type = detail.type;
    this.code = detail.code;
    this.retryable = options.retryable ?? (detail.status === null || detail.status === 429 || detail.status >= 500);
  }

  /** A failed call, from the SDK's or `fetchStripeClient`'s error. */
  static from(step: string, cause: unknown): StripeAdapterError {
    return new StripeAdapterError(step, stripeErrorDetail(cause));
  }

  /** An answer that arrived but is not one this adapter can trust: not retryable. */
  static answer(step: string): StripeAdapterError {
    return new StripeAdapterError(step, { status: 200, type: "malformed_response", code: null });
  }
}
