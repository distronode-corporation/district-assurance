// Stripe webhooks: the signature check and the mapping from Stripe's event types to the engine's
// outcomes. The signature scheme is Stripe's published one: the `Stripe-Signature` header carries
// `t=<unix seconds>` and one or more `v1=<hex>`, each an HMAC-SHA256 of `<t>.<raw body>` under the
// endpoint's signing secret. Nothing here calls Stripe.
import { EngineError } from "../core/errors.ts";
import { hexDigestsEqual, hmacSha256Hex } from "../core/hash.ts";
import type { PaymentOutcome } from "../pay/payment.ts";
import { DISPUTE_STATUSES, type DisputeOutcome, type DisputeStatus } from "../pay/refunds.ts";

export type SignatureCheck =
  | { ok: true; timestamp: number }
  | { ok: false; reason: "missing_header" | "malformed_header" | "no_secret" | "timestamp_out_of_tolerance" | "no_matching_signature" };

export interface StripeSignatureInput {
  /** The raw request body, exactly as received. A re-serialised body never verifies. */
  payload: string;
  header: string | null | undefined;
  /** The endpoint's signing secrets; more than one while a secret is rolled. */
  secrets: readonly string[];
  now: Date;
  /** Default 300 seconds, Stripe's own default; an integer from 0 to 86,400. Applies to the past and the future. */
  toleranceSeconds?: number;
}

/** The widest tolerance a host may set: a day. */
const MAX_TOLERANCE_SECONDS = 86_400;

/**
 * Checks a Stripe webhook signature. A tolerance that is not an integer from 0 to 86,400, or a
 * `now` that is not a valid date, throws `invalid_input` before anything is checked: a NaN or an
 * Infinity in either would make every timestamp look fresh, so a replay of any age would pass.
 */
export function verifyStripeSignature(input: StripeSignatureInput): SignatureCheck {
  // Only a missing tolerance takes the default: null, a string or NaN is a host bug, refused.
  // Each field is read once, so a getter cannot pass a check and answer something else after it.
  const { header, payload, now, toleranceSeconds } = input;
  const tolerance: unknown = toleranceSeconds === undefined ? 300 : toleranceSeconds;
  if (!Number.isSafeInteger(tolerance) || (tolerance as number) < 0 || (tolerance as number) > MAX_TOLERANCE_SECONDS) {
    throw new EngineError("invalid_input", "toleranceSeconds must be an integer from 0 to 86400");
  }
  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  if (!Number.isFinite(nowMs)) throw new EngineError("invalid_input", "now must be a valid Date");
  const secrets = input.secrets.filter((s) => s.length > 0);
  if (secrets.length === 0) return { ok: false, reason: "no_secret" };
  if (header === null || header === undefined || header === "") return { ok: false, reason: "missing_header" };
  let timestamp: number | null = null;
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === "t" && /^\d{1,12}$/.test(value)) timestamp = Number(value);
    if (key === "v1") signatures.push(value);
  }
  if (timestamp === null || signatures.length === 0) return { ok: false, reason: "malformed_header" };
  if (Math.abs(Math.floor(nowMs / 1000) - timestamp) > (tolerance as number)) {
    return { ok: false, reason: "timestamp_out_of_tolerance" };
  }
  const signed = `${timestamp}.${payload}`;
  for (const secret of secrets) {
    const expected = hmacSha256Hex(secret, signed);
    if (signatures.some((sig) => hexDigestsEqual(expected, sig))) return { ok: true, timestamp };
  }
  return { ok: false, reason: "no_matching_signature" };
}

/** A header for a payload, in Stripe's format. For tests, the demo and local replays. */
export function signStripePayload(payload: string, secret: string, timestamp: number): string {
  return `t=${timestamp},v1=${hmacSha256Hex(secret, `${timestamp}.${payload}`)}`;
}

export interface IdentityOutcome {
  sessionId: string;
  status: "verified" | "requires_input" | "canceled";
}

export type ParsedStripeEvent =
  | { eventId: string; livemode: boolean; kind: "identity"; outcome: IdentityOutcome }
  | { eventId: string; livemode: boolean; kind: "payment"; outcome: PaymentOutcome & { paymentIntentId?: string } }
  | { eventId: string; livemode: boolean; kind: "dispute"; outcome: DisputeOutcome }
  | { eventId: string; livemode: boolean; kind: "ignored"; type: string };

/** Stripe's dispute events. Each carries the dispute as it is now; the engine keeps the latest. */
const DISPUTE_TYPES = new Set(["charge.dispute.created", "charge.dispute.updated", "charge.dispute.closed", "charge.dispute.funds_withdrawn", "charge.dispute.funds_reinstated"]);

const IDENTITY_TYPES: Record<string, IdentityOutcome["status"]> = {
  "identity.verification_session.verified": "verified",
  "identity.verification_session.requires_input": "requires_input",
  "identity.verification_session.canceled": "canceled",
};

const PAYMENT_STATUSES = new Set(["paid", "unpaid", "no_payment_required"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Maps a verified event body to an outcome. Null when the body is not a well-formed Stripe event. */
export function parseStripeEvent(body: string): ParsedStripeEvent | null {
  let event: unknown;
  try {
    event = JSON.parse(body);
  } catch {
    return null;
  }
  if (!isRecord(event) || typeof event.id !== "string" || typeof event.type !== "string") return null;
  const object = isRecord(event.data) ? event.data.object : undefined;
  if (!isRecord(object) || typeof object.id !== "string") return null;
  const base = { eventId: event.id, livemode: event.livemode === true };
  // A Connect event names the connected account it came from; the engine checks it against the payment's.
  // One that is present but not a name is not a well-formed event: never read as "no account".
  if (event.account !== undefined && typeof event.account !== "string") return null;
  const account = typeof event.account === "string" ? { account: event.account } : {};
  const linkId = object.id;
  const identity = IDENTITY_TYPES[event.type];
  if (identity !== undefined) return { ...base, kind: "identity", outcome: { sessionId: linkId, status: identity } };
  if (DISPUTE_TYPES.has(event.type)) {
    const dispute = disputeOutcome(object);
    return dispute === null ? null : { ...base, kind: "dispute", outcome: { ...dispute, ...account } };
  }
  // A Checkout Session names its payment intent; a platform payment's disputes are found by it.
  const intent = typeof object.payment_intent === "string" ? { paymentIntentId: object.payment_intent } : {};
  switch (event.type) {
    case "checkout.session.completed": {
      const status = object.payment_status;
      if (typeof status !== "string" || !PAYMENT_STATUSES.has(status)) return null;
      const paymentStatus = status as "paid" | "unpaid" | "no_payment_required";
      return { ...base, kind: "payment", outcome: { kind: "completed", linkId, paymentStatus, ...intent, ...account } };
    }
    case "checkout.session.async_payment_succeeded":
      return { ...base, kind: "payment", outcome: { kind: "async_succeeded", linkId, ...intent, ...account } };
    case "checkout.session.async_payment_failed":
      return { ...base, kind: "payment", outcome: { kind: "async_failed", linkId, ...intent, ...account } };
    case "checkout.session.expired":
      return { ...base, kind: "payment", outcome: { kind: "expired", linkId, ...intent, ...account } };
    default:
      return { ...base, kind: "ignored", type: event.type };
  }
}

/**
 * A Dispute object: its id, the charge and payment intent it names, its status and amount. Never
 * its evidence or the card's details. Null when a field is missing or not what Stripe sends.
 */
function disputeOutcome(object: Record<string, unknown>): Omit<DisputeOutcome, "account"> | null {
  const { charge, payment_intent: intent, status, amount, currency } = object;
  if (typeof charge !== "string" || (intent !== null && typeof intent !== "string")) return null;
  if (!(DISPUTE_STATUSES as readonly unknown[]).includes(status) || !Number.isSafeInteger(amount) || (amount as number) < 0) return null;
  if (typeof currency !== "string" || !/^[a-z]{3}$/.test(currency)) return null;
  return { disputeId: object.id as string, chargeId: charge, paymentIntentId: intent, status: status as DisputeStatus, amountMinor: amount as number, currency };
}
