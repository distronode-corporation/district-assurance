// Stripe webhooks: the signature check and the mapping from Stripe's event types to the engine's
// outcomes. The signature scheme is Stripe's published one: the `Stripe-Signature` header carries
// `t=<unix seconds>` and one or more `v1=<hex>`, each an HMAC-SHA256 of `<t>.<raw body>` under the
// endpoint's signing secret. Nothing here calls Stripe.
import { hexDigestsEqual, hmacSha256Hex } from "../core/hash.ts";
import type { PaymentOutcome } from "../pay/payment.ts";

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
  /** Default 300 seconds, Stripe's own default. Applies to the past and the future. */
  toleranceSeconds?: number;
}

export function verifyStripeSignature(input: StripeSignatureInput): SignatureCheck {
  const secrets = input.secrets.filter((s) => s.length > 0);
  if (secrets.length === 0) return { ok: false, reason: "no_secret" };
  if (input.header === null || input.header === undefined || input.header === "") return { ok: false, reason: "missing_header" };
  let timestamp: number | null = null;
  const signatures: string[] = [];
  for (const part of input.header.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === "t" && /^\d{1,12}$/.test(value)) timestamp = Number(value);
    if (key === "v1") signatures.push(value);
  }
  if (timestamp === null || signatures.length === 0) return { ok: false, reason: "malformed_header" };
  const tolerance = input.toleranceSeconds ?? 300;
  if (Math.abs(Math.floor(input.now.getTime() / 1000) - timestamp) > tolerance) {
    return { ok: false, reason: "timestamp_out_of_tolerance" };
  }
  const signed = `${timestamp}.${input.payload}`;
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
  | { eventId: string; livemode: boolean; kind: "payment"; outcome: PaymentOutcome }
  | { eventId: string; livemode: boolean; kind: "ignored"; type: string };

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
  const linkId = object.id;
  const identity = IDENTITY_TYPES[event.type];
  if (identity !== undefined) return { ...base, kind: "identity", outcome: { sessionId: linkId, status: identity } };
  switch (event.type) {
    case "checkout.session.completed": {
      const status = object.payment_status;
      if (typeof status !== "string" || !PAYMENT_STATUSES.has(status)) return null;
      const paymentStatus = status as "paid" | "unpaid" | "no_payment_required";
      return { ...base, kind: "payment", outcome: { kind: "completed", linkId, paymentStatus } };
    }
    case "checkout.session.async_payment_succeeded":
      return { ...base, kind: "payment", outcome: { kind: "async_succeeded", linkId } };
    case "checkout.session.async_payment_failed":
      return { ...base, kind: "payment", outcome: { kind: "async_failed", linkId } };
    case "checkout.session.expired":
      return { ...base, kind: "payment", outcome: { kind: "expired", linkId } };
    default:
      return { ...base, kind: "ignored", type: event.type };
  }
}
