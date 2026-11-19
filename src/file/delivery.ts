// Record delivery (FIL-3): a confirmed record, posted to the business's endpoint as a signed
// webhook, retried with backoff, under one idempotency key per record and destination. The
// signature is the `t=<unix seconds>,v1=<hex>` HMAC-SHA256 scheme the engine verifies for Stripe,
// so a receiver can check it with `verifyStripeSignature`. Each attempt is a ledger entry that
// says what happened, never what was sent: no field value, no URL, no secret.
import type { AuditLedger, IntakeRecord, RecordDelivery, RecordStore } from "../core/adapters.ts";
import { canonicalJson } from "../core/canonical.ts";
import type { Clock } from "../core/clock.ts";
import { EngineError } from "../core/errors.ts";
import { hmacSha256Hex, sha256Hex } from "../core/hash.ts";
import { isIntegerIn } from "../core/shape.ts";

/** The request header that carries the signature. */
export const DELIVERY_SIGNATURE_HEADER = "district-signature";

/** Where a workspace's records go. Comes from the host's own configuration, never from a call. */
export interface DeliveryDestination {
  /** The host's name for the endpoint: in the idempotency key and the ledger, where the URL never is. */
  destinationId: string;
  /** `https:`, or `http:` on a loopback host only (a local receiver). */
  url: string;
  /** The endpoint's signing secret, at least 16 characters, shared with the receiver only. */
  secret: string;
}

export interface DeliveryRetry {
  /** Attempts in all, 1 to 10. */
  maxAttempts: number;
  /** The wait after the first failed attempt, doubled after each one after it, 0 to 600,000. */
  baseDelayMs: number;
  /** The longest wait, from `baseDelayMs` to 3,600,000. */
  maxDelayMs: number;
}

export const DEFAULT_DELIVERY_RETRY: Readonly<DeliveryRetry> = { maxAttempts: 5, baseDelayMs: 1000, maxDelayMs: 60_000 };

export interface DeliverRecordInput {
  workspaceId: string;
  recordId: string;
  destination: DeliveryDestination;
  /** Where the confirmed record is read from. */
  records: RecordStore;
  delivery: RecordDelivery;
  ledger: AuditLedger;
  clock: Clock;
  /** Waits between attempts. Default `timerSleep`; tests pass one that moves a fixed clock. */
  sleep?: (ms: number) => Promise<void>;
  retry?: Partial<DeliveryRetry>;
}

/** What the receiver gets: the same bytes on every attempt, so a retry is recognisably the same delivery. */
export interface RecordDeliveryBody {
  v: 1;
  type: "record.confirmed";
  idempotencyKey: string;
  destinationId: string;
  record: IntakeRecord;
}

/** One attempt: delivered (a 2xx), to be retried, or failed for good. */
export type DeliveryOutcome = "delivered" | "retry" | "failed";

export interface DeliveryResult {
  delivered: boolean;
  attempts: number;
  /** The last answer's HTTP status; null when the last attempt got no answer. */
  status: number | null;
  idempotencyKey: string;
}

const DESTINATION_ID = /^[a-z][a-z0-9_-]{0,63}$/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * The idempotency key of a record and a destination: SHA-256 hex of the JSON tuple
 * `[workspaceId, "delivery", recordId, destinationId]`. The same on every attempt and every
 * call, so a receiver applies a record once however often it arrives.
 */
export function deliveryIdempotencyKey(workspaceId: string, recordId: string, destinationId: string): string {
  return sha256Hex(JSON.stringify([workspaceId, "delivery", recordId, destinationId]));
}

/** The signature header for a body: `t=<timestamp>,v1=<HMAC-SHA256(secret, t + "." + body)>`. */
export function signDelivery(body: string, secret: string, timestamp: number): string {
  return `t=${timestamp},v1=${hmacSha256Hex(secret, `${timestamp}.${body}`)}`;
}

/** The wait after failed attempt `attempt` (1-based): the base, doubled per attempt, capped. */
export function deliveryDelay(retry: DeliveryRetry, attempt: number): number {
  return Math.min(retry.maxDelayMs, retry.baseDelayMs * 2 ** (attempt - 1));
}

/** A request timeout, a rate limit and a server error are worth another try; other answers are final. */
export function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

/** Waits on a real timer. */
export function timerSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function destinationProblem(d: DeliveryDestination): string | null {
  if (!DESTINATION_ID.test(d.destinationId)) return "destinationId must be lower-case letters, digits, hyphens or underscores";
  if (d.secret.length < 16) return "the destination secret must be at least 16 characters";
  const url = URL.parse(d.url);
  if (url === null) return "the destination url is not a URL";
  if (url.username !== "" || url.password !== "") return "the destination url must not carry credentials";
  if (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname))) return null;
  return "the destination url must be https, or http on a loopback host";
}

function retryProblem(r: DeliveryRetry): string | null {
  if (!isIntegerIn(r.maxAttempts, 1, 10)) return "retry.maxAttempts must be an integer from 1 to 10";
  if (!isIntegerIn(r.baseDelayMs, 0, 600_000)) return "retry.baseDelayMs must be an integer from 0 to 600000";
  if (!isIntegerIn(r.maxDelayMs, r.baseDelayMs, 3_600_000)) return "retry.maxDelayMs must be an integer from retry.baseDelayMs to 3600000";
  return null;
}

/**
 * Delivers a confirmed record to one destination. Each attempt is signed afresh (the timestamp is
 * the attempt's), carries the same body and idempotency key, and appends one `delivery.attempted`
 * entry. A 2xx delivers; no answer, 408, 429 or 5xx waits and tries again until `maxAttempts`;
 * any other answer fails at once. Returns the outcome rather than throwing on a failed delivery;
 * throws `invalid_input` for a bad destination or retry setting or an unknown record, and passes
 * a ledger failure through, in which case the host may deliver again: the receiver sees the
 * same idempotency key.
 */
export async function deliverRecord(input: DeliverRecordInput): Promise<DeliveryResult> {
  const { destination, clock } = input;
  const retry: DeliveryRetry = { ...DEFAULT_DELIVERY_RETRY, ...input.retry };
  const problem = destinationProblem(destination) ?? retryProblem(retry);
  if (problem !== null) throw new EngineError("invalid_input", problem);
  const record = await input.records.getIntakeRecord(input.workspaceId, input.recordId);
  if (record === null) throw new EngineError("invalid_input", `no record ${input.recordId} in this workspace`);
  const idempotencyKey = deliveryIdempotencyKey(input.workspaceId, input.recordId, destination.destinationId);
  const message: RecordDeliveryBody = { v: 1, type: "record.confirmed", idempotencyKey, destinationId: destination.destinationId, record };
  const body = canonicalJson(message);
  const sleep = input.sleep ?? timerSleep;
  for (let attempt = 1; ; attempt++) {
    const timestamp = Math.floor(clock.now().getTime() / 1000);
    const headers = {
      "content-type": "application/json",
      "idempotency-key": idempotencyKey,
      [DELIVERY_SIGNATURE_HEADER]: signDelivery(body, destination.secret, timestamp),
    };
    const status = await input.delivery.post({ url: destination.url, headers, body }).then(
      (answer) => answer.status,
      () => null,
    );
    const delivered = status !== null && status >= 200 && status < 300;
    const again = !delivered && attempt < retry.maxAttempts && (status === null || isRetryableStatus(status));
    const outcome: DeliveryOutcome = delivered ? "delivered" : again ? "retry" : "failed";
    await input.ledger.append({
      callId: record.callId,
      actor: "system",
      event: "delivery.attempted",
      at: clock.now().toISOString(),
      detail: { recordId: record.recordId, destination: destination.destinationId, attempt, outcome, status },
    });
    if (!again) return { delivered, attempts: attempt, status, idempotencyKey };
    await sleep(deliveryDelay(retry, attempt));
  }
}
