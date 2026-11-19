// The adapter interfaces: everything the engine needs from the outside world. A host plugs in its
// own (a carrier, Stripe, its database, its key store); `district-assurance/testing` has
// in-memory and fake versions for tests and the demo. None of these ever carries card data.
import type { JsonWebKey } from "node:crypto";

import type { JsonValue } from "./canonical.ts";
import type { Actor, EngineEventName } from "./events.ts";
import type { AssuranceLevel, CarrierSignalReport } from "./policy.ts";
import type { Locale } from "./runtime.ts";

/** Photo ID plus selfie by a link the caller opens on their phone (for example Stripe Identity). */
export interface IdentityProvider {
  createDocumentCheck(input: { callId: string; idempotencyKey: string }): Promise<{
    /** The provider's session id; the outcome webhook names it. */
    sessionId: string;
    /** Single-use; sent only to the number on file. */
    url: string;
  }>;
}

/** Carrier facts about a phone number (for example SIM swap, porting, identity match). */
export interface CarrierSignals {
  check(input: { phoneNumber: string }): Promise<CarrierSignalReport>;
}

/**
 * Places a callback (VER-9): the host's telephony dials the number on file as a new outbound call
 * and, when it is answered, plays a fixed prompt asking the person to key a confirmation. Keys only:
 * speech never confirms, so voicemail or an answering machine never passes. The host reports the
 * result with `Engine.applyCallbackOutcome({ ref, answered, confirmed })`. A retried dial with the
 * same idempotency key must not ring the line twice.
 */
export interface CallbackDialer {
  dial(input: {
    /** The callback call the engine created; the host runs the rest of the callback on it. */
    callId: string;
    /** E.164. Always the number on file, resolved by the engine. */
    to: string;
    locale: Locale;
    idempotencyKey: string;
  }): Promise<{
    /** The dialer's reference for the outbound call; its outcome names it. */
    ref: string;
  }>;
}

export type MessagePurpose = "identity_link" | "payment_link" | "one_time_code" | "reference";

/**
 * Texts sent by code. The destination is always the number on file, resolved by the engine.
 * `sendText` must settle (sent or failed) within 60 seconds: Paylink holds a payment link against a
 * concurrent expiry for that long while it is being texted (its send lease).
 */
export interface MessageSender {
  sendText(input: { to: string; body: string; purpose: MessagePurpose; idempotencyKey: string }): Promise<{
    messageId: string;
  }>;
}

/**
 * Whose account takes the money. `connect`: the business's own account at the provider (for
 * example a Stripe direct charge on a connected account); the business is the merchant.
 * `platform`: the platform's own account; the platform is the merchant.
 */
export type PaymentMode = "connect" | "platform";

/** Payment methods that settle while the caller is still on the call. Nothing else may be offered. */
export type InstantPaymentMethod = "card" | "apple_pay" | "google_pay" | "link";

export interface PaymentLinkRequest {
  callId: string;
  paymentId: string;
  /** Integer, in the currency's minor unit (cents). */
  amountMinor: number;
  /** ISO 4217, lower case. */
  currency: string;
  description: string;
  mode: PaymentMode;
  /** The business's account at the provider. Present exactly when `mode` is `connect`. */
  connectedAccountId?: string;
  /** What the page may offer: only methods that settle at once. How a provider names them is the adapter's. */
  paymentMethods: readonly InstantPaymentMethod[];
  /**
   * The latest the link may live (ISO 8601): twice the flow's link life from the request, kept
   * within the adapter's declared `minLinkMinutes` and `maxLinkMinutes`, so a text sent late still
   * gets its full life and the provider never refuses the time. The engine closes the link earlier,
   * at its own deadline (the text plus the link life), by calling `expireLink`.
   */
  expiresAt: string;
  idempotencyKey: string;
}

/**
 * What a payment link adapter can do, declared by the adapter and checked when a config is saved.
 * Stripe Checkout: both modes, and `expires_at` from 30 minutes to 24 hours after creation.
 */
export interface PaymentLinkCapabilities {
  modes: readonly PaymentMode[];
  /** The shortest link life the provider allows, in minutes. The engine expires links sooner itself. */
  minLinkMinutes: number;
  /** The longest link life the provider allows, in minutes. */
  maxLinkMinutes: number;
}

/** What a texted code's send is counted against: one subject (its subject key) or one calling number (a keyed hash). */
export interface CodeSendKey {
  scope: "subject" | "number";
  /** The subject key, or the keyed hash of the calling number. 64 lower-case hex characters, never a number. */
  key: string;
}

/**
 * The send limits for texted codes, across calls: every engine of a workspace shares one, as they
 * share the SessionStore. The codes themselves live in the call record; this holds only when codes
 * were sent, per subject and per calling number. `codeStoreContract` in
 * `district-assurance/testing` is the suite a durable one must pass; `MemoryCodeStore` is the
 * reference.
 */
export interface CodeStore {
  /**
   * Counts one send against the key, atomically, only if the key had fewer than `max` sends in the
   * `windowSeconds` up to `at` and none in the `minIntervalSeconds` up to `at`. True when it
   * counted; false, and nothing counted, otherwise. Two concurrent calls never both count past a limit.
   */
  take(input: { workspaceId: string; key: CodeSendKey; at: string; max: number; windowSeconds: number; minIntervalSeconds: number }): Promise<boolean>;
}

/** Which link to close, on whose account. `connectedAccountId` is present exactly in connect mode. */
export interface PaymentLinkClose {
  linkId: string;
  mode: PaymentMode;
  connectedAccountId?: string;
  idempotencyKey: string;
}

/** Hosted payment pages (for example Stripe Checkout, on the business's account or the platform's). */
export interface PaymentLinks {
  readonly capabilities: PaymentLinkCapabilities;
  createLink(input: PaymentLinkRequest): Promise<{ linkId: string; url: string }>;
  /**
   * Expires an open link now (its deadline came, or the call ended). `expired` when it was open
   * and is closed; `not_open` when the provider says it already completed or expired.
   */
  expireLink(input: PaymentLinkClose): Promise<{ state: "expired" | "not_open" }>;
  /**
   * Cancels an open link because the caller changed their mind, with the same answers as
   * `expireLink`. Optional: without it the engine cancels with `expireLink` (Stripe Checkout has
   * one call for both). A provider that keeps a cancelled link apart from an expired one has it.
   */
  cancel?(input: PaymentLinkClose): Promise<{ state: "expired" | "not_open" }>;
  /**
   * Refunds a paid platform payment on the platform's own account, in full or in part. Optional:
   * no flow step needs it, so a config is valid without it, and `refundPayment` is refused at run
   * time when it is absent; connect payments are refunded by the business on its own account,
   * never here.
   * A refund the provider refuses answers `failed`; only an answer that was lost (a timeout, a
   * dropped connection) may throw, since the engine keeps a refund that threw in flight and resumes
   * it, with the same key, until it gets an answer.
   */
  refund?(input: PaymentRefundRequest): Promise<{ refundId: string; status: "pending" | "succeeded" | "failed" }>;
}

export interface PaymentRefundRequest {
  /** The hosted page the payment was taken on (for example a Checkout Session id). */
  linkId: string;
  /** The provider's payment intent, when the outcome named it. */
  paymentIntentId?: string;
  mode: "platform";
  /** Integer, in the currency's minor unit; never more than is left of the payment. */
  amountMinor: number;
  currency: string;
  reason: "requested_by_customer" | "duplicate" | "fraudulent";
  /** One per refund: a resumed refund replays the first answer. */
  idempotencyKey: string;
}

/** The person on record, as the engine sees them: keyed digests, never the values. */
export interface SubjectRecord {
  /** HMAC of the account number under the workspace's knowledge key. */
  subjectKey: string;
  /**
   * E.164. Where texted links and codes go, and the line a callback dials. Never the calling number
   * unless they are the same. A value that is not E.164 (an empty string) means no number on file,
   * and a callback is refused.
   */
  phoneOnFile: string;
  /** Field name to the HMAC of its value (`knowledgeDigest`). */
  knowledge: Record<string, string>;
  /** The HMAC of the subject's PIN (`pinDigest`), for the PIN factor in `keyed_hash` mode. */
  pinDigest?: string;
  /** The HMAC of the subject's duress PIN (`duressDigest`), set only by the business (VER-12). */
  duressDigest?: string;
  /**
   * Which enrolment stored `pinDigest` (VER-6): written with it by `putPinDigest`, so a call
   * finishing an enrolment whose last write failed can tell its own from another's. Opaque.
   */
  pinEnrolmentId?: string;
}

/** What the engine asks an `AmountSource` for: the reference a step or the host's code named, and whose call it is. */
export interface AmountLookup {
  workspaceId: string;
  callId: string;
  /** Where the amount comes from: `intake_record`, `business_endpoint` or `price_list`. */
  source: string;
  /** The reference the `paylink.request` step (or the host's code) names, for example a price list entry. */
  reference: string;
  /** The subject Badge matched on this call (a keyed hash, never an account number). */
  subjectKey: string;
  /** The records filed on this call so far, oldest first. */
  recordIds: readonly string[];
}

/**
 * Resolves a payment amount from a reference: a record, the business's endpoint or a price list
 * (PAY-2). Code asks it, never the model; the engine checks the answer like any other amount and
 * reads it back to the caller before a link is sent.
 */
export interface AmountSource {
  /** The amount in minor units and its currency, or null when the reference names none. */
  resolve(input: AmountLookup): Promise<{ amountMinor: number; currency: string } | null>;
}

/**
 * The host's own PIN store, for the PIN factor in `verifier` mode: a host that already keeps PINs
 * (for example as scrypt hashes) checks the entry itself. The engine hands over the digits once,
 * keeps nothing, and counts the attempt before asking. The answer must not depend on whether the
 * subject exists, and should take the same time either way.
 */
export interface PinVerifier {
  /**
   * `duress: true` when the entry is the subject's duress PIN (VER-12): the call then looks like a
   * pass to the caller, and `matched` is ignored. It counts only while Badge's `pin.duress` is set.
   */
  verify(input: { workspaceId: string; subjectKey: string; pin: string }): Promise<{ matched: boolean; duress?: boolean }>;
}

/** One duress alert (VER-12): `alertId` is the same on every retry of it, for a host to drop repeats. */
export interface DuressAlert {
  alertId: string;
  workspaceId: string;
  subjectKey: string;
  callId: string;
  /** When the duress PIN was entered, ISO 8601. */
  at: string;
}

/**
 * Told when a caller enters a duress PIN (VER-12), for every duress entry. The alert is owed in the
 * call record, in the same write that recorded the entry, and sent after that write, off the
 * caller's response path; it stays owed until `notify` resolves, and is retried on the call's next
 * write, on `flushLedger` and on `deliverDuressAlerts` (the host's sweep). So it is delivered at
 * least once: drop repeats by `alertId`. Never given the PIN. The host alerts whoever the business
 * named, away from the call. `notify` must not block: hand the alert to a queue and return.
 */
export interface DuressNotifier {
  notify(input: DuressAlert): Promise<void>;
}

/**
 * Which failures a counter holds: one factor kind, in one workspace, for one subject (its subject
 * key) or one calling number (`numberKeyFor`, a keyed hash: the store never sees the number).
 * Never a flow or a call: failures in one flow count in every other (VER-15).
 */
export interface AttemptCounterKey {
  workspaceId: string;
  /** The factor kind, for example `pin`, or `flow.start` for the starts of flows that need a money, contact or access scope (VER-15). The engine also keeps its lock notices under `notice:` kinds, which no factor kind can be (INT-7). */
  factor: string;
  scope: "subject" | "number";
  /** The subject key, or the keyed hash of the calling number. 64 lower-case hex characters. */
  key: string;
}

/**
 * Failed attempts across calls, for lockouts that outlive a call (VER-1), and the starts of flows
 * that need a money, contact or access scope, for their hourly limit (VER-15). Every engine of a
 * workspace, in every process, must share one store. Times are ISO 8601. `attemptCountersContract`
 * in `district-assurance/testing` is the suite a durable store must pass; `MemoryAttemptCounters`
 * is the reference.
 */
export interface AttemptCounters {
  /** The failures recorded for the key at or after `since`, in the order they were recorded. */
  get(key: AttemptCounterKey, since: string): Promise<string[]>;
  /**
   * Records one failure at `at`, and returns the failures at or after `since` in the order they
   * were recorded, this one last, in one atomic step: of two concurrent failures, the second sees
   * the first. The store may forget failures before `since`.
   */
  recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]>;
  /**
   * Forgets one failure recorded at `at` and keeps every other, in one atomic step, so a failure
   * another attempt records meanwhile is never lost; nothing when there is none. After a pass, it
   * takes the passing attempt's own failure off the calling number.
   */
  removeFailure(key: AttemptCounterKey, at: string): Promise<void>;
  /** Forgets every failure for the key: after a pass, or when the business lifts a lock. */
  reset(key: AttemptCounterKey): Promise<void>;
}

/**
 * A lock, as the business is told of it: the counter that locked (what `Engine.unlock` takes to
 * lift it), the factor kind and when it ends. The key is the subject key or the keyed hash of the
 * calling number: never an account number, a phone number or anything the caller keyed.
 */
export interface LockNotice extends AttemptCounterKey {
  /** True for the lock after too many failures in the window; false for a wait after a failure. */
  hard: boolean;
  /** ISO 8601. */
  until: string;
  /** True on the workspace's last notice for the hour: locks after it are in the ledger only. */
  capped: boolean;
}

/**
 * Tells the business that someone is locked out (INT-7), for example by email or a dashboard.
 * Told after the `verification.locked` entry is written, once per lock and at most 20 times an
 * hour per workspace, best effort: a notifier that fails or hangs never
 * blocks the call or the ledger, and the ledger stays the record.
 */
export interface Notifier {
  lockout(notice: LockNotice): Promise<void>;
}

/** A stored call session and its version. The version goes up by one on every write. */
export interface StoredSession {
  version: number;
  record: JsonValue;
}

/**
 * Where call sessions live, so several processes (a voice agent and a web backend, several
 * replicas) can run one call. Every write is a compare-and-set on the session's version: the
 * engine reads, applies one step, and writes only if nobody wrote in between, retrying the step
 * from a fresh read when someone did. `MemorySessionStore` is the reference implementation, and
 * `sessionStoreContract` in `district-assurance/testing` is the suite a durable one must pass.
 */
export interface SessionStore {
  /** Stores a new session at version 1. False, and nothing written, when the id exists. */
  create(workspaceId: string, callId: string, record: JsonValue): Promise<boolean>;
  get(workspaceId: string, callId: string): Promise<StoredSession | null>;
  /**
   * Writes the record only if the stored version is `expectedVersion`, and returns the new
   * version (`expectedVersion + 1`). `{ ok: false }` when the version moved or the session is gone.
   */
  compareAndSet(workspaceId: string, callId: string, expectedVersion: number, record: JsonValue): Promise<{ ok: true; version: number } | { ok: false }>;
  /** Points a provider reference (an identity session, a payment link) at a call. The first binding wins. */
  bindRef(workspaceId: string, ref: string, callId: string): Promise<boolean>;
  resolveRef(workspaceId: string, ref: string): Promise<string | null>;
  /**
   * The ids of the workspace's calls whose stored record has `owesAlerts: true`, for
   * `Engine.sweepAlerts` after a crash (VER-12). Optional: without it the host sweeps by call id
   * (`deliverDuressAlerts`). A durable store indexes that one field.
   */
  listCallsOwingAlerts?(workspaceId: string): Promise<string[]>;
}

export interface IntakeRecord {
  recordId: string;
  workspaceId: string;
  callId: string;
  formId: string;
  formVersion: string;
  values: Record<string, string | number | boolean>;
  /** SHA-256 of the canonical form id, version and values: what the receipt carries. */
  digest: string;
  confirmedBy: "voice" | "keypad";
  confirmedAt: string;
}

/** The host's records: subjects to verify against, and the intake records callers confirm. */
export interface RecordStore {
  getSubject(workspaceId: string, subjectKey: string): Promise<SubjectRecord | null>;
  /** Idempotent by `recordId`: the engine retries a write whose outcome it could not see, with the same record. */
  putIntakeRecord(record: IntakeRecord): Promise<void>;
  getIntakeRecord(workspaceId: string, recordId: string): Promise<IntakeRecord | null>;
  /**
   * Stores a subject's PIN digest (`pinDigest`) with the id of the enrolment that chose it
   * (`pinEnrolmentId`), or removes both with null (a reset by the business), and the duress PIN
   * (`duressDigest`, VER-12) in the same atomic step, so no duress PIN enrolled against a newer PIN
   * is ever removed by an older reset. Never given the PIN
   * itself. A digest is stored only if the subject has none, as one atomic step (of two enrolments at
   * once, one wins and the other replaces nothing); the answer says whether it was stored. Null always
   * removes and answers true. A subject the store does not have is left alone, and the answer is false.
   */
  putPinDigest(workspaceId: string, subjectKey: string, digest: string | null, enrolmentId?: string): Promise<boolean>;
  /**
   * Stores a subject's duress PIN digest (`duressDigest`), replacing any (the business changes it),
   * only if the subject's PIN digest is still `ifPinDigest`, in one atomic step, so a PIN reset and
   * a new PIN in between can never leave the duress PIN equal to the PIN; the answer says whether it
   * stored. Null removes it (whatever `ifPinDigest`) and answers true. Never given the PIN itself. A
   * subject the store does not have is left alone, and the answer is false.
   */
  putDuressDigest(workspaceId: string, subjectKey: string, digest: string | null, ifPinDigest?: string): Promise<boolean>;
}

export interface AuditInput {
  /** The engine's id for this entry. A ledger appends an id once: a second append returns the first entry. */
  eventId?: string;
  callId: string | null;
  actor: Actor;
  event: EngineEventName;
  /** ISO 8601. */
  at: string;
  detail: { [key: string]: JsonValue };
}

export interface AuditEntry extends AuditInput {
  seq: number;
  /** The previous entry's hash; 64 zeros for the first entry. */
  prevHash: string;
  /** SHA-256 over the canonical JSON of every other field of this entry. */
  hash: string;
}

/** Append-only. No update, no delete. Idempotent by `eventId`, so the engine can retry an append. */
export interface AuditLedger {
  append(input: AuditInput): Promise<AuditEntry>;
  head(): Promise<{ seq: number; hash: string }>;
  /**
   * Entries with seq >= fromSeq, in order, at most `limit` of them (an integer of 1 or more) when
   * it is given. A durable ledger reads only that page, so an export or an audit tool can walk a
   * large ledger page by page.
   */
  list(fromSeq?: number, limit?: number): Promise<AuditEntry[]>;
}

/** Signs receipt payloads. The private key stays with the host (a KMS, an HSM, a file). */
export interface ReceiptSigner {
  readonly keyId: string;
  readonly algorithm: "ES256";
  /** An ES256 signature over the bytes, in IEEE P1363 form (r || s, 64 bytes). */
  sign(payload: Uint8Array): Promise<Uint8Array>;
  /** The public key, for publishing in a key set. */
  publicJwk(): JsonWebKey;
}

/** An access grant's signed body (Gate): what a door's relay checks. SPEC.md, section 17. */
export interface AccessGrantBody {
  v: 1;
  kind: "access";
  /** Unique per grant. A relay refuses an id it has seen until the grant expires. */
  grantId: string;
  /** The workspace that issued it. A relay checks it is its own. */
  workspaceId: string;
  /** The controller it is for: its name in the engine's `access` adapters. A relay checks it is its own. */
  audience: string;
  /** The door, lock or access point, as the controller names it. Set in config, never by the model. */
  target: string;
  action: "unlock";
  /** The scope the call's verification grant covered. */
  scope: string;
  /** The level the caller was verified to. */
  level: AssuranceLevel;
  /** ISO 8601. */
  issuedAt: string;
  /** ISO 8601. Never later than the call's verification grant. */
  expiresAt: string;
}

/** ES256 over the body's canonical JSON, the receipts' format. */
export interface SignedAccessGrant {
  body: AccessGrantBody;
  alg: "ES256";
  kid: string;
  /** base64url of the 64-byte P1363 signature. */
  signature: string;
}

/** What a door controller answered. A lost answer is a thrown error, never a value. */
export type UnlockResult =
  /** The controller took the request. `confirmed` only when it reports that the door actually moved. */
  | { outcome: "delivered"; providerRef: string; confirmed: boolean }
  /** The controller certainly did not act (it refused the grant, the door is offline). */
  | { outcome: "refused"; reason: string };

/**
 * A door controller, lock or access system (Gate). The engine calls `unlock` once per grant and
 * never retries: if the call throws or times out, the engine records "unknown", and opening again
 * needs a fresh request (a new grant). An adapter must not retry on its own either.
 */
export interface AccessController {
  unlock(input: { grant: SignedAccessGrant; target: string; idempotencyKey: string }): Promise<UnlockResult>;
}
