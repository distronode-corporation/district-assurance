// The adapter interfaces: everything the engine needs from the outside world. A host plugs in its
// own (a carrier, Stripe, its database, its key store); `district-assurance/testing` has
// in-memory and fake versions for tests and the demo. None of these ever carries card data.
import type { JsonWebKey } from "node:crypto";

import type { JsonValue } from "./canonical.ts";
import type { Actor, EngineEventName } from "./events.ts";
import type { CarrierSignalReport } from "./policy.ts";

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

export type MessagePurpose = "identity_link" | "payment_link" | "one_time_code" | "reference";

/** Texts sent by code. The destination is always the number on file, resolved by the engine. */
export interface MessageSender {
  sendText(input: { to: string; body: string; purpose: MessagePurpose; idempotencyKey: string }): Promise<{
    messageId: string;
  }>;
}

/** Hosted payment pages (for example Stripe Checkout on the business's own account). */
export interface PaymentLinks {
  createLink(input: {
    callId: string;
    paymentId: string;
    /** Integer, in the currency's minor unit (cents). */
    amountMinor: number;
    /** ISO 4217, lower case. */
    currency: string;
    description: string;
    idempotencyKey: string;
  }): Promise<{ linkId: string; url: string }>;
}

/** The person on record, as the engine sees them: keyed digests, never the values. */
export interface SubjectRecord {
  /** HMAC of the account number under the workspace's knowledge key. */
  subjectKey: string;
  /** E.164. Where texted links and codes go. Never the calling number unless they are the same. */
  phoneOnFile: string;
  /** Field name to the HMAC of its value (`knowledgeDigest`). */
  knowledge: Record<string, string>;
  /** The HMAC of the subject's PIN (`pinDigest`), for the PIN factor in `keyed_hash` mode. */
  pinDigest?: string;
}

/**
 * The host's own PIN store, for the PIN factor in `verifier` mode: a host that already keeps PINs
 * (for example as scrypt hashes) checks the entry itself. The engine hands over the digits once,
 * keeps nothing, and counts the attempt before asking. The answer must not depend on whether the
 * subject exists, and should take the same time either way.
 */
export interface PinVerifier {
  verify(input: { workspaceId: string; subjectKey: string; pin: string }): Promise<{ matched: boolean }>;
}

/**
 * Which failures a counter holds: one factor kind, in one workspace, for one subject (its subject
 * key) or one calling number (`numberKeyFor`, a keyed hash: the store never sees the number).
 */
export interface AttemptCounterKey {
  workspaceId: string;
  /** The factor kind, for example `pin`. The engine also keeps its lock notices under `notice:` kinds, which no factor kind can be (INT-7). */
  factor: string;
  scope: "subject" | "number";
  /** The subject key, or the keyed hash of the calling number. 64 lower-case hex characters. */
  key: string;
}

/**
 * Failed attempts across calls, for lockouts that outlive a call (VER-1). Every engine of a
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
  /** Entries with seq >= fromSeq, in order. */
  list(fromSeq?: number): Promise<AuditEntry[]>;
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
