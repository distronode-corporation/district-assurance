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
  putIntakeRecord(record: IntakeRecord): Promise<void>;
  getIntakeRecord(workspaceId: string, recordId: string): Promise<IntakeRecord | null>;
}

export interface AuditInput {
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

/** Append-only. No update, no delete. */
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
