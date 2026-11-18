// In-memory and fake adapters, for tests and the demo. They never call a network. Hosts use them
// to test their own wiring; production hosts plug in real adapters behind the same interfaces.
import { generateKeyPairSync } from "node:crypto";

import type {
  CarrierSignals,
  IdentityProvider,
  IntakeRecord,
  MessagePurpose,
  MessageSender,
  PaymentLinks,
  PinVerifier,
  ReceiptSigner,
  RecordStore,
  SubjectRecord,
} from "../core/adapters.ts";
import type { Clock, IdGenerator } from "../core/clock.ts";
import type { CarrierSignalReport } from "../core/policy.ts";
import { keyPairSigner } from "../prove/receipt.ts";
import { knowledgeDigest, pinDigest, subjectKeyFor } from "../verify/knowledge.ts";

/** A clock that only moves when told to. */
export class FixedClock implements Clock {
  #ms: number;

  constructor(start: string | Date = "2026-01-01T00:00:00.000Z") {
    this.#ms = new Date(start).getTime();
  }

  now(): Date {
    return new Date(this.#ms);
  }

  advance(ms: number): void {
    this.#ms += ms;
  }
}

/** Ids `prefix_1`, `prefix_2`, ... counted per prefix. */
export class SequentialIds implements IdGenerator {
  readonly #counts = new Map<string, number>();

  next(prefix: string): string {
    const n = (this.#counts.get(prefix) ?? 0) + 1;
    this.#counts.set(prefix, n);
    return `${prefix}_${n}`;
  }
}

export class FakeIdentityProvider implements IdentityProvider {
  readonly created: Array<{ callId: string; sessionId: string }> = [];

  async createDocumentCheck(input: { callId: string; idempotencyKey: string }): Promise<{ sessionId: string; url: string }> {
    const sessionId = `vs_fake_${this.created.length + 1}`;
    this.created.push({ callId: input.callId, sessionId });
    return { sessionId, url: `https://identity.example.test/session/${sessionId}` };
  }
}

/** Answers every check with the same report, unless one is set per number. */
export class FakeCarrierSignals implements CarrierSignals {
  readonly checked: string[] = [];
  readonly #byNumber = new Map<string, CarrierSignalReport>();
  #fallback: CarrierSignalReport;

  constructor(fallback: Partial<CarrierSignalReport> = {}) {
    this.#fallback = { checked: true, lastSimSwapHoursAgo: null, lastPortHoursAgo: null, identityMatch: "unavailable", ...fallback };
  }

  set(phoneNumber: string, report: Partial<CarrierSignalReport>): void {
    this.#byNumber.set(phoneNumber, { ...this.#fallback, ...report });
  }

  async check(input: { phoneNumber: string }): Promise<CarrierSignalReport> {
    this.checked.push(input.phoneNumber);
    return structuredClone(this.#byNumber.get(input.phoneNumber) ?? this.#fallback);
  }
}

export class FakeMessageSender implements MessageSender {
  readonly sent: Array<{ to: string; body: string; purpose: MessagePurpose; messageId: string }> = [];

  async sendText(input: { to: string; body: string; purpose: MessagePurpose; idempotencyKey: string }): Promise<{ messageId: string }> {
    const messageId = `msg_fake_${this.sent.length + 1}`;
    this.sent.push({ to: input.to, body: input.body, purpose: input.purpose, messageId });
    return { messageId };
  }
}

/** Hands out one link per idempotency key, like a provider that honours idempotency keys. */
export class FakePaymentLinks implements PaymentLinks {
  readonly created: Array<{ linkId: string; paymentId: string; amountMinor: number; currency: string }> = [];
  readonly #byKey = new Map<string, { linkId: string; url: string }>();

  async createLink(input: {
    callId: string;
    paymentId: string;
    amountMinor: number;
    currency: string;
    description: string;
    idempotencyKey: string;
  }): Promise<{ linkId: string; url: string }> {
    const existing = this.#byKey.get(input.idempotencyKey);
    if (existing !== undefined) return existing;
    const linkId = `cs_fake_${this.created.length + 1}`;
    const link = { linkId, url: `https://pay.example.test/c/${linkId}` };
    this.#byKey.set(input.idempotencyKey, link);
    this.created.push({ linkId, paymentId: input.paymentId, amountMinor: input.amountMinor, currency: input.currency });
    return link;
  }
}

export class MemoryRecordStore implements RecordStore {
  readonly #subjects = new Map<string, SubjectRecord>();
  readonly #records = new Map<string, IntakeRecord>();

  putSubject(workspaceId: string, subject: SubjectRecord): void {
    this.#subjects.set(`${workspaceId}/${subject.subjectKey}`, structuredClone(subject));
  }

  async getSubject(workspaceId: string, subjectKey: string): Promise<SubjectRecord | null> {
    const subject = this.#subjects.get(`${workspaceId}/${subjectKey}`);
    return subject === undefined ? null : structuredClone(subject);
  }

  async putIntakeRecord(record: IntakeRecord): Promise<void> {
    this.#records.set(`${record.workspaceId}/${record.recordId}`, structuredClone(record));
  }

  async getIntakeRecord(workspaceId: string, recordId: string): Promise<IntakeRecord | null> {
    const record = this.#records.get(`${workspaceId}/${recordId}`);
    return record === undefined ? null : structuredClone(record);
  }
}

/**
 * A host's own PIN store, for the PIN factor in `verifier` mode. Holds plain PINs (it is a fake);
 * a real one compares against its own hashes, for example scrypt.
 */
export class FakePinVerifier implements PinVerifier {
  readonly asked: string[] = [];
  readonly #pins = new Map<string, string>();

  set(workspaceId: string, subjectKey: string, pin: string): void {
    this.#pins.set(`${workspaceId}/${subjectKey}`, pin);
  }

  async verify(input: { workspaceId: string; subjectKey: string; pin: string }): Promise<{ matched: boolean }> {
    this.asked.push(input.subjectKey);
    return { matched: this.#pins.get(`${input.workspaceId}/${input.subjectKey}`) === input.pin };
  }
}

/** A subject record built from plain values, hashed the way the engine compares them. */
export function testSubject(
  knowledgeKey: string | Uint8Array,
  input: { accountNumber: string; phoneOnFile: string; knowledge: Record<string, string>; pin?: string },
): SubjectRecord {
  const knowledge: Record<string, string> = {};
  for (const [field, value] of Object.entries(input.knowledge)) knowledge[field] = knowledgeDigest(knowledgeKey, field, value);
  const subjectKey = subjectKeyFor(knowledgeKey, input.accountNumber);
  const subject: SubjectRecord = { subjectKey, phoneOnFile: input.phoneOnFile, knowledge };
  if (input.pin !== undefined) subject.pinDigest = pinDigest(knowledgeKey, subjectKey, input.pin);
  return subject;
}

/** A receipt signer over a fresh P-256 key that lives only in this process. */
export function generateTestSigner(keyId = "test-key-1"): ReceiptSigner {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return keyPairSigner(keyId, privateKey.export({ format: "pem", type: "pkcs8" }).toString());
}
