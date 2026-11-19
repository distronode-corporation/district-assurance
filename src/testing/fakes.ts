// In-memory and fake adapters, for tests and the demo. They never call a network. Hosts use them
// to test their own wiring; production hosts plug in real adapters behind the same interfaces.
import { X509Certificate, createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";

import type {
  Anchor,
  AnchorProof,
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

/** Hands out one check per idempotency key, like a provider that honours idempotency keys. */
export class FakeIdentityProvider implements IdentityProvider {
  readonly created: Array<{ callId: string; sessionId: string }> = [];
  readonly #byKey = new Map<string, { sessionId: string; url: string }>();

  async createDocumentCheck(input: { callId: string; idempotencyKey: string }): Promise<{ sessionId: string; url: string }> {
    const existing = this.#byKey.get(input.idempotencyKey);
    if (existing !== undefined) return existing;
    const sessionId = `vs_fake_${this.created.length + 1}`;
    this.created.push({ callId: input.callId, sessionId });
    const check = { sessionId, url: `https://identity.example.test/session/${sessionId}` };
    this.#byKey.set(input.idempotencyKey, check);
    return check;
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

// ---- a time-stamp authority (PRV-9) -------------------------------------------------------------

/** A DER element: one-byte tag, definite length. */
function der(tag: number, ...parts: Uint8Array[]): Buffer {
  const body = Buffer.concat(parts);
  const size: number[] = [];
  for (let n = body.length; n > 0; n = Math.floor(n / 256)) size.unshift(n % 256);
  const length = body.length < 0x80 ? [body.length] : [0x80 | size.length, ...size];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}

const derSequence = (...parts: Uint8Array[]): Buffer => der(0x30, ...parts);
const derOid = (hex: string): Buffer => der(0x06, Buffer.from(hex, "hex"));
const derText = (tag: number, text: string): Buffer => der(tag, Buffer.from(text, "latin1"));
const ONE = der(0x02, Buffer.from([1]));
const SHA256_ALGORITHM = derSequence(derOid("608648016503040201"), der(0x05));
const ECDSA_SHA256 = derSequence(derOid("2a8648ce3d040302"));
const TST_INFO_OID = derOid("2a864886f70d0109100104");

/**
 * A time-stamp authority in memory: a throwaway P-256 key, a self-signed certificate for
 * time-stamping, and an RFC 3161 token over SHA-256 of each anchor payload at the clock's time.
 * `chain` is what a host passes to `verifyAnchor`. It never sees more than the payload.
 */
export class FakeTimestampAuthority implements Anchor {
  readonly anchored: Array<{ seq: number; hash: string }> = [];
  readonly chain: X509Certificate[];
  readonly #clock: Clock;
  readonly #key: KeyObject;
  readonly #name: Buffer;

  constructor(clock: Clock) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.#clock = clock;
    this.#key = privateKey;
    this.#name = derSequence(der(0x31, derSequence(derOid("550403"), derText(0x0c, "Fake time-stamp authority, not a secret"))));
    const timeStamping = der(0x04, derSequence(derOid("2b06010505070308")));
    const extensions = der(0xa3, derSequence(derSequence(derOid("551d25"), der(0x01, Buffer.from([0xff])), timeStamping)));
    const validity = derSequence(derText(0x17, "200101000000Z"), derText(0x17, "491231235959Z"));
    const spki = publicKey.export({ type: "spki", format: "der" });
    const tbs = derSequence(der(0xa0, der(0x02, Buffer.from([2]))), ONE, ECDSA_SHA256, this.#name, validity, this.#name, spki, extensions);
    this.chain = [new X509Certificate(derSequence(tbs, ECDSA_SHA256, der(0x03, Buffer.from([0]), sign("sha256", tbs, privateKey))))];
  }

  async anchor(input: { seq: number; hash: string; payload: Uint8Array }): Promise<AnchorProof> {
    this.anchored.push({ seq: input.seq, hash: input.hash });
    const time = this.#clock.now().toISOString().replace(/[-:T]|\.\d+/g, "");
    const imprint = derSequence(SHA256_ALGORITHM, der(0x04, createHash("sha256").update(input.payload).digest()));
    const serial = der(0x02, Buffer.from([this.anchored.length % 128]));
    const tstInfo = derSequence(ONE, derOid("2a0304"), imprint, serial, derText(0x18, time));
    const attributes = [
      derSequence(derOid("2a864886f70d010903"), der(0x31, TST_INFO_OID)),
      derSequence(derOid("2a864886f70d010904"), der(0x31, der(0x04, createHash("sha256").update(tstInfo).digest()))),
    ];
    const signature = sign("sha256", der(0x31, ...attributes), this.#key);
    const signerInfo = derSequence(ONE, derSequence(this.#name, ONE), SHA256_ALGORITHM, der(0xa0, ...attributes), ECDSA_SHA256, der(0x04, signature));
    const content = derSequence(TST_INFO_OID, der(0xa0, der(0x04, tstInfo)));
    const signedData = derSequence(der(0x02, Buffer.from([3])), der(0x31, SHA256_ALGORITHM), content, der(0x31, signerInfo));
    return { kind: "rfc3161", token: derSequence(derOid("2a864886f70d010702"), der(0xa0, signedData)).toString("base64") };
  }
}
