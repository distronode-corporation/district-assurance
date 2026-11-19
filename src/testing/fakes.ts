// In-memory and fake adapters, for tests and the demo. They never call a network. Hosts use them
// to test their own wiring; production hosts plug in real adapters behind the same interfaces.
import { generateKeyPairSync } from "node:crypto";

import type {
  AttemptCounterKey,
  AttemptCounters,
  CarrierSignals,
  CodeSendKey,
  CodeStore,
  IdentityProvider,
  IntakeRecord,
  MessagePurpose,
  MessageSender,
  PaymentLinkCapabilities,
  PaymentLinkRequest,
  PaymentLinks,
  PaymentMode,
  PaymentRefundRequest,
  PinVerifier,
  ReceiptSigner,
  RecordStore,
  SubjectRecord,
} from "../core/adapters.ts";
import type { Clock, IdGenerator } from "../core/clock.ts";
import type { CarrierSignalReport } from "../core/policy.ts";
import type { AccessController, SignedAccessGrant, UnlockResult } from "../gate/access.ts";
import { keyPairSigner } from "../prove/receipt.ts";
import { knowledgeDigest, pinDigest, subjectKeyFor, type KnowledgeKeyBytes } from "../verify/knowledge.ts";

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

/**
 * Hands out one link per idempotency key, like a provider that honours idempotency keys, and
 * expires an open link once. `created` records the mode, account, methods and expiry each link
 * was asked for; `settle(linkId)` marks one as no longer open (paid or expired at the provider).
 */
export class FakePaymentLinks implements PaymentLinks {
  /** Stripe Checkout's by default: both modes, 30 minutes to 24 hours. */
  readonly capabilities: PaymentLinkCapabilities;
  readonly created: Array<Omit<PaymentLinkRequest, "callId" | "description" | "idempotencyKey"> & { linkId: string }> = [];
  readonly expired: Array<{ linkId: string; mode: PaymentMode; connectedAccountId?: string }> = [];
  readonly refunds: Array<Omit<PaymentRefundRequest, "idempotencyKey"> & { refundId: string }> = [];
  refundStatus: "pending" | "succeeded" | "failed" = "succeeded";
  readonly #byKey = new Map<string, { linkId: string; url: string }>();
  readonly #refundsByKey = new Map<string, { refundId: string; status: "pending" | "succeeded" | "failed" }>();
  readonly #closed = new Set<string>();

  constructor(capabilities: Partial<PaymentLinkCapabilities> = {}) {
    this.capabilities = { modes: ["connect", "platform"], minLinkMinutes: 30, maxLinkMinutes: 1440, ...capabilities };
  }

  async createLink(input: PaymentLinkRequest): Promise<{ linkId: string; url: string }> {
    const existing = this.#byKey.get(input.idempotencyKey);
    if (existing !== undefined) return existing;
    const linkId = `cs_fake_${this.created.length + 1}`;
    const link = { linkId, url: `https://pay.example.test/c/${linkId}` };
    this.#byKey.set(input.idempotencyKey, link);
    const { callId: _c, description: _d, idempotencyKey: _k, ...asked } = input;
    this.created.push({ ...structuredClone(asked), linkId });
    return link;
  }

  async expireLink(input: { linkId: string; mode: PaymentMode; connectedAccountId?: string; idempotencyKey: string }): Promise<{ state: "expired" | "not_open" }> {
    if (this.#closed.has(input.linkId)) return { state: "not_open" };
    this.#closed.add(input.linkId);
    const { idempotencyKey: _k, ...asked } = input;
    this.expired.push(asked);
    return { state: "expired" };
  }

  /**
   * Refunds once per idempotency key, like the provider: a repeated key returns the first answer.
   * `refunds` records each refund asked for; `refundStatus` is what a new one answers.
   */
  async refund(input: PaymentRefundRequest): Promise<{ refundId: string; status: "pending" | "succeeded" | "failed" }> {
    const existing = this.#refundsByKey.get(input.idempotencyKey);
    if (existing !== undefined) return existing;
    const answer = { refundId: `re_fake_${this.refunds.length + 1}`, status: this.refundStatus };
    this.#refundsByKey.set(input.idempotencyKey, answer);
    const { idempotencyKey: _k, ...asked } = input;
    this.refunds.push({ ...structuredClone(asked), refundId: answer.refundId });
    return answer;
  }

  /** The provider closed a link on its own (paid or expired): a later expireLink answers not_open. */
  settle(linkId: string): void {
    this.#closed.add(linkId);
  }
}

/**
 * A door controller for tests and the demo. `mode` says how it answers: `deliver` (took it),
 * `confirm` (took it and the door moved), `refuse` (did not act), or `lose` (acted, then the
 * answer was lost: the call throws). Every grant it received is in `received`.
 */
export class FakeAccessController implements AccessController {
  readonly received: Array<{ grant: SignedAccessGrant; target: string; idempotencyKey: string }> = [];
  mode: "deliver" | "confirm" | "refuse" | "lose";

  constructor(mode: FakeAccessController["mode"] = "confirm") {
    this.mode = mode;
  }

  async unlock(input: { grant: SignedAccessGrant; target: string; idempotencyKey: string }): Promise<UnlockResult> {
    this.received.push(structuredClone(input));
    const providerRef = `door_fake_${this.received.length}`;
    switch (this.mode) {
      case "deliver":
        return { outcome: "delivered", providerRef, confirmed: false };
      case "confirm":
        return { outcome: "delivered", providerRef, confirmed: true };
      case "refuse":
        return { outcome: "refused", reason: "door_offline" };
      case "lose":
        throw new Error("the controller's answer was lost");
    }
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

  async putPinDigest(workspaceId: string, subjectKey: string, digest: string | null, enrolmentId?: string): Promise<boolean> {
    // No await: one atomic step.
    const subject = this.#subjects.get(`${workspaceId}/${subjectKey}`);
    if (subject === undefined) return false;
    if (digest === null) {
      delete subject.pinDigest;
      delete subject.pinEnrolmentId;
    } else if (subject.pinDigest !== undefined) return false;
    else {
      subject.pinDigest = digest;
      if (enrolmentId !== undefined) subject.pinEnrolmentId = enrolmentId;
    }
    return true;
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

/**
 * The reference `CodeStore`: send times per key, in memory. Share one between the engines of a
 * workspace, as a durable one is shared.
 */
export class MemoryCodeStore implements CodeStore {
  readonly #sends = new Map<string, number[]>();

  async take(input: { workspaceId: string; key: CodeSendKey; at: string; max: number; windowSeconds: number; minIntervalSeconds: number }): Promise<boolean> {
    const id = JSON.stringify([input.workspaceId, input.key.scope, input.key.key]);
    const at = Date.parse(input.at);
    // Keep sends for the longer of the window and the interval; count only those in the window.
    const kept = (this.#sends.get(id) ?? []).filter((t) => t > at - Math.max(input.windowSeconds, input.minIntervalSeconds) * 1000);
    const inWindow = kept.filter((t) => t > at - input.windowSeconds * 1000).length;
    if (inWindow >= input.max || kept.some((t) => t > at - input.minIntervalSeconds * 1000)) return false;
    kept.push(at);
    this.#sends.set(id, kept);
    return true;
  }
}

/**
 * The reference `AttemptCounters`: failure times per key, in memory. Share one between engines
 * to share lockouts, as a host shares one database table between processes.
 */
export class MemoryAttemptCounters implements AttemptCounters {
  readonly #failures = new Map<string, number[]>();

  async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    return this.#since(this.#failures.get(counterId(key)) ?? [], since);
  }

  async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    // No await between the read and the write: in one process, this is one atomic step.
    const id = counterId(key);
    const kept = (this.#failures.get(id) ?? []).filter((t) => t >= Date.parse(since));
    kept.push(Date.parse(at));
    this.#failures.set(id, kept);
    return this.#since(kept, since);
  }

  async removeFailure(key: AttemptCounterKey, at: string): Promise<void> {
    // No await: one atomic step, like recordFailure.
    const times = this.#failures.get(counterId(key)) ?? [];
    const i = times.lastIndexOf(Date.parse(at));
    if (i !== -1) times.splice(i, 1);
  }

  async reset(key: AttemptCounterKey): Promise<void> {
    this.#failures.delete(counterId(key));
  }

  #since(times: readonly number[], since: string): string[] {
    const from = Date.parse(since);
    return times.filter((t) => t >= from).map((t) => new Date(t).toISOString());
  }
}

/** A JSON tuple, so no two keys share an id whatever their parts contain. */
function counterId(key: AttemptCounterKey): string {
  return JSON.stringify([key.workspaceId, key.factor, key.scope, key.key]);
}

/** A subject record built from plain values, hashed the way the engine compares them. */
export function testSubject(
  knowledgeKey: KnowledgeKeyBytes,
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
