// In-memory and fake adapters, for tests and the demo. They never call a network. Hosts use them
// to test their own wiring; production hosts plug in real adapters behind the same interfaces.
import { generateKeyPairSync } from "node:crypto";

import type {
  AttemptCounterKey,
  AttemptCounters,
  CallbackDialer,
  CarrierSignals,
  CodeSendKey,
  CodeStore,
  DuressAlert,
  DuressNotifier,
  ConsentRecord,
  ConsentRevocation,
  ConsentStore,
  IdentityProvider,
  IntakeRecord,
  LockNotice,
  MessagePurpose,
  MessageSender,
  PaymentLinkCapabilities,
  PaymentLinkRequest,
  Notifier,
  PaymentLinks,
  PaymentMode,
  PaymentRefundRequest,
  PinVerifier,
  ReceiptSigner,
  RecordDelivery,
  RecordStore,
  SubjectRecord,
} from "../core/adapters.ts";
import type { Clock, IdGenerator } from "../core/clock.ts";
import type { CarrierSignalReport } from "../core/policy.ts";
import type { FieldCipher, Locale } from "../core/runtime.ts";
import type { AccessController, SignedAccessGrant, UnlockResult } from "../gate/access.ts";
import { keyPairSigner } from "../prove/receipt.ts";
import { duressDigest } from "../verify/factors.ts";
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

/** Answers every check with the same report, unless one is set per number: by default a carrier that answered about SIM changes and saw none. */
export class FakeCarrierSignals implements CarrierSignals {
  readonly checked: string[] = [];
  readonly #byNumber = new Map<string, CarrierSignalReport>();
  #fallback: CarrierSignalReport;

  constructor(fallback: Partial<CarrierSignalReport> = {}) {
    this.#fallback = { checked: true, simSwapChecked: true, lastSimSwapHoursAgo: null, lastPortHoursAgo: null, identityMatch: "unavailable", ...fallback };
  }

  set(phoneNumber: string, report: Partial<CarrierSignalReport>): void {
    this.#byNumber.set(phoneNumber, { ...this.#fallback, ...report });
  }

  async check(input: { phoneNumber: string }): Promise<CarrierSignalReport> {
    this.checked.push(input.phoneNumber);
    return structuredClone(this.#byNumber.get(input.phoneNumber) ?? this.#fallback);
  }
}

/**
 * Rings nothing: records each callback and hands out one reference per idempotency key, like a
 * dialer that honours idempotency keys. The test reports the outcome with `applyCallbackOutcome`.
 */
export class FakeCallbackDialer implements CallbackDialer {
  readonly dialed: Array<{ callId: string; to: string; locale: Locale; ref: string }> = [];
  readonly #byKey = new Map<string, string>();

  async dial(input: { callId: string; to: string; locale: Locale; idempotencyKey: string }): Promise<{ ref: string }> {
    const existing = this.#byKey.get(input.idempotencyKey);
    if (existing !== undefined) return { ref: existing };
    const ref = `cb_fake_${this.dialed.length + 1}`;
    this.#byKey.set(input.idempotencyKey, ref);
    this.dialed.push({ callId: input.callId, to: input.to, locale: input.locale, ref });
    return { ref };
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

/** A map key for an id within a workspace that no two pairs share, whatever either holds ("/" included). */
function scoped(workspaceId: string, id: string): string {
  return JSON.stringify([workspaceId, id]);
}

/** Keys are JSON tuples, so no pair of workspace and id can collide with another (`"a/b", "c"` is not `"a", "b/c"`). */
export class MemoryRecordStore implements RecordStore {
  readonly #subjects = new Map<string, SubjectRecord>();
  readonly #records = new Map<string, IntakeRecord>();
  /** Ids of deleted records: a late write of one stores nothing. */
  readonly #deleted = new Set<string>();
  /** Erasures counted per subject: a write reserved before the latest stores nothing. */
  readonly #erasures = new Map<string, number>();

  putSubject(workspaceId: string, subject: SubjectRecord): void {
    this.#subjects.set(scoped(workspaceId, subject.subjectKey), structuredClone(subject));
  }

  async getSubject(workspaceId: string, subjectKey: string): Promise<SubjectRecord | null> {
    const subject = this.#subjects.get(scoped(workspaceId, subjectKey));
    return subject === undefined ? null : structuredClone(subject);
  }

  async putIntakeRecord(record: IntakeRecord, erasuresSeen?: number): Promise<void> {
    const key = scoped(record.workspaceId, record.recordId);
    if (this.#deleted.has(key)) return;
    if (erasuresSeen !== undefined && record.subjectKey !== null && (await this.subjectErasures(record.workspaceId, record.subjectKey)) > erasuresSeen) return;
    this.#records.set(key, structuredClone(record));
  }

  async getIntakeRecord(workspaceId: string, recordId: string): Promise<IntakeRecord | null> {
    const record = this.#records.get(scoped(workspaceId, recordId));
    return record === undefined ? null : structuredClone(record);
  }

  async listIntakeRecords(workspaceId: string, subjectKey: string): Promise<IntakeRecord[]> {
    return [...this.#records.values()].filter((r) => r.workspaceId === workspaceId && r.subjectKey === subjectKey).map((r) => structuredClone(r));
  }

  async deleteIntakeRecords(workspaceId: string, recordIds: readonly string[]): Promise<void> {
    for (const recordId of recordIds) {
      this.#records.delete(scoped(workspaceId, recordId));
      this.#deleted.add(scoped(workspaceId, recordId));
    }
  }

  async putPinDigest(workspaceId: string, subjectKey: string, digest: string | null, enrolmentId?: string): Promise<boolean> {
    // No await: one atomic step.
    const subject = this.#subjects.get(scoped(workspaceId, subjectKey));
    if (subject === undefined) return false;
    if (digest === null) {
      delete subject.pinDigest;
      delete subject.pinEnrolmentId;
      delete subject.duressDigest;
    } else if (subject.pinDigest !== undefined) return false;
    else {
      subject.pinDigest = digest;
      if (enrolmentId !== undefined) subject.pinEnrolmentId = enrolmentId;
    }
    return true;
  }

  async putDuressDigest(workspaceId: string, subjectKey: string, digest: string | null, ifPinDigest?: string): Promise<boolean> {
    // No await: one atomic step.
    const subject = this.#subjects.get(scoped(workspaceId, subjectKey));
    if (subject === undefined) return false;
    if (digest === null) delete subject.duressDigest;
    else if (subject.pinDigest !== ifPinDigest) return false;
    else subject.duressDigest = digest;
    return true;
  }

  async markSubjectErased(workspaceId: string, subjectKey: string): Promise<void> {
    const key = scoped(workspaceId, subjectKey);
    this.#erasures.set(key, (this.#erasures.get(key) ?? 0) + 1);
  }

  async subjectErasures(workspaceId: string, subjectKey: string): Promise<number> {
    return this.#erasures.get(scoped(workspaceId, subjectKey)) ?? 0;
  }

  async deletePinDigest(workspaceId: string, subjectKey: string): Promise<void> {
    const subject = this.#subjects.get(scoped(workspaceId, subjectKey));
    // The duress PIN is a PIN too: left alone, it would still pass for the subject (VER-12).
    delete subject?.pinDigest;
    delete subject?.duressDigest;
  }
}

/** Consents and their revocations, in memory. The first revocation of a consent wins. */
export class MemoryConsentStore implements ConsentStore {
  readonly #consents = new Map<string, { consent: ConsentRecord; revoked: ConsentRevocation | null }>();

  async putConsent(workspaceId: string, record: ConsentRecord): Promise<void> {
    const key = JSON.stringify([workspaceId, record.consentId]);
    if (!this.#consents.has(key)) this.#consents.set(key, { consent: structuredClone(record), revoked: null });
  }

  async getConsent(workspaceId: string, consentId: string): Promise<{ consent: ConsentRecord; revoked: ConsentRevocation | null } | null> {
    const stored = this.#consents.get(JSON.stringify([workspaceId, consentId]));
    return stored === undefined ? null : structuredClone(stored);
  }

  async revokeConsent(workspaceId: string, revocation: ConsentRevocation): Promise<ConsentRevocation> {
    const stored = this.#consents.get(JSON.stringify([workspaceId, revocation.consentId]));
    if (stored === undefined) throw new Error("no such consent");
    stored.revoked ??= structuredClone(revocation);
    return structuredClone(stored.revoked);
  }
}

/**
 * Answers record deliveries from a script: each queued answer is used once, a status or `"no_answer"`
 * (the post rejects, as a refused connection or a timeout would), then 200 for every post after.
 */
export class FakeRecordDelivery implements RecordDelivery {
  readonly posts: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
  readonly #script: Array<number | "no_answer">;

  constructor(script: Array<number | "no_answer"> = []) {
    this.#script = [...script];
  }

  async post(input: { url: string; headers: Record<string, string>; body: string }): Promise<{ status: number }> {
    this.posts.push(structuredClone(input));
    const next = this.#script.shift() ?? 200;
    if (next === "no_answer") throw new Error("no answer");
    return { status: next };
  }
}

/**
 * A host's own PIN store, for the PIN factor in `verifier` mode. Holds plain PINs (it is a fake);
 * a real one compares against its own hashes, for example scrypt.
 */
export class FakePinVerifier implements PinVerifier {
  readonly asked: string[] = [];
  readonly #pins = new Map<string, string>();
  readonly #duress = new Map<string, string>();

  set(workspaceId: string, subjectKey: string, pin: string): void {
    this.#pins.set(scoped(workspaceId, subjectKey), pin);
  }

  /** The subject's duress PIN (VER-12). */
  setDuress(workspaceId: string, subjectKey: string, pin: string): void {
    this.#duress.set(scoped(workspaceId, subjectKey), pin);
  }

  async verify(input: { workspaceId: string; subjectKey: string; pin: string }): Promise<{ matched: boolean; duress?: boolean }> {
    this.asked.push(input.subjectKey);
    const key = scoped(input.workspaceId, input.subjectKey);
    return { matched: this.#pins.get(key) === input.pin, duress: this.#duress.get(key) === input.pin };
  }
}

/** Keeps what it is told of duress PIN entries (VER-12). */
export class FakeDuressNotifier implements DuressNotifier {
  readonly told: DuressAlert[] = [];

  async notify(input: DuressAlert): Promise<void> {
    this.told.push({ ...input });
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

/**
 * Keeps the lock notices it is told of, as a host's email or dashboard would show them. `fail`
 * makes it throw at once (`"throws"`), reject (`"rejects"`) or never answer (`"hangs"`).
 */
export class FakeNotifier implements Notifier {
  readonly notices: LockNotice[] = [];
  fail: "throws" | "rejects" | "hangs" | null = null;

  lockout(notice: LockNotice): Promise<void> {
    this.notices.push(structuredClone(notice));
    if (this.fail === "throws") throw new Error("notifier down");
    if (this.fail === "rejects") return Promise.reject(new Error("notifier down"));
    if (this.fail === "hangs") return new Promise(() => undefined);
    return Promise.resolve();
  }
}

/** A JSON tuple, so no two keys share an id whatever their parts contain. */
function counterId(key: AttemptCounterKey): string {
  return JSON.stringify([key.workspaceId, key.factor, key.scope, key.key]);
}

/**
 * A field cipher that does not encrypt: it wraps the value in base64url with a counter, so every
 * answer differs, like a real cipher with a fresh nonce, and `decrypt` reads it back. Tests only.
 */
export class FakeFieldCipher implements FieldCipher {
  readonly encrypted: Array<{ workspaceId: string; recordId: string; field: string }> = [];

  async encrypt(plain: string, context: { workspaceId: string; recordId: string; field: string }): Promise<string> {
    this.encrypted.push({ ...context });
    return `fake-cipher:${this.encrypted.length}:${Buffer.from(plain, "utf8").toString("base64url")}`;
  }

  decrypt(ciphertext: string): string {
    return Buffer.from(ciphertext.split(":")[2]!, "base64url").toString("utf8");
  }
}

/** A subject record built from plain values, hashed the way the engine compares them. */
export function testSubject(
  knowledgeKey: KnowledgeKeyBytes,
  input: { accountNumber: string; phoneOnFile: string; knowledge: Record<string, string>; pin?: string; duressPin?: string },
): SubjectRecord {
  const knowledge: Record<string, string> = {};
  for (const [field, value] of Object.entries(input.knowledge)) knowledge[field] = knowledgeDigest(knowledgeKey, field, value);
  const subjectKey = subjectKeyFor(knowledgeKey, input.accountNumber);
  const subject: SubjectRecord = { subjectKey, phoneOnFile: input.phoneOnFile, knowledge };
  if (input.pin !== undefined) subject.pinDigest = pinDigest(knowledgeKey, subjectKey, input.pin);
  if (input.duressPin !== undefined) subject.duressDigest = duressDigest(knowledgeKey, subjectKey, input.duressPin);
  return subject;
}

/** A receipt signer over a fresh P-256 key that lives only in this process. */
export function generateTestSigner(keyId = "test-key-1"): ReceiptSigner {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return keyPairSigner(keyId, privateKey.export({ format: "pem", type: "pkcs8" }).toString());
}
