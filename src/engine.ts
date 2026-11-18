// The engine: one object per workspace that runs call sessions through Verify, File, Pay and
// Prove. The host's voice agent calls it from code paths (keypad events, tool handlers, webhook
// routes); the model never calls it directly and never sees what it compares.
//
// Every step writes an audit entry, every refusal is an EngineError with a stable code, and every
// planned-but-unbuilt step throws NotImplementedError. SPEC.md describes the flow.
import type { JsonWebKey } from "node:crypto";

import type {
  AuditLedger,
  CarrierSignals,
  IdentityProvider,
  IntakeRecord,
  MessageSender,
  PaymentLinks,
  ReceiptSigner,
  RecordStore,
  SubjectRecord,
} from "./core/adapters.ts";
import type { JsonValue } from "./core/canonical.ts";
import { randomIds, systemClock, type Clock, type IdGenerator } from "./core/clock.ts";
import { EngineError, NotImplementedError } from "./core/errors.ts";
import type { Actor, EngineEvent, EngineEventName, EventListener } from "./core/events.ts";
import {
  defaultVerificationPolicy,
  evaluateAssurance,
  scopesForLevel,
  textCodeTrusted,
  validatePolicy,
  type AssuranceLevel,
  type CarrierSignalReport,
  type VerificationPolicy,
} from "./core/policy.ts";
import { cardNumberRedactor, type RedactionFinding, type Redactor } from "./core/redaction.ts";
import { canApply, newSession, reduce, snapshot, type SensitiveReason, type SessionEvent, type SessionState } from "./core/session.ts";
import { intakeDigest, missingRequired, normaliseFieldValue, validateForm, type FieldValue, type IntakeForm, type NormaliseResult } from "./file/intake.ts";
import { settlementFor, validateAmount, type AmountSource, type PaymentOutcome, type PaymentRequest, type PaymentStatus } from "./pay/payment.ts";
import { wordingDigest, type ConsentRecord, type ConsentWording } from "./prove/consent.ts";
import { receiptDigest, signReceipt, type ReceiptBody, type SignedReceipt } from "./prove/receipt.ts";
import { isKeypadEntry, judgeKeypadFactors, subjectKeyFor } from "./verify/knowledge.ts";
import type { IdentityOutcome } from "./webhooks/stripe.ts";

export interface EngineAdapters {
  identity: IdentityProvider;
  carrier: CarrierSignals;
  messages: MessageSender;
  payments: PaymentLinks;
  records: RecordStore;
  ledger: AuditLedger;
  signer: ReceiptSigner;
}

export interface EngineOptions {
  workspaceId: string;
  /** The per-workspace HMAC key for knowledge factors. At least 16 bytes. */
  knowledgeKey: string | Uint8Array;
  adapters: EngineAdapters;
  policy?: VerificationPolicy;
  clock?: Clock;
  ids?: IdGenerator;
  /** Default: card numbers. */
  redactor?: Redactor;
  /** Default 900 (15 minutes). At most 3600. */
  grantTtlSeconds?: number;
  /** Upper bound per payment link, in minor units. */
  maxPaymentMinor?: number;
  onEvent?: EventListener;
}

export type Locale = "en" | "fr";

interface CallContext {
  state: SessionState;
  locale: Locale;
  subjectKey: string | null;
  subject: SubjectRecord | null;
  keypadAttempts: number;
  keypadMatched: boolean;
  carrier: CarrierSignalReport | null;
  identityLinks: number;
  intake: { form: IntakeForm; values: Record<string, FieldValue> } | null;
  payments: Map<string, PaymentRequest>;
  records: ReceiptBody["records"];
  consents: ConsentRecord[];
  receipt: SignedReceipt | null;
}

export interface KeypadResult {
  /** One answer for all fields: never which one failed. */
  matched: boolean;
  /** No more keypad attempts on this call. */
  locked: boolean;
}

export interface VerificationResult {
  level: AssuranceLevel;
  scopes: string[];
}

export type OutcomeResult = { applied: false } | { applied: true; callId: string };

export class Engine {
  readonly workspaceId: string;
  readonly policy: VerificationPolicy;
  readonly #key: string | Uint8Array;
  readonly #adapters: EngineAdapters;
  readonly #clock: Clock;
  readonly #ids: IdGenerator;
  readonly #redactor: Redactor;
  readonly #grantTtlMs: number;
  readonly #maxPaymentMinor: number | undefined;
  readonly #onEvent: EventListener | undefined;
  readonly #calls = new Map<string, CallContext>();
  readonly #identitySessions = new Map<string, string>();
  readonly #paymentLinks = new Map<string, { callId: string; paymentId: string }>();

  constructor(options: EngineOptions) {
    const policy = options.policy ?? defaultVerificationPolicy();
    const errors = validatePolicy(policy);
    const keyLength = typeof options.knowledgeKey === "string" ? Buffer.byteLength(options.knowledgeKey) : options.knowledgeKey.byteLength;
    if (keyLength < 16) errors.push("knowledgeKey must be at least 16 bytes");
    const ttl = options.grantTtlSeconds ?? 900;
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > 3600) errors.push("grantTtlSeconds must be an integer from 1 to 3600");
    if (options.workspaceId === "") errors.push("workspaceId is empty");
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    this.workspaceId = options.workspaceId;
    this.policy = structuredClone(policy);
    this.#key = options.knowledgeKey;
    this.#adapters = options.adapters;
    this.#clock = options.clock ?? systemClock;
    this.#ids = options.ids ?? randomIds;
    this.#redactor = options.redactor ?? cardNumberRedactor;
    this.#grantTtlMs = ttl * 1000;
    this.#maxPaymentMinor = options.maxPaymentMinor;
    this.#onEvent = options.onEvent;
  }

  // ---- sessions ----------------------------------------------------------------------------

  async startCall(input: { callId?: string; locale?: Locale } = {}): Promise<SessionState> {
    const callId = input.callId ?? this.#ids.next("call");
    if (this.#calls.has(callId)) throw new EngineError("invalid_input", "a call with that id exists");
    const ctx: CallContext = {
      state: newSession(callId, this.workspaceId, this.#now()),
      locale: input.locale ?? "en",
      subjectKey: null,
      subject: null,
      keypadAttempts: 0,
      keypadMatched: false,
      carrier: null,
      identityLinks: 0,
      intake: null,
      payments: new Map(),
      records: [],
      consents: [],
      receipt: null,
    };
    this.#calls.set(callId, ctx);
    await this.#emit(ctx, "call.started", "system", { locale: ctx.locale });
    return snapshot(ctx.state);
  }

  state(callId: string): SessionState {
    return snapshot(this.#call(callId).state);
  }

  /** Untrusted text (a business webhook reply, a document) entered the conversation. */
  async markUntrusted(callId: string, source: string): Promise<void> {
    const ctx = this.#call(callId);
    this.#apply(ctx, { type: "untrusted_content", source });
    // A photo ID link sent before the taint no longer counts. One link per call still holds.
    for (const [sessionId, owner] of this.#identitySessions) if (owner === callId) this.#identitySessions.delete(sessionId);
    await this.#emit(ctx, "session.tainted", "code", { source });
  }

  /** Keypad entry is open: the host pauses transcripts, cuts audio to the model and holds listen-in. */
  async openSensitive(callId: string, reason: SensitiveReason): Promise<void> {
    const ctx = this.#call(callId);
    this.#apply(ctx, { type: "sensitive_opened", reason });
    await this.#emit(ctx, "sensitive.opened", "code", { reason });
  }

  async closeSensitive(callId: string): Promise<void> {
    const ctx = this.#call(callId);
    this.#apply(ctx, { type: "sensitive_closed" });
    await this.#emit(ctx, "sensitive.closed", "code", {});
  }

  /**
   * Redacts text before the host stores or forwards it. `interrupt` tells the host to speak its
   * fixed "please don't read card numbers" line.
   */
  async redact(callId: string, text: string): Promise<{ text: string; findings: RedactionFinding[]; interrupt: boolean }> {
    const ctx = this.#call(callId);
    const result = this.#redactor.redact(text);
    if (result.findings.length > 0) {
      const kinds: Record<string, number> = {};
      for (const f of result.findings) kinds[f.kind] = (kinds[f.kind] ?? 0) + 1;
      await this.#emit(ctx, "redaction.applied", "code", { kinds });
    }
    return { ...result, interrupt: result.findings.length > 0 };
  }

  // ---- verify ------------------------------------------------------------------------------

  /** Starts (or restarts) verification with the account number the caller keyed. */
  async beginVerification(callId: string, input: { accountNumber: string }): Promise<void> {
    const ctx = this.#call(callId);
    const subjectKey = isKeypadEntry(input.accountNumber) ? subjectKeyFor(this.#key, input.accountNumber) : null;
    const reset = subjectKey !== ctx.subjectKey;
    this.#apply(ctx, { type: "verification_started", reset });
    if (ctx.state.factors.length === 0) {
      ctx.keypadMatched = false;
      ctx.carrier = null;
    }
    ctx.subjectKey = subjectKey;
    ctx.subject = subjectKey === null ? null : await this.#adapters.records.getSubject(this.workspaceId, subjectKey);
    await this.#emit(ctx, "verification.started", "code", {});
  }

  /** Judges every keypad field at once. The answer is the same for an unknown account and a wrong value. */
  async submitKeypad(callId: string, entries: Readonly<Record<string, string>>): Promise<KeypadResult> {
    const ctx = this.#call(callId);
    const factor = { kind: "keypad_knowledge" as const, passed: false, at: this.#now() };
    this.#assertCan(ctx, { type: "factor_recorded", factor });
    const max = this.policy.maxKeypadAttemptsPerCall;
    if (ctx.keypadAttempts >= max) return { matched: false, locked: true };
    ctx.keypadAttempts++;
    factor.passed = judgeKeypadFactors(this.#key, ctx.subject, this.policy.keypadFields, entries);
    ctx.keypadMatched ||= factor.passed;
    this.#apply(ctx, { type: "factor_recorded", factor });
    await this.#emit(ctx, "verification.factor", "code", { kind: factor.kind, passed: factor.passed });
    return { matched: factor.passed, locked: !factor.passed && ctx.keypadAttempts >= max };
  }

  /** Asks the carrier about the number on file. Only after the keypad checks matched. */
  async checkCarrier(callId: string): Promise<{ textCodeTrusted: boolean }> {
    const ctx = this.#call(callId);
    const subject = this.#matchedSubject(ctx);
    const report = await this.#adapters.carrier.check({ phoneNumber: subject.phoneOnFile });
    ctx.carrier = report;
    const trusted = textCodeTrusted(this.policy, report);
    if (report.identityMatch !== "unavailable") {
      const factor = { kind: "carrier_identity_match" as const, passed: report.identityMatch === "match", at: this.#now() };
      this.#apply(ctx, { type: "factor_recorded", factor });
    }
    await this.#emit(ctx, "verification.carrier_checked", "code", {
      checked: report.checked,
      textCodeTrusted: trusted,
      identityMatch: report.identityMatch,
    });
    return { textCodeTrusted: trusted };
  }

  /** The texted one-time code. Planned (VER-2): limits per subject and per number come first. */
  async sendTextCode(callId: string): Promise<never> {
    this.#matchedSubject(this.#call(callId));
    throw new NotImplementedError("Engine.sendTextCode", "VER-2");
  }

  /**
   * The strong tier: a photo ID and selfie check by a link texted to the number on file, only
   * after the keypad checks matched, at most one link per call.
   */
  async startPhotoId(callId: string): Promise<{ sent: true }> {
    const ctx = this.#call(callId);
    const subject = this.#matchedSubject(ctx);
    if (ctx.identityLinks > 0) throw new EngineError("precondition_failed", "a photo ID link was already sent on this call");
    ctx.identityLinks++;
    const check = await this.#adapters.identity.createDocumentCheck({ callId, idempotencyKey: `${callId}:identity` });
    this.#identitySessions.set(check.sessionId, callId);
    await this.#adapters.messages.sendText({
      to: subject.phoneOnFile,
      body: identityText(ctx.locale, check.url),
      purpose: "identity_link",
      idempotencyKey: `${callId}:identity:text`,
    });
    await this.#emit(ctx, "identity.link_sent", "code", {});
    return { sent: true };
  }

  /** The identity provider's verified webhook outcome. Unknown or late sessions are ignored. */
  async applyIdentityOutcome(outcome: IdentityOutcome): Promise<OutcomeResult> {
    const callId = this.#identitySessions.get(outcome.sessionId);
    if (callId === undefined) return { applied: false };
    const ctx = this.#call(callId);
    const factor = { kind: "photo_id" as const, passed: outcome.status === "verified", at: this.#now() };
    if (!canApply(ctx.state, { type: "factor_recorded", factor })) return { applied: false };
    this.#identitySessions.delete(outcome.sessionId);
    this.#apply(ctx, { type: "factor_recorded", factor });
    await this.#emit(ctx, "verification.factor", "system", { kind: factor.kind, passed: factor.passed, status: outcome.status });
    return { applied: true, callId };
  }

  /** Computes the level from the recorded factors and issues the grant. */
  async finishVerification(callId: string): Promise<VerificationResult> {
    const ctx = this.#call(callId);
    const result = evaluateAssurance(this.policy, ctx.state.factors, ctx.carrier);
    const scopes = scopesForLevel(this.policy, result.level);
    const issuedAt = this.#clock.now();
    const grant =
      result.level === 0
        ? null
        : {
            grantId: this.#ids.next("grant"),
            level: result.level,
            scopes,
            issuedAt: issuedAt.toISOString(),
            expiresAt: new Date(issuedAt.getTime() + this.#grantTtlMs).toISOString(),
          };
    this.#apply(ctx, { type: "verification_finished", level: result.level, grant });
    await this.#emit(ctx, "verification.finished", "code", {
      level: result.level,
      methods: result.counted,
      discounted: result.discounted.map((d) => d.kind),
    });
    if (grant !== null) {
      await this.#emit(ctx, "grant.issued", "code", { grantId: grant.grantId, level: grant.level, scopes, expiresAt: grant.expiresAt });
    }
    return { level: result.level, scopes: grant === null ? [] : scopes };
  }

  /** Whether the call's grant covers a scope now. A scope the policy does not list is refused. */
  authorize(callId: string, scope: string): boolean {
    const state = this.#call(callId).state;
    const min = this.policy.scopes[scope];
    if (min === undefined || state.phase === "ended") return false;
    if (min === 0) return true;
    const grant = state.grant;
    return grant !== null && grant.scopes.includes(scope) && this.#clock.now().getTime() < Date.parse(grant.expiresAt);
  }

  // ---- file --------------------------------------------------------------------------------

  async startIntake(callId: string, form: IntakeForm): Promise<void> {
    const ctx = this.#call(callId);
    this.#require(ctx, "intake.file");
    const errors = validateForm(form);
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    if (form.fields.some((f) => f.sensitive === true)) throw new NotImplementedError("sensitive intake fields", "FIL-2");
    this.#apply(ctx, { type: "intake_started" });
    ctx.intake = { form: structuredClone(form), values: {} };
    await this.#emit(ctx, "intake.started", "code", { formId: form.formId, version: form.version });
  }

  /** Normalises and stores one value in the draft. A refused value is not stored. */
  setIntakeField(callId: string, key: string, raw: string): NormaliseResult {
    const intake = this.#intake(this.#call(callId));
    const field = intake.form.fields.find((f) => f.key === key);
    if (field === undefined) throw new EngineError("invalid_input", `the form has no field ${key}`);
    const result = normaliseFieldValue(field, raw);
    if (result.ok) intake.values[key] = result.value;
    return result;
  }

  /** Files the draft once the caller confirmed the read-back. */
  async confirmIntake(callId: string, input: { confirmedBy: "voice" | "keypad" }): Promise<IntakeRecord> {
    const ctx = this.#call(callId);
    const intake = this.#intake(ctx);
    this.#require(ctx, "intake.file");
    const missing = missingRequired(intake.form, intake.values);
    if (missing.length > 0) throw new EngineError("invalid_input", `required fields missing: ${missing.join(", ")}`);
    const record: IntakeRecord = {
      recordId: this.#ids.next("rec"),
      workspaceId: this.workspaceId,
      callId,
      formId: intake.form.formId,
      formVersion: intake.form.version,
      values: structuredClone(intake.values),
      digest: intakeDigest(intake.form, intake.values),
      confirmedBy: input.confirmedBy,
      confirmedAt: this.#now(),
    };
    await this.#adapters.records.putIntakeRecord(record);
    this.#apply(ctx, { type: "intake_confirmed", recordId: record.recordId });
    ctx.intake = null;
    ctx.records.push({ recordId: record.recordId, formId: record.formId, digest: record.digest });
    await this.#emit(ctx, "intake.confirmed", "caller", {
      recordId: record.recordId,
      formId: record.formId,
      digest: record.digest,
      confirmedBy: record.confirmedBy,
    });
    return record;
  }

  async abandonIntake(callId: string): Promise<void> {
    const ctx = this.#call(callId);
    this.#apply(ctx, { type: "intake_abandoned" });
    ctx.intake = null;
    await this.#emit(ctx, "intake.abandoned", "code", {});
  }

  // ---- pay ---------------------------------------------------------------------------------

  /**
   * Texts a hosted payment link to the number on file. The amount comes from the host's code
   * (`amountSource` says where), never from the model.
   */
  async requestPayment(
    callId: string,
    input: { amountMinor: number; currency: string; description: string; amountSource: AmountSource },
  ): Promise<{ paymentId: string; status: PaymentStatus }> {
    const ctx = this.#call(callId);
    this.#require(ctx, "payment.request");
    const errors = validateAmount(input.amountMinor, input.currency, this.#maxPaymentMinor);
    const description = input.description.trim();
    if (description === "" || description.length > 200) errors.push("description must be 1 to 200 characters");
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    const paymentId = this.#ids.next("pay");
    this.#assertCan(ctx, { type: "payment_requested", paymentId });
    const subject = this.#matchedSubject(ctx);
    const link = await this.#adapters.payments.createLink({
      callId,
      paymentId,
      amountMinor: input.amountMinor,
      currency: input.currency,
      description,
      idempotencyKey: `${callId}:${paymentId}`,
    });
    await this.#adapters.messages.sendText({
      to: subject.phoneOnFile,
      body: paymentText(ctx.locale, link.url, input.amountMinor, input.currency),
      purpose: "payment_link",
      idempotencyKey: `${callId}:${paymentId}:text`,
    });
    const request: PaymentRequest = {
      paymentId,
      callId,
      amountMinor: input.amountMinor,
      currency: input.currency,
      description,
      amountSource: input.amountSource,
      linkId: link.linkId,
      status: "open",
      requestedAt: this.#now(),
      settledAt: null,
    };
    ctx.payments.set(paymentId, request);
    this.#paymentLinks.set(link.linkId, { callId, paymentId });
    this.#apply(ctx, { type: "payment_requested", paymentId });
    await this.#emit(ctx, "payment.link_sent", "code", {
      paymentId,
      linkId: link.linkId,
      amountMinor: input.amountMinor,
      currency: input.currency,
      amountSource: input.amountSource,
    });
    return { paymentId, status: "open" };
  }

  /** The payment provider's verified webhook outcome. "Paid" only when the provider says paid. */
  async applyPaymentOutcome(outcome: PaymentOutcome): Promise<OutcomeResult & { status?: PaymentStatus }> {
    const ref = this.#paymentLinks.get(outcome.linkId);
    if (ref === undefined) return { applied: false };
    const ctx = this.#call(ref.callId);
    const request = ctx.payments.get(ref.paymentId) as PaymentRequest;
    const status = settlementFor(outcome);
    if (request.status !== "open" || status === null) return { applied: false };
    request.status = status;
    request.settledAt = this.#now();
    if (ctx.state.phase === "paying") this.#apply(ctx, { type: "payment_settled", paymentId: request.paymentId });
    await this.#emit(ctx, "payment.settled", "system", { paymentId: request.paymentId, status });
    return { applied: true, callId: ref.callId, status };
  }

  // ---- prove -------------------------------------------------------------------------------

  async recordConsent(
    callId: string,
    input: { wording: ConsentWording; answer: "yes" | "no"; channel?: ConsentRecord["channel"] },
  ): Promise<ConsentRecord> {
    const ctx = this.#call(callId);
    if (ctx.state.phase === "ended") throw new EngineError("invalid_transition", "the call has ended");
    const record: ConsentRecord = {
      consentId: this.#ids.next("cns"),
      callId,
      purpose: input.wording.purpose,
      wordingVersion: input.wording.version,
      wordingDigest: wordingDigest(input.wording),
      locale: ctx.locale,
      answer: input.answer,
      channel: input.channel ?? "call",
      at: this.#now(),
    };
    ctx.consents.push(record);
    await this.#emit(ctx, "consent.recorded", "caller", {
      consentId: record.consentId,
      purpose: record.purpose,
      wordingVersion: record.wordingVersion,
      wordingDigest: record.wordingDigest,
      answer: record.answer,
      locale: record.locale,
    });
    return structuredClone(record);
  }

  /** Ends the call and issues its signed receipt, which carries the ledger head. */
  async endCall(callId: string): Promise<SignedReceipt> {
    const ctx = this.#call(callId);
    const endedAt = this.#now();
    this.#apply(ctx, { type: "call_ended", at: endedAt });
    await this.#emit(ctx, "call.ended", "system", {});
    const head = await this.#adapters.ledger.head();
    const result = evaluateAssurance(this.policy, ctx.state.factors, ctx.carrier);
    const body: ReceiptBody = {
      v: 1,
      receiptId: this.#ids.next("rcpt"),
      callId,
      workspaceId: this.workspaceId,
      startedAt: ctx.state.startedAt,
      endedAt,
      issuedAt: this.#now(),
      verification: { level: ctx.state.level, methods: ctx.state.level === 0 ? [] : result.counted },
      records: structuredClone(ctx.records),
      payments: [...ctx.payments.values()].map((p) => ({
        paymentId: p.paymentId,
        status: p.status,
        amountMinor: p.amountMinor,
        currency: p.currency,
        providerRef: p.linkId,
      })),
      consents: ctx.consents.map((c) => ({
        purpose: c.purpose,
        wordingVersion: c.wordingVersion,
        wordingDigest: c.wordingDigest,
        answer: c.answer,
      })),
      ledger: head,
    };
    const receipt = await signReceipt(this.#adapters.signer, body);
    ctx.receipt = receipt;
    await this.#emit(ctx, "receipt.issued", "code", { receiptId: body.receiptId, digest: receiptDigest(body), kid: receipt.kid });
    return structuredClone(receipt);
  }

  receipt(callId: string): SignedReceipt | null {
    const receipt = this.#call(callId).receipt;
    return receipt === null ? null : structuredClone(receipt);
  }

  /** The key set for verifying this engine's receipts. */
  receiptKeys(): JsonWebKey[] {
    return [this.#adapters.signer.publicJwk()];
  }

  // ---- internals ---------------------------------------------------------------------------

  #call(callId: string): CallContext {
    const ctx = this.#calls.get(callId);
    if (ctx === undefined) throw new EngineError("unknown_call", "no such call");
    return ctx;
  }

  #now(): string {
    return this.#clock.now().toISOString();
  }

  #assertCan(ctx: CallContext, event: SessionEvent): void {
    if (!canApply(ctx.state, event)) {
      throw new EngineError("invalid_transition", `${event.type} is not allowed while ${ctx.state.phase}`);
    }
  }

  #apply(ctx: CallContext, event: SessionEvent): void {
    ctx.state = reduce(ctx.state, event);
  }

  #require(ctx: CallContext, scope: string): void {
    if (!this.authorize(ctx.state.callId, scope)) throw new EngineError("scope_denied", `the grant does not cover ${scope}`);
  }

  #matchedSubject(ctx: CallContext): SubjectRecord {
    if (!ctx.keypadMatched || ctx.subject === null) {
      throw new EngineError("precondition_failed", "the keypad checks have not matched on this call");
    }
    return ctx.subject;
  }

  #intake(ctx: CallContext): { form: IntakeForm; values: Record<string, FieldValue> } {
    if (ctx.intake === null) throw new EngineError("invalid_transition", "no intake is open on this call");
    return ctx.intake;
  }

  async #emit(ctx: CallContext, name: EngineEventName, actor: Actor, detail: { [key: string]: JsonValue }): Promise<void> {
    const event: EngineEvent = { name, callId: ctx.state.callId, actor, at: this.#now(), detail };
    await this.#adapters.ledger.append({ callId: event.callId, actor, event: name, at: event.at, detail });
    this.#onEvent?.(event);
  }
}

export function createEngine(options: EngineOptions): Engine {
  return new Engine(options);
}

// ---- code-built texts, English and French --------------------------------------------------

function identityText(locale: Locale, url: string): string {
  return locale === "fr"
    ? `Votre lien de vérification d'identité, à usage unique : ${url}`
    : `Your one-time identity check link: ${url}`;
}

/** Formats an amount in minor units with the currency's own number of decimals. */
export function formatAmount(locale: Locale, amountMinor: number, currency: string): string {
  const format = new Intl.NumberFormat(locale === "fr" ? "fr-CA" : "en-CA", { style: "currency", currency: currency.toUpperCase() });
  const digits = format.resolvedOptions().maximumFractionDigits as number;
  return format.format(amountMinor / 10 ** digits);
}

function paymentText(locale: Locale, url: string, amountMinor: number, currency: string): string {
  const amount = formatAmount(locale, amountMinor, currency);
  return locale === "fr" ? `Votre lien de paiement sécurisé pour ${amount} : ${url}` : `Your secure payment link for ${amount}: ${url}`;
}
