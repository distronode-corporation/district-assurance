// Trace (prove): the audit ledger, signed receipts and consent records. The ledger is always on:
// Trace is the one module that cannot be turned off or removed, and every engine needs a ledger
// adapter. Receipts and consent are optional parts, switched in Trace's settings and per flow.
//
// Trace also sends the two texts that follow a money, contact or access step: a link to the call's
// receipt, when the flow asks for it and the caller consented, and the security notice after a
// contact change, which always goes. Code builds both, and neither carries a value.
import type { ConsentChannel, ConsentRecord, ConsentRevocation, ConsentStore } from "../core/adapters.ts";
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { ScopeClass } from "../core/policy.ts";
import { LOCALES, type CallDraft, type CallRecord, type EngineRuntime, type Locale } from "../core/runtime.ts";
import { isObject, unknownKeys } from "../core/shape.ts";
import { wordingDigest, type ConsentWording } from "./consent.ts";
import { detailCarriesCardNumber } from "./ledger.ts";
import { receiptDigest, signReceipt, type ReceiptBody, type SignedReceipt } from "./receipt.ts";

export const TRACE = "trace";

export interface TraceSettings {
  /** Whether a call that runs no flow ends with a signed receipt. Default true. A flow decides with a `trace.receipt` step. */
  receipts?: boolean;
  /** The consent wordings a call may read, by purpose. */
  wordings?: ConsentWording[];
  /** The name the texts sign with (1 to 64 characters). Needed by a flow that texts a receipt link. */
  businessName?: string;
}

export interface TraceReceiptStep extends FlowStep {
  type: "trace.receipt";
  /** Text a link to the receipt after a money, contact or access step, when the caller said "yes" to this consent purpose. */
  textLink?: { consent: string };
}

/** What a completed flow step did, by the class of the scope it needed. */
export type ActionClass = Exclude<ScopeClass, "none">;

/** A security notice a contact change owes: to the number on file of the subject it changed, before the change. */
export interface ContactNotice {
  /** The subject whose contact details changed. */
  subjectKey: string;
  /** Their number on file before the change, as Badge read it. */
  to: string;
  sent: boolean;
}

export interface TraceTexts {
  /** The classes of the money, contact and access steps the call completed, each once, in order. */
  actions: ActionClass[];
  /** One notice per contact change, in order, but never two to the same subject's same number. */
  notices: ContactNotice[];
  receiptLink: "none" | "sent";
}

export interface TraceConsentStep extends FlowStep {
  type: "trace.consent";
  purpose: string;
  /** "yes" (the default): a "no" fails the step and stops the flow. "answer": either answer moves on. */
  require?: "yes" | "answer";
}

export interface TraceSlice {
  /** The wordings in force when the call started: a config change never strands a consent step. */
  wordings: ConsentWording[];
  consents: ConsentRecord[];
  /** A consent reserved and being written to the ConsentStore: recorded on the call once stored. */
  storing: ConsentRecord | null;
  /** Consents still being stored when the call ended: never recorded, so no consent (fail closed). */
  unrecorded: ConsentRecord[];
  /** The ledger head after `call.ended`, kept so a retried receipt carries the same one. */
  endedHead: { seq: number; hash: string } | null;
  receipt: SignedReceipt | null;
  /** The business name in force when the call started, as the wordings. */
  businessName: string | null;
  texts: TraceTexts;
}

function wordingErrors(wording: unknown, index: number): string[] {
  const at = `wordings[${index}]`;
  if (!isObject(wording) || typeof wording.purpose !== "string" || typeof wording.version !== "string" || !isObject(wording.text)) {
    return [`${at} must be { purpose, version, text: { en, fr, es? } }`];
  }
  const errors: string[] = [];
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(wording.purpose)) errors.push(`${at}: purpose must be snake_case`);
  if (wording.version === "") errors.push(`${at}: version is empty`);
  // Both go into the ledger's consent.recorded detail, which refuses a card number: caught here,
  // before a call can reserve a consent the ledger would then never accept.
  if (detailCarriesCardNumber([wording.purpose, wording.version])) errors.push(`${at}: purpose and version must not look like a card number`);
  const text = wording.text;
  if (typeof text.en !== "string" || text.en.trim() === "" || typeof text.fr !== "string" || text.fr.trim() === "") errors.push(`${at}: needs an English and a French text`);
  // Spanish is optional; when given it is a text like the others.
  if (text.es !== undefined && (typeof text.es !== "string" || text.es.trim() === "")) errors.push(`${at}: the Spanish text (es), when given, must not be empty`);
  errors.push(...unknownKeys(text, LOCALES).map((k) => `${at}: ${k} is not a locale (en, fr or es)`));
  return errors;
}

/**
 * A business name: 1 to 64 characters, no control characters (so no line breaks), no lone
 * surrogates, and no bidirectional embedding, override or isolate, which could make the text read
 * as another business's name.
 */
const BUSINESS_NAME = /^[^\p{Cc}\p{Cs}\u202a-\u202e\u2066-\u2069]{1,64}$/u;

function textLinkErrors(link: unknown, ctx: StepContext): string[] {
  if (!isObject(link) || typeof link.consent !== "string" || unknownKeys(link, ["consent"]).length > 0) return ["textLink must be { consent: <a wording purpose> }"];
  const errors: string[] = [];
  if (!ctx.adapters.has("messages")) errors.push("a texted receipt link needs the messages adapter, which the engine does not have");
  const settings = ctx.settings as TraceSettings | undefined | null;
  if (settings === null) return errors;
  if (!(settings?.wordings ?? []).some((w) => w.purpose === link.consent)) errors.push(`no wording for ${link.consent} in the trace settings`);
  if (settings?.businessName === undefined) errors.push("a texted receipt link needs businessName in the trace settings");
  return errors;
}

function settingsOf(rt: EngineRuntime): TraceSettings {
  return rt.settings<TraceSettings | undefined>(TRACE) ?? {};
}

export const traceModule: AssuranceModule = {
  manifest: {
    name: TRACE,
    version: "1",
    summary: "The hash-chained audit ledger (always on), signed receipts and consent records.",
    provides: { factors: [], steps: ["trace.consent", "trace.receipt"], outcomes: ["ledger", "receipt", "consent"] },
    scopes: { grants: [], needs: {} },
    adapters: ["ledger"],
    alwaysOn: true,
  },

  validateSettings(settings: unknown): string[] {
    if (settings === undefined) return [];
    if (!isObject(settings)) return ["must be an object"];
    const errors = unknownKeys(settings, ["receipts", "wordings", "businessName"]).map((k) => `${k} is not a trace setting`);
    if (settings.receipts !== undefined && typeof settings.receipts !== "boolean") errors.push("receipts must be true or false");
    const name = settings.businessName;
    if (name !== undefined && (typeof name !== "string" || !BUSINESS_NAME.test(name) || name.trim() === "")) errors.push("businessName must be 1 to 64 characters on one line");
    if (settings.wordings !== undefined) {
      if (!Array.isArray(settings.wordings)) return [...errors, "wordings must be a list"];
      settings.wordings.forEach((w: unknown, i: number) => errors.push(...wordingErrors(w, i)));
      const purposes = settings.wordings.map((w: unknown) => (isObject(w) ? w.purpose : undefined));
      if (new Set(purposes).size !== purposes.length) errors.push("two wordings have the same purpose");
    }
    return errors;
  },

  requiredAdapters(settings: unknown): string[] {
    return (settings as TraceSettings | undefined)?.receipts === false ? ["ledger"] : ["ledger", "signer"];
  },

  validateStep(step: FlowStep, ctx: StepContext): string[] {
    if (step.type === "trace.receipt") {
      const errors = unknownKeys(step, ["type", "textLink"]).map((k) => `${k} is not a field of this step`);
      if (!ctx.adapters.has("signer")) errors.push("a receipt needs the signer adapter, which the engine does not have");
      if (step.textLink !== undefined) errors.push(...textLinkErrors(step.textLink, ctx));
      return errors;
    }
    const errors = unknownKeys(step, ["type", "purpose", "require"]).map((k) => `${k} is not a field of this step`);
    if (step.require !== undefined && step.require !== "yes" && step.require !== "answer") errors.push('require must be "yes" (the default) or "answer"');
    if (typeof step.purpose !== "string") return [...errors, "purpose must name a wording"];
    const settings = ctx.settings as TraceSettings | undefined | null;
    if (settings !== null && !(settings?.wordings ?? []).some((w) => w.purpose === step.purpose)) {
      errors.push(`no wording for ${step.purpose} in the trace settings`);
    }
    return errors;
  },

  initCall(settings: unknown): JsonValue {
    const wordings = (settings as TraceSettings | undefined)?.wordings ?? [];
    const businessName = (settings as TraceSettings | undefined)?.businessName ?? null;
    const texts: TraceTexts = { actions: [], notices: [], receiptLink: "none" };
    return { wordings: structuredClone(wordings), consents: [], storing: null, unrecorded: [], endedHead: null, receipt: null, businessName, texts } as unknown as JsonValue;
  },

  enterStep(_step: FlowStep, s: JsonValue): JsonValue {
    return (s as unknown as TraceSlice).consents.length;
  },

  cannotRunStep(step: FlowStep, s: JsonValue, locale: Locale): string | null {
    if (step.type === "trace.receipt") {
      return step.textLink !== undefined && (s as unknown as TraceSlice).businessName === null ? "the call has no business name to text a receipt link with" : null;
    }
    const wording = (s as unknown as TraceSlice).wordings.find((w) => w.purpose === step.purpose);
    if (wording === undefined) return `the call has no wording for ${String(step.purpose)}`;
    return wording.text[locale] === undefined ? `the wording for ${wording.purpose} has no ${locale} text` : null;
  },

  stepStatus(step: FlowStep, view: StepView): StepStatus {
    if (step.type === "trace.receipt") return "complete";
    const answer = (view.slice as unknown as TraceSlice).consents.slice(view.mark as number).find((c) => c.purpose === step.purpose);
    if (answer === undefined) return "pending";
    // A "no" stops the flow unless the step only asks for an answer (require: "answer").
    return answer.answer === "yes" || step.require === "answer" ? "complete" : "failed";
  },
};

// ---- runtime -------------------------------------------------------------------------------

/**
 * Records a consent: the wording read (fingerprinted, from the settings) and the caller's answer.
 * With a `consents` adapter, the consent is reserved on the call, written to the ConsentStore and
 * then recorded, so every consent on the record can be revoked later. A store write that failed
 * stays reserved: the next `recordConsent` with the same purpose and answer resumes it with the
 * same record. A call that ends first settles it as not recorded (`settleUnrecorded`): no consent.
 */
export async function recordConsent(
  rt: EngineRuntime,
  callId: string,
  input: { purpose: string; answer: "yes" | "no"; channel?: ConsentChannel },
): Promise<ConsentRecord> {
  // Read once: the purpose a wording was found for is the one checked against the step and stored.
  const { purpose, answer, channel } = input;
  // Both go into the consent record, the store and the ledger as they are: only the values a consent
  // can hold (a host passing a transcript or a phone number by mistake is refused, not recorded).
  if (answer !== "yes" && answer !== "no") throw new EngineError("invalid_input", "answer must be yes or no");
  if (channel !== undefined && !CHANNELS.includes(channel)) throw new EngineError("invalid_input", "channel must be call, text or web");
  const store = consentStore(rt);
  const reserved = await rt.update(callId, (draft): ConsentRecord => {
    const s = draft.slice<TraceSlice>(TRACE);
    if (s.storing !== null) {
      if (s.storing.purpose !== purpose || s.storing.answer !== answer) {
        throw new EngineError("precondition_failed", `a consent to ${s.storing.purpose} is being stored; record it again first`);
      }
      return s.storing;
    }
    const wording = s.wordings.find((w) => w.purpose === purpose);
    if (wording === undefined) throw new EngineError("invalid_input", `no wording for ${purpose} in this call's trace settings`);
    if (draft.record.state.phase === "ended") throw new EngineError("invalid_transition", "the call has ended");
    // The caller cannot have heard a wording that has no text in the call's language.
    if (wording.text[draft.record.locale] === undefined) throw new EngineError("precondition_failed", `the wording for ${wording.purpose} has no ${draft.record.locale} text`);
    const step = stepOfType<TraceConsentStep>(draft.record, "trace.consent");
    if (step !== null && step.purpose !== purpose) throw new EngineError("precondition_failed", `the flow step asks for consent to ${step.purpose}`);
    const record: ConsentRecord = {
      consentId: rt.ids.next("cns"),
      callId,
      purpose: wording.purpose,
      wordingVersion: wording.version,
      wordingDigest: wordingDigest(wording),
      locale: draft.record.locale,
      answer,
      channel: channel ?? "call",
      at: rt.now(),
    };
    if (store === null) commitConsent(draft, record);
    else s.storing = record;
    return record;
  });
  if (store !== null) {
    // A rejected write may still have been stored, so the reservation is kept until the consent is
    // recorded, and a retry writes this same record again. Two processes resuming at once both
    // write it; the first to commit records it, and the other finds it recorded.
    await store.putConsent(rt.workspaceId, reserved);
    await rt.update(callId, (draft) => {
      const s = draft.slice<TraceSlice>(TRACE);
      if (s.storing?.consentId !== reserved.consentId) {
        // Another process recorded it first, or the call ended first and settled it as not recorded.
        if (s.consents.some((c) => c.consentId === reserved.consentId)) return;
        throw new EngineError("precondition_failed", "the call ended before the consent was stored: it was not recorded");
      }
      s.storing = null;
      commitConsent(draft, reserved);
    });
  }
  return structuredClone(reserved);
}

/**
 * At the end of a call, a consent still being stored settles as not recorded, which counts as no
 * consent: a store outage never keeps a call from ending, and never leaves a yes behind. The
 * ledger notes the purpose only, and the receipt lists it as `not_recorded`. A later write of the
 * reservation finds it gone and records nothing; a revocation of it is refused.
 */
export function settleUnrecorded(draft: CallDraft): void {
  const s = draft.slice<TraceSlice>(TRACE);
  if (s.storing === null) return;
  s.unrecorded.push(s.storing);
  draft.emit("consent.unrecorded", "system", { purpose: s.storing.purpose });
  s.storing = null;
}

function commitConsent(draft: CallDraft, record: ConsentRecord): void {
  draft.slice<TraceSlice>(TRACE).consents.push(record);
  draft.emit("consent.recorded", "caller", {
    consentId: record.consentId,
    purpose: record.purpose,
    wordingVersion: record.wordingVersion,
    wordingDigest: record.wordingDigest,
    answer: record.answer,
    locale: record.locale,
  });
}

/** The host's ConsentStore, or null without one: consents then live on the call record only, and cannot be revoked. */
function consentStore(rt: EngineRuntime): ConsentStore | null {
  return (rt.adapter("consents") as ConsentStore | undefined) ?? null;
}

const CHANNELS: readonly ConsentChannel[] = ["call", "text", "web"];

/**
 * Revokes a consent by voice (`call`), text or dashboard (`web`), during its call or long after:
 * the revocation is kept in the ConsentStore and written to the ledger as `consent.revoked`. A
 * retry, or a second revocation, returns the first one and appends nothing twice. A text or a
 * spoken answer that `isStopRequest` matches is the host's cue to call this.
 */
export async function revokeConsent(rt: EngineRuntime, input: { consentId: string; via: ConsentChannel }): Promise<ConsentRevocation> {
  if (!isObject(input)) throw new EngineError("invalid_input", "consentId is empty");
  // Read once: the id looked up and the channel checked are the ones the revocation records.
  const { consentId, via } = input;
  if (typeof consentId !== "string" || consentId === "") throw new EngineError("invalid_input", "consentId is empty");
  if (!CHANNELS.includes(via)) throw new EngineError("invalid_input", "via must be call, text or web");
  const store = consentStore(rt);
  if (store === null) throw new EngineError("precondition_failed", "revoking a consent needs the consents adapter, which the engine does not have");
  const stored = await store.getConsent(rt.workspaceId, consentId);
  if (stored === null) throw new EngineError("invalid_input", "no such consent");
  const consent = stored.consent;
  if (consent.answer !== "yes") throw new EngineError("precondition_failed", "the answer was no: there is nothing to revoke");
  // consent.revoked never precedes consent.recorded: the consent must be recorded on its call (not
  // still being stored, nor settled as not recorded), and the call's pending ledger entries are
  // appended first. A call record the host has since removed leaves only the store to go by.
  const call = await rt.read(consent.callId).catch((error: unknown) => {
    if (error instanceof EngineError && error.code === "unknown_call") return null;
    throw error;
  });
  if (call !== null) {
    if (!(call.modules[TRACE] as unknown as TraceSlice).consents.some((c) => c.consentId === consent.consentId)) {
      throw new EngineError("precondition_failed", "the consent is not recorded on its call: there is nothing to revoke yet");
    }
    await rt.flushLedger(consent.callId);
  }
  const revoked = stored.revoked ?? (await store.revokeConsent(rt.workspaceId, { consentId: consent.consentId, via, at: rt.now() }));
  // One entry per consent, however often it is revoked: the event id names the consent, and a
  // ledger appends an id once, so a retry after a failed append completes it.
  await rt.append({
    eventId: JSON.stringify([rt.workspaceId, consent.callId, "consent.revoked", consent.consentId]),
    callId: consent.callId,
    actor: revoked.via === "web" ? "member" : "caller",
    event: "consent.revoked",
    at: revoked.at,
    detail: { consentId: consent.consentId, purpose: consent.purpose, wordingVersion: consent.wordingVersion, via: revoked.via },
  });
  return structuredClone(revoked);
}

/** Whether a call ends with a receipt: its flow has a `trace.receipt` step, or it ran no flow and receipts are on. */
export function wantsReceipt(rt: EngineRuntime, record: CallRecord): boolean {
  if (record.flow !== null) return record.flow.steps.some((s) => s.type === "trace.receipt");
  return settingsOf(rt).receipts !== false;
}

/** The receipt a call holds, or null. */
export function receiptOf(record: CallRecord): SignedReceipt | null {
  return (record.modules[TRACE] as unknown as TraceSlice).receipt;
}

/** The ledger head after the call ended: taken once, then kept for any retry of the receipt. */
export async function endedHead(rt: EngineRuntime, record: CallRecord, head: () => Promise<{ seq: number; hash: string }>): Promise<{ seq: number; hash: string }> {
  const kept = (record.modules[TRACE] as unknown as TraceSlice).endedHead;
  if (kept !== null) return kept;
  const taken = await head();
  // Two retries can both take a head: the first one kept is the one every receipt uses.
  return rt.update(record.state.callId, (draft) => {
    const s = draft.slice<TraceSlice>(TRACE);
    s.endedHead ??= taken;
    return s.endedHead;
  });
}

/** Signs the receipt of an ended call. `parts` are what the other modules contribute. */
export async function issueReceipt(
  rt: EngineRuntime,
  record: CallRecord,
  head: { seq: number; hash: string },
  parts: Pick<ReceiptBody, "verification" | "records" | "payments" | "stepUp">,
): Promise<SignedReceipt> {
  const callId = record.state.callId;
  const slice = record.modules[TRACE] as unknown as TraceSlice;
  const body: ReceiptBody = {
    v: 1,
    receiptId: rt.ids.next("rcpt"),
    callId,
    workspaceId: rt.workspaceId,
    startedAt: record.state.startedAt,
    endedAt: record.state.endedAt!,
    issuedAt: rt.now(),
    verification: parts.verification,
    attestation: record.attestation ?? "none",
    records: parts.records,
    payments: parts.payments,
    consents: [
      ...slice.consents.map((c) => ({ purpose: c.purpose, wordingVersion: c.wordingVersion, wordingDigest: c.wordingDigest, answer: c.answer })),
      ...slice.unrecorded.map((c) => ({ purpose: c.purpose, wordingVersion: c.wordingVersion, wordingDigest: c.wordingDigest, answer: "not_recorded" as const })),
    ],
    ...(parts.stepUp === undefined || parts.stepUp.length === 0 ? {} : { stepUp: parts.stepUp }),
    ledger: head,
  };
  const signer = rt.adapter("signer");
  const receipt = await signReceipt(signer, body);
  // Two retries can both sign: the first stored is the call's receipt, returned to both.
  return rt.update(callId, (draft) => {
    const s = draft.slice<TraceSlice>(TRACE);
    if (s.receipt === null) {
      s.receipt = receipt;
      draft.emit("receipt.issued", "code", { receiptId: body.receiptId, digest: receiptDigest(body), kid: receipt.kid });
    }
    return structuredClone(s.receipt);
  });
}

// ---- texts after the call ------------------------------------------------------------------

function textsOf(record: CallRecord): TraceTexts {
  const slice = record.modules[TRACE] as unknown as TraceSlice;
  // A call stored before PRV-10 has no texts yet: it loads with none.
  slice.texts ??= { actions: [], notices: [], receiptLink: "none" };
  return slice.texts;
}

/**
 * A money, contact or access action happened on the call, for `subject`, the matched subject as
 * Badge read it when verification started: a flow step that needed such a scope completed, or an
 * outside module said it changed contact details (`ModuleCallView.contactChanged`). Each class is
 * noted once. Each contact change owes a security notice to the subject's number on file before
 * the change, unless one is owed or sent to that same number for that same subject already (no two
 * identical texts to one number). The notice owed is saved in the same write as the change, and
 * `contact.notice_owed` goes to the ledger with it, so a sweep can find a call that never ends.
 */
export function noteAction(draft: CallDraft, action: ActionClass, subject: { subjectKey: string; phoneOnFile: string }): void {
  const texts = textsOf(draft.record);
  if (!texts.actions.includes(action)) texts.actions.push(action);
  if (action !== "contact") return;
  if (texts.notices.some((n) => n.subjectKey === subject.subjectKey && n.to === subject.phoneOnFile)) return;
  texts.notices.push({ subjectKey: subject.subjectKey, to: subject.phoneOnFile, sent: false });
  draft.emit("contact.notice_owed", "code", {});
}

/** Whether the call still owes a security notice of a contact change. */
export function noticeDue(record: CallRecord): boolean {
  return textsOf(record).notices.some((n) => !n.sent);
}

/**
 * Texts each owed security notice of a contact change to the number on file before that change,
 * once each, in order. Nobody can turn them off: they alert the real customer, they are not
 * receipts. Each is read fresh before it is sent, so a notice another write already sent is not
 * sent again. A retry after a failure sends again with the same idempotency key, one key per notice.
 */
export async function sendContactNotice(rt: EngineRuntime, callId: string): Promise<void> {
  for (;;) {
    const record = await rt.read(callId);
    const index = textsOf(record).notices.findIndex((n) => !n.sent);
    if (index === -1) return;
    const slice = record.modules[TRACE] as unknown as TraceSlice;
    await rt.adapter("messages").sendText({
      to: slice.texts.notices[index]!.to,
      body: contactNoticeText(record.locale, slice.businessName),
      purpose: "contact_changed",
      idempotencyKey: rt.idempotencyKey(callId, "contact-notice", String(index), "text"),
    });
    await rt.update(callId, (draft) => {
      const kept = textsOf(draft.record).notices[index]!;
      // Two processes can both send (one text, by its key): the first records it, once.
      if (kept.sent) return;
      kept.sent = true;
      draft.emit("contact.notice_sent", "code", {});
    });
  }
}

/**
 * Texts a link to an ended call's receipt (the host's capability link, SRV-3) to the number on
 * file, at most once per call. It goes only when the flow's `trace.receipt` step asks for it, a
 * money, contact or access step completed, the caller said "yes" to the step's consent purpose, and
 * a keypad or PIN factor matched; after a contact change, to the number on file before it. Only the
 * caller's latest answer for the purpose counts. The link goes only to a number of the subject
 * Badge holds last (`subject`), whose receipt it is, never to a number kept for another subject.
 * `texted` is false when any of that does not hold, or the link was texted already.
 */
export async function textReceiptLink(
  rt: EngineRuntime,
  callId: string,
  url: string,
  subject: (record: CallRecord) => { subjectKey: string | null; numberOnFile: string | null },
): Promise<{ texted: boolean }> {
  if (!isReceiptLink(url)) throw new EngineError("invalid_input", "the receipt link must be an https URL of at most 512 characters");
  const record = await rt.read(callId);
  if (record.state.phase !== "ended") throw new EngineError("precondition_failed", "a receipt link is texted once the call has ended");
  const slice = record.modules[TRACE] as unknown as TraceSlice;
  if (slice.receipt === null) throw new EngineError("precondition_failed", "the call has no receipt yet");
  const step = record.flow?.steps.find((s): s is TraceReceiptStep => s.type === "trace.receipt");
  const texts = slice.texts;
  const consent = step?.textLink?.consent;
  // Answers are appended: a later "no" withdraws an earlier "yes".
  const consented = slice.consents.findLast((c) => c.purpose === consent)?.answer === "yes";
  if (consent === undefined || texts.receiptLink === "sent" || texts.actions.length === 0 || !consented) return { texted: false };
  const current = subject(record);
  const kept = texts.notices.find((n) => n.subjectKey === current.subjectKey);
  const to = kept?.to ?? current.numberOnFile;
  if (to === null) return { texted: false };
  await rt.adapter("messages").sendText({
    to,
    body: receiptLinkText(record.locale, slice.businessName!, texts.actions, url),
    purpose: "receipt_link",
    idempotencyKey: rt.idempotencyKey(callId, "receipt-link", "text"),
  });
  return rt.update(callId, (draft) => {
    const s = draft.slice<TraceSlice>(TRACE).texts;
    // Two processes can both send (one text, by its key): the first records it, once.
    if (s.receiptLink !== "sent") {
      s.receiptLink = "sent";
      draft.emit("receipt.link_texted", "code", { actions: [...s.actions] });
    }
    return { texted: true };
  });
}

function isReceiptLink(url: unknown): boolean {
  // The body carries the link as given, so a lone surrogate (which URL parsing would replace) is
  // refused, and so is any control or format character (NEL, NUL, a zero-width space, a bidi
  // override or isolate), which URL parsing accepts but would put more than a link into the text
  // or make it read as another.
  return typeof url === "string" && url.isWellFormed() && url.length <= 512 && !/[\s\p{Cc}\p{Cf}]/u.test(url) && URL.canParse(url) && new URL(url).protocol === "https:";
}

/** The kinds of action a receipt text names, in each supported locale. */
export const ACTION_WORDS: Record<Locale, Readonly<Record<ActionClass, string>>> = {
  en: { money: "a payment", contact: "a change to your contact details", access: "an access request" },
  fr: { money: "un paiement", contact: "une modification de vos coordonnées", access: "une demande d'accès" },
  es: { money: "un pago", contact: "un cambio en sus datos de contacto", access: "una solicitud de acceso" },
};

/** Where each supported locale's lists are joined (as AMOUNT_REGION formats amounts). */
export const LIST_REGION: Record<Locale, string> = { en: "en-CA", fr: "fr-CA", es: "es-US" };

/** The receipt link text, in each supported locale. */
export const RECEIPT_LINK_TEXT: Record<Locale, (businessName: string, kinds: string, url: string) => string> = {
  en: (businessName, kinds, url) => `Receipt from ${businessName} for ${kinds} on your call: ${url}`,
  fr: (businessName, kinds, url) => `Reçu de ${businessName} pour ${kinds} lors de votre appel : ${url}`,
  es: (businessName, kinds, url) => `Recibo de ${businessName} por ${kinds} durante su llamada: ${url}`,
};

/** The contact change notice, in each supported locale. */
export const CONTACT_NOTICE_TEXT: Record<Locale, (businessName: string | null) => string> = {
  en: (businessName) => `${businessName ?? "Security notice"}: the contact details on your account were changed during a call. If it was not you, contact us right away.`,
  fr: (businessName) =>
    `${businessName ?? "Avis de sécurité"} : les coordonnées de votre compte ont été modifiées pendant un appel. Si ce n'était pas vous, communiquez avec nous sans tarder.`,
  es: (businessName) =>
    `${businessName ?? "Aviso de seguridad"}: los datos de contacto de su cuenta se cambiaron durante una llamada. Si no fue usted, comuníquese con nosotros de inmediato.`,
};

/** The receipt text: the business and the kinds of action, never an amount, a code or a personal value. */
export function receiptLinkText(locale: Locale, businessName: string, actions: readonly ActionClass[], url: string): string {
  const kinds = new Intl.ListFormat(LIST_REGION[locale], { type: "conjunction" }).format(actions.map((a) => ACTION_WORDS[locale][a]));
  return RECEIPT_LINK_TEXT[locale](businessName, kinds, url);
}

/** The security notice of a contact change: no values, not even which detail changed. */
export function contactNoticeText(locale: Locale, businessName: string | null): string {
  return CONTACT_NOTICE_TEXT[locale](businessName);
}
