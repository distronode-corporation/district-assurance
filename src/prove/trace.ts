// Trace (prove): the audit ledger, signed receipts and consent records. The ledger is always on:
// Trace is the one module that cannot be turned off or removed, and every engine needs a ledger
// adapter. Receipts and consent are optional parts, switched in Trace's settings and per flow.
//
// Trace also sends the two texts that follow a money, contact or access step: a link to the call's
// receipt, when the flow asks for it and the caller consented, and the security notice after a
// contact change, which always goes. Code builds both, and neither carries a value.
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { ScopeClass } from "../core/policy.ts";
import type { CallRecord, EngineRuntime, Locale } from "../core/runtime.ts";
import { isObject, unknownKeys } from "../core/shape.ts";
import { wordingDigest, type ConsentRecord, type ConsentWording } from "./consent.ts";
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

export interface TraceTexts {
  /** The classes of the money, contact and access steps the call completed, each once, in order. */
  actions: ActionClass[];
  /** The number on file before the call's first contact change, where both texts go after one. */
  priorNumber: string | null;
  /** The contact change notice: due once a contact step completed after a keypad or PIN match. */
  notice: "none" | "due" | "sent";
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
    return [`${at} must be { purpose, version, text: { en, fr } }`];
  }
  const errors: string[] = [];
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(wording.purpose)) errors.push(`${at}: purpose must be snake_case`);
  if (wording.version === "") errors.push(`${at}: version is empty`);
  const text = wording.text;
  if (typeof text.en !== "string" || text.en.trim() === "" || typeof text.fr !== "string" || text.fr.trim() === "") errors.push(`${at}: needs an English and a French text`);
  return errors;
}

/** A business name: 1 to 64 characters, no control characters (so no line breaks). */
const BUSINESS_NAME = /^[^\p{Cc}]{1,64}$/u;

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
    const texts: TraceTexts = { actions: [], priorNumber: null, notice: "none", receiptLink: "none" };
    return { wordings: structuredClone(wordings), consents: [], endedHead: null, receipt: null, businessName, texts } as unknown as JsonValue;
  },

  enterStep(_step: FlowStep, s: JsonValue): JsonValue {
    return (s as unknown as TraceSlice).consents.length;
  },

  cannotRunStep(step: FlowStep, s: JsonValue): string | null {
    if (step.type === "trace.receipt") {
      return step.textLink !== undefined && (s as unknown as TraceSlice).businessName === null ? "the call has no business name to text a receipt link with" : null;
    }
    return (s as unknown as TraceSlice).wordings.some((w) => w.purpose === step.purpose) ? null : `the call has no wording for ${String(step.purpose)}`;
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

/** Records a consent: the wording read (fingerprinted, from the settings) and the caller's answer. */
export async function recordConsent(
  rt: EngineRuntime,
  callId: string,
  input: { purpose: string; answer: "yes" | "no"; channel?: ConsentRecord["channel"] },
): Promise<ConsentRecord> {
  return rt.update(callId, (draft) => {
    const wording = draft.slice<TraceSlice>(TRACE).wordings.find((w) => w.purpose === input.purpose);
    if (wording === undefined) throw new EngineError("invalid_input", `no wording for ${input.purpose} in this call's trace settings`);
    if (draft.record.state.phase === "ended") throw new EngineError("invalid_transition", "the call has ended");
    const step = stepOfType<TraceConsentStep>(draft.record, "trace.consent");
    if (step !== null && step.purpose !== input.purpose) throw new EngineError("precondition_failed", `the flow step asks for consent to ${step.purpose}`);
    const record: ConsentRecord = {
      consentId: rt.ids.next("cns"),
      callId,
      purpose: wording.purpose,
      wordingVersion: wording.version,
      wordingDigest: wordingDigest(wording),
      locale: draft.record.locale,
      answer: input.answer,
      channel: input.channel ?? "call",
      at: rt.now(),
    };
    draft.slice<TraceSlice>(TRACE).consents.push(record);
    draft.emit("consent.recorded", "caller", {
      consentId: record.consentId,
      purpose: record.purpose,
      wordingVersion: record.wordingVersion,
      wordingDigest: record.wordingDigest,
      answer: record.answer,
      locale: record.locale,
    });
    return structuredClone(record);
  });
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
  parts: Pick<ReceiptBody, "verification" | "records" | "payments">,
): Promise<SignedReceipt> {
  const callId = record.state.callId;
  const body: ReceiptBody = {
    v: 1,
    receiptId: rt.ids.next("rcpt"),
    callId,
    workspaceId: rt.workspaceId,
    startedAt: record.state.startedAt,
    endedAt: record.state.endedAt!,
    issuedAt: rt.now(),
    verification: parts.verification,
    records: parts.records,
    payments: parts.payments,
    consents: (record.modules[TRACE] as unknown as TraceSlice).consents.map((c) => ({
      purpose: c.purpose,
      wordingVersion: c.wordingVersion,
      wordingDigest: c.wordingDigest,
      answer: c.answer,
    })),
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
  return (record.modules[TRACE] as unknown as TraceSlice).texts;
}

/**
 * A flow step that needed a money, contact or access scope completed. The first contact step keeps
 * `numberOnFile`, the matched subject's number as Badge read it before the change, and makes the
 * security notice due.
 */
export function noteAction(record: CallRecord, action: ActionClass, numberOnFile: string): void {
  const texts = textsOf(record);
  if (texts.actions.includes(action)) return;
  texts.actions.push(action);
  if (action === "contact") {
    texts.priorNumber = numberOnFile;
    texts.notice = "due";
  }
}

/** Whether the call still owes the security notice of a contact change. */
export function noticeDue(record: CallRecord): boolean {
  return textsOf(record).notice === "due";
}

/**
 * Texts the security notice of a contact change to the number on file before the change, once.
 * Nobody can turn it off: it is an alert to the real customer, not a receipt. A retry after a
 * failure sends again with the same idempotency key.
 */
export async function sendContactNotice(rt: EngineRuntime, record: CallRecord): Promise<void> {
  if (!noticeDue(record)) return;
  const callId = record.state.callId;
  const slice = record.modules[TRACE] as unknown as TraceSlice;
  await rt.adapter("messages").sendText({
    to: slice.texts.priorNumber!,
    body: contactNoticeText(record.locale, slice.businessName),
    purpose: "contact_changed",
    idempotencyKey: rt.idempotencyKey(callId, "contact-notice", "text"),
  });
  await rt.update(callId, (draft) => {
    const texts = draft.slice<TraceSlice>(TRACE).texts;
    // Two processes can both send (one text, by its key): the first records it, once.
    if (texts.notice !== "due") return;
    texts.notice = "sent";
    draft.emit("contact.notice_sent", "code", {});
  });
}

/**
 * Texts a link to an ended call's receipt (the host's capability link, SRV-3) to the number on
 * file, at most once per call. It goes only when the flow's `trace.receipt` step asks for it, a
 * money, contact or access step completed, the caller said "yes" to the step's consent purpose, and
 * a keypad or PIN factor matched; after a contact change, to the number on file before it. `texted`
 * is false when any of that does not hold, or the link was texted already.
 */
export async function textReceiptLink(
  rt: EngineRuntime,
  callId: string,
  url: string,
  numberOnFile: (record: CallRecord) => string | null,
): Promise<{ texted: boolean }> {
  if (!isReceiptLink(url)) throw new EngineError("invalid_input", "the receipt link must be an https URL of at most 512 characters");
  const record = await rt.read(callId);
  if (record.state.phase !== "ended") throw new EngineError("precondition_failed", "a receipt link is texted once the call has ended");
  const slice = record.modules[TRACE] as unknown as TraceSlice;
  if (slice.receipt === null) throw new EngineError("precondition_failed", "the call has no receipt yet");
  const step = record.flow?.steps.find((s): s is TraceReceiptStep => s.type === "trace.receipt");
  const texts = slice.texts;
  const consent = step?.textLink?.consent;
  const consented = slice.consents.some((c) => c.purpose === consent && c.answer === "yes");
  if (consent === undefined || texts.receiptLink === "sent" || texts.actions.length === 0 || !consented) return { texted: false };
  const to = texts.priorNumber ?? numberOnFile(record);
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

function isReceiptLink(url: string): boolean {
  return url.length <= 512 && !/\s/.test(url) && URL.canParse(url) && new URL(url).protocol === "https:";
}

const ACTION_WORDS: Readonly<Record<Locale, Readonly<Record<ActionClass, string>>>> = {
  en: { money: "a payment", contact: "a change to your contact details", access: "an access request" },
  fr: { money: "un paiement", contact: "une modification de vos coordonnées", access: "une demande d'accès" },
};

/** The receipt text: the business and the kinds of action, never an amount, a code or a personal value. */
export function receiptLinkText(locale: Locale, businessName: string, actions: readonly ActionClass[], url: string): string {
  const kinds = new Intl.ListFormat(locale === "fr" ? "fr-CA" : "en-CA", { type: "conjunction" }).format(actions.map((a) => ACTION_WORDS[locale][a]));
  return locale === "fr" ? `Reçu de ${businessName} pour ${kinds} lors de votre appel : ${url}` : `Receipt from ${businessName} for ${kinds} on your call: ${url}`;
}

/** The security notice of a contact change: no values, not even which detail changed. */
export function contactNoticeText(locale: Locale, businessName: string | null): string {
  if (locale === "fr") {
    return `${businessName ?? "Avis de sécurité"} : les coordonnées de votre compte ont été modifiées pendant un appel. Si ce n'était pas vous, communiquez avec nous sans tarder.`;
  }
  return `${businessName ?? "Security notice"}: the contact details on your account were changed during a call. If it was not you, contact us right away.`;
}
