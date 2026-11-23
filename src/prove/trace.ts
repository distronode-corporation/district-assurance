// Trace (prove): the audit ledger, signed receipts and consent records. The ledger is always on:
// Trace is the one module that cannot be turned off or removed, and every engine needs a ledger
// adapter. Receipts and consent are optional parts, switched in Trace's settings and per flow.
//
// Trace also sends the two texts that follow a money, contact or access step: a link to the call's
// receipt, when the flow asks for it and the caller consented, and the security notice after a
// contact change, which always goes. Code builds both, and neither carries a value.
import type { AuditEntry, ConsentChannel, ConsentRecord, ConsentRevocation, ConsentStore, EmailSender } from "../core/adapters.ts";
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { isEmailAddress } from "../core/email.ts";
import { stepOfType } from "../core/flow.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { ScopeClass } from "../core/policy.ts";
import { LOCALES, type CallDraft, type CallRecord, type EngineRuntime, type Locale } from "../core/runtime.ts";
import { isObject, unknownKeys } from "../core/shape.ts";
import type { PaymentChannel } from "../pay/payment.ts";
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
  /**
   * The channels a receipt link may go by: `["text"]` (the default) or `["text", "email"]`, which
   * turns on receipt links by email (`sendReceiptLink`): it needs the `emails` adapter and a
   * `receipt_email` wording, and goes only to the address kept for the subject when the call's
   * action was noted, the verified address on file as the call held it then. Text is always one:
   * it is the channel when the caller chose text for their payment link, or chose nothing.
   */
  channels?: PaymentChannel[];
}

/** The consent purpose a receipt link by email is sent under, fixed in code: the wording for it is the host's, in Trace's settings. */
export const RECEIPT_EMAIL_PURPOSE = "receipt_email";

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
  /**
   * The address on file for a subject as Badge held it when the call's first action was noted, one
   * per subject, and `null` when that first observation saw no address, so a later action never
   * fills one in: a receipt email goes to the one kept here, never to an address the host's
   * records changed to later on the call (a recheck re-reads the subject).
   */
  emails: Array<{ subjectKey: string; to: string | null }>;
  /** Whether a receipt link went out on this call, whichever channel sent it. */
  receiptLink: "none" | "sent";
  /**
   * The channels whose send is recorded on the ledger (`receipt.link_texted`, `receipt.link_emailed`),
   * in the order they were recorded. Absent on a call saved before receipt links had channels.
   */
  receiptLinkChannels?: ("text" | "email")[];
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

/** Whether a receipt link may go by email under these settings (Paylink's `channels` shape: text always, email to turn it on). */
function receiptEmailOn(settings: TraceSettings | undefined): boolean {
  return (settings?.channels ?? []).includes("email");
}

/** Problems with Trace's `channels` setting: text always, email at most once, and email needs its wording. */
function channelsErrors(value: unknown, wordings: unknown): string[] {
  if (!Array.isArray(value) || !value.every((c) => c === "text" || c === "email")) return ["channels must list text, and email or not"];
  if (new Set(value).size !== value.length) return ["channels has duplicates"];
  if (!value.includes("text")) return ["channels must include text: it is how a receipt link goes when the caller chose text, or nothing, for their payment link"];
  if (value.includes("email") && !(Array.isArray(wordings) && wordings.some((w: unknown) => isObject(w) && w.purpose === RECEIPT_EMAIL_PURPOSE))) {
    return [`the email channel needs a ${RECEIPT_EMAIL_PURPOSE} wording in the trace settings`];
  }
  return [];
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
    const errors = unknownKeys(settings, ["receipts", "wordings", "businessName", "channels"]).map((k) => `${k} is not a trace setting`);
    if (settings.receipts !== undefined && typeof settings.receipts !== "boolean") errors.push("receipts must be true or false");
    const name = settings.businessName;
    if (name !== undefined && (typeof name !== "string" || !BUSINESS_NAME.test(name) || name.trim() === "")) errors.push("businessName must be 1 to 64 characters on one line");
    if (settings.wordings !== undefined) {
      if (!Array.isArray(settings.wordings)) return [...errors, "wordings must be a list"];
      settings.wordings.forEach((w: unknown, i: number) => errors.push(...wordingErrors(w, i)));
      const purposes = settings.wordings.map((w: unknown) => (isObject(w) ? w.purpose : undefined));
      if (new Set(purposes).size !== purposes.length) errors.push("two wordings have the same purpose");
    }
    if (settings.channels !== undefined) errors.push(...channelsErrors(settings.channels, settings.wordings));
    return errors;
  },

  requiredAdapters(settings: unknown): string[] {
    const trace = settings as TraceSettings | undefined;
    const adapters = (trace?.receipts === false ? ["ledger"] : ["ledger", "signer"]) as string[];
    return receiptEmailOn(trace) ? [...adapters, "emails"] : adapters;
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
    const texts: TraceTexts = { actions: [], notices: [], emails: [], receiptLink: "none" };
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
 * `subjectOf` names the subject the call matched (or null), which the consent is recorded under:
 * the engine passes it, so Trace never reads Badge's part of the call itself. In a flow, the step
 * must be a `trace.consent` step for this purpose, or, for a consent another module's step takes
 * as part of its own work (Paylink's channel choice), the step type `onStep` names.
 */
export async function recordConsent(
  rt: EngineRuntime,
  callId: string,
  input: { purpose: string; answer: "yes" | "no"; channel?: ConsentChannel },
  subjectOf: (record: CallRecord) => string | null,
  onStep?: string,
): Promise<ConsentRecord> {
  // Read once: the purpose a wording was found for is the one checked against the step and stored.
  const { purpose, answer, channel } = input;
  // Both go into the consent record, the store and the ledger as they are: only the values a consent
  // can hold (a host passing a transcript or a phone number by mistake is refused, not recorded).
  if (answer !== "yes" && answer !== "no") throw new EngineError("invalid_input", "answer must be yes or no");
  if (channel !== undefined && !CHANNELS.includes(channel)) throw new EngineError("invalid_input", "channel must be call, text or web");
  const store = consentStore(rt);
  const reserved = await rt.update(callId, (draft): ConsentRecord => {
    const s = consentsOf(draft.slice<TraceSlice>(TRACE));
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
    if (onStep !== undefined) stepOfType(draft.record, onStep);
    else {
      const step = stepOfType<TraceConsentStep>(draft.record, "trace.consent");
      if (step !== null && step.purpose !== purpose) throw new EngineError("precondition_failed", `the flow step asks for consent to ${step.purpose}`);
    }
    const record: ConsentRecord = {
      consentId: rt.ids.next("cns"),
      callId,
      subjectKey: subjectOf(draft.record),
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
  const s = consentsOf(draft.slice<TraceSlice>(TRACE));
  if (s.storing === null) return;
  s.unrecorded.push(s.storing);
  draft.emit("consent.unrecorded", "system", { purpose: s.storing.purpose });
  s.storing = null;
}

/** A call stored before PRV-3 has no consent being stored and none unrecorded: it loads with none. */
function consentsOf(s: TraceSlice): TraceSlice {
  const legacy = s as Partial<TraceSlice>;
  legacy.storing ??= null;
  legacy.unrecorded ??= [];
  return s;
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
 * the revocation is kept in the ConsentStore and written to the ledger as `consent.revoked`
 * (`priorRecord: false` when the call is gone and the ledger holds no `consent.recorded` for it). A
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
  // With the call gone, the store alone is no proof the call recorded the consent: a store write
  // that landed after the call settled it as not recorded leaves a yes the call never recorded, and
  // a call removed before its consent.recorded entry was appended leaves no entry. Either way the
  // withdrawal is kept in the store (a yes there never outlives the caller's no) and always reaches
  // the ledger; without this workspace's consent.recorded entry for it, the entry says so
  // (priorRecord: false), so consent.revoked never stands for a recording the ledger lacks.
  const ledgered = call !== null || (await recordedOnLedger(rt, consent));
  const revoked = stored.revoked ?? (await store.revokeConsent(rt.workspaceId, { consentId: consent.consentId, via, at: rt.now() }));
  // One entry per consent, however often it is revoked: the event id names the consent, and a
  // ledger appends an id once, so a retry after a failed append completes it. An id a prune
  // spent was appended before the prune: the engine skips the write and the stored revocation
  // answers, so no second entry is written below a base either.
  await rt.append({
    eventId: JSON.stringify([rt.workspaceId, consent.callId, "consent.revoked", consent.consentId]),
    callId: consent.callId,
    actor: revoked.via === "web" ? "member" : "caller",
    event: "consent.revoked",
    at: revoked.at,
    detail: { consentId: consent.consentId, purpose: consent.purpose, wordingVersion: consent.wordingVersion, via: revoked.via, ...(ledgered ? {} : { priorRecord: false }) },
  });
  return structuredClone(revoked);
}

/** Ledger entries read per page when looking for one entry. */
export const LEDGER_PAGE = 256;

/** Whether this workspace's ledger holds the consent.recorded entry of a consent, on its call. */
async function recordedOnLedger(rt: EngineRuntime, consent: ConsentRecord): Promise<boolean> {
  // A ledger can be shared by several workspaces: the event id (a JSON tuple starting with the
  // workspace and the call) says whose entry it is.
  const prefix = `${JSON.stringify([rt.workspaceId, consent.callId]).slice(0, -1)},`;
  const recorded = (e: AuditEntry) => e.event === "consent.recorded" && e.callId === consent.callId && e.detail.consentId === consent.consentId && e.eventId?.startsWith(prefix) === true;
  // Read page by page, stopping at the entry or an empty page: a shared ledger's whole history is
  // never held at once. A page may be shorter than asked (an adapter can cap it), so the next one
  // starts after the last entry returned.
  const ledger = rt.adapter("ledger");
  for (let page = await ledger.list(1, LEDGER_PAGE); page.length > 0; page = await ledger.list(page.at(-1)!.seq + 1, LEDGER_PAGE)) {
    if (page.some(recorded)) return true;
  }
  return false;
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
  const slice = consentsOf(record.modules[TRACE] as unknown as TraceSlice);
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
  // A call stored before PRV-10 has no texts yet, and one stored before receipt links had channels
  // keeps neither list: both load with none.
  slice.texts ??= { actions: [], notices: [], emails: [], receiptLink: "none" };
  slice.texts.emails ??= [];
  slice.texts.receiptLinkChannels ??= [];
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
export function noteAction(draft: CallDraft, action: ActionClass, subjectOf: () => { subjectKey: string | null; numberOnFile: string | null; emailOnFile: string | null }): void {
  const texts = textsOf(draft.record);
  // Read before anything changes, so a refusal leaves the call as it was.
  const subject = subjectOf();
  if (!texts.actions.includes(action)) texts.actions.push(action);
  // The address on file as Badge holds the subject now, kept at the call's first action for them,
  // and a first observation of no address is kept too, so a later re-read never fills one in: the
  // receipt email goes to this one, as the notice below keeps the number, never to an address the
  // host's records changed to later on the call.
  if (subject.subjectKey !== null && !texts.emails.some((e) => e.subjectKey === subject.subjectKey)) {
    texts.emails.push({ subjectKey: subject.subjectKey, to: subject.emailOnFile });
  }
  if (action !== "contact") return;
  // A contact action owes a notice to its subject, so it needs a standing keypad or PIN match.
  if (subject.subjectKey === null || subject.numberOnFile === null) {
    throw new EngineError("precondition_failed", "the keypad or PIN checks have not matched on this call");
  }
  if (texts.notices.some((n) => n.subjectKey === subject.subjectKey && n.to === subject.numberOnFile)) return;
  texts.notices.push({ subjectKey: subject.subjectKey, to: subject.numberOnFile, sent: false });
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
  // Each owed notice is tried once a run: one the adapter refuses stays owed for the next run, and
  // the notices after it still go. The first failure is passed on once every notice was tried.
  const tried = new Set<number>();
  const failures: unknown[] = [];
  for (;;) {
    const record = await rt.read(callId);
    const index = textsOf(record).notices.findIndex((n, i) => !n.sent && !tried.has(i));
    if (index === -1) break;
    tried.add(index);
    const slice = record.modules[TRACE] as unknown as TraceSlice;
    try {
      await rt.adapter("messages").sendText({
        to: slice.texts.notices[index]!.to,
        body: contactNoticeText(record.locale, slice.businessName),
        purpose: "contact_changed",
        idempotencyKey: rt.idempotencyKey(callId, "contact-notice", String(index), "text"),
      });
    } catch (error) {
      failures.push(error);
      continue;
    }
    await rt.update(callId, (draft) => {
      const kept = textsOf(draft.record).notices[index]!;
      // Two processes can both send (one text, by its key): the first records it, once.
      if (kept.sent) return;
      kept.sent = true;
      draft.emit("contact.notice_sent", "code", {});
    });
  }
  if (failures.length > 0) throw failures[0];
}

/**
 * What a receipt link send is judged on, read once. Throws the refusals both channels share: a
 * link that is not an https URL of the right shape, a call that has not ended, a call with no
 * receipt yet.
 */
async function receiptLinkContext(rt: EngineRuntime, callId: string, url: string): Promise<{ record: CallRecord; slice: TraceSlice; step: TraceReceiptStep | undefined; texts: TraceTexts }> {
  if (!isReceiptLink(url)) throw new EngineError("invalid_input", "the receipt link must be an https URL of at most 512 characters");
  const record = await rt.read(callId);
  if (record.state.phase !== "ended") throw new EngineError("precondition_failed", "a receipt link is texted once the call has ended");
  const slice = record.modules[TRACE] as unknown as TraceSlice;
  if (slice.receipt === null) throw new EngineError("precondition_failed", "the call has no receipt yet");
  const step = record.flow?.steps.find((s): s is TraceReceiptStep => s.type === "trace.receipt");
  return { record, slice, step, texts: textsOf(record) };
}

/**
 * Whether the caller's latest answer to a purpose on this call is a standing yes: answers are
 * appended, so a later "no" withdraws an earlier "yes", and an answer still being stored when the
 * call ended (not_recorded) may be a later "no", so any one for the purpose sends nothing (fail
 * closed). A revocation is kept in the ConsentStore, not on the call: the yes is read back from the
 * store, and one revoked, or not found there, sends nothing. A read that fails sends nothing too.
 */
async function consentStands(rt: EngineRuntime, slice: TraceSlice, purpose: string | undefined): Promise<boolean> {
  if (purpose === undefined) return false;
  if (slice.consents.findLast((c) => c.purpose === purpose)?.answer !== "yes") return false;
  if (consentsOf(slice).unrecorded.some((c) => c.purpose === purpose)) return false;
  const store = consentStore(rt);
  if (store !== null) {
    const latest = slice.consents.findLast((c) => c.purpose === purpose)!;
    if ((await store.getConsent(rt.workspaceId, latest.consentId))?.revoked !== null) return false;
  }
  return true;
}

/**
 * Records the send. `receiptLink` is the once-per-call guard, exactly the value a process running
 * 0.3.0 reads; each channel's own entry is written when that channel's send is not recorded yet, so
 * two entry points racing still log one entry per channel that really sent, and no channel logs
 * twice (two processes can both send one message, by its key).
 */
async function recordLinkSent(rt: EngineRuntime, callId: string, channel: "text" | "email"): Promise<void> {
  await rt.update(callId, (draft) => {
    const s = textsOf(draft.record);
    const recorded = (s.receiptLinkChannels ??= []);
    if (recorded.includes(channel)) return;
    recorded.push(channel);
    s.receiptLink = "sent";
    draft.emit(channel === "email" ? "receipt.link_emailed" : "receipt.link_texted", "code", { actions: [...s.actions] });
  });
}

/**
 * Texts the receipt link by the text channel's own rules: the flow's `trace.receipt` step asks for
 * it (`textLink`), the caller's latest answer to that consent purpose is yes, and the number is the
 * one kept for Badge's current subject before a contact change, else that subject's number on file.
 * Answers whether the text went out.
 */
async function textTheLink(
  rt: EngineRuntime,
  callId: string,
  url: string,
  ctx: { record: CallRecord; slice: TraceSlice; step: TraceReceiptStep | undefined; texts: TraceTexts },
  subject: (record: CallRecord) => { subjectKey: string | null; numberOnFile: string | null },
): Promise<boolean> {
  if (!(await consentStands(rt, ctx.slice, ctx.step?.textLink?.consent))) return false;
  const current = subject(ctx.record);
  const kept = ctx.texts.notices.find((n) => n.subjectKey === current.subjectKey);
  const to = kept?.to ?? current.numberOnFile;
  if (to === null) return false;
  await rt.adapter("messages").sendText({
    to,
    body: receiptLinkText(ctx.record.locale, ctx.slice.businessName!, ctx.texts.actions, url),
    purpose: "receipt_link",
    idempotencyKey: rt.idempotencyKey(callId, "receipt-link", "text"),
  });
  await recordLinkSent(rt, callId, "text");
  return true;
}

/**
 * Texts a link to an ended call's receipt (the host's capability link, SRV-3) to the number on
 * file, at most once per call. It goes only when the flow's `trace.receipt` step asks for it, a
 * money, contact or access step completed, the caller said "yes" to the step's consent purpose, and
 * a keypad or PIN factor matched; after a contact change, to the number on file before it. Only the
 * caller's latest answer for the purpose counts. The link goes only to a number of the subject
 * Badge holds last (`subject`), whose receipt it is, never to a number kept for another subject.
 * `texted` is false when any of that does not hold, or a link was sent already (by either channel).
 */
export async function textReceiptLink(
  rt: EngineRuntime,
  callId: string,
  url: string,
  subject: (record: CallRecord) => { subjectKey: string | null; numberOnFile: string | null },
): Promise<{ texted: boolean }> {
  const ctx = await receiptLinkContext(rt, callId, url);
  if (ctx.texts.receiptLink !== "none" || ctx.texts.actions.length === 0) return { texted: false };
  return { texted: await textTheLink(rt, callId, url, ctx, subject) };
}

/**
 * Sends a link to an ended call's receipt by the channel the caller chose for their payment link:
 * email when their last delivered payment link went by email and Trace's `channels` setting still
 * has the email channel on, text otherwise. At most one link per call, whichever channel. The
 * email goes only to the address kept for the subject when the call's first action was noted
 * (as the contact notice keeps the number), held to `isEmailAddress`, under the caller's standing
 * yes to `receipt_email`; it never carries the address anywhere else. A channel that was chosen
 * but cannot be served (a withdrawn or missing yes, no address kept, one the plain-address check
 * refuses) sends nothing: the link never falls back to the other channel, and a host that runs
 * `textReceiptLink` beside this can still text on its own consent, so a host that adopts this
 * calls it alone. The text channel follows `textReceiptLink`'s rules exactly.
 */
export async function sendReceiptLink(
  rt: EngineRuntime,
  callId: string,
  url: string,
  subject: (record: CallRecord) => { subjectKey: string | null; numberOnFile: string | null; emailOnFile: string | null },
  paymentChannel: (record: CallRecord) => PaymentChannel,
): Promise<{ sent: boolean; channel: PaymentChannel | null }> {
  const ctx = await receiptLinkContext(rt, callId, url);
  if (ctx.texts.receiptLink !== "none" || ctx.texts.actions.length === 0) return { sent: false, channel: null };
  // The settings are read now: a business turns the email channel off without editing a flow.
  if (paymentChannel(ctx.record) === "email" && receiptEmailOn(settingsOf(rt))) {
    const current = subject(ctx.record);
    // The address kept when the call's first action was noted, never the one on file now: a host's
    // records can change under the call, and a recheck re-reads them.
    const kept = ctx.texts.emails.find((e) => e.subjectKey === current.subjectKey);
    const to = kept !== undefined && kept.to !== null && isEmailAddress(kept.to) ? kept.to : null;
    if (to !== null && (await consentStands(rt, ctx.slice, RECEIPT_EMAIL_PURPOSE))) {
      // The call keeps its business name from the start, and a payment went out by email, which
      // needed it, so it is there.
      const business = ctx.slice.businessName!;
      const email = RECEIPT_EMAIL[ctx.record.locale];
      await (rt.adapter("emails") as EmailSender).sendEmail({
        to,
        subject: email.subject(business),
        body: email.body(business, actionKinds(ctx.record.locale, ctx.texts.actions), url),
        locale: ctx.record.locale,
        purpose: "receipt_link",
        idempotencyKey: rt.idempotencyKey(callId, "receipt-link", "email"),
      });
      await recordLinkSent(rt, callId, "email");
      return { sent: true, channel: "email" };
    }
    // The email channel was chosen and cannot be served: nothing goes out, and never by text instead.
    return { sent: false, channel: null };
  }
  return (await textTheLink(rt, callId, url, ctx, subject)) ? { sent: true, channel: "text" } : { sent: false, channel: null };
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

/**
 * The receipt link email, in each supported locale. It names the business, what the call did and
 * the link, so a forwarded copy holds nothing more: never an amount, a code, a phone number or a
 * personal value.
 */
export const RECEIPT_EMAIL: Record<Locale, { subject: (business: string) => string; body: (business: string, kinds: string, url: string) => string }> = {
  en: {
    subject: (business) => `Your receipt from ${business}`,
    body: (business, kinds, url) => `${business} sent you a receipt for ${kinds} on your call.\n\n${url}\n\nIf you did not have this call, do not use the link.`,
  },
  fr: {
    subject: (business) => `Votre reçu de ${business}`,
    body: (business, kinds, url) => `${business} vous a envoyé un reçu pour ${kinds} lors de votre appel.\n\n${url}\n\nSi vous n'avez pas passé cet appel, n'utilisez pas le lien.`,
  },
  es: {
    subject: (business) => `Su recibo de ${business}`,
    body: (business, kinds, url) => `${business} le envió un recibo por ${kinds} durante su llamada.\n\n${url}\n\nSi no realizó esta llamada, no use el enlace.`,
  },
};

/** The contact change notice, in each supported locale. */
export const CONTACT_NOTICE_TEXT: Record<Locale, (businessName: string | null) => string> = {
  en: (businessName) => `${businessName ?? "Security notice"}: the contact details on your account were changed during a call. If it was not you, contact us right away.`,
  fr: (businessName) =>
    `${businessName ?? "Avis de sécurité"} : les coordonnées de votre compte ont été modifiées pendant un appel. Si ce n'était pas vous, communiquez avec nous sans tarder.`,
  es: (businessName) =>
    `${businessName ?? "Aviso de seguridad"}: los datos de contacto de su cuenta se cambiaron durante una llamada. Si no fue usted, comuníquese con nosotros de inmediato.`,
};

/** The call's actions as one list, in the locale's words ("a payment and a change to your contact details"). */
function actionKinds(locale: Locale, actions: readonly ActionClass[]): string {
  return new Intl.ListFormat(LIST_REGION[locale], { type: "conjunction" }).format(actions.map((a) => ACTION_WORDS[locale][a]));
}

/** The receipt text: the business and the kinds of action, never an amount, a code or a personal value. */
export function receiptLinkText(locale: Locale, businessName: string, actions: readonly ActionClass[], url: string): string {
  return RECEIPT_LINK_TEXT[locale](businessName, actionKinds(locale, actions), url);
}

/** The security notice of a contact change: no values, not even which detail changed. */
export function contactNoticeText(locale: Locale, businessName: string | null): string {
  return CONTACT_NOTICE_TEXT[locale](businessName);
}
