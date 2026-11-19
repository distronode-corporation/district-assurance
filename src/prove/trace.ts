// Trace (prove): the audit ledger, signed receipts and consent records. The ledger is always on:
// Trace is the one module that cannot be turned off or removed, and every engine needs a ledger
// adapter. Receipts and consent are optional parts, switched in Trace's settings and per flow.
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import { LOCALES, type CallRecord, type EngineRuntime, type Locale } from "../core/runtime.ts";
import { isObject, unknownKeys } from "../core/shape.ts";
import { wordingDigest, type ConsentRecord, type ConsentWording } from "./consent.ts";
import { receiptDigest, signReceipt, type ReceiptBody, type SignedReceipt } from "./receipt.ts";

export const TRACE = "trace";

export interface TraceSettings {
  /** Whether a call that runs no flow ends with a signed receipt. Default true. A flow decides with a `trace.receipt` step. */
  receipts?: boolean;
  /** The consent wordings a call may read, by purpose. */
  wordings?: ConsentWording[];
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
}

function wordingErrors(wording: unknown, index: number): string[] {
  const at = `wordings[${index}]`;
  if (!isObject(wording) || typeof wording.purpose !== "string" || typeof wording.version !== "string" || !isObject(wording.text)) {
    return [`${at} must be { purpose, version, text: { en, fr, es? } }`];
  }
  const errors: string[] = [];
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(wording.purpose)) errors.push(`${at}: purpose must be snake_case`);
  if (wording.version === "") errors.push(`${at}: version is empty`);
  const text = wording.text;
  if (typeof text.en !== "string" || text.en.trim() === "" || typeof text.fr !== "string" || text.fr.trim() === "") errors.push(`${at}: needs an English and a French text`);
  // Spanish is optional; when given it is a text like the others.
  if (text.es !== undefined && (typeof text.es !== "string" || text.es.trim() === "")) errors.push(`${at}: the Spanish text (es), when given, must not be empty`);
  errors.push(...unknownKeys(text, LOCALES).map((k) => `${at}: ${k} is not a locale (en, fr or es)`));
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
    const errors = unknownKeys(settings, ["receipts", "wordings"]).map((k) => `${k} is not a trace setting`);
    if (settings.receipts !== undefined && typeof settings.receipts !== "boolean") errors.push("receipts must be true or false");
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
      const errors = unknownKeys(step, ["type"]).map((k) => `${k} is not a field of this step`);
      if (!ctx.adapters.has("signer")) errors.push("a receipt needs the signer adapter, which the engine does not have");
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
    return { wordings: structuredClone(wordings), consents: [], endedHead: null, receipt: null } as unknown as JsonValue;
  },

  enterStep(_step: FlowStep, s: JsonValue): JsonValue {
    return (s as unknown as TraceSlice).consents.length;
  },

  cannotRunStep(step: FlowStep, s: JsonValue, locale: Locale): string | null {
    if (step.type === "trace.receipt") return null;
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

/** Records a consent: the wording read (fingerprinted, from the settings) and the caller's answer. */
export async function recordConsent(
  rt: EngineRuntime,
  callId: string,
  input: { purpose: string; answer: "yes" | "no"; channel?: ConsentRecord["channel"] },
): Promise<ConsentRecord> {
  // Read once: the purpose a wording was found for is the one the flow step is checked against.
  const { purpose, answer, channel } = input;
  // The answer goes into the record, the receipt and the ledger as it is: refused before any write.
  if (answer !== "yes" && answer !== "no") throw new EngineError("invalid_input", "answer must be yes or no");
  return rt.update(callId, (draft) => {
    const wording = draft.slice<TraceSlice>(TRACE).wordings.find((w) => w.purpose === purpose);
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
  parts: Pick<ReceiptBody, "verification" | "records" | "payments" | "stepUp">,
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
    attestation: record.attestation ?? "none",
    records: parts.records,
    payments: parts.payments,
    consents: (record.modules[TRACE] as unknown as TraceSlice).consents.map((c) => ({
      purpose: c.purpose,
      wordingVersion: c.wordingVersion,
      wordingDigest: c.wordingDigest,
      answer: c.answer,
    })),
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
