// Paylink (pay): payment by a hosted link texted to the number on file. The engine never sees a
// card. In a flow, the `paylink.request` step carries the amount, or names a reference the host's
// `AmountSource` adapter resolves, so it is checked when the config is saved; outside a flow the
// host's code passes it. Either way it never comes from the model.
//
// Before the link, code can read the amount back to the caller (`readBackPayment`) and the caller
// confirms it (`confirmPaymentAmount`); for an amount resolved by the AmountSource this is
// required. The link is reserved in one write (the call enters `paying`, so a second request is
// refused everywhere), created and texted, then committed. Once a link exists, only the provider
// settles it.
import type { SubjectRecord } from "../core/adapters.ts";
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import { hexDigestsEqual } from "../core/hash.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { AmountSource, CallDraft, CallRecord, EngineRuntime, Locale } from "../core/runtime.ts";
import type { SessionState } from "../core/session.ts";
import { isIntegerIn, isObject, unknownKeys } from "../core/shape.ts";
import { matchedSubject } from "../verify/badge.ts";
import { AMOUNT_REF, buildAmountReadBack, formatAmount, type AmountQuote, type AmountReadBack } from "./amount.ts";
import { MAX_LINK_AMOUNT_MINOR, settlementFor, validateAmount, type AmountSourceKind, type PaymentOutcome, type PaymentRequest, type PaymentStatus } from "./payment.ts";

export { formatAmount } from "./amount.ts";

export const PAYLINK = "paylink";

/** Whose account takes the money. Chosen per flow step; built in PAY-7, refused by the validator until then. */
export const PAYMENT_MODES = ["connect", "platform"] as const;
export type PaymentMode = (typeof PAYMENT_MODES)[number];

const AMOUNT_SOURCES: readonly AmountSourceKind[] = ["intake_record", "business_endpoint", "price_list"];

export interface PaylinkSettings {
  /** Upper bound per link, in minor units. At most 1,000,000. */
  maxAmountMinor?: number;
}

/** A step with a fixed amount (`amountMinor` and `currency`) or one the AmountSource resolves (`amountRef`), never both. */
export interface PaylinkRequestStep extends FlowStep {
  type: "paylink.request";
  amountMinor?: number;
  currency?: string;
  /** Instead of `amountMinor` and `currency`: a reference the `amounts` adapter resolves (PAY-2). */
  amountRef?: string;
  description: string;
  amountSource: AmountSourceKind;
  /** Planned (PAY-7). */
  mode?: PaymentMode;
}

/** A fixed amount, from the host's code. */
export interface FixedPaymentInput {
  amountMinor: number;
  currency: string;
  description: string;
  amountSource: AmountSourceKind;
}

/** An amount the `amounts` adapter resolves from a reference; read back and confirmed before the link. */
export interface ReferencedPaymentInput {
  amountRef: string;
  description: string;
  amountSource: AmountSourceKind;
}

export type PaymentInput = FixedPaymentInput | ReferencedPaymentInput;

export interface PaylinkSlice {
  payments: PaymentRequest[];
  /** The amount last read back on this call and not yet used by a link. */
  quote: AmountQuote | null;
}

function requestErrors(input: Record<string, unknown>, maxMinor: number | undefined): string[] {
  const errors: string[] = [];
  if (input.amountRef !== undefined) {
    if (input.amountMinor !== undefined || input.currency !== undefined) errors.push("name amountMinor and currency, or amountRef, not both");
    if (typeof input.amountRef !== "string" || !AMOUNT_REF.test(input.amountRef)) errors.push("amountRef must be 1 to 64 letters, digits, '.', ':', '-' or '_'");
  } else {
    const amount = input.amountMinor;
    const currency = input.currency;
    errors.push(...(typeof amount === "number" && typeof currency === "string" ? validateAmount(amount, currency, maxMinor) : ["amountMinor and currency are required"]));
  }
  const description = input.description;
  if (typeof description !== "string" || description.trim() === "" || description.trim().length > 200) errors.push("description must be 1 to 200 characters");
  if (!AMOUNT_SOURCES.includes(input.amountSource as AmountSourceKind)) errors.push(`amountSource must be one of ${AMOUNT_SOURCES.join(", ")}`);
  return errors;
}

export const paylinkModule: AssuranceModule = {
  manifest: {
    name: PAYLINK,
    version: "1",
    summary: "Take a payment by a hosted link texted to the number on file.",
    provides: { factors: [], steps: ["paylink.request"], outcomes: ["payment"] },
    scopes: { grants: [], needs: { "paylink.request": "payment.request" }, classes: { "payment.request": "money" } },
    adapters: ["payments", "messages"],
  },

  validateSettings(settings: unknown): string[] {
    if (settings === undefined) return [];
    if (!isObject(settings)) return ["must be an object"];
    const errors = unknownKeys(settings, ["maxAmountMinor"]).map((k) => `${k} is not a paylink setting`);
    if (settings.maxAmountMinor !== undefined && !isIntegerIn(settings.maxAmountMinor, 1, MAX_LINK_AMOUNT_MINOR)) {
      errors.push(`maxAmountMinor must be an integer from 1 to ${MAX_LINK_AMOUNT_MINOR}`);
    }
    return errors;
  },

  requiredAdapters(): string[] {
    return ["payments", "messages"];
  },

  validateStep(step: FlowStep, ctx: StepContext): string[] {
    const errors = unknownKeys(step, ["type", "amountMinor", "currency", "amountRef", "description", "amountSource", "mode"]).map((k) => `${k} is not a field of this step`);
    const settings = ctx.settings as PaylinkSettings | undefined | null;
    errors.push(...requestErrors(step, settings?.maxAmountMinor));
    if (step.amountRef !== undefined && !ctx.adapters.has("amounts")) errors.push("an amountRef needs the amounts adapter, which the engine does not have");
    if (step.mode !== undefined) {
      if (!(PAYMENT_MODES as readonly unknown[]).includes(step.mode)) errors.push("mode must be connect or platform");
      else errors.push(`mode ${String(step.mode)} is not built yet (PAY-7)`);
    }
    return errors;
  },

  initCall(): JsonValue {
    return { payments: [], quote: null };
  },

  onUntrusted(s: JsonValue): JsonValue {
    // A confirmation heard before untrusted text entered the call no longer counts: read it back again.
    return { ...(s as unknown as PaylinkSlice), quote: null } as unknown as JsonValue;
  },

  enterStep(_step: FlowStep, s: JsonValue): JsonValue {
    return (s as unknown as PaylinkSlice).payments.length;
  },

  stepStatus(_step: FlowStep, view: StepView): StepStatus {
    const payments = (view.slice as unknown as PaylinkSlice).payments;
    if (payments.length <= (view.mark as number)) return "pending";
    const status = payments.at(-1)!.status;
    return status === "paid" ? "complete" : status === "open" ? "pending" : "failed";
  },

  receiptPart(s: JsonValue, _state: SessionState): { [key: string]: JsonValue } {
    return {
      payments: (s as unknown as PaylinkSlice).payments.map((p) => ({
        paymentId: p.paymentId,
        status: p.status,
        amountMinor: p.amountMinor,
        currency: p.currency,
        providerRef: p.linkId,
      })),
    };
  },
};

// ---- runtime -------------------------------------------------------------------------------

/** The checks every payment entry point makes: the flow's step, the scope, and the subject Badge matched. */
function requestContext(rt: EngineRuntime, record: CallRecord, input: PaymentInput | undefined): { step: PaymentInput | null; subject: SubjectRecord } {
  const step = stepOfType<PaylinkRequestStep>(record, "paylink.request");
  if (!rt.authorized(record, "payment.request")) throw new EngineError("scope_denied", "the grant does not cover payment.request");
  if (step !== null && input !== undefined) throw new EngineError("invalid_input", "the flow step sets the amount; pass no input");
  // validateConfig let the step through with a fixed amount or an amountRef, never neither.
  return { step: step as PaymentInput | null, subject: matchedSubject(record) };
}

const OUTSIDE_A_FLOW = "outside a flow, the amount (or amountRef), description and amountSource are required";

/** What an amount was read back for, so a read-back serves only the request it was made for. */
function specKey(spec: PaymentInput): string {
  const s = spec as Partial<FixedPaymentInput & ReferencedPaymentInput>;
  return JSON.stringify([s.amountMinor ?? null, s.currency ?? null, s.amountRef ?? null, s.description, s.amountSource]);
}

/** The amount request in force on an open call, checked: the flow step's, or outside a flow the host's. */
function readBackSpec(rt: EngineRuntime, record: CallRecord, input: PaymentInput | undefined, maxMinor: number | undefined): { spec: PaymentInput; subject: SubjectRecord } {
  const { step, subject } = requestContext(rt, record, input);
  if (record.state.phase !== "open") throw new EngineError("invalid_transition", `an amount is read back on an open call, not while ${record.state.phase}`);
  const spec: PaymentInput | undefined = step ?? input;
  if (spec === undefined) throw new EngineError("invalid_input", OUTSIDE_A_FLOW);
  const errors = requestErrors({ ...spec }, maxMinor);
  if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
  return { spec, subject };
}

/**
 * Builds the amount read-back the host speaks before a link is sent. The amount is the step's (or
 * the host's) fixed amount, or the one the `amounts` adapter resolves from its reference; it is
 * checked like any amount. The read-back replaces any earlier one on the call and waits for
 * `confirmPaymentAmount`. Its ledger entry carries the amount and the digest, never the reference.
 */
export async function readBackPayment(rt: EngineRuntime, callId: string, input?: PaymentInput): Promise<AmountReadBack> {
  const settings = rt.settings<PaylinkSettings>(PAYLINK) ?? {};
  const before = await rt.read(callId);
  const { spec, subject } = readBackSpec(rt, before, input, settings.maxAmountMinor);
  const fixed = spec as Partial<FixedPaymentInput & ReferencedPaymentInput>;
  let amount = { amountMinor: fixed.amountMinor!, currency: fixed.currency! };
  if (fixed.amountRef !== undefined) {
    const source = rt.adapter("amounts") as AmountSource | undefined;
    if (source === undefined) throw new EngineError("precondition_failed", "an amountRef needs the amounts adapter, which the engine does not have");
    const found = await source.resolve({
      workspaceId: rt.workspaceId,
      callId,
      source: spec.amountSource,
      reference: fixed.amountRef,
      subjectKey: subject.subjectKey,
      recordIds: [...before.state.recordIds],
    });
    if (found === null) throw new EngineError("precondition_failed", "the amount source has no amount for this reference");
    amount = { amountMinor: found.amountMinor, currency: found.currency };
    const errors = requestErrors({ ...amount, description: spec.description, amountSource: spec.amountSource }, settings.maxAmountMinor);
    if (errors.length > 0) throw new EngineError("invalid_input", `the amount source answered with a bad amount: ${errors.join("; ")}`);
  }
  const readBack = buildAmountReadBack(before.locale, { ...amount, description: spec.description.trim() });
  return rt.update(callId, (draft) => {
    // Checked again: the call can have moved on while the amount was looked up.
    readBackSpec(rt, draft.record, input, settings.maxAmountMinor);
    draft.slice<PaylinkSlice>(PAYLINK).quote = {
      spec: specKey(spec),
      amountMinor: readBack.amountMinor,
      currency: readBack.currency,
      description: readBack.description,
      amountSource: spec.amountSource,
      digest: readBack.digest,
      readAt: rt.now(),
      confirmedAt: null,
    };
    draft.emit("payment.amount_read_back", "code", { amountMinor: readBack.amountMinor, currency: readBack.currency, amountSource: spec.amountSource, digest: readBack.digest });
    return readBack;
  });
}

/**
 * The caller said yes to the amount read back. `digest` is the read-back's digest as the host got
 * it; a different one (a newer read-back, or none) is refused, so a confirmation is only ever for
 * the amount the caller heard. Confirming twice is harmless.
 */
export async function confirmPaymentAmount(rt: EngineRuntime, callId: string, input: { digest: string; confirmedBy: "voice" | "keypad" }): Promise<void> {
  rt.settings(PAYLINK);
  await rt.update(callId, (draft) => {
    requestContext(rt, draft.record, undefined);
    const quote = draft.slice<PaylinkSlice>(PAYLINK).quote;
    if (quote === null) throw new EngineError("precondition_failed", "no amount was read back on this call");
    if (!hexDigestsEqual(input.digest, quote.digest)) throw new EngineError("precondition_failed", "this is not the amount last read back; read it back again");
    if (quote.confirmedAt !== null) return;
    quote.confirmedAt = rt.now();
    draft.emit("payment.amount_confirmed", "caller", { digest: quote.digest, confirmedBy: input.confirmedBy });
  });
}

/**
 * The amount a new link is for. A read-back on the call must be confirmed and match the request;
 * an amount from the AmountSource is never sent without one.
 */
function confirmedAmount(quote: AmountQuote | null, spec: PaymentInput | undefined): FixedPaymentInput {
  if (quote !== null) {
    if (spec !== undefined && specKey(spec) !== quote.spec) throw new EngineError("precondition_failed", "this request is not the amount read back; read it back again");
    if (quote.confirmedAt === null) throw new EngineError("precondition_failed", "the caller has not confirmed the amount read back");
    return { amountMinor: quote.amountMinor, currency: quote.currency, description: quote.description, amountSource: quote.amountSource };
  }
  if (spec === undefined) throw new EngineError("invalid_input", OUTSIDE_A_FLOW);
  if ((spec as Partial<ReferencedPaymentInput>).amountRef !== undefined) {
    throw new EngineError("precondition_failed", "an amount from the amount source is read back and confirmed before the link is sent");
  }
  return spec as FixedPaymentInput;
}

/**
 * Texts a hosted payment link to the number on file. In a flow, the step sets the amount and
 * `input` must be left out; outside one, the host's code passes it (`amountSource` says where from).
 * When an amount was read back on the call, the caller must have confirmed it and the link is for
 * exactly that amount; an `amountRef` always needs a confirmed read-back.
 *
 * The request is reserved first. If creating or texting the link fails, the request stays open
 * (a provider can create a link and still fail to answer), and calling `requestPayment` again
 * resumes it with the same payment id and idempotency keys: the provider returns the same link,
 * and the text is sent again. It settles only by the provider's outcome.
 */
export async function requestPayment(rt: EngineRuntime, callId: string, input?: PaymentInput): Promise<{ paymentId: string; status: PaymentStatus }> {
  const settings = rt.settings<PaylinkSettings>(PAYLINK) ?? {};
  const reserved = await rt.update(callId, (draft) => {
    const { step, subject } = requestContext(rt, draft.record, input);
    const where = { phone: subject.phoneOnFile, locale: draft.record.locale };
    const slice = draft.slice<PaylinkSlice>(PAYLINK);
    const last = slice.payments.at(-1);
    if (draft.record.state.phase === "paying" && last !== undefined && last.status === "open" && last.textedAt === null) {
      const fixed = input as Partial<FixedPaymentInput> | undefined;
      if (fixed !== undefined && (fixed.amountMinor !== last.amountMinor || fixed.currency !== last.currency)) {
        throw new EngineError("invalid_input", "a payment link is still being sent on this call; resume it with the same amount, or none");
      }
      return { request: last, ...where };
    }
    const chosen = confirmedAmount(slice.quote, step ?? input);
    const errors = requestErrors({ ...chosen }, settings.maxAmountMinor);
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    slice.quote = null;
    const paymentId = rt.ids.next("pay");
    draft.apply({ type: "payment_requested", paymentId });
    const request: PaymentRequest = {
      paymentId,
      callId,
      amountMinor: chosen.amountMinor,
      currency: chosen.currency,
      description: chosen.description.trim(),
      amountSource: chosen.amountSource,
      linkId: "",
      status: "open",
      requestedAt: rt.now(),
      settledAt: null,
      textedAt: null,
    };
    draft.slice<PaylinkSlice>(PAYLINK).payments.push(request);
    return { request, ...where };
  });
  const { request } = reserved;
  const link = await rt.adapter("payments").createLink({
    callId,
    paymentId: request.paymentId,
    amountMinor: request.amountMinor,
    currency: request.currency,
    description: request.description,
    idempotencyKey: rt.idempotencyKey(callId, request.paymentId, "link"),
  });
  await rt.update(callId, (draft) => {
    find(draft, request.paymentId).linkId = link.linkId;
  });
  await rt.bindRef(`payment:${link.linkId}`, callId);
  await rt.adapter("messages").sendText({
    to: reserved.phone,
    body: paymentText(reserved.locale, link.url, request.amountMinor, request.currency),
    purpose: "payment_link",
    idempotencyKey: rt.idempotencyKey(callId, request.paymentId, "text"),
  });
  return rt.update(callId, (draft) => {
    const sent = find(draft, request.paymentId);
    // Two resumes of one request can both get here: the first records the delivery, once.
    if (sent.textedAt !== null) return { paymentId: request.paymentId, status: sent.status };
    sent.textedAt = rt.now();
    draft.emit("payment.link_sent", "code", {
      paymentId: request.paymentId,
      linkId: link.linkId,
      amountMinor: request.amountMinor,
      currency: request.currency,
      amountSource: request.amountSource,
    });
    return { paymentId: request.paymentId, status: sent.status };
  });
}

function find(draft: CallDraft, paymentId: string): PaymentRequest {
  return draft.slice<PaylinkSlice>(PAYLINK).payments.find((p) => p.paymentId === paymentId)!;
}

/** Settles an open request. The session leaves `paying` only if it is still there (a call can end first). */
function settle(rt: EngineRuntime, draft: CallDraft, paymentId: string, status: Exclude<PaymentStatus, "open">): void {
  const request = find(draft, paymentId);
  request.status = status;
  request.settledAt = rt.now();
  if (draft.record.state.phase === "paying") draft.apply({ type: "payment_settled", paymentId });
  draft.emit("payment.settled", "system", { paymentId, status });
}

/** The payment provider's verified webhook outcome. "Paid" only when the provider says paid; each request settles once. */
export async function applyPaymentOutcome(rt: EngineRuntime, outcome: PaymentOutcome): Promise<{ applied: false } | { applied: true; callId: string; status: PaymentStatus }> {
  const callId = await rt.resolveRef(`payment:${outcome.linkId}`);
  if (callId === null) return { applied: false };
  return rt.update(callId, (draft) => {
    const request = draft.slice<PaylinkSlice>(PAYLINK).payments.find((p) => p.linkId === outcome.linkId)!;
    const status = settlementFor(outcome);
    if (request.status !== "open" || status === null) return { applied: false } as const;
    settle(rt, draft, request.paymentId, status);
    return { applied: true, callId, status } as const;
  });
}

function paymentText(locale: Locale, url: string, amountMinor: number, currency: string): string {
  const amount = formatAmount(locale, amountMinor, currency);
  return locale === "fr" ? `Votre lien de paiement sécurisé pour ${amount} : ${url}` : `Your secure payment link for ${amount}: ${url}`;
}
