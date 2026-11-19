// Paylink (pay): payment by a hosted link texted to the number on file. The engine never sees a
// card. In a flow, the `paylink.request` step carries the amount, so it is checked when the config
// is saved; outside a flow the host's code passes it. Either way it never comes from the model.
//
// The link is reserved in one write (the call enters `paying`, so a second request is refused
// everywhere), created and texted, then committed. A failed create settles it as failed; once a
// link exists, only the provider settles it.
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { CallDraft, EngineRuntime, Locale } from "../core/runtime.ts";
import type { SessionState } from "../core/session.ts";
import { isIntegerIn, isObject, unknownKeys } from "../core/shape.ts";
import { matchedSubject } from "../verify/badge.ts";
import { MAX_LINK_AMOUNT_MINOR, settlementFor, validateAmount, type AmountSource, type PaymentOutcome, type PaymentRequest, type PaymentStatus } from "./payment.ts";

export const PAYLINK = "paylink";

/** Whose account takes the money. Chosen per flow step; built in PAY-7, refused by the validator until then. */
export const PAYMENT_MODES = ["connect", "platform"] as const;
export type PaymentMode = (typeof PAYMENT_MODES)[number];

const AMOUNT_SOURCES: readonly AmountSource[] = ["intake_record", "business_endpoint", "price_list"];

export interface PaylinkSettings {
  /** Upper bound per link, in minor units. At most 1,000,000. */
  maxAmountMinor?: number;
}

export interface PaylinkRequestStep extends FlowStep {
  type: "paylink.request";
  amountMinor: number;
  currency: string;
  description: string;
  amountSource: AmountSource;
  /** Planned (PAY-7). */
  mode?: PaymentMode;
}

export interface PaymentInput {
  amountMinor: number;
  currency: string;
  description: string;
  amountSource: AmountSource;
}

export interface PaylinkSlice {
  payments: PaymentRequest[];
}

function requestErrors(input: Record<string, unknown>, maxMinor: number | undefined): string[] {
  const amount = input.amountMinor;
  const currency = input.currency;
  const errors =
    typeof amount === "number" && typeof currency === "string"
      ? validateAmount(amount, currency, maxMinor)
      : ["amountMinor and currency are required"];
  const description = input.description;
  if (typeof description !== "string" || description.trim() === "" || description.trim().length > 200) errors.push("description must be 1 to 200 characters");
  if (!AMOUNT_SOURCES.includes(input.amountSource as AmountSource)) errors.push(`amountSource must be one of ${AMOUNT_SOURCES.join(", ")}`);
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
    const errors = unknownKeys(step, ["type", "amountMinor", "currency", "description", "amountSource", "mode"]).map((k) => `${k} is not a field of this step`);
    const settings = ctx.settings as PaylinkSettings | undefined | null;
    errors.push(...requestErrors(step, settings?.maxAmountMinor));
    if (step.mode !== undefined) {
      if (!(PAYMENT_MODES as readonly unknown[]).includes(step.mode)) errors.push("mode must be connect or platform");
      else errors.push(`mode ${String(step.mode)} is not built yet (PAY-7)`);
    }
    return errors;
  },

  initCall(): JsonValue {
    return { payments: [] };
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

/**
 * Texts a hosted payment link to the number on file. In a flow, the step sets the amount and
 * `input` must be left out; outside one, the host's code passes it (`amountSource` says where from).
 *
 * The request is reserved first. If creating or texting the link fails, the request stays open
 * (a provider can create a link and still fail to answer), and calling `requestPayment` again
 * resumes it with the same payment id and idempotency keys: the provider returns the same link,
 * and the text is sent again. It settles only by the provider's outcome.
 */
export async function requestPayment(rt: EngineRuntime, callId: string, input?: PaymentInput): Promise<{ paymentId: string; status: PaymentStatus }> {
  const settings = rt.settings<PaylinkSettings>(PAYLINK) ?? {};
  const reserved = await rt.update(callId, (draft) => {
    const step = stepOfType<PaylinkRequestStep>(draft.record, "paylink.request");
    if (!rt.authorized(draft.record, "payment.request")) throw new EngineError("scope_denied", "the grant does not cover payment.request");
    if (step !== null && input !== undefined) throw new EngineError("invalid_input", "the flow step sets the amount; pass no input");
    const subject = matchedSubject(draft.record);
    const where = { phone: subject.phoneOnFile, locale: draft.record.locale };
    const last = draft.slice<PaylinkSlice>(PAYLINK).payments.at(-1);
    if (draft.record.state.phase === "paying" && last !== undefined && last.status === "open" && last.textedAt === null) {
      if (input !== undefined && (input.amountMinor !== last.amountMinor || input.currency !== last.currency)) {
        throw new EngineError("invalid_input", "a payment link is still being sent on this call; resume it with the same amount");
      }
      return { request: last, ...where };
    }
    const chosen: PaymentInput | undefined = step ?? input;
    if (chosen === undefined) throw new EngineError("invalid_input", "outside a flow, the amount, currency, description and amountSource are required");
    const errors = requestErrors({ ...chosen }, settings.maxAmountMinor);
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
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

/**
 * Where each locale's amounts are formatted: English and French as in Canada, Spanish as in the
 * United States (`$1,500.50`, a period before the cents).
 */
export const AMOUNT_REGION: Record<Locale, string> = { en: "en-CA", fr: "fr-CA", es: "es-US" };

/** Formats an amount in minor units with the currency's own number of decimals. */
export function formatAmount(locale: Locale, amountMinor: number, currency: string): string {
  const format = new Intl.NumberFormat(AMOUNT_REGION[locale], { style: "currency", currency: currency.toUpperCase() });
  const digits = format.resolvedOptions().maximumFractionDigits as number;
  return format.format(amountMinor / 10 ** digits);
}

/** The payment link text, in every locale (SPEC.md section 16). */
export const PAYMENT_TEXT: Record<Locale, (amount: string, url: string) => string> = {
  en: (amount, url) => `Your secure payment link for ${amount}: ${url}`,
  fr: (amount, url) => `Votre lien de paiement sécurisé pour ${amount} : ${url}`,
  es: (amount, url) => `Su enlace de pago seguro por ${amount}: ${url}`,
};

function paymentText(locale: Locale, url: string, amountMinor: number, currency: string): string {
  return PAYMENT_TEXT[locale](formatAmount(locale, amountMinor, currency), url);
}
