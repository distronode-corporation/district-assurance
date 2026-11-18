// Paylink (pay): payment by a hosted link texted to the number on file. The engine never sees a
// card. In a flow, the `paylink.request` step carries the amount, the payment mode, the link's
// life and the payment methods, so they are checked when the config is saved; outside a flow the
// host's code passes the amount and Paylink's settings give the rest. Either way none of it comes
// from the model.
//
// Two modes, chosen per step: `connect` takes the money on the business's own account at the
// provider (the business is the merchant), `platform` on the platform's own account (the platform
// is the merchant). One adapter shape serves both: the request carries the mode and, in connect
// mode, the connected account.
//
// The link is reserved in one write (the call enters `paying`, so a second request is refused
// everywhere), created and texted, then committed. Once texted it lives `linkLifeMinutes` (15 by
// default): the engine expires it itself at that deadline (`expirePaymentLinks`), because a
// provider's shortest link life can be longer than a call. A failed create leaves the request open
// to resume; once a link exists, only the provider's outcome or the engine's deadline settles it.
import type { InstantPaymentMethod, PaymentMode } from "../core/adapters.ts";
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { CallDraft, EngineRuntime, Locale } from "../core/runtime.ts";
import type { SessionState } from "../core/session.ts";
import { isIntegerIn, isObject, unknownKeys } from "../core/shape.ts";
import { matchedSubject } from "../verify/badge.ts";
import {
  DEFAULT_LINK_LIFE_MINUTES,
  INSTANT_PAYMENT_METHODS,
  MAX_LINK_AMOUNT_MINOR,
  MAX_LINK_LIFE_MINUTES,
  MIN_LINK_LIFE_MINUTES,
  PAYMENT_MODES,
  outcomeAccountMatches,
  paymentMethodErrors,
  settlementFor,
  validateAmount,
  type AmountSource,
  type PaymentOutcome,
  type PaymentRequest,
  type PaymentStatus,
} from "./payment.ts";


export const PAYLINK = "paylink";

const AMOUNT_SOURCES: readonly AmountSource[] = ["intake_record", "business_endpoint", "price_list"];

/** A provider's account id: what a host's adapter passes on (for Stripe, `acct_...`). */
const ACCOUNT_ID = /^[A-Za-z0-9_-]{1,255}$/;

export interface PaylinkSettings {
  /** Upper bound per link, in minor units. At most 1,000,000. */
  maxAmountMinor?: number;
  /** The mode for a step that names none, and for payments outside a flow. Default `platform`. */
  mode?: PaymentMode;
  /** The business's account at the provider, which `connect` mode needs. */
  connectedAccountId?: string;
  /** The default link life, in minutes, from 5 to 60. Default 15. */
  linkLifeMinutes?: number;
  /** The default payment methods: instant ones only. Default card, Apple Pay, Google Pay and Link. */
  paymentMethods?: InstantPaymentMethod[];
}

export interface PaylinkRequestStep extends FlowStep {
  type: "paylink.request";
  amountMinor: number;
  currency: string;
  description: string;
  amountSource: AmountSource;
  mode?: PaymentMode;
  linkLifeMinutes?: number;
  paymentMethods?: InstantPaymentMethod[];
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

/** How a payment is taken: from the step, then the settings, then the defaults. */
interface PaymentTerms {
  mode: PaymentMode;
  connectedAccountId: string | null;
  linkLifeMinutes: number;
  paymentMethods: InstantPaymentMethod[];
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

/** Problems with the fields a step and the settings share: mode, link life and payment methods. */
function termErrors(value: Record<string, unknown>): string[] {
  const errors: string[] = [];
  if (value.mode !== undefined && !(PAYMENT_MODES as readonly unknown[]).includes(value.mode)) errors.push("mode must be connect or platform");
  if (value.linkLifeMinutes !== undefined && !isIntegerIn(value.linkLifeMinutes, MIN_LINK_LIFE_MINUTES, MAX_LINK_LIFE_MINUTES)) {
    errors.push(`linkLifeMinutes must be an integer from ${MIN_LINK_LIFE_MINUTES} to ${MAX_LINK_LIFE_MINUTES}`);
  }
  if (value.paymentMethods !== undefined) errors.push(...paymentMethodErrors(value.paymentMethods));
  return errors;
}

function termsFor(settings: PaylinkSettings, step: PaylinkRequestStep | null): PaymentTerms {
  const mode = step?.mode ?? settings.mode ?? "platform";
  return {
    mode,
    connectedAccountId: mode === "connect" ? (settings.connectedAccountId ?? null) : null,
    linkLifeMinutes: step?.linkLifeMinutes ?? settings.linkLifeMinutes ?? DEFAULT_LINK_LIFE_MINUTES,
    paymentMethods: [...(step?.paymentMethods ?? settings.paymentMethods ?? INSTANT_PAYMENT_METHODS)],
  };
}

const CONNECT_NEEDS_ACCOUNT = "connect mode needs connectedAccountId in the paylink settings";

export const paylinkModule: AssuranceModule = {
  manifest: {
    name: PAYLINK,
    version: "2",
    summary: "Take a payment by a hosted link texted to the number on file, on the business's account or the platform's.",
    provides: { factors: [], steps: ["paylink.request"], outcomes: ["payment"] },
    scopes: { grants: [], needs: { "paylink.request": "payment.request" }, classes: { "payment.request": "money" } },
    adapters: ["payments", "messages"],
  },

  validateSettings(settings: unknown): string[] {
    if (settings === undefined) return [];
    if (!isObject(settings)) return ["must be an object"];
    const errors = unknownKeys(settings, ["maxAmountMinor", "mode", "connectedAccountId", "linkLifeMinutes", "paymentMethods"]).map((k) => `${k} is not a paylink setting`);
    if (settings.maxAmountMinor !== undefined && !isIntegerIn(settings.maxAmountMinor, 1, MAX_LINK_AMOUNT_MINOR)) {
      errors.push(`maxAmountMinor must be an integer from 1 to ${MAX_LINK_AMOUNT_MINOR}`);
    }
    errors.push(...termErrors(settings));
    const account = settings.connectedAccountId;
    if (account !== undefined && (typeof account !== "string" || !ACCOUNT_ID.test(account))) {
      errors.push("connectedAccountId must be 1 to 255 letters, digits, hyphens or underscores");
    } else if (settings.mode === "connect" && account === undefined) {
      errors.push(CONNECT_NEEDS_ACCOUNT);
    }
    return errors;
  },

  requiredAdapters(): string[] {
    return ["payments", "messages"];
  },

  validateStep(step: FlowStep, ctx: StepContext): string[] {
    const errors = unknownKeys(step, ["type", "amountMinor", "currency", "description", "amountSource", "mode", "linkLifeMinutes", "paymentMethods"]).map(
      (k) => `${k} is not a field of this step`,
    );
    const settings = ctx.settings as PaylinkSettings | undefined | null;
    errors.push(...requestErrors(step, settings?.maxAmountMinor));
    errors.push(...termErrors(step));
    // Settings that did not validate are reported on their own; the cross-check needs good ones.
    if (settings !== null && (step.mode ?? settings?.mode) === "connect" && settings?.connectedAccountId === undefined) errors.push(CONNECT_NEEDS_ACCOUNT);
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
        mode: p.mode,
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
 * and the text is sent again. Once texted, `expiresAt` is the engine's deadline: the host calls
 * `expirePaymentLinks` at that time (or later), which expires the link if it is still open.
 */
export async function requestPayment(
  rt: EngineRuntime,
  callId: string,
  input?: PaymentInput,
): Promise<{ paymentId: string; status: PaymentStatus; expiresAt: string | null }> {
  const settings = rt.settings<PaylinkSettings | undefined>(PAYLINK) ?? {};
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
    const terms = termsFor(settings, step);
    // The config was checked when saved; a call keeps its steps while the settings can change under it.
    if (terms.mode === "connect" && terms.connectedAccountId === null) errors.push(CONNECT_NEEDS_ACCOUNT);
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
      ...terms,
      expiresAt: null,
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
    mode: request.mode,
    ...(request.connectedAccountId === null ? {} : { connectedAccountId: request.connectedAccountId }),
    paymentMethods: request.paymentMethods,
    expiresAt: providerExpiry(request),
    // The mode is part of the key, so a request resumed under another mode can never replay the first.
    idempotencyKey: rt.idempotencyKey(callId, request.paymentId, "link", request.mode),
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
    if (sent.textedAt !== null) return { paymentId: request.paymentId, status: sent.status, expiresAt: sent.expiresAt };
    sent.textedAt = rt.now();
    // The link life counts from the text, but never past what the provider was asked for when the
    // link was created, so the engine never promises a deadline the link itself would not reach.
    sent.expiresAt = new Date(Math.min(Date.parse(deadline(sent.textedAt, sent.linkLifeMinutes)), Date.parse(providerExpiry(sent)))).toISOString();
    draft.emit("payment.link_sent", "code", {
      paymentId: request.paymentId,
      linkId: link.linkId,
      amountMinor: request.amountMinor,
      currency: request.currency,
      amountSource: request.amountSource,
      mode: request.mode,
      expiresAt: sent.expiresAt,
    });
    return { paymentId: request.paymentId, status: sent.status, expiresAt: sent.expiresAt };
  });
}

/**
 * What the provider is asked for: twice the link life from the request, so a text that goes out
 * late (a resumed request) still gets its full life after it is sent. The engine's own deadline,
 * the text plus the life, is what closes the link.
 */
function providerExpiry(request: PaymentRequest): string {
  return deadline(request.requestedAt, 2 * request.linkLifeMinutes);
}

function deadline(from: string, minutes: number): string {
  return new Date(Date.parse(from) + minutes * 60_000).toISOString();
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

/**
 * The payment provider's verified webhook outcome. "Paid" only when the provider says paid; each
 * request settles once. An outcome from another account than the payment's (a connect-mode
 * payment's event without its connected account, or a platform payment's event from a connected
 * account) is ignored and written to the ledger.
 */
export async function applyPaymentOutcome(rt: EngineRuntime, outcome: PaymentOutcome): Promise<{ applied: false } | { applied: true; callId: string; status: PaymentStatus }> {
  const callId = await rt.resolveRef(`payment:${outcome.linkId}`);
  if (callId === null) return { applied: false };
  return rt.update(callId, (draft) => {
    const request = draft.slice<PaylinkSlice>(PAYLINK).payments.find((p) => p.linkId === outcome.linkId)!;
    if (!outcomeAccountMatches(request, outcome)) {
      draft.emit("payment.outcome_ignored", "system", { paymentId: request.paymentId, reason: "account" });
      return { applied: false } as const;
    }
    const status = settlementFor(outcome);
    if (request.status !== "open" || status === null) return { applied: false } as const;
    settle(rt, draft, request.paymentId, status);
    return { applied: true, callId, status } as const;
  });
}

/**
 * Expires every texted link of a call that is still open at or after its deadline, at the
 * provider first. The host calls it at the `expiresAt` that `requestPayment` returned, or later
 * (a timer, a sweep); calling it early or twice does nothing. A link the provider says is no
 * longer open is left for its webhook to settle (it may have been paid at the last moment).
 */
export async function expirePaymentLinks(rt: EngineRuntime, callId: string): Promise<{ expired: string[] }> {
  const record = await rt.read(callId);
  const slice = record.modules[PAYLINK] as unknown as PaylinkSlice | undefined;
  if (slice === undefined) throw new EngineError("module_disabled", `${PAYLINK} was off when this call started`);
  const now = rt.clock.now().getTime();
  const due = slice.payments.filter((p) => p.status === "open" && p.expiresAt !== null && Date.parse(p.expiresAt) <= now);
  const expired: string[] = [];
  for (const payment of due) {
    const answer = await rt.adapter("payments").expireLink({
      linkId: payment.linkId,
      mode: payment.mode,
      ...(payment.connectedAccountId === null ? {} : { connectedAccountId: payment.connectedAccountId }),
      idempotencyKey: rt.idempotencyKey(callId, payment.paymentId, "expire", payment.mode),
    });
    const settled = await rt.update(callId, (draft) => {
      const request = find(draft, payment.paymentId);
      if (request.status !== "open") return false;
      draft.emit("payment.link_expired", "code", { paymentId: payment.paymentId, provider: answer.state });
      if (answer.state !== "expired") return false;
      settle(rt, draft, payment.paymentId, "expired");
      return true;
    });
    if (settled) expired.push(payment.paymentId);
  }
  return { expired };
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
