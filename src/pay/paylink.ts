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
// to resume; once a link exists, only the provider's outcome, the engine's deadline, a cancel or
// the end of the call settles it. Money that moves after the engine closed a link is still
// recorded as paid, and flagged in the ledger.
import type { InstantPaymentMethod, PaymentLinkCapabilities, PaymentLinkClose, PaymentMode } from "../core/adapters.ts";
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { CallDraft, CallRecord, EngineRuntime, Locale } from "../core/runtime.ts";
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

/** How long a process that is texting a link holds it against a concurrent expiry. */
const SEND_LEASE_MS = 60_000;

const CONNECT_NEEDS_ACCOUNT = "connect mode needs connectedAccountId in the paylink settings";

function isCapabilities(value: unknown): value is PaymentLinkCapabilities {
  if (!isObject(value)) return false;
  const { modes, minLinkMinutes: min, maxLinkMinutes: max } = value;
  return Array.isArray(modes) && modes.every((m) => (PAYMENT_MODES as readonly unknown[]).includes(m)) && isIntegerIn(min, 0, 100_000) && isIntegerIn(max, 1, 100_000) && min <= max;
}

/** Problems between a mode and a link life and what the payments adapter declares it can do. */
function adapterErrors(caps: PaymentLinkCapabilities, mode: PaymentMode, lifeMinutes: number): string[] {
  const errors: string[] = [];
  if (!caps.modes.includes(mode)) errors.push(`the payments adapter does not take ${mode} payments (it takes: ${caps.modes.join(", ") || "none"})`);
  if (lifeMinutes > caps.maxLinkMinutes) errors.push(`linkLifeMinutes ${lifeMinutes} is longer than the payments adapter keeps a link (${caps.maxLinkMinutes} minutes)`);
  return errors;
}

/**
 * What the provider is asked for: twice the link life from the request, so a text that goes out
 * late (a resumed request) still gets its full life after it is sent, kept within what the adapter
 * declares (Stripe Checkout: 30 minutes to 24 hours), so the provider never refuses the time.
 */
function providerExpiry(requestedAt: string, lifeMinutes: number, caps: PaymentLinkCapabilities): string {
  // A margin over the provider's minimum, so the create that follows the reservation is never under it.
  const minutes = Math.min(Math.max(2 * lifeMinutes, caps.minLinkMinutes + MIN_LINK_LIFE_MINUTES), caps.maxLinkMinutes);
  return deadline(requestedAt, minutes);
}

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
    } else if (account !== undefined && settings.mode === undefined) {
      // A business account with the default mode would quietly take the money on the platform's.
      errors.push("connectedAccountId needs an explicit mode: connect, or platform with connect chosen per step");
    }
    return errors;
  },

  checkAdapters(settings: unknown, capabilities: Readonly<Record<string, unknown>>): string[] {
    const s = (settings ?? {}) as PaylinkSettings;
    // Known to be absent (an engine's adapter declared nothing): refused. Not known at all: skipped.
    if (Object.hasOwn(capabilities, "payments") && capabilities.payments === undefined) {
      return ["the payments adapter declares no capabilities ({ modes, minLinkMinutes, maxLinkMinutes })"];
    }
    const caps = capabilities.payments;
    if (caps === undefined) return [];
    if (!isCapabilities(caps)) return ["the payments adapter's capabilities must be { modes, minLinkMinutes, maxLinkMinutes }"];
    // The provider is asked for at least its minimum plus 5 minutes, so a narrower range could never create a link.
    if (caps.maxLinkMinutes < caps.minLinkMinutes + MIN_LINK_LIFE_MINUTES) {
      return [`the payments adapter's maxLinkMinutes must be at least its minLinkMinutes plus ${MIN_LINK_LIFE_MINUTES}`];
    }
    return adapterErrors(caps, s.mode ?? "platform", s.linkLifeMinutes ?? DEFAULT_LINK_LIFE_MINUTES);
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
    const caps = ctx.capabilities.payments;
    if (settings !== null && isCapabilities(caps) && (PAYMENT_MODES as readonly unknown[]).includes(step.mode ?? settings?.mode ?? "platform")) {
      const life = isIntegerIn(step.linkLifeMinutes, MIN_LINK_LIFE_MINUTES, MAX_LINK_LIFE_MINUTES) ? step.linkLifeMinutes : (settings?.linkLifeMinutes ?? DEFAULT_LINK_LIFE_MINUTES);
      errors.push(...adapterErrors(caps, (step.mode ?? settings?.mode ?? "platform") as PaymentMode, life));
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
    const requestedAt = rt.now();
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
      requestedAt,
      settledAt: null,
      textedAt: null,
      ...terms,
      expiresAt: null,
      providerExpiresAt: providerExpiry(requestedAt, terms.linkLifeMinutes, rt.adapter("payments").capabilities),
      sendingSince: null,
    };
    draft.slice<PaylinkSlice>(PAYLINK).payments.push(request);
    return { request, ...where };
  });
  const { request } = reserved;
  // A link not known to exist yet must be created with at least the provider's shortest life left,
  // or the provider refuses it, every retry included. Too late for that: the request is expired
  // (it was never texted, so nobody holds its link) and a new one may follow.
  const caps = rt.adapter("payments").capabilities;
  // One minute over the minimum, for the provider's own latency on the create.
  if (request.linkId === "" && Date.parse(request.providerExpiresAt) - rt.clock.now().getTime() < (caps.minLinkMinutes + 1) * 60_000) {
    await rt.update(callId, (draft) => {
      const current = find(draft, request.paymentId);
      if (current.status !== "open") return;
      // Checked again in this write: another process may have created the link meanwhile, and only
      // it may decide about a link that exists (it expires it at the provider if it is too late).
      if (current.linkId !== "") throw new EngineError("precondition_failed", "another process created this payment link meanwhile");
      draft.emit("payment.link_expired", "code", { paymentId: request.paymentId, provider: "not_created", reason: "not_created_in_time" });
      settle(rt, draft, request.paymentId, "expired");
    });
    throw new EngineError("precondition_failed", "the payment link could not be created in time and the request was expired; request a new payment");
  }
  const link = await rt.adapter("payments").createLink({
    callId,
    paymentId: request.paymentId,
    amountMinor: request.amountMinor,
    currency: request.currency,
    description: request.description,
    mode: request.mode,
    ...(request.connectedAccountId === null ? {} : { connectedAccountId: request.connectedAccountId }),
    paymentMethods: request.paymentMethods,
    expiresAt: request.providerExpiresAt,
    // The mode is part of the key, so a request resumed under another mode can never replay the first.
    idempotencyKey: rt.idempotencyKey(callId, request.paymentId, "link", request.mode),
  });
  // A text that goes out this late would carry a link with less than the shortest life left, or
  // one already dead: the request is expired instead (at the provider too), and never sent.
  // The process that will text it holds a short lease, so a concurrent resume never expires the
  // link while it is being sent; once the lease lapses (that sender stopped), it may.
  let claimedAt = "";
  const claim = await rt.update(callId, (draft): "sent" | "claimed" | "late" | "settled" => {
    const pending = find(draft, request.paymentId);
    pending.linkId = link.linkId;
    if (pending.textedAt !== null) return "sent";
    // Another process settled the request while this one created the link (it took too long), or
    // the call ended meanwhile (its links are being closed): the link is live at the provider but
    // must never be texted.
    if (pending.status !== "open" || draft.record.state.phase === "ended") return "settled";
    const now = rt.clock.now().getTime();
    const leased = pending.sendingSince !== null && now - Date.parse(pending.sendingSince) < SEND_LEASE_MS;
    if (Date.parse(request.providerExpiresAt) - now >= MIN_LINK_LIFE_MINUTES * 60_000) {
      claimedAt = rt.now();
      pending.sendingSince = claimedAt;
      return "claimed";
    }
    if (leased) throw new EngineError("precondition_failed", "another process is texting this payment link");
    return "late";
  });
  await rt.bindRef(paymentRef(request, link.linkId), callId);
  // Checked again right before the text: binding the reference can take time too.
  const tooLate = claim === "late" || (claim === "claimed" && Date.parse(request.providerExpiresAt) - rt.clock.now().getTime() < MIN_LINK_LIFE_MINUTES * 60_000);
  if (claim === "settled") {
    await expireAtProvider(rt, callId, request, link.linkId);
    throw new EngineError("precondition_failed", "the payment request was closed while its link was created; the link was expired and never texted");
  }
  if (tooLate) {
    const answer = await expireAtProvider(rt, callId, request, link.linkId);
    await rt.update(callId, (draft) => {
      if (find(draft, request.paymentId).status !== "open") return;
      draft.emit("payment.link_expired", "code", { paymentId: request.paymentId, provider: answer.state, reason: "not_sent_in_time" });
      // Only an expiry the provider confirms settles it; a link no longer open waits for its webhook.
      if (answer.state === "expired") settle(rt, draft, request.paymentId, "expired");
    });
    throw new EngineError("precondition_failed", "the payment link could not be texted in time and was expired; request a new payment");
  }
  if (claim === "claimed") {
    // Binding the reference can stall past the lease, and then a cancel or the end of the call may
    // have gone ahead (and failed to expire the link at the provider). So the claim is checked
    // again, and renewed, in a write right before the text: a request closed, a call ended, or a
    // lease another sender took since is never texted from here.
    const still = await rt.update(callId, (draft): "ok" | "closed" | "taken" => {
      const pending = find(draft, request.paymentId);
      if (pending.status !== "open" || draft.record.state.phase === "ended") return "closed";
      if (pending.textedAt !== null || pending.sendingSince !== claimedAt) return "taken";
      claimedAt = rt.now();
      pending.sendingSince = claimedAt;
      return "ok";
    });
    if (still === "closed") {
      await expireAtProvider(rt, callId, request, link.linkId);
      throw new EngineError("precondition_failed", "the payment request was closed while its link was being sent; the link was expired and never texted");
    }
    if (still === "taken") throw new EngineError("precondition_failed", "another process took over texting this payment link");
  }
  await rt.adapter("messages").sendText({
    to: reserved.phone,
    body: paymentText(reserved.locale, link.url, request.amountMinor, request.currency),
    purpose: "payment_link",
    idempotencyKey: rt.idempotencyKey(callId, request.paymentId, "text"),
  });
  return rt.update(callId, (draft) => {
    const sent = find(draft, request.paymentId);
    // Two resumes of one request can both get here: the first records the delivery, once. A request
    // the engine closed meanwhile (a cancel, or the call ended, after this sender's lease lapsed) had
    // its link expired at the provider first, so the text carried a dead link: nothing is recorded,
    // so no entry follows the close or the call's receipt.
    const closed = sent.status === "expired" || draft.record.state.phase === "ended";
    if (sent.textedAt !== null || closed) return { paymentId: request.paymentId, status: sent.status, expiresAt: sent.expiresAt };
    sent.textedAt = rt.now();
    // The link life counts from the text, but never past what the provider was asked for when the
    // link was created, so the engine never promises a deadline the link itself would not reach.
    sent.expiresAt = new Date(Math.min(Date.parse(deadline(sent.textedAt, sent.linkLifeMinutes)), Date.parse(sent.providerExpiresAt))).toISOString();
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

/** The session store reference a payment link is bound under: per connected account in connect mode. */
function paymentRef(payment: Pick<PaymentRequest, "connectedAccountId">, linkId: string): string {
  return payment.connectedAccountId === null ? `payment:${linkId}` : `payment:${JSON.stringify([payment.connectedAccountId, linkId])}`;
}

/** Asks the provider to expire a link, on the account the payment was taken on. */
function expireAtProvider(rt: EngineRuntime, callId: string, payment: PaymentRequest, linkId: string): Promise<{ state: "expired" | "not_open" }> {
  return rt.adapter("payments").expireLink(closeInput(rt, callId, payment, linkId, "expire"));
}

/** The request to close a payment's link at the provider, on its account. The operation and the mode are part of the key. */
function closeInput(rt: EngineRuntime, callId: string, payment: PaymentRequest, linkId: string, operation: "expire" | "cancel"): PaymentLinkClose {
  return {
    linkId,
    mode: payment.mode,
    ...(payment.connectedAccountId === null ? {} : { connectedAccountId: payment.connectedAccountId }),
    idempotencyKey: rt.idempotencyKey(callId, payment.paymentId, operation, payment.mode),
  };
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
 *
 * The one exception to settling once: a payment the engine closed (cancelled, its call ended, its
 * deadline came) can still be paid at the provider, by a caller already on the page. The money
 * moved, so it is recorded as paid, flagged `late` in the ledger. The session does not move.
 */
export async function applyPaymentOutcome(rt: EngineRuntime, outcome: PaymentOutcome): Promise<{ applied: false } | { applied: true; callId: string; status: PaymentStatus }> {
  // A connect-mode payment is bound under its account, so two accounts' link ids never collide. A
  // platform payment's binding is tried last, so a connected account's event for one is seen (and
  // written down as ignored) rather than lost.
  const account = outcome.account ?? null;
  const callId = (account === null ? null : await rt.resolveRef(paymentRef({ connectedAccountId: account }, outcome.linkId))) ?? (await rt.resolveRef(paymentRef({ connectedAccountId: null }, outcome.linkId)));
  if (callId === null) return { applied: false };
  return rt.update(callId, (draft) => {
    const payments = draft.slice<PaylinkSlice>(PAYLINK).payments.filter((p) => p.linkId === outcome.linkId);
    const request = payments.find((p) => p.connectedAccountId === account) ?? payments[0]!;
    if (!outcomeAccountMatches(request, outcome)) {
      draft.emit("payment.outcome_ignored", "system", { paymentId: request.paymentId, reason: "account" });
      return { applied: false } as const;
    }
    const status = settlementFor(outcome);
    // Money that moved is always recorded: a payment the engine had expired (its own deadline, or a
    // race with a slow create) and the provider then reports paid becomes paid, flagged as late.
    if (request.status === "expired" && status === "paid") {
      request.status = "paid";
      request.settledAt = rt.now();
      draft.emit("payment.settled", "system", { paymentId: request.paymentId, status: "paid", late: true });
      return { applied: true, callId, status } as const;
    }
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
    const answer = await expireAtProvider(rt, callId, payment, payment.linkId);
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

/**
 * Closes one open payment for good: settles it `expired`, at the provider first when a link exists.
 * Unlike the deadline, a `not_open` answer settles it too, because the engine stops waiting for
 * it: a payment that went through after all is recorded by its webhook as a late payment. A
 * request whose link was never created (or whose create was never answered) is settled here
 * alone, in one write, and `requestPayment` closes the link at the provider if one comes back.
 * Returns the payment's status, which is the one it had when it was no longer open.
 */
async function closePayment(rt: EngineRuntime, callId: string, paymentId: string, reason: "cancelled" | "call_ended"): Promise<PaymentStatus> {
  const close = (draft: CallDraft, provider: "expired" | "not_open" | "not_created"): PaymentStatus => {
    draft.emit("payment.link_expired", "code", { paymentId, provider, reason });
    settle(rt, draft, paymentId, "expired");
    return "expired";
  };
  const seen = await rt.update(callId, (draft) => {
    const request = draft.slice<PaylinkSlice>(PAYLINK).payments.find((p) => p.paymentId === paymentId);
    if (request === undefined) throw new EngineError("invalid_input", "no payment with that id on this call");
    if (request.status !== "open") return request.status;
    // The link id is written once, so a request without one here is closed before any link can be texted.
    if (request.linkId === "") return close(draft, "not_created");
    // A process is texting the link now: closing it under that sender would text a dead link.
    if (sending(rt, request)) throw new EngineError("precondition_failed", "a payment link is being texted on this call; close it once it is sent");
    return structuredClone(request);
  });
  if (typeof seen === "string") return seen;
  const links = rt.adapter("payments");
  const answer =
    reason === "cancelled" && links.cancel !== undefined ? await links.cancel(closeInput(rt, callId, seen, seen.linkId, "cancel")) : await expireAtProvider(rt, callId, seen, seen.linkId);
  return rt.update(callId, (draft) => {
    const request = find(draft, paymentId);
    return request.status === "open" ? close(draft, answer.state) : request.status;
  });
}

/**
 * Cancels a payment's link: the caller changed their mind. Through `PaymentLinks.cancel` when the
 * adapter has it, else `expireLink`. The request settles `expired` (its flow step fails) and the
 * session leaves `paying`. It needs no scope, since it only closes, and cancelling a payment that
 * is no longer open changes nothing and returns its status.
 */
export async function cancelPaymentLink(rt: EngineRuntime, callId: string, paymentId: string): Promise<{ paymentId: string; status: PaymentStatus }> {
  return { paymentId, status: await closePayment(rt, callId, paymentId, "cancelled") };
}

/**
 * Expires every open payment of an ended call, at the provider first (`expireLink`), so the
 * receipt shows them `expired` and no link outlives its call. Nothing to do on a call that
 * started with Paylink off.
 */
export async function expireOpenPayments(rt: EngineRuntime, record: CallRecord): Promise<void> {
  for (const payment of openPayments(record)) await closePayment(rt, record.state.callId, payment.paymentId, "call_ended");
}

/** Whether a process holds the lease to text this request's link now (it claimed it and has not recorded the text). */
function sending(rt: EngineRuntime, payment: PaymentRequest): boolean {
  return payment.textedAt === null && payment.sendingSince !== null && rt.clock.now().getTime() - Date.parse(payment.sendingSince) < SEND_LEASE_MS;
}

/**
 * Refuses, inside the write that ends a call, while a payment link is being texted: the call ends
 * once the text is recorded or the sender's lease lapses, so no text goes out, and no entry is
 * written, after the call ended. Nothing to check on a call that started with Paylink off.
 */
export function assertNoSendInFlight(rt: EngineRuntime, record: CallRecord): void {
  if (openPayments(record).some((p) => sending(rt, p))) {
    throw new EngineError("precondition_failed", "a payment link is being texted on this call; end the call once it is sent");
  }
}

/** A call's payments still open; none on a call that started with Paylink off. */
export function openPayments(record: CallRecord): PaymentRequest[] {
  const slice = record.modules[PAYLINK] as unknown as PaylinkSlice | undefined;
  return (slice?.payments ?? []).filter((p) => p.status === "open");
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
