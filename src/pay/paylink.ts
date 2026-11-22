// Paylink (pay): payment by a hosted link sent to the subject on file, by text to the number on
// file or, when the caller chose it, by email to the verified address on file. The engine never sees a
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
// Before every link, code reads the amount back to the caller (`readBackPayment`) and the caller
// confirms it (`confirmPaymentAmount`), whether the amount is fixed or resolved by the host's
// `AmountSource` adapter from the step's `amountRef` (PAY-2); no link is sent without that.
//
// The link is reserved in one write (the call enters `paying`, so a second request is refused
// everywhere), created and texted, then committed. Once texted it lives `linkLifeMinutes` (15 by
// default): the engine expires it itself at that deadline (`expirePaymentLinks`), because a
// provider's shortest link life can be longer than a call. A failed create leaves the request open
// to resume; once a link exists, only the provider's outcome, the engine's deadline, a cancel or
// the end of the call settles it. Money that moves after the engine closed a link is still
// recorded as paid, and flagged in the ledger.
//
// The channel (`paylink.channel`): when the subject has a verified address on file, the caller
// chooses text (key 1) or email (key 2), and the keypress is their consent to that channel, under
// its versioned wording. Without an address the choice is not offered and the link goes by text.
// Either way it is the same single-use link, with the same deadline, send lease and close.
import type { AmountSource, EmailSender, InstantPaymentMethod, PaymentLinkCapabilities, PaymentLinkClose, PaymentMode, SubjectRecord } from "../core/adapters.ts";
import type { JsonValue } from "../core/canonical.ts";
import { isEmailAddress } from "../core/email.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import { stepAmount, type StepUpAmount } from "../core/policy.ts";
import { hexDigestsEqual } from "../core/hash.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { CallDraft, CallRecord, EngineRuntime, Locale } from "../core/runtime.ts";
import type { SessionState } from "../core/session.ts";
import { isIntegerIn, isObject, unknownKeys } from "../core/shape.ts";
import { recordConsent, TRACE, type TraceSettings, type TraceSlice } from "../prove/trace.ts";
import { matchedSubject } from "../verify/badge.ts";
import { AMOUNT_REF, buildAmountReadBack, formatAmount, type AmountQuote, type AmountReadBack } from "./amount.ts";
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
  type AmountSourceKind,
  type PaymentChannel,
  type PaymentOutcome,
  type PaymentRequest,
  type PaymentStatus,
} from "./payment.ts";
import type { PaymentAfterwards } from "./refunds.ts";

export const PAYLINK = "paylink";

export { AMOUNT_REGION, formatAmount } from "./amount.ts";

const AMOUNT_SOURCES: readonly AmountSourceKind[] = ["intake_record", "business_endpoint", "price_list"];
const CONFIRMED_BY: readonly string[] = ["voice", "keypad"];

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
  /**
   * The channels a link may go by: `["text"]` (the default) or `["text", "email"]`, which turns on
   * the `paylink.channel` step and needs the `emails` adapter. Text is always one: it is the channel
   * when no verified address is on file.
   */
  channels?: PaymentChannel[];
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
  mode?: PaymentMode;
  linkLifeMinutes?: number;
  paymentMethods?: InstantPaymentMethod[];
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

/** A channel step: the caller chooses how the next payment link reaches them. It has no fields of its own. */
export interface PaylinkChannelStep extends FlowStep {
  type: "paylink.channel";
}

/** The channel chosen for the next link on this call, and for whom. */
export interface ChannelChoice {
  channel: PaymentChannel;
  /** The subject matched when it was chosen: the link goes only to that subject. */
  subjectKey: string;
  /** The consent the keypress recorded (`payment_link_text` or `payment_link_email`); null when no choice was offered. */
  consentId: string | null;
  at: string;
}

export interface PaylinkSlice {
  /** Each request, and once a platform payment is paid, its payment intent, refunds and disputes (`refunds.ts`). */
  payments: Array<PaymentRequest & PaymentAfterwards>;
  /** The amount last read back on this call and not yet used by a link (PAY-2). Absent on a call saved before PAY-2. */
  quote?: AmountQuote | null;
  /** The channel chosen and not yet used by a link. Absent on a call saved before channels existed. */
  channel?: ChannelChoice | null;
  /** How many choices were made on this call, for the channel step's status. Absent before the first. */
  choices?: number;
}

/** The channels a link can go by, in the order they are offered. */
export const PAYMENT_CHANNELS: readonly PaymentChannel[] = ["text", "email"];

/** The key the caller presses for each channel. Fixed in code: the host never maps keys to channels. */
export const PAYMENT_CHANNEL_KEYS: Readonly<Record<PaymentChannel, string>> = Object.freeze({ text: "1", email: "2" });

/** The consent purpose each channel's choice records, with its versioned wording from Trace's settings. */
export const PAYMENT_CHANNEL_PURPOSES: Readonly<Record<PaymentChannel, string>> = Object.freeze({ text: "payment_link_text", email: "payment_link_email" });

/** What `offerPaymentChannels` answers. */
export interface PaymentChannelOffer {
  /** The channels offered, each with its key: text only when no verified address is on file. */
  channels: Array<{ channel: PaymentChannel; key: string }>;
  /** The line the host reads, built by code: each channel's consent wording and its key. Null when only text is offered. */
  prompt: string | null;
  /** `text` when nothing was offered and the choice is already made (no address on file); null while the caller chooses. */
  chosen: PaymentChannel | null;
}

/** How a payment is taken: from the step, then the settings, then the defaults. */
interface PaymentTerms {
  mode: PaymentMode;
  connectedAccountId: string | null;
  linkLifeMinutes: number;
  paymentMethods: InstantPaymentMethod[];
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
  // A lone surrogate is not text: it cannot be read back or hashed into the read-back's digest.
  else if (!description.isWellFormed()) errors.push("description must be well-formed text, with no lone surrogate");
  if (!AMOUNT_SOURCES.includes(input.amountSource as AmountSourceKind)) errors.push(`amountSource must be one of ${AMOUNT_SOURCES.join(", ")}`);
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
const NEEDS_AMOUNTS = "an amountRef needs the amounts adapter, which the engine does not have";

function isCapabilities(value: unknown): value is PaymentLinkCapabilities {
  if (!isObject(value)) return false;
  const { modes, minLinkMinutes: min, maxLinkMinutes: max } = value;
  return Array.isArray(modes) && modes.every((m) => (PAYMENT_MODES as readonly unknown[]).includes(m)) && isIntegerIn(min, 0, 100_000) && isIntegerIn(max, 1, 100_000) && min <= max;
}

/** Problems between a mode and a link life and what the payments adapter declares it can do. */
function adapterErrors(caps: PaymentLinkCapabilities, mode: PaymentMode, lifeMinutes: number): string[] {
  const errors: string[] = [];
  // A refund is optional for the adapter: no flow step needs one (refunds are host calls), so a
  // platform payment flow is valid without it, and `refundPayment` is refused at run time instead.
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

/** Problems with Paylink's `channels` setting. */
function channelsErrors(value: unknown): string[] {
  if (!Array.isArray(value) || !value.every((c) => (PAYMENT_CHANNELS as readonly unknown[]).includes(c))) return ["channels must list text, and email or not"];
  if (new Set(value).size !== value.length) return ["channels has duplicates"];
  return value.includes("text") ? [] : ["channels must include text: it is how a link goes when no verified address is on file"];
}

/** Whether Paylink's settings turn the email channel on. */
function emailOn(settings: PaylinkSettings | undefined | null): boolean {
  return (settings?.channels ?? []).includes("email");
}

/** Problems with a `paylink.channel` step: the email channel on, and Trace's wordings and business name the choice and the email need. */
function channelStepErrors(step: FlowStep, ctx: StepContext): string[] {
  const errors = unknownKeys(step, ["type"]).map((k) => `${k} is not a field of this step`);
  // Settings that did not validate are reported on their own.
  if (ctx.settings !== null && !emailOn(ctx.settings as PaylinkSettings | undefined)) errors.push('the channel choice needs "email" in Paylink\'s channels setting');
  // Without a config in view, or with Trace's settings refused (reported on their own), there is nothing to check against.
  if (ctx.settingsOf === undefined) return errors;
  const trace = ctx.settingsOf(TRACE) as TraceSettings | undefined | null;
  if (trace === null) return errors;
  for (const purpose of Object.values(PAYMENT_CHANNEL_PURPOSES)) {
    if (!(trace?.wordings ?? []).some((w) => w.purpose === purpose)) errors.push(`the channel choice needs a wording for ${purpose} in the trace settings`);
  }
  if (trace?.businessName === undefined) errors.push("the email channel needs businessName in the trace settings");
  return errors;
}

export const paylinkModule: AssuranceModule = {
  manifest: {
    name: PAYLINK,
    version: "3",
    summary: "Take a payment by a hosted link sent to the subject on file, by text or by email, on the business's account or the platform's.",
    provides: { factors: [], steps: ["paylink.request", "paylink.channel"], outcomes: ["payment"] },
    scopes: { grants: [], needs: { "paylink.request": "payment.request" }, classes: { "payment.request": "money" } },
    adapters: ["payments", "messages"],
  },

  validateSettings(settings: unknown): string[] {
    if (settings === undefined) return [];
    if (!isObject(settings)) return ["must be an object"];
    const errors = unknownKeys(settings, ["maxAmountMinor", "mode", "connectedAccountId", "linkLifeMinutes", "paymentMethods", "channels"]).map((k) => `${k} is not a paylink setting`);
    if (settings.channels !== undefined) errors.push(...channelsErrors(settings.channels));
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

  requiredAdapters(settings: unknown): string[] {
    return emailOn(settings as PaylinkSettings | undefined) ? ["payments", "messages", "emails"] : ["payments", "messages"];
  },

  validateStep(step: FlowStep, ctx: StepContext): string[] {
    if (step.type === "paylink.channel") return channelStepErrors(step, ctx);
    const errors = unknownKeys(step, ["type", "amountMinor", "currency", "amountRef", "description", "amountSource", "mode", "linkLifeMinutes", "paymentMethods"]).map(
      (k) => `${k} is not a field of this step`,
    );
    const settings = ctx.settings as PaylinkSettings | undefined | null;
    errors.push(...requestErrors(step, settings?.maxAmountMinor));
    if (step.amountRef !== undefined && !ctx.adapters.has("amounts")) errors.push(NEEDS_AMOUNTS);
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

  validateFlow(steps: readonly FlowStep[], ctx: StepContext): string[] {
    // A choice serves the one link after it: each channel step is followed by a request, before another choice.
    const errors: string[] = [];
    let waiting = false;
    let verified = false;
    // The level payment.request needs; without a policy in view nothing is checked against it.
    const min = ctx.policy === null ? 0 : (ctx.policy.scopes["payment.request"] ?? Infinity);
    steps.forEach((step, index) => {
      if (step.type === "badge.verify") {
        // The last verification is the one the call holds: it must reach payment.request and, when it lists scopes, grant it.
        verified = typeof step.level === "number" && step.level >= min && (!Array.isArray(step.scopes) || step.scopes.includes("payment.request"));
      } else if (step.type === "paylink.channel") {
        // It needs no scope in the manifest (a choice is not a money action a receipt names), so its
        // place after the verification is checked here: it asks for payment.request when it runs.
        if (!verified) errors.push(`steps[${index}]: a paylink.channel step comes after a badge.verify step that grants payment.request, since it needs that scope when it runs`);
        if (waiting) errors.push(`steps[${index}]: a second paylink.channel step before the paylink.request the first one is for`);
        waiting = true;
      } else if (step.type === "paylink.request") waiting = false;
    });
    if (waiting) errors.push("a paylink.channel step must be followed by the paylink.request step it chooses for");
    return errors;
  },

  initCall(): JsonValue {
    return { payments: [], quote: null, channel: null, choices: 0 };
  },

  onUntrusted(s: JsonValue): JsonValue {
    // A confirmation, or a channel choice, heard before untrusted text entered the call no longer counts: ask again.
    return { ...(s as unknown as PaylinkSlice), quote: null, channel: null } as unknown as JsonValue;
  },

  enterStep(step: FlowStep, s: JsonValue): JsonValue {
    const slice = s as unknown as PaylinkSlice;
    return step.type === "paylink.channel" ? (slice.choices ?? 0) : slice.payments.length;
  },

  stepStatus(step: FlowStep, view: StepView): StepStatus {
    if (step.type === "paylink.channel") return ((view.slice as unknown as PaylinkSlice).choices ?? 0) > (view.mark as number) ? "complete" : "pending";
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
        // A payment recorded before modes existed was taken on the host's own account: platform.
        mode: p.mode ?? "platform",
        providerRef: p.linkId,
      })),
    };
  },
};

// ---- runtime -------------------------------------------------------------------------------

/**
 * The checks every payment entry point makes: the flow's step, the scope, and the subject Badge
 * matched. The scope is held at the minimum the step-up rules raise it to for `amount` (VER-13;
 * null when no amount is known yet, so amount rules wait for it); `requestPayment` holds it itself
 * (`requireScope`), so the flow fails and the ledger keeps the rule, and passes `false`.
 */
function requestContext(
  rt: EngineRuntime,
  record: CallRecord,
  input: PaymentInput | undefined,
  amount: StepUpAmount | null | false,
): { step: PaylinkRequestStep | null; subject: SubjectRecord } {
  const step = stepOfType<PaylinkRequestStep>(record, "paylink.request");
  if (amount !== false && !rt.authorized(record, "payment.request", amount)) throw new EngineError("scope_denied", "the grant does not cover payment.request");
  if (step !== null && input !== undefined) throw new EngineError("invalid_input", "the flow step sets the amount; pass no input");
  return { step, subject: matchedSubject(record) };
}

const OUTSIDE_A_FLOW = "outside a flow, the amount (or amountRef), description and amountSource are required";

/** What an amount was read back for, so a read-back serves only the request it was made for. */
function specKey(spec: PaymentInput): string {
  const s = spec as Partial<FixedPaymentInput & ReferencedPaymentInput>;
  return JSON.stringify([s.amountMinor ?? null, s.currency ?? null, s.amountRef ?? null, s.description, s.amountSource]);
}

/** The amount request in force on an open call, checked: the flow step's, or outside a flow the host's. */
function readBackSpec(
  rt: EngineRuntime,
  record: CallRecord,
  input: PaymentInput | undefined,
  maxMinor: number | undefined,
  amount: StepUpAmount | null,
): { spec: PaymentInput; subject: SubjectRecord } {
  const { step, subject } = requestContext(rt, record, input, amount);
  if (record.state.phase !== "open") throw new EngineError("invalid_transition", `an amount is read back on an open call, not while ${record.state.phase}`);
  // validateConfig let a step through with a fixed amount or an amountRef, never neither.
  const spec = (step as PaymentInput | null) ?? input;
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
export async function readBackPayment(rt: EngineRuntime, callId: string, given?: PaymentInput): Promise<AmountReadBack> {
  const settings = rt.settings<PaylinkSettings | undefined>(PAYLINK) ?? {};
  // Read once, before the lookup: the request checked, looked up and quoted is one snapshot, so a
  // host changing its object (an amountRef) while the amount is looked up changes nothing.
  const input = given === undefined ? undefined : ({ ...given } as PaymentInput);
  const before = await rt.read(callId);
  // An amount not looked up yet waits for its answer before the step-up rules on amounts judge it.
  const known = input === undefined ? stepAmount(stepOfType<PaylinkRequestStep>(before, "paylink.request")) : stepAmount(input as unknown as Record<string, unknown>);
  const { spec, subject } = readBackSpec(rt, before, input, settings.maxAmountMinor, known ?? null);
  const named = spec as Partial<FixedPaymentInput & ReferencedPaymentInput>;
  let amount = { amountMinor: named.amountMinor!, currency: named.currency! };
  if (named.amountRef !== undefined) {
    const source = rt.adapter("amounts") as AmountSource | undefined;
    if (source === undefined) throw new EngineError("precondition_failed", NEEDS_AMOUNTS);
    const found = await source.resolve({
      workspaceId: rt.workspaceId,
      callId,
      source: spec.amountSource,
      reference: named.amountRef,
      subjectKey: subject.subjectKey,
      recordIds: [...before.state.recordIds],
    });
    // undefined too: an async resolve that falls through answers it instead of null.
    if (found === null || found === undefined) throw new EngineError("precondition_failed", "the amount source has no amount for this reference");
    amount = { amountMinor: found.amountMinor, currency: found.currency };
    const errors = requestErrors({ ...amount, description: spec.description, amountSource: spec.amountSource }, settings.maxAmountMinor);
    if (errors.length > 0) throw new EngineError("invalid_input", `the amount source answered with a bad amount: ${errors.join("; ")}`);
  }
  // Each read-back has an id of its own, in its digest: a confirmation of an earlier, identical
  // read-back (a second deposit of the same amount) never confirms this one.
  const readBack = buildAmountReadBack(before.locale, { ...amount, description: spec.description.trim() }, rt.ids.next("amt"));
  return rt.update(callId, (draft) => {
    // Checked again: the call can have moved on while the amount was looked up, and now on the
    // amount the caller will hear (a step-up rule on amounts judges it here, VER-13).
    const now = readBackSpec(rt, draft.record, input, settings.maxAmountMinor, amount);
    if (now.subject.subjectKey !== subject.subjectKey) {
      throw new EngineError("precondition_failed", "the matched subject changed while the amount was looked up; read it back again");
    }
    draft.slice<PaylinkSlice>(PAYLINK).quote = {
      spec: specKey(spec),
      subjectKey: subject.subjectKey,
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
 * the amount the caller heard. Confirming twice is harmless. `confirmedBy` goes into the ledger,
 * so it is one of two fixed words, never the host's text.
 */
export async function confirmPaymentAmount(rt: EngineRuntime, callId: string, input: { digest: string; confirmedBy: "voice" | "keypad" }): Promise<void> {
  rt.settings(PAYLINK);
  if (!isObject(input)) throw new EngineError("invalid_input", "digest must be the read-back's digest");
  // Read once: the checked values are the ones compared and ledgered, so a getter or a host
  // changing the object while the update waits cannot swap them.
  const digest: unknown = input.digest;
  const confirmedBy = input.confirmedBy as unknown as string;
  if (typeof digest !== "string") throw new EngineError("invalid_input", "digest must be the read-back's digest");
  if (!CONFIRMED_BY.includes(confirmedBy)) throw new EngineError("invalid_input", "confirmedBy must be voice or keypad");
  await rt.update(callId, (draft) => {
    requestContext(rt, draft.record, undefined, null);
    // A call saved before PAY-2 has no quote field: the same as no read-back.
    const quote = draft.slice<PaylinkSlice>(PAYLINK).quote ?? null;
    if (quote === null) throw new EngineError("precondition_failed", "no amount was read back on this call");
    if (!hexDigestsEqual(digest, quote.digest)) throw new EngineError("precondition_failed", "this is not the amount last read back; read it back again");
    if (quote.confirmedAt !== null) return;
    quote.confirmedAt = rt.now();
    draft.emit("payment.amount_confirmed", "caller", { digest: quote.digest, confirmedBy });
  });
}

// ---- channel ------------------------------------------------------------------------------

/** What a channel choice is judged on: the subject, the channels it can be offered, and the words for them. */
interface ChannelContext {
  subject: SubjectRecord;
  offered: PaymentChannel[];
  trace: TraceSlice;
}

/**
 * The checks a channel offer and a choice make: Paylink on, the flow on its channel step (or no
 * flow), an open call, `payment.request` covered and a keypad or PIN match standing. Email is
 * offered only with the email channel on (Paylink's `channels`) and a verified address on file; then the call must have both
 * channels' wordings in its language and the business's name, or nothing is offered (fail closed).
 */
function channelContext(rt: EngineRuntime, record: CallRecord): ChannelContext {
  rt.settings(PAYLINK);
  stepOfType<PaylinkChannelStep>(record, "paylink.channel");
  if (record.state.phase !== "open") throw new EngineError("invalid_transition", `a channel is chosen on an open call, not while ${record.state.phase}`);
  if (!rt.authorized(record, "payment.request", null)) throw new EngineError("scope_denied", "the grant does not cover payment.request");
  const subject = matchedSubject(record);
  const trace = record.modules[TRACE] as unknown as TraceSlice;
  const email = emailOn(rt.settings<PaylinkSettings | undefined>(PAYLINK)) && isEmailAddress(subject.emailOnFile);
  if (!email) return { subject, offered: ["text"], trace };
  for (const channel of PAYMENT_CHANNELS) {
    const purpose = PAYMENT_CHANNEL_PURPOSES[channel];
    if (trace.wordings.find((w) => w.purpose === purpose)?.text[record.locale] === undefined) {
      throw new EngineError("precondition_failed", `the channel choice needs a ${record.locale} wording for ${purpose} on this call`);
    }
  }
  if (trace.businessName === null) throw new EngineError("precondition_failed", "the email channel needs the business's name on this call");
  return { subject, offered: [...PAYMENT_CHANNELS], trace };
}

/** Records a choice on the call, for the next link: the step completes, and the ledger names the channel, never the address. */
function noteChoice(rt: EngineRuntime, draft: CallDraft, channel: PaymentChannel, ctx: ChannelContext, consentId: string | null): void {
  const slice = draft.slice<PaylinkSlice>(PAYLINK);
  slice.channel = { channel, subjectKey: ctx.subject.subjectKey, consentId, at: rt.now() };
  slice.choices = (slice.choices ?? 0) + 1;
  draft.emit("payment.channel_chosen", consentId === null ? "code" : "caller", { channel, offered: [...ctx.offered], ...(consentId === null ? {} : { consentId }) });
}

/**
 * Offers the caller a channel for the next payment link. With a verified address on file it
 * answers both channels and the prompt the host reads (each channel's consent wording, then its
 * key, in the call's language) and writes nothing; the caller's key goes to `choosePaymentChannel`.
 * Without one, nothing is offered: the link goes by text, and that choice is recorded now (the step
 * completes, `chosen: "text"`).
 */
export async function offerPaymentChannels(rt: EngineRuntime, callId: string): Promise<PaymentChannelOffer> {
  const record = await rt.read(callId);
  const ctx = channelContext(rt, record);
  const channels = ctx.offered.map((channel) => ({ channel, key: PAYMENT_CHANNEL_KEYS[channel] }));
  if (ctx.offered.length > 1) {
    const locale = record.locale;
    const prompt = ctx.offered
      .map((channel) => `${ctx.trace.wordings.find((w) => w.purpose === PAYMENT_CHANNEL_PURPOSES[channel])!.text[locale]!.trim()} ${CHANNEL_KEY_TEXT[locale](PAYMENT_CHANNEL_KEYS[channel])}`)
      .join(" ");
    return { channels, prompt, chosen: null };
  }
  await rt.update(callId, (draft) => {
    const now = channelContext(rt, draft.record);
    // An address that came on file since the read (a restart that read the subject again) is offered next time.
    if (now.offered.length > 1) throw new EngineError("precondition_failed", "the channels changed while they were offered; offer them again");
    noteChoice(rt, draft, "text", now, null);
  });
  return { channels, prompt: null, chosen: "text" };
}

/**
 * The caller keyed their choice: `1` for text, `2` for email (`PAYMENT_CHANNEL_KEYS`), only among
 * the channels offered. With both offered, the keypress is the caller's consent to that channel:
 * recorded as a consent to `payment_link_text` or `payment_link_email` under its wording (version
 * and digest), through the ConsentStore when there is one, before the choice. The choice serves
 * the next link on the call, for the subject matched now.
 */
export async function choosePaymentChannel(rt: EngineRuntime, callId: string, input: { key: string }): Promise<{ channel: PaymentChannel }> {
  // Read once: the key checked is the one used.
  const key: unknown = isObject(input) ? input.key : undefined;
  if (typeof key !== "string") throw new EngineError("invalid_input", "key must be the digit the caller keyed");
  const ctx = channelContext(rt, await rt.read(callId));
  const channel = ctx.offered.find((c) => PAYMENT_CHANNEL_KEYS[c] === key);
  if (channel === undefined) throw new EngineError("invalid_input", `key must be one of ${ctx.offered.map((c) => PAYMENT_CHANNEL_KEYS[c]).join(", ")}`);
  const consentId =
    ctx.offered.length > 1
      ? (await recordConsent(rt, callId, { purpose: PAYMENT_CHANNEL_PURPOSES[channel], answer: "yes", channel: "call" }, (record) => matchedSubject(record).subjectKey, "paylink.channel")).consentId
      : null;
  await rt.update(callId, (draft) => {
    const now = channelContext(rt, draft.record);
    if (now.subject.subjectKey !== ctx.subject.subjectKey || now.offered.length !== ctx.offered.length) {
      throw new EngineError("precondition_failed", "the call changed while the choice was recorded; offer the channels again");
    }
    noteChoice(rt, draft, channel, now, consentId);
  });
  return { channel };
}

/**
 * The channel a new link goes by: the one chosen on the call, for this subject, or text when none
 * was. A choice that recorded a consent needs the caller's latest answer to that purpose to still
 * be yes (a later no withdraws it). Email needs the channel still on and the address still there.
 */
function chosenChannel(record: CallRecord, slice: PaylinkSlice, subject: SubjectRecord): PaymentChannel {
  const choice = slice.channel ?? null;
  if (choice === null) return "text";
  if (choice.subjectKey !== subject.subjectKey) throw new EngineError("precondition_failed", "the channel was chosen for another subject; offer the channels again");
  if (choice.consentId !== null) {
    const purpose = PAYMENT_CHANNEL_PURPOSES[choice.channel];
    const latest = (record.modules[TRACE] as unknown as TraceSlice).consents.filter((c) => c.purpose === purpose).at(-1);
    if (latest?.answer !== "yes") throw new EngineError("precondition_failed", "the caller withdrew their consent to this channel; offer the channels again");
  }
  return choice.channel;
}

/** Where a link goes, by its channel: the number on file, or the verified address on file with the business's name. */
interface Destination {
  phone: string;
  email: string | null;
  businessName: string | null;
  locale: Locale;
}

function destinationFor(rt: EngineRuntime, record: CallRecord, subject: SubjectRecord, channel: PaymentChannel): Destination {
  const businessName = (record.modules[TRACE] as unknown as TraceSlice).businessName;
  if (channel === "email") {
    // The channel turned off since the choice (or a call resumed on an engine without it), or a subject read again without its address.
    if (!emailOn(rt.settings<PaylinkSettings | undefined>(PAYLINK))) throw new EngineError("precondition_failed", "the link is to be emailed, and the email channel is off");
    if (!isEmailAddress(subject.emailOnFile) || businessName === null) throw new EngineError("precondition_failed", "the link is to be emailed, and no verified address is on file now");
  }
  return { phone: subject.phoneOnFile, email: channel === "email" ? subject.emailOnFile! : null, businessName, locale: record.locale };
}

/**
 * The read-back a new link is for. Every link needs one, confirmed by the caller and made for this
 * request and this subject, fixed amount or not: the caller hears every amount before it is sent.
 */
function confirmedQuote(quote: AmountQuote | null, spec: PaymentInput | undefined, subject: SubjectRecord): AmountQuote {
  if (quote === null) throw new EngineError("precondition_failed", "the amount is read back and confirmed before the link is sent");
  if (quote.subjectKey !== subject.subjectKey) throw new EngineError("precondition_failed", "the amount was read back for another subject; read it back again");
  if (spec !== undefined && specKey(spec) !== quote.spec) throw new EngineError("precondition_failed", "this request is not the amount read back; read it back again");
  if (quote.confirmedAt === null) throw new EngineError("precondition_failed", "the caller has not confirmed the amount read back");
  return quote;
}

/**
 * Sends a hosted payment link: by text to the number on file, or by email to the verified address
 * on file when the caller chose email (`choosePaymentChannel`). In a flow, the step sets the amount and
 * `input` must be left out; outside one, the host's code passes it (`amountSource` says where from).
 * Every link needs a read-back on the call (`readBackPayment`) that the caller confirmed
 * (`confirmPaymentAmount`), for this request, and the link is for exactly that amount.
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
    const slice = draft.slice<PaylinkSlice>(PAYLINK);
    const last = slice.payments.at(-1);
    const resuming = draft.record.state.phase === "paying" && last !== undefined && last.status === "open" && last.textedAt === null;
    // The scope is held to its minimum for this amount first, as every scope check (VER-13): the
    // request being resumed, else the amount the caller confirmed, else the one named (an amountRef
    // not read back yet has none, and is refused below for want of a read-back).
    const named = (stepOfType<PaylinkRequestStep>(draft.record, "paylink.request") ?? input ?? null) as Readonly<Record<string, unknown>> | null;
    const refused = rt.requireScope(draft, "payment.request", resuming ? last : (slice.quote ?? stepAmount(named) ?? null));
    if (refused !== null) return { refused };
    const { step, subject } = requestContext(rt, draft.record, input, false);
    if (resuming) {
      const where = destinationFor(rt, draft.record, subject, last.channel ?? "text");
      const named = input as Partial<FixedPaymentInput & ReferencedPaymentInput> | undefined;
      // A resume names nothing, the same amount, or the same amountRef request it was made for.
      const same =
        named === undefined ||
        (named.amountRef !== undefined ? last.requestKey === specKey(named as PaymentInput) : named.amountMinor === last.amountMinor && named.currency === last.currency);
      if (!same) throw new EngineError("invalid_input", "a payment link is still being sent on this call; resume it with the same amount or amountRef, or none");
      return { request: last, ...where };
    }
    // A link already out (or a call not open) is refused as a transition, before the read-back.
    draft.assertCan({ type: "payment_requested", paymentId: "next" });
    const channel = chosenChannel(draft.record, slice, subject);
    const where = destinationFor(rt, draft.record, subject, channel);
    // A call saved before PAY-2 has no quote field: the same as no read-back.
    const quote = confirmedQuote(slice.quote ?? null, (step as PaymentInput | null) ?? input, subject);
    const chosen: FixedPaymentInput = { amountMinor: quote.amountMinor, currency: quote.currency, description: quote.description, amountSource: quote.amountSource };
    const errors = requestErrors({ ...chosen }, settings.maxAmountMinor);
    const terms = termsFor(settings, step);
    // The config was checked when saved; a call keeps its steps while the settings can change under it.
    if (terms.mode === "connect" && terms.connectedAccountId === null) errors.push(CONNECT_NEEDS_ACCOUNT);
    // So can the engine: a call saved by an engine whose adapter took connect payments, or longer
    // links, is resumed here against this engine's adapter, before the read-back is used up.
    errors.push(...adapterErrors(rt.adapter("payments").capabilities, terms.mode, terms.linkLifeMinutes));
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    slice.quote = null;
    // A choice serves one link.
    slice.channel = null;
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
      channel,
      // The request the read-back was made for (confirmedQuote held any request named to it).
      requestKey: quote.spec,
      ...terms,
      expiresAt: null,
      providerExpiresAt: providerExpiry(requestedAt, terms.linkLifeMinutes, rt.adapter("payments").capabilities),
      sendingSince: null,
    };
    draft.slice<PaylinkSlice>(PAYLINK).payments.push(request);
    return { request, ...where };
  });
  if ("refused" in reserved) throw reserved.refused;
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
  let recorded: { paymentId: string; status: PaymentStatus; expiresAt: string | null } | null = null;
  const claim = await rt.update(callId, (draft): "sent" | "claimed" | "late" | "settled" => {
    const pending = find(draft, request.paymentId);
    pending.linkId = link.linkId;
    if (pending.textedAt !== null) {
      recorded = { paymentId: request.paymentId, status: pending.status, expiresAt: pending.expiresAt };
      return "sent";
    }
    // Another process settled the request while this one created the link (it took too long), or
    // the call ended meanwhile (its links are being closed): the link is live at the provider but
    // must never be texted.
    // A close that has begun (a cancel, or the end of the call, waiting on the provider) counts too.
    if (pending.status !== "open" || draft.record.state.phase === "ended" || pending.closingSince !== undefined) return "settled";
    // Another sender's live lease is never replaced: it may be in the middle of the text.
    if (sending(rt, pending)) throw new EngineError("precondition_failed", "another process is texting this payment link");
    if (Date.parse(request.providerExpiresAt) - rt.clock.now().getTime() >= MIN_LINK_LIFE_MINUTES * 60_000) {
      claimedAt = rt.now();
      pending.sendingSince = claimedAt;
      return "claimed";
    }
    return "late";
  });
  // Another resume texted it and recorded the delivery while this one created the link: nothing is
  // sent again, and the delivery recorded is the answer.
  if (claim === "sent") return recorded!;
  const closeLate = async (): Promise<never> => {
    const answer = await expireAtProvider(rt, callId, request, link.linkId);
    await rt.update(callId, (draft) => {
      if (find(draft, request.paymentId).status !== "open") return;
      draft.emit("payment.link_expired", "code", { paymentId: request.paymentId, provider: answer.state, reason: "not_sent_in_time" });
      // Only an expiry the provider confirms settles it; a link no longer open waits for its webhook.
      if (answer.state === "expired") settle(rt, draft, request.paymentId, "expired");
    });
    if (answer.state === "expired") throw new EngineError("precondition_failed", "the payment link could not be texted in time and was expired; request a new payment");
    // The provider says the link is no longer open (paid, or expired on its side) before its webhook
    // came: the payment stays open until that outcome arrives, so no new payment can start yet.
    throw new EngineError("precondition_failed", "the payment link could not be texted in time and the provider says it is no longer open; wait for its outcome");
  };
  const leftMs = () => Date.parse(request.providerExpiresAt) - rt.clock.now().getTime();
  try {
    await rt.bindRef(paymentRef(request, link.linkId), callId);
    // Checked again right before the text: binding the reference can take time too.
    if (claim === "settled") {
      await expireAtProvider(rt, callId, request, link.linkId);
      throw new EngineError("precondition_failed", "the payment request was closed while its link was created; the link was expired and never texted");
    }
    if (claim === "late" || leftMs() < MIN_LINK_LIFE_MINUTES * 60_000) await closeLate();
    // Only a claimed sender gets here. Binding the reference can stall past the lease, and then a
    // cancel or the end of the call may have gone ahead (and failed to expire the link at the
    // provider). So the claim is checked again, and renewed, in a write right before the text: a
    // request closed, a call ended, or a lease another sender took since is never texted from here.
    // The lease this sender holds is fixed before the write: a retry of the write (another write
    // won the compare-and-set) compares against the same one, and the renewal is adopted only once
    // the write is saved.
    const held = claimedAt;
    let renewed = held;
    let hold: EngineError | null = null;
    const still = await rt.update(callId, (draft): "ok" | "closed" | "taken" | "held" => {
      const pending = find(draft, request.paymentId);
      if (pending.status !== "open" || draft.record.state.phase === "ended" || pending.closingSince !== undefined) return "closed";
      if (pending.textedAt !== null || pending.sendingSince !== held) return "taken";
      // Checked again before the text: a signal raised, or a time window opened, while the link was
      // being created holds the request (VER-13). The link id is kept, so a resume finds the same link.
      try {
        hold = rt.requireScope(draft, "payment.request", request);
      } catch (e) {
        hold = e as EngineError;
      }
      if (hold !== null) return "held";
      renewed = rt.now();
      pending.sendingSince = renewed;
      return "ok";
    });
    claimedAt = renewed;
    if (still === "closed") {
      await expireAtProvider(rt, callId, request, link.linkId);
      throw new EngineError("precondition_failed", "the payment request was closed while its link was being sent; the link was expired and never texted");
    }
    if (still === "taken") throw new EngineError("precondition_failed", "another process took over texting this payment link");
    if (still === "held") throw hold!;
    // And the life left, once more: the renewal can take time too.
    if (leftMs() < MIN_LINK_LIFE_MINUTES * 60_000) await closeLate();
    if (reserved.email !== null) {
      // The life the email states: the link's, or what the provider has left of it, whichever is shorter.
      const minutes = Math.min(request.linkLifeMinutes, Math.floor(leftMs() / 60_000));
      const email = PAYMENT_EMAIL[reserved.locale];
      const amount = formatAmount(reserved.locale, request.amountMinor, request.currency);
      await (rt.adapter("emails") as EmailSender).sendEmail({
        to: reserved.email,
        subject: email.subject(reserved.businessName!),
        body: email.body(reserved.businessName!, amount, minutes, link.url),
        locale: reserved.locale,
        purpose: "payment_link",
        idempotencyKey: rt.idempotencyKey(callId, request.paymentId, "email"),
      });
    } else {
      await rt.adapter("messages").sendText({
        to: reserved.phone,
        body: paymentText(reserved.locale, link.url, request.amountMinor, request.currency),
        purpose: "payment_link",
        idempotencyKey: rt.idempotencyKey(callId, request.paymentId, "text"),
      });
    }
  } catch (error) {
    // A sender that fails (the text, or a write before it) gives its own lease back at once, so
    // the immediate retry can claim it; one another sender holds now is left as it is. A release
    // that fails leaves the lease to lapse, and the first error is the one thrown.
    if (claim === "claimed") await releaseLease(rt, callId, request.paymentId, claimedAt).catch(() => undefined);
    throw error;
  }
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
      channel: request.channel ?? "text",
      expiresAt: sent.expiresAt,
    });
    return { paymentId: request.paymentId, status: sent.status, expiresAt: sent.expiresAt };
  });
}

/** Gives a sender's lease on a link's text back, if it still holds it and nothing was texted. */
async function releaseLease(rt: EngineRuntime, callId: string, paymentId: string, held: string): Promise<void> {
  await rt.update(callId, (draft) => {
    const pending = find(draft, paymentId);
    if (pending.textedAt === null && pending.sendingSince === held) pending.sendingSince = null;
  });
}

/** The session store reference a payment link is bound under: per connected account in connect mode. */
function paymentRef(payment: Pick<PaymentRequest, "connectedAccountId">, linkId: string): string {
  return payment.connectedAccountId === null ? `payment:${linkId}` : `payment:${JSON.stringify([payment.connectedAccountId, linkId])}`;
}

/**
 * Asks the provider to expire a link, on the account the payment was taken on. Its answer goes into
 * the ledger (`payment.link_expired`'s `provider`), so it is read once and must be one of its two
 * answers: anything else ("paid", a phone number, nothing) is a provider fault, thrown like one
 * that throws, and the payment stays open.
 */
async function expireAtProvider(rt: EngineRuntime, callId: string, payment: PaymentRequest, linkId: string): Promise<{ state: "expired" | "not_open" }> {
  const answer: unknown = await rt.adapter("payments").expireLink(closeInput(rt, callId, payment, linkId, "expire"));
  const state: unknown = typeof answer === "object" && answer !== null ? (answer as { state?: unknown }).state : undefined;
  if (state !== "expired" && state !== "not_open") throw new EngineError("precondition_failed", "the payment provider answered neither expired nor not_open; the link is still open");
  return { state };
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
export async function applyPaymentOutcome(
  rt: EngineRuntime,
  given: PaymentOutcome & { paymentIntentId?: string },
): Promise<{ applied: false; unbound?: true } | { applied: true; callId: string; status: PaymentStatus }> {
  // One snapshot, taken before the first wait: the link looked up, the account checked and the
  // payment settled are the same one, even if the host reuses its object while the lookup runs.
  const outcome = { ...given };
  // A connect-mode payment is bound under its account, so two accounts' link ids never collide. A
  // platform payment's binding is tried last, so a connected account's event for one is seen (and
  // written down as ignored) rather than lost.
  const account = outcome.account ?? null;
  const callId = (account === null ? null : await rt.resolveRef(paymentRef({ connectedAccountId: account }, outcome.linkId))) ?? (await rt.resolveRef(paymentRef({ connectedAccountId: null }, outcome.linkId)));
  // No call holds this link yet: its reference may still be being bound (the provider can answer
  // before the engine wrote it down). `unbound` tells the host to have the event delivered again.
  if (callId === null) return { applied: false, unbound: true };
  const { result, paymentIntentId } = await rt.update(callId, (draft) => {
    const payments = draft.slice<PaylinkSlice>(PAYLINK).payments.filter((p) => p.linkId === outcome.linkId);
    const request = payments.find((p) => p.connectedAccountId === account) ?? payments[0]!;
    if (!outcomeAccountMatches(request, outcome)) {
      draft.emit("payment.outcome_ignored", "system", { paymentId: request.paymentId, reason: "account" });
      return { result: { applied: false } as const, paymentIntentId: undefined };
    }
    const status = settlementFor(outcome);
    // A platform payment's disputes name its payment intent, not the page: it is kept to bind,
    // whenever it is paid (late too: a disputed late payment is still the platform's).
    const keepIntent = () => {
      if (request.mode === "platform" && outcome.paymentIntentId !== undefined) request.paymentIntentId ??= outcome.paymentIntentId;
    };
    // Money that moved is always recorded: a payment the engine had expired (its own deadline, or a
    // race with a slow create) and the provider then reports paid becomes paid, flagged as late.
    if (request.status === "expired" && status === "paid") {
      request.status = "paid";
      request.settledAt = rt.now();
      keepIntent();
      draft.emit("payment.settled", "system", { paymentId: request.paymentId, status: "paid", late: true });
      return { result: { applied: true, callId, status } as const, paymentIntentId: request.paymentIntentId };
    }
    if (request.status === "open" && status !== null) {
      settle(rt, draft, request.paymentId, status);
      if (status === "paid") keepIntent();
      return { result: { applied: true, callId, status } as const, paymentIntentId: request.paymentIntentId };
    }
    // Paid already, by an outcome that named no payment intent: a later one that names it is kept.
    if (request.status === "paid" && status === "paid") keepIntent();
    return { result: { applied: false } as const, paymentIntentId: request.paymentIntentId };
  });
  // Bound after the write, and again on every later outcome for the link, so a bind that failed
  // is made when the provider sends the event again.
  if (paymentIntentId !== undefined) await rt.bindRef(paymentIntentRef(paymentIntentId), callId);
  return result;
}

/** The provider reference a payment intent is bound under, so a dispute can land on any process. */
export function paymentIntentRef(paymentIntentId: string): string {
  return `payment_intent:${paymentIntentId}`;
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

/** The key instruction after each channel's wording in the channel prompt, in every supported locale (SPEC.md section 16). */
export const CHANNEL_KEY_TEXT: Record<Locale, (key: string) => string> = {
  en: (key) => `Press ${key}.`,
  fr: (key) => `Appuyez sur ${key}.`,
  es: (key) => `Pulse ${key}.`,
};

/**
 * The payment link email, in every supported locale (SPEC.md section 16). It names the merchant,
 * the amount, the link's life and the link, so a forwarded copy holds nothing more: never a code,
 * a phone number or an account number.
 */
export const PAYMENT_EMAIL: Record<Locale, { subject: (business: string) => string; body: (business: string, amount: string, minutes: number, url: string) => string }> = {
  en: {
    subject: (business) => `Your secure payment link from ${business}`,
    body: (business, amount, minutes, url) =>
      `${business} sent you a secure payment link for ${amount}. It works once and expires in ${minutes} minutes.\n\n${url}\n\nIf you did not ask for this payment, do not use the link.`,
  },
  fr: {
    subject: (business) => `Votre lien de paiement sécurisé de ${business}`,
    body: (business, amount, minutes, url) =>
      `${business} vous a envoyé un lien de paiement sécurisé pour ${amount}. Il ne sert qu'une fois et expire dans ${minutes} minutes.\n\n${url}\n\nSi vous n'avez pas demandé ce paiement, n'utilisez pas le lien.`,
  },
  es: {
    subject: (business) => `Su enlace de pago seguro de ${business}`,
    body: (business, amount, minutes, url) =>
      `${business} le envió un enlace de pago seguro por ${amount}. Sirve una sola vez y caduca en ${minutes} minutos.\n\n${url}\n\nSi no solicitó este pago, no use el enlace.`,
  },
};

/** The payment link text, in every supported locale (SPEC.md section 16). */
export const PAYMENT_TEXT: Record<Locale, (amount: string, url: string) => string> = {
  en: (amount, url) => `Your secure payment link for ${amount}: ${url}`,
  fr: (amount, url) => `Votre lien de paiement sécurisé pour ${amount} : ${url}`,
  es: (amount, url) => `Su enlace de pago seguro por ${amount}: ${url}`,
};

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
    // The close is claimed in this write, before the provider is asked: no sender texts the link
    // from now on (it would be a dead one), and a close that fails at the provider can be tried
    // again without a sender taking over meanwhile.
    request.closingSince ??= rt.now();
    return structuredClone(request);
  });
  if (typeof seen === "string") return seen;
  const links = rt.adapter("payments");
  const answer =
    reason === "cancelled" && links.cancel !== undefined ? await links.cancel(closeInput(rt, callId, seen, seen.linkId, "cancel")) : await expireAtProvider(rt, callId, seen, seen.linkId);
  // The provider's answer goes into the ledger: anything but its two answers is a provider fault,
  // like one that throws, so the payment stays open and the next cancel or endCall closes it.
  const state: unknown = isObject(answer) ? answer.state : undefined;
  if (state !== "expired" && state !== "not_open") throw new EngineError("precondition_failed", "the payment provider answered neither expired nor not_open; the link is still open");
  return rt.update(callId, (draft) => {
    const request = find(draft, paymentId);
    return request.status === "open" ? close(draft, state) : request.status;
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


function paymentText(locale: Locale, url: string, amountMinor: number, currency: string): string {
  return PAYMENT_TEXT[locale](formatAmount(locale, amountMinor, currency), url);
}
