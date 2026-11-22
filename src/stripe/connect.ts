// Stripe Connect onboarding on Accounts v2: the business's own Stripe account, connected by
// Stripe-hosted onboarding, so a payment link is a direct charge on it and the business is the
// merchant. Standard-equivalent: the merchant configuration, the full Dashboard (the business
// handles its own refunds and disputes), and Stripe as fees and losses collector. The host stores
// the account id; nothing here stores anything.
import type { AccountLinkCreateParams, ConnectAccountCreateParams, StripeClientLike } from "./client.ts";
import { StripeAdapterError } from "./errors.ts";
import type { StripeMode } from "./keys.ts";

const CONNECTED_ACCOUNT = /^acct_[A-Za-z0-9]{1,255}$/;
/** ISO 3166-1 alpha-2, upper case: Stripe refuses the merchant configuration without the business's own country. */
const COUNTRY = /^[A-Z]{2}$/;
const METADATA_KEY = /^[A-Za-z0-9_]{1,40}$/;

/** What a v2 Account must include for its status to be read: v2 answers an unincluded field as null. */
export const CONNECT_ACCOUNT_INCLUDE: ReadonlyArray<"configuration.merchant" | "requirements"> = Object.freeze(["configuration.merchant", "requirements"]);

/** The two flags a host shows. Anything missing reads false: an unknown is never "can take charges". */
export interface ConnectStatus {
  /** The merchant configuration's `card_payments` capability is `active`. */
  chargesEnabled: boolean;
  /**
   * The business has submitted its onboarding details: Stripe has requested the merchant
   * configuration's capabilities (it does so only once onboarding has collected the business's
   * details; a new account answers `capabilities: null`), and no requirement awaiting the business,
   * currently or past due, restricts a payment capability. A requirement that restricts only payouts
   * (a bank account still to add) does not hold it back.
   */
  detailsSubmitted: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The v2 Account create body. `country` is the business's own (never guessed from a region or a
 * dial code: Stripe fixes it once set). `metadata` holds the host's reference to its own record;
 * put a digest there, not a name or an email.
 */
export function connectAccountCreateParams(input: { country: string; metadata?: Record<string, string> }): ConnectAccountCreateParams {
  if (typeof input.country !== "string" || !COUNTRY.test(input.country)) throw new TypeError("country must be ISO 3166-1 alpha-2, upper case");
  const entries = Object.entries(input.metadata ?? {});
  for (const [key, value] of entries) {
    if (!METADATA_KEY.test(key) || typeof value !== "string" || value.length > 500) throw new TypeError("metadata keys are 1 to 40 word characters and values at most 500");
  }
  // fromEntries defines each key as its own property, so even `__proto__` is kept, never a setter call.
  const metadata = Object.fromEntries(entries) as Record<string, string>;
  return {
    identity: { country: input.country },
    dashboard: "full",
    configuration: { merchant: {} },
    defaults: { responsibilities: { fees_collector: "stripe", losses_collector: "stripe" } },
    metadata,
    include: [...CONNECT_ACCOUNT_INCLUDE],
  };
}

/** The card's two flags from a v2 Account read with `CONNECT_ACCOUNT_INCLUDE`. */
export function connectStatusOf(account: unknown): ConnectStatus {
  const a = isRecord(account) ? account : {};
  const configuration = isRecord(a.configuration) ? a.configuration : {};
  const merchant = isRecord(configuration.merchant) ? configuration.merchant : {};
  const capabilities = isRecord(merchant.capabilities) ? merchant.capabilities : {};
  const card = isRecord(capabilities.card_payments) ? capabilities.card_payments : {};
  const chargesEnabled = card.status === "active";
  // ⛔ "Nothing due" alone is not "submitted": a new account has no entries and nothing requested
  // (test mode, 2026-11-22: `requirements.entries` empty, `capabilities` null). Collection has
  // happened only once Stripe has requested a capability with a status.
  const requested = Object.values(capabilities).some((capability) => isRecord(capability) && typeof capability.status === "string");
  // Requirements not included, or no entries list: nothing establishes what is due.
  if (!requested || !isRecord(a.requirements) || !Array.isArray(a.requirements.entries)) return { chargesEnabled, detailsSubmitted: false };
  const outstanding = a.requirements.entries.some((entry: unknown) => {
    // An entry that cannot be read is unknown, and unknown is never "submitted".
    if (!isRecord(entry)) return true;
    if (entry.awaiting_action_from !== "user") return false;
    const deadline = isRecord(entry.minimum_deadline) ? entry.minimum_deadline.status : undefined;
    // Only a readable deadline that is not yet due lets a requirement wait; a missing one counts as due.
    const due = typeof deadline !== "string" || deadline === "currently_due" || deadline === "past_due";
    return due && restrictsPayments(entry);
  });
  return { chargesEnabled, detailsSubmitted: !outstanding };
}

/**
 * Whether a requirement restricts one of the merchant's payment capabilities (`card_payments` and
 * the other `*_payments`). One whose impact cannot be read counts as restricting them: unknown is
 * never "submitted".
 */
function restrictsPayments(entry: Record<string, unknown>): boolean {
  const impact = isRecord(entry.impact) ? entry.impact : null;
  if (impact === null || !Array.isArray(impact.restricts_capabilities)) return true;
  return impact.restricts_capabilities.some((item: unknown) => {
    // A restriction whose fields cannot be read is unknown: it counts as restricting payments.
    if (!isRecord(item) || typeof item.configuration !== "string" || typeof item.capability !== "string") return true;
    return item.configuration === "merchant" && item.capability.endsWith("_payments");
  });
}

function checkedAccount(answer: unknown, mode: StripeMode, step: string): Record<string, unknown> & { id: string } {
  const account = isRecord(answer) ? answer : {};
  if (typeof account.id !== "string" || !CONNECTED_ACCOUNT.test(account.id) || account.livemode !== (mode === "live")) {
    throw StripeAdapterError.answer(step);
  }
  return account as Record<string, unknown> & { id: string };
}

/**
 * Creates the connected account, once: the host passes an idempotency key it derives from its own
 * record, so two starts at once get Stripe's one account. Answers its id and status.
 */
export async function createConnectAccount(
  client: StripeClientLike,
  input: { mode: StripeMode; params: ConnectAccountCreateParams; idempotencyKey: string },
): Promise<{ accountId: string } & ConnectStatus> {
  let answer: unknown;
  try {
    answer = await client.v2.core.accounts.create(input.params, { idempotencyKey: input.idempotencyKey });
  } catch (err) {
    throw StripeAdapterError.from("create the connected account", err);
  }
  const account = checkedAccount(answer, input.mode, `answer a ${input.mode}-mode connected account`);
  return { accountId: account.id, ...connectStatusOf(account) };
}

/**
 * A fresh, single-use Stripe-hosted onboarding link for the owner's own browser. ⛔ Never text or
 * email it: it is a bearer link to the business's account setup.
 */
export async function createOnboardingLink(client: StripeClientLike, input: { accountId: string; returnUrl: string; refreshUrl: string }): Promise<{ url: string }> {
  if (!CONNECTED_ACCOUNT.test(input.accountId)) throw new TypeError("not a connected account id (acct_...)");
  for (const url of [input.returnUrl, input.refreshUrl]) {
    if (typeof url !== "string" || !URL.canParse(url) || new URL(url).protocol !== "https:") throw new TypeError("returnUrl and refreshUrl must be https");
  }
  const params: AccountLinkCreateParams = {
    account: input.accountId,
    use_case: { type: "account_onboarding", account_onboarding: { return_url: input.returnUrl, refresh_url: input.refreshUrl } },
  };
  let answer: unknown;
  try {
    answer = await client.v2.core.accountLinks.create(params);
  } catch (err) {
    throw StripeAdapterError.from("create the onboarding link", err);
  }
  const url = isRecord(answer) ? answer.url : undefined;
  if (typeof url !== "string" || !URL.canParse(url) || new URL(url).protocol !== "https:") throw StripeAdapterError.answer("answer an https onboarding link");
  // A bearer link to another account's setup is never handed on.
  if ((answer as Record<string, unknown>).account !== input.accountId) throw StripeAdapterError.answer("answer the onboarding link for the requested account");
  return { url };
}

/** Re-reads the connected account from Stripe: the status after onboarding, never an event's copy of it. */
export async function readConnectStatus(
  client: StripeClientLike,
  input: { mode: StripeMode; accountId: string; timeoutMs?: number },
): Promise<ConnectStatus> {
  if (!CONNECTED_ACCOUNT.test(input.accountId)) throw new TypeError("not a connected account id (acct_...)");
  let answer: unknown;
  try {
    answer = await client.v2.core.accounts.retrieve(
      input.accountId,
      { include: [...CONNECT_ACCOUNT_INCLUDE] },
      input.timeoutMs === undefined ? {} : { timeout: input.timeoutMs, maxNetworkRetries: 1 },
    );
  } catch (err) {
    throw StripeAdapterError.from("read the connected account", err);
  }
  const account = checkedAccount(answer, input.mode, `answer the ${input.mode}-mode connected account`);
  if (account.id !== input.accountId) throw StripeAdapterError.answer(`answer the ${input.mode}-mode connected account`);
  return connectStatusOf(account);
}
