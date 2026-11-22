// The Stripe TEST-mode proof of district-assurance/stripe: every call the package's adapters make,
// sent to real Stripe test mode through the package's own `fetchStripeClient` (no SDK on the call
// path). Run by hand; not part of `npm test`. No phone call, no text, nothing stored.
//
//   <print your test key> | node examples/reference-server/src/stripe-proof.ts [acct_...]
//
// The key is read from STDIN only, never an argument or the environment, and never printed.
// TEST MODE ONLY: a live key (`sk_live_`, `rk_live_`) or anything that is not a test-mode secret or
// restricted key is refused before any request, and every answer must read `livemode: false`.
//
// 1. Connect onboarding on Accounts v2: `connectAccountCreateParams`, `createConnectAccount`,
//    `createOnboardingLink` (only the link's host is printed: it is a bearer link) and
//    `readConnectStatus`.
// 2. Checkout on a connected account that can take charges (the one named on the command line, else
//    the first such test account found, every page of the list read): `StripeCheckoutLinks` on
//    endive creates a CAD 1.00 session with `allowed_payment_method_types`, reads it, expires it
//    (`expired`) and expires it again (`already_expired`).
// 3. `verifyConnectEvent` over checkout.session.completed, checkout.session.expired and
//    account.updated bodies carrying the real objects (read with the same client), each signed with Stripe's own
//    `webhooks.generateTestHeaderString`; plus a live event under the test secret (`wrong_mode`),
//    the same secret in both modes (`invalid`) and a stale signature (`invalid`).
// Every Stripe object id is printed.
import { randomBytes } from "node:crypto";

import Stripe from "stripe";

import {
  STRIPE_API_VERSION,
  StripeCheckoutLinks,
  assertStripeKey,
  checkoutExpiresAt,
  connectAccountCreateParams,
  connectEventAccount,
  createConnectAccount,
  createOnboardingLink,
  fetchStripeClient,
  readConnectStatus,
  stripeErrorDetail,
  verifyConnectEvent,
} from "../../../src/stripe/index.ts";

const LIVE_PREFIX = /^(?:sk|rk)_live_/;

function check(condition: unknown, what: string): asserts condition {
  if (!condition) throw new Error(`PROOF FAILED: ${what}`);
  console.log(`  ok  ${what}`);
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) throw new Error("Refused: pipe a Stripe TEST key on stdin; it is never an argument.");
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8").trim();
}

/** The first test connected account that can take charges, reading every page of the list. */
async function chargeableAccount(key: string, preferred: string | undefined): Promise<string> {
  const client = fetchStripeClient(key, { mode: "test" });
  if (preferred !== undefined) {
    if ((await readConnectStatus(client, { mode: "test", accountId: preferred })).chargesEnabled) return preferred;
    throw new Error("PROOF FAILED: the account named cannot take charges in test mode");
  }
  // The listing only, through the SDK (StripeClientLike has no list): never on the proved path.
  const sdk = new Stripe(key, { apiVersion: STRIPE_API_VERSION, maxNetworkRetries: 1 });
  for await (const summary of sdk.v2.core.accounts.list({ limit: 20 })) {
    if (summary.livemode !== false) throw new Error("PROOF FAILED: the account list answered a live account");
    if ((await readConnectStatus(client, { mode: "test", accountId: summary.id })).chargesEnabled) return summary.id;
  }
  throw new Error("PROOF FAILED: no test connected account can take charges; onboard one in test mode, or name one");
}

async function main(): Promise<void> {
  const key = await readStdin();
  if (LIVE_PREFIX.test(key)) throw new Error("Refused: that is a LIVE Stripe key. This proof runs in test mode only.");
  assertStripeKey(key, "test");
  const named = process.argv[2];
  if (named !== undefined && !/^acct_[A-Za-z0-9]{1,255}$/.test(named)) throw new Error("Refused: the argument must be a connected account id (acct_...)");
  const client = fetchStripeClient(key, { mode: "test" });
  const ids: Record<string, string> = {};
  console.log(`API version: ${STRIPE_API_VERSION}`);

  console.log("\n1. Connect onboarding (Accounts v2)");
  const ref = randomBytes(16).toString("hex");
  const created = await createConnectAccount(client, {
    mode: "test",
    params: connectAccountCreateParams({ country: "CA", metadata: { proof_ref: ref } }),
    idempotencyKey: `district-assurance-proof:${ref}`,
  });
  ids.account = created.accountId;
  check(created.accountId.startsWith("acct_"), `createConnectAccount: ${created.accountId} (chargesEnabled ${created.chargesEnabled})`);
  const link = await createOnboardingLink(client, {
    accountId: created.accountId,
    returnUrl: "https://example.com/return",
    refreshUrl: "https://example.com/refresh",
  });
  check(new URL(link.url).protocol === "https:", `createOnboardingLink: an https link on ${new URL(link.url).host} (the link is not printed)`);
  const status = await readConnectStatus(client, { mode: "test", accountId: created.accountId, timeoutMs: 10_000 });
  check(status.chargesEnabled === false, `readConnectStatus: a new account cannot take charges yet (detailsSubmitted ${status.detailsSubmitted})`);

  console.log("\n2. Checkout on a connected account (StripeCheckoutLinks, endive)");
  const account = await chargeableAccount(key, named);
  ids.checkoutAccount = account;
  console.log(`  checkout account: ${account}`);
  const links = new StripeCheckoutLinks(client, { mode: "test", successUrl: "https://example.com/thanks", modes: ["connect"] });
  const paymentId = `proof-pay-${ref}`;
  const session = await links.createLink({
    callId: `proof-call-${ref}`,
    paymentId,
    amountMinor: 100,
    currency: "cad",
    description: "District Assurance proof (test mode)",
    mode: "connect",
    connectedAccountId: account,
    paymentMethods: ["card"],
    expiresAt: checkoutExpiresAt(new Date(Date.now() + 60_000), 31),
    idempotencyKey: `proof-link:${ref}`,
  });
  ids.checkoutSession = session.linkId;
  check(session.linkId.startsWith("cs_test_"), `createLink: ${session.linkId}`);
  const open = await links.readLink(session.linkId, account);
  check(open.status === "open" && open.paymentStatus === "unpaid", `readLink: ${open.status}/${open.paymentStatus}`);
  const close = { linkId: session.linkId, mode: "connect" as const, connectedAccountId: account };
  const first = await links.expire({ ...close, idempotencyKey: `proof-expire:${ref}` });
  check(first.outcome === "expired", `expire: ${first.outcome}`);
  const again = await links.expire({ ...close, idempotencyKey: `proof-expire-again:${ref}` });
  check(again.outcome === "already_expired", `expire again: ${again.outcome} (idempotent)`);

  console.log("\n3. verifyConnectEvent under Stripe's own test header");
  // Real objects for the event bodies, read raw through the same client and the same scopes the
  // adapters use (no v1 Accounts read, which a host's restricted key need not have).
  const expiredSession = (await client.checkout.sessions.retrieve(session.linkId, {}, { stripeAccount: account })) as Record<string, unknown>;
  const accountObject = (await client.v2.core.accounts.retrieve(created.accountId, { include: ["configuration.merchant", "requirements"] })) as Record<string, unknown>;
  check(expiredSession.livemode === false && accountObject.id === created.accountId, "the objects for the event bodies are test mode");
  const secret = `whsec_${randomBytes(24).toString("hex")}`;
  const now = Math.floor(Date.now() / 1000);
  const body = (type: string, object: unknown, eventAccount: string, livemode = false) =>
    JSON.stringify({ id: `evt_proof_${type.replaceAll(".", "_")}_${now}`, object: "event", api_version: STRIPE_API_VERSION, created: now, type, livemode, account: eventAccount, data: { object } });
  const completed = { ...expiredSession, status: "complete", payment_status: "paid" };
  for (const [type, object, eventAccount] of [
    ["checkout.session.completed", completed, account],
    ["checkout.session.expired", expiredSession, account],
    ["account.updated", accountObject, created.accountId],
  ] as const) {
    const payload = body(type, object, eventAccount);
    const header = Stripe.webhooks.generateTestHeaderString({ payload, secret });
    const verdict = verifyConnectEvent({ payload, header, secrets: { test: secret }, now: new Date() });
    check(verdict.kind === "verified" && verdict.mode === "test" && verdict.event.type === type, `${type}: verified in test mode`);
    check(connectEventAccount(verdict.event, eventAccount) === "match", `${type}: its account is the stored one`);
  }
  const live = body("checkout.session.completed", completed, account, true);
  const liveHeader = Stripe.webhooks.generateTestHeaderString({ payload: live, secret });
  check(verifyConnectEvent({ payload: live, header: liveHeader, secrets: { test: secret }, now: new Date() }).kind === "wrong_mode", "a livemode:true event under the test secret: wrong_mode");
  check(verifyConnectEvent({ payload: live, header: liveHeader, secrets: { test: secret, live: secret }, now: new Date() }).kind === "invalid", "the same secret in both modes: invalid");
  const stale = Stripe.webhooks.generateTestHeaderString({ payload: live, secret, timestamp: now - 3600 });
  check(verifyConnectEvent({ payload: live, header: stale, secrets: { live: secret }, now: new Date() }).kind === "invalid", "a signature an hour old: invalid");

  console.log("\nObject ids (Stripe TEST mode):");
  for (const [name, id] of Object.entries(ids)) console.log(`  ${name}: ${id}`);
  console.log("\nPROOF PASSED");
}

main().catch((err: unknown) => {
  // Our messages and the adapters' errors carry no key and no Stripe message; anything else is named by its class only.
  const e = err as { name?: unknown; message?: unknown };
  const safe = typeof e.message === "string" && (/^(PROOF FAILED|Refused)/.test(e.message) || ["StripeAdapterError", "StripeKeyRefused", "StripeHttpError"].includes(String(e.name)));
  const detail = stripeErrorDetail(err);
  console.error(safe ? String(e.message) : `failed: ${String(e.name ?? "error")} (status ${String(detail.status)}, ${String(detail.type)}, ${String(detail.code)})`);
  process.exit(1);
});
