// district-assurance/stripe: keys and modes, errors, Checkout payment links, Connect onboarding
// and the Connect webhook verifier, against an in-memory StripeClientLike. What Stripe itself
// accepts is proven against Stripe test mode (examples/reference-server/src/stripe-proof.ts); the
// bytes the SDK and fetchStripeClient send are compared in test/stripe-client-bytes.test.ts.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { signStripePayload } from "../src/index.ts";
import {
  CHECKOUT_DEFAULT_LINK_MINUTES,
  CHECKOUT_MAX_LINK_MINUTES,
  CHECKOUT_MIN_LINK_MINUTES,
  STRIPE_API_VERSION,
  STRIPE_BASIL_API_VERSION,
  StripeAdapterError,
  StripeCheckoutLinks,
  StripeHttpError,
  StripeKeyRefused,
  assertStripeKey,
  checkedApiVersion,
  checkoutExpiresAt,
  checkoutPaymentMethodTypes,
  connectAccountCreateParams,
  connectEventAccount,
  connectStatusOf,
  createConnectAccount,
  createOnboardingLink,
  fetchStripeClient,
  readConnectStatus,
  stripeFormEncode,
  stripeErrorDetail,
  stripeIdempotencyKey,
  stripeMetadataCallId,
  verifyConnectEvent,
  type StripeClientLike,
} from "../src/stripe/index.ts";

const NOW = new Date("2026-11-22T12:00:00.000Z");
const ACCT = "acct_1Merchant";
const TEST_SESSION = "cs_test_a1B2";
const LIVE_SESSION = "cs_live_a1B2";
const key = (...parts: string[]) => parts.join("_");

type Fn = (...args: unknown[]) => Promise<unknown>;
interface Calls {
  [name: string]: unknown[][];
}

/** An in-memory StripeClientLike: each method answers from `answers[name]` (a value, or an Error to throw), and records its arguments. */
function fake(answers: Record<string, unknown | unknown[]> = {}): { client: StripeClientLike; calls: Calls } {
  const calls: Calls = {};
  const queues: Record<string, unknown[]> = {};
  for (const [name, value] of Object.entries(answers)) queues[name] = Array.isArray(value) ? [...value] : [value];
  const method =
    (name: string): Fn =>
    async (...args) => {
      (calls[name] ??= []).push(structuredClone(args));
      const queue = queues[name] ?? [];
      const next = queue.length > 1 ? queue.shift() : queue[0];
      if (next instanceof Error || (typeof next === "object" && next !== null && "statusCode" in next)) throw next;
      return next;
    };
  const client = {
    checkout: { sessions: { create: method("create"), retrieve: method("retrieve"), expire: method("expire") } },
    v2: { core: { accounts: { create: method("accountCreate"), retrieve: method("accountRetrieve") }, accountLinks: { create: method("linkCreate") } } },
  } as unknown as StripeClientLike;
  return { client, calls };
}

const session = (over: Record<string, unknown> = {}) => ({ id: TEST_SESSION, url: "https://checkout.stripe.com/c/pay/x", livemode: false, status: "open", payment_status: "unpaid", ...over });
const liveSession = (over: Record<string, unknown> = {}) => session({ id: LIVE_SESSION, livemode: true, ...over });
const refusal = (statusCode: number | null, extra: Record<string, unknown> = {}) => Object.assign(new Error("Stripe says: invalid key sk_test_SECRETSECRET"), { statusCode, rawType: "invalid_request_error", code: "x", ...extra });

const REQUEST = {
  callId: "call_1",
  paymentId: "pay_1",
  amountMinor: 100,
  currency: "cad",
  description: "Deposit",
  mode: "connect" as const,
  connectedAccountId: ACCT,
  paymentMethods: ["card", "link"] as const,
  expiresAt: new Date(NOW.getTime() + 35 * 60_000).toISOString(),
  idempotencyKey: "call_1:pay_1",
};
const CLOSE = { linkId: TEST_SESSION, mode: "connect" as const, connectedAccountId: ACCT, idempotencyKey: "close_1" };

function links(client: StripeClientLike, over: Partial<ConstructorParameters<typeof StripeCheckoutLinks>[1]> = {}) {
  return new StripeCheckoutLinks(client, { mode: "test", successUrl: "https://example.com/thanks", now: () => NOW, ...over });
}

/** Every 6-character window of the key's body: none may appear in a message. */
function assertNoKeyPart(message: string, value: string): void {
  const body = value.replace(/^[a-z]{2}_(test|live)_/, "");
  for (let i = 0; i + 6 <= body.length; i++) assert.ok(!message.includes(body.slice(i, i + 6)), `the message quotes part of the key: ${message}`);
  assert.ok(!message.includes(value), "the message quotes the key");
}

describe("assertStripeKey", () => {
  it("accepts a secret or restricted key of its own mode only", () => {
    for (const k of [key("sk", "test", "abcdefgh12345678"), key("rk", "test", "abcdefgh12345678")]) assert.doesNotThrow(() => assertStripeKey(k, "test"));
    for (const k of [key("sk", "live", "abcdefgh12345678"), key("rk", "live", "abcdefgh12345678")]) assert.doesNotThrow(() => assertStripeKey(k, "live"));
  });

  it("⛔ refuses a live key in test mode and a test key in live mode, by name", () => {
    for (const k of [key("sk", "live", "LIVELIVE12345678"), key("rk", "live", "LIVELIVE12345678")]) {
      assert.throws(() => assertStripeKey(k, "test"), (e: Error) => e instanceof StripeKeyRefused && /LIVE Stripe key in test mode/.test(e.message) && (assertNoKeyPart(e.message, k), true));
    }
    for (const k of [key("sk", "test", "TESTTEST12345678"), key("rk", "test", "TESTTEST12345678")]) {
      assert.throws(() => assertStripeKey(k, "live"), (e: Error) => e instanceof StripeKeyRefused && /TEST Stripe key in live mode/.test(e.message) && (assertNoKeyPart(e.message, k), true));
    }
  });

  it("⛔ refuses publishable keys, webhook secrets, short keys, whitespace and non-strings, never quoting them", () => {
    const bad = [
      key("pk", "test", "PUBLISHABLE12345678"),
      key("pk", "live", "PUBLISHABLE12345678"),
      key("whsec", "WEBHOOKSECRET12345678"),
      key("sk", "test", "short"),
      ` ${key("sk", "test", "PADDEDPADDED12345678")}`,
      `${key("sk", "test", "PADDEDPADDED12345678")}\n`,
      key("sk", "test", "WITH SPACE12345678"),
      key("sk", "test", "TOOLONG".repeat(40)),
      key("sk", "prod", "abcdefgh12345678"),
    ];
    for (const mode of ["test", "live"] as const) {
      for (const k of bad) assert.throws(() => assertStripeKey(k, mode), (e: Error) => e instanceof StripeKeyRefused && (assertNoKeyPart(e.message, k.trim()), true));
      for (const k of [undefined, null, 42, "", {}]) assert.throws(() => assertStripeKey(k, mode), /no Stripe key/);
    }
    assert.throws(() => assertStripeKey(key("sk", "test", "abcdefgh12345678"), "prod" as never), /must be test or live/);
  });

  it("⛔ endive by default; basil in test mode only (the recordings), never in live mode", () => {
    assert.equal(checkedApiVersion("live", undefined), STRIPE_API_VERSION);
    assert.equal(checkedApiVersion("live", STRIPE_API_VERSION), STRIPE_API_VERSION);
    assert.equal(checkedApiVersion("test", STRIPE_BASIL_API_VERSION), STRIPE_BASIL_API_VERSION);
    assert.throws(() => checkedApiVersion("live", STRIPE_BASIL_API_VERSION), StripeKeyRefused);
    assert.throws(() => checkedApiVersion("test", "2024-01-01.acacia" as never), StripeKeyRefused);
    // An unknown mode is refused even on the default version, so no adapter is built in it.
    assert.throws(() => checkedApiVersion("preview" as never, undefined), /must be test or live/);
    assert.throws(() => links(fake().client, { mode: "preview" as never }), /must be test or live/);
    assert.throws(() => links(fake().client, { mode: "live", apiVersion: STRIPE_BASIL_API_VERSION }), /replays test-mode recordings only/);
    assert.throws(() => fetchStripeClient(key("rk", "live", "abcdefgh12345678"), { mode: "live", apiVersion: STRIPE_BASIL_API_VERSION }), StripeKeyRefused);
  });
});

describe("StripeAdapterError", () => {
  it("names the step, status, type and code only, never Stripe's message", () => {
    const e = StripeAdapterError.from("do it", refusal(400, { code: "resource_missing" }));
    assert.equal(e.message, "Stripe did not do it (HTTP 400, invalid_request_error, resource_missing)");
    assert.equal(e.retryable, false);
    assert.ok(!e.message.includes("SECRET"));
    assert.deepEqual(stripeErrorDetail({ statusCode: 402, type: "StripeCardError", code: null }), { status: 402, type: "StripeCardError", code: null });
  });

  it("⛔ never throws on an error object whose fields cannot be read", () => {
    const hostile = Object.defineProperty({}, "statusCode", { get: () => { throw new Error("boom"); } });
    assert.deepEqual(stripeErrorDetail(hostile), { status: null, type: null, code: null });
    assert.equal(StripeAdapterError.from("x", hostile).retryable, true);
  });

  it("drops anything that is not a plain word, and anything shaped like a key", () => {
    assert.deepEqual(stripeErrorDetail({ statusCode: 99, rawType: key("sk", "test", "leak"), code: "with space" }), { status: null, type: null, code: null });
    assert.deepEqual(stripeErrorDetail({ statusCode: 500.5, type: key("whsec", "leak"), code: 7 }), { status: null, type: null, code: null });
    assert.deepEqual(stripeErrorDetail("text"), { status: null, type: null, code: null });
    assert.deepEqual(stripeErrorDetail(null), { status: null, type: null, code: null });
  });

  it("is retryable with no answer, on 429 and on 5xx; not on another 4xx or a malformed answer", () => {
    assert.equal(StripeAdapterError.from("x", new Error("socket hang up")).retryable, true);
    assert.match(StripeAdapterError.from("x", new Error("socket hang up")).message, /no answer/);
    assert.equal(StripeAdapterError.from("x", refusal(429)).retryable, true);
    assert.equal(StripeAdapterError.from("x", refusal(503)).retryable, true);
    assert.equal(StripeAdapterError.from("x", refusal(404)).retryable, false);
    assert.equal(StripeAdapterError.answer("x").retryable, false);
    assert.equal(new StripeAdapterError("x", { status: 200, type: null, code: null }, { retryable: true }).retryable, true);
  });
});

describe("the Checkout helpers", () => {
  it("keeps a plain idempotency key and call id, and hashes the others", () => {
    assert.equal(stripeIdempotencyKey("call_1:pay:1"), "call_1:pay:1");
    assert.match(stripeIdempotencyKey("with space"), /^sha256:[0-9a-f]{64}$/);
    assert.equal(stripeMetadataCallId("call_1"), "call_1");
    assert.match(stripeMetadataCallId("é".repeat(251)), /^sha256:[0-9a-f]{64}$/);
  });

  it("maps wallets to card, keeps link beside cards, and refuses link alone and an empty list", () => {
    assert.deepEqual(checkoutPaymentMethodTypes(["card", "apple_pay", "google_pay", "link"]), ["card", "link"]);
    assert.throws(() => checkoutPaymentMethodTypes(["link"]), TypeError);
    assert.throws(() => checkoutPaymentMethodTypes([]), /at least one payment method/);
  });

  it("defaults a link to Stripe's 30-minute minimum plus a 5-minute dispatch margin, and refuses a life outside 30 minutes to 24 hours", () => {
    assert.equal(CHECKOUT_DEFAULT_LINK_MINUTES, 35);
    assert.equal(checkoutExpiresAt(NOW), new Date(NOW.getTime() + 35 * 60_000).toISOString());
    assert.equal(checkoutExpiresAt(NOW, 30), new Date(NOW.getTime() + 30 * 60_000).toISOString());
    assert.equal(checkoutExpiresAt(NOW, CHECKOUT_MAX_LINK_MINUTES), new Date(NOW.getTime() + 1440 * 60_000).toISOString());
    for (const minutes of [CHECKOUT_MIN_LINK_MINUTES - 1, CHECKOUT_MAX_LINK_MINUTES + 1, 30.5, Number.NaN]) assert.throws(() => checkoutExpiresAt(NOW, minutes), TypeError);
  });
});

describe("StripeCheckoutLinks: create", () => {
  it("creates a direct charge on the connected account, on endive: allowed_payment_method_types and the Stripe-Account header", async () => {
    const { client, calls } = fake({ create: session() });
    assert.deepEqual(await links(client).createLink({ ...REQUEST, paymentMethods: [...REQUEST.paymentMethods] }), { linkId: TEST_SESSION, url: "https://checkout.stripe.com/c/pay/x" });
    const [params, options] = calls.create![0]!;
    assert.deepEqual(options, { stripeAccount: ACCT, idempotencyKey: "call_1:pay_1" });
    assert.deepEqual(params, {
      mode: "payment",
      line_items: [{ quantity: 1, price_data: { currency: "cad", unit_amount: 100, product_data: { name: "Deposit" } } }],
      allowed_payment_method_types: ["card", "link"],
      expires_at: Math.floor(Date.parse(REQUEST.expiresAt) / 1000),
      client_reference_id: "pay_1",
      metadata: { payment_id: "pay_1", call_id: "call_1" },
      success_url: "https://example.com/thanks",
    });
    for (const field of ["payment_method_types", "on_behalf_of", "transfer_data", "payment_intent_data"]) assert.ok(!(field in (params as object)), field);
  });

  it("sends basil's payment_method_types only on basil (test mode), and no account in platform mode", async () => {
    const { client, calls } = fake({ create: session() });
    await links(client, { apiVersion: STRIPE_BASIL_API_VERSION }).createLink({ ...REQUEST, mode: "platform", connectedAccountId: undefined as never, paymentMethods: ["card"] });
    const [params, options] = calls.create![0]! as [Record<string, unknown>, Record<string, unknown>];
    assert.deepEqual(params.payment_method_types, ["card"]);
    assert.ok(!("allowed_payment_method_types" in params));
    assert.deepEqual(options, { idempotencyKey: "call_1:pay_1" });
  });

  it("creates in live mode: cs_live_ with livemode true", async () => {
    const { client } = fake({ create: liveSession() });
    assert.equal((await links(client, { mode: "live" }).createLink({ ...REQUEST, paymentMethods: ["card"] })).linkId, LIVE_SESSION);
  });

  it("⛔ refuses a mode it does not take, platform with an account, and a malformed account, before anything is sent", async () => {
    const { client, calls } = fake({ create: session() });
    const connectOnly = links(client, { modes: ["connect"] });
    assert.deepEqual(connectOnly.capabilities, { modes: ["connect"], minLinkMinutes: 30, maxLinkMinutes: 1440 });
    await assert.rejects(connectOnly.createLink({ ...REQUEST, mode: "platform", connectedAccountId: undefined as never, paymentMethods: ["card"] }), /do not take platform/);
    await assert.rejects(links(client).createLink({ ...REQUEST, mode: "platform", paymentMethods: ["card"] }), /takes no connected account/);
    await assert.rejects(links(client).createLink({ ...REQUEST, connectedAccountId: "acct_x y", paymentMethods: ["card"] }), /acct_/);
    await assert.rejects(links(client).createLink({ ...REQUEST, connectedAccountId: undefined as never, paymentMethods: ["card"] }), /acct_/);
    assert.equal(calls.create, undefined);
  });

  it("⛔ refuses an expiresAt under 30 minutes or over 24 hours from now, or not a time, before anything is sent", async () => {
    const { client, calls } = fake({ create: session() });
    for (const minutes of [29, 1441]) {
      await assert.rejects(links(client).createLink({ ...REQUEST, paymentMethods: ["card"], expiresAt: new Date(NOW.getTime() + minutes * 60_000).toISOString() }), /30 minutes to 24 hours/);
    }
    await assert.rejects(links(client).createLink({ ...REQUEST, paymentMethods: ["card"], expiresAt: "soon" }), /ISO 8601/);
    assert.equal(calls.create, undefined);
    // The edges themselves are accepted.
    for (const minutes of [30, 1440]) {
      await links(client).createLink({ ...REQUEST, paymentMethods: ["card"], expiresAt: new Date(NOW.getTime() + minutes * 60_000).toISOString() });
    }
    // The default clock is the system's.
    await new StripeCheckoutLinks(client, { mode: "test", successUrl: "https://example.com/" }).createLink({ ...REQUEST, paymentMethods: ["card"], expiresAt: checkoutExpiresAt(new Date(Date.now() + 60_000)) });
  });

  for (const [name, answer, mode] of [
    ["a live session in test mode", liveSession(), "test"],
    ["a cs_live_ id answered as test mode", session({ id: LIVE_SESSION }), "test"],
    ["a test session in live mode", session(), "live"],
    ["a cs_test_ id answered as live mode", session({ livemode: true }), "live"],
    ["no URL", session({ url: null }), "test"],
    ["a URL that is not https", session({ url: "http://checkout.stripe.com/x" }), "test"],
    ["no object", null, "test"],
  ] as const) {
    it(`⛔ refuses ${name}`, async () => {
      const { client } = fake({ create: answer });
      await assert.rejects(links(client, { mode }).createLink({ ...REQUEST, paymentMethods: ["card"] }), (e: Error) => e instanceof StripeAdapterError && /mode Checkout Session/.test(e.message));
    });
  }

  it("wraps Stripe's refusal of a create, never quoting its message", async () => {
    const { client } = fake({ create: refusal(400, { code: "parameter_unknown" }) });
    await assert.rejects(links(client).createLink({ ...REQUEST, paymentMethods: ["card"] }), (e: Error) => /parameter_unknown/.test(e.message) && !e.message.includes("SECRET"));
  });

  it("⛔ refuses a success URL that is not https (http only to the loopback), carries credentials or is no URL, and a bad modes list", () => {
    const { client } = fake();
    for (const successUrl of ["http://example.com/", "https://u:p@example.com/", "not a url", 7]) assert.throws(() => links(client, { successUrl: successUrl as string }), TypeError);
    assert.equal(links(client, { successUrl: "http://127.0.0.1:8080/done" }).successUrl, "http://127.0.0.1:8080/done");
    for (const modes of [[], ["refund"]]) assert.throws(() => links(client, { modes: modes as never }), /platform, connect or both/);
  });
});

describe("StripeCheckoutLinks: expire (the host cancels the link when the wait ends)", () => {
  it("expires an open session on the connected account: outcome expired", async () => {
    const { client, calls } = fake({ expire: session({ status: "expired" }) });
    const l = links(client);
    assert.deepEqual(await l.expire(CLOSE), { outcome: "expired", session: { linkId: TEST_SESSION, status: "expired", paymentStatus: "unpaid", livemode: false } });
    // ⛔ No idempotency key: Stripe saves a key's first result, a 500 included, for every retry under it.
    assert.deepEqual(calls.expire![0], [TEST_SESSION, {}, { stripeAccount: ACCT }]);
    assert.equal(calls.retrieve, undefined);
    assert.deepEqual(await l.expireLink(CLOSE), { state: "expired" });
  });

  it("⛔ is idempotent: an already-expired session (Stripe's 400) answers already_expired, never throws", async () => {
    const { client } = fake({ expire: refusal(400), retrieve: session({ status: "expired" }) });
    const l = links(client);
    assert.equal((await l.expire(CLOSE)).outcome, "already_expired");
    assert.equal((await l.expire(CLOSE)).outcome, "already_expired");
    assert.deepEqual(await l.expireLink(CLOSE), { state: "not_open" });
  });

  it("⛔ tells a payment that won the race (complete) from an expire, on a 400 or on a 200 that did not expire", async () => {
    const paid = session({ status: "complete", payment_status: "paid" });
    let { client } = fake({ expire: refusal(400), retrieve: paid });
    assert.deepEqual(await links(client).expire(CLOSE), { outcome: "complete", session: { linkId: TEST_SESSION, status: "complete", paymentStatus: "paid", livemode: false } });
    assert.deepEqual(await links(client).expireLink(CLOSE), { state: "not_open" });
    ({ client } = fake({ expire: paid, retrieve: paid }));
    assert.equal((await links(client).expire(CLOSE)).outcome, "complete");
  });

  it("⛔ reads back an answer that is not this session expired, never claiming the close: already_expired, or still open (retryable from expireLink)", async () => {
    let { client } = fake({ expire: session({ id: "cs_test_other", status: "expired" }), retrieve: session({ status: "expired" }) });
    assert.equal((await links(client).expire(CLOSE)).outcome, "already_expired");
    assert.deepEqual(await links(client).expireLink(CLOSE), { state: "not_open" });
    ({ client } = fake({ expire: session(), retrieve: session() }));
    assert.equal((await links(client).expire(CLOSE)).outcome, "open");
    await assert.rejects(links(client).expireLink(CLOSE), (e: Error) => e instanceof StripeAdapterError && e.retryable && /still open/.test(e.message));
    // Stripe's 400 on a session that still reads open (a refusal, not a closed session): its own, non-retryable error.
    ({ client } = fake({ expire: refusal(400), retrieve: session() }));
    await assert.rejects(links(client).expire(CLOSE), (e: Error) => e instanceof StripeAdapterError && !e.retryable && /HTTP 400/.test(e.message));
  });

  it("⛔ surfaces a 5xx, a 429 or a lost answer as a retryable StripeAdapterError, and another 4xx as not retryable, when the session reads open", async () => {
    for (const [cause, retryable] of [
      [refusal(500), true],
      [refusal(503), true],
      [refusal(429), true],
      [new Error("ECONNRESET"), true],
      [refusal(401), false],
    ] as const) {
      const { client, calls } = fake({ expire: cause, retrieve: session() });
      await assert.rejects(links(client).expire(CLOSE), (e: Error) => e instanceof StripeAdapterError && e.retryable === retryable);
      assert.equal(calls.retrieve!.length, 1, "the session is read back after any failure");
    }
  });

  it("⛔ after a 5xx or a lost answer, reads the session back: a close or a payment that took effect is answered, an unreadable session throws the expire's error", async () => {
    let { client } = fake({ expire: refusal(500), retrieve: session({ status: "expired" }) });
    assert.equal((await links(client).expire(CLOSE)).outcome, "already_expired");
    ({ client } = fake({ expire: new Error("ECONNRESET"), retrieve: session({ status: "complete", payment_status: "paid" }) }));
    assert.equal((await links(client).expire(CLOSE)).outcome, "complete");
    ({ client } = fake({ expire: refusal(502), retrieve: refusal(503) }));
    await assert.rejects(links(client).expire(CLOSE), (e: Error) => e instanceof StripeAdapterError && e.retryable && /expire the Checkout Session \(HTTP 502/.test(e.message));
  });

  it("⛔ refuses a cs_test_ id in live mode and a cs_live_ id in test mode, before anything is sent", async () => {
    const { client, calls } = fake();
    await assert.rejects(links(client, { mode: "live" }).expire(CLOSE), /not a live-mode Checkout Session id/);
    await assert.rejects(links(client, { mode: "live" }).readLink(TEST_SESSION, ACCT), /not a live-mode/);
    await assert.rejects(links(client).expire({ ...CLOSE, linkId: LIVE_SESSION }), /not a test-mode/);
    await assert.rejects(links(client).readLink(7 as never), /not a test-mode/);
    assert.deepEqual(calls, {});
  });

  it("expires a platform session with no Stripe-Account header", async () => {
    const { client, calls } = fake({ expire: session({ status: "expired" }) });
    assert.equal((await links(client).expire({ linkId: TEST_SESSION, mode: "platform", idempotencyKey: "close_2" })).outcome, "expired");
    assert.deepEqual(calls.expire![0]![2], {});
  });

  it("expires and reads in live mode, and refuses a test-mode answer there", async () => {
    let { client } = fake({ expire: liveSession({ status: "expired" }) });
    assert.equal((await links(client, { mode: "live" }).expire({ ...CLOSE, linkId: LIVE_SESSION })).outcome, "expired");
    ({ client } = fake({ expire: liveSession({ status: "expired", livemode: false }), retrieve: liveSession({ status: "expired", livemode: false }) }));
    await assert.rejects(links(client, { mode: "live" }).expire({ ...CLOSE, linkId: LIVE_SESSION }), /answer the live-mode Checkout Session/);
  });
});

describe("StripeCheckoutLinks: readLink", () => {
  it("reads a session on the connected account or the platform, and refuses an answer it cannot trust", async () => {
    const { client, calls } = fake({
      retrieve: [
        session({ status: "complete", payment_status: "paid" }),
        session({ status: "complete", payment_status: "no_payment_required" }),
        session({ id: "cs_test_other" }),
        session({ status: "weird" }),
        session({ payment_status: "weird" }),
        session({ status: "toString" }),
        "text",
      ],
    });
    const l = links(client);
    assert.deepEqual(await l.readLink(TEST_SESSION, ACCT), { linkId: TEST_SESSION, status: "complete", paymentStatus: "paid", livemode: false });
    assert.deepEqual(calls.retrieve![0], [TEST_SESSION, {}, { stripeAccount: ACCT }]);
    assert.equal((await l.readLink(TEST_SESSION)).paymentStatus, "no_payment_required");
    assert.deepEqual(calls.retrieve![1], [TEST_SESSION, {}, {}]);
    for (let i = 0; i < 5; i++) await assert.rejects(l.readLink(TEST_SESSION), StripeAdapterError);
    await assert.rejects(l.readLink(TEST_SESSION, "acct_x y"), /acct_/);
  });

  it("wraps a failed read", async () => {
    const { client } = fake({ retrieve: refusal(502) });
    await assert.rejects(links(client).readLink(TEST_SESSION), (e: Error) => e instanceof StripeAdapterError && e.retryable);
  });
});

describe("Connect onboarding (Accounts v2)", () => {
  const v2 = (over: Record<string, unknown> = {}) => ({ id: ACCT, object: "v2.core.account", livemode: false, configuration: { merchant: { capabilities: {} } }, requirements: { entries: [] }, ...over });
  const due = (status: string, from = "user") => ({ awaiting_action_from: from, minimum_deadline: { status } });

  it("builds the Standard-equivalent create body with the business's own country", () => {
    assert.deepEqual(connectAccountCreateParams({ country: "CA", metadata: { ref: "abc" } }), {
      identity: { country: "CA" },
      dashboard: "full",
      configuration: { merchant: {} },
      defaults: { responsibilities: { fees_collector: "stripe", losses_collector: "stripe" } },
      metadata: { ref: "abc" },
      include: ["configuration.merchant", "requirements"],
    });
    assert.deepEqual(connectAccountCreateParams({ country: "FR" }).metadata, {});
    // An own `__proto__` key (from parsed JSON) is kept as a key, never handed to the prototype setter.
    const parsed = JSON.parse('{"__proto__":"x","ref":"y"}') as Record<string, string>;
    const kept = connectAccountCreateParams({ country: "CA", metadata: parsed }).metadata;
    assert.deepEqual(Object.keys(kept), ["__proto__", "ref"]);
    assert.equal(Object.getPrototypeOf(kept), Object.prototype);
    for (const country of ["ca", "CAN", "", 124]) assert.throws(() => connectAccountCreateParams({ country: country as string }), /alpha-2/);
    for (const metadata of [{ "bad key": "x" }, { ref: "x".repeat(501) }, { ref: 7 }]) assert.throws(() => connectAccountCreateParams({ country: "CA", metadata: metadata as never }), /metadata/);
  });

  it("creates the account once under the host's idempotency key, in its mode", async () => {
    const { client, calls } = fake({ accountCreate: [v2({ requirements: { entries: [due("currently_due")] } }), v2({ livemode: true })] });
    const params = connectAccountCreateParams({ country: "CA" });
    assert.deepEqual(await createConnectAccount(client, { mode: "test", params, idempotencyKey: "acct-1" }), { accountId: ACCT, chargesEnabled: false, detailsSubmitted: false });
    assert.deepEqual(calls.accountCreate![0], [params, { idempotencyKey: "acct-1" }]);
    assert.equal((await createConnectAccount(client, { mode: "live", params, idempotencyKey: "acct-1" })).accountId, ACCT);
  });

  it("⛔ refuses an account in the other mode, a malformed id, and wraps Stripe's refusal", async () => {
    const params = connectAccountCreateParams({ country: "CA" });
    for (const answer of [v2({ livemode: true }), v2({ id: "not-an-account" }), null]) {
      const { client } = fake({ accountCreate: answer });
      await assert.rejects(createConnectAccount(client, { mode: "test", params, idempotencyKey: "k" }), /answer a test-mode connected account/);
    }
    const { client } = fake({ accountCreate: refusal(400, { code: "identity_country_required" }) });
    await assert.rejects(createConnectAccount(client, { mode: "test", params, idempotencyKey: "k" }), /identity_country_required/);
  });

  it("links the owner's browser to Stripe-hosted onboarding, https only", async () => {
    const { client, calls } = fake({
      linkCreate: [
        { account: ACCT, url: "https://connect.stripe.com/setup/s/x" },
        { account: ACCT, url: "http://connect.stripe.com/x" },
        { account: ACCT, url: 7 },
        null,
        { account: "acct_2Other", url: "https://connect.stripe.com/setup/s/other" },
        { url: "https://connect.stripe.com/setup/s/none" },
      ],
    });
    const input = { accountId: ACCT, returnUrl: "https://example.com/r", refreshUrl: "https://example.com/f" };
    assert.deepEqual(await createOnboardingLink(client, input), { url: "https://connect.stripe.com/setup/s/x" });
    assert.deepEqual(calls.linkCreate![0], [{ account: ACCT, use_case: { type: "account_onboarding", account_onboarding: { return_url: input.returnUrl, refresh_url: input.refreshUrl } } }]);
    for (let i = 0; i < 3; i++) await assert.rejects(createOnboardingLink(client, input), /https onboarding link/);
    // ⛔ A bearer link for another account, or for none named, is never handed on.
    for (let i = 0; i < 2; i++) await assert.rejects(createOnboardingLink(client, input), /for the requested account/);
    await assert.rejects(createOnboardingLink(client, { ...input, accountId: "acct_x y" }), /acct_/);
    await assert.rejects(createOnboardingLink(client, { ...input, returnUrl: "http://example.com/r" }), /https/);
    await assert.rejects(createOnboardingLink(fake({ linkCreate: refusal(500) }).client, input), /create the onboarding link/);
  });

  it("re-reads the account's status with the fields included, bounded when asked", async () => {
    const { client, calls } = fake({ accountRetrieve: [v2({ configuration: { merchant: { capabilities: { card_payments: { status: "active" } } } } }), v2({ id: "acct_2Other" }), v2({ livemode: true })] });
    assert.deepEqual(await readConnectStatus(client, { mode: "test", accountId: ACCT, timeoutMs: 10_000 }), { chargesEnabled: true, detailsSubmitted: true });
    assert.deepEqual(calls.accountRetrieve![0], [ACCT, { include: ["configuration.merchant", "requirements"] }, { timeout: 10_000, maxNetworkRetries: 1 }]);
    await assert.rejects(readConnectStatus(client, { mode: "test", accountId: ACCT }), /answer the test-mode connected account/);
    assert.deepEqual(calls.accountRetrieve![1]![2], {});
    await assert.rejects(readConnectStatus(client, { mode: "test", accountId: ACCT }), /answer the test-mode connected account/);
    await assert.rejects(readConnectStatus(client, { mode: "test", accountId: "nope" }), /acct_/);
    await assert.rejects(readConnectStatus(fake({ accountRetrieve: refusal(504) }).client, { mode: "test", accountId: ACCT }), (e: Error) => e instanceof StripeAdapterError && e.retryable);
  });

  it("⛔ a fresh account, as Stripe answers it, has not submitted its details; an onboarded one has", () => {
    // Real test-mode v2 Account shapes (ids replaced, identity and contact removed): test/fixtures/stripe-v2-accounts/.
    const fixture = (name: string): unknown => JSON.parse(readFileSync(new URL(`./fixtures/stripe-v2-accounts/${name}.json`, import.meta.url), "utf8"));
    assert.deepEqual(connectStatusOf(fixture("fresh")), { chargesEnabled: false, detailsSubmitted: false });
    // Onboarded: card payments active; its one requirement left (a bank account, past due) restricts payouts only.
    assert.deepEqual(connectStatusOf(fixture("onboarded")), { chargesEnabled: true, detailsSubmitted: true });
  });

  it("⛔ charges enabled only with card_payments active; details submitted only once a capability is requested and nothing due restricts payments", () => {
    for (const [account, charges] of [
      [{}, false],
      [{ configuration: {} }, false],
      [{ configuration: { merchant: {} } }, false],
      [{ configuration: { merchant: { capabilities: { card_payments: { status: "pending" } } } } }, false],
      [{ configuration: { merchant: { capabilities: { card_payments: { status: "active" } } } } }, true],
      ["text", false],
    ] as const) {
      assert.equal(connectStatusOf(account).chargesEnabled, charges);
    }
    const requested = { configuration: { merchant: { capabilities: { card_payments: { status: "pending" }, ach_debit_payments: null } } } };
    const restricts = (capability: string, configuration = "merchant") => ({ restricts_capabilities: [{ capability, configuration, deadline: { status: "past_due" } }] });
    for (const [requirements, submitted] of [
      [null, false],
      [undefined, false],
      [{}, false],
      [{ entries: "none" }, false],
      [{ entries: [] }, true],
      [{ entries: [due("currently_due")] }, false],
      [{ entries: [due("eventually_due"), due("past_due")] }, false],
      [{ entries: [due("eventually_due")] }, true],
      [{ entries: [due("currently_due", "stripe")] }, true],
      [{ entries: ["x", { awaiting_action_from: "user" }] }, true],
      [{ entries: [{ ...due("past_due"), impact: restricts("stripe_balance.payouts") }] }, true],
      [{ entries: [{ ...due("past_due"), impact: restricts("card_payments") }] }, false],
      [{ entries: [{ ...due("currently_due"), impact: restricts("bancontact_payments") }] }, false],
      [{ entries: [{ ...due("currently_due"), impact: restricts("card_payments", "customer") }] }, true],
      [{ entries: [{ ...due("currently_due"), impact: { restricts_capabilities: ["x"] } }] }, false],
      [{ entries: [{ ...due("currently_due"), impact: { restricts_capabilities: [{ configuration: "merchant", capability: 7 }] } }] }, true],
      [{ entries: [{ ...due("currently_due"), impact: {} }] }, false],
    ] as const) {
      assert.equal(connectStatusOf({ ...requested, requirements }).detailsSubmitted, submitted, JSON.stringify(requirements));
    }
    // ⛔ Nothing requested yet (null, empty, or no status): not submitted, however empty the requirements.
    for (const capabilities of [null, {}, { card_payments: null }, { card_payments: { status: 7 } }]) {
      assert.equal(connectStatusOf({ configuration: { merchant: { capabilities } }, requirements: { entries: [] } }).detailsSubmitted, false, JSON.stringify(capabilities));
    }
  });
});

describe("verifyConnectEvent", () => {
  const TEST_SECRET = "whsec_test_connect";
  const LIVE_SECRET = "whsec_live_connect";
  const t = Math.floor(NOW.getTime() / 1000);
  const body = (over: Record<string, unknown> = {}) =>
    JSON.stringify({ id: "evt_1", object: "event", type: "checkout.session.completed", livemode: false, account: ACCT, data: { object: { id: TEST_SESSION } }, ...over });
  const verify = (payload: string, header: string, secrets: { test?: string | string[]; live?: string | string[] } = { test: TEST_SECRET, live: LIVE_SECRET }, extra: { now?: Date; toleranceSeconds?: number } = {}) =>
    verifyConnectEvent({ payload, header, secrets, now: extra.now ?? NOW, ...(extra.toleranceSeconds === undefined ? {} : { toleranceSeconds: extra.toleranceSeconds }) });

  it("verifies a test event under the test secret and a live event under the live secret", () => {
    const test = verify(body(), signStripePayload(body(), TEST_SECRET, t));
    assert.equal(test.kind, "verified");
    assert.ok(test.kind === "verified" && test.mode === "test" && test.event.account === ACCT && test.event.data.object.id === TEST_SESSION);
    const live = verify(body({ livemode: true }), signStripePayload(body({ livemode: true }), LIVE_SECRET, t));
    assert.ok(live.kind === "verified" && live.mode === "live");
    // Bytes verify too, and a rolled secret list.
    const bytes = new TextEncoder().encode(body());
    assert.equal(verifyConnectEvent({ payload: bytes, header: signStripePayload(body(), TEST_SECRET, t), secrets: { test: ["whsec_old", TEST_SECRET] }, now: NOW }).kind, "verified");
  });

  it("⛔ a test-secret-verified event with livemode true is wrong_mode, and the reverse too", () => {
    assert.ok(verify(body({ livemode: true }), signStripePayload(body({ livemode: true }), TEST_SECRET, t)).kind === "wrong_mode");
    const reverse = verify(body(), signStripePayload(body(), LIVE_SECRET, t));
    assert.ok(reverse.kind === "wrong_mode" && reverse.mode === "live");
  });

  it("⛔ refuses as invalid a signature BOTH modes' secrets verify (the same secret set in both)", () => {
    assert.deepEqual(verify(body(), signStripePayload(body(), TEST_SECRET, t), { test: TEST_SECRET, live: TEST_SECRET }), { kind: "invalid" });
    assert.deepEqual(verify(body(), signStripePayload(body(), TEST_SECRET, t), { test: TEST_SECRET, live: ["whsec_x", TEST_SECRET] }), { kind: "invalid" });
  });

  it("⛔ holds Stripe's timestamp tolerance at its edge, and refuses a replay of a very old event", () => {
    assert.equal(verify(body(), signStripePayload(body(), TEST_SECRET, t - 300)).kind, "verified");
    assert.equal(verify(body(), signStripePayload(body(), TEST_SECRET, t - 301)).kind, "invalid");
    assert.equal(verify(body(), signStripePayload(body(), TEST_SECRET, t + 301)).kind, "invalid");
    assert.equal(verify(body(), signStripePayload(body(), TEST_SECRET, t - 86_400 * 365)).kind, "invalid");
    assert.equal(verify(body(), signStripePayload(body(), TEST_SECRET, t - 10), undefined, { toleranceSeconds: 5 }).kind, "invalid");
  });

  it("⛔ is invalid under another secret, over a tampered body, or with no header; unconfigured with no secret", () => {
    assert.deepEqual(verify(body(), signStripePayload(body(), "whsec_other", t)), { kind: "invalid" });
    assert.deepEqual(verify(body({ account: "acct_2Other" }), signStripePayload(body(), TEST_SECRET, t)), { kind: "invalid" });
    assert.deepEqual(verify(body(), ""), { kind: "invalid" });
    assert.deepEqual(verify(body(), signStripePayload(body(), TEST_SECRET, t), {}), { kind: "unconfigured" });
    assert.deepEqual(verify(body(), signStripePayload(body(), TEST_SECRET, t), { test: "", live: [""] }), { kind: "unconfigured" });
  });

  it("⛔ is malformed when signed but not a Stripe event it can read", () => {
    for (const payload of [
      "not json",
      "[]",
      body({ object: "charge" }),
      body({ id: "e1" }),
      body({ type: "" }),
      body({ livemode: "false" }),
      body({ data: null }),
      body({ data: { object: [] } }),
      body({ account: "acct_x y" }),
      body({ account: 7 }),
    ]) {
      const verdict = verify(payload, signStripePayload(payload, TEST_SECRET, t));
      assert.deepEqual(verdict, { kind: "malformed", mode: "test" }, payload);
    }
    const invalidUtf8 = new Uint8Array([0x7b, 0xff, 0x7d]);
    const header = `t=${t},v1=${signStripePayload("", TEST_SECRET, t).split("v1=")[1]}`;
    assert.equal(verifyConnectEvent({ payload: invalidUtf8, header, secrets: { test: TEST_SECRET }, now: NOW }).kind, "invalid");
  });

  it("reads a platform event's account as null", () => {
    const payload = body({ account: undefined });
    const verdict = verify(payload, signStripePayload(payload, TEST_SECRET, t));
    assert.ok(verdict.kind === "verified" && verdict.event.account === null);
  });
});

describe("connectEventAccount", () => {
  it("⛔ matches only the stored acct_ id itself", () => {
    assert.equal(connectEventAccount({ account: ACCT }, ACCT), "match");
    assert.equal(connectEventAccount({ account: ACCT }, "acct_2Other"), "mismatch");
    assert.equal(connectEventAccount({ account: ACCT }, null), "mismatch");
    assert.equal(connectEventAccount({ account: ACCT }, "not an account"), "mismatch");
    assert.equal(connectEventAccount({ account: null }, ACCT), "missing");
  });
});

describe("stripeFormEncode", () => {
  it("encodes as stripe-node does: indexed arrays, bracketed keys, null as empty, undefined left out", () => {
    assert.equal(stripeFormEncode({ a: null, b: undefined, c: [1, undefined, true], d: { e: "x y!*'()" } }), "a=&c[0]=1&c[2]=true&d[e]=x%20y%21%2A%27%28%29");
  });
});

describe("fetchStripeClient", () => {
  const KEY = key("rk", "test", "FETCHFETCH0123456789");
  type Seen = { url: string; init: RequestInit };

  function stub(responses: Array<Response | Error>): { fetch: typeof fetch; seen: Seen[] } {
    const seen: Seen[] = [];
    return {
      seen,
      fetch: (async (url: URL, init: RequestInit) => {
        seen.push({ url: String(url), init });
        const next = responses.shift()!;
        if (next instanceof Error) throw next;
        return next;
      }) as unknown as typeof fetch,
    };
  }
  const json = (status: number, value: unknown) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });

  it("checks the key, the version, the base and the timeout before any client exists", () => {
    assert.throws(() => fetchStripeClient(key("sk", "live", "abcdefgh12345678"), { mode: "test" }), StripeKeyRefused);
    assert.throws(() => fetchStripeClient(KEY, { mode: "test", apiBase: "http://api.stripe.com" }), /https/);
    assert.throws(() => fetchStripeClient(KEY, { mode: "test", apiBase: "https://u:p@api.stripe.com" }), /no credentials/);
    assert.throws(() => fetchStripeClient(KEY, { mode: "test", apiBase: "nope" }), /https/);
    for (const timeoutMs of [0, 60_001, 1.5]) assert.throws(() => fetchStripeClient(KEY, { mode: "test", timeoutMs }), /timeoutMs/);
    assert.doesNotThrow(() => fetchStripeClient(KEY, { mode: "test", apiBase: "http://localhost:1", timeoutMs: 1 }));
  });

  it("sends the key, the version, the account and the idempotency key, and answers the JSON object", async () => {
    const { fetch: f, seen } = stub([json(200, { id: TEST_SESSION })]);
    const client = fetchStripeClient(KEY, { mode: "test", fetch: f, timeoutMs: 500 });
    assert.deepEqual(await client.checkout.sessions.expire(TEST_SESSION, {}, { stripeAccount: ACCT, idempotencyKey: "k", timeout: 100 }), { id: TEST_SESSION });
    const [{ url, init }] = seen as [Seen];
    assert.equal(url, `https://api.stripe.com/v1/checkout/sessions/${TEST_SESSION}/expire`);
    assert.equal(init.redirect, "error");
    assert.deepEqual(init.headers, {
      authorization: `Bearer ${KEY}`,
      "stripe-version": STRIPE_API_VERSION,
      "stripe-account": ACCT,
      "idempotency-key": "k",
      "content-type": "application/x-www-form-urlencoded",
    });
    assert.equal(init.body, "");
  });

  it("sends a v2 body as JSON and a GET with no query when there is none", async () => {
    const { fetch: f, seen } = stub([json(200, { id: ACCT }), json(200, { id: TEST_SESSION }), json(200, { url: "https://x" })]);
    const client = fetchStripeClient(KEY, { mode: "test", fetch: f, apiVersion: STRIPE_BASIL_API_VERSION });
    await client.v2.core.accounts.retrieve(ACCT);
    await client.checkout.sessions.retrieve(TEST_SESSION);
    await client.v2.core.accountLinks.create({ account: ACCT, use_case: { type: "account_onboarding", account_onboarding: { return_url: "https://a", refresh_url: "https://b" } } });
    assert.equal(seen[0]!.url, `https://api.stripe.com/v2/core/accounts/${ACCT}`);
    assert.equal(seen[1]!.init.body, undefined);
    assert.equal((seen[1]!.init.headers as Record<string, string>)["stripe-version"], STRIPE_BASIL_API_VERSION);
    assert.equal((seen[2]!.init.headers as Record<string, string>)["content-type"], "application/json");
    assert.match(String(seen[2]!.init.body), /^\{"account":"acct_1Merchant"/);
  });

  it("⛔ throws StripeHttpError with the status, type and code only, never Stripe's message", async () => {
    const { fetch: f } = stub([
      json(400, { error: { type: "invalid_request_error", code: "resource_missing", message: `No such key ${KEY}` } }),
      json(500, { error: { type: "api_error", code: "Has Space" } }),
      new Response("<html>bad gateway</html>", { status: 502 }),
      json(200, ["not", "an", "object"]),
      new Error(`connect ECONNREFUSED https://api.stripe.com?key=${KEY}`),
    ]);
    const client = fetchStripeClient(KEY, { mode: "test", fetch: f });
    const expectError = async (status: number | null, type: string | null, code: string | null) => {
      await assert.rejects(client.checkout.sessions.retrieve(TEST_SESSION), (e: Error) => {
        assert.ok(e instanceof StripeHttpError);
        assert.deepEqual([e.statusCode, e.rawType, e.code], [status, type, code]);
        assertNoKeyPart(e.message, KEY);
        return true;
      });
    };
    await expectError(400, "invalid_request_error", "resource_missing");
    await expectError(500, "api_error", null);
    await expectError(502, null, null);
    await expectError(200, "malformed_response", null);
    await expectError(null, null, null);
    const { fetch: leaky } = stub([json(400, { error: { type: "sk_test_abcdefgh12345678", code: "rk_live_abcdefgh12345678" } }), json(400, { error: { type: "invalid_request_error", code: "whsec_abcdefgh" } })]);
    const leakyClient = fetchStripeClient(KEY, { mode: "test", fetch: leaky });
    for (let i = 0; i < 2; i++) {
      await assert.rejects(leakyClient.checkout.sessions.retrieve(TEST_SESSION), (e: Error) => {
        assert.ok(e instanceof StripeHttpError && e.code === null && (e.rawType === null || e.rawType === "invalid_request_error"));
        return true;
      });
    }
    assert.equal(StripeAdapterError.from("read", new StripeHttpError(null, null, null)).retryable, true);
  });

  it("⛔ refuses an object id that is not letters, digits and underscores through the returned promise, before anything is sent", async () => {
    const { fetch: f, seen } = stub([]);
    const client = fetchStripeClient(KEY, { mode: "test", fetch: f });
    const pending = [
      client.checkout.sessions.retrieve("../v1/charges"),
      client.checkout.sessions.expire("cs_test_x/../y"),
      client.v2.core.accounts.retrieve("acct_1 2"),
    ];
    for (const p of pending) await assert.rejects(p, /letters, digits/);
    assert.equal(seen.length, 0);
  });

  it("asks a read again after a lost answer, up to maxNetworkRetries (at most 2), and never a write or a cancelled read", async () => {
    let { fetch: f, seen } = stub([new Error("ECONNRESET"), json(200, { id: ACCT })]);
    let client = fetchStripeClient(KEY, { mode: "test", fetch: f });
    assert.deepEqual(await client.v2.core.accounts.retrieve(ACCT, { include: ["requirements"] }, { maxNetworkRetries: 1, timeout: 50 }), { id: ACCT });
    assert.equal(seen.length, 2);
    ({ fetch: f, seen } = stub([new Error("a"), new Error("b"), new Error("c"), new Error("d")]));
    client = fetchStripeClient(KEY, { mode: "test", fetch: f });
    await assert.rejects(client.checkout.sessions.retrieve(TEST_SESSION, {}, { maxNetworkRetries: 9 }), StripeHttpError);
    assert.equal(seen.length, 3, "at most two retries");
    ({ fetch: f, seen } = stub([new Error("a"), json(200, {})]));
    client = fetchStripeClient(KEY, { mode: "test", fetch: f });
    await assert.rejects(client.checkout.sessions.expire(TEST_SESSION, {}, { maxNetworkRetries: 2 }), StripeHttpError);
    assert.equal(seen.length, 1, "a write is never asked again here");
    ({ fetch: f, seen } = stub([new Error("a"), json(200, {})]));
    client = fetchStripeClient(KEY, { mode: "test", fetch: f });
    const cancelled = new AbortController();
    cancelled.abort();
    await assert.rejects(client.checkout.sessions.retrieve(TEST_SESSION, {}, { maxNetworkRetries: 2, signal: cancelled.signal }), StripeHttpError);
    assert.equal(seen.length, 1, "a cancelled read is not asked again");
    ({ fetch: f, seen } = stub([new Error("a"), json(200, {})]));
    client = fetchStripeClient(KEY, { mode: "test", fetch: f });
    await assert.rejects(client.checkout.sessions.retrieve(TEST_SESSION, {}, { maxNetworkRetries: -1 }), StripeHttpError);
    assert.equal(seen.length, 1);
  });
});
