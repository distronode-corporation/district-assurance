// The Stripe Checkout adapter (PAY-1, test mode only) and the live demo's scripts, against a local
// fake of Stripe's REST API on 127.0.0.1. Nothing here reaches Stripe.
import { strict as assert } from "node:assert";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, describe, it } from "node:test";

import { DemoRuns, type RunView } from "../examples/reference-server/src/demo-runs.ts";
import { e2eConfig, e2eScripts, shortSessionId, startE2eDemo } from "../examples/reference-server/src/e2e.ts";
import { createDemoWorld } from "../examples/reference-server/src/script.ts";
import { StripeKeyRefused, assertTestModeSecretKey, stripeMetadataCallId, testModeCheckout } from "../examples/reference-server/src/stripe-adapters.ts";
import { STRIPE_API_VERSION, StripeAdapterError, checkoutPaymentMethodTypes, type StripeCheckoutLinks } from "../src/stripe/index.ts";
import { systemClock, type Clock, type PaymentLinkRequest } from "../src/index.ts";

// Made up, shaped like a test key; never a real one.
// Joined at run time so no scanner mistakes this file for a leaked key.
const KEY = ["sk", "test", "FAKEFAKEFAKEFAKE0123456789"].join("_");

interface Seen {
  method: string;
  path: string;
  headers: IncomingMessage["headers"];
  form: URLSearchParams;
}

interface FakeSession {
  id: string;
  status: "open" | "complete" | "expired";
  payment_status: "paid" | "unpaid";
  livemode: boolean;
  url: string;
  /** Reads left before it turns complete and paid; -1 never. */
  paidAfterReads: number;
}

/** A fake of the four Checkout endpoints the adapter uses. `next` overrides the next answer. */
class FakeStripe {
  seen: Seen[] = [];
  sessions = new Map<string, FakeSession>();
  next: { status: number; body: string } | null = null;
  paidAfterReads = -1;
  createLive = false;
  /** The payer pays just as the demo closes the page. */
  payOnExpire = false;
  /** Overrides the next GET only: an answer, or "drop" (a body lost on the way). */
  nextGet: { status: number; body: string } | "drop" | null = null;
  #n = 0;
  server: Server;
  base = "";

  constructor() {
    this.server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const url = new URL(req.url!, "http://x");
        this.seen.push({ method: req.method!, path: url.pathname, headers: req.headers, form: new URLSearchParams(Buffer.concat(chunks).toString("utf8")) });
        const send = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(typeof body === "string" ? body : JSON.stringify(body));
        if (this.next !== null) {
          const next = this.next;
          this.next = null;
          return send(next.status, next.body);
        }
        if (req.method === "GET" && this.nextGet !== null) {
          const next = this.nextGet;
          this.nextGet = null;
          if (next === "drop") {
            // Headers, then the connection drops before the promised body arrives.
            res.writeHead(200, { "content-type": "application/json", "content-length": "500" });
            res.write("{");
            return void res.socket?.destroy();
          }
          return send(next.status, next.body);
        }
        if (req.method === "POST" && url.pathname === "/v1/checkout/sessions") {
          const id = `cs_test_fake${++this.#n}`;
          const session: FakeSession = { id, status: "open", payment_status: "unpaid", livemode: this.createLive, url: `https://checkout.stripe.com/c/pay/${id}`, paidAfterReads: this.paidAfterReads };
          this.sessions.set(id, session);
          return send(200, session);
        }
        const one = /^\/v1\/checkout\/sessions\/([^/]+)(\/expire)?$/.exec(url.pathname);
        const session = one === null ? undefined : this.sessions.get(one[1]!);
        if (session === undefined) return send(404, { error: { type: "invalid_request_error", code: "resource_missing" } });
        if (req.method === "POST" && one![2] !== undefined) {
          if (this.payOnExpire) Object.assign(session, { status: "complete", payment_status: "paid" });
          if (session.status !== "open") return send(400, { error: { type: "invalid_request_error", message: "Only Checkout Sessions with a status in [open] can be expired." } });
          session.status = "expired";
          return send(200, session);
        }
        if (req.method === "GET" && one![2] === undefined) {
          if (session.paidAfterReads === 0) Object.assign(session, { status: "complete", payment_status: "paid" });
          if (session.paidAfterReads > 0) session.paidAfterReads--;
          return send(200, session);
        }
        return send(405, {});
      });
    });
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    this.base = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  reset(): void {
    this.seen = [];
    this.next = null;
    this.paidAfterReads = -1;
    this.createLive = false;
    this.payOnExpire = false;
    this.nextGet = null;
  }
}

const NOW = Date.parse("2026-11-18T12:00:00.000Z");
const RETURN = "http://127.0.0.1:8787/";

/** A port nothing listens on now. */
async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

function request(overrides: Partial<PaymentLinkRequest> = {}): PaymentLinkRequest {
  return {
    callId: "call_1",
    paymentId: "pay_1",
    amountMinor: 2500,
    currency: "cad",
    description: "Visit deposit",
    mode: "platform",
    paymentMethods: ["card", "apple_pay", "google_pay"],
    expiresAt: new Date(NOW + 30 * 60_000).toISOString(),
    idempotencyKey: "idem_1",
    ...overrides,
  };
}

describe("Stripe Checkout adapter: test-mode keys only", () => {
  it("refuses live, publishable and malformed keys, never quoting the key (a restricted TEST key is accepted)", () => {
    assert.doesNotThrow(() => assertTestModeSecretKey("rk_test_abcdefgh12345678"));
    const refused = ["sk_live_abcdefgh12345678", "rk_live_abcdefgh12345678", "pk_test_abcdefgh12345678", "sk_test_", "sk_test_short", "sk_test_has space 123456", "", undefined, 42];
    for (const key of refused) {
      assert.throws(
        () => assertTestModeSecretKey(key),
        (e: unknown) => e instanceof StripeKeyRefused && e.name === "StripeKeyRefused" && (typeof key !== "string" || key.length <= "sk_test_".length || !e.message.includes(key)),
        String(key),
      );
    }
    assert.throws(() => testModeCheckout("sk_live_abcdefgh12345678", { successUrl: RETURN }), /LIVE Stripe key/);
    assert.throws(() => testModeCheckout("rk_live_abcdefgh12345678", { successUrl: RETURN }), /LIVE Stripe key/);
    assert.throws(() => testModeCheckout("", { successUrl: RETURN }), /set STRIPE_TEST_SECRET_KEY/);
    assert.doesNotThrow(() => assertTestModeSecretKey(KEY));
  });

  it("refuses a live key before the demo starts anything", async () => {
    await assert.rejects(startE2eDemo("sk_live_abcdefgh12345678", 0), StripeKeyRefused);
    await assert.rejects(startE2eDemo("rk_live_abcdefgh12345678", 0), StripeKeyRefused);
    for (const port of [0, -1, 1.5, 65_536]) await assert.rejects(startE2eDemo(KEY, port), RangeError);
  });

  it("talks to https only (http to the loopback), with no credentials in the URL", () => {
    assert.throws(() => testModeCheckout(KEY, { apiBase: "http://api.stripe.com", successUrl: RETURN }), /apiBase must be https/);
    assert.throws(() => testModeCheckout(KEY, { apiBase: "https://u:p@api.stripe.com", successUrl: RETURN }), /carries no credentials/);
    assert.throws(() => testModeCheckout(KEY, { successUrl: "http://example.com/" }), /successUrl must be https/);
    assert.throws(() => testModeCheckout(KEY, {} as never), TypeError, "a hosted page needs a return URL");
    assert.doesNotThrow(() => testModeCheckout(KEY, { successUrl: "https://example.com/done" }));
    const links = testModeCheckout(KEY, { successUrl: RETURN });
    assert.deepEqual(links.capabilities, { modes: ["platform", "connect"], minLinkMinutes: 30, maxLinkMinutes: 1440 });
  });

  it("maps Apple Pay and Google Pay to card, and keeps Link, which Checkout takes only beside card", () => {
    assert.deepEqual(checkoutPaymentMethodTypes(["card", "apple_pay", "google_pay"]), ["card"]);
    assert.deepEqual(checkoutPaymentMethodTypes(["apple_pay", "link"]), ["card", "link"]);
    assert.throws(() => checkoutPaymentMethodTypes(["link"]), /Link only beside cards/);
  });
});

describe("Stripe Checkout adapter against a local fake", () => {
  const fake = new FakeStripe();
  let links: StripeCheckoutLinks;

  before(async () => {
    await fake.start();
    links = testModeCheckout(KEY, { apiBase: fake.base, successUrl: RETURN, timeoutMs: 5000, now: () => new Date(NOW) });
  });
  after(() => new Promise<void>((resolve) => fake.server.close(() => resolve())));
  beforeEach(() => fake.reset());

  it("creates a Checkout Session in payment mode on the platform's account", async () => {
    const link = await links.createLink(request());
    assert.match(link.linkId, /^cs_test_fake\d+$/);
    assert.equal(link.url, `https://checkout.stripe.com/c/pay/${link.linkId}`);
    const [seen] = fake.seen;
    assert.equal(seen!.method, "POST");
    assert.equal(seen!.path, "/v1/checkout/sessions");
    assert.equal(seen!.headers.authorization, `Bearer ${KEY}`);
    assert.equal(seen!.headers["idempotency-key"], "idem_1");
    assert.equal(seen!.headers["stripe-account"], undefined, "platform mode: the platform's own account");
    assert.equal(seen!.headers["content-type"], "application/x-www-form-urlencoded");
    assert.deepEqual(Object.fromEntries(seen!.form), {
      mode: "payment",
      "line_items[0][quantity]": "1",
      "line_items[0][price_data][currency]": "cad",
      "line_items[0][price_data][unit_amount]": "2500",
      "line_items[0][price_data][product_data][name]": "Visit deposit",
      "allowed_payment_method_types[0]": "card",
      "expires_at": String(NOW / 1000 + 30 * 60),
      client_reference_id: "pay_1",
      "metadata[payment_id]": "pay_1",
      "metadata[call_id]": "call_1",
      success_url: "http://127.0.0.1:8787/",
    });
  });

  it("sends Stripe-Account for a connected account, and the same parameters on a retry", async () => {
    await links.createLink(request({ mode: "connect", connectedAccountId: "acct_x", paymentMethods: ["card", "link"], expiresAt: new Date(NOW + 2 * 3600_000).toISOString() }));
    assert.equal(fake.seen[0]!.headers["stripe-account"], "acct_x");
    assert.equal(fake.seen[0]!.form.get("allowed_payment_method_types[1]"), "link");
    assert.equal(fake.seen[0]!.form.get("payment_method_types[1]"), null, "endive took payment_method_types away");
    assert.equal(fake.seen[0]!.form.get("expires_at"), String(NOW / 1000 + 7200), "the engine's expiresAt, unchanged");
    // A retry under the same idempotency key, later: the same body, so Stripe answers the first Session.
    fake.next = { status: 500, body: "{}" };
    await assert.rejects(links.createLink(request()));
    await links.createLink(request());
    assert.equal(fake.seen[1]!.form.toString(), fake.seen[2]!.form.toString());
    assert.equal(fake.seen[1]!.headers["idempotency-key"], fake.seen[2]!.headers["idempotency-key"]);
  });

  it("names the status and Stripe's error type and code, never its message, on a refusal", async () => {
    fake.next = { status: 401, body: JSON.stringify({ error: { type: "invalid_request_error", code: "api_key_invalid", message: `Invalid API Key provided: ${KEY}` } }) };
    await assert.rejects(links.createLink(request()), (e: unknown) => {
      const message = (e as Error).message;
      return (
        e instanceof StripeAdapterError &&
        e.name === "StripeAdapterError" &&
        e.status === 401 &&
        !e.retryable &&
        message === "Stripe did not create the Checkout Session (HTTP 401, invalid_request_error, api_key_invalid)" &&
        !message.includes(KEY)
      );
    });
    fake.next = { status: 429, body: "{}" };
    await assert.rejects(links.createLink(request()), (e: unknown) => e instanceof StripeAdapterError && e.retryable);
    fake.next = { status: 500, body: "not json" };
    await assert.rejects(links.createLink(request()), /HTTP 500\)/);
    fake.next = { status: 200, body: "[]" };
    await assert.rejects(links.createLink(request()), /HTTP 200, malformed_response\)/);
    fake.next = { status: 200, body: JSON.stringify({ id: "cs_live_x", url: "https://checkout.stripe.com/x", livemode: false }) };
    await assert.rejects(links.createLink(request()), /answer a test-mode Checkout Session/, "a live session id is not an answer to a test key");
    fake.next = { status: 200, body: JSON.stringify({ id: "cs_test_x", url: "http://checkout.stripe.com/x", livemode: false }) };
    await assert.rejects(links.createLink(request()), /answer a test-mode Checkout Session/);
    fake.next = { status: 400, body: JSON.stringify({ error: "a string" }) };
    await assert.rejects(links.createLink(request()), /\(HTTP 400\)/);
  });

  it("refuses a live-mode session even from a test key", async () => {
    fake.createLive = true;
    await assert.rejects(links.createLink(request()), /answer a test-mode Checkout Session/);
  });

  it("expires an open session, and answers not_open for one that is no longer open", async () => {
    const open = await links.createLink(request());
    assert.deepEqual(await links.expireLink({ linkId: open.linkId, mode: "platform", idempotencyKey: "e1" }), { state: "expired" });
    const expire = fake.seen.find((s) => s.path.endsWith("/expire"))!;
    assert.equal(expire.method, "POST");
    assert.equal(expire.headers["idempotency-key"], "e1");
    assert.deepEqual(await links.expireLink({ linkId: open.linkId, mode: "platform", idempotencyKey: "e2" }), { state: "not_open" });
    const connect = await links.createLink(request({ mode: "connect", connectedAccountId: "acct_x" }));
    fake.sessions.get(connect.linkId)!.status = "complete";
    fake.seen = [];
    assert.deepEqual(await links.expireLink({ linkId: connect.linkId, mode: "connect", connectedAccountId: "acct_x", idempotencyKey: "e3" }), { state: "not_open" });
    assert.deepEqual(fake.seen.map((s) => [s.method, s.headers["stripe-account"]]), [["POST", "acct_x"], ["GET", "acct_x"]]);
  });

  it("throws (retryable) when Stripe refuses to expire a session that is still open, or fails", async () => {
    const open = await links.createLink(request());
    fake.next = { status: 400, body: JSON.stringify({ error: { type: "invalid_request_error" } }) };
    await assert.rejects(
      links.expireLink({ linkId: open.linkId, mode: "platform", idempotencyKey: "e" }),
      (e: unknown) => e instanceof StripeAdapterError && e.retryable && /still open/.test(e.message),
    );
    fake.next = { status: 503, body: "{}" };
    await assert.rejects(links.expireLink({ linkId: open.linkId, mode: "platform", idempotencyKey: "e" }), (e: unknown) => e instanceof StripeAdapterError && e.retryable && /HTTP 503/.test(e.message));
    await assert.rejects(links.expireLink({ linkId: "cs_test_../../v1/x", mode: "platform", idempotencyKey: "e" }), TypeError);
  });

  it("expires only on Stripe's own word: a 200 that is not this session, expired, in test mode, is read back (L1 review round 2)", async () => {
    for (const patch of [null, { id: "cs_test_other" }, { status: "open" }, { livemode: true }]) {
      const open = await links.createLink(request());
      const body = patch === null ? "{}" : JSON.stringify({ id: open.linkId, status: "expired", livemode: false, ...patch });
      const expire = (key: string) => {
        fake.next = { status: 200, body };
        return links.expireLink({ linkId: open.linkId, mode: "platform", idempotencyKey: key });
      };
      // Still open when read back: the close is not established, and asking again may establish it.
      await assert.rejects(expire("a"), (e: unknown) => e instanceof StripeAdapterError && e.retryable && /still open/.test((e as Error).message), body);
      fake.sessions.get(open.linkId)!.status = "expired";
      assert.deepEqual(await expire("b"), { state: "expired" }, body);
      fake.sessions.get(open.linkId)!.status = "complete";
      assert.deepEqual(await expire("c"), { state: "not_open" }, body);
    }
  });

  it("refuses a Checkout URL that opens nothing, bounds the call id in metadata, and pins the API version (L1 review round 2)", async () => {
    fake.next = { status: 200, body: JSON.stringify({ id: "cs_test_x", url: "https://", livemode: false }) };
    await assert.rejects(links.createLink(request()), /answer a test-mode Checkout Session/);
    const long = "c".repeat(501);
    await links.createLink(request({ callId: long }));
    assert.equal(fake.seen.at(-1)!.form.get("metadata[call_id]"), stripeMetadataCallId(long));
    assert.match(fake.seen.at(-1)!.form.get("metadata[call_id]")!, /^sha256:[0-9a-f]{64}$/);
    const open = await links.createLink(request());
    await links.readLink(open.linkId);
    await links.expireLink({ linkId: open.linkId, mode: "platform", idempotencyKey: "v" });
    for (const seen of fake.seen) assert.equal(seen.headers["stripe-version"], STRIPE_API_VERSION, `${seen.method} ${seen.path}`);
  });

  it("reads a session back, read only, and refuses an answer it cannot trust", async () => {
    const open = await links.createLink(request());
    fake.seen = [];
    assert.deepEqual(await links.readLink(open.linkId), { linkId: open.linkId, status: "open", paymentStatus: "unpaid", livemode: false });
    assert.equal(fake.seen[0]!.method, "GET");
    assert.equal(fake.seen[0]!.headers["idempotency-key"], undefined);
    assert.equal(fake.seen[0]!.headers["content-type"], undefined);
    for (const body of [
      { id: "cs_test_other", status: "open", payment_status: "paid", livemode: false },
      { id: open.linkId, status: "weird", payment_status: "paid", livemode: false },
      { id: open.linkId, status: "open", payment_status: "weird", livemode: false },
      { id: open.linkId, status: "open", payment_status: "paid", livemode: "no" },
      { id: open.linkId, status: "complete", payment_status: "paid", livemode: true },
    ]) {
      fake.next = { status: 200, body: JSON.stringify(body) };
      await assert.rejects(links.readLink(open.linkId), /did not answer/);
    }
    fake.next = { status: 404, body: JSON.stringify({ error: { type: "invalid_request_error", code: "resource_missing" } }) };
    await assert.rejects(links.readLink(open.linkId), /HTTP 404/);
    await assert.rejects(async () => links.readLink("cs_live_abc"), TypeError);
  });

  it("connect mode names a well-formed connected account and platform mode none, before anything is sent", async () => {
    fake.seen = [];
    const connect = { mode: "connect", connectedAccountId: "acct_1Business" } as const;
    await assert.rejects(links.createLink(request({ mode: "connect" })), /connect mode needs a connected account id/);
    await assert.rejects(links.createLink(request({ mode: "platform", connectedAccountId: "acct_x" })), /platform mode takes no connected account/);
    // Never a header built from anything but an account id: no line break, no other characters.
    for (const bad of ["acct_x\r\nx-evil: 1", "acct_", "cus_x", "acct_x y", `acct_${"a".repeat(256)}`]) {
      await assert.rejects(links.createLink(request({ ...connect, connectedAccountId: bad })), TypeError);
      await assert.rejects(links.expireLink({ linkId: "cs_test_x", mode: "connect", connectedAccountId: bad, idempotencyKey: "e" }), TypeError);
      await assert.rejects(links.readLink("cs_test_x", bad), TypeError);
    }
    await assert.rejects(links.expireLink({ linkId: "cs_test_x", mode: "connect", idempotencyKey: "e" }), /needs a connected account id/);
    await assert.rejects(links.expireLink({ linkId: "cs_test_x", mode: "platform", connectedAccountId: "acct_x", idempotencyKey: "e" }), /takes no connected account/);
    // Link alone: Checkout refuses it (recorded in test/fixtures/stripe-real/), so it is never sent.
    await assert.rejects(links.createLink(request({ ...connect, paymentMethods: ["link"] })), /Link only beside cards/);
    assert.equal(fake.seen.length, 0, "nothing reached Stripe");
    // Created, read and expired on the connected account: each with its Stripe-Account header.
    const link = await links.createLink(request(connect));
    await links.readLink(link.linkId, connect.connectedAccountId);
    await links.expireLink({ linkId: link.linkId, ...connect, idempotencyKey: "c" });
    assert.deepEqual(fake.seen.map((seen) => seen.headers["stripe-account"]), ["acct_1Business", "acct_1Business", "acct_1Business"]);
  });
});

describe("the live demo's scripts (e2e.ts) on the fake", () => {
  const fake = new FakeStripe();
  before(() => fake.start());
  after(() => new Promise<void>((resolve) => fake.server.close(() => resolve())));
  beforeEach(() => fake.reset());

  async function runAll(runs: DemoRuns, flow: string): Promise<RunView> {
    const run = await runs.start(flow);
    let answer = await runs.step(run.runId);
    while (answer.ok && !answer.view.done) answer = await runs.step(run.runId);
    assert.ok(answer.ok);
    return answer.view;
  }

  async function world(options: Parameters<typeof e2eScripts>[1], clock: Clock = systemClock) {
    const stripe = testModeCheckout(KEY, { apiBase: fake.base, successUrl: RETURN, now: () => clock.now() });
    const w = createDemoWorld({ payments: stripe, clock, config: e2eConfig() });
    await w.relayUrl();
    const relay = { close: (done: () => void) => void w.close().then(done) };
    return { w, relay, runs: new DemoRuns(w, 20, e2eScripts(stripe, options)) };
  }

  const WAIT = "pay: test payment read back from Stripe";

  it("runs owner-command, then visit: a test-mode link, the payment read back, the door, a receipt", async () => {
    fake.paidAfterReads = 2;
    const lines: string[] = [];
    const { w, relay, runs } = await world({ pollMs: 1, waitMs: 5000, log: (label, detail) => lines.push(`${label} ${detail}`) });
    try {
      assert.deepEqual(runs.flows().map((f) => f.flow), ["owner-command", "visit"]);
      assert.equal(runs.hasFlow("deposit-connect"), false, "not in this config");
      const owner = await runAll(runs, "owner-command");
      assert.ok(owner.results.every((r) => r.ok));
      const visit = await runAll(runs, "visit");
      assert.ok(visit.results.every((r) => r.ok), JSON.stringify(visit.results.filter((r) => !r.ok)));
      const link = visit.results.find((r) => r.link !== undefined)!;
      assert.match(link.detail, /Checkout Session cs_test_fake1\.\.\. created, livemode false, status open/);
      assert.equal(link.link!.href, "https://checkout.stripe.com/c/pay/cs_test_fake1");
      assert.match(visit.results.at(-3)!.detail, /session complete, payment paid, livemode false; settled: true/);
      assert.match(visit.results.at(-2)!.detail, /delivered, door moved: true, opened door-1$/);
      assert.deepEqual(w.doorsOpened, ["door-1"]);
      const receipt = (await w.engine.receipt(visit.callId!))!;
      assert.deepEqual(receipt.body.payments.map((p) => [p.status, p.mode, p.providerRef]), [["paid", "platform", "cs_test_fake1"]]);
      assert.equal(lines.length, owner.results.length + visit.results.length);
      assert.ok(lines.every((line) => !line.includes("https://")), "the terminal never shows the Checkout URL");
      assert.ok(lines.some((line) => line.startsWith("gate: door opened")));
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("asks again after a lost read or a busy Stripe, and stops at a refusal", async () => {
    const lines: string[] = [];
    const { relay, runs } = await world({ pollMs: 1, waitMs: 5000, log: (label, detail) => lines.push(`${label} ${detail}`) });
    try {
      fake.paidAfterReads = 1;
      const run = await runs.start("visit");
      for (let i = 0; i < 3; i++) await runs.step(run.runId);
      fake.next = { status: 503, body: "{}" };
      let answer = await runs.step(run.runId);
      assert.ok(answer.ok);
      assert.deepEqual([answer.view.results.at(-1)!.label, answer.view.results.at(-1)!.ok], [WAIT, true]);
      const second = await runs.start("visit");
      for (let i = 0; i < 3; i++) await runs.step(second.runId);
      fake.next = { status: 401, body: JSON.stringify({ error: { type: "authentication_error" } }) };
      answer = await runs.step(second.runId);
      assert.ok(answer.ok);
      assert.deepEqual([answer.view.results.at(-1)!.detail, answer.view.done], ["failed: internal error", true]);
      assert.ok(lines.includes(`${WAIT} FAILED: Stripe did not read the Checkout Session (HTTP 401, authentication_error)`));
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("asks again after a body lost on the way, on the first read and while polling", async () => {
    const { relay, runs } = await world({ pollMs: 1, waitMs: 5000 });
    try {
      const run = await runs.start("visit");
      for (let i = 0; i < 2; i++) await runs.step(run.runId);
      fake.nextGet = "drop";
      let answer = await runs.step(run.runId);
      assert.ok(answer.ok);
      assert.deepEqual([answer.view.results.at(-1)!.ok, answer.view.done], [true, false], "the link step read again after the lost body");
      fake.sessions.get([...fake.sessions.keys()].at(-1)!)!.paidAfterReads = 1;
      fake.nextGet = "drop";
      answer = await runs.step(run.runId);
      assert.ok(answer.ok);
      assert.match(answer.view.results.at(-1)!.detail, /session complete, payment paid/);
      // A body that arrived but is not JSON is Stripe's answer, not a lost read: the step ends.
      const second = await runs.start("visit");
      for (let i = 0; i < 3; i++) await runs.step(second.runId);
      fake.nextGet = { status: 200, body: "not json" };
      answer = await runs.step(second.runId);
      assert.ok(answer.ok);
      assert.deepEqual([answer.view.results.at(-1)!.detail, answer.view.done], ["failed: internal error", true]);
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("never sleeps past the end of the wait, however long the poll interval (L1 review round 2)", { timeout: 10_000 }, async () => {
    const { relay, runs } = await world({ pollMs: 600_000, waitMs: 30 });
    try {
      const started = Date.now();
      const visit = await runAll(runs, "visit");
      assert.ok(Date.now() - started < 5000, "stopped at the end of the wait, not after a poll interval");
      assert.equal(visit.results.at(-1)!.ok, false);
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("ends the run on a payment that does not come, and on a session that expired, before any door", async () => {
    const lines: string[] = [];
    const { w, relay, runs } = await world({ pollMs: 1, waitMs: 30, log: (label, detail) => lines.push(`${label} ${detail}`) });
    try {
      let visit = await runAll(runs, "visit");
      assert.deepEqual([visit.results.at(-1)!.label, visit.results.at(-1)!.ok, visit.results.at(-1)!.detail], [WAIT, false, "not paid in time: the Checkout page is closed, start a new run"]);
      // The wait ended before the link's deadline: the page is closed at Stripe all the same (L1 review round 2).
      assert.equal(fake.sessions.get(w.links.at(-1)!.linkId)!.status, "expired");
      assert.equal(visit.done, true, "a failed check ends the run: no door step after it");
      assert.deepEqual(await runs.step(visit.runId), { ok: false, status: 409, error: "done" });
      assert.deepEqual(w.doorsOpened, []);
      assert.ok(lines.some((line) => line.includes("CHECK FAILED: not paid")));
      const run = await runs.start("visit");
      for (let i = 0; i < 3; i++) await runs.step(run.runId);
      fake.sessions.get(w.links.at(-1)!.linkId)!.status = "expired";
      const answer = await runs.step(run.runId);
      assert.ok(answer.ok);
      visit = answer.view;
      assert.deepEqual([visit.results.at(-1)!.ok, visit.results.at(-1)!.detail], [false, "the session expired unpaid"]);
      // A refusal from Stripe ends the run; the terminal names the status, type and code only.
      fake.next = { status: 400, body: JSON.stringify({ error: { type: "idempotency_error", message: `Keys for idempotent requests ... ${KEY}` } }) };
      const third = await runs.start("visit");
      for (let i = 0; i < 3; i++) await runs.step(third.runId);
      const failed = lines.find((line) => line.includes(") FAILED: "))!;
      assert.equal(failed, "pay: Checkout link created (Stripe test mode) FAILED: Stripe did not create the Checkout Session (HTTP 400, idempotency_error)");
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("closes the Checkout page at the engine's deadline, and settles a payment made just then", async () => {
    let offset = 0;
    const clock: Clock = { now: () => new Date(Date.now() + offset) };
    const { w, relay, runs } = await world({ pollMs: 1 }, clock);
    try {
      const run = await runs.start("visit");
      for (let i = 0; i < 3; i++) await runs.step(run.runId);
      // The engine's deadline (the text plus 15 minutes) is already behind it.
      offset = 20 * 60_000;
      const closed = await runs.step(run.runId);
      assert.ok(closed.ok);
      assert.deepEqual([closed.view.results.at(-1)!.ok, closed.view.results.at(-1)!.detail], [false, "not paid in time: the Checkout page is closed, start a new run"]);
      assert.equal(fake.sessions.get(w.links.at(-1)!.linkId)!.status, "expired");
      assert.deepEqual((await w.engine.state(closed.view.callId!)).paymentIds.length, 1);

      offset = 0;
      const late = await runs.start("visit");
      for (let i = 0; i < 3; i++) await runs.step(late.runId);
      offset = 20 * 60_000;
      fake.payOnExpire = true;
      const paid = await runs.step(late.runId);
      assert.ok(paid.ok);
      assert.match(paid.view.results.at(-1)!.detail, /session complete, payment paid, livemode false; settled: true/);
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("uses its defaults without a log, and stops a waiting step when told to", async () => {
    const stripe = testModeCheckout(KEY, { apiBase: fake.base, successUrl: RETURN });
    const scripts = e2eScripts(stripe);
    assert.deepEqual(Object.keys(scripts), ["owner-command", "visit"]);
    assert.equal(shortSessionId("cs_test_a1b2c3d4e5f6g7"), "cs_test_a1b2c3...");
    const stop = new AbortController();
    const { relay, runs } = await world({ pollMs: 60_000, signal: stop.signal });
    try {
      const run = await runs.start("visit");
      for (let i = 0; i < 3; i++) await runs.step(run.runId);
      const waiting = runs.step(run.runId);
      setTimeout(() => stop.abort(), 50);
      const answer = await waiting;
      assert.ok(answer.ok);
      assert.deepEqual([answer.view.results.at(-1)!.ok, answer.view.results.at(-1)!.detail], [false, "stopped: the demo is shutting down"]);
      // Once stopped, a new run's Stripe read is cancelled at once: the link step ends the run.
      const next = await runs.start("visit");
      for (let i = 0; i < 2; i++) await runs.step(next.runId);
      const after = await runs.step(next.runId);
      assert.ok(after.ok);
      assert.deepEqual([after.view.results.at(-1)!.label, after.view.done], ["pay: Checkout link created (Stripe test mode)", true]);
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("starts the server and the door relay on the loopback, and a waiting payment does not hold up the stop", async () => {
    const port = await freePort();
    const demo = await startE2eDemo(KEY, port, { apiBase: fake.base, pollMs: 60_000 });
    let waiting: Promise<Response> | undefined;
    try {
      assert.equal(demo.base, `http://127.0.0.1:${port}`);
      const { flows } = (await (await fetch(`${demo.base}/demo/flows`)).json()) as { flows: Array<{ flow: string }> };
      assert.deepEqual(flows.map((f) => f.flow), ["owner-command", "visit"]);
      assert.match(demo.relayUrl, /^http:\/\/127\.0\.0\.1:\d+\/unlock$/);
      const json = { "content-type": "application/json" };
      const run = (await (await fetch(`${demo.base}/demo/runs`, { method: "POST", headers: json, body: JSON.stringify({ flow: "visit" }) })).json()) as { runId: string };
      const next = () => fetch(`${demo.base}/demo/runs/${run.runId}/next`, { method: "POST", headers: json, body: "{}" });
      for (let i = 0; i < 3; i++) assert.equal((await next()).status, 200);
      assert.equal(fake.seen.find((s) => s.method === "POST")!.form.get("success_url"), `${demo.base}/`);
      const reads = fake.seen.filter((s) => s.method === "GET").length;
      waiting = next();
      // Close only once the payment step is polling (its first read reached the fake).
      const deadline = Date.now() + 5000;
      while (fake.seen.filter((s) => s.method === "GET").length === reads && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
      assert.ok(fake.seen.filter((s) => s.method === "GET").length > reads, "the payment step polled");
    } finally {
      await demo.close();
    }
    const stopped = await waiting!;
    assert.equal(stopped.status, 200, "answered when the demo stopped");
    const view = (await stopped.json()) as { results: Array<{ detail: string }> };
    assert.equal(view.results.at(-1)!.detail, "stopped: the demo is shutting down");
    await assert.rejects(
      (async () => {
        const first = await startE2eDemo(KEY, await freePort(), { apiBase: fake.base });
        try {
          await startE2eDemo(KEY, (first.server.address() as AddressInfo).port, { apiBase: fake.base });
        } finally {
          await first.close();
        }
      })(),
      /EADDRINUSE/,
    );
  });
});
