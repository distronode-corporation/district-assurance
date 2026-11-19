// The Stripe Checkout adapter (PAY-1, test mode only) and the live demo's scripts, against a local
// fake of Stripe's REST API on 127.0.0.1. Nothing here reaches Stripe.
import { strict as assert } from "node:assert";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, describe, it } from "node:test";

import { DemoRuns, type RunView } from "../examples/reference-server/src/demo-runs.ts";
import { e2eConfig, e2eScripts, shortSessionId, startE2eDemo } from "../examples/reference-server/src/e2e.ts";
import { createDemoWorld, startDoorRelay } from "../examples/reference-server/src/script.ts";
import { StripeCheckoutLinks, StripeKeyRefused, assertTestModeSecretKey, checkoutPaymentMethodTypes } from "../examples/reference-server/src/stripe-adapters.ts";
import { systemClock, type PaymentLinkRequest } from "../src/index.ts";

// Made up, shaped like a test key; never a real one.
const KEY = "sk_test_FAKEFAKEFAKEFAKE0123456789";

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
  }
}

const NOW = Date.parse("2026-11-18T12:00:00.000Z");
const clock = { now: () => new Date(NOW) };

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
  it("refuses live, restricted, publishable and malformed keys, never quoting the key", () => {
    const refused = ["sk_live_abcdefgh12345678", "rk_live_abcdefgh12345678", "rk_test_abcdefgh12345678", "pk_test_abcdefgh12345678", "sk_test_", "sk_test_short", "sk_test_has space 123456", "", undefined, 42];
    for (const key of refused) {
      assert.throws(
        () => assertTestModeSecretKey(key),
        (e: unknown) => e instanceof StripeKeyRefused && e.name === "StripeKeyRefused" && (typeof key !== "string" || key.length <= "sk_test_".length || !e.message.includes(key)),
        String(key),
      );
    }
    assert.throws(() => new StripeCheckoutLinks("sk_live_abcdefgh12345678"), /LIVE Stripe key/);
    assert.throws(() => new StripeCheckoutLinks("rk_live_abcdefgh12345678"), /LIVE Stripe key/);
    assert.throws(() => new StripeCheckoutLinks(""), /set STRIPE_TEST_SECRET_KEY/);
    assert.doesNotThrow(() => assertTestModeSecretKey(KEY));
  });

  it("refuses a live key before the demo starts anything", async () => {
    await assert.rejects(startE2eDemo("sk_live_abcdefgh12345678", 0), StripeKeyRefused);
    await assert.rejects(startE2eDemo("rk_live_abcdefgh12345678", 0), StripeKeyRefused);
  });

  it("talks to https only (http to the loopback), with no credentials in the URL", () => {
    assert.throws(() => new StripeCheckoutLinks(KEY, { apiBase: "http://api.stripe.com" }), /apiBase must be https/);
    assert.throws(() => new StripeCheckoutLinks(KEY, { apiBase: "https://u:p@api.stripe.com" }), /carries no credentials/);
    assert.throws(() => new StripeCheckoutLinks(KEY, { successUrl: "http://example.com/" }), /successUrl must be https/);
    assert.doesNotThrow(() => new StripeCheckoutLinks(KEY, { successUrl: "http://127.0.0.1:8787/" }));
    assert.doesNotThrow(() => new StripeCheckoutLinks(KEY));
  });

  it("maps Apple Pay and Google Pay to card, and keeps Link", () => {
    assert.deepEqual(checkoutPaymentMethodTypes(["card", "apple_pay", "google_pay"]), ["card"]);
    assert.deepEqual(checkoutPaymentMethodTypes(["apple_pay", "link"]), ["card", "link"]);
    assert.deepEqual(checkoutPaymentMethodTypes(["link"]), ["link"]);
  });
});

describe("Stripe Checkout adapter against a local fake", () => {
  const fake = new FakeStripe();
  let links: StripeCheckoutLinks;

  before(async () => {
    await fake.start();
    links = new StripeCheckoutLinks(KEY, { apiBase: fake.base, successUrl: "http://127.0.0.1:8787/", clock, timeoutMs: 5000 });
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
      "payment_method_types[0]": "card",
      "expires_at": String(NOW / 1000 + 31 * 60),
      client_reference_id: "pay_1",
      "metadata[payment_id]": "pay_1",
      "metadata[call_id]": "call_1",
      success_url: "http://127.0.0.1:8787/",
    });
  });

  it("charges the connected account in connect mode, and keeps expires_at inside Stripe's window", async () => {
    await links.createLink(request({ mode: "connect", connectedAccountId: "acct_x", paymentMethods: ["card", "link"], expiresAt: new Date(NOW + 2 * 3600_000).toISOString() }));
    await links.createLink(request({ expiresAt: new Date(NOW + 48 * 3600_000).toISOString() }));
    assert.equal(fake.seen[0]!.headers["stripe-account"], "acct_x");
    assert.equal(fake.seen[0]!.form.get("payment_method_types[1]"), "link");
    assert.equal(fake.seen[0]!.form.get("expires_at"), String(NOW / 1000 + 7200), "the engine's deadline, when inside the window");
    assert.equal(fake.seen[1]!.form.get("expires_at"), String(NOW / 1000 + 23 * 3600 + 59 * 60), "never past Stripe's 24 hours");
    const bare = new StripeCheckoutLinks(KEY, { apiBase: fake.base, clock });
    await bare.createLink(request());
    assert.equal(fake.seen[2]!.form.has("success_url"), false);
  });

  it("names the status and Stripe's error type and code, never its message, on a refusal", async () => {
    fake.next = { status: 401, body: JSON.stringify({ error: { type: "invalid_request_error", code: "api_key_invalid", message: `Invalid API Key provided: ${KEY}` } }) };
    await assert.rejects(links.createLink(request()), (e: unknown) => {
      const message = (e as Error).message;
      return message === "Stripe did not create the Checkout Session (HTTP 401, type invalid_request_error, code api_key_invalid)" && !message.includes(KEY);
    });
    fake.next = { status: 500, body: "not json" };
    await assert.rejects(links.createLink(request()), /HTTP 500\)/);
    fake.next = { status: 200, body: "[]" };
    await assert.rejects(links.createLink(request()), /HTTP 200\)/);
    fake.next = { status: 200, body: JSON.stringify({ id: "cs_live_x", url: "https://checkout.stripe.com/x", livemode: false }) };
    await assert.rejects(links.createLink(request()), /did not create/, "a live session id is not an answer to a test key");
    fake.next = { status: 200, body: JSON.stringify({ id: "cs_test_x", url: "http://checkout.stripe.com/x", livemode: false }) };
    await assert.rejects(links.createLink(request()), /did not create/);
    fake.next = { status: 400, body: JSON.stringify({ error: "a string" }) };
    await assert.rejects(links.createLink(request()), /\(HTTP 400\)/);
  });

  it("refuses a live-mode session even from a test key", async () => {
    fake.createLive = true;
    await assert.rejects(links.createLink(request()), /live-mode session/);
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

  it("throws when Stripe refuses to expire a session that is still open, or fails", async () => {
    const open = await links.createLink(request());
    fake.next = { status: 400, body: JSON.stringify({ error: { type: "invalid_request_error" } }) };
    await assert.rejects(links.expireLink({ linkId: open.linkId, mode: "platform", idempotencyKey: "e" }), /did not expire the Checkout Session \(HTTP 400, type invalid_request_error\)/);
    fake.next = { status: 503, body: "{}" };
    await assert.rejects(links.expireLink({ linkId: open.linkId, mode: "platform", idempotencyKey: "e" }), /HTTP 503/);
    await assert.rejects(links.expireLink({ linkId: "cs_test_../../v1/x", mode: "platform", idempotencyKey: "e" }), TypeError);
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
    ]) {
      fake.next = { status: 200, body: JSON.stringify(body) };
      await assert.rejects(links.readLink(open.linkId), /did not answer/);
    }
    fake.next = { status: 404, body: JSON.stringify({ error: { type: "invalid_request_error", code: "resource_missing" } }) };
    await assert.rejects(links.readLink(open.linkId), /HTTP 404/);
    await assert.rejects(async () => links.readLink("cs_live_abc"), TypeError);
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

  async function world(options: Parameters<typeof e2eScripts>[1]) {
    const stripe = new StripeCheckoutLinks(KEY, { apiBase: fake.base });
    const w = createDemoWorld({ payments: stripe, clock: systemClock, config: e2eConfig() });
    const relay = await startDoorRelay(w);
    return { w, relay, runs: new DemoRuns(w, 20, e2eScripts(stripe, options)) };
  }

  it("runs owner-command, then visit: a test-mode link, the payment read back, the door, a receipt", async () => {
    fake.paidAfterReads = 2;
    const lines: string[] = [];
    const { w, relay, runs } = await world({ pollMs: 1, waitMs: 5000, log: (label, detail) => lines.push(`${label} ${detail}`) });
    try {
      assert.deepEqual(runs.flows().map((f) => f.flow), ["owner-command", "visit"]);
      const owner = await runAll(runs, "owner-command");
      assert.ok(owner.results.every((r) => r.ok));
      const visit = await runAll(runs, "visit");
      assert.ok(visit.results.every((r) => r.ok), JSON.stringify(visit.results.filter((r) => !r.ok)));
      const link = visit.results.find((r) => r.link !== undefined)!;
      assert.match(link.detail, /Checkout Session cs_test_fake1\.\.\. created, livemode false, status open/);
      assert.equal(link.link!.href, "https://checkout.stripe.com/c/pay/cs_test_fake1");
      assert.match(visit.results.at(-3)!.detail, /session complete, payment paid, livemode false; settled: true/);
      assert.deepEqual(w.doorOpened, ["door-1"]);
      const receipt = (await w.engine.receipt(visit.callId!))!;
      assert.deepEqual(receipt.body.payments.map((p) => [p.status, p.mode, p.providerRef]), [["paid", "platform", "cs_test_fake1"]]);
      assert.equal(lines.length, owner.results.length + visit.results.length);
      assert.ok(lines.every((line) => !line.includes("https://")), "the terminal never shows the Checkout URL");
      assert.ok(lines.some((line) => line.startsWith("gate: door opened")));
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("reports an expired session and a payment that never comes, and logs a failed check", async () => {
    const lines: string[] = [];
    const { w, relay, runs } = await world({ pollMs: 1, waitMs: 30, log: (label, detail) => lines.push(`${label} ${detail}`) });
    try {
      let visit = await runAll(runs, "visit");
      const wait = visit.results.findIndex((r) => r.label === "pay: test payment read back from Stripe");
      assert.deepEqual([visit.results[wait]!.ok, visit.results[wait]!.detail], [false, "not paid within 0 minutes: start a new run"]);
      assert.ok(lines.some((line) => line.includes("CHECK FAILED: not paid")));
      fake.sessions.get(w.links.at(-1)!.linkId)!.status = "expired";
      const run = await runs.start("visit");
      for (let i = 0; i < 5; i++) await runs.step(run.runId);
      fake.sessions.get(w.links.at(-1)!.linkId)!.status = "expired";
      const answer = await runs.step(run.runId);
      assert.ok(answer.ok);
      visit = answer.view;
      assert.deepEqual([visit.results.at(-1)!.ok, visit.results.at(-1)!.detail], [false, "the session expired unpaid"]);
      // A refusal from Stripe ends the run; the terminal names the status, type and code only.
      fake.next = { status: 400, body: JSON.stringify({ error: { type: "idempotency_error", message: `Keys for idempotent requests ... ${KEY}` } }) };
      const third = await runs.start("visit");
      for (let i = 0; i < 5; i++) await runs.step(third.runId);
      const failed = lines.find((line) => line.includes(") FAILED: "))!;
      assert.equal(failed, "pay: Checkout link created (Stripe test mode) FAILED: Stripe did not create the Checkout Session (HTTP 400, type idempotency_error)");
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("uses its defaults without a log", async () => {
    const stripe = new StripeCheckoutLinks(KEY, { apiBase: fake.base });
    const scripts = e2eScripts(stripe);
    assert.deepEqual(Object.keys(scripts), ["owner-command", "visit"]);
    assert.equal(shortSessionId("cs_test_a1b2c3d4e5f6g7"), "cs_test_a1b2c3...");
  });

  it("starts the server and the door relay on the loopback, and stops them", async () => {
    const demo = await startE2eDemo(KEY, 0, { apiBase: fake.base });
    try {
      const port = (demo.server.address() as AddressInfo).port;
      const res = await fetch(`http://127.0.0.1:${port}/demo/flows`);
      const { flows } = (await res.json()) as { flows: Array<{ flow: string }> };
      assert.deepEqual(flows.map((f) => f.flow), ["owner-command", "visit"]);
      assert.equal(demo.base, "http://127.0.0.1:0");
      assert.equal((demo.relay.address() as AddressInfo).address, "127.0.0.1");
    } finally {
      await demo.close();
    }
    await assert.rejects(
      (async () => {
        const first = await startE2eDemo(KEY, 0, { apiBase: fake.base });
        const port = (first.server.address() as AddressInfo).port;
        try {
          await startE2eDemo(KEY, port, { apiBase: fake.base });
        } finally {
          await first.close();
        }
      })(),
      /EADDRINUSE/,
    );
  });
});
