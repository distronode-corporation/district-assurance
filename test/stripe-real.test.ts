// VER-5 and PAY-1 against Stripe test mode: the runs test/fixtures/stripe-real/record.ts recorded
// through the reference server's own adapters and webhook routes, redacted, replayed here offline.
// Each replay makes the same request the recording made (checked field by field), gets Stripe's
// recorded answer, then posts Stripe's recorded event body to the same route the real delivery
// reached, and the engine applies it as it did then. The real deliveries were signed by Stripe and
// verified at recording time; redaction changes the bytes, so the replay signs the redacted body
// with a test secret. No request leaves the machine.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { createReferenceServer } from "../examples/reference-server/src/app.ts";
import { createServe } from "../examples/reference-server/src/main.ts";
import { createDemoWorld, type DemoWorld } from "../examples/reference-server/src/script.ts";
import { STRIPE_API_VERSION, StripeCheckoutLinks, checkoutPaymentMethodTypes } from "../examples/reference-server/src/stripe-adapters.ts";
import { signStripePayload, systemClock } from "../src/index.ts";
import { recordedConfig, requestRecordedLink } from "./fixtures/stripe-real/flows.ts";
import { Redactor, leaks } from "./fixtures/stripe-real/redact.ts";

const SECRET = "whsec_test_replay_not_a_secret";
/** The Connect endpoint's own signing secret, as Stripe gives each endpoint one. */
const CONNECT_SECRET = "whsec_test_replay_connect_not_a_secret";
// Made up, shaped like a test key; joined at run time so no scanner mistakes it for a leaked key.
const KEY = ["sk", "test", "REPLAYREPLAYREPLAY0123456789"].join("_");
const FILES = ["identity.json", "checkout-platform.json", "checkout-connect.json", "checkout-connect-link.json", "methods.json", "recording.json"] as const;
const text = (name: string): string => readFileSync(new URL(`./fixtures/stripe-real/${name}`, import.meta.url), "utf8");

interface Exchange {
  method: string;
  path: string;
  headers: { "stripe-version": string | null; "stripe-account": string | null; "idempotency-key": boolean };
  form: Array<[string, string]>;
  status: number;
  body: string;
}
interface Delivery {
  listener: "account" | "connect";
  route: "identity" | "payments" | "connect";
  type: string;
  objectId: string;
  body: string;
  signatureVerified: boolean;
  answer: { status: number; body: unknown };
}
interface Run {
  exchanges: Exchange[];
  delivery: Delivery;
  flowStatus?: string;
  engineEvents?: string[];
}

const recording = JSON.parse(text("recording.json")) as { recordedOn: string; stripeVersionPinned: string; eventApiVersion: string; account: string };
const identity = JSON.parse(text("identity.json")) as Run;
const runs: Record<"record-platform" | "record-connect", Run> = {
  "record-platform": JSON.parse(text("checkout-platform.json")) as Run,
  "record-connect": JSON.parse(text("checkout-connect.json")) as Run,
};
/** The success URL the recording's Checkout sessions named (a loopback page of that run). */
const RETURN = runs["record-platform"].exchanges[0]!.form.find(([name]) => name === "success_url")![1];
const connectLink = JSON.parse(text("checkout-connect-link.json")) as { exchanges: Exchange[]; cancelStatus: string };
const methods = JSON.parse(text("methods.json")) as { account: string; refused: Array<{ types: string[]; status: number; error: Record<string, unknown> }> };

/** Posts `body` to `url`, signed now with the endpoint's secret (the Connect one on the Connect route), as Stripe signs a delivery. */
async function deliver(url: string, body: string, secret = url.endsWith("/connect") ? CONNECT_SECRET : SECRET): Promise<{ status: number; body: unknown }> {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", "stripe-signature": signStripePayload(body, secret, Math.floor(Date.now() / 1000)) }, body });
  return { status: res.status, body: await res.json() };
}

function listen(server: Server): Promise<string> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

function close(server: Server): Promise<void> {
  server.closeAllConnections();
  return new Promise((resolve) => server.close(() => resolve()));
}

describe("the recorded Stripe test-mode runs: what was kept", () => {
  it("holds no key, secret, real Stripe id or hosted page path", () => {
    for (const name of FILES) assert.deepEqual(leaks(text(name)), [], name);
  });

  it("was made in test mode on one connected account, each delivery signed by Stripe and verified when it arrived", () => {
    assert.equal(recording.stripeVersionPinned, STRIPE_API_VERSION);
    assert.match(recording.recordedOn, /^\d{4}-\d{2}-\d{2}$/);
    assert.equal(methods.account, recording.account);
    for (const run of [identity, runs["record-platform"], runs["record-connect"]]) {
      assert.equal(run.delivery.signatureVerified, true);
      const event = JSON.parse(run.delivery.body) as { livemode: boolean; api_version: string; data: { object: { livemode: boolean } } };
      assert.equal(event.livemode, false);
      assert.equal(event.data.object.livemode, false);
      assert.equal(event.api_version, recording.eventApiVersion);
      for (const exchange of run.exchanges) assert.equal(exchange.headers["stripe-version"], STRIPE_API_VERSION, "every request pins the API version");
    }
  });
});

describe("the redactor the recording used", () => {
  it("gives one id one placeholder everywhere, keeps the prefix, and removes keys, secrets, page paths and display names", () => {
    const r = new Redactor();
    const id = ["acct", "1AbCdEfGhIjKlMn0"].join("_");
    const session = ["cs", "test", "a1B2c3D4e5F6g7H8"].join("_");
    const key = ["sk", "test", "abc123"].join("_");
    const page = `https://checkout.stripe.com/c/pay/${session}#fidkdWxOYHwnPyd1blpxYHZxWjA0`;
    const out = r.text(JSON.stringify({ a: id, b: [id, session], k: key, secret: `${session}_secret_Zz9`, page, display_name: "A Business" }));
    assert.deepEqual(JSON.parse(out), {
      a: "acct_redacted0001",
      b: ["acct_redacted0001", "cs_test_redacted0001"],
      k: "[removed]",
      secret: "[removed]",
      page: "https://checkout.stripe.com/redacted",
      display_name: "[redacted]",
    });
    assert.equal(r.id(id), "acct_redacted0001", "the same placeholder on a second file");
    assert.deepEqual(r.json({ nested: `{\\"display_name\\": \\"Inner\\"}` }), { nested: `{\\"display_name\\": \\"[redacted]\\"}` });
  });

  it("finds a leak: a key, a webhook secret, an unredacted id, a page path", () => {
    const found = leaks(["sk", "live", "abc"].join("_") + " " + ["whsec", "abc"].join("_") + " " + ["pi", "3AbCdEfGhIjK1"].join("_") + " https://verify.stripe.com/start/x acct_redacted0001");
    assert.equal(found.length, 4);
  });
});

describe("VER-5: Stripe Identity, the recorded test-mode run replayed through `npm run serve`'s trial call", () => {
  const seen: Array<{ url: string; init: RequestInit }> = [];
  const printed: string[] = [];
  let serve: ReturnType<typeof createServe>;
  let base = "";

  before(async () => {
    const [create] = identity.exchanges;
    serve = createServe({
      env: { STRIPE_IDENTITY_KEY: "rk_test_replayNotASecret", STRIPE_IDENTITY_WEBHOOK_SECRET: SECRET },
      stripe: {
        apiBase: "https://api.stripe.com",
        fetch: async (url, init) => {
          seen.push({ url: String(url), init: init! });
          return new Response(create!.body, { status: create!.status, headers: { "content-type": "application/json" } });
        },
      },
      print: (line) => printed.push(line),
      log: () => undefined,
    });
    base = await listen(serve.server);
  });
  after(() => close(serve.server));

  it("creates the check with the request the recording sent, and gets Stripe's session", async () => {
    const [create] = identity.exchanges;
    assert.equal(identity.exchanges.length, 1);
    const trial = await serve.startTrialCall!();
    const session = JSON.parse(create!.body) as { id: string; status: string; type: string; options: unknown; livemode: boolean };
    assert.equal(trial.sessionId, session.id);
    assert.deepEqual([session.status, session.type, session.livemode], ["requires_input", "document", false]);
    assert.deepEqual(session.options, { document: { require_matching_selfie: true } });
    const [request] = seen;
    assert.equal(request!.url, `https://api.stripe.com${create!.path}`);
    assert.equal(request!.init.method, create!.method);
    // The call id differs (the recording used ids of its own run, so Stripe saw a fresh idempotency key); the rest is the same.
    const sentForm = [...new URLSearchParams(String(request!.init.body))];
    const callIdOf = (form: Array<[string, string]>) => form.find(([name]) => name === "metadata[call_id]")?.[1];
    assert.equal(callIdOf(sentForm), trial.callId);
    assert.match(callIdOf(create!.form)!, /^call_run[a-z0-9]+_\d+$/);
    const withoutCallId = (form: Array<[string, string]>) => form.filter(([name]) => name !== "metadata[call_id]");
    assert.deepEqual(withoutCallId(sentForm), withoutCallId(create!.form));
    assert.equal(sentForm.length, create!.form.length);
    const headers = request!.init.headers as Record<string, string>;
    assert.equal(headers["stripe-version"], create!.headers["stripe-version"]);
    assert.equal(typeof headers["idempotency-key"], "string");
    // The text with the single-use link went to the stand-in phone only.
    assert.ok(printed.some((line) => line.startsWith("stand-in phone +15555550100 received: ") && line.includes("https://verify.stripe.com/redacted")));
  });

  it("applies Stripe's recorded `verified` event on the identity webhook, as it did live, once", async () => {
    assert.equal(identity.delivery.listener, "account");
    assert.equal(identity.delivery.route, "identity");
    assert.equal(identity.delivery.type, "identity.verification_session.verified");
    assert.deepEqual(await deliver(`${base}/webhooks/stripe/identity`, identity.delivery.body), identity.delivery.answer);
    assert.deepEqual(identity.delivery.answer, { status: 200, body: { received: true, applied: true } });
    // The engine's events for the trial, without the call id: the same lines the live run printed.
    const events = printed.filter((line) => !line.startsWith("stand-in phone")).map((line) => line.replace(/^\S+ /, ""));
    assert.deepEqual(events, identity.engineEvents);
    assert.equal(events.at(-1), 'verification.factor {"kind":"photo_id","passed":true,"status":"verified"}');
    assert.deepEqual(await deliver(`${base}/webhooks/stripe/identity`, identity.delivery.body), { status: 200, body: { received: true, duplicate: true } });
  });
});

/** A fake of Stripe's Checkout endpoint answering one recorded exchange, and keeping what it was sent. */
class ReplayStripe {
  readonly seen: Array<{ method: string; path: string; headers: IncomingMessage["headers"]; form: Array<[string, string]> }> = [];
  answer: Exchange | null = null;
  readonly server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c: Buffer) => (raw += c.toString()));
    req.on("end", () => {
      this.seen.push({ method: req.method!, path: req.url!, headers: req.headers, form: [...new URLSearchParams(raw)] });
      res.writeHead(this.answer!.status, { "content-type": "application/json" }).end(this.answer!.body);
    });
  });
}

describe("PAY-1: Stripe Checkout, the recorded test-mode runs replayed through the engine and the reference server", () => {
  const stripe = new ReplayStripe();
  let world: DemoWorld;
  let server: Server;
  let base = "";

  before(async () => {
    const apiBase = await listen(stripe.server);
    world = createDemoWorld({ payments: new StripeCheckoutLinks(KEY, { apiBase, successUrl: RETURN }), config: recordedConfig(recording.account) });
    server = createReferenceServer({ engine: world.engine, clock: systemClock, stripeSecrets: { identity: [], payments: [SECRET], connect: [CONNECT_SECRET] }, log: () => undefined });
    base = await listen(server);
  });
  after(async () => {
    await Promise.all([close(server), close(stripe.server), world.close()]);
  });

  /** The parameters that change with every call (its ids and the clock); everything else must match. */
  const VOLATILE = new Set(["expires_at", "client_reference_id", "metadata[payment_id]", "metadata[call_id]"]);
  const stable = (form: Array<[string, string]>) => form.filter(([name]) => !VOLATILE.has(name));

  /** One recorded paid link: the same request, then Stripe's completed event, refused on `wrong` and applied on `endpoint`. */
  async function replayPaid(flow: "record-platform" | "record-connect", endpoint: "payments" | "connect", wrong: "payments" | "connect"): Promise<void> {
    const run = runs[flow];
    const [create] = run.exchanges;
    assert.equal(run.exchanges.length, 1);
    stripe.answer = create!;
    const before = stripe.seen.length;
    const { call, link } = await requestRecordedLink(world, flow);
    const session = JSON.parse(create!.body) as { id: string; mode: string; status: string; livemode: boolean; payment_method_types: string[] };
    assert.equal(link.linkId, session.id);
    assert.deepEqual([session.mode, session.status, session.livemode], ["payment", "open", false]);
    const sent = stripe.seen[before]!;
    assert.equal(sent.method, create!.method);
    assert.equal(sent.path, create!.path);
    assert.deepEqual(stable(sent.form), stable(create!.form));
    assert.deepEqual(new Set(create!.form.map(([name]) => name)), new Set(sent.form.map(([name]) => name)), "no parameter added or dropped");
    assert.equal(sent.headers["stripe-account"] ?? null, create!.headers["stripe-account"]);
    assert.equal(sent.headers["stripe-version"], create!.headers["stripe-version"]);

    // The delivery the real run got, from the listener that names the account in connect mode.
    const event = JSON.parse(run.delivery.body) as { type: string; account?: string; data: { object: { id: string; payment_status: string; status: string } } };
    assert.equal(run.delivery.type, "checkout.session.completed");
    assert.equal(event.data.object.id, session.id);
    assert.deepEqual([event.data.object.status, event.data.object.payment_status], ["complete", "paid"]);
    assert.equal(run.delivery.route, endpoint);
    assert.equal(run.delivery.listener, flow === "record-connect" ? "connect" : "account");
    assert.equal(event.account, flow === "record-connect" ? recording.account : undefined);
    // Each endpoint checks its own secret: the other endpoint's signature is refused.
    const otherSecret = endpoint === "connect" ? SECRET : CONNECT_SECRET;
    assert.deepEqual(await deliver(`${base}/webhooks/stripe/${endpoint}`, run.delivery.body, otherSecret), { status: 400, body: { error: "signature", reason: "no_matching_signature" } });
    // On the other endpoint it is acknowledged and left alone (the endpoint fixes the mode).
    assert.deepEqual(await deliver(`${base}/webhooks/stripe/${wrong}`, run.delivery.body), { status: 200, body: { received: true, applied: false, handled: false } });
    assert.equal((await world.engine.flowPosition(call.callId))!.status, "running");
    // On its own endpoint it settles the payment, and the flow finishes, as it did live.
    assert.deepEqual(await deliver(`${base}/webhooks/stripe/${endpoint}`, run.delivery.body), run.delivery.answer);
    assert.deepEqual(run.delivery.answer, { status: 200, body: { received: true, applied: true } });
    const position = (await world.engine.flowPosition(call.callId))!;
    assert.equal(`${position.status} at step ${position.index}`, run.flowStatus);
  }

  it("record-platform: the same Checkout Session request, then Stripe's recorded completed event settles it on /webhooks/stripe/payments only", () => replayPaid("record-platform", "payments", "connect"));

  it("record-connect: the same Checkout Session request, then Stripe's recorded completed event settles it on /webhooks/stripe/connect only", () => replayPaid("record-connect", "connect", "payments"));

  it("connect mode is a direct charge: the Stripe-Account header and nothing else (no on_behalf_of, no transfer_data)", () => {
    const [create] = runs["record-connect"].exchanges;
    assert.equal(create!.headers["stripe-account"], recording.account);
    assert.deepEqual(create!.form.filter(([name]) => /on_behalf_of|transfer_data|application_fee/.test(name)), []);
    assert.equal(runs["record-platform"].exchanges[0]!.headers["stripe-account"], null);
  });
});

describe("PAY-1: the payment method mapping, as Stripe answered it", () => {
  it("offers Apple Pay and Google Pay as `card`: Stripe took the session with card only, and refuses either wallet as a type", () => {
    const [create] = runs["record-connect"].exchanges;
    assert.deepEqual(checkoutPaymentMethodTypes(["card", "apple_pay", "google_pay"]), ["card"]);
    assert.deepEqual(create!.form.filter(([name]) => name.startsWith("payment_method_types")), [["payment_method_types[0]", "card"]]);
    assert.deepEqual((JSON.parse(create!.body) as { payment_method_types: string[] }).payment_method_types, ["card"]);
    assert.deepEqual(
      methods.refused.filter((r) => r.types[0] !== "link").map((r) => [r.types, r.status, r.error.type, r.error.param]),
      [
        [["apple_pay"], 400, "invalid_request_error", "payment_method_types[0]"],
        [["google_pay"], 400, "invalid_request_error", "payment_method_types[0]"],
      ],
    );
  });

  it("offers Link as `link` beside `card`, which Stripe took; Link alone Stripe refuses, so the adapter refuses it first", () => {
    const [create] = connectLink.exchanges;
    assert.deepEqual(checkoutPaymentMethodTypes(["card", "link"]), ["card", "link"]);
    assert.deepEqual(create!.form.filter(([name]) => name.startsWith("payment_method_types")), [
      ["payment_method_types[0]", "card"],
      ["payment_method_types[1]", "link"],
    ]);
    assert.equal(create!.status, 200);
    assert.deepEqual((JSON.parse(create!.body) as { payment_method_types: string[] }).payment_method_types, ["card", "link"]);
    const alone = methods.refused.find((r) => r.types.length === 1 && r.types[0] === "link")!;
    assert.deepEqual([alone.status, alone.error.type, alone.error.param], [400, "invalid_request_error", "payment_method_types"]);
    assert.throws(() => checkoutPaymentMethodTypes(["link"]), /Link only beside cards/);
  });
});

describe("PAY-1: a cancelled link closed on the connected account, as Stripe answered it", () => {
  const stripe = new ReplayStripe();
  let world: DemoWorld;

  before(async () => {
    const apiBase = await listen(stripe.server);
    world = createDemoWorld({ payments: new StripeCheckoutLinks(KEY, { apiBase, successUrl: RETURN }), config: recordedConfig(recording.account) });
  });
  after(async () => {
    await Promise.all([close(stripe.server), world.close()]);
  });

  it("creates the session, then expires it with Stripe-Account when the caller cancels; Stripe answered it expired", async () => {
    const [create, expire] = connectLink.exchanges;
    assert.equal(connectLink.exchanges.length, 2);
    stripe.answer = create!;
    const { call, link } = await requestRecordedLink(world, "record-connect-link");
    stripe.answer = expire!;
    const cancel = await world.engine.cancelPaymentLink(call.callId, link.paymentId);
    assert.equal(cancel.status, connectLink.cancelStatus);
    const [sentCreate, sentExpire] = stripe.seen;
    assert.equal(sentCreate!.headers["stripe-account"], recording.account);
    assert.equal(sentExpire!.method, "POST");
    assert.equal(sentExpire!.path, expire!.path);
    assert.equal(sentExpire!.path, `/v1/checkout/sessions/${link.linkId}/expire`);
    assert.equal(sentExpire!.headers["stripe-account"], expire!.headers["stripe-account"]);
    assert.equal(expire!.headers["stripe-account"], recording.account);
    assert.equal(expire!.status, 200);
    const expired = JSON.parse(expire!.body) as { id: string; status: string; livemode: boolean };
    assert.deepEqual([expired.id, expired.status, expired.livemode], [link.linkId, "expired", false]);
  });
});
