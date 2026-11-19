// Hostile-pass regressions for #50 (the e2e demo): the Stripe Checkout adapter, the demo routes and
// DemoRuns. S1 to S4 failed before the adapter sent its idempotency key as printable ASCII and
// kept to plain words in errors; the rest held.
import { strict as assert } from "node:assert";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, describe, it } from "node:test";

import { createReferenceServer } from "../examples/reference-server/src/app.ts";
import { DemoRuns } from "../examples/reference-server/src/demo-runs.ts";
import { createDemoWorld, type ScriptStep } from "../examples/reference-server/src/script.ts";
import { StripeApiError, StripeCheckoutLinks } from "../examples/reference-server/src/stripe-adapters.ts";
import type { PaymentLinkRequest } from "../src/index.ts";

const KEY = ["sk", "test", "FAKEFAKEFAKEFAKE0123456789"].join("_");
const RETURN = "http://127.0.0.1:8787/";

/** Answers every request with `answer` and keeps the headers it saw. */
class TinyStripe {
  seen: IncomingMessage["headers"][] = [];
  answer: { status: number; body: unknown } = { status: 200, body: {} };
  server: Server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      this.seen.push(req.headers);
      res.writeHead(this.answer.status, { "content-type": "application/json" }).end(JSON.stringify(this.answer.body));
    });
  });
  base = "";
  async start(): Promise<void> {
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    this.base = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }
}

const session = (over: Record<string, unknown> = {}) => ({ id: "cs_test_abc", url: "https://checkout.stripe.com/c/pay/cs_test_abc", livemode: false, status: "open", payment_status: "unpaid", ...over });

function request(over: Partial<PaymentLinkRequest> = {}): PaymentLinkRequest {
  return {
    callId: "call_1",
    paymentId: "pay_1",
    amountMinor: 2500,
    currency: "cad",
    description: "Visit deposit",
    mode: "platform",
    paymentMethods: ["card"],
    expiresAt: "2026-11-18T12:30:00.000Z",
    idempotencyKey: "idem_1",
    ...over,
  };
}

describe("hostile #50: the Stripe Checkout adapter", () => {
  const fake = new TinyStripe();
  let links: StripeCheckoutLinks;
  before(async () => {
    await fake.start();
    links = new StripeCheckoutLinks(KEY, { apiBase: fake.base, successUrl: RETURN, timeoutMs: 5000 });
  });
  after(() => new Promise<void>((resolve) => fake.server.close(() => resolve())));
  beforeEach(() => {
    fake.seen = [];
    fake.answer = { status: 200, body: session() };
  });

  it("S1: sends an engine idempotency key holding a non-ASCII call id, the same header every retry", async () => {
    // The engine's key is a JSON tuple of workspace, call and payment ids; ids may be any text.
    const key = JSON.stringify(["ws_test", "\u901a\u8a71-1", "pay_1", "link", "platform"]);
    await links.createLink(request({ callId: "\u901a\u8a71-1", idempotencyKey: key }));
    await links.createLink(request({ callId: "\u901a\u8a71-1", idempotencyKey: key }));
    assert.equal(fake.seen.length, 2, "both requests reached Stripe");
    const [a, b] = fake.seen.map((h) => h["idempotency-key"] as string);
    assert.equal(a, b);
    assert.match(a!, /^[\x20-\x7e]{1,255}$/, "printable ASCII, within Stripe's 255");
    const other = JSON.stringify(["ws_test", "\u901a\u8a71-2", "pay_1", "link", "platform"]);
    await links.createLink(request({ idempotencyKey: other }));
    assert.notEqual(fake.seen[2]!["idempotency-key"], a, "two keys stay two keys");
  });

  it("S2: sends a key longer than Stripe's 255 characters as one that fits, the same each time", async () => {
    const key = JSON.stringify(["w".repeat(200), "c".repeat(200), "pay_1", "link", "platform"]);
    await links.createLink(request({ idempotencyKey: key }));
    await links.createLink(request({ idempotencyKey: key }));
    const [a, b] = fake.seen.map((h) => h["idempotency-key"] as string);
    assert.equal(a, b);
    assert.ok(a!.length <= 255, String(a!.length));
  });

  it("S3: expireLink sends a non-ASCII key too", async () => {
    fake.answer = { status: 200, body: session({ status: "expired" }) };
    assert.deepEqual(await links.expireLink({ linkId: "cs_test_abc", mode: "platform", idempotencyKey: JSON.stringify(["ws", "\u00e9-1", "x"]) }), { state: "expired" });
    assert.match(fake.seen[0]!["idempotency-key"] as string, /^[\x20-\x7e]+$/);
  });

  it("S4: never echoes a key-shaped or control-laden error type or code", async () => {
    for (const error of [
      { type: KEY, code: "bad\u202ecode\nnext" },
      { type: "sk_test_lowercase0123456789", code: "rk_test_abcdefgh0123" },
      { type: "x".repeat(81), code: "<script>" },
    ]) {
      fake.answer = { status: 401, body: { error } };
      await assert.rejects(links.createLink(request()), (e: unknown) => e instanceof StripeApiError && e.message === "Stripe did not create the Checkout Session (HTTP 401)");
    }
    fake.answer = { status: 402, body: { error: { type: "card_error", code: "card_declined" } } };
    await assert.rejects(links.createLink(request()), /\(HTTP 402, type card_error, code card_declined\)$/, "Stripe's own words still show");
  });

  it("S5: refuses a session answer with no livemode, a live one, or the wrong id on a read", async () => {
    for (const body of [session({ livemode: undefined }), session({ livemode: true }), session({ livemode: "false" })]) {
      fake.answer = { status: 200, body };
      await assert.rejects(links.createLink(request()), StripeApiError, JSON.stringify(body));
    }
    fake.answer = { status: 200, body: session({ id: "cs_test_other" }) };
    await assert.rejects(links.readLink("cs_test_abc"), StripeApiError);
    for (const id of ["cs_live_abc", "cs_test_../x", "cs_test_a?b", "", "cs_test_\u{1F600}"]) await assert.rejects(links.readLink(id), TypeError, id);
  });
});

describe("hostile #50: the demo routes", () => {
  const world = createDemoWorld();
  let base = "";
  let server: Server;
  before(async () => {
    server = createReferenceServer({ engine: world.engine, clock: world.clock, stripeSecrets: { identity: [], payments: [] }, ui: new DemoRuns(world) });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await world.close();
  });
  const post = (path: string, body: string, headers: Record<string, string> = { "content-type": "application/json" }) => fetch(`${base}${path}`, { method: "POST", headers, body });

  it("R1: a flow name that is a prototype key, huge, not a string or a lone surrogate is unknown_flow, never a 500", async () => {
    const bodies = ["__proto__", "constructor", "hasOwnProperty", "toString", "x".repeat(60_000), "entry\uD800"].map((flow) => JSON.stringify({ flow }));
    bodies.push(JSON.stringify({ flow: ["entry"] }), JSON.stringify({ flow: { toString: "entry" } }), "null", "[]", '{"__proto__":{"flow":"entry"}}', "1");
    for (const body of bodies) {
      const res = await post("/demo/runs", body);
      assert.equal(res.status, 400, body.slice(0, 40));
      assert.deepEqual(await res.json(), { error: "unknown_flow" });
    }
  });

  it("R2: refuses a step sent cross-origin, from a sandboxed frame, or as a simple form", async () => {
    const { runId } = (await (await post("/demo/runs", JSON.stringify({ flow: "entry" }))).json()) as { runId: string };
    for (const [headers, status] of [
      [{ "content-type": "application/json", origin: "null" }, 403],
      [{ "content-type": "application/json", origin: "http://evil.example" }, 403],
      [{ "content-type": "text/plain" }, 415],
      [{ "content-type": "application/x-www-form-urlencoded" }, 415],
      [{ "content-type": "multipart/form-data; boundary=x" }, 415],
    ] as const) {
      const res = await post(`/demo/runs/${runId}/next`, "{}", headers as Record<string, string>);
      assert.equal(res.status, status, JSON.stringify(headers));
    }
    const view = (await (await fetch(`${base}/demo/runs/${runId}`)).json()) as { next: number };
    assert.equal(view.next, 0, "no refused request ran a step");
  });

  it("R4: an unknown, malformed or over-long run id is 404 or 405, never a 500", async () => {
    for (const path of [`/demo/runs/run_${"a".repeat(65)}`, "/demo/runs/run_", "/demo/runs/run_x/../../healthz", "/demo/runs/run_%00", "/demo/runs/run_\u00e9"]) {
      const res = await fetch(`${base}${encodeURI(path)}`);
      assert.ok(res.status === 404 || res.status === 405, `${path} ${res.status}`);
    }
  });
});

describe("hostile #50: DemoRuns", () => {
  it("D1: a run evicted while its step is in flight finishes quietly, and its id is gone", async () => {
    const world = createDemoWorld();
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const slow: ScriptStep = { label: "slow", run: async () => (await held, { detail: "done", ok: true }) };
    const runs = new DemoRuns(world, 1, { entry: [slow], deposit: [slow] });
    const first = await runs.start("entry");
    const stepping = runs.step(first.runId);
    await runs.start("deposit");
    release();
    const answer = await stepping;
    assert.ok(answer.ok);
    assert.deepEqual(await runs.view(first.runId), { ok: false, status: 404, error: "not_found" });
    await world.close();
  });

  it("D3: two steps of one run at once: the second answers busy while the first runs, and runs nothing", async () => {
    const world = createDemoWorld();
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    let ran = 0;
    const slow: ScriptStep = { label: "slow", run: async () => (ran++, await held, { detail: "done", ok: true }) };
    const runs = new DemoRuns(world, 5, { entry: [slow, slow] });
    const run = await runs.start("entry");
    const first = runs.step(run.runId);
    assert.deepEqual(await runs.step(run.runId), { ok: false, status: 409, error: "busy" });
    release();
    assert.ok((await first).ok);
    assert.equal(ran, 1);
    await world.close();
  });

  it("D2: a step that throws a non-engine error shows no part of its message", async () => {
    const world = createDemoWorld();
    const leaky: ScriptStep = {
      label: "leaky",
      run: async () => {
        throw new Error(`Invalid API Key provided: ${KEY}`);
      },
    };
    const runs = new DemoRuns(world, 5, { entry: [leaky] });
    const run = await runs.start("entry");
    const answer = await runs.step(run.runId);
    assert.ok(answer.ok);
    assert.equal(JSON.stringify(answer.view).includes("sk_test_"), false);
    assert.equal(answer.view.results[0]!.detail, "failed: internal error");
    await world.close();
  });
});
