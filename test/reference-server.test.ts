// The reference server, over a real socket on 127.0.0.1, and the scripted demo.
import { strict as assert } from "node:assert";
import { request } from "node:http";
import { connect, type AddressInfo } from "node:net";
import { after, before, describe, it, type TestContext } from "node:test";

import { DEFAULT_BODY_LIMITS, createReferenceServer, logJsonLines, type ReferenceServerOptions, type RequestLog } from "../examples/reference-server/src/app.ts";
import { DemoRuns } from "../examples/reference-server/src/demo-runs.ts";
import { runDemo } from "../examples/reference-server/src/demo.ts";
import { createDemoWorld } from "../examples/reference-server/src/script.ts";
import { StripeCheckoutLinks, StripeIdentityProvider } from "../examples/reference-server/src/stripe-adapters.ts";
import { NotImplementedError, signStripePayload, type Engine } from "../src/index.ts";
import { FixedClock, createTestEngine, type TestEngine } from "../src/testing/index.ts";

const SECRET = "whsec_test_not_a_secret";

describe("reference server", () => {
  let t: TestEngine;
  let base = "";
  let close: () => Promise<void>;
  const logs: RequestLog[] = [];

  before(async () => {
    t = createTestEngine();
    const server = createReferenceServer({
      engine: t.engine,
      stripeSecrets: { identity: [SECRET], payments: [] },
      clock: t.clock,
      bodyLimits: { stripeIdentity: 1024 },
      log: (entry) => logs.push(entry),
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    close = () => new Promise((resolve) => server.close(() => resolve()));
  });
  after(() => close());

  const post = (path: string, body: string, headers: Record<string, string> = {}) => fetch(`${base}${path}`, { method: "POST", body, headers });
  const signed = (body: string) => ({ "stripe-signature": signStripePayload(body, SECRET, Math.floor(t.clock.now().getTime() / 1000)) });
  const event = (id: string, type: string, object: Record<string, unknown>) => JSON.stringify({ id, type, data: { object } });

  it("answers health, the key set, and 404 for anything else", async () => {
    assert.deepEqual(await (await fetch(`${base}/healthz`)).json(), { ok: true });
    const keys = (await (await fetch(`${base}/.well-known/receipt-keys.json`)).json()) as { keys: Array<Record<string, unknown>> };
    assert.equal(keys.keys[0]!.kty, "EC");
    assert.equal("d" in keys.keys[0]!, false);
    assert.equal((await fetch(`${base}/nope`)).status, 404);
    assert.equal((await post("/healthz", "")).status, 405);
    assert.equal((await fetch(`${base}/webhooks/stripe/identity`)).status, 405);
  });

  it("verifies Stripe signatures before reading the event", async () => {
    const body = event("evt_1", "identity.verification_session.verified", { id: "vs_unknown" });
    let res = await post("/webhooks/stripe/identity", body);
    assert.equal(res.status, 400);
    assert.deepEqual(await res.json(), { error: "signature", reason: "missing_header" });
    res = await post("/webhooks/stripe/identity", body, { "stripe-signature": signStripePayload(body, "whsec_other", 1767225600) });
    assert.deepEqual(await res.json(), { error: "signature", reason: "no_matching_signature" });
    res = await post("/webhooks/stripe/payments", body, signed(body));
    assert.deepEqual(await res.json(), { error: "signature", reason: "no_secret" }, "an endpoint without a secret refuses everything");
    res = await post("/webhooks/stripe/identity", "{}", signed("{}"));
    assert.deepEqual([res.status, await res.json()], [400, { error: "malformed_event" }]);
  });

  it("applies a signed event once and ignores events of the other kind", async () => {
    const body = event("evt_2", "identity.verification_session.verified", { id: "vs_unknown" });
    assert.deepEqual(await (await post("/webhooks/stripe/identity", body, signed(body))).json(), { received: true, applied: false });
    assert.deepEqual(await (await post("/webhooks/stripe/identity", body, signed(body))).json(), { received: true, duplicate: true });
    const pay = event("evt_3", "checkout.session.expired", { id: "cs_x" });
    assert.deepEqual(await (await post("/webhooks/stripe/identity", pay, signed(pay))).json(), { received: true, applied: false });
  });

  it("refuses a body over its route's limit, declared or streamed", async () => {
    let res = await post("/webhooks/stripe/identity", "x".repeat(5000));
    assert.deepEqual([res.status, await res.json()], [413, { error: "body_too_large" }]);
    // No Content-Length: the body arrives in chunks and is cut off once it passes the limit.
    const streamed = await raw(base, "POST", "/webhooks/stripe/identity", { "transfer-encoding": "chunked" }, ["x".repeat(800), "x".repeat(800)]);
    assert.deepEqual([streamed.status, JSON.parse(streamed.body)], [413, { error: "body_too_large" }]);
    // The payments route keeps its own default of 64 KiB, so the same body reaches the signature check.
    res = await post("/webhooks/stripe/payments", "x".repeat(5000));
    assert.deepEqual([res.status, await res.json()], [400, { error: "signature", reason: "no_secret" }]);
    res = await post("/webhooks/stripe/payments", "x".repeat(DEFAULT_BODY_LIMITS.stripePayments + 1));
    assert.equal(res.status, 413);
  });

  it("logs one entry per request, by route pattern, without paths, headers or bodies", async () => {
    logs.length = 0;
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    assert.equal((await fetch(`${base}/receipts/${callId}?token=tok_not_a_secret`)).status, 200);
    const body = event("evt_log", "identity.verification_session.verified", { id: "vs_secret_session" });
    await post("/webhooks/stripe/identity", body, { ...signed(body), authorization: "Bearer not_a_secret_token" });
    await post("/webhooks/stripe/identity", body, { "stripe-signature": "t=1,v1=00" });
    await fetch(`${base}/nope/${callId}`);
    assert.deepEqual(
      logs.map(({ ms, ...entry }) => {
        assert.ok(Number.isInteger(ms) && ms >= 0);
        return entry;
      }),
      [
        { time: "2026-01-01T00:00:00.000Z", address: "127.0.0.1", method: "GET", route: "/receipts/:callId", status: 200 },
        { time: "2026-01-01T00:00:00.000Z", address: "127.0.0.1", method: "POST", route: "/webhooks/stripe/identity", status: 200 },
        { time: "2026-01-01T00:00:00.000Z", address: "127.0.0.1", method: "POST", route: "/webhooks/stripe/identity", status: 400, error: "signature" },
        { time: "2026-01-01T00:00:00.000Z", address: "127.0.0.1", method: "GET", route: "unmatched", status: 404, error: "not_found" },
      ],
    );
    const text = JSON.stringify(logs);
    for (const leak of [callId, "tok_not_a_secret", "not_a_secret_token", "evt_log", "vs_secret_session", "v1=", SECRET]) assert.equal(text.includes(leak), false, leak);
  });

  it("writes log entries as JSON lines with logJsonLines", (ctx) => {
    const write = ctx.mock.method(process.stdout, "write", () => true);
    const entry: RequestLog = { time: "2026-01-01T00:00:00.000Z", address: "127.0.0.1", method: "GET", route: "/healthz", status: 200, ms: 0 };
    logJsonLines(entry);
    write.mock.restore();
    assert.deepEqual(write.mock.calls.map((c) => c.arguments[0]), [`${JSON.stringify(entry)}\n`]);
  });

  it("answers 501 on the carrier webhooks that are not built", async () => {
    const res = await post("/webhooks/twilio", "");
    assert.deepEqual([res.status, await res.json()], [501, { error: "not_implemented", issue: "SRV-1", carrier: "twilio" }]);
  });

  it("serves a receipt once the call ended, 404 before and for unknown calls", async () => {
    const { callId } = await t.engine.startCall();
    assert.equal((await fetch(`${base}/receipts/${callId}`)).status, 404);
    await t.engine.endCall(callId);
    const receipt = (await (await fetch(`${base}/receipts/${callId}`)).json()) as { body: { callId: string } };
    assert.equal(receipt.body.callId, callId);
    assert.equal((await fetch(`${base}/receipts/call_404`)).status, 404);
    assert.equal((await fetch(`${base}/receipts/bad%20id`)).status, 404);
  });

  it("answers 500 without detail when the engine fails", async () => {
    const broken = { receipt: () => { throw new Error("boom"); } } as unknown as Engine;
    const server = createReferenceServer({ engine: broken, stripeSecrets: { identity: [], payments: [] }, clock: t.clock });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const res = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/receipts/c1`);
    assert.deepEqual([res.status, await res.json()], [500, { error: "internal" }]);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("reference server limits", () => {
  /** A server on `host`, closed when the test ends, passed or failed. */
  async function serve(ctx: TestContext, options: Partial<ReferenceServerOptions>, host = "127.0.0.1"): Promise<{ base: string; port: number }> {
    const t = createTestEngine();
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [], payments: [] }, clock: t.clock, ...options });
    await new Promise<void>((resolve) => server.listen(0, host, resolve));
    ctx.after(
      () =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => resolve());
        }),
    );
    const port = (server.address() as AddressInfo).port;
    return { base: `http://127.0.0.1:${port}`, port };
  }

  it("limits each address to a number of requests per window, on the rate limit's clock", async (ctx) => {
    const clock = new FixedClock();
    const logs: RequestLog[] = [];
    const s = await serve(ctx, { clock, rateLimit: { requests: 2, windowMs: 60_000, clock }, log: (e) => logs.push(e) });
    assert.equal((await fetch(`${s.base}/healthz`)).status, 200);
    assert.equal((await fetch(`${s.base}/nope`)).status, 404, "every request counts, matched or not");
    let res = await fetch(`${s.base}/healthz`, { headers: { "x-forwarded-for": "192.0.2.1" } });
    assert.deepEqual([res.status, res.headers.get("retry-after"), await res.json()], [429, "60", { error: "rate_limited" }], "X-Forwarded-For is not trusted");
    clock.advance(45_500);
    res = await fetch(`${s.base}/healthz`);
    assert.deepEqual([res.status, res.headers.get("retry-after")], [429, "15"]);
    clock.advance(14_500);
    assert.equal((await fetch(`${s.base}/healthz`)).status, 200, "a new window");
    assert.deepEqual(logs.map((e) => [e.route, e.status, e.error]), [
      ["/healthz", 200, undefined],
      ["unmatched", 404, "not_found"],
      ["unmatched", 429, "rate_limited"],
      ["unmatched", 429, "rate_limited"],
      ["/healthz", 200, undefined],
    ]);
  });

  it("counts windows on the rate limit's own clock, so a server on the demo's fixed clock is never locked out", async (ctx) => {
    // npm run ui and npm run demo give the server the demo's FixedClock, which never moves.
    const serverClock = new FixedClock();
    const rateClock = new FixedClock();
    const s = await serve(ctx, { clock: serverClock, rateLimit: { requests: 1, windowMs: 60_000, clock: rateClock } });
    assert.equal((await fetch(`${s.base}/healthz`)).status, 200);
    assert.equal((await fetch(`${s.base}/healthz`)).status, 429);
    serverClock.advance(60_000);
    assert.equal((await fetch(`${s.base}/healthz`)).status, 429, "the server's clock does not end a window");
    rateClock.advance(60_000);
    assert.equal((await fetch(`${s.base}/healthz`)).status, 200, "the rate limit's clock does");
    const d = await serve(ctx, { clock: serverClock, rateLimit: { requests: 1, windowMs: 60_000 } });
    assert.equal((await fetch(`${d.base}/healthz`)).status, 200);
    serverClock.advance(120_000);
    assert.equal((await fetch(`${d.base}/healthz`)).status, 429, "by default the system clock counts the window, not the server's");
  });

  it("tracks a bounded number of addresses, forgetting ended windows first, then the oldest", async (ctx) => {
    const clock = new FixedClock();
    // Listening on every address, so the same server sees IPv4 and IPv6 loopback as two callers.
    const s = await serve(ctx, { clock, rateLimit: { requests: 1, windowMs: 60_000, addresses: 1, clock } }, "::");
    const v4 = `http://127.0.0.1:${s.port}/healthz`;
    const v6 = `http://[::1]:${s.port}/healthz`;
    assert.equal((await fetch(v4)).status, 200);
    assert.equal((await fetch(v4)).status, 429);
    assert.equal((await fetch(v6)).status, 200, "the IPv4 window is dropped, though not ended, to make room");
    assert.equal((await fetch(v4)).status, 200, "and so IPv4 starts again");
    clock.advance(60_000);
    assert.equal((await fetch(v6)).status, 200, "the ended IPv4 window makes room");
    assert.equal((await fetch(v6)).status, 429);
  });

  it("answers 503 when a request takes longer than its deadline", async (ctx) => {
    const logs: RequestLog[] = [];
    const engine = { receipt: () => new Promise(() => undefined) } as unknown as Engine;
    const s = await serve(ctx, { engine, timeoutMs: 100, log: (e) => logs.push(e) });
    const res = await fetch(`${s.base}/receipts/call_slow`);
    assert.deepEqual([res.status, await res.json()], [503, { error: "timeout" }]);
    assert.deepEqual(logs.map((e) => [e.route, e.status, e.error]), [["/receipts/:callId", 503, "timeout"]]);
  });

  it("disconnects a client that sends its headers too slowly with a 408, in JSON, and logs it", async (ctx) => {
    const logs: RequestLog[] = [];
    const s = await serve(ctx, { timeoutMs: 100, log: (e) => logs.push(e) });
    // The headers never end, so no handler runs: node:http times the request out.
    const answer = await rawSocket(s.port, "POST /webhooks/stripe/identity HTTP/1.1\r\nhost: 127.0.0.1\r\n");
    assert.match(answer, /^HTTP\/1\.1 408 Request Timeout\r\n/);
    assert.match(answer, /\r\ncontent-type: application\/json; charset=utf-8\r\n/);
    assert.match(answer, /\r\nconnection: close\r\n/);
    assert.equal(answer.slice(answer.indexOf("\r\n\r\n") + 4), JSON.stringify({ error: "request_timeout" }));
    assert.deepEqual(
      logs.map((e) => [e.address, e.method, e.route, e.status, e.error]),
      [["127.0.0.1", "unknown", "unmatched", 408, "request_timeout"]],
    );
  });

  it("answers and logs once when a body arrives too slowly", async (ctx) => {
    const logs: RequestLog[] = [];
    const s = await serve(ctx, { timeoutMs: 100, log: (e) => logs.push(e) });
    // The headers end but the body never does: whichever deadline comes first answers, once.
    const answer = await rawSocket(s.port, "POST /webhooks/stripe/identity HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 10\r\n\r\nab");
    const status = Number(/^HTTP\/1\.1 (\d{3}) /.exec(answer)![1]);
    assert.ok(status === 408 || status === 503, answer);
    assert.equal(answer.match(/HTTP\/1\.1 /g)!.length, 1, "one answer");
    // node:http checks its deadline every 100 ms here, so give a late check time to run.
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.deepEqual(
      logs.map((e) => [e.method, e.route, e.status]),
      [["POST", "/webhooks/stripe/identity", status]],
    );
  });

  it("refuses requests node:http cannot read in JSON, and logs them", async (ctx) => {
    const logs: RequestLog[] = [];
    const s = await serve(ctx, { log: (e) => logs.push(e) });
    const bodyOf = (answer: string) => JSON.parse(answer.slice(answer.indexOf("\r\n\r\n") + 4)) as unknown;
    let answer = await rawSocket(s.port, "NOT HTTP AT ALL\r\n\r\n");
    assert.match(answer, /^HTTP\/1\.1 400 Bad Request\r\n/);
    assert.deepEqual(bodyOf(answer), { error: "bad_request" });
    answer = await rawSocket(s.port, `GET /healthz HTTP/1.1\r\nhost: 127.0.0.1\r\nx-big: ${"x".repeat(20_000)}\r\n\r\n`);
    assert.match(answer, /^HTTP\/1\.1 431 /);
    assert.deepEqual(bodyOf(answer), { error: "headers_too_large" });
    answer = await rawSocket(s.port, `POST /webhooks/stripe/identity HTTP/1.1\r\nhost: 127.0.0.1\r\ntransfer-encoding: chunked\r\n\r\n1;${"x".repeat(20_000)}\r\n`);
    assert.match(answer, /^HTTP\/1\.1 413 /);
    assert.deepEqual(bodyOf(answer), { error: "body_too_large" });
    assert.deepEqual(
      logs.map((e) => [e.method, e.route, e.status, e.error]),
      [
        ["unknown", "unmatched", 400, "bad_request"],
        ["unknown", "unmatched", 431, "headers_too_large"],
        ["POST", "/webhooks/stripe/identity", 413, "body_too_large"],
      ],
    );
  });

  it("closes a reset connection without answering or logging", () => {
    const logs: RequestLog[] = [];
    const t = createTestEngine();
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [], payments: [] }, clock: t.clock, log: (e) => logs.push(e) });
    const written: string[] = [];
    let destroyed = false;
    const socket = { writable: true, remoteAddress: "127.0.0.1", write: (s: string) => written.push(s), destroy: () => (destroyed = true) };
    server.emit("clientError", Object.assign(new Error("reset"), { code: "ECONNRESET" }), socket);
    assert.deepEqual([written, logs, destroyed], [[], [], true]);
  });

  it("keeps serving when the log sink throws", async (ctx) => {
    let calls = 0;
    const s = await serve(ctx, {
      timeoutMs: 100,
      log: () => {
        calls += 1;
        throw new Error("sink down");
      },
    });
    assert.deepEqual(await (await fetch(`${s.base}/healthz`)).json(), { ok: true });
    assert.match(await rawSocket(s.port, "GET /healthz HTTP/1.1\r\n"), /^HTTP\/1\.1 408 /);
    assert.deepEqual(await (await fetch(`${s.base}/healthz`)).json(), { ok: true });
    assert.equal(calls, 3);
  });

  it("gives the demo's runs a small body limit of their own", async (ctx) => {
    const world = createDemoWorld();
    const s = await serve(ctx, { engine: world.engine, clock: world.t.clock, ui: new DemoRuns(world) });
    const start = (body: string) => fetch(`${s.base}/demo/runs`, { method: "POST", headers: { "content-type": "application/json" }, body });
    let res = await start(JSON.stringify({ flow: "deposit", pad: "x".repeat(DEFAULT_BODY_LIMITS.demo) }));
    assert.deepEqual([res.status, await res.json()], [413, { error: "body_too_large" }]);
    res = await start(JSON.stringify({ flow: "deposit" }));
    assert.equal(res.status, 201);
  });
});

/** Writes `text` on a new connection and resolves with everything the server sent before closing. */
function rawSocket(port: number, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1", () => socket.write(text));
    let answer = "";
    socket.on("data", (chunk: Buffer) => (answer += chunk.toString("utf8")));
    socket.on("close", () => resolve(answer));
    socket.on("error", reject);
  });
}

/** A raw HTTP/1.1 request whose body is written chunk by chunk, with the headers exactly as given. */
function raw(base: string, method: string, path: string, headers: Record<string, string>, chunks: string[]): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(`${base}${path}`, { method, headers }, (res) => {
      const parts: Buffer[] = [];
      res.on("data", (c: Buffer) => parts.push(c));
      res.on("end", () => resolve({ status: res.statusCode!, body: Buffer.concat(parts).toString("utf8") }));
    });
    req.on("error", reject);
    for (const chunk of chunks) req.write(chunk);
    req.end();
  });
}

describe("demo and Stripe adapters", () => {
  it("runs the owner-command and deposit flows end to end", async () => {
    const result = await runDemo(false);
    assert.equal(result.checksOk, true);
    assert.equal(result.ownerReceipt, null, "owner-command has no receipt step");
    assert.equal(result.tamperedFails, true);
    assert.equal(result.chainOk, true);
    assert.deepEqual(result.receipt.body.verification, { level: 2, methods: ["carrier_identity_match", "keypad_knowledge"] });
    assert.equal(result.receipt.body.payments[0]!.status, "paid");
    assert.equal(result.receipt.body.consents[0]!.purpose, "repair_texts");
  });

  it("has Stripe adapters that are planned, not built", async () => {
    await assert.rejects(new StripeIdentityProvider("rk_test").createDocumentCheck({ callId: "c", idempotencyKey: "k" }), (e: unknown) => e instanceof NotImplementedError && e.issue === "VER-5");
    await assert.rejects(
      new StripeCheckoutLinks("rk_test").createLink({ callId: "c", paymentId: "p", amountMinor: 1, currency: "cad", description: "d", idempotencyKey: "k" }),
      (e: unknown) => e instanceof NotImplementedError && e.issue === "PAY-1",
    );
  });
});
