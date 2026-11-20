// Hostile-pass regressions for #93 (SRV-2): the reference server's limits, deadlines and request logs.
import { strict as assert } from "node:assert";
import { connect, type AddressInfo } from "node:net";
import { describe, it, type TestContext } from "node:test";

import { ReceiptLinks, createReferenceServer, rateLimitKey, type ReferenceServerOptions, type RequestLog } from "../examples/reference-server/src/app.ts";
import type { Engine } from "../src/index.ts";
import { FixedClock, createTestEngine } from "../src/testing/index.ts";

async function serve(ctx: TestContext, options: Partial<ReferenceServerOptions>): Promise<{ base: string; port: number }> {
  const t = createTestEngine();
  const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [], payments: [] }, clock: t.clock, ...options });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
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

/** A connection the test writes to step by step; `read` waits until the answers so far include `count` status lines. */
function conversation(port: number) {
  const socket = connect(port, "127.0.0.1");
  let answer = "";
  let closed = false;
  const waiters: Array<() => void> = [];
  socket.on("data", (chunk: Buffer) => {
    answer += chunk.toString("utf8");
    for (const w of waiters.splice(0)) w();
  });
  socket.on("close", () => {
    closed = true;
    for (const w of waiters.splice(0)) w();
  });
  socket.on("error", () => undefined);
  return {
    write: (text: string) => new Promise<void>((resolve) => socket.write(text, () => resolve())),
    async read(count: number): Promise<string> {
      while ((answer.match(/HTTP\/1\.1 \d{3} /g) ?? []).length < count && !closed) await new Promise<void>((resolve) => waiters.push(resolve));
      return answer;
    },
    async closed(): Promise<string> {
      while (!closed) await new Promise<void>((resolve) => waiters.push(resolve));
      return answer;
    },
    end: () => socket.destroy(),
  };
}

describe("hostile #93: request logs", () => {
  it("logs a malformed request that follows a refused body on the same connection", async (ctx) => {
    const logs: RequestLog[] = [];
    const s = await serve(ctx, { bodyLimits: { stripeIdentity: 16 }, log: (e) => logs.push(e) });
    const c = conversation(s.port);
    // A body declared over the limit is refused before it is read: answered while it is unread.
    await c.write("POST /webhooks/stripe/identity HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 64\r\n\r\n");
    assert.match(await c.read(1), /^HTTP\/1\.1 413 /);
    // The body, then a probe node:http cannot read, on the same connection, in order.
    await c.write(`${"x".repeat(64)}NOT HTTP AT ALL\r\n\r\n`);
    const answer = await c.closed();
    assert.equal((answer.match(/HTTP\/1\.1 \d{3} /g) ?? []).length, 2, `the probe is answered: ${JSON.stringify(answer)}`);
    assert.deepEqual(
      logs.map((e) => [e.route, e.status]),
      [
        ["/webhooks/stripe/identity", 413],
        ["unmatched", 400],
      ],
      "a probe after a refused body is still logged",
    );
  });

  it("an async log sink that rejects never takes the server down", async (ctx) => {
    const seen: unknown[] = [];
    const onUnhandled = (reason: unknown) => seen.push(reason);
    process.on("unhandledRejection", onUnhandled);
    ctx.after(() => process.off("unhandledRejection", onUnhandled));
    const s = await serve(ctx, { log: (async () => Promise.reject(new Error("sink down"))) as never });
    assert.deepEqual(await (await fetch(`${s.base}/healthz`)).json(), { ok: true });
    assert.deepEqual(await (await fetch(`${s.base}/nope`)).json(), { error: "not_found" });
    // Unhandled rejections are reported after the microtask queue drains: one macrotask is enough.
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(seen, [], "no unhandled rejection from the log sink");
  });

  it("a request answered 503 at its deadline is answered and logged once, however the route ends later", async (ctx) => {
    const logs: RequestLog[] = [];
    let finish!: (value: unknown) => void;
    let fail!: (error: unknown) => void;
    const engine = { receipt: () => new Promise((resolve, reject) => ((finish = resolve), (fail = reject))) } as unknown as Engine;
    const links = new ReceiptLinks();
    const [a, b] = [links.issue("call_a"), links.issue("call_b")];
    const s = await serve(ctx, { engine, receiptLinks: links, timeoutMs: 50, log: (e) => logs.push(e) });
    const res = await fetch(`${s.base}/r/${a}.json`);
    assert.equal(res.status, 503);
    finish(null);
    const res2 = await fetch(`${s.base}/r/${b}`);
    assert.equal(res2.status, 503);
    fail(new Error("late"));
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(logs.map((e) => [e.route, e.status]), [
      ["/r/:token.json", 503],
      ["/r/:token", 503],
    ]);
    const text = JSON.stringify(logs);
    for (const leak of ["call_", a, b]) assert.equal(text.includes(leak), false, "no call id or token in the log");
  });

  it("never logs a path, query, header or body, whatever the request carries", async (ctx) => {
    const logs: RequestLog[] = [];
    const s = await serve(ctx, { log: (e) => logs.push(e) });
    await fetch(`${s.base}/r/call_secret123?token=tok_secret`, { headers: { authorization: "Bearer sec_hdr" } });
    await fetch(`${s.base}/x/%E2%80%AE/__proto__?pin=4826`);
    await fetch(`${s.base}/webhooks/stripe/identity`, { method: "POST", body: "card=4111111111111111", headers: { "stripe-signature": "t=1,v1=sec_sig" } });
    const text = JSON.stringify(logs);
    for (const leak of ["secret123", "tok_secret", "sec_hdr", "4826", "4111", "sec_sig", "__proto__", "‮"]) assert.equal(text.includes(leak), false, leak);
    assert.equal(logs.length, 3);
  });
});

describe("hostile #93: rate limit", () => {
  it("pipelined requests over the limit are answered in order and each logged", async (ctx) => {
    const clock = new FixedClock();
    const logs: RequestLog[] = [];
    const s = await serve(ctx, { clock, rateLimit: { requests: 1, windowMs: 60_000, clock }, log: (e) => logs.push(e) });
    const c = conversation(s.port);
    await c.write("GET /healthz HTTP/1.1\r\nhost: x\r\n\r\nGET /healthz HTTP/1.1\r\nhost: x\r\n\r\nGET /healthz HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n");
    const answer = await c.closed();
    assert.deepEqual([...answer.matchAll(/HTTP\/1\.1 (\d{3}) /g)].map((m) => m[1]), ["200", "429", "429"]);
    assert.deepEqual(logs.map((e) => e.status), [200, 429, 429]);
  });

  it("rateLimitKey takes any text without throwing, and keeps prototype keys and lookalikes apart", () => {
    const keys = ["__proto__", "constructor", "\ud800", "‮192.0.2.1", "x".repeat(1_000_000), "", "::ffff:999.1.1.1", "1::2::3", ":::"].map((a) => rateLimitKey(a));
    assert.equal(keys[0], "__proto__");
    assert.notEqual(rateLimitKey("::ffff:192.0.2.1"), rateLimitKey("‮192.0.2.1"));
    assert.equal(rateLimitKey("2001:db8::1"), "2001:db8:0:0::/64");
    assert.notEqual(rateLimitKey("2001:db8:0:1::1"), rateLimitKey("2001:db8:0:0::1"));
  });

  it("a rate-limit clock that runs backwards never ends a window early", async (ctx) => {
    let ms = 1_000_000;
    const clock = { now: () => new Date(ms) };
    const s = await serve(ctx, { rateLimit: { requests: 1, windowMs: 60_000, clock } });
    assert.equal((await fetch(`${s.base}/healthz`)).status, 200);
    ms -= 500_000;
    const res = await fetch(`${s.base}/healthz`);
    assert.equal(res.status, 429);
    assert.match(res.headers.get("retry-after")!, /^\d+$/);
  });
});
