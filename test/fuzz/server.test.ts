// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// SRV-7: the reference server's request parsing, over raw sockets on 127.0.0.1, so the request line,
// the headers and the body go out exactly as generated. Whatever arrives, the server answers with a
// status it means (never a 500), in JSON on every route that is not a static file, and keeps serving.
import { strict as assert } from "node:assert";
import { connect, type AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import fc from "fast-check";

import { createReferenceServer } from "../../examples/reference-server/src/app.ts";
import { DemoRuns } from "../../examples/reference-server/src/demo-runs.ts";
import { DEMO_SECRET, createDemoWorld, type DemoWorld } from "../../examples/reference-server/src/script.ts";
import { STATIC_FILES } from "../../examples/reference-server/src/static.ts";
import { signStripePayload } from "../../src/webhooks/stripe.ts";
import { fuzz, int, jsonValue, mutate, nastyString, pick, printableString } from "./harness.ts";

/** Whether a draw of `g` falls under `fraction`. */
const chance = (g: fc.GeneratorValue, fraction: number): boolean => int(g, 0, 999) < fraction * 1000;

/** A string of up to `maxLength` items of the alphabet. */
const stringOf = (g: fc.GeneratorValue, maxLength: number, alphabet: readonly string[]): string => g(fc.string, { unit: fc.constantFrom(...alphabet), maxLength });

interface Served {
  world: DemoWorld;
  port: number;
  ui: boolean;
  close(): Promise<void>;
}

async function serve(ui: boolean): Promise<Served> {
  const world = createDemoWorld();
  const server = createReferenceServer({
    engine: world.engine,
    clock: world.t.clock,
    stripeSecrets: { identity: [DEMO_SECRET], payments: [DEMO_SECRET] },
    // Every route that reads a body, under one small limit, so the oversized bodies get a 413.
    // Every request here comes from one address, so the per-address limit (SRV-2, tested on its
    // own) is set out of reach: this property is about parsing, not about being rate limited.
    rateLimit: { requests: 1_000_000, windowMs: 60_000 },
    bodyLimits: { stripeIdentity: 2048, stripePayments: 2048, stripeConnect: 2048, records: 2048, twilio: 2048, telnyx: 2048, demo: 2048 },
    ...(ui ? { ui: new DemoRuns(world) } : {}),
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  world.base = `http://127.0.0.1:${port}`;
  return { world, port, ui, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

interface Reply {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** Sends bytes as they are and reads the reply until the server closes the connection. */
function send(port: number, bytes: Buffer): Promise<Reply | null> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1");
    const chunks: Buffer[] = [];
    socket.on("data", (c: Buffer) => chunks.push(c));
    // A reset after a refused request is an answer too: nothing was served.
    socket.on("error", (e: NodeJS.ErrnoException) => (e.code === "ECONNRESET" || e.code === "EPIPE" ? undefined : reject(e)));
    socket.on("close", () => {
      const text = Buffer.concat(chunks).toString("latin1");
      if (text === "") return resolve(null);
      const end = text.indexOf("\r\n\r\n");
      const head = text.slice(0, end < 0 ? text.length : end).split("\r\n");
      const status = /^HTTP\/1\.1 (\d{3}) /.exec(head[0]!);
      assert.ok(status !== null, `a reply starts with a status line: ${JSON.stringify(head[0])}`);
      const headers: Record<string, string> = {};
      for (const line of head.slice(1)) {
        const colon = line.indexOf(":");
        headers[line.slice(0, colon).toLowerCase()] = line.slice(colon + 1).trim();
      }
      let body = end < 0 ? "" : text.slice(end + 4);
      if (headers["transfer-encoding"] === "chunked") body = dechunk(body);
      resolve({ status: Number(status[1]), headers, body: Buffer.from(body, "latin1").toString("utf8") });
    });
    socket.end(bytes);
  });
}

function dechunk(text: string): string {
  let out = "";
  for (let at = 0; ; ) {
    const line = text.indexOf("\r\n", at);
    const size = Number.parseInt(text.slice(at, line), 16);
    if (!(size > 0)) return out;
    out += text.slice(line + 2, line + 2 + size);
    at = line + 2 + size + 2;
  }
}

const ROUTES = [
  "/healthz",
  "/.well-known/receipt-keys.json",
  "/webhooks/stripe/identity",
  "/webhooks/stripe/payments",
  "/webhooks/stripe/connect",
  "/webhooks/records",
  "/webhooks/twilio",
  "/webhooks/telnyx",
  "/r/rcl_not_a_token",
  "/r/rcl_not_a_token.json",
  "/r/",
  "/u/upl_not_a_token",
  "/u/",
  "/.well-known/security.txt",
  "/demo/flows",
  "/demo/runs",
  "/demo/runs/run_1",
  "/demo/runs/run_1/next",
  ...Object.keys(STATIC_FILES),
];

const EVENT_TYPES = ["identity.verification_session.verified", "identity.verification_session.canceled", "checkout.session.completed", "checkout.session.expired", "checkout.session.async_payment_failed", "constructor", "__proto__", "x.y"];

function target(g: fc.GeneratorValue): string {
  const base = pick(g, ROUTES);
  return pick<() => string>(g, [
    () => base,
    () => base,
    () => `${base}?${stringOf(g, 12, ["a", "=", "&", "%", "2", "f", "/"])}`,
    () => base + pick(g, ["/", "//", "/..", "/../..", "%2e%2e/", "%00", "%", "#frag", "/x"]),
    () => pick(g, ["//healthz", "/..%2f..%2fetc%2fpasswd", "/%2e%2e/", "*", "http://127.0.0.1/healthz", "healthz", "/" + "a".repeat(int(g, 1, 5000)), "/é", "/a b"]),
    () => `/${g(nastyString, 30)}`,
  ])();
}

function body(g: fc.GeneratorValue, path: string, served: Served): { body: string; headers: string[] } {
  const now = Math.floor(served.world.t.clock.now().getTime() / 1000);
  if (path.startsWith("/webhooks/stripe/")) {
    const event = {
      id: `evt_${g(printableString, 6)}`,
      type: pick(g, EVENT_TYPES),
      data: { object: { id: pick(g, ["vs_1", "cs_1", `x_${g(printableString, 6)}`]), payment_status: pick(g, ["paid", "unpaid", 1]) } },
    };
    const text = chance(g, 0.8) ? JSON.stringify(chance(g, 0.6) ? event : mutate(g, event)) ?? "" : g(nastyString, 80);
    const signature = pick(g, [signStripePayload(text, DEMO_SECRET, now), signStripePayload(text, "whsec_other", now), `t=${now},v1=${g(printableString, 64)}`, g(nastyString, 30)]);
    return { body: text, headers: chance(g, 0.9) ? [`Stripe-Signature: ${signature}`] : [] };
  }
  const json = pick<() => string>(g, [() => JSON.stringify({ flow: pick(g, ["deposit", "owner-command", "nope", 1, null]) }), () => JSON.stringify(g(jsonValue, 3)), () => g(nastyString, 60), () => ""])();
  return { body: json, headers: chance(g, 0.8) ? [`Content-Type: ${pick(g, ["application/json", "application/json; charset=utf-8", "text/plain", "application/x-www-form-urlencoded"])}`] : [] };
}

interface RequestPlan {
  bytes: Buffer;
  method: string;
  path: string;
}

function request(g: fc.GeneratorValue, served: Served): RequestPlan {
  const method = pick(g, ["GET", "GET", "POST", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD", "get", "TRACE", "BREW"]);
  const path = target(g);
  const host = pick(g, [`127.0.0.1:${served.port}`, `127.0.0.1:${served.port}`, `localhost:${served.port}`, `[::1]:${served.port}`, "evil.example.test", `127.0.0.1:${served.port + 1}`, "", null]);
  const { body: text, headers } = body(g, path, served);
  const bytes = Buffer.from(chance(g, 0.95) ? text : "x".repeat(4096), "utf8");
  if (chance(g, 0.3)) headers.push(`Origin: ${pick(g, [`http://${host}`, "http://evil.example.test", "null"])}`);
  if (chance(g, 0.1)) headers.push(`${pick(g, ["X-Junk", "Content-Length", "Transfer-Encoding", "Host"])}: ${stringOf(g, 10, ["a", "1", " ", ",", "chunked"])}`);
  const lines = [`${method} ${path} HTTP/1.1`, ...(host === null ? [] : [`Host: ${host}`]), ...headers, `Content-Length: ${bytes.length}`, "Connection: close", "", ""];
  const raw = Buffer.concat([Buffer.from(lines.join("\r\n"), "utf8"), bytes]);
  // Now and then, bytes that are not HTTP at all, or a request cut short.
  const roll = int(g, 0, 99);
  if (roll < 5) return { bytes: Buffer.from(g(fc.uint8Array, { minLength: 1, maxLength: 200 })), method, path };
  if (roll < 10) return { bytes: raw.subarray(0, int(g, 0, raw.length)), method, path };
  return { bytes: raw, method, path };
}

// 503 is a signed webhook event the engine could not apply yet, answered with `retry: true` so
// Stripe sends it again, or the server's own overload refusal (SRV-2).
const MEANT = new Set([200, 201, 400, 403, 404, 405, 409, 413, 415, 501, 503]);

describe("fuzz: the reference server's request parsing", () => {
  const servers: Served[] = [];
  before(async () => {
    servers.push(await serve(false), await serve(true));
  });
  after(async () => {
    for (const s of servers) await s.close();
  });

  it("answers any request with a status it means, never a 500, and keeps serving", async () => {
    await fuzz(
      fc.asyncProperty(fc.gen(), async (g) => {
        const served = pick(g, servers);
        const plan = request(g, served);
        const reply = await send(served.port, plan.bytes);
        if (reply !== null) {
          assert.ok(MEANT.has(reply.status), `status ${reply.status}: ${reply.body}`);
          if (reply.body !== "" && plan.method !== "HEAD") {
            if (reply.headers["content-type"]?.startsWith("application/json")) {
              const answer = JSON.parse(reply.body) as Record<string, unknown>;
              if (reply.status === 503 && answer.retry === true) assert.deepEqual(answer, { received: true, applied: false, retry: true });
              else if (reply.status >= 400) assert.equal(typeof answer.error, "string");
            } else {
              // Node's own parser refuses a request it cannot read with a bare 400, and the UI
              // serves its static files; nothing else answers in anything but JSON.
              assert.ok(reply.status === 400 || (served.ui && reply.status === 200), `${reply.status} ${reply.headers["content-type"]}`);
            }
          }
          if (reply.status === 500) assert.fail("a 500");
        }
        if (chance(g, 0.1)) {
          const health = await send(served.port, Buffer.from(`GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:${served.port}\r\nConnection: close\r\n\r\n`));
          assert.equal(health?.status, 200, "the server still answers");
        }
      }),
      // Each case is a new connection, and a closed one holds its port for a while (TIME_WAIT):
      // the cap keeps a long run inside the ephemeral port range.
      { minRuns: 10, maxRuns: 4000 },
    );
  });
});
