// The reference server's browser UI: the static files (allow-list, traversal, content types,
// headers), the /demo/* routes that run the scripted calls one step at a time, and the page's own
// receipt and ledger checks (public/receipt-check.js), run here against what the engine signed.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { request } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it, mock } from "node:test";

import { createReferenceServer } from "../examples/reference-server/src/app.ts";
import { DemoRuns, type RunView } from "../examples/reference-server/src/demo-runs.ts";
import {
  DEMO_CONNECT_SECRET,
  DEMO_SECRET,
  FIRST_FAILURE_WAIT_MS,
  SCRIPTS,
  createDemoWorld,
  isDemoFlow,
  recordLinks,
  verifyToLevel2,
  waitOutFailureWait,
  type CreatedLink,
  type DemoWorld,
} from "../examples/reference-server/src/script.ts";
import { STATIC_FILES, UI_CSP } from "../examples/reference-server/src/static.ts";
import { EngineError, canonicalJson, signStripePayload, verifyReceipt, type AuditEntry, type PaymentLinks, type SignedReceipt } from "../src/index.ts";
import { FixedClock, FakePaymentLinks } from "../src/testing/index.ts";
import { confirmAmount } from "./helpers.ts";

interface CheckResult {
  ok: boolean;
  reason: string;
}
interface ReceiptCheckModule {
  canonicalJson(value: unknown): string;
  base64urlToBytes(text: string): Uint8Array;
  sha256Hex(text: string): Promise<string>;
  checkReceipt(receipt: unknown, keys: readonly unknown[]): Promise<CheckResult>;
  entryHashMatches(entry: unknown): Promise<boolean>;
  tamperedCopy<R>(receipt: R): R;
  shortHash(hex: string): string;
}

const PUBLIC = new URL("../examples/reference-server/public/", import.meta.url);

interface Served {
  world: DemoWorld;
  base: string;
  port: number;
  close(): Promise<void>;
}

async function serve(ui = true): Promise<Served> {
  const world = createDemoWorld();
  const server = createReferenceServer({
    engine: world.engine,
    clock: world.t.clock,
    stripeSecrets: { identity: [DEMO_SECRET], payments: [DEMO_SECRET], connect: [DEMO_CONNECT_SECRET] },
    ...(ui ? { ui: new DemoRuns(world) } : {}),
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  world.base = `http://127.0.0.1:${port}`;
  return {
    world,
    base: world.base,
    port,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await world.close();
    },
  };
}

/** A raw request, so the path and the Host header go out exactly as written. */
function raw(port: number, path: string, headers: Record<string, string> = {}, method = "GET", body = ""): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    // Without a host header, send none at all (node would otherwise add its own).
    const req = request({ host: "127.0.0.1", port, path, method, headers, setHost: "host" in headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

describe("reference UI: static files", () => {
  let s: Served;
  before(async () => {
    s = await serve();
  });
  after(() => s.close());

  it("serves every allow-listed file with its content type, the strict CSP and the hardening headers", async () => {
    assert.deepEqual(Object.keys(STATIC_FILES).sort(), ["/", "/app.js", "/receipt-check.js", "/style.css"]);
    for (const [path, [file, type]] of Object.entries(STATIC_FILES)) {
      const res = await fetch(`${s.base}${path}`);
      assert.equal(res.status, 200, path);
      assert.equal(res.headers.get("content-type"), type);
      assert.equal(res.headers.get("content-security-policy"), UI_CSP);
      assert.equal(res.headers.get("x-content-type-options"), "nosniff");
      assert.equal(res.headers.get("referrer-policy"), "no-referrer");
      assert.equal(res.headers.get("cache-control"), "no-store");
      assert.equal(await res.text(), readFileSync(new URL(file, PUBLIC), "utf8"));
    }
    assert.match(UI_CSP, /script-src 'self';/);
    assert.doesNotMatch(UI_CSP, /unsafe-inline|unsafe-eval|\*/);
    assert.match(UI_CSP, /^default-src 'none'/);
    assert.match(UI_CSP, /frame-ancestors 'none'/);
  });

  it("keeps the page free of inline script, inline style and inline handlers, so the CSP holds", () => {
    const html = readFileSync(new URL("index.html", PUBLIC), "utf8");
    for (const tag of html.match(/<script\b[^>]*>/gi) ?? []) assert.match(tag, /src="\/[a-z-]+\.js"/, "every script is a file");
    assert.doesNotMatch(html, /<script\b[^>]*>\s*[^<\s]/i, "no inline script");
    assert.doesNotMatch(html, /<style\b|\sstyle\s*=/i, "no inline style");
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, "no inline event handler");
    const app = readFileSync(new URL("app.js", PUBLIC), "utf8");
    assert.doesNotMatch(app, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/, "values are written as text");
  });

  it("serves nothing outside the allow-list: traversal, encodings, case, other files", async () => {
    const outside = [
      "/index.html",
      "/package.json",
      "/../package.json",
      "/%2e%2e/package.json",
      "/%2E%2E/%2E%2E/package.json",
      "/..%2fpackage.json",
      "/..%5c..%5cpackage.json",
      "/public/app.js",
      "/app.js/",
      "/APP.JS",
      "/app.js%00.png",
      "/src/app.ts",
      "/examples/reference-server/public/app.js",
      "/receipt-check.js/../../src/app.ts",
      "/style.css%2f..%2f..%2fapp.ts",
    ];
    for (const path of outside) {
      const res = await raw(s.port, path, { host: `127.0.0.1:${s.port}` });
      assert.ok(res.status === 404, `${path}: ${res.status}`);
      assert.equal(res.headers["content-type"], "application/json; charset=utf-8", path);
      assert.equal(res.headers["x-content-type-options"], "nosniff", path);
      assert.doesNotMatch(res.body, /"name": "district-assurance"|createReferenceServer/, path);
    }
  });

  it("answers 405 to anything but GET on a file", async () => {
    const res = await fetch(`${s.base}/app.js`, { method: "POST", body: "" });
    assert.deepEqual([res.status, await res.json()], [405, { error: "method_not_allowed" }]);
  });

  it("refuses a Host header that is not this machine (DNS rebinding), and accepts the local names", async () => {
    // No Host header at all: node:http refuses an HTTP/1.1 request without one before the route runs.
    assert.equal((await raw(s.port, "/", {})).status, 400);
    for (const host of ["evil.example", "evil.example:80", "127.0.0.1.evil.example", "[bad", "localhost.evil.example:8787"]) {
      for (const path of ["/", "/demo/flows"]) {
        const res = await raw(s.port, path, { host });
        assert.equal(res.status, 403, `${host} ${path}`);
        assert.deepEqual(JSON.parse(res.body), { error: "host_not_allowed" });
      }
    }
    for (const host of [`127.0.0.1:${s.port}`, `localhost:${s.port}`, `[::1]:${s.port}`, `LOCALHOST:${s.port}`]) {
      assert.equal((await raw(s.port, "/", { host })).status, 200, host);
    }
  });

  it("matches the Host header's port too: another port or none is not this server", async () => {
    for (const host of ["localhost:9999", "127.0.0.1:1", `[::1]:${s.port + 1}`, "localhost", "127.0.0.1", `localhost:${s.port}0`, `localhost:0${s.port}`]) {
      for (const path of ["/", "/demo/flows", "/healthz"]) {
        const res = await raw(s.port, path, { host });
        assert.equal(res.status, 403, `${host} ${path}`);
      }
    }
  });

  it("with the UI on, refuses a foreign Host on every route, the webhooks, receipts and key set included", async () => {
    const host = `evil.example:${s.port}`;
    for (const path of ["/.well-known/receipt-keys.json", "/receipts/call_1", "/healthz", "/webhooks/twilio", "/nope"]) {
      const res = await raw(s.port, path, { host });
      assert.deepEqual([res.status, JSON.parse(res.body)], [403, { error: "host_not_allowed" }], path);
    }
    // A webhook signed with the published demo secret, from a page on a rebound name: refused before it is read.
    const payload = JSON.stringify({ id: "evt_rebind", type: "checkout.session.completed", data: { object: { id: "cs_fake_1", payment_status: "paid" } } });
    const signature = signStripePayload(payload, DEMO_SECRET, Math.floor(s.world.t.clock.now().getTime() / 1000));
    const res = await raw(s.port, "/webhooks/stripe/payments", { host, "stripe-signature": signature, "content-type": "application/json" }, "POST", payload);
    assert.deepEqual([res.status, JSON.parse(res.body)], [403, { error: "host_not_allowed" }]);
    const local = await raw(s.port, "/webhooks/stripe/payments", { host: `127.0.0.1:${s.port}`, "stripe-signature": signature }, "POST", payload);
    assert.deepEqual([local.status, JSON.parse(local.body)], [503, { received: true, applied: false, retry: true }], "the same event on this machine's name is read (no call holds its link yet)");
  });

  it("answers 400 to a request target that is not a path", async () => {
    for (const [path, method] of [["*", "OPTIONS"], ["http://evil.example/style.css", "GET"]] as const) {
      const res = await raw(s.port, path, { host: `127.0.0.1:${s.port}` }, method);
      assert.deepEqual([res.status, JSON.parse(res.body)], [400, { error: "bad_request" }], path);
    }
  });

  it("reads a path that starts with // as a path, not as a host", async () => {
    for (const path of ["//style.css", "//app.js", "//evil.example/", "///"]) {
      const res = await raw(s.port, path, { host: `127.0.0.1:${s.port}` });
      assert.equal(res.status, 404, path);
      assert.equal(res.headers["content-type"], "application/json; charset=utf-8", path);
    }
  });

  it("sends the hardening headers on JSON answers too", async () => {
    const res = await fetch(`${s.base}/healthz`);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.equal(res.headers.get("content-security-policy"), "default-src 'none'; frame-ancestors 'none'");
  });

  it("serves no UI and no demo routes when the server has no `ui`", async () => {
    const off = await serve(false);
    try {
      for (const path of ["/", "/app.js", "/demo/flows", "/demo/runs"]) assert.equal((await fetch(`${off.base}${path}`)).status, 404, path);
      assert.equal((await fetch(`${off.base}/healthz`)).status, 200);
      // `npm run serve` takes forwarded webhooks under any name, as before (no UI, no demo secret).
      assert.equal((await raw(off.port, "/healthz", { host: "tunnel.example" })).status, 200);
    } finally {
      await off.close();
    }
  });
});

describe("reference UI: demo routes", () => {
  let s: Served;
  before(async () => {
    s = await serve();
  });
  after(() => s.close());

  const json = { "content-type": "application/json" };
  const start = async (flow: string) => {
    const res = await fetch(`${s.base}/demo/runs`, { method: "POST", headers: json, body: JSON.stringify({ flow }) });
    return [res.status, (await res.json()) as RunView] as const;
  };
  const next = (runId: string) => fetch(`${s.base}/demo/runs/${runId}/next`, { method: "POST", headers: json, body: "{}" });

  it("lists the demo's four flows with their steps", async () => {
    const { flows } = (await (await fetch(`${s.base}/demo/flows`)).json()) as { flows: Array<{ flow: string; summary: string; steps: string[] }> };
    assert.deepEqual(flows.map((f) => [f.flow, f.steps.length]), [["owner-command", 6], ["deposit", 12], ["deposit-connect", 6], ["entry", 6]]);
    assert.match(flows[1]!.summary, /deposit/);
    assert.equal((await fetch(`${s.base}/demo/flows`, { method: "POST", headers: json, body: "{}" })).status, 405);
  });

  it("runs deposit one step per request, with state, ledger and a receipt the page's own check accepts", async () => {
    const [status, view] = await start("deposit");
    assert.equal(status, 201);
    assert.match(view.runId, /^run_[0-9a-f-]{36}$/);
    assert.deepEqual([view.next, view.done, view.callId, view.state, view.position, view.ledger], [0, false, null, null, null, []]);
    let last = view;
    for (let i = 0; i < SCRIPTS.deposit.length; i++) {
      const res = await next(view.runId);
      assert.equal(res.status, 200);
      last = (await res.json()) as RunView;
      assert.equal(last.next, i + 1);
      assert.equal(last.results[i]!.ok, true, `${last.results[i]!.label}: ${last.results[i]!.detail}`);
      assert.ok(last.ledger.every((e) => e.callId === last.callId), "only this call's entries");
      assert.equal(last.chain.ok, true);
    }
    assert.equal(last.done, true);
    assert.equal(last.state!.phase, "ended");
    assert.equal(last.state!.level, 2);
    assert.equal(last.position!.status, "completed");
    assert.deepEqual((await (await next(view.runId)).json()) as unknown, { error: "done" });
    assert.equal((await next(view.runId)).status, 409);
    const again = (await (await fetch(`${s.base}/demo/runs/${view.runId}`)).json()) as RunView;
    assert.deepEqual(again.results, last.results);

    const check = (await import(new URL("receipt-check.js", PUBLIC).href)) as ReceiptCheckModule;
    const receipt = (await (await fetch(`${s.base}/receipts/${last.callId}`)).json()) as SignedReceipt;
    const { keys } = (await (await fetch(`${s.base}/.well-known/receipt-keys.json`)).json()) as { keys: unknown[] };
    assert.deepEqual(await check.checkReceipt(receipt, keys), { ok: true, reason: "valid" });
    assert.deepEqual(await check.checkReceipt(check.tamperedCopy(receipt), keys), { ok: false, reason: "signature_mismatch" });
    for (const entry of last.ledger) assert.equal(await check.entryHashMatches(entry), true, `entry ${entry.seq}`);
  });

  it("runs owner-command to the end, with no receipt", async () => {
    const [, view] = await start("owner-command");
    let last = view;
    for (let i = 0; i < SCRIPTS["owner-command"].length; i++) last = (await (await next(view.runId)).json()) as RunView;
    assert.deepEqual(last.results.map((r) => r.ok), [true, true, true, true, true, true]);
    assert.equal(last.done, true);
    assert.equal((await fetch(`${s.base}/receipts/${last.callId}`)).status, 404);
  });

  it("runs two entry calls that reach the door together: both wait for the relay, and each checks its own door (review of #50)", async () => {
    const world = createDemoWorld();
    const server = createReferenceServer({ engine: world.engine, clock: world.t.clock, stripeSecrets: { identity: [DEMO_SECRET], payments: [DEMO_SECRET], connect: [DEMO_CONNECT_SECRET] }, ui: new DemoRuns(world) });
    const runs = new DemoRuns(world);
    try {
      const a = await runs.start("entry");
      const b = await runs.start("entry");
      for (let i = 0; i < 2; i++) await Promise.all([runs.step(a.runId), runs.step(b.runId)]);
      // Both reach the door at once, before the relay has started.
      const [ra, rb] = await Promise.all([runs.step(a.runId), runs.step(b.runId)]);
      for (const r of [ra, rb]) assert.ok(r.ok && r.view.results.at(-1)!.ok, JSON.stringify(r.ok ? r.view.results.at(-1) : r));
      assert.equal(world.openedFor.size, 2);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await world.close();
    }
  });

  it("runs deposit-connect and entry to the end, one step per request", async () => {
    for (const flow of ["deposit-connect", "entry"] as const) {
      const [, view] = await start(flow);
      let last = view;
      for (let i = 0; i < SCRIPTS[flow].length; i++) last = (await (await next(view.runId)).json()) as RunView;
      assert.deepEqual(last.results.map((r) => [r.label, r.ok]), SCRIPTS[flow].map((step) => [step.label, true]), flow);
      assert.equal(last.done, true);
    }
  });

  it("refuses an unknown flow, bad JSON, a non-JSON body and another origin", async () => {
    assert.deepEqual(await start("refund"), [400, { error: "unknown_flow" }] as unknown);
    assert.deepEqual(await start("__proto__"), [400, { error: "unknown_flow" }] as unknown);
    let res = await fetch(`${s.base}/demo/runs`, { method: "POST", headers: json, body: "{not json" });
    assert.deepEqual([res.status, await res.json()], [400, { error: "malformed_json" }]);
    res = await fetch(`${s.base}/demo/runs`, { method: "POST", headers: json, body: "null" });
    assert.deepEqual([res.status, await res.json()], [400, { error: "unknown_flow" }]);
    res = await fetch(`${s.base}/demo/runs`, { method: "POST", headers: { "content-type": "text/plain" }, body: JSON.stringify({ flow: "deposit" }) });
    assert.deepEqual([res.status, await res.json()], [415, { error: "json_required" }]);
    res = await fetch(`${s.base}/demo/runs`, { method: "POST", body: JSON.stringify({ flow: "deposit" }) });
    assert.equal(res.status, 415);
    res = await fetch(`${s.base}/demo/runs`, { method: "POST", headers: { ...json, origin: "http://evil.example" }, body: JSON.stringify({ flow: "deposit" }) });
    assert.deepEqual([res.status, await res.json()], [403, { error: "cross_origin" }]);
    res = await fetch(`${s.base}/demo/runs`, { method: "POST", headers: { ...json, origin: "null" }, body: JSON.stringify({ flow: "deposit" }) });
    assert.equal(res.status, 403);
    res = await fetch(`${s.base}/demo/runs`, { method: "POST", headers: { ...json, origin: s.base }, body: JSON.stringify({ flow: "deposit" }) });
    assert.equal(res.status, 201, "the page's own origin");
    const [, view] = await start("deposit");
    res = await fetch(`${s.base}/demo/runs/${view.runId}/next`, { method: "POST", headers: { "content-type": "text/plain" }, body: "{}" });
    assert.equal(res.status, 415);
    assert.equal(((await (await fetch(`${s.base}/demo/runs/${view.runId}`)).json()) as RunView).next, 0, "nothing ran");
  });

  it("answers 404 for unknown runs and 405 for the wrong method", async () => {
    assert.equal((await fetch(`${s.base}/demo/runs/run_nope`)).status, 404);
    assert.deepEqual(await (await next("run_nope")).json(), { error: "not_found" });
    assert.equal((await fetch(`${s.base}/demo/runs/bad%20id`)).status, 404);
    assert.equal((await fetch(`${s.base}/demo/runs/run_x/next/more`)).status, 404);
    assert.equal((await fetch(`${s.base}/demo/other`)).status, 404);
    assert.equal((await fetch(`${s.base}/demo/runs`)).status, 405);
    const [, view] = await start("deposit");
    assert.equal((await fetch(`${s.base}/demo/runs/${view.runId}`, { method: "POST", headers: json, body: "{}" })).status, 405);
    assert.equal((await fetch(`${s.base}/demo/runs/${view.runId}/next`)).status, 405);
  });

  it("refuses a body over the limit", async () => {
    const res = await fetch(`${s.base}/demo/runs`, { method: "POST", headers: json, body: JSON.stringify({ flow: "x".repeat(70_000) }) });
    assert.deepEqual([res.status, await res.json()], [413, { error: "body_too_large" }]);
  });
});

describe("reference UI: DemoRuns", () => {
  it("runs one step at a time per run: a second request while one runs is busy", async () => {
    const runs = new DemoRuns(createDemoWorld());
    const { runId } = await runs.start("deposit");
    const first = runs.step(runId);
    assert.deepEqual(await runs.step(runId), { ok: false, status: 409, error: "busy" });
    const done = await first;
    assert.equal(done.ok && done.view.next, 1);
  });

  it("answers a view asked for during a step after that step, never half way", async () => {
    const runs = new DemoRuns(createDemoWorld());
    const { runId } = await runs.start("deposit");
    const stepping = runs.step(runId);
    const seen = await runs.view(runId);
    assert.ok(seen.ok);
    assert.equal(seen.view.next, 1);
    assert.notEqual(seen.view.callId, null);
    assert.equal(seen.view.state!.callId, seen.view.callId);
    await stepping;
  });

  it("keeps a run's payment its own when runs interleave", async () => {
    const s = await serve();
    try {
      const runs = new DemoRuns(s.world);
      const a = await runs.start("deposit");
      const b = await runs.start("deposit");
      const payAt = SCRIPTS.deposit.findIndex((step) => step.label.startsWith("pay: link"));
      for (let i = 0; i <= payAt; i++) {
        await runs.step(a.runId);
        await runs.step(b.runId);
      }
      let last: RunView | null = null;
      for (const runId of [a.runId, b.runId]) {
        let answer = await runs.step(runId);
        while (answer.ok && !answer.view.done) answer = await runs.step(runId);
        assert.ok(answer.ok);
        assert.ok(answer.view.results.every((r) => r.ok), JSON.stringify(answer.view.results.filter((r) => !r.ok)));
        assert.equal(answer.view.results[payAt]!.detail.endsWith(`cs_fake_${runId === a.runId ? 1 : 2}"`), true);
        last = answer.view;
        const receipt = (await s.world.engine.receipt(answer.view.callId!))!;
        assert.equal(receipt.body.payments[0]!.status, "paid");
      }
      assert.ok(last !== null);
    } finally {
      await s.close();
    }
  });

  it("keeps only the newest runs", async () => {
    const runs = new DemoRuns(createDemoWorld(), 2);
    const a = await runs.start("deposit");
    const b = await runs.start("owner-command");
    const c = await runs.start("deposit");
    assert.deepEqual(await runs.view(a.runId), { ok: false, status: 404, error: "not_found" });
    assert.equal((await runs.view(b.runId)).ok, true);
    assert.equal((await runs.view(c.runId)).ok, true);
  });

  it("ends a run on a step that throws, naming an engine refusal and hiding anything else", async () => {
    const world = createDemoWorld();
    const runs = new DemoRuns(world);
    world.engine.startCall = () => Promise.reject(new EngineError("unknown_call", "secret detail"));
    let run = await runs.start("deposit");
    let answer = await runs.step(run.runId);
    assert.ok(answer.ok);
    assert.deepEqual(answer.view.results, [{ index: 0, label: "deposit: call started", detail: "refused: unknown_call", ok: false }]);
    assert.equal(answer.view.done, true);
    assert.deepEqual(await runs.step(run.runId), { ok: false, status: 409, error: "done" });

    world.engine.startCall = () => Promise.reject(new Error("secret detail"));
    run = await runs.start("owner-command");
    answer = await runs.step(run.runId);
    assert.ok(answer.ok);
    assert.equal(answer.view.results[0]!.detail, "failed: internal error");
  });

  it("knows only the four demo flows", () => {
    assert.deepEqual(
      [isDemoFlow("deposit"), isDemoFlow("owner-command"), isDemoFlow("deposit-connect"), isDemoFlow("entry"), isDemoFlow("toString"), isDemoFlow(1)],
      [true, true, true, true, false, false],
    );
  });
});

describe("reference UI: the page's checks (receipt-check.js, no DOM)", () => {
  let check: ReceiptCheckModule;
  let receipt: SignedReceipt;
  let keys: Array<Record<string, unknown>>;
  let entries: AuditEntry[];

  before(async () => {
    check = (await import(new URL("receipt-check.js", PUBLIC).href)) as ReceiptCheckModule;
    const world = createDemoWorld();
    const runs = new DemoRuns(world);
    const server = createReferenceServer({ engine: world.engine, clock: world.t.clock, stripeSecrets: { identity: [], payments: [DEMO_SECRET] } });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    world.base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const { runId } = await runs.start("deposit");
    let answer = await runs.step(runId);
    while (answer.ok && !answer.view.done) answer = await runs.step(runId);
    await new Promise<void>((resolve) => server.close(() => resolve()));
    assert.ok(answer.ok);
    receipt = (await world.engine.receipt(answer.view.callId!))!;
    keys = world.engine.receiptKeys() as Array<Record<string, unknown>>;
    entries = await world.t.ledger.list();
  });

  it("writes the same canonical JSON as the engine", () => {
    const samples: unknown[] = [
      receipt.body,
      entries,
      { b: 1, a: [true, false, null, "x"], "é": { z: -0.5, y: 1e21 }, A: "  \"q\" \\" },
      { "😀": 1, "￿": 2, "": 3 },
      [],
      {},
    ];
    for (const sample of samples) assert.equal(check.canonicalJson(sample), canonicalJson(sample));
    assert.throws(() => check.canonicalJson({ n: Number.NaN }), TypeError);
    assert.throws(() => check.canonicalJson(undefined), TypeError);
    assert.throws(() => check.canonicalJson(() => 1), TypeError);
  });

  it("accepts the engine's receipt, as verifyReceipt does, and rejects every kind of change", async () => {
    assert.equal(verifyReceipt(receipt, keys), true);
    assert.deepEqual(await check.checkReceipt(receipt, keys), { ok: true, reason: "valid" });
    const head = receipt.body.ledger.hash;
    const forged = check.tamperedCopy(receipt);
    assert.notEqual(forged.body.ledger.hash, head);
    assert.equal(forged.body.ledger.hash.slice(1), head.slice(1), "one character changed");
    assert.equal(receipt.body.ledger.hash, head, "the original is untouched");
    assert.equal(verifyReceipt(forged, keys), false);
    assert.deepEqual(await check.checkReceipt(forged, keys), { ok: false, reason: "signature_mismatch" });
    const zero = structuredClone(receipt);
    zero.body.ledger.hash = `0${zero.body.ledger.hash.slice(1)}`;
    assert.equal(check.tamperedCopy(zero).body.ledger.hash[0], "1");
    const amount = structuredClone(receipt);
    amount.body.payments[0]!.amountMinor += 1;
    assert.deepEqual(await check.checkReceipt(amount, keys), { ok: false, reason: "signature_mismatch" });
    assert.deepEqual(await check.checkReceipt({ ...receipt, alg: "RS256" }, keys), { ok: false, reason: "wrong_alg" });
    assert.deepEqual(await check.checkReceipt({ ...receipt, kid: "other" }, keys), { ok: false, reason: "unknown_kid" });
    assert.deepEqual(await check.checkReceipt(receipt, []), { ok: false, reason: "unknown_kid" });
    assert.deepEqual(await check.checkReceipt({ ...receipt, signature: "not base64url!" }, keys), { ok: false, reason: "malformed_signature" });
    assert.deepEqual(await check.checkReceipt({ ...receipt, signature: receipt.signature.slice(4) }, keys), { ok: false, reason: "malformed_signature" });
    assert.deepEqual(await check.checkReceipt(receipt, [{ ...keys[0], x: "AAAA" }]), { ok: false, reason: "bad_key" });
    const other = createDemoWorld().engine.receiptKeys()[0] as Record<string, unknown>;
    assert.deepEqual(await check.checkReceipt(receipt, [{ ...other, kid: receipt.kid }]), { ok: false, reason: "signature_mismatch" });
  });

  it("recomputes every ledger entry's hash, and notices a change", async () => {
    for (const entry of entries) assert.equal(await check.entryHashMatches(entry), true);
    const changed = { ...entries[0]!, actor: "caller" };
    assert.equal(await check.entryHashMatches(changed), false);
  });

  it("has small helpers that behave", async () => {
    assert.deepEqual([...check.base64urlToBytes("_-8")], [255, 239]);
    assert.deepEqual([...check.base64urlToBytes("")], []);
    assert.throws(() => check.base64urlToBytes("a+b"), TypeError);
    assert.equal(await check.sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert.equal(check.shortHash("a".repeat(64)), "aaaaaaaa...aaaaaaaa");
    assert.equal(check.shortHash("abc"), "abc");
  });
});

describe("reference UI: the demo world's adapters and clock (review of #50)", () => {
  /** A real adapter's shape: private state, and the optional `cancel` and `refund` of later PRs. */
  class RealLinks {
    readonly capabilities = new FakePaymentLinks().capabilities;
    readonly #calls: string[] = [];
    get calls(): readonly string[] {
      return this.#calls;
    }
    async createLink(input: { paymentId: string }): Promise<{ linkId: string; url: string }> {
      this.#calls.push(`create ${input.paymentId}`);
      return { linkId: `cs_${input.paymentId}`, url: `https://checkout.example/cs_${input.paymentId}` };
    }
    async expireLink(input: { linkId: string }): Promise<{ state: "expired" }> {
      this.#calls.push(`expire ${input.linkId}`);
      return { state: "expired" };
    }
    async cancel(input: { linkId: string }): Promise<{ state: "cancelled" }> {
      this.#calls.push(`cancel ${input.linkId}`);
      return { state: "cancelled" };
    }
    async refund(input: { paymentIntentId: string }): Promise<{ state: "refunded" }> {
      this.#calls.push(`refund ${input.paymentIntentId}`);
      return { state: "refunded" };
    }
  }

  it("passes cancel and refund through to the real adapter, on the adapter itself, and records each link", async () => {
    const real = new RealLinks();
    const links: CreatedLink[] = [];
    const wrapped = recordLinks(real as unknown as PaymentLinks, links) as unknown as RealLinks;
    assert.equal(wrapped.capabilities, real.capabilities);
    assert.equal(typeof wrapped.cancel, "function");
    assert.equal(typeof wrapped.refund, "function");
    assert.deepEqual(await wrapped.createLink({ paymentId: "pay_1" }), { linkId: "cs_pay_1", url: "https://checkout.example/cs_pay_1" });
    assert.deepEqual(await wrapped.expireLink({ linkId: "cs_pay_1" }), { state: "expired" });
    assert.deepEqual(await wrapped.cancel({ linkId: "cs_pay_1" }), { state: "cancelled" });
    assert.deepEqual(await wrapped.refund({ paymentIntentId: "pi_1" }), { state: "refunded" });
    assert.deepEqual(real.calls, ["create pay_1", "expire cs_pay_1", "cancel cs_pay_1", "refund pi_1"]);
    assert.deepEqual(links, [{ paymentId: "pay_1", linkId: "cs_pay_1", url: "https://checkout.example/cs_pay_1" }]);
  });

  it("wraps a frozen adapter too (L1 review round 2)", async () => {
    const links: CreatedLink[] = [];
    const fake = new FakePaymentLinks();
    // An object-literal adapter, frozen: its methods are its own, non-writable and non-configurable.
    const literal: PaymentLinks = { capabilities: fake.capabilities, createLink: (input) => fake.createLink(input), expireLink: (input) => fake.expireLink(input), refund: (input) => fake.refund(input) };
    const frozen = Object.freeze(literal);
    const wrapped = recordLinks(frozen, links);
    assert.equal((await wrapped.createLink({ callId: "c", paymentId: "pay_1", amountMinor: 100, currency: "cad", description: "d", mode: "platform", paymentMethods: ["card"], expiresAt: new Date(Date.now() + 3_600_000).toISOString(), idempotencyKey: "k" })).linkId, "cs_fake_1");
    assert.equal(links.length, 1);
    assert.equal(typeof wrapped.refund, "function");
  });

  it("leaves an optional method missing when the real adapter lacks it", () => {
    const plain: PaymentLinks = { capabilities: new FakePaymentLinks().capabilities, createLink: async () => ({ linkId: "l", url: "u" }), expireLink: async () => ({ state: "expired" }) };
    const wrapped = recordLinks(plain, []) as PaymentLinks & { cancel?: unknown; refund?: unknown };
    assert.equal("cancel" in wrapped, false);
    assert.equal(wrapped.cancel, undefined);
    assert.equal(wrapped.refund, undefined);
  });

  it("builds the demo world on the wrapped adapter, so a link the real one creates is recorded", async () => {
    const real = new RealLinks();
    const world = createDemoWorld({ payments: real as unknown as PaymentLinks });
    const call = { callId: (await world.engine.startCall({ locale: "fr", flow: "deposit-connect" })).callId, linkId: "", receipt: null };
    assert.ok((await verifyToLevel2(world, call, "payment.request")).ok);
    await confirmAmount(world.engine, call.callId);
    const payment = await world.engine.requestPayment(call.callId);
    assert.deepEqual(real.calls, [`create ${payment.paymentId}`]);
    assert.deepEqual(world.links.map((link) => link.paymentId), [payment.paymentId]);
    await world.close();
  });

  it("starts the door relay once for callers that ask together (#47's shared startup)", async () => {
    const world = createDemoWorld();
    const [a, b] = await Promise.all([world.relayUrl(), world.relayUrl()]);
    assert.equal(a, b);
    assert.equal(await world.relayUrl(), a);
    await world.close();
  });

  it("counts only a door opened for this run's own grant, never one opened for another grant", async () => {
    const world = createDemoWorld();
    const runs = new DemoRuns(world);
    const first = await runs.start("entry");
    for (let i = 0; i < 3; i++) await runs.step(first.runId);
    assert.equal(world.doorsOpened.length, 1);
    // The same world, but the record of which grants opened a door is lost: a door did open (for the
    // first run), yet none for this run's grant, so the step must not pass.
    const blind: DemoWorld = { ...world, openedFor: new Set<string>() };
    const call = { callId: "", linkId: "", receipt: null };
    const steps = SCRIPTS.entry;
    for (const step of steps.slice(0, 2)) assert.ok((await step.run(blind, call)).ok);
    const door = await steps[2]!.run(blind, call);
    assert.equal(door.ok, false, door.detail);
    assert.match(door.detail, /NO door opened for it/);
    await world.close();
  });

  it("moves a fixed clock past VER-1's first wait, without a timer", async () => {
    const clock = new FixedClock();
    const before = clock.now().getTime();
    mock.timers.enable({ apis: ["setTimeout"] });
    try {
      await waitOutFailureWait(clock);
    } finally {
      mock.timers.reset();
    }
    assert.ok(clock.now().getTime() - before > FIRST_FAILURE_WAIT_MS);
  });

  it("waits VER-1's first wait out for real on any other clock (the live demo's wall clock)", async () => {
    mock.timers.enable({ apis: ["setTimeout"] });
    try {
      let done = false;
      const waiting = waitOutFailureWait({ now: () => new Date() }).then(() => (done = true));
      await Promise.resolve();
      mock.timers.tick(FIRST_FAILURE_WAIT_MS);
      await Promise.resolve();
      assert.equal(done, false, "resolved before the wait passed");
      mock.timers.tick(100);
      await waiting;
      assert.equal(done, true);
    } finally {
      mock.timers.reset();
    }
  });

  it("the owner-command step waits for the right PIN on a clock that cannot be moved", async () => {
    const fixed = new FixedClock();
    // A clock with the fixed clock's time but no advance(): only real time can pass for it.
    const world = createDemoWorld({ clock: { now: () => fixed.now() } });
    const call = { callId: "", linkId: "", receipt: null };
    const steps = SCRIPTS["owner-command"];
    for (const step of steps.slice(0, 2)) assert.ok((await step.run(world, call)).ok);
    // Watch the right PIN itself, not the whole step: it must not be keyed before the wait passes.
    const pins: string[] = [];
    const submit = world.engine.submitPin.bind(world.engine);
    world.engine.submitPin = (callId, pin) => (pins.push(pin), submit(callId, pin));
    mock.timers.enable({ apis: ["setTimeout"] });
    try {
      const right = steps[2]!.run(world, call);
      await new Promise<void>((resolve) => setImmediate(resolve));
      assert.deepEqual(pins, [], "keyed the right PIN before VER-1's wait passed");
      mock.timers.tick(FIRST_FAILURE_WAIT_MS + 100);
      assert.ok((await right).ok);
      assert.equal(pins.length, 1, "keyed once, after the wait");
    } finally {
      mock.timers.reset();
    }
    await world.close();
  });
});
