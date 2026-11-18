// The reference server's browser UI: the static files (allow-list, traversal, content types,
// headers), the /demo/* routes that run the scripted calls one step at a time, and the page's own
// receipt and ledger checks (public/receipt-check.js), run here against what the engine signed.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { request } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { createReferenceServer } from "../examples/reference-server/src/app.ts";
import { DemoRuns, type RunView } from "../examples/reference-server/src/demo-runs.ts";
import { DEMO_SECRET, SCRIPTS, createDemoWorld, isDemoFlow, type DemoWorld } from "../examples/reference-server/src/script.ts";
import { STATIC_FILES, UI_CSP } from "../examples/reference-server/src/static.ts";
import { EngineError, canonicalJson, verifyReceipt, type AuditEntry, type SignedReceipt } from "../src/index.ts";

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
    stripeSecrets: { identity: [DEMO_SECRET], payments: [DEMO_SECRET] },
    ...(ui ? { ui: new DemoRuns(world) } : {}),
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  world.base = `http://127.0.0.1:${port}`;
  return { world, base: world.base, port, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

/** A raw request, so the path and the Host header go out exactly as written. */
function raw(port: number, path: string, headers: Record<string, string> = {}, method = "GET"): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    // Without a host header, send none at all (node would otherwise add its own).
    const req = request({ host: "127.0.0.1", port, path, method, headers, setHost: "host" in headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
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
    for (const tag of html.match(/<script\b[^>]*>/g) ?? []) assert.match(tag, /src="\/[a-z-]+\.js"/, "every script is a file");
    assert.doesNotMatch(html, /<script\b[^>]*>[^<]/, "no inline script");
    assert.doesNotMatch(html, /<style\b|\sstyle=/, "no inline style");
    assert.doesNotMatch(html, /\son[a-z]+=/, "no inline event handler");
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
    for (const host of [`localhost:${s.port}`, `[::1]:${s.port}`, "LOCALHOST"]) assert.equal((await raw(s.port, "/", { host })).status, 200, host);
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

  it("lists the demo's two flows with their steps", async () => {
    const { flows } = (await (await fetch(`${s.base}/demo/flows`)).json()) as { flows: Array<{ flow: string; summary: string; steps: string[] }> };
    assert.deepEqual(flows.map((f) => [f.flow, f.steps.length]), [["owner-command", 6], ["deposit", 11]]);
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
      const payAt = SCRIPTS.deposit.findIndex((step) => step.label.startsWith("pay:"));
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

  it("knows only the two demo flows", () => {
    assert.deepEqual([isDemoFlow("deposit"), isDemoFlow("owner-command"), isDemoFlow("toString"), isDemoFlow(1)], [true, true, false, false]);
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
