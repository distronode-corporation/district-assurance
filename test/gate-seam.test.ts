// The Seam adapter (GAT-5), against a local HTTP server that replays Seam's answers. The answers
// below follow the shapes of Seam's sandbox (`/devices/get`, `/locks/unlock_door`,
// `/action_attempts/get`); the device id picks the scenario. No request leaves the machine.
import { strict as assert } from "node:assert";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import type { SignedAccessGrant } from "../src/gate/access.ts";
import { seamAccessController, type SeamAccessControllerOptions } from "../src/gate/seam.ts";
import { FixedClock, generateTestSigner } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, setup, testConfig } from "./helpers.ts";

/** Not a secret: a made-up key in Seam's format. */
const API_KEY = "seam_test_notASecret_0000";

const grant: SignedAccessGrant = {
  body: {
    v: 1,
    kind: "access",
    grantId: "acc_1",
    workspaceId: "w",
    audience: "lobby",
    target: "dev-ok",
    action: "unlock",
    scope: "entry.open",
    level: 2,
    issuedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2026-01-01T00:01:00.000Z",
  },
  alg: "ES256",
  kid: "k1",
  signature: "sig",
};
const input = (target: string) => ({ grant, target, idempotencyKey: '["w","c","acc_1","unlock"]' });

// Recorded answers, trimmed to the fields the adapter reads plus a few it must ignore.
const device = (id: string, extra: Record<string, unknown> = {}) => ({
  ok: true,
  device: {
    device_id: id,
    device_type: "august_lock",
    display_name: "Front door",
    can_remotely_unlock: true,
    can_remotely_lock: true,
    properties: { online: true, locked: true, name: "Front door" },
    ...extra,
  },
});
const attempt = (id: string, status: string, extra: Record<string, unknown> = {}) => ({
  ok: true,
  action_attempt: { action_attempt_id: id, action_type: "UNLOCK_DOOR", status, result: status === "success" ? {} : null, error: null, ...extra },
});
const seamError = (type: string, message: string) => ({ ok: false, error: { type, message, request_id: "req_1" } });

type Answer = [number, unknown] | "hang" | "redirect";

/** What Seam answers to `/devices/get`, by device id. A device not listed is not found. */
const DEVICES: Record<string, Answer> = {
  "dev-no-remote": [200, device("dev-no-remote", { can_remotely_unlock: false })],
  "dev-offline": [200, device("dev-offline", { properties: { online: false, locked: true } })],
  "dev-other-id": [200, device("dev-someone-else")],
  "dev-not-json": [200, "<html>"],
  "dev-precheck-down": [503, seamError("internal_error", "Service unavailable")],
  "dev-precheck-slow": "hang",
  "dev-precheck-moved": "redirect",
  "dev-unauthorized": [401, seamError("unauthorized", "Unauthorized")],
};

/** What Seam answers to `/locks/unlock_door`, by device id. */
const UNLOCKS: Record<string, Answer> = {
  "dev-ok": [200, attempt("aa-ok", "pending")],
  "dev-instant": [200, attempt("aa-instant", "success")],
  "dev-stuck": [200, attempt("aa-stuck", "pending")],
  "dev-fails": [200, attempt("aa-fails", "pending")],
  "dev-fails-at-once": [200, attempt("aa-fails-at-once", "error", { error: { type: "lock_timeout", message: "The lock did not answer" } })],
  "dev-poll-down": [200, attempt("aa-poll-down", "pending")],
  "dev-poll-junk": [200, attempt("aa-poll-junk", "pending")],
  "dev-poll-other": [200, attempt("aa-poll-other", "pending")],
  "dev-poll-slow": [200, attempt("aa-poll-slow", "pending")],
  "dev-disconnected": [422, seamError("device_disconnected", "Device is disconnected")],
  "dev-wordy-error": [400, seamError("Invalid Input: device_id is not a lock", "x")],
  "dev-unlock-down": [502, "bad gateway"],
  "dev-unlock-slow": "hang",
  "dev-unlock-moved": "redirect",
  "dev-unlock-junk": [200, "not json"],
  "dev-odd-status": [200, attempt("aa-odd", "running")],
  "dev-no-id": [200, attempt("", "success")],
  "dev-long-id": [200, attempt("a".repeat(201), "success")],
  "dev-numeric-id": [200, { ok: true, action_attempt: { action_attempt_id: 7, status: "success" } }],
};

/** What Seam answers to `/action_attempts/get`, by attempt id. */
const ATTEMPTS: Record<string, Answer> = {
  "aa-ok": [200, attempt("aa-ok", "success")],
  "aa-stuck": [200, attempt("aa-stuck", "pending")],
  "aa-fails": [200, attempt("aa-fails", "error", { error: { type: "lock_timeout", message: "x" } })],
  "aa-poll-down": [500, seamError("internal_error", "x")],
  "aa-poll-junk": [200, "<html>"],
  "aa-poll-other": [200, attempt("aa-someone-else", "success")],
  "aa-poll-slow": "hang",
};

describe("seamAccessController", () => {
  let base = "";
  const seen: Array<{ path: string; body: Record<string, unknown>; headers: IncomingMessage["headers"] }> = [];
  const routes: Record<string, [string, Record<string, Answer>]> = {
    "/devices/get": ["device_id", DEVICES],
    "/locks/unlock_door": ["device_id", UNLOCKS],
    "/action_attempts/get": ["action_attempt_id", ATTEMPTS],
  };
  const reply = (res: ServerResponse, answer: Answer | undefined, fallback: Answer) => {
    const a = answer ?? fallback;
    if (a === "hang") return;
    if (a === "redirect") return void res.writeHead(307, { location: "/locks/unlock_door" }).end();
    res.writeHead(a[0], { "content-type": "application/json" }).end(typeof a[1] === "string" ? a[1] : JSON.stringify(a[1]));
  };
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<string, unknown>;
      const path = (req.url ?? "").replace(/^\/v1/, "");
      seen.push({ path, body, headers: req.headers });
      const route = routes[path];
      if (route === undefined) return void res.writeHead(404).end("no");
      const id = String(body[route[0]]);
      // A device that is listed nowhere is "not found"; any listed one is a healthy lock for the pre-check.
      const known = id in DEVICES || id in UNLOCKS;
      const fallback: Answer = path === "/devices/get" && known ? [200, device(id)] : [404, seamError("device_not_found", "Device not found")];
      reply(res, Object.hasOwn(route[1], id) ? route[1][id] : undefined, fallback);
    });
  });
  // The grant above is issued at the fixed clock's start and lives a minute.
  const clock = new FixedClock();
  const seam = (options: Partial<SeamAccessControllerOptions> = {}) => seamAccessController({ apiKey: API_KEY, baseUrl: base, pollIntervalMs: 10, confirmWithinMs: 100, timeoutMs: 200, clock, ...options });
  const unlocks = (target: string) => seen.filter((s) => s.path === "/locks/unlock_door" && s.body.device_id === target).length;
  const polls = (attemptId: string) => seen.filter((s) => s.path === "/action_attempts/get" && s.body.action_attempt_id === attemptId).length;

  before(async () => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("refuses a missing key, bad base URLs and bad timings", () => {
    assert.throws(() => seamAccessController({ apiKey: " " }), /needs an API key/);
    assert.throws(() => seamAccessController({ apiKey: 7 as never }), /needs an API key/);
    assert.throws(() => seamAccessController({ apiKey: API_KEY, baseUrl: "http://seam.example.test" }), /https base URL/);
    assert.throws(() => seamAccessController({ apiKey: API_KEY, baseUrl: "ftp://127.0.0.1" }), /https base URL/);
    assert.throws(() => seamAccessController({ apiKey: API_KEY, baseUrl: "https://u:p@seam.example.test" }), /no credentials/);
    assert.throws(() => seamAccessController({ apiKey: API_KEY, timeoutMs: 99 }), /timeoutMs must be an integer from 100 to 30000/);
    assert.throws(() => seamAccessController({ apiKey: API_KEY, timeoutMs: 1.5 }), /timeoutMs/);
    assert.throws(() => seamAccessController({ apiKey: API_KEY, confirmWithinMs: 30_001 }), /confirmWithinMs must be an integer from 0 to 30000/);
    assert.throws(() => seamAccessController({ apiKey: API_KEY, pollIntervalMs: 9 }), /pollIntervalMs must be an integer from 10 to 5000/);
    assert.ok(seamAccessController({ apiKey: API_KEY }));
    for (const baseUrl of ["https://seam.example.test/v1/", "http://localhost:1", "http://[::1]:1"]) assert.ok(seamAccessController({ apiKey: API_KEY, baseUrl }));
    // The key never appears in what the constructor throws.
    assert.throws(() => seamAccessController({ apiKey: API_KEY, timeoutMs: 0 }), (e: unknown) => e instanceof TypeError && !e.message.includes(API_KEY));
  });

  it("checks the device, unlocks once, and is confirmed only when Seam reports success", async () => {
    const before = seen.length;
    assert.deepEqual(await seam().unlock(input("dev-ok")), { outcome: "delivered", providerRef: "aa-ok", confirmed: true });
    const requests = seen.slice(before);
    assert.deepEqual(
      requests.map((r) => [r.path, r.body]),
      [
        ["/devices/get", { device_id: "dev-ok" }],
        ["/locks/unlock_door", { device_id: "dev-ok" }],
        ["/action_attempts/get", { action_attempt_id: "aa-ok" }],
      ],
    );
    for (const r of requests) {
      assert.equal(r.headers.authorization, `Bearer ${API_KEY}`);
      assert.equal(r.headers["content-type"], "application/json");
      assert.equal(r.headers["idempotency-key"], undefined, "Seam documents no idempotency key");
      assert.ok(!JSON.stringify(r.body).includes(API_KEY));
    }
    assert.deepEqual(await seam().unlock(input("dev-instant")), { outcome: "delivered", providerRef: "aa-instant", confirmed: true });
    assert.equal(polls("aa-instant"), 0, "an attempt that already succeeded is not asked about");
  });

  it("is delivered but unconfirmed while the attempt is pending or cannot be read, and never unlocks twice", async () => {
    for (const [target, ref] of [
      ["dev-stuck", "aa-stuck"],
      ["dev-poll-down", "aa-poll-down"],
      ["dev-poll-junk", "aa-poll-junk"],
      ["dev-poll-other", "aa-poll-other"],
      ["dev-poll-slow", "aa-poll-slow"],
    ] as const) {
      assert.deepEqual(await seam({ timeoutMs: 100 }).unlock(input(target)), { outcome: "delivered", providerRef: ref, confirmed: false }, target);
      assert.equal(unlocks(target), 1, target);
    }
    assert.equal(polls("aa-stuck"), 10, "asked for the whole confirmation window, then stopped");
    assert.equal(polls("aa-poll-down"), 1, "a failed read ends the asking");
    assert.deepEqual(await seam({ confirmWithinMs: 0 }).unlock(input("dev-ok")), { outcome: "delivered", providerRef: "aa-ok", confirmed: false });
    assert.equal(polls("aa-ok"), 1, "a window of 0 never asks");
  });

  it("refuses, without unlocking, a device that cannot unlock remotely, is offline, or cannot be checked", async () => {
    const cases: Array<[string, string]> = [
      ["dev-no-remote", "cannot_unlock_remotely"],
      ["dev-offline", "device_offline"],
      ["dev-other-id", "device_unreadable"],
      ["dev-not-json", "device_unreadable"],
      ["dev-unknown", "device_not_found"],
      ["dev-unauthorized", "unauthorized"],
      ["dev-precheck-down", "seam_unavailable"],
      ["dev-precheck-slow", "seam_unavailable"],
      ["dev-precheck-moved", "seam_unavailable"],
    ];
    for (const [target, reason] of cases) {
      assert.deepEqual(await seam({ timeoutMs: 100 }).unlock(input(target)), { outcome: "refused", reason }, target);
      assert.equal(unlocks(target), 0, target);
    }
    const lost = seamAccessController({ apiKey: API_KEY, baseUrl: `${base}/nowhere` });
    assert.deepEqual(await lost.unlock(input("dev-ok")), { outcome: "refused", reason: "http_404" });
  });

  it("is refused when Seam refuses the unlock, with its error type as a short code", async () => {
    assert.deepEqual(await seam().unlock(input("dev-disconnected")), { outcome: "refused", reason: "device_disconnected" });
    assert.deepEqual(await seam().unlock(input("dev-wordy-error")), { outcome: "refused", reason: "http_400" });
  });

  it("throws when the unlock's answer is lost or unreadable, or the attempt failed, so Gate records unknown", async () => {
    const cases: Array<[string, RegExp | ((e: unknown) => boolean)]> = [
      ["dev-unlock-down", /answered the unlock with 502/],
      ["dev-unlock-slow", (e: unknown) => e instanceof Error && e.name === "TimeoutError"],
      ["dev-unlock-moved", /fetch failed/],
      ["dev-unlock-junk", /without a readable action attempt/],
      ["dev-odd-status", /without a readable action attempt/],
      ["dev-no-id", /without a readable action attempt/],
      ["dev-long-id", /without a readable action attempt/],
      ["dev-numeric-id", /without a readable action attempt/],
      ["dev-fails", /attempt failed/],
      ["dev-fails-at-once", /attempt failed/],
    ];
    for (const [target, error] of cases) {
      await assert.rejects(seam({ timeoutMs: 100 }).unlock(input(target)), (e: unknown) => {
        assert.ok(e instanceof Error && !e.message.includes(API_KEY), target);
        return typeof error === "function" ? error(e) : error.test(e.message);
      });
      assert.equal(unlocks(target), 1, `${target}: sent once, never retried`);
    }
  });

  it("joins routes to a base URL with a path, and uses an injected fetch", async () => {
    const calls: string[] = [];
    const controller = seamAccessController({
      apiKey: API_KEY,
      baseUrl: "https://seam.example.test/v1/",
      clock,
      fetch: async (url, init) => {
        calls.push(String(url));
        const body = JSON.parse(String(init?.body)) as Record<string, string>;
        const answer = String(url).endsWith("/devices/get") ? device(body.device_id!) : attempt("aa-1", "success");
        return new Response(JSON.stringify(answer), { status: 200 });
      },
    });
    assert.deepEqual(await controller.unlock(input("dev-1")), { outcome: "delivered", providerRef: "aa-1", confirmed: true });
    assert.deepEqual(calls, ["https://seam.example.test/v1/devices/get", "https://seam.example.test/v1/locks/unlock_door"]);
  });

  it("never sends an unlock that might reach Seam after the grant expired, and defaults to the system clock", async () => {
    const late = new FixedClock(new Date(Date.parse(grant.body.expiresAt) - 199));
    const before = unlocks("dev-ok");
    assert.deepEqual(await seam({ clock: late }).unlock(input("dev-ok")), { outcome: "refused", reason: "grant_expiring" });
    assert.equal(unlocks("dev-ok"), before, "nothing was sent to the lock");
    const justInTime = new FixedClock(new Date(Date.parse(grant.body.expiresAt) - 200));
    assert.equal((await seam({ clock: justInTime }).unlock(input("dev-ok"))).outcome, "delivered");
    // The system clock is long past this grant's expiry.
    assert.deepEqual(await seamAccessController({ apiKey: API_KEY, baseUrl: base, timeoutMs: 200 }).unlock(input("dev-ok")), { outcome: "refused", reason: "grant_expiring" });
  });

  it("works as Gate's controller: delivered and confirmed, refused, and a lost answer recorded as unknown", async () => {
    const t = setup({
      adapters: { access: { lobby: seam({ timeoutMs: 100 }) }, accessSigner: generateTestSigner("gate-key-1") },
      config: testConfig((c) => {
        c.policy.scopes["entry.open"] = 2;
        c.modules.gate = {
          settings: {
            targets: [
              { id: "front-door", controller: "lobby", ref: "dev-ok" },
              { id: "garage", controller: "lobby", ref: "dev-offline" },
              { id: "side-door", controller: "lobby", ref: "dev-unlock-down" },
            ],
          },
        };
      }),
    });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall({});
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    assert.equal((await t.engine.finishVerification(callId)).level, 2);

    assert.deepEqual(await t.engine.grantAccess(callId, { target: "front-door" }), { grantId: "acc_1", status: "delivered", confirmed: true });
    assert.deepEqual(await t.engine.grantAccess(callId, { target: "garage" }), { grantId: "acc_2", status: "refused", confirmed: false });
    const before = unlocks("dev-unlock-down");
    assert.deepEqual(await t.engine.grantAccess(callId, { target: "side-door" }), { grantId: "acc_3", status: "unknown", confirmed: false });
    assert.equal(unlocks("dev-unlock-down"), before + 1, "a lost answer is never retried");

    assert.deepEqual((await t.engine.accessGrants(callId)).map((g) => [g.status, g.providerRef]), [["delivered", "aa-ok"], ["refused", null], ["unknown", null]]);
    const ledger = JSON.stringify(await t.ledger.list());
    assert.ok(ledger.includes("device_offline"));
    assert.ok(!ledger.includes(API_KEY), "the key never reaches the ledger");
  });
});
