// Direct vendor adapters (GAT-6), Kisi and Verkada, against a real HTTP server on the loopback
// address that answers with the vendors' documented response shapes. No vendor is called.
import { strict as assert } from "node:assert";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import type { SignedAccessGrant } from "../src/gate/access.ts";
import { vendorAccessController, type VendorAccessOptions } from "../src/gate/vendors.ts";
import { FixedClock, generateTestSigner } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, setup, testConfig } from "./helpers.ts";

/** The grants below are issued at the fixed clock's start and live a minute. */
const clock = new FixedClock();

const KISI_LOCK = "48213";
const VERKADA_DOOR = "8f6a1b2c-3d4e-4f50-8a6b-7c8d9e0f1a2b";
const API_KEY = "test-key-not-a-secret";
const TOKEN = "verkada-token-not-a-secret";

function grantFor(target: string): SignedAccessGrant {
  return {
    body: {
      v: 1,
      kind: "access",
      grantId: "acc_1",
      workspaceId: "w",
      audience: "lobby",
      target,
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
}
const kisiInput = { grant: grantFor(KISI_LOCK), target: KISI_LOCK, idempotencyKey: '["w","c","acc_1","unlock"]' };
const verkadaInput = { grant: grantFor(VERKADA_DOOR), target: VERKADA_DOOR, idempotencyKey: '["w","c","acc_1","unlock"]' };

const json = (status: number, body: unknown) => (res: ServerResponse) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));

// The vendors' documented answers. Kisi: an unlock answers 200 with a message; errors carry a code
// and a message. Verkada: the token call answers {"token"}; an admin unlock answers the door id.
const KISI_UNLOCKED = json(200, { message: "Unlocked!" });
const VERKADA_TOKEN = json(200, { token: TOKEN });
const VERKADA_UNLOCKED = json(200, { door_id: VERKADA_DOOR });

describe("vendorAccessController", () => {
  let base = "";
  const seen: Array<{ path: string; body: string; headers: IncomingMessage["headers"] }> = [];
  // Each scenario is a path prefix, used as the adapter's baseUrl; the rest of the path is the vendor's.
  const answers = new Map<string, (res: ServerResponse) => void>([
    [`/kisi-ok/locks/${KISI_LOCK}/unlock`, KISI_UNLOCKED],
    [`/kisi-ok/v1/locks/${KISI_LOCK}/unlock`, KISI_UNLOCKED],
    [`/kisi-empty/locks/${KISI_LOCK}/unlock`, (res) => res.writeHead(204).end()],
    [`/kisi-401/locks/${KISI_LOCK}/unlock`, json(401, { code: "000001", message: `bad key ${API_KEY}` })],
    [`/kisi-404/locks/${KISI_LOCK}/unlock`, json(404, { code: "000404", message: "Lock not found" })],
    [`/kisi-down/locks/${KISI_LOCK}/unlock`, (res) => res.writeHead(503).end()],
    [`/kisi-moved/locks/${KISI_LOCK}/unlock`, (res) => res.writeHead(302, { location: `/kisi-ok/locks/${KISI_LOCK}/unlock` }).end()],
    [`/kisi-slow/locks/${KISI_LOCK}/unlock`, (res) => setTimeout(() => KISI_UNLOCKED(res), 500)],
    ["/vk-ok/token", VERKADA_TOKEN],
    ["/vk-ok/access/v1/door/admin_unlock", VERKADA_UNLOCKED],
    ["/vk-403/token", VERKADA_TOKEN],
    ["/vk-403/access/v1/door/admin_unlock", json(403, { id: "x", message: "forbidden" })],
    ["/vk-down/token", VERKADA_TOKEN],
    ["/vk-down/access/v1/door/admin_unlock", (res) => res.writeHead(500).end()],
    ["/vk-slow/token", VERKADA_TOKEN],
    ["/vk-slow/access/v1/door/admin_unlock", (res) => setTimeout(() => VERKADA_UNLOCKED(res), 500)],
    ["/vk-token-401/token", json(401, { message: "invalid api key" })],
    ["/vk-token-text/token", (res) => res.writeHead(200).end("not json")],
    ["/vk-token-null/token", json(200, null)],
    ["/vk-token-none/token", json(200, { expires: 1800 })],
    ["/vk-token-odd/token", json(200, { token: "has a space" })],
    ["/vk-token-down/token", (res) => res.writeHead(502).end()],
    ["/vk-token-slow/token", (res) => setTimeout(() => VERKADA_TOKEN(res), 500)],
  ]);
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push({ path: req.url!, body: Buffer.concat(chunks).toString("utf8"), headers: req.headers });
      // Only the paths this test defines answer; any other is a 404.
      const handler = answers.get(req.url ?? "");
      if (typeof handler === "function") handler(res);
      else res.writeHead(404).end();
    });
  });
  const hits = (prefix: string) => seen.filter((s) => s.path.startsWith(`${prefix}/`));
  const kisi = (prefix: string, extra: Partial<VendorAccessOptions> = {}) => vendorAccessController({ vendor: "kisi", apiKey: API_KEY, baseUrl: `${base}${prefix}`, clock, ...extra });
  const verkada = (prefix: string, extra: Partial<VendorAccessOptions> = {}) => vendorAccessController({ vendor: "verkada", apiKey: API_KEY, baseUrl: `${base}${prefix}`, clock, ...extra });

  before(async () => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("refuses an unknown vendor, a bad API key, URLs that are not HTTPS (or loopback HTTP), and bad timeouts", () => {
    assert.throws(() => vendorAccessController({ vendor: "brivo" as never, apiKey: API_KEY }), /kisi or verkada/);
    for (const apiKey of ["", "two words", "line\nbreak", "x".repeat(501), 7 as never]) {
      assert.throws(() => vendorAccessController({ vendor: "kisi", apiKey }), /apiKey/);
    }
    for (const baseUrl of ["http://api.kisi.example.test", "ftp://127.0.0.1"]) {
      assert.throws(() => vendorAccessController({ vendor: "kisi", apiKey: API_KEY, baseUrl }), /https baseUrl/);
    }
    for (const baseUrl of ["https://user:pw@api.example.test", "https://api.example.test/?key=1", "https://api.example.test/#x"]) {
      assert.throws(() => vendorAccessController({ vendor: "verkada", apiKey: API_KEY, baseUrl }), /no credentials, query or fragment/);
    }
    assert.throws(() => vendorAccessController({ vendor: "kisi", apiKey: API_KEY, timeoutMs: 99 }), /timeoutMs/);
    assert.throws(() => vendorAccessController({ vendor: "kisi", apiKey: API_KEY, timeoutMs: 30_001 }), /timeoutMs/);
    assert.throws(() => vendorAccessController({ vendor: "kisi", apiKey: API_KEY, timeoutMs: 1000.5 }), /timeoutMs/);
    for (const baseUrl of [undefined, "https://api.eu.verkada.com", "http://localhost:1", "http://[::1]:1"]) {
      assert.ok(vendorAccessController({ vendor: "verkada", apiKey: API_KEY, ...(baseUrl === undefined ? {} : { baseUrl }) }));
    }
  });

  it("uses each vendor's own API by default", async () => {
    const calls: string[] = [];
    const record: typeof fetch = async (url) => {
      calls.push(String(url));
      return String(url).endsWith("/token") ? new Response(JSON.stringify({ token: TOKEN }), { status: 200 }) : new Response(null, { status: 200 });
    };
    await vendorAccessController({ vendor: "kisi", apiKey: API_KEY, fetch: record, clock }).unlock(kisiInput);
    await vendorAccessController({ vendor: "verkada", apiKey: API_KEY, fetch: record, clock }).unlock(verkadaInput);
    assert.deepEqual(calls, [
      `https://api.kisi.io/locks/${KISI_LOCK}/unlock`,
      "https://api.verkada.com/token",
      "https://api.verkada.com/access/v1/door/admin_unlock",
    ]);
  });

  describe("Kisi", () => {
    it("posts one unlock to the lock with the API key, and reports delivered, never confirmed", async () => {
      assert.deepEqual(await kisi("/kisi-ok").unlock(kisiInput), { outcome: "delivered", providerRef: "acc_1", confirmed: false });
      const sent = hits("/kisi-ok");
      assert.equal(sent.length, 1);
      assert.equal(sent[0]!.path, `/kisi-ok/locks/${KISI_LOCK}/unlock`);
      assert.equal(sent[0]!.headers.authorization, `KISI-LOGIN ${API_KEY}`);
      assert.equal(sent[0]!.headers["content-type"], "application/json");
      assert.equal(sent[0]!.body, "{}", "the grant and its signature are not sent to the vendor");
    });

    it("keeps a path in the base URL, with or without a trailing slash", async () => {
      for (const prefix of ["/kisi-ok/v1", "/kisi-ok/v1/"]) {
        assert.equal((await kisi(prefix).unlock(kisiInput)).outcome, "delivered");
      }
    });

    it("treats a 2xx without a body as delivered", async () => {
      assert.deepEqual(await kisi("/kisi-empty").unlock(kisiInput), { outcome: "delivered", providerRef: "acc_1", confirmed: false });
    });

    it("treats a 4xx as refused with the status only, never the vendor's text", async () => {
      assert.deepEqual(await kisi("/kisi-401").unlock(kisiInput), { outcome: "refused", reason: "http_401" });
      assert.deepEqual(await kisi("/kisi-404").unlock(kisiInput), { outcome: "refused", reason: "http_404" });
    });

    it("throws on a 5xx, a redirect and a timeout, never retrying and never naming the key", async () => {
      await assert.rejects(kisi("/kisi-down").unlock(kisiInput), (e: unknown) => e instanceof Error && e.message === "kisi answered 503" && !e.message.includes(API_KEY));
      assert.equal(hits("/kisi-down").length, 1, "not retried");
      const okBefore = hits("/kisi-ok").length;
      await assert.rejects(kisi("/kisi-moved").unlock(kisiInput));
      assert.equal(hits("/kisi-ok").length, okBefore, "the redirect was not followed");
      await assert.rejects(kisi("/kisi-slow", { timeoutMs: 100 }).unlock(kisiInput), (e: unknown) => e instanceof Error && e.name === "TimeoutError");
      assert.equal(hits("/kisi-slow").length, 1, "not retried");
    });

    it("sends nothing for a target the grant does not name, or that is not a Kisi lock id", async () => {
      const before = seen.length;
      assert.deepEqual(await kisi("/kisi-ok").unlock({ ...kisiInput, target: "99999" }), { outcome: "refused", reason: "target_mismatch" });
      const odd = "../users/1";
      assert.deepEqual(await kisi("/kisi-ok").unlock({ ...kisiInput, grant: grantFor(odd), target: odd }), { outcome: "refused", reason: "bad_target" });
      assert.equal(seen.length, before);
    });
  });

  describe("Verkada", () => {
    it("gets a token with the API key, then posts one admin unlock for the door with the token only", async () => {
      assert.deepEqual(await verkada("/vk-ok").unlock(verkadaInput), { outcome: "delivered", providerRef: "acc_1", confirmed: false });
      const [token, unlock, ...rest] = hits("/vk-ok");
      assert.equal(rest.length, 0);
      assert.equal(token!.path, "/vk-ok/token");
      assert.equal(token!.headers["x-api-key"], API_KEY);
      assert.equal(unlock!.path, "/vk-ok/access/v1/door/admin_unlock");
      assert.equal(unlock!.headers["x-verkada-auth"], TOKEN);
      assert.equal(unlock!.headers["x-api-key"], undefined, "the API key goes to the token call only");
      assert.equal(unlock!.headers["content-type"], "application/json");
      assert.deepEqual(JSON.parse(unlock!.body), { door_id: VERKADA_DOOR });
    });

    it("refuses without sending the unlock when no token can be had", async () => {
      for (const prefix of ["/vk-token-401", "/vk-token-text", "/vk-token-null", "/vk-token-none", "/vk-token-odd", "/vk-token-down"]) {
        assert.deepEqual(await verkada(prefix).unlock(verkadaInput), { outcome: "refused", reason: "token_unavailable" }, prefix);
        assert.deepEqual(hits(prefix).map((s) => s.path), [`${prefix}/token`], prefix);
      }
      assert.deepEqual(await verkada("/vk-token-slow", { timeoutMs: 100 }).unlock(verkadaInput), { outcome: "refused", reason: "token_unavailable" });
      const lost = vendorAccessController({
        vendor: "verkada",
        apiKey: API_KEY,
        clock,
        fetch: async () => {
          throw new TypeError("fetch failed");
        },
      });
      assert.deepEqual(await lost.unlock(verkadaInput), { outcome: "refused", reason: "token_unavailable" });
    });

    it("treats an unlock 4xx as refused, and a 5xx or a timeout as a throw, never retried", async () => {
      assert.deepEqual(await verkada("/vk-403").unlock(verkadaInput), { outcome: "refused", reason: "http_403" });
      await assert.rejects(verkada("/vk-down").unlock(verkadaInput), (e: unknown) => e instanceof Error && e.message === "verkada answered 500");
      assert.equal(hits("/vk-down").length, 2, "one token call, one unlock");
      await assert.rejects(verkada("/vk-slow", { timeoutMs: 100 }).unlock(verkadaInput), (e: unknown) => e instanceof Error && e.name === "TimeoutError");
      assert.equal(hits("/vk-slow").length, 2, "one token call, one unlock");
    });

    it("sends nothing for a target the grant does not name, or that is not a Verkada door id", async () => {
      const before = seen.length;
      assert.deepEqual(await verkada("/vk-ok").unlock({ ...verkadaInput, target: KISI_LOCK }), { outcome: "refused", reason: "target_mismatch" });
      assert.deepEqual(await verkada("/vk-ok").unlock({ ...verkadaInput, grant: grantFor("door-1"), target: "door-1" }), { outcome: "refused", reason: "bad_target" });
      assert.equal(seen.length, before);
    });
  });

  it("sends nothing for a grant with less than its timeout left, and defaults to the system clock", async () => {
    const late = new FixedClock(new Date(Date.parse(kisiInput.grant.body.expiresAt) - 4_999));
    const before = seen.length;
    assert.deepEqual(await kisi("/kisi-ok", { clock: late }).unlock(kisiInput), { outcome: "refused", reason: "grant_expiring" });
    assert.deepEqual(await verkada("/vk-ok", { clock: late }).unlock(verkadaInput), { outcome: "refused", reason: "grant_expiring" });
    assert.equal(seen.length, before, "not even Verkada's token was asked for");
    const inTime = new FixedClock(new Date(Date.parse(kisiInput.grant.body.expiresAt) - 5_000));
    assert.equal((await kisi("/kisi-ok", { clock: inTime }).unlock(kisiInput)).outcome, "delivered");
    // The system clock is long past these grants' expiry.
    assert.deepEqual(await vendorAccessController({ vendor: "kisi", apiKey: API_KEY, baseUrl: `${base}/kisi-ok` }).unlock(kisiInput), { outcome: "refused", reason: "grant_expiring" });
  });

  it("works as Gate's controller in the engine's access adapter, the API key never in the ledger", async () => {
    const t = setup({
      adapters: { access: { kisi: kisi("/kisi-ok"), verkada: verkada("/vk-down") }, accessSigner: generateTestSigner("gate-key-1") },
      config: testConfig((c) => {
        c.policy.scopes["entry.open"] = 2;
        c.modules.gate = {
          settings: {
            targets: [
              { id: "front-door", controller: "kisi", ref: KISI_LOCK },
              { id: "garage", controller: "verkada", ref: VERKADA_DOOR },
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
    assert.deepEqual(await t.engine.grantAccess(callId, { target: "front-door" }), { grantId: "acc_1", status: "delivered", confirmed: false });
    assert.deepEqual(await t.engine.grantAccess(callId, { target: "garage" }), { grantId: "acc_2", status: "unknown", confirmed: false });
    assert.deepEqual((await t.engine.accessGrants(callId)).map((g) => [g.status, g.providerRef]), [["delivered", "acc_1"], ["unknown", null]]);
    assert.ok(!JSON.stringify(await t.ledger.list()).includes(API_KEY));
  });
});
