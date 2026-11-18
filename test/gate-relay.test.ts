// The signed-webhook relay adapter (GAT-2), against a real HTTP server on the loopback address.
import { strict as assert } from "node:assert";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { canonicalJson } from "../src/core/canonical.ts";
import type { SignedAccessGrant } from "../src/gate/access.ts";
import { webhookRelay } from "../src/gate/relay.ts";

const grant: SignedAccessGrant = {
  body: {
    v: 1,
    kind: "access",
    grantId: "acc_1",
    workspaceId: "w",
    audience: "lobby",
    target: "door-1",
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
const input = { grant, target: "door-1", idempotencyKey: '["w","c","acc_1","unlock"]' };

describe("webhookRelay", () => {
  let base = "";
  const seen: Array<{ path: string; body: string; headers: IncomingMessage["headers"] }> = [];
  const answers = new Map<string, (res: ServerResponse) => void>([
    ["/confirmed", (res) => res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ state: "confirmed", ref: "relay-7" }))],
    ["/accepted", (res) => res.writeHead(202).end("ok")],
    ["/number", (res) => res.writeHead(200).end("5")],
    ["/long-ref", (res) => res.writeHead(200).end(JSON.stringify({ state: "requested", ref: "r".repeat(201) }))],
    ["/replay", (res) => res.writeHead(409).end(JSON.stringify({ error: "replay" }))],
    ["/missing", (res) => res.writeHead(404).end("no")],
    ["/odd-error", (res) => res.writeHead(400).end(JSON.stringify({ error: 7 }))],
    ["/null-error", (res) => res.writeHead(401).end("null")],
    ["/down", (res) => res.writeHead(503).end()],
    ["/moved", (res) => res.writeHead(302, { location: "/confirmed" }).end()],
    ["/slow", (res) => setTimeout(() => res.writeHead(200).end("{}"), 500)],
  ]);
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push({ path: req.url!, body: Buffer.concat(chunks).toString("utf8"), headers: req.headers });
      answers.get(req.url!)!(res);
    });
  });
  before(async () => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("refuses URLs that are not HTTPS (or loopback HTTP), carry credentials, and bad timeouts", () => {
    assert.throws(() => webhookRelay({ url: "http://relay.example.test/unlock" }), /https URL/);
    assert.throws(() => webhookRelay({ url: "ftp://127.0.0.1/unlock" }), /https URL/);
    assert.throws(() => webhookRelay({ url: "https://user:pw@relay.example.test/unlock" }), /no credentials/);
    assert.throws(() => webhookRelay({ url: "https://relay.example.test/unlock", timeoutMs: 99 }), /timeoutMs/);
    assert.throws(() => webhookRelay({ url: "https://relay.example.test/unlock", timeoutMs: 30_001 }), /timeoutMs/);
    for (const url of ["https://relay.example.test/unlock", "http://localhost:1/unlock", "http://[::1]:1/unlock"]) assert.ok(webhookRelay({ url }));
  });

  it("posts the signed grant as canonical JSON, once, and reads a confirmed answer", async () => {
    const result = await webhookRelay({ url: `${base}/confirmed` }).unlock(input);
    assert.deepEqual(result, { outcome: "delivered", providerRef: "relay-7", confirmed: true });
    const request = seen.at(-1)!;
    assert.equal(request.body, canonicalJson(grant));
    assert.equal(request.headers["content-type"], "application/json");
    assert.equal(request.headers["idempotency-key"], input.idempotencyKey);
    assert.equal(seen.filter((s) => s.path === "/confirmed").length, 1);
  });

  it("treats any 2xx as delivered, confirmed only when the relay says so", async () => {
    const relay = (path: string) => webhookRelay({ url: `${base}${path}` }).unlock(input);
    assert.deepEqual(await relay("/accepted"), { outcome: "delivered", providerRef: "acc_1", confirmed: false });
    assert.deepEqual(await relay("/number"), { outcome: "delivered", providerRef: "acc_1", confirmed: false });
    assert.deepEqual(await relay("/long-ref"), { outcome: "delivered", providerRef: "acc_1", confirmed: false });
  });

  it("treats a 4xx as refused, with the relay's error code or the status", async () => {
    const relay = (path: string) => webhookRelay({ url: `${base}${path}` }).unlock(input);
    assert.deepEqual(await relay("/replay"), { outcome: "refused", reason: "replay" });
    assert.deepEqual(await relay("/missing"), { outcome: "refused", reason: "http_404" });
    assert.deepEqual(await relay("/odd-error"), { outcome: "refused", reason: "http_400" });
    assert.deepEqual(await relay("/null-error"), { outcome: "refused", reason: "http_401" });
  });

  it("throws on a 5xx, a redirect and a timeout, so Gate records unknown", async () => {
    await assert.rejects(webhookRelay({ url: `${base}/down` }).unlock(input), /answered 503/);
    await assert.rejects(webhookRelay({ url: `${base}/moved` }).unlock(input));
    assert.equal(seen.filter((s) => s.path === "/confirmed").length, 1, "the redirect was not followed");
    await assert.rejects(webhookRelay({ url: `${base}/slow`, timeoutMs: 100 }).unlock(input), (e: unknown) => e instanceof Error && e.name === "TimeoutError");
  });

  it("uses an injected fetch", async () => {
    const calls: string[] = [];
    const relay = webhookRelay({
      url: "https://relay.example.test/unlock",
      fetch: async (url) => {
        calls.push(String(url));
        return new Response(JSON.stringify({ state: "confirmed" }), { status: 200 });
      },
    });
    assert.deepEqual(await relay.unlock(input), { outcome: "delivered", providerRef: "acc_1", confirmed: true });
    assert.deepEqual(calls, ["https://relay.example.test/unlock"]);
  });
});
