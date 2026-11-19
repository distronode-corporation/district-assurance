// The reference server, over a real socket on 127.0.0.1, and the scripted demo.
import { strict as assert } from "node:assert";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { createReferenceServer } from "../examples/reference-server/src/app.ts";
import { runDemo } from "../examples/reference-server/src/demo.ts";
import { StripeCheckoutLinks, StripeIdentityProvider } from "../examples/reference-server/src/stripe-adapters.ts";
import { MemoryDocumentStore, NotImplementedError, createUploadLink, signStripePayload, type Engine } from "../src/index.ts";
import { createTestEngine, type TestEngine } from "../src/testing/index.ts";

const SECRET = "whsec_test_not_a_secret";

describe("reference server", () => {
  let t: TestEngine;
  let base = "";
  let close: () => Promise<void>;

  before(async () => {
    t = createTestEngine();
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [SECRET], payments: [] }, clock: t.clock, maxBodyBytes: 1024 });
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

  it("refuses a body over the limit", async () => {
    const res = await post("/webhooks/stripe/identity", "x".repeat(5000));
    assert.deepEqual([res.status, await res.json()], [413, { error: "body_too_large" }]);
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

describe("reference server: document uploads", () => {
  const JPEG = Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]);
  let t: TestEngine;
  let documents: MemoryDocumentStore;
  let scanner: { clean: boolean; scan(): Promise<{ clean: boolean }> };
  let base = "";
  let close: () => Promise<void>;

  before(async () => {
    t = createTestEngine();
    documents = new MemoryDocumentStore();
    scanner = {
      clean: true,
      async scan() {
        return { clean: this.clean };
      },
    };
    await t.records.putIntakeRecord({ recordId: "rec_1", workspaceId: t.engine.workspaceId, callId: "call_1", formId: "f", formVersion: "1", values: {}, digest: "0".repeat(64), confirmedBy: "voice", confirmedAt: "2026-01-01T00:00:00.000Z" });
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [], payments: [] }, clock: t.clock, uploads: { documents, scanner, ids: t.ids } });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    close = () => new Promise((resolve) => server.close(() => resolve()));
  });
  after(() => close());

  const link = async (input: { locale?: "en" | "fr"; maxBytes?: number; allowedTypes?: Array<"image/jpeg" | "image/png" | "application/pdf"> } = {}) =>
    (await createUploadLink({ callId: "call_1", recordId: "rec_1", ...input }, { workspaceId: t.engine.workspaceId, documents, clock: t.clock, records: t.records })).token;
  const send = (token: string, bytes: Uint8Array, type = "image/jpeg", query = "") => {
    const body = new FormData();
    body.append("note", "ignored");
    body.append("file", new Blob([bytes], { type }), "photo.jpg");
    return fetch(`${base}/u/${token}${query}`, { method: "POST", body });
  };

  it("serves the upload page in the link's language, with a switch, and strict headers", async () => {
    const token = await link({ locale: "fr" });
    let res = await fetch(`${base}/u/${token}`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "text/html; charset=utf-8");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.match(res.headers.get("content-security-policy")!, /default-src 'none';.*form-action 'self'; frame-ancestors 'none'/);
    let html = await res.text();
    assert.match(html, /<html lang="fr">/);
    assert.match(html, /Ajouter un document/);
    assert.match(html, /Acceptés : JPEG, PNG, PDF, jusqu'à 10 Mo\./);
    assert.match(html, /accept="image\/jpeg,image\/png,application\/pdf"/);
    assert.match(html, /href="\?lang=en"/);
    assert.ok(!html.includes(token), "the page never repeats the token");
    res = await fetch(`${base}/u/${token}?lang=en`);
    html = await res.text();
    assert.match(html, /<html lang="en">/);
    assert.match(html, /Add a document/);
    assert.match(html, /Accepted: JPEG, PNG, PDF, up to 10 MB\./);
    html = await (await fetch(`${base}/u/${await link({ maxBytes: 2000, allowedTypes: ["application/pdf"] })}?lang=xx`)).text();
    assert.match(html, /Accepted: PDF, up to 2 KB\./);
  });

  it("takes one upload per link, then answers that the link is used", async () => {
    const token = await link();
    let res = await send(token, JPEG);
    assert.equal(res.status, 201);
    assert.match(await res.text(), /Your document was received/);
    assert.deepEqual([...documents.documents().at(-1)!.bytes], [...JPEG]);
    res = await send(token, JPEG);
    assert.equal(res.status, 410);
    assert.match(await res.text(), /expired or was already used/);
    res = await fetch(`${base}/u/${token}?lang=fr`);
    assert.equal(res.status, 410);
    assert.match(await res.text(), /Ce lien a expiré ou a déjà été utilisé/);
  });

  it("refuses an expired or unknown link the same way", async () => {
    const token = await link();
    t.clock.advance(30 * 60 * 1000);
    for (const path of [`/u/${token}`, "/u/upl_unknown", "/u/"]) {
      const res = await fetch(`${base}${path}`);
      assert.equal(res.status, 410, path);
    }
    assert.equal((await send(token, JPEG)).status, 410);
  });

  it("refuses a wrong type, a mismatch, an empty or missing file and one over the cap, in the page's language", async () => {
    const token = await link({ locale: "fr", maxBytes: JPEG.length, allowedTypes: ["image/jpeg"] });
    let res = await send(token, JPEG, "image/png");
    assert.equal(res.status, 415);
    assert.match(await res.text(), /Ce type de fichier n'est pas accepté ici/);
    res = await send(token, Uint8Array.from([1, 2, 3]), "image/jpeg", "?lang=en");
    assert.equal(res.status, 415);
    assert.match(await res.text(), /This type of file is not accepted here/);
    assert.equal((await send(token, new Uint8Array(0))).status, 400);
    assert.equal((await send(token, Uint8Array.from([...JPEG, 0]))).status, 413);
    res = await fetch(`${base}/u/${token}`, { method: "POST", body: new Uint8Array(JPEG.length + 20 * 1024) });
    assert.equal(res.status, 413);
    assert.match(await res.text(), /Ce fichier est trop volumineux/);
    for (const [type, body] of [
      ["text/plain", "x"],
      ["multipart/form-data; boundary=b", "nothing here"],
      ["multipart/form-data; boundary=b", "--b\r\nno end of headers"],
      ["multipart/form-data; boundary=b", "--b\r\ncontent-disposition: form-data; name=\"file\"\r\n\r\nno closing boundary"],
      ["multipart/form-data; boundary=\"b\"", "--b\r\ncontent-disposition: form-data; name=\"other\"\r\n\r\nx\r\n--b--\r\n"],
    ] as const) {
      res = await fetch(`${base}/u/${token}`, { method: "POST", body, headers: { "content-type": type } });
      assert.equal(res.status, 400, body);
      assert.match(await res.text(), /Choisissez d'abord un fichier/);
    }
    assert.equal((await fetch(`${base}/u/${token}`, { method: "PUT" })).status, 405);
    assert.equal((await send(token, JPEG)).status, 201, "none of those spent the link");
  });

  it("refuses what the scanner does not pass, and spends the link", async () => {
    const token = await link();
    scanner.clean = false;
    const res = await send(token, JPEG);
    scanner.clean = true;
    assert.equal(res.status, 422);
    const html = await res.text();
    assert.match(html, /could not be accepted/);
    assert.doesNotMatch(html, /<form/);
    assert.equal((await send(token, JPEG)).status, 410);
  });

  it("answers a page, not a 500, when the scanner throws, and the link is spent", async () => {
    const token = await link({ locale: "fr" });
    const scan = scanner.scan;
    scanner.scan = async () => {
      throw new Error("scanner internals");
    };
    const res = await send(token, JPEG);
    scanner.scan = scan;
    assert.equal(res.status, 503);
    const html = await res.text();
    assert.match(html, /n'a pas pu être vérifié/);
    assert.doesNotMatch(html, /internals|<form/);
    assert.equal((await send(token, JPEG)).status, 410);
  });

  it("is off without the uploads option", async () => {
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [], payments: [] }, clock: t.clock });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const res = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/u/${await link()}`);
    assert.deepEqual([res.status, await res.json()], [404, { error: "not_found" }]);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

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
