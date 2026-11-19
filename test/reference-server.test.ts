// The reference server, over a real socket on 127.0.0.1, and the scripted demo.
import { strict as assert } from "node:assert";
import type { JsonWebKey } from "node:crypto";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { ReceiptLinks, SEEN_EVENT_MAX, SEEN_EVENT_TTL_MS, SeenEvents, createReferenceServer } from "../examples/reference-server/src/app.ts";
import { runDemo } from "../examples/reference-server/src/demo.ts";
import { createDoorRelay } from "../examples/reference-server/src/door-relay.ts";
import {
  canonicalJson,
  formatAmount,
  newReceiptLinkToken,
  receiptKeyRing,
  receiptLinkTokenHash,
  sha256Hex,
  signDocument,
  signReceipt,
  signStripePayload,
  verifyReceipt,
  type Engine,
  type FactorKind,
  type ReceiptBody,
  type SignedReceipt,
} from "../src/index.ts";
import { FixedClock, createTestEngine, generateTestSigner, type TestEngine } from "../src/testing/index.ts";

/** When k1 stopped signing: after the test clock's receipts (2026-01-01), so they predate it. */
const RETIRED_AT = "2026-06-01T00:00:00.000Z";
const SECRET = "whsec_test_not_a_secret";

describe("reference server", () => {
  let t: TestEngine;
  let base = "";
  let close: () => Promise<void>;
  const links = new ReceiptLinks();

  before(async () => {
    t = createTestEngine();
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [SECRET], payments: [] }, clock: t.clock, maxBodyBytes: 1024, receiptLinks: links });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    close = () => new Promise((resolve) => server.close(() => resolve()));
  });
  after(() => close());

  const post = (path: string, body: string, headers: Record<string, string> = {}) => fetch(`${base}${path}`, { method: "POST", body, headers });
  const signed = (body: string) => ({ "stripe-signature": signStripePayload(body, SECRET, Math.floor(t.clock.now().getTime() / 1000)) });
  const event = (id: string, type: string, object: Record<string, unknown>, extra: Record<string, unknown> = {}) => JSON.stringify({ id, type, data: { object }, ...extra });

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
    res = await post("/webhooks/stripe/connect", body, signed(body));
    assert.deepEqual(await res.json(), { error: "signature", reason: "no_secret" }, "the Connect endpoint has its own secret, unset here");
    res = await post("/webhooks/stripe/identity", "{}", signed("{}"));
    assert.deepEqual([res.status, await res.json()], [400, { error: "malformed_event" }]);
  });

  it("applies a signed event once and ignores events of the other kind", async () => {
    const body = event("evt_2", "identity.verification_session.verified", { id: "vs_unknown" });
    assert.deepEqual(await (await post("/webhooks/stripe/identity", body, signed(body))).json(), { received: true, applied: false });
    assert.deepEqual(await (await post("/webhooks/stripe/identity", body, signed(body))).json(), { received: true, duplicate: true });
    const pay = event("evt_3", "checkout.session.expired", { id: "cs_x" });
    assert.deepEqual(await (await post("/webhooks/stripe/identity", pay, signed(pay))).json(), { received: true, applied: false, handled: false });
  });

  it("has Stripe deliver again a dispute whose payment is not bound yet, and remembers it once applied", async () => {
    const both = createTestEngine();
    const server = createReferenceServer({ engine: both.engine, stripeSecrets: { identity: [SECRET], payments: [SECRET], connect: [SECRET] }, clock: both.clock });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const send = async (path: string, body: string) => {
      const res = await fetch(`${url}${path}`, { method: "POST", headers: signed(body), body });
      return [res.status, await res.json()] as const;
    };
    try {
      const object = { id: "dp_1", object: "dispute", charge: "ch_1", payment_intent: "pi_unbound", status: "needs_response", amount: 15000, currency: "cad" };
      const dispute = event("evt_20", "charge.dispute.created", object);
      assert.deepEqual(await send("/webhooks/stripe/payments", dispute), [503, { received: true, applied: false, retry: true }]);
      assert.deepEqual(await send("/webhooks/stripe/payments", dispute), [503, { received: true, applied: false, retry: true }], "never remembered as processed");
      const placed = event("evt_21", "charge.dispute.created", { ...object, payment_intent: null });
      assert.deepEqual(await send("/webhooks/stripe/payments", placed), [200, { received: true, applied: false }], "one that can never be placed is acknowledged");
      assert.deepEqual(await send("/webhooks/stripe/payments", placed), [200, { received: true, duplicate: true }]);
      assert.deepEqual(await send("/webhooks/stripe/connect", dispute), [200, { received: true, applied: false, handled: false }], "a connected account's dispute is the business's");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("applies an event only on its own endpoint, never remembering one that went to the wrong one", async () => {
    const both = createTestEngine();
    const server = createReferenceServer({ engine: both.engine, stripeSecrets: { identity: [SECRET], payments: [SECRET], connect: [SECRET] }, clock: both.clock });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const send = async (path: string, body: string) => (await fetch(`${url}${path}`, { method: "POST", headers: signed(body), body })).json();
    try {
      // An identity event that an unfiltered listener sent to the payments endpoint first.
      const id = event("evt_10", "identity.verification_session.verified", { id: "vs_unknown" });
      assert.deepEqual(await send("/webhooks/stripe/payments", id), { received: true, applied: false, handled: false });
      assert.deepEqual(await send("/webhooks/stripe/identity", id), { received: true, applied: false }, "applied where it belongs, not a duplicate");
      // The endpoint fixes the payment mode: a Connect event names an account, an account event does not.
      const platform = event("evt_11", "checkout.session.expired", { id: "cs_x" });
      assert.deepEqual(await send("/webhooks/stripe/connect", platform), { received: true, applied: false, handled: false });
      assert.deepEqual(await send("/webhooks/stripe/payments", platform), { received: true, applied: false });
      const connect = event("evt_12", "checkout.session.expired", { id: "cs_y" }, { account: "acct_1" });
      assert.deepEqual(await send("/webhooks/stripe/payments", connect), { received: true, applied: false, handled: false });
      assert.deepEqual(await send("/webhooks/stripe/connect", connect), { received: true, applied: false });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("remembers event ids for longer than Stripe retries, and no more than its cap (fixed clock)", async () => {
    const clock = new FixedClock();
    const seen = new SeenEvents(clock, 1000, 3);
    seen.add("a");
    clock.advance(999);
    assert.equal(seen.has("a"), true, "within the ttl");
    clock.advance(1);
    assert.equal(seen.has("a"), false, "forgotten at the ttl");
    assert.equal(seen.size, 0);
    // The least recently seen goes first past the cap; a hit counts as a use.
    for (const id of ["a", "b", "c"]) seen.add(id);
    assert.equal(seen.has("a"), true);
    seen.add("d");
    assert.deepEqual(["a", "b", "c", "d"].map((id) => seen.has(id)), [true, false, true, true]);
    // A flood of distinct ids never holds more than the cap, and expired ones go on the next look.
    for (let i = 0; i < 10_000; i++) seen.add(`evt_${i}`);
    assert.equal(seen.size, 3);
    clock.advance(1000);
    assert.equal(seen.has("evt_9999"), false);
    assert.equal(seen.size, 0);
    // A re-added id starts its ttl again.
    seen.add("e");
    clock.advance(600);
    seen.add("e");
    clock.advance(600);
    assert.equal(seen.has("e"), true);
    for (const [ttl, max] of [[0, 1], [1, 0], [1.5, 1], [1, Number.NaN]] as const) assert.throws(() => new SeenEvents(clock, ttl, max), TypeError);
    // The defaults outlast Stripe's 3-day retry window.
    assert.ok(SEEN_EVENT_TTL_MS > 3 * 24 * 60 * 60 * 1000);
    assert.equal(SEEN_EVENT_MAX, 10_000);
  });

  it("answers a retried event as a duplicate only while it is remembered", async () => {
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [SECRET], payments: [] }, clock: t.clock, seenEvents: { ttlMs: 60_000, max: 2 } });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/webhooks/stripe/identity`;
    const send = async (id: string) => {
      const body = event(id, "identity.verification_session.verified", { id: "vs_unknown" });
      return (await fetch(url, { method: "POST", body, headers: signed(body) }).then((r) => r.json())) as Record<string, unknown>;
    };
    try {
      assert.deepEqual(await send("evt_r1"), { received: true, applied: false });
      assert.deepEqual(await send("evt_r1"), { received: true, duplicate: true });
      await send("evt_r2");
      await send("evt_r3");
      assert.deepEqual(await send("evt_r2"), { received: true, duplicate: true }, "kept: among the two most recent");
      assert.deepEqual(await send("evt_r1"), { received: true, applied: false }, "evicted past the cap");
      t.clock.advance(60_000);
      assert.deepEqual(await send("evt_r2"), { received: true, applied: false }, "forgotten after the ttl");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("refuses a body over the limit", async () => {
    const res = await post("/webhooks/stripe/identity", "x".repeat(5000));
    assert.deepEqual([res.status, await res.json()], [413, { error: "body_too_large" }]);
  });

  it("answers 501 on the carrier webhooks that are not built", async () => {
    const res = await post("/webhooks/twilio", "");
    assert.deepEqual([res.status, await res.json()], [501, { error: "not_implemented", issue: "SRV-1", carrier: "twilio" }]);
  });

  it("serves a receipt only by its link token: the page, the JSON, and one 404 for everything else", async () => {
    const { callId } = await t.engine.startCall();
    const early = links.issue(callId);
    const notFound = async (path: string) => {
      const res = await fetch(`${base}${path}`);
      assert.deepEqual([res.status, await res.json()], [404, { error: "not_found" }], path);
    };
    await notFound(`/r/${early}`); // the call has no receipt yet
    const receipt = (await t.engine.endCall(callId))!;
    const token = links.issue(callId);
    assert.match(token, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(token, early);

    const json = await fetch(`${base}/r/${token}.json`);
    assert.equal(json.headers.get("cache-control"), "no-store");
    assert.deepEqual(await json.json(), receipt);
    assert.deepEqual(await (await fetch(`${base}/r/${early}.json`)).json(), receipt, "a token issued before the call ended works once it has its receipt");

    const page = await fetch(`${base}/r/${token}`);
    assert.equal(page.status, 200);
    assert.equal(page.headers.get("content-type"), "text/html; charset=utf-8");
    assert.equal(page.headers.get("referrer-policy"), "no-referrer");
    assert.equal(page.headers.get("cache-control"), "no-store");
    assert.equal(page.headers.get("x-robots-tag"), "noindex, nofollow");
    assert.equal(page.headers.get("content-security-policy"), "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    const html = await page.text();
    assert.match(html, /<html lang="en">/);
    assert.match(html, /<h1>Call receipt<\/h1>/);
    assert.ok(html.includes(`Signature valid: signed with key ${receipt.kid}`));
    assert.ok(html.includes(`<dd>${receipt.body.receiptId}</dd>`));
    assert.ok(html.includes("<dt>Identity check</dt><dd>not verified</dd>"));
    assert.ok(html.includes(`<a href="${token}.json">`));
    assert.ok(html.includes('<a href="?lang=fr" hreflang="fr" lang="fr">Français</a>'));

    // The route by call id is gone, and nothing but an issued token finds a receipt.
    await notFound(`/receipts/${callId}`);
    await notFound(`/r/${callId}`);
    await notFound(`/r/${newReceiptLinkToken().token}`);
    await notFound(`/r/${token.slice(1)}`);
    await notFound(`/r/${token}A`);
    await notFound(`/r/${token}.txt`);
    await notFound(`/r/${links.issue("call_404")}`);
    assert.equal((await post(`/r/${token}`, "")).status, 405);
  });

  it("serves the page in French on ?lang=fr or when the browser asks for French first", async () => {
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    const token = links.issue(callId);
    const lang = async (query: string, acceptLanguage?: string) => {
      const html = await (await fetch(`${base}/r/${token}${query}`, acceptLanguage === undefined ? {} : { headers: { "accept-language": acceptLanguage } })).text();
      return /<html lang="(en|fr)">/.exec(html)![1];
    };
    assert.equal(await lang("?lang=fr"), "fr");
    assert.equal(await lang("", "fr-CA,fr;q=0.9,en;q=0.8"), "fr");
    assert.equal(await lang("", "fr"), "fr");
    assert.equal(await lang("", "en-CA,fr;q=0.9"), "en");
    assert.equal(await lang("", "fra"), "en");
    assert.equal(await lang("?lang=en", "fr-CA"), "en");
    assert.equal(await lang("?lang=de", "fr-CA"), "fr");
    assert.equal(await lang(""), "en");
    const html = await (await fetch(`${base}/r/${token}?lang=fr`)).text();
    assert.match(html, /<h1>Reçu d&#39;appel<\/h1>/);
    assert.ok(html.includes("Signature valide : signé avec la clé"));
    assert.ok(html.includes("<dt>Vérification d&#39;identité</dt><dd>non vérifiée</dd>"));
    assert.ok(html.includes('<a href="?lang=en" hreflang="en" lang="en">English</a>'));
  });

  it("without receipt links, answers 404 for every token", async () => {
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    const token = links.issue(callId);
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [], payments: [] }, clock: t.clock });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const res = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/r/${token}`);
    assert.deepEqual([res.status, await res.json()], [404, { error: "not_found" }]);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("answers 500 without detail when the engine fails", async () => {
    const broken = { receipt: () => { throw new Error("boom"); } } as unknown as Engine;
    const brokenLinks = new ReceiptLinks();
    const server = createReferenceServer({ engine: broken, stripeSecrets: { identity: [], payments: [] }, clock: t.clock, receiptLinks: brokenLinks });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const res = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/r/${brokenLinks.issue("c1")}`);
    assert.deepEqual([res.status, await res.json()], [500, { error: "internal" }]);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("serves the key set history, so a receipt signed before a rotation still verifies (PRV-1)", async () => {
    const k1 = generateTestSigner("k1");
    const earlier = createTestEngine({ adapters: { signer: k1 } });
    const old = (await earlier.engine.endCall((await earlier.engine.startCall()).callId))!;
    const later = createTestEngine({ adapters: { signer: receiptKeyRing({ signers: [generateTestSigner("k2")], active: "k2", retired: [{ ...k1.publicJwk(), retiredAt: RETIRED_AT }] }) } });
    const server = createReferenceServer({ engine: later.engine, stripeSecrets: { identity: [], payments: [] }, clock: later.clock });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { keys } = (await (await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/.well-known/receipt-keys.json`)).json()) as { keys: JsonWebKey[] };
    await new Promise<void>((resolve) => server.close(() => resolve()));
    assert.deepEqual(keys.map((k) => k.kid), ["k2", "k1"]);
    assert.equal(keys.some((k) => "d" in k), false);
    assert.equal(verifyReceipt(old, keys), true);
  });
});

describe("example door relay", () => {
  it("refuses an oversized body without keeping it, and a body that is not JSON", async () => {
    const opened: string[] = [];
    const relay = createDoorRelay({ audience: "lobby", workspaceId: "w", keys: [], clock: { now: () => new Date(0) }, open: async (target) => void opened.push(target) });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(relay.address() as AddressInfo).port}`;
    try {
      // The cutoff can land before the headers or while the body is read: either is "cut off".
      const big = await (async () => {
        try {
          const r = await fetch(`${url}/unlock`, { method: "POST", body: "x".repeat(64 * 1024) });
          return { status: r.status, text: await r.text() };
        } catch {
          return "cut off";
        }
      })();
      // Only a transport failure counts as cut off: a complete answer that is not JSON fails here.
      // Answered at once and the upload cut off: the client sees the 413, or the connection close.
      if (big !== "cut off") assert.deepEqual([big.status, JSON.parse(big.text)], [413, { error: "body_too_large" }]);
      const junk = await fetch(`${url}/unlock`, { method: "POST", body: "{" });
      assert.deepEqual([junk.status, await junk.json()], [400, { error: "malformed" }]);
      assert.equal((await fetch(`${url}/other`)).status, 404);
      assert.deepEqual(opened, []);
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });

  it("answers 502 when the door callback throws, without stopping the relay", async () => {
    const signer = generateTestSigner("g1");
    const body = { v: 1, kind: "access", grantId: "acc_1", workspaceId: "w", audience: "lobby", target: "door-1", action: "unlock", scope: "entry.open", level: 2, issuedAt: "1970-01-01T00:00:00.000Z", expiresAt: "1970-01-01T00:01:00.000Z" } as const;
    const grant = await signDocument(signer, body);
    const relay = createDoorRelay({
      audience: "lobby",
      workspaceId: "w",
      keys: [signer.publicJwk()],
      clock: { now: () => new Date(0) },
      open: () => {
        throw new Error("relay board unplugged");
      },
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(relay.address() as AddressInfo).port}/unlock`;
    try {
      const res = await fetch(url, { method: "POST", body: canonicalJson(grant) });
      assert.deepEqual([res.status, await res.json()], [502, { error: "door" }]);
      assert.equal((await fetch(url, { method: "POST", body: canonicalJson(grant) })).status, 409, "still running, and the grant stays seen");
    } finally {
      await new Promise<void>((resolve) => relay.close(() => resolve()));
    }
  });
});

describe("reference server: the receipt page", () => {
  const signer = generateTestSigner("page-key");
  const body: ReceiptBody = {
    v: 1,
    receiptId: "rcpt_1",
    callId: "call_1",
    workspaceId: "ws_test",
    startedAt: "2026-01-01T00:00:00.000Z",
    endedAt: "2026-01-01T00:05:00.000Z",
    issuedAt: "2026-01-01T00:05:00.000Z",
    verification: { level: 2, methods: ["carrier_identity_match", "keypad_knowledge", "badge_scan" as FactorKind] },
    records: [{ recordId: "rec_1", formId: "maintenance", digest: "a".repeat(64) }],
    payments: [
      { paymentId: "pay_1", status: "paid", amountMinor: 15000, currency: "cad", mode: "platform", providerRef: "cs_1" },
      { paymentId: "pay_2", status: "refunded", amountMinor: 500, currency: "jpy", mode: "platform", providerRef: "cs_2" },
    ],
    consents: [
      { purpose: "repair_texts", wordingVersion: "1", wordingDigest: "b".repeat(64), answer: "yes" },
      { purpose: "x<script>&\"'", wordingVersion: "1", wordingDigest: "c".repeat(64), answer: "no" },
    ],
    ledger: { seq: 17, hash: "d".repeat(64) },
  };

  async function page(receipt: SignedReceipt, keys: unknown[], lang: "en" | "fr"): Promise<string> {
    const pageLinks = new ReceiptLinks();
    const engine = { receipt: async () => receipt, receiptKeys: () => keys } as unknown as Engine;
    const server = createReferenceServer({ engine, stripeSecrets: { identity: [], payments: [] }, clock: new FixedClock(), receiptLinks: pageLinks });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      return await (await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/r/${pageLinks.issue("call_1")}?lang=${lang}`)).text();
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }

  it("shows the verification, records, payments, consents and ledger head, every value escaped", async () => {
    const receipt = await signReceipt(signer, body);
    const en = await page(receipt, [signer.publicJwk()], "en");
    assert.ok(en.includes("Signature valid: signed with key page-key, and not one byte has changed since."));
    assert.ok(en.includes("<dd>level 2, by the carrier&#39;s match on the number on file, answers keyed on the phone, badge_scan</dd>"));
    assert.ok(en.includes(`<dd>maintenance, fingerprint ${"a".repeat(64)}</dd>`));
    assert.ok(en.includes(`<dd>${formatAmount("en", 15000, "cad")}, paid; ${formatAmount("en", 500, "jpy")}, refunded</dd>`));
    assert.ok(en.includes("<dd>repair_texts: yes; x&#60;script&#62;&#38;&#34;&#39;: no</dd>"));
    assert.ok(en.includes(`<dd>entry 17, hash ${"d".repeat(64)}</dd>`));
    assert.equal(en.includes("<script>"), false);

    const fr = await page(receipt, [signer.publicJwk()], "fr");
    assert.ok(fr.includes("<dd>niveau 2, par la correspondance de l&#39;opérateur pour le numéro au dossier, réponses saisies au clavier, badge_scan</dd>"));
    assert.ok(fr.includes(`<dd>maintenance, empreinte ${"a".repeat(64)}</dd>`));
    assert.ok(fr.includes(`<dd>${formatAmount("fr", 15000, "cad")}, payé; ${formatAmount("fr", 500, "jpy")}, refunded</dd>`));
    assert.ok(fr.includes("<dd>repair_texts: oui; x&#60;script&#62;&#38;&#34;&#39;: non</dd>"));
    assert.ok(fr.includes(`<dd>entrée 17, empreinte ${"d".repeat(64)}</dd>`));
  });

  it("says when the signature does not hold, in both languages", async () => {
    const receipt = await signReceipt(signer, body);
    const changed = structuredClone(receipt);
    changed.body.payments[0]!.amountMinor = 1;
    assert.ok((await page(changed, [signer.publicJwk()], "en")).includes("Signature not valid: do not rely on this receipt."));
    assert.ok((await page(receipt, [], "fr")).includes("Signature non valide : ne vous fiez pas à ce reçu."));
  });

  it("shows every built-in method in both languages", async () => {
    const all: FactorKind[] = ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "text_code", "spoken_knowledge"];
    const receipt = await signReceipt(signer, { ...body, verification: { level: 3, methods: all } });
    const en = await page(receipt, [signer.publicJwk()], "en");
    assert.ok(en.includes("level 3, by answers keyed on the phone, PIN, the carrier&#39;s match on the number on file, photo ID and selfie, texted code, spoken answers"));
    const fr = await page(receipt, [signer.publicJwk()], "fr");
    assert.ok(fr.includes("niveau 3, par réponses saisies au clavier, NIP, la correspondance de l&#39;opérateur pour le numéro au dossier, pièce d&#39;identité avec photo et égoportrait, code reçu par texto, réponses de vive voix"));
  });
});

describe("receipt link tokens", () => {
  it("are 256 random bits in base64url, and only their hash is kept", () => {
    const fixed = newReceiptLinkToken(() => new Uint8Array(32));
    assert.deepEqual(fixed, { token: "A".repeat(43), hash: sha256Hex(`receipt-link:${"A".repeat(43)}`) });
    assert.equal(receiptLinkTokenHash(fixed.token), fixed.hash);
    const a = newReceiptLinkToken();
    const b = newReceiptLinkToken();
    assert.notEqual(a.token, b.token);
    assert.match(a.token, /^[A-Za-z0-9_-]{43}$/);
    assert.match(a.hash, /^[0-9a-f]{64}$/);
    assert.equal(a.hash.includes(a.token), false);
    assert.throws(() => newReceiptLinkToken(() => new Uint8Array(16)), RangeError, "a short random source fails closed");
  });

  it("hash only a well-formed token, and never throw", () => {
    const { token } = newReceiptLinkToken();
    for (const bad of ["", token.slice(1), `${token}A`, `${token.slice(1)}+`, `${token.slice(1)}=`, `${token.slice(1)}/`, `${token.slice(2)}\n`]) {
      assert.equal(receiptLinkTokenHash(bad), null, JSON.stringify(bad));
    }
  });

  it("are resolved by ReceiptLinks to the call they were issued for", () => {
    const store = new ReceiptLinks();
    const one = store.issue("call_1");
    const two = store.issue("call_2");
    assert.equal(store.callFor(one), "call_1");
    assert.equal(store.callFor(two), "call_2");
    assert.equal(store.callFor(newReceiptLinkToken().token), null);
    assert.equal(store.callFor("call_1"), null);
  });
});

describe("demo and Stripe adapters", () => {
  it("runs the owner-command, deposit (both modes) and entry flows end to end", async () => {
    const result = await runDemo(false);
    assert.equal(result.checksOk, true);
    assert.equal(result.receipt.body.payments[0]!.mode, "platform");
    assert.equal(result.connectReceipt.body.payments[0]!.mode, "connect");
    assert.equal(result.connectReceipt.body.payments[0]!.status, "paid");
    assert.deepEqual(result.doorOpened, ["door-1"], "opened once, the replay and the changed grant refused");
    assert.equal(result.ownerReceipt, null, "owner-command has no receipt step");
    assert.equal(result.tamperedFails, true);
    assert.equal(result.chainOk, true);
    assert.deepEqual(result.receipt.body.verification, { level: 2, methods: ["carrier_identity_match", "keypad_knowledge"], policyVersion: "demo-1", configRevision: "demo-2026-11" });
    assert.equal(result.receipt.body.payments[0]!.status, "paid");
    assert.equal(result.receipt.body.consents[0]!.purpose, "repair_texts");
  });
});
