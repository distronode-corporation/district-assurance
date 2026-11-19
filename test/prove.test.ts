import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";

import type { AuditInput, ConsentRecord } from "../src/core/adapters.ts";
import { EngineError } from "../src/core/errors.ts";
import { wordingDigest } from "../src/prove/consent.ts";
import { GENESIS_HASH, MemoryAuditLedger, chainEntry, detailCarriesCardNumber, hashEntry, verifyChain } from "../src/prove/ledger.ts";
import { keyPairSigner, receiptDigest, receiptPayload, signReceipt, verifyReceipt, type ReceiptBody } from "../src/prove/receipt.ts";
import { MemoryConsentStore, generateTestSigner } from "../src/testing/fakes.ts";

const at = "2026-01-01T00:00:00.000Z";
const input = (event: AuditInput["event"], detail: AuditInput["detail"] = {}): AuditInput => ({ callId: "c1", actor: "code", event, at, detail });

describe("audit ledger", () => {
  it("chains entries from the genesis and verifies the chain", async () => {
    const ledger = new MemoryAuditLedger();
    assert.deepEqual(await ledger.head(), { seq: 0, hash: GENESIS_HASH });
    const first = await ledger.append(input("call.started", { locale: "en" }));
    const second = await ledger.append(input("call.ended"));
    assert.equal(first.seq, 1);
    assert.equal(first.prevHash, GENESIS_HASH);
    assert.equal(second.prevHash, first.hash);
    const { hash, ...rest } = first;
    assert.equal(hashEntry(rest), hash);
    const entries = await ledger.list();
    assert.deepEqual(verifyChain(entries), { ok: true, head: { seq: 2, hash: second.hash } });
    assert.deepEqual(await ledger.head(), { seq: 2, hash: second.hash });
    assert.deepEqual(await ledger.list(2), [second]);
    assert.deepEqual(verifyChain(await ledger.list(2), { seq: 1, hash: first.hash }), { ok: true, head: { seq: 2, hash: second.hash } });
    assert.deepEqual(verifyChain([]), { ok: true, head: { seq: 0, hash: GENESIS_HASH } });
  });

  it("detects a changed, removed or reordered entry", async () => {
    const ledger = new MemoryAuditLedger();
    for (const e of ["call.started", "verification.started", "call.ended"] as const) await ledger.append(input(e));
    const entries = await ledger.list();
    const changed = structuredClone(entries);
    changed[1]!.detail = { level: 3 };
    assert.deepEqual(verifyChain(changed), { ok: false, seq: 2, reason: "hash" });
    assert.deepEqual(verifyChain([entries[0]!, entries[2]!]), { ok: false, seq: 3, reason: "seq" });
    const relinked = structuredClone(entries);
    relinked[2]!.prevHash = GENESIS_HASH;
    assert.deepEqual(verifyChain(relinked), { ok: false, seq: 3, reason: "prev_hash" });
  });

  it("stores copies, so a caller cannot rewrite history", async () => {
    const ledger = new MemoryAuditLedger();
    const detail = { n: 1 };
    const entry = await ledger.append(input("call.started", detail));
    detail.n = 2;
    entry.detail.n = 3;
    const [stored] = await ledger.list();
    assert.deepEqual(stored!.detail, { n: 1 });
    stored!.detail.n = 4;
    assert.deepEqual((await ledger.list())[0]!.detail, { n: 1 });
  });

  it("refuses detail that carries a card number, anywhere in it", () => {
    assert.throws(
      () => chainEntry(input("redaction.applied", { note: ["fine", { deep: "pan 4242 4242 4242 4242" }] }), 1, GENESIS_HASH),
      (e: unknown) => e instanceof EngineError && e.code === "invalid_input",
    );
    assert.equal(detailCarriesCardNumber({ a: 1, b: null, c: true, d: ["x"] }), false);
    assert.equal(detailCarriesCardNumber("4242424242424242"), true);
  });

  it("does not mistake a hex digest for a card number", () => {
    // 64 hex characters with a 16-digit Luhn-valid run inside.
    const digest = `${"4242424242424242"}${"a".repeat(48)}`;
    assert.equal(detailCarriesCardNumber({ digest }), false);
    assert.equal(detailCarriesCardNumber({ digest: digest.slice(0, 63) }), true);
  });
});

function body(patch: Partial<ReceiptBody> = {}): ReceiptBody {
  return {
    v: 1,
    receiptId: "rcpt_1",
    callId: "c1",
    workspaceId: "w1",
    startedAt: at,
    endedAt: at,
    issuedAt: at,
    verification: { level: 3, methods: ["keypad_knowledge", "photo_id"] },
    records: [{ recordId: "rec_1", formId: "repair", digest: "ab".repeat(32) }],
    payments: [{ paymentId: "pay_1", status: "paid", amountMinor: 15000, currency: "cad", providerRef: "cs_1" }],
    consents: [{ purpose: "texts", wordingVersion: "1", wordingDigest: "cd".repeat(32), answer: "yes" }],
    ledger: { seq: 9, hash: "ef".repeat(32) },
    ...patch,
  };
}

describe("receipts", () => {
  it("signs the canonical body and verifies with the public key only", async () => {
    const signer = generateTestSigner("k1");
    const receipt = await signReceipt(signer, body());
    assert.equal(receipt.alg, "ES256");
    assert.equal(receipt.kid, "k1");
    assert.equal(Buffer.from(receipt.signature, "base64url").length, 64);
    const keys = [signer.publicJwk()];
    assert.equal("d" in keys[0]!, false, "the published key has no private part");
    assert.equal(verifyReceipt(receipt, keys), true);
    assert.equal(new TextDecoder().decode(receiptPayload(body())).startsWith('{"callId":"c1","consents":'), true);
    assert.match(receiptDigest(body()), /^[0-9a-f]{64}$/);
  });

  it("fails on any change, a wrong key, an unknown kid or a malformed signature", async () => {
    const signer = generateTestSigner("k1");
    const receipt = await signReceipt(signer, body());
    const keys = [signer.publicJwk()];
    assert.equal(verifyReceipt({ ...receipt, body: body({ endedAt: "2026-01-01T00:00:01.000Z" }) }, keys), false);
    const raw = JSON.stringify(receipt.body).replace("15000", "15001");
    assert.equal(verifyReceipt({ ...receipt, body: JSON.parse(raw) as ReceiptBody }, keys), false);
    assert.equal(verifyReceipt(receipt, [generateTestSigner("k1").publicJwk()]), false);
    assert.equal(verifyReceipt({ ...receipt, kid: "k2" }, keys), false);
    assert.equal(verifyReceipt({ ...receipt, alg: "HS256" as "ES256" }, keys), false);
    assert.equal(verifyReceipt({ ...receipt, signature: receipt.signature.slice(4) }, keys), false);
    assert.equal(verifyReceipt(receipt, [{ kid: "k1", kty: "EC", crv: "P-256", x: "bad", y: "bad" }]), false);
  });

  it("builds a signer from a PEM or a JWK, P-256 only", async () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const fromJwk = keyPairSigner("j", privateKey.export({ format: "jwk" }));
    const receipt = await signReceipt(fromJwk, body());
    assert.equal(verifyReceipt(receipt, [fromJwk.publicJwk()]), true);
    assert.deepEqual(
      { kid: fromJwk.publicJwk().kid, alg: fromJwk.publicJwk().alg, use: fromJwk.publicJwk().use },
      { kid: "j", alg: "ES256", use: "sig" },
    );
    const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" }).privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    assert.throws(() => keyPairSigner("x", p384), /P-256/);
    const ed = generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    assert.throws(() => keyPairSigner("x", ed), /P-256/);
  });
});

describe("consent wording", () => {
  it("fingerprints purpose, version and both texts", () => {
    const w = { purpose: "texts", version: "1", text: { en: "May we text you?", fr: "Pouvons-nous vous texter?" } };
    assert.match(wordingDigest(w), /^[0-9a-f]{64}$/);
    assert.notEqual(wordingDigest(w), wordingDigest({ ...w, version: "2" }));
    assert.notEqual(wordingDigest(w), wordingDigest({ ...w, text: { ...w.text, fr: "Autre" } }));
  });
});

describe("memory consent store", () => {
  it("keeps workspace and consent apart, whatever slashes they hold", async () => {
    const store = new MemoryConsentStore();
    const consent = (consentId: string, purpose: string): ConsentRecord => ({
      consentId,
      callId: "call_1",
      purpose,
      wordingVersion: "1",
      wordingDigest: "0".repeat(64),
      locale: "en",
      answer: "yes",
      channel: "call",
      at: "2026-01-01T00:00:00.000Z",
    });
    await store.putConsent("a/b", consent("c", "first"));
    await store.putConsent("a", consent("b/c", "second"));
    assert.equal((await store.getConsent("a", "b/c"))?.consent.purpose, "second");
    await store.revokeConsent("a", { consentId: "b/c", via: "text", at: "2026-01-02T00:00:00.000Z" });
    assert.equal((await store.getConsent("a/b", "c"))?.revoked, null);
  });
});
