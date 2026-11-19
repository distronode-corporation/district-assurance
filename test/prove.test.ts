import { strict as assert } from "node:assert";
import { generateKeyPairSync, sign, verify, type JsonWebKey } from "node:crypto";
import { describe, it } from "node:test";

import type { AuditInput, ConsentRecord, ReceiptSigner } from "../src/core/adapters.ts";
import { EngineError } from "../src/core/errors.ts";
import { wordingDigest } from "../src/prove/consent.ts";
import { GENESIS_HASH, MemoryAuditLedger, chainEntry, detailCarriesCardNumber, hashEntry, verifyChain } from "../src/prove/ledger.ts";
import {
  checkReceipt,
  derToP1363,
  keyPairSigner,
  receiptDigest,
  receiptKeyRing,
  receiptKeySet,
  receiptPayload,
  signReceipt,
  verifyReceipt,
  type ReceiptBody,
  type ReceiptKeyRingOptions,
} from "../src/prove/receipt.ts";
import { MemoryConsentStore, generateTestSigner } from "../src/testing/fakes.ts";
import { createTestEngine } from "../src/testing/index.ts";

/** When k1 stopped signing: after the test clock's receipts (2026-01-01), so they predate it. */
const RETIRED_AT = "2026-06-01T00:00:00.000Z";
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
    payments: [{ paymentId: "pay_1", status: "paid", amountMinor: 15000, currency: "cad", mode: "platform", providerRef: "cs_1" }],
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
    for (const bad of [null, "x", 7, { ...receipt, signature: 1 }]) assert.equal(verifyReceipt(bad as never, keys), false, "never throws on a malformed envelope");
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

  it("signs the policy version and config revision when the verification names them, and stays at version 1", async () => {
    const signer = generateTestSigner("k1");
    const keys = [signer.publicJwk()];
    const judged = body({ verification: { level: 3, methods: ["keypad_knowledge", "photo_id"], policyVersion: "default-1", configRevision: "2026-11-18.1" } });
    const receipt = await signReceipt(signer, judged);
    assert.equal(receipt.body.v, 1);
    assert.equal(verifyReceipt(receipt, keys), true);
    assert.match(new TextDecoder().decode(receiptPayload(judged)), /"verification":\{"configRevision":"2026-11-18.1","level":3,"methods":\["keypad_knowledge","photo_id"\],"policyVersion":"default-1"\}/);
    const swapped = { ...receipt, body: body({ verification: { ...judged.verification, policyVersion: "default-2" } }) };
    assert.equal(verifyReceipt(swapped, keys), false, "the policy version is signed");
    const dropped = { ...receipt, body: body() };
    assert.equal(verifyReceipt(dropped, keys), false, "dropping the fields breaks the signature");
    assert.notEqual(receiptDigest(judged), receiptDigest(body()));
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

describe("receipt signer contract (INT-4)", () => {
  const der = (...bytes: number[]): Uint8Array => Uint8Array.from(bytes);
  const run = (length: number, byte: number): number[] => Array.from({ length }, () => byte);
  const malformed = /DER-encoded ECDSA P-256 signature/;

  it("keyPairSigner returns a 64-byte P1363 signature that node:crypto verifies", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const signer = keyPairSigner("k", privateKey.export({ format: "pem", type: "pkcs8" }).toString());
    const payload = receiptPayload(body());
    const signature = await signer.sign(payload);
    assert.equal(signature.byteLength, 64);
    assert.equal(verify("sha256", payload, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature), true);
  });

  it("converts node:crypto's DER signatures to the P1363 form node:crypto verifies", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const payload = receiptPayload(body());
    const lengths = new Set<number>();
    // Enough signatures to see an r or s with its sign-bit padding byte and without it.
    for (let i = 0; i < 64; i++) {
      const signature = sign("sha256", payload, { key: privateKey, dsaEncoding: "der" });
      lengths.add(signature.length);
      const p1363 = derToP1363(signature);
      assert.equal(p1363.byteLength, 64);
      assert.equal(verify("sha256", payload, { key: publicKey, dsaEncoding: "ieee-p1363" }, p1363), true);
      assert.equal(verify("sha256", payload, { key: publicKey, dsaEncoding: "der" }, signature), true);
    }
    assert.ok(lengths.size > 1, "DER lengths vary with the integers' leading bytes");
  });

  it("left-pads short integers and drops the sign-bit padding byte", () => {
    const expected = new Uint8Array(64);
    expected[31] = 1;
    expected[63] = 0x80;
    assert.deepEqual(derToP1363(der(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80)), expected);
    const full = der(0x30, 0x45, 0x02, 0x21, 0x00, ...run(32, 0xff), 0x02, 0x20, ...run(32, 0x7f));
    assert.deepEqual(derToP1363(full), Uint8Array.from([...run(32, 0xff), ...run(32, 0x7f)]));
  });

  it("refuses anything that is not a strict DER P-256 signature", () => {
    const tooLong = der(0x30, 0x26, 0x02, 0x21, ...run(33, 0x01), 0x02, 0x01, 0x01);
    for (const [name, bytes] of [
      ["empty", der()],
      ["not a sequence", der(0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)],
      ["a wrong sequence length", der(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)],
      ["an empty sequence", der(0x30, 0x00)],
      ["no second integer", der(0x30, 0x03, 0x02, 0x01, 0x01)],
      ["not an integer", der(0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x01)],
      ["an empty integer", der(0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01)],
      ["a truncated integer", der(0x30, 0x03, 0x02, 0x05, 0x01)],
      ["a negative integer", der(0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01)],
      ["zero", der(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00)],
      ["a needless leading zero", der(0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01)],
      ["more than 32 bytes", tooLong],
      ["bytes after the integers", der(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00)],
      ["the long length form", der(0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)],
    ] as const) {
      assert.throws(() => derToP1363(bytes), malformed, name);
    }
  });

  it("a key store signer that returns DER works through derToP1363, and is refused without it", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    // A stand-in for a KMS: it signs where the key lives and answers in DER.
    const kmsSign = async (payload: Uint8Array): Promise<Uint8Array> => sign("sha256", payload, { key: privateKey, dsaEncoding: "der" });
    const publicJwk = { ...publicKey.export({ format: "jwk" }), kid: "kms-1", alg: "ES256", use: "sig" };
    const kmsSigner: ReceiptSigner = { keyId: "kms-1", algorithm: "ES256", sign: async (p) => derToP1363(await kmsSign(p)), publicJwk: () => publicJwk };
    assert.equal(verifyReceipt(await signReceipt(kmsSigner, body()), [publicJwk]), true);
    const raw: ReceiptSigner = { ...kmsSigner, sign: kmsSign };
    await assert.rejects(signReceipt(raw, body()), (e: unknown) => e instanceof EngineError && e.code === "invalid_input" && /not a 64-byte P1363 signature/.test(e.message));
  });
});

describe("receipt key rings and rotation (PRV-1)", () => {
  it("a receipt signed before rotation still verifies against the key set after it", async () => {
    const k1 = generateTestSigner("k1");
    const k2 = generateTestSigner("k2");
    // Before: k1 signs, and k2 is published ahead of use, so cached key sets already hold it.
    const before = createTestEngine({ adapters: { signer: receiptKeyRing({ signers: [k1, k2], active: "k1" }) } });
    assert.deepEqual(before.engine.receiptKeys().map((k) => k.kid), ["k1", "k2"]);
    const old = (await before.engine.endCall((await before.engine.startCall()).callId))!;
    assert.equal(old.kid, "k1");
    // After: k2 signs, and k1 is retired: only its public key is kept, its private key is gone.
    const after = createTestEngine({ adapters: { signer: receiptKeyRing({ signers: [k2], active: "k2", retired: [{ ...k1.publicJwk(), retiredAt: RETIRED_AT }] }) } });
    const fresh = (await after.engine.endCall((await after.engine.startCall()).callId))!;
    assert.equal(fresh.kid, "k2");
    const keys = after.engine.receiptKeys();
    assert.deepEqual(keys.map((k) => k.kid), ["k2", "k1"]);
    assert.equal(keys.every((k) => k.d === undefined && k.alg === "ES256" && k.use === "sig"), true);
    assert.equal(verifyReceipt(old, keys), true);
    assert.equal(verifyReceipt(fresh, keys), true);
    assert.equal(verifyReceipt(old, [keys[0]!]), false, "without the retired key the old receipt does not verify");
    const changed = { ...old, body: { ...old.body, endedAt: "2026-01-01T00:00:01.000Z" } };
    assert.equal(verifyReceipt(changed, keys), false);
  });

  it("marks a retired key in the key set, and says a receipt it signed before retiring is valid under a retired key", async () => {
    const k1 = generateTestSigner("k1");
    const k2 = generateTestSigner("k2");
    const signedBy = (signer: ReceiptSigner, issuedAt: string) => signReceipt(signer, body({ issuedAt }));
    const old = await signedBy(k1, "2026-01-01T00:00:00.000Z");
    const keys = receiptKeyRing({ signers: [k2], active: "k2", retired: [{ ...k1.publicJwk(), retiredAt: RETIRED_AT }] }).keySet();
    assert.deepEqual(keys.map((k) => [k.kid, (k as { retired?: boolean }).retired ?? false, (k as { retiredAt?: string }).retiredAt ?? null]), [
      ["k2", false, null],
      ["k1", true, RETIRED_AT],
    ]);
    assert.deepEqual(checkReceipt(old, keys), { valid: true, retiredAt: RETIRED_AT }, "valid, signed with a retired key");
    assert.deepEqual(checkReceipt(await signedBy(k2, "2026-07-01T00:00:00.000Z"), keys), { valid: true, retiredAt: null }, "the active key");
    // A receipt the retired key signed at or after its retirement (a key that leaked, a host that
    // kept signing with it) is invalid, and so is one whose times cannot be compared.
    for (const issuedAt of [RETIRED_AT, "2026-07-01T00:00:00.000Z"]) {
      const late = await signedBy(k1, issuedAt);
      assert.deepEqual(checkReceipt(late, keys), { valid: false }, issuedAt);
      assert.equal(verifyReceipt(late, keys), false);
      assert.equal(verifyReceipt(late, [k1.publicJwk()]), true, "the same signature under the key before it was retired");
    }
    for (const retiredAt of ["2026-06-01", "soon", 7]) {
      assert.deepEqual(checkReceipt(old, [{ ...k1.publicJwk(), retiredAt } as JsonWebKey]), { valid: false }, String(retiredAt));
    }
    const odd = await signedBy(k1, "2026-01-01T00:00:00Z");
    assert.deepEqual(checkReceipt(odd, keys), { valid: false }, "an issuedAt that is not the engine's own form is not compared");
  });

  it("signs with the active key, publishes copies, and leaves a single signer's key set alone", async () => {
    const k1 = generateTestSigner("k1");
    const ring = receiptKeyRing({ signers: [k1], active: "k1" });
    assert.equal(ring.keyId, "k1");
    assert.equal(ring.algorithm, "ES256");
    assert.equal(verifyReceipt(await signReceipt(ring, body()), [k1.publicJwk()]), true);
    ring.publicJwk().kid = "x";
    ring.keySet()[0]!.kid = "x";
    assert.deepEqual([ring.publicJwk().kid, ring.keySet()[0]!.kid], ["k1", "k1"]);
    assert.deepEqual(receiptKeySet(ring), ring.keySet());
    assert.deepEqual(receiptKeySet(k1), [k1.publicJwk()]);
    assert.deepEqual(receiptKeySet(undefined), []);
  });

  it("refuses a key ring it could not publish faithfully", () => {
    const k1 = generateTestSigner("k1");
    const { kty, crv, x, y } = k1.publicJwk();
    const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" }).publicKey.export({ format: "jwk" });
    const renamed: ReceiptSigner = { ...k1, keyId: "k9" };
    const leaky: ReceiptSigner = { ...generateTestSigner("k3"), publicJwk: () => generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }) };
    for (const [name, options, message] of [
      ["no active signer", { signers: [k1], active: "k2" }, /no signer has the active kid k2/],
      ["a retired key without a kid", { signers: [k1], active: "k1", retired: [{ kty, crv, x, y }] }, /every key needs a kid/],
      ["a retired key without a retiredAt", { signers: [k1], active: "k1", retired: [{ kty, crv, x, y, kid: "old" }] }, /old needs a retiredAt/],
      ["a retiredAt that is not UTC", { signers: [k1], active: "k1", retired: [{ kty, crv, x, y, kid: "old", retiredAt: "2026-06-01T00:00:00+02:00" }] }, /old needs a retiredAt/],
      ["an empty kid", { signers: [k1], active: "k1", retired: [{ kty, crv, x, y, kid: "" }] }, /every key needs a kid/],
      ["a retired key with the active kid", { signers: [k1], active: "k1", retired: [k1.publicJwk()] }, /two keys have the kid k1/],
      ["two signers with one kid", { signers: [k1, generateTestSigner("k1")], active: "k1" }, /two keys have the kid k1/],
      ["a signer whose key names another kid", { signers: [renamed], active: "k9" }, /the signer k9 publishes a key named k1/],
      ["a private part", { signers: [leaky], active: "k3" }, /has a private part/],
      ["another curve", { signers: [k1], active: "k1", retired: [{ ...p384, kid: "old" }] }, /old is not a P-256 public key/],
      ["another key type", { signers: [k1], active: "k1", retired: [{ kty: "OKP", crv: "P-256", x, y, kid: "old" }] }, /not a P-256 public key/],
      ["a point off the curve", { signers: [k1], active: "k1", retired: [{ kty, crv, x, y: x, kid: "old" }] }, /not a P-256 public key/],
    ] as const) {
      assert.throws(() => receiptKeyRing(options as ReceiptKeyRingOptions), (e: unknown) => e instanceof TypeError && message.test(e.message), name);
    }
  });
});

describe("consent wording", () => {
  it("fingerprints purpose, version and both texts", () => {
    const w = { purpose: "texts", version: "1", text: { en: "May we text you?", fr: "Pouvons-nous vous texter?" } };
    assert.match(wordingDigest(w), /^[0-9a-f]{64}$/);
    assert.notEqual(wordingDigest(w), wordingDigest({ ...w, version: "2" }));
    assert.notEqual(wordingDigest(w), wordingDigest({ ...w, text: { ...w.text, fr: "Autre" } }));
  });

  it("keeps the digest a wording without Spanish had before Spanish existed, and covers Spanish when given", () => {
    const w = { purpose: "texts", version: "1", text: { en: "May we text you?", fr: "Pouvons-nous vous texter?" } };
    // Pinned: SHA-256 of canonicalJson({purpose, version, text: {en, fr}}), as receipts already carry it.
    assert.equal(wordingDigest(w), "77671e4df90e7ca2b7d6f7ee791eff69a9ea430b87e684f23a85bc85fef79991");
    const es = { ...w, text: { ...w.text, es: "¿Podemos enviarle mensajes de texto?" } };
    assert.notEqual(wordingDigest(es), wordingDigest(w));
    assert.notEqual(wordingDigest(es), wordingDigest({ ...es, text: { ...es.text, es: "Otro" } }));
  });
});

describe("memory consent store", () => {
  it("keeps workspace and consent apart, whatever slashes they hold", async () => {
    const store = new MemoryConsentStore();
    const consent = (consentId: string, purpose: string): ConsentRecord => ({
      consentId,
      callId: "call_1", subjectKey: null,
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
