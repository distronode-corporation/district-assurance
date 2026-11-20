import { strict as assert } from "node:assert";
import { generateKeyPairSync, sign, verify, type JsonWebKey } from "node:crypto";
import { describe, it } from "node:test";

import type { AuditEntry, AuditInput, AuditLedger, ConsentRecord, ReceiptSigner } from "../src/core/adapters.ts";
import { canonicalJson } from "../src/core/canonical.ts";
import { EngineError } from "../src/core/errors.ts";
import { wordingDigest } from "../src/prove/consent.ts";
import {
  EXPORT_WALK_PAGE,
  decodeCursor,
  encodeCursor,
  exportLedger,
  ledgerExportPayload,
  verifyLedgerExport,
  type ChainPoint,
  type LedgerExportInput,
  type LedgerExportTrailer,
} from "../src/prove/export.ts";
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
import { FixedClock, MemoryConsentStore, generateTestSigner } from "../src/testing/fakes.ts";
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

  it("reports a stored entry changed into what canonical JSON refuses as a break, without throwing", async () => {
    // Found by SRV-7's fuzzing (test/property/ledger.test.ts): one changed byte turned a number in
    // stored JSON into 1e999, which parses as Infinity.
    const ledger = new MemoryAuditLedger();
    await ledger.append({ callId: "c1", actor: "code", event: "call.started", at: "2026-01-01T00:00:00.000Z", detail: { n: 1 } });
    const line = JSON.stringify((await ledger.list())[0]).replace('"n":1', '"n":1e999');
    assert.deepEqual(verifyChain([JSON.parse(line)]), { ok: false, seq: 1, reason: "hash" });
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
    // One real signature for the round trip; the fixed vectors below cover padding and short integers.
    const signature = sign("sha256", payload, { key: privateKey, dsaEncoding: "der" });
    const p1363 = derToP1363(signature);
    assert.equal(p1363.byteLength, 64);
    assert.equal(verify("sha256", payload, { key: publicKey, dsaEncoding: "ieee-p1363" }, p1363), true);
    assert.equal(verify("sha256", payload, { key: publicKey, dsaEncoding: "der" }, signature), true);
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

/** A ledger that hands out what `edit` makes of the real entries and head, as a tampered or broken store would. */
class EditedLedger implements AuditLedger {
  readonly inner: MemoryAuditLedger;
  readonly edit: { list?: (entries: AuditEntry[]) => AuditEntry[]; head?: (head: ChainPoint) => ChainPoint };

  constructor(inner: MemoryAuditLedger, edit: EditedLedger["edit"]) {
    this.inner = inner;
    this.edit = edit;
  }

  append(i: AuditInput): Promise<AuditEntry> {
    return this.inner.append(i);
  }

  async head(): Promise<ChainPoint> {
    const head = await this.inner.head();
    return this.edit.head === undefined ? head : this.edit.head(head);
  }

  async list(fromSeq?: number, limit?: number): Promise<AuditEntry[]> {
    const entries = await this.inner.list(fromSeq, limit);
    return this.edit.list === undefined ? entries : this.edit.list(entries);
  }
}

async function ledgerOf(n: number, offset = 0): Promise<MemoryAuditLedger> {
  const ledger = new MemoryAuditLedger();
  for (let i = 1; i <= n; i++) await ledger.append(input("module.event", { i: i + offset }));
  return ledger;
}

async function collect(lines: AsyncIterable<string>): Promise<string> {
  let out = "";
  for await (const line of lines) out += line;
  return out;
}

describe("ledger pages", () => {
  it("lists at most `limit` entries from `fromSeq`, in order", async () => {
    const ledger = await ledgerOf(5);
    const seqs = async (from?: number, limit?: number) => (await ledger.list(from, limit)).map((e) => e.seq);
    assert.deepEqual(await seqs(), [1, 2, 3, 4, 5]);
    assert.deepEqual(await seqs(1, 1), [1], "one");
    assert.deepEqual(await seqs(1, 5), [1, 2, 3, 4, 5], "exactly all");
    assert.deepEqual(await seqs(2, 2), [2, 3], "after plus limit");
    assert.deepEqual(await seqs(4, 10), [4, 5], "a limit larger than the rest");
    assert.deepEqual(await seqs(6, 3), [], "past the head");
    for (const limit of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      await assert.rejects(ledger.list(1, limit), /limit must be an integer of 1 or more/, String(limit));
    }
  });
});

describe("ledger export", () => {
  const clock = new FixedClock("2026-11-18T12:00:00.000Z");
  const signer = generateTestSigner("k1");
  const keys = [signer.publicJwk()];
  const run = (ledger: AuditLedger, more: Partial<LedgerExportInput>) => collect(exportLedger({ ledger, signer, clock, ledgerId: "ws_1", ...more }));
  const malformed = { ok: false, reason: "malformed" };

  it("yields one canonical entry per line and a signed trailer with the head", async () => {
    const ledger = await ledgerOf(3);
    const text = await run(ledger, { fromSeq: 1 });
    const lines = text.split("\n");
    assert.equal(lines.length, 5, "three entries, a trailer and the final newline");
    assert.equal(lines.at(-1), "");
    const entries = await ledger.list();
    assert.deepEqual(lines.slice(0, 3), entries.map((e) => canonicalJson(e)));
    const head = await ledger.head();
    const signed = JSON.parse(lines[3]!) as LedgerExportTrailer;
    assert.deepEqual(signed.trailer, {
      v: 1,
      type: "ledger_export",
      ledgerId: "ws_1",
      from: { seq: 0, hash: GENESIS_HASH },
      through: head,
      count: 3,
      head,
      exportedAt: "2026-11-18T12:00:00.000Z",
      cursor: `3.${head.hash}`,
    });
    assert.equal(signed.alg, "ES256");
    assert.equal(signed.kid, "k1");
    assert.equal(new TextDecoder().decode(ledgerExportPayload(signed.trailer)).startsWith("district-assurance ledger export v1\n{"), true);
    assert.deepEqual(verifyLedgerExport(text, keys), { ok: true, entries, trailer: signed.trailer });
  });

  it("starts at any seq, anchored on the entry before it", async () => {
    const ledger = await ledgerOf(3);
    const [first, second, third] = await ledger.list();
    const check = verifyLedgerExport(await run(ledger, { fromSeq: 2 }), keys);
    assert.ok(check.ok);
    assert.deepEqual(check.trailer.from, { seq: 1, hash: first!.hash });
    assert.deepEqual(check.entries, [second, third]);
    const empty = verifyLedgerExport(await run(ledger, { fromSeq: 4 }), keys);
    assert.ok(empty.ok);
    assert.deepEqual([empty.entries, empty.trailer.count, empty.trailer.through], [[], 0, { seq: 3, hash: third!.hash }]);
    const none = verifyLedgerExport(await run(new MemoryAuditLedger(), { fromSeq: 1 }), keys);
    assert.ok(none.ok);
    assert.equal(none.trailer.cursor, `0.${GENESIS_HASH}`);
  });

  it("resumes by cursor, page by page, into one checked chain", async () => {
    const ledger = await ledgerOf(5);
    const first = verifyLedgerExport(await run(ledger, { fromSeq: 1, limit: 2 }), keys);
    assert.ok(first.ok);
    assert.deepEqual([first.trailer.through.seq, first.trailer.head.seq, first.entries.length], [2, 5, 2]);
    const second = verifyLedgerExport(await run(ledger, { cursor: first.trailer.cursor, limit: 2 }), keys, first.trailer);
    assert.ok(second.ok);
    assert.deepEqual(second.entries.map((e) => e.seq), [3, 4]);
    // An entry appended between pages is picked up by the next one.
    await ledger.append(input("call.ended"));
    const third = verifyLedgerExport(await run(ledger, { cursor: second.trailer.cursor }), keys, second.trailer);
    assert.ok(third.ok);
    assert.deepEqual(third.entries.map((e) => e.seq), [5, 6]);
    assert.deepEqual(third.trailer.through, await ledger.head());
    assert.deepEqual([...first.entries, ...second.entries, ...third.entries], await ledger.list());
    const caughtUp = verifyLedgerExport(await run(ledger, { cursor: third.trailer.cursor }), keys, third.trailer);
    assert.ok(caughtUp.ok);
    assert.deepEqual(caughtUp.entries, []);
    const fromGenesis = verifyLedgerExport(await run(ledger, { cursor: `0.${GENESIS_HASH}` }), keys);
    assert.ok(fromGenesis.ok);
    assert.equal(fromGenesis.entries.length, 6);
  });

  it("refuses a run that does not continue the previous one", async () => {
    const ledger = await ledgerOf(4);
    const first = verifyLedgerExport(await run(ledger, { fromSeq: 1, limit: 2 }), keys);
    assert.ok(first.ok);
    const skipped = await run(ledger, { fromSeq: 4 });
    assert.deepEqual(verifyLedgerExport(skipped, keys, first.trailer), { ok: false, reason: "continuity" });
    const otherLedger = await run(ledger, { cursor: first.trailer.cursor, ledgerId: "ws_2" });
    assert.deepEqual(verifyLedgerExport(otherLedger, keys, first.trailer), { ok: false, reason: "continuity" });
    assert.equal(verifyLedgerExport(otherLedger, keys).ok, true, "on its own it is a valid run of ws_2");
  });

  it("detects a changed, removed or replaced entry, and a changed trailer", async () => {
    const text = await run(await ledgerOf(3), { fromSeq: 1 });
    const lines = text.split("\n");
    assert.deepEqual(verifyLedgerExport(text.replace('"i":2', '"i":7'), keys), { ok: false, reason: "chain", seq: 2 });
    assert.deepEqual(verifyLedgerExport([lines[0], lines[2], lines[3], ""].join("\n"), keys), { ok: false, reason: "chain", seq: 3 });
    assert.deepEqual(verifyLedgerExport([lines[0], lines[1], lines[3], ""].join("\n"), keys), { ok: false, reason: "chain" }, "cut short");
    const page = (await run(await ledgerOf(3), { fromSeq: 1, limit: 2 })).split("\n");
    assert.deepEqual(verifyLedgerExport([page[0], page[1], lines[2], page[2], ""].join("\n"), keys), { ok: false, reason: "chain" }, "one added");
    // A whole other chain of the same length from the same start ends on another hash.
    const other = (await (await ledgerOf(3, 10)).list()).map((e) => canonicalJson(e));
    assert.deepEqual(verifyLedgerExport([...other, lines[3], ""].join("\n"), keys), { ok: false, reason: "chain" });
    const signed = JSON.parse(lines[3]!) as LedgerExportTrailer;
    const moved = { ...signed, trailer: { ...signed.trailer, exportedAt: "2026-11-18T12:00:01.000Z" } };
    assert.deepEqual(verifyLedgerExport([lines[0], lines[1], lines[2], JSON.stringify(moved), ""].join("\n"), keys), { ok: false, reason: "signature" });
  });

  it("refuses a bad signature, key or algorithm", async () => {
    const text = await run(await ledgerOf(1), { fromSeq: 1 });
    const [entry, trailerLine] = text.split("\n");
    const signed = JSON.parse(trailerLine!) as LedgerExportTrailer;
    const withTrailer = (t: unknown) => `${entry}\n${JSON.stringify(t)}\n`;
    const bad = { ok: false, reason: "signature" };
    assert.deepEqual(verifyLedgerExport(text, [generateTestSigner("k1").publicJwk()]), bad);
    assert.deepEqual(verifyLedgerExport(text, []), bad);
    assert.deepEqual(verifyLedgerExport(withTrailer({ ...signed, alg: "HS256" }), keys), bad);
    assert.deepEqual(verifyLedgerExport(withTrailer({ ...signed, signature: signed.signature.slice(4) }), keys), bad);
    assert.deepEqual(verifyLedgerExport(text, [{ kid: "k1", kty: "EC", crv: "P-256", x: "bad", y: "bad" }]), bad);
    // A signature over the bare canonical body, as a receipt is signed, never passes as a trailer signature.
    const bare = Buffer.from(await signer.sign(new TextEncoder().encode(canonicalJson(signed.trailer)))).toString("base64url");
    assert.deepEqual(verifyLedgerExport(withTrailer({ ...signed, signature: bare }), keys), bad);
  });

  it("refuses malformed input without throwing", async () => {
    const text = await run(await ledgerOf(2), { fromSeq: 1 });
    const [e1, e2, trailerLine] = text.split("\n");
    const signed = JSON.parse(trailerLine!) as LedgerExportTrailer;
    for (const bad of ["", text.slice(0, -1), "\n", `${e1}\n{oops\n${trailerLine}\n`, `${e1}\n${e2}\n`, "null\n", "7\n", '{"trailer":null}\n']) {
      assert.deepEqual(verifyLedgerExport(bad, keys), malformed);
    }
    const bodies: unknown[] = [
      { ...signed.trailer, v: 2 },
      { ...signed.trailer, from: null },
      { ...signed.trailer, from: { seq: -1, hash: GENESIS_HASH } },
      { ...signed.trailer, through: { seq: 2, hash: "XY" } },
      { ...signed.trailer, count: 3 },
      { ...signed.trailer, head: { seq: 1, hash: GENESIS_HASH } },
      { ...signed.trailer, from: { seq: 3, hash: GENESIS_HASH } },
      { ...signed.trailer, cursor: `1.${GENESIS_HASH}` },
    ];
    for (const trailer of bodies) assert.deepEqual(verifyLedgerExport(`${e1}\n${e2}\n${JSON.stringify({ ...signed, trailer })}\n`, keys), malformed);
    // Signed, but an entry line is not an entry.
    assert.deepEqual(verifyLedgerExport(`${e1}\nnull\n${trailerLine}\n`, keys), malformed);
    // Whatever an auditor's tool hands it, it answers and never throws.
    for (const value of [null, undefined, 42, Buffer.from(text)]) assert.deepEqual(verifyLedgerExport(value as unknown as string, keys), malformed);
    for (const keySet of [null, undefined, {}, "keys", [null, 7]]) {
      assert.deepEqual(verifyLedgerExport(text, keySet as unknown as typeof keys), { ok: false, reason: "signature" });
    }
    for (const after of [null, 7, "trailer", {}]) {
      assert.deepEqual(verifyLedgerExport(text, keys, after as unknown as LedgerExportTrailer["trailer"]), { ok: false, reason: "continuity" });
    }
  });

  it("refuses a signer that does not answer a 64-byte P1363 signature, before yielding", async () => {
    const der: ReceiptSigner = { ...signer, sign: async () => new Uint8Array(70) };
    const lines: string[] = [];
    await assert.rejects(
      (async () => {
        for await (const line of exportLedger({ ledger: await ledgerOf(2), signer: der, clock, ledgerId: "ws_1", fromSeq: 1 })) lines.push(line);
      })(),
      (e: unknown) => e instanceof EngineError && e.code === "invalid_input" && /64-byte P1363/.test(e.message),
    );
    assert.deepEqual(lines, [], "no entry is handed out under a trailer that could never verify");
  });

  it("refuses bad arguments", async () => {
    const ledger = await ledgerOf(2);
    const refused = (e: unknown) => e instanceof EngineError && e.code === "invalid_input";
    await assert.rejects(run(ledger, {}), refused);
    await assert.rejects(run(ledger, { fromSeq: 1, cursor: `0.${GENESIS_HASH}` }), refused);
    for (const fromSeq of [0, 1.5, Number.NaN, 4]) await assert.rejects(run(ledger, { fromSeq }), refused);
    for (const limit of [0, -1, 2.5]) await assert.rejects(run(ledger, { fromSeq: 1, limit }), refused);
    await assert.rejects(run(ledger, { fromSeq: 1, ledgerId: "" }), refused);
    for (const cursor of ["", "3", `01.${GENESIS_HASH}`, `1.${"AB".repeat(32)}`, `3.${GENESIS_HASH}`]) {
      await assert.rejects(run(ledger, { cursor }), refused);
    }
    assert.equal(decodeCursor("x"), null);
    assert.deepEqual(decodeCursor(encodeCursor({ seq: 2, hash: GENESIS_HASH })), { seq: 2, hash: GENESIS_HASH });
  });

  it("refuses to sign a ledger that was tampered with", async () => {
    const ledger = await ledgerOf(3);
    const [first] = await ledger.list();
    const head = await ledger.head();
    const refused = (seq?: number) => (e: unknown) =>
      e instanceof EngineError && e.code === "precondition_failed" && (seq === undefined || e.message.endsWith(`seq ${seq}`));
    // The cursor's entry is not what the ledger holds now.
    await assert.rejects(run(ledger, { cursor: `1.${"ab".repeat(32)}` }), refused());
    const rewritten = new EditedLedger(ledger, { list: (es) => es.map((e) => (e.seq === 2 ? { ...e, detail: { i: 9 } } : e)) });
    await assert.rejects(run(rewritten, { fromSeq: 1 }), refused(2));
    await assert.rejects(run(rewritten, { cursor: encodeCursor(first!) }), refused(2));
    const dropped = new EditedLedger(ledger, { list: (es) => es.filter((e) => e.seq !== 2) });
    await assert.rejects(run(dropped, { fromSeq: 1 }), refused(3), "an entry is missing");
    await assert.rejects(run(dropped, { fromSeq: 3 }), refused(2), "the entry before fromSeq is missing");
    await assert.rejects(run(dropped, { cursor: encodeCursor({ seq: 2, hash: (await ledger.list(2))[0]!.hash }) }), refused());
    await assert.rejects(run(new EditedLedger(ledger, { list: () => [] }), { cursor: encodeCursor(head) }), refused());
    const wrongHead = new EditedLedger(ledger, { head: (h) => ({ ...h, hash: "ab".repeat(32) }) });
    await assert.rejects(run(wrongHead, { fromSeq: 1 }), refused());
    await assert.rejects(run(wrongHead, { fromSeq: 1, limit: 1 }), refused(), "even on a page short of the head");
  });

  it("refuses to sign a page whose first entry was swapped for another chain's (the page never reaches the head)", async () => {
    const ledger = await ledgerOf(3);
    const [foreign] = await (await ledgerOf(1, 10)).list();
    // A valid first entry of another chain: the page 1..1 verifies from genesis on its own.
    const swapped = new EditedLedger(ledger, { list: (es) => es.map((e) => (e.seq === 1 ? foreign! : e)) });
    const refused = (e: unknown) => e instanceof EngineError && e.code === "precondition_failed";
    await assert.rejects(run(swapped, { fromSeq: 1, limit: 1 }), refused);
    await assert.rejects(run(swapped, { fromSeq: 1, limit: 2 }), refused);
    // The same pages of the untouched ledger are signed.
    assert.equal(verifyLedgerExport(await run(ledger, { fromSeq: 1, limit: 1 }), keys).ok, true);
  });

  it("reads one page of exactly the run's entries, then walks to the head in bounded pages, and cuts an adapter that hands back more", async () => {
    const inner = await ledgerOf(50);
    const asked: Array<[number | undefined, number | undefined]> = [];
    const paged: AuditLedger = {
      append: (i) => inner.append(i),
      head: () => inner.head(),
      list: async (fromSeq, limit) => {
        asked.push([fromSeq, limit]);
        return inner.list(fromSeq);
      },
    };
    const check = verifyLedgerExport(await run(paged, { fromSeq: 11, limit: 5 }), keys);
    assert.equal(check.ok && check.entries.map((e) => e.seq).join(","), "11,12,13,14,15");
    assert.ok(asked.some(([from, limit]) => from === 11 && limit === 5), "the run's page, no more");
    assert.deepEqual(asked.at(-1), [16, 35], "then the rest of the chain to the head");
    assert.equal(asked.every(([, limit]) => limit !== undefined && limit <= EXPORT_WALK_PAGE), true, "in bounded pages, never the whole ledger at once");
  });

  it("walks on past a read that hands back fewer entries than asked, as a ledger may", async () => {
    const inner = await ledgerOf(201);
    // At most 100 per read: "at most limit" is all AuditLedger.list promises.
    const capped: AuditLedger = { append: (i) => inner.append(i), head: () => inner.head(), list: async (f, l) => inner.list(f, Math.min(l ?? 100, 100)) };
    const check = verifyLedgerExport(await run(capped, { fromSeq: 1, limit: 1 }), keys);
    assert.equal(check.ok && check.entries.length, 1);
  });

  it("cuts entries before the asked seq that an adapter hands back, and still reads the run", async () => {
    const inner = await ledgerOf(10);
    // A page read (more than one entry asked) starts two entries early, 4 at most: only entries from
    // the asked seq count. Single-entry reads (the head and start checks) are exact.
    const early: AuditLedger = {
      append: (i) => inner.append(i),
      head: () => inner.head(),
      list: async (f, l) => (l === 1 ? inner.list(f, l) : (await inner.list(Math.max(1, (f ?? 1) - 2))).slice(0, 4)),
    };
    const check = verifyLedgerExport(await run(early, { fromSeq: 3, limit: 5 }), keys);
    assert.equal(check.ok && check.entries.map((e) => e.seq).join(","), "3,4,5,6,7");
  });

  it("reads a run past a read that hands back fewer entries than asked, as a ledger may", async () => {
    const inner = await ledgerOf(201);
    const capped: AuditLedger = { append: (i) => inner.append(i), head: () => inner.head(), list: async (f, l) => inner.list(f, Math.min(l ?? 100, 100)) };
    for (const limit of [201, 150, undefined]) {
      const check = verifyLedgerExport(await run(capped, { fromSeq: 1, ...(limit === undefined ? {} : { limit }) }), keys);
      assert.equal(check.ok && check.entries.length, limit ?? 201, String(limit));
    }
  });

  it("walks to the head in pages of at most EXPORT_WALK_PAGE entries", async () => {
    const inner = await ledgerOf(EXPORT_WALK_PAGE + 5);
    const asked: Array<[number | undefined, number | undefined]> = [];
    const paged: AuditLedger = { append: (i) => inner.append(i), head: () => inner.head(), list: async (f, l) => (asked.push([f, l]), inner.list(f, l)) };
    assert.equal(verifyLedgerExport(await run(paged, { fromSeq: 1, limit: 2 }), keys).ok, true);
    assert.deepEqual(asked.slice(-2), [[3, EXPORT_WALK_PAGE], [EXPORT_WALK_PAGE + 3, 3]]);
  });

  it("refuses a page whose walk to the head is cut short or ends on another head", async () => {
    const ledger = await ledgerOf(3);
    const stored = await ledger.list();
    const refused = (e: unknown) => e instanceof EngineError && e.code === "precondition_failed" && /does not reach the head/.test(e.message);
    // The walk is the third read: the head check, the run's page, then the walk.
    const onWalk = (edit: (es: AuditEntry[]) => AuditEntry[]) => {
      let calls = 0;
      return new EditedLedger(ledger, { list: (es) => (++calls >= 3 ? edit(es) : es) });
    };
    await assert.rejects(run(onWalk((es) => es.filter((e) => e.seq !== 3)), { fromSeq: 1, limit: 1 }), refused, "a walk that stops before the head");
    // Seq 3 rewritten and chained on seq 2: the walk verifies, and ends on a hash that is not the head.
    const rewritten = chainEntry({ ...input("module.event", { i: 99 }) }, 3, stored[1]!.hash);
    await assert.rejects(run(onWalk((es) => es.map((e) => (e.seq === 3 ? rewritten : e))), { fromSeq: 1, limit: 1 }), refused, "a walk that ends on another head");
  });

  it("refuses a run read short of, or past a rewrite of, its end", async () => {
    const ledger = await ledgerOf(3);
    const refused = (e: unknown) => e instanceof EngineError && e.code === "precondition_failed" && e.message.endsWith("expected end");
    // The head check reads list(3); every read after it is the run's (a short read is asked again
    // for the rest) or the walk's. Edit all of them, so a dropped entry stays dropped.
    const onRunRead = (edit: (es: AuditEntry[]) => AuditEntry[]) => {
      let calls = 0;
      return new EditedLedger(ledger, { list: (es) => (++calls >= 2 ? edit(es) : es) });
    };
    await assert.rejects(run(onRunRead((es) => es.filter((e) => e.seq !== 3)), { fromSeq: 1 }), refused, "a verified prefix short of the head");
    await assert.rejects(run(onRunRead((es) => es.filter((e) => e.seq !== 2)), { fromSeq: 1, limit: 2 }), refused, "a limited run short of its end");
    const other = await (await ledgerOf(3, 10)).list();
    await assert.rejects(run(onRunRead(() => other), { fromSeq: 1 }), refused, "a rewrite that ends on another hash at the head's seq");
    // Valid limited and empty runs still pass.
    assert.equal(verifyLedgerExport(await run(onRunRead((es) => es), { fromSeq: 1, limit: 2 }), keys).ok, true);
    assert.equal(verifyLedgerExport(await run(ledger, { fromSeq: 4 }), keys).ok, true);
  });
});
