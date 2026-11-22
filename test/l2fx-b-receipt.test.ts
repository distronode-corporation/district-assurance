// Receipts: a signature that is not a base64url string is never valid, and a single signer's
// published key names its kid, so the receipts it signs verify against it.
import { strict as assert } from "node:assert";
import type { JsonWebKey } from "node:crypto";
import { describe, it } from "node:test";

import type { ReceiptSigner } from "../src/core/adapters.ts";
import { RECEIPT_KEYS_CACHE_CONTROL, checkReceipt, receiptKeySet, receiptKeysDocument, signReceipt, verifyReceipt } from "../src/prove/receipt.ts";
import { generateTestSigner } from "../src/testing/fakes.ts";
import { createTestEngine } from "../src/testing/index.ts";

async function signed(signer: ReceiptSigner) {
  const t = createTestEngine({ adapters: { signer } });
  return (await t.engine.endCall((await t.engine.startCall()).callId))!;
}

describe("receipts: the signature is a string", () => {
  it("refuses the signature's bytes as an array, which Buffer.from would read as the same bytes", async () => {
    const k1 = generateTestSigner("k1");
    const receipt = await signed(k1);
    assert.equal(verifyReceipt(receipt, [k1.publicJwk()]), true);
    const bytes = Array.from(Buffer.from(receipt.signature, "base64url"));
    assert.deepEqual(checkReceipt({ ...receipt, signature: bytes } as never, [k1.publicJwk()]), { valid: false });
    assert.equal(verifyReceipt({ ...receipt, signature: Buffer.from(bytes) } as never, [k1.publicJwk()]), false);
  });
});

describe("receipts: receiptKeySet for a single signer (T17)", () => {
  it("publishes the signer's kid when its public JWK has none, so its receipts verify", async () => {
    const k1 = generateTestSigner("k1");
    const { kid: _kid, ...bare } = k1.publicJwk() as JsonWebKey & { kid?: string };
    const signer: ReceiptSigner = { ...k1, publicJwk: () => ({ ...bare }) };
    const receipt = await signReceipt(signer, (await signed(k1)).body);
    const keys = receiptKeySet(signer);
    assert.equal(keys.length, 1);
    assert.equal((keys[0] as { kid?: string }).kid, "k1");
    assert.equal(verifyReceipt(receipt, keys), true);
  });

  it("never publishes a private part", () => {
    const k1 = generateTestSigner("k1");
    const leaky: ReceiptSigner = { ...k1, publicJwk: () => ({ ...k1.publicJwk(), d: "secret" }) };
    assert.throws(() => receiptKeySet(leaky), /private part/);
  });
});

describe("receipts: receiptKeysDocument", () => {
  it("publishes every signer's keys once each, in order, and none without a signer", () => {
    const k1 = generateTestSigner("k1");
    const k2 = generateTestSigner("k2");
    const doc = receiptKeysDocument([k1, undefined, k2, k1]);
    assert.deepEqual(
      doc.keys.map((k) => (k as { kid?: string }).kid),
      ["k1", "k2"],
    );
    assert.deepEqual(receiptKeysDocument([]), { keys: [] });
    assert.equal(RECEIPT_KEYS_CACHE_CONTROL, "public, max-age=300");
  });

  it("⛔ refuses two different keys under one kid, and a private part", () => {
    const a = generateTestSigner("same");
    const b = generateTestSigner("same");
    assert.throws(() => receiptKeysDocument([a, b]), /two different keys are named same/);
    const leaky: ReceiptSigner = { ...a, publicJwk: () => ({ ...a.publicJwk(), d: "secret" }) };
    assert.throws(() => receiptKeysDocument([leaky]), /private part/);
    // ⛔ A key ring's set is not checked by receiptKeySet: the document refuses a private part in it too.
    const ring = { ...a, keySet: () => [{ ...a.publicJwk(), kid: "same", d: "secret" }] } as unknown as ReceiptSigner;
    assert.throws(() => receiptKeysDocument([ring]), /the key same has a private part/);
  });
});
