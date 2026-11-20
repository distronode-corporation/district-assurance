// A document or a key without a kid never matches: a missing kid is not equal to another missing kid.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { checkReceipt, signDocument, verifyDocument } from "../src/prove/receipt.ts";
import { generateTestSigner } from "../src/testing/index.ts";

describe("verifyDocument and checkReceipt need a kid on both sides (#75)", () => {
  it("is invalid when the document and the key both lack a kid, or both carry an empty one", async () => {
    const signer = generateTestSigner("k");
    const signed = await signDocument(signer, { issuedAt: "2026-01-01T00:00:00.000Z", text: "hello" });
    const { kid: _dropped, ...noKidJwk } = { ...signer.publicJwk(), kid: "k" } as Record<string, unknown>;
    const { kid: _gone, ...noKidDoc } = signed;
    assert.equal(verifyDocument({ ...signed }, [{ ...signer.publicJwk(), kid: "k" }]), true, "control: matching kids verify");
    assert.equal(verifyDocument(noKidDoc as never, [noKidJwk]), false, "no kid on either side");
    assert.equal(verifyDocument({ ...signed, kid: "" }, [{ ...noKidJwk, kid: "" }]), false, "an empty kid on both sides");
    assert.equal(checkReceipt(noKidDoc as never, [noKidJwk]).valid, false, "a receipt: no kid on either side");
    assert.equal(checkReceipt({ ...signed, kid: "" } as never, [{ ...noKidJwk, kid: "" }]).valid, false, "a receipt: an empty kid on both sides");
  });
});
