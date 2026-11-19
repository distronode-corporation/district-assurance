// checkReceipt reads the receipt once: the body whose issue time is checked against a key's
// retirement is the body whose signature is verified.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { checkReceipt } from "../src/prove/receipt.ts";
import { generateTestSigner } from "../src/testing/fakes.ts";
import { FixedClock, createTestEngine } from "../src/testing/index.ts";

const RETIRED_AT = "2026-06-01T00:00:00.000Z";

describe("receipts: checkReceipt reads the receipt once", () => {
  it("never passes a retirement check on one body and verifies the signature of another", async () => {
    const k1 = generateTestSigner("k1");
    // k1 signs on 2026-07-01, a month after the key set says it retired.
    const late = createTestEngine({ clock: new FixedClock("2026-07-01T00:00:00.000Z"), adapters: { signer: k1 } });
    const signed = (await late.engine.endCall((await late.engine.startCall()).callId))!;
    const keys = [{ ...k1.publicJwk(), retiredAt: RETIRED_AT }];
    assert.deepEqual(checkReceipt(signed, keys), { valid: false }, "signed after retirement");
    let reads = 0;
    const early = { ...signed.body, issuedAt: "2026-01-01T00:00:00.000Z" };
    const forged = {
      alg: signed.alg,
      kid: signed.kid,
      signature: signed.signature,
      get body() {
        reads += 1;
        return reads <= 2 ? early : signed.body;
      },
    };
    assert.deepEqual(checkReceipt(forged as never, keys), { valid: false });
  });

  it("checks the issue time in the bytes it verifies: a body whose issuedAt getter changes is never valid", async () => {
    const k1 = generateTestSigner("k1");
    const late = createTestEngine({ clock: new FixedClock("2026-07-01T00:00:00.000Z"), adapters: { signer: k1 } });
    const signed = (await late.engine.endCall((await late.engine.startCall()).callId))!;
    const keys = [{ ...k1.publicJwk(), retiredAt: RETIRED_AT }];
    let reads = 0;
    const body = { ...signed.body } as Record<string, unknown>;
    Object.defineProperty(body, "issuedAt", { enumerable: true, get: () => (reads++ === 0 ? "2026-01-01T00:00:00.000Z" : signed.body.issuedAt) });
    assert.deepEqual(checkReceipt({ ...signed, body } as never, keys), { valid: false });
  });
});
