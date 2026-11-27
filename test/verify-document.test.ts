// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// verifyDocument (access grants and receipts share it) with a key or a body it cannot use: false, never a throw.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { verifyDocument } from "../src/prove/receipt.ts";
import { generateTestSigner } from "../src/testing/index.ts";

describe("verifyDocument with a key or a body it cannot use (#75 with #47)", () => {
  it("is false, never throwing, for a malformed key, a body canonical JSON refuses, or a short signature", () => {
    const signer = generateTestSigner("k");
    const signature = Buffer.alloc(64).toString("base64url");
    const bad = [{ kid: "k", kty: "EC", crv: "P-256", x: "not-a-point", y: "not-a-point" }];
    assert.equal(verifyDocument({ alg: "ES256", kid: "k", body: {}, signature } as never, bad), false, "a key node:crypto refuses");
    const good = [{ ...signer.publicJwk(), kid: "k" }];
    assert.equal(verifyDocument({ alg: "ES256", kid: "k", body: { text: "\uD800" }, signature } as never, good), false, "a lone surrogate canonical JSON refuses");
    assert.equal(verifyDocument({ alg: "ES256", kid: "k", body: {}, signature: "AAAA" } as never, good), false, "a signature that is not 64 bytes");
  });
});
