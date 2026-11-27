// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile pass on #72 (async KnowledgeHmac, derToP1363), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { describe, it } from "node:test";

import { derToP1363 } from "../src/prove/receipt.ts";
import { knowledgeHmac } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup } from "./helpers.ts";

describe("#72 hostile: the knowledge key", () => {
  it("K1 a knowledge key that is neither bytes nor a function is refused when the engine is built, not at the first call", () => {
    for (const knowledgeKey of [1234567890123456, { byteLength: 32 }, Array.from({ length: 32 }, () => "a"), true, null, undefined]) {
      assert.throws(() => createTestEngine({ knowledgeKey: knowledgeKey as never }), rejects("invalid_input", /knowledgeKey/), String(knowledgeKey));
    }
    // What is accepted still works: bytes as a string or a Uint8Array, and a function.
    for (const knowledgeKey of [TEST_KNOWLEDGE_KEY, new Uint8Array(16), async () => "a".repeat(64)]) assert.doesNotThrow(() => createTestEngine({ knowledgeKey }));
  });

  it("K2 an HMAC function's answer is refused unless it is 64 lower-case hex, and the answer is never quoted", async () => {
    for (const answer of ["A".repeat(64), "a".repeat(63), "a".repeat(65), ` ${"a".repeat(63)}`, `${"a".repeat(64)}\n`, 42, null, ["a".repeat(64)], { toString: () => "a".repeat(64) }]) {
      const hmac = knowledgeHmac(async () => answer as never);
      await assert.rejects(hmac("pin:x:1234"), (e: unknown) => e instanceof Error && /64 lower-case hex/.test(e.message) && !e.message.includes("aaaa") && !e.message.includes("1234"), String(answer));
    }
  });

  it("K3 a key store that fails passes its error to the host, and refuses before any subject is named", async () => {
    const t = setup({ knowledgeKey: async () => {
      throw new Error("kms throttled");
    } } as never);
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.beginVerification(callId, { accountNumber: ACCOUNT }), /kms throttled/);
    const ok = setup();
    const { callId: c2 } = await ok.engine.startCall();
    await ok.engine.beginVerification(c2, { accountNumber: ACCOUNT });
    assert.deepEqual((await ok.engine.submitKeypad(c2, { dob: DOB })).matched, true);
  });
});

describe("#72 hostile: derToP1363", () => {
  it("K4 matches node's own P1363 form for real signatures, and never throws anything but a TypeError on junk", () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    for (let i = 0; i < 300; i++) {
      const data = randomBytes(32);
      // ECDSA is randomized, so the conversion is checked by verifying it in the P1363 encoding.
      const der = sign("sha256", data, { key: privateKey, dsaEncoding: "der" });
      const p1363 = derToP1363(der);
      assert.equal(p1363.length, 64);
      assert.equal(verify("sha256", data, { key: createPublicKey(privateKey), dsaEncoding: "ieee-p1363" }, p1363), true);
    }
    for (let i = 0; i < 2000; i++) {
      const junk = randomBytes(Math.floor(Math.random() * 80));
      if (Math.random() < 0.5 && junk.length > 2) {
        junk[0] = 0x30;
        junk[1] = junk.length - 2;
      }
      try {
        const out = derToP1363(junk);
        assert.equal(out.length, 64);
      } catch (e) {
        assert.ok(e instanceof TypeError, String(e));
      }
    }
  });

  it("K5 refuses non-minimal and long-form encodings", () => {
    const int = (bytes: number[]) => [0x02, bytes.length, ...bytes];
    const seq = (...parts: number[][]) => new Uint8Array([0x30, parts.flat().length, ...parts.flat()]);
    const r = Array.from({ length: 32 }, (_, i) => (i === 0 ? 0x7f : i));
    assert.equal(derToP1363(seq(int(r), int(r))).length, 64);
    for (const bad of [
      seq(int([0x00, ...r]), int(r)), // a leading zero before a byte without the sign bit
      seq(int([0x80, ...r.slice(1)]), int(r)), // negative
      seq(int([0x00]), int(r)), // zero
      seq(int([0x01, ...r]), int(r)), // 33 bytes of magnitude
      new Uint8Array([0x30, 0x81, 0x44, ...int(r), ...int(r)]), // long-form length
      seq(int(r)), // one integer only
      new Uint8Array([...seq(int(r), int(r)), 0x00]), // a trailing byte
    ]) {
      assert.throws(() => derToP1363(bad), TypeError);
    }
  });
});

describe("#72 hostile: signReceipt", () => {
  it("K6 refuses a 64-byte signature that does not verify against the signer's own key, so no receipt is issued that cannot verify", async () => {
    const { signReceipt, verifyReceipt } = await import("../src/prove/receipt.ts");
    const { generateTestSigner } = await import("../src/testing/index.ts");
    const good = generateTestSigner("k1");
    const other = generateTestSigner("k1");
    const body = { v: 1 } as never;
    const signed = await signReceipt(good, body);
    assert.equal(verifyReceipt(signed, [{ ...good.publicJwk(), kid: "k1" }]), true);
    const junk = { ...good, keyId: "k1", algorithm: "ES256" as const, sign: async () => randomBytes(64), publicJwk: () => good.publicJwk() };
    await assert.rejects(signReceipt(junk, body), rejects("invalid_input", /does not verify/));
    const wrongKey = { keyId: "k1", algorithm: "ES256" as const, sign: (p: Uint8Array) => other.sign(p), publicJwk: () => good.publicJwk() };
    await assert.rejects(signReceipt(wrongKey, body), rejects("invalid_input", /does not verify/));
  });
});
