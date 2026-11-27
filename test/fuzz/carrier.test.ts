// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// SRV-7: the carrier signature checks (SRV-1) on any input, as the Stripe check is fuzzed. A
// request signed under the carrier's scheme verifies; any changed byte of what is signed does not;
// garbage is refused with a reason and never throws.
import { strict as assert } from "node:assert";
import { createHmac, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { describe, it } from "node:test";

import fc from "fast-check";

import { verifyTelnyxSignature, verifyTwilioSignature, type TelnyxSignatureInput, type TwilioSignatureInput } from "../../src/webhooks/carrier.ts";
import { flipByte, fuzz, int, nastyString, pick, printableString } from "./harness.ts";

const NOW = new Date("2026-11-18T12:00:00.000Z");
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);

const TWILIO_REASONS = new Set(["missing_header", "no_secret", "no_matching_signature", "body_hash_mismatch"]);
const TELNYX_REASONS = new Set(["missing_header", "malformed_header", "no_secret", "timestamp_out_of_tolerance", "no_matching_signature"]);

/** Form parameters as Twilio signs them, written here from its documentation, not from the code under test. */
function twilioSigned(url: string, body: string): string {
  const pairs = [...new URLSearchParams(body)].sort(([ak, av], [bk, bv]) => (ak === bk ? (av < bv ? -1 : av > bv ? 1 : 0) : ak < bk ? -1 : 1));
  const distinct = pairs.filter(([k, v], i) => i === 0 || k !== pairs[i - 1]![0] || v !== pairs[i - 1]![1]);
  return url + distinct.map(([k, v]) => k + v).join("");
}

const twilioSign = (token: string, url: string, body: string): string => createHmac("sha1", token).update(twilioSigned(url, body)).digest("base64");

const token: fc.Arbitrary<string> = nastyString(16).map((s) => `tok_${s}_not_a_secret`);
const twilioUrl: fc.Arbitrary<string> = fc
  .tuple(fc.constantFrom("https://example.test/webhooks/twilio", "https://example.test:8443/webhooks/twilio", "http://example.test/webhooks/twilio"), printableString(12))
  .map(([base, query]) => (query === "" ? base : `${base}?q=${encodeURIComponent(query)}`));
/** A form body with names and values that need escaping, and now and then a name sent twice. */
const formBody: fc.Arbitrary<string> = fc
  .array(fc.tuple(fc.oneof(fc.constantFrom("CallSid", "From", "To", "Digits", "__proto__"), nastyString(6)), nastyString(12)), { maxLength: 6 })
  .map((pairs) => new URLSearchParams(pairs).toString());

/** A garbage header, body or token list: what a request from anyone may hold. */
const garbage: fc.Arbitrary<string | null | undefined> = fc.oneof(fc.constantFrom(null, undefined, ""), nastyString(40), printableString(28));

describe("fuzz: verifyTwilioSignature", () => {
  it("accepts a form body signed under any of the tokens it was given", async () => {
    await fuzz(
      fc.property(fc.array(token, { minLength: 1, maxLength: 3 }), twilioUrl, formBody, fc.gen(), (tokens, url, body, g) => {
        const header = twilioSign(pick(g, tokens), url, body);
        const input: TwilioSignatureInput = { url, payload: int(g, 0, 1) === 0 ? body : Buffer.from(body, "utf8"), header, authTokens: tokens };
        assert.deepEqual(verifyTwilioSignature(input), { ok: true });
      }),
    );
  });

  it("refuses a body or header with any single byte changed, unless the signed parameters are the same", async () => {
    await fuzz(
      fc.property(token, twilioUrl, formBody, fc.boolean(), fc.gen(), (key, url, body, inBody, g) => {
        const header = twilioSign(key, url, body);
        const original = Buffer.from(inBody ? body : header, "utf8");
        if (original.length === 0) return;
        const changed = g(flipByte, original).toString("utf8");
        const payload = inBody ? changed : body;
        // A flipped `+` and a space, or two bytes that decode to the same U+FFFD, sign the same
        // parameters: nothing that is signed changed.
        if (inBody && twilioSigned(url, payload) === twilioSigned(url, body)) return;
        if (!inBody && changed === header) return;
        const result = verifyTwilioSignature({ url, payload, header: inBody ? header : changed, authTokens: [key] });
        assert.equal(result.ok, false);
        if (!result.ok) assert.ok(TWILIO_REASONS.has(result.reason), result.reason);
      }),
    );
  });

  it("refuses garbage with a reason and never throws", async () => {
    await fuzz(
      fc.property(fc.oneof(twilioUrl, nastyString(60)), fc.oneof(formBody, nastyString(80)), garbage, fc.array(fc.oneof(token, fc.constantFrom("")), { maxLength: 3 }), (url, payload, header, authTokens) => {
        const result = verifyTwilioSignature({ url, payload, header, authTokens });
        // Garbage signs nothing: a pass would be a forgery.
        assert.equal(result.ok, false);
        if (!result.ok) assert.ok(TWILIO_REASONS.has(result.reason), result.reason);
      }),
    );
  });
});

/** A few Ed25519 key pairs, made once: key generation is the slow part. */
const KEYS: readonly { privateKey: KeyObject; publicKey: string }[] = Array.from({ length: 3 }, () => {
  const pair = generateKeyPairSync("ed25519");
  const jwk = pair.publicKey.export({ format: "jwk" });
  return { privateKey: pair.privateKey, publicKey: Buffer.from(jwk.x!, "base64url").toString("base64") };
});

const telnyxSign = (key: KeyObject, stamp: string, body: string): string => sign(null, Buffer.from(`${stamp}|${body}`), key).toString("base64");

const telnyxBody: fc.Arbitrary<string> = fc.oneof(
  { weight: 3, arbitrary: fc.record({ event_type: fc.constantFrom("call.initiated", "call.hangup", "__proto__"), id: printableString(12) }).map((data) => JSON.stringify({ data })) },
  { weight: 1, arbitrary: nastyString(80) },
);

describe("fuzz: verifyTelnyxSignature", () => {
  it("accepts a body signed under any of the keys it was given, inside the tolerance", async () => {
    await fuzz(
      fc.property(fc.integer({ min: 0, max: 600 }), telnyxBody, fc.gen(), (tolerance, body, g) => {
        const signer = pick(g, KEYS);
        const stamp = String(NOW_SECONDS + int(g, -tolerance, tolerance));
        const input: TelnyxSignatureInput = {
          payload: int(g, 0, 1) === 0 ? body : Buffer.from(body, "utf8"),
          signatureHeader: telnyxSign(signer.privateKey, stamp, body),
          timestampHeader: stamp,
          publicKeys: g(fc.shuffledSubarray, [...KEYS.map((k) => k.publicKey), "", "not a key"], { minLength: 0 }).concat(signer.publicKey),
          now: NOW,
          toleranceSeconds: tolerance,
        };
        assert.deepEqual(verifyTelnyxSignature(input), { ok: true, timestamp: Number(stamp) });
      }),
    );
  });

  it("refuses a body, signature or timestamp with any single byte changed", async () => {
    await fuzz(
      fc.property(telnyxBody, fc.constantFrom("body", "signature", "timestamp"), fc.gen(), (body, part, g) => {
        const signer = pick(g, KEYS);
        const stamp = String(NOW_SECONDS);
        const signature = telnyxSign(signer.privateKey, stamp, body);
        const original = { body, signature, timestamp: stamp }[part];
        if (original === "") return;
        const changed = g(flipByte, Buffer.from(original, "utf8")).toString("utf8");
        // The same signed bytes: a broken UTF-8 sequence that decodes to the same U+FFFD. A
        // signature changed only in the unused bits of its last character is refused too (one
        // spelling per signature).
        if (part === "body" && Buffer.from(changed, "utf8").equals(Buffer.from(body, "utf8"))) return;
        const result = verifyTelnyxSignature({
          payload: part === "body" ? changed : body,
          signatureHeader: part === "signature" ? changed : signature,
          timestampHeader: part === "timestamp" ? changed : stamp,
          publicKeys: [signer.publicKey],
          now: NOW,
          toleranceSeconds: 86_400,
        });
        assert.equal(result.ok, false, `${part}: ${JSON.stringify(changed)}`);
        if (!result.ok) assert.ok(TELNYX_REASONS.has(result.reason), result.reason);
      }),
    );
  });

  it("refuses garbage with a reason and never throws", async () => {
    await fuzz(
      fc.property(
        nastyString(80),
        garbage,
        fc.oneof(garbage, fc.integer({ min: -1, max: 2 ** 40 }).map(String), fc.constantFrom(String(NOW_SECONDS), "1e9", " 1", "0x10", "9".repeat(13))),
        fc.array(fc.oneof(fc.constantFrom(...KEYS.map((k) => k.publicKey), "", Buffer.alloc(32).toString("base64")), nastyString(44)), { maxLength: 3 }),
        fc.oneof(fc.constantFrom(0, NOW.getTime(), Number.NaN), fc.integer({ min: 0, max: 2 ** 42 })).map((ms) => new Date(ms)),
        (payload, signatureHeader, timestampHeader, publicKeys, now) => {
          const result = verifyTelnyxSignature({ payload, signatureHeader, timestampHeader, publicKeys, now });
          // Garbage signs nothing: a pass would be a forgery.
          assert.equal(result.ok, false);
          if (!result.ok) assert.ok(TELNYX_REASONS.has(result.reason), result.reason);
        },
      ),
    );
  });
});
