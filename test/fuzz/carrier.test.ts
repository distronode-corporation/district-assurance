// SRV-7: the carrier signature checks on any input. Until SRV-1 builds them, both must fail closed
// whatever they are given: a NotImplementedError naming SRV-1, never a pass and never another error.
// When SRV-1 lands, this file is where its checks get the same treatment as the Stripe one
// (a signed request verifies, any changed byte or header does not, garbage never throws).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { NotImplementedError } from "../../src/core/errors.ts";
import { verifyTelnyxSignature, verifyTwilioSignature, type CarrierWebhookInput } from "../../src/webhooks/carrier.ts";
import fc from "fast-check";

import { fuzz, nastyString, setOwn } from "./harness.ts";

const input: fc.Arbitrary<CarrierWebhookInput> = fc.record({
  url: fc.oneof(fc.constantFrom("https://example.test/webhooks/twilio", "https://example.test/webhooks/telnyx"), nastyString(40)),
  headers: fc
    .array(
      fc.tuple(
        fc.oneof(fc.constantFrom("x-twilio-signature", "telnyx-signature-ed25519", "telnyx-timestamp", "__proto__"), nastyString(8)),
        fc.oneof({ weight: 1, arbitrary: fc.constant(undefined) }, { weight: 9, arbitrary: nastyString(40) }),
      ),
      { maxLength: 4 },
    )
    .map((entries) => {
      const headers: Record<string, string | undefined> = {};
      for (const [key, value] of entries) setOwn(headers, key, value);
      return headers;
    }),
  body: nastyString(200),
  now: fc.oneof(fc.constantFrom(0, Date.UTC(2026, 10, 18), Number.NaN), fc.integer({ min: 0, max: 2 ** 42 })).map((ms) => new Date(ms)),
});

describe("fuzz: carrier signature checks (stand-in until SRV-1)", () => {
  for (const [name, verify] of [
    ["verifyTwilioSignature", verifyTwilioSignature],
    ["verifyTelnyxSignature", verifyTelnyxSignature],
  ] as const) {
    it(`${name} refuses every request, citing SRV-1`, async () => {
      await fuzz(
        fc.property(input, (request) => {
          assert.throws(
            () => verify(request),
            (e: unknown) => e instanceof NotImplementedError && e.issue === "SRV-1",
          );
        }),
      );
    });
  }
});
