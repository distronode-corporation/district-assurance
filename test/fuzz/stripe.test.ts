// SRV-7: verifyStripeSignature and parseStripeEvent on hostile headers and bodies. A signature
// holds for exactly the bytes it was made over; any header or body change, or any garbage, is
// refused with a reason and never throws. An event body maps to a well-formed outcome or to null.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import fc from "fast-check";

import { EngineError } from "../../src/core/errors.ts";
import { parseStripeEvent, signStripePayload, verifyStripeSignature, type SignatureCheck } from "../../src/webhooks/stripe.ts";
import { flipByte, fuzz, int, jsonValue, mutate, nastyString, pick, printableString } from "./harness.ts";

const REASONS = new Set(["missing_header", "malformed_header", "no_secret", "timestamp_out_of_tolerance", "no_matching_signature"]);
const NOW = new Date("2026-11-18T12:00:00.000Z");
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);

/**
 * Header noise without commas: a comma inside a value starts a new element, so `k=,t=0` placed
 * last would set the timestamp to 0, a correct refusal the accepting property must not draw.
 */
const noise = (maxLength: number): fc.Arbitrary<string> => printableString(maxLength).map((s) => s.replaceAll(",", ""));

const secret: fc.Arbitrary<string> = nastyString(16).map((s) => `whsec_test_${s}_not_a_secret`);

function assertShape(result: SignatureCheck): void {
  if (result.ok) assert.ok(Number.isSafeInteger(result.timestamp));
  else assert.ok(REASONS.has(result.reason), result.reason);
}

const TYPES = [
  "identity.verification_session.verified",
  "identity.verification_session.requires_input",
  "identity.verification_session.canceled",
  "checkout.session.completed",
  "checkout.session.async_payment_succeeded",
  "checkout.session.async_payment_failed",
  "checkout.session.expired",
  "customer.created",
  "__proto__",
  "constructor",
  "toString",
  "charge.dispute.created",
  "refund.updated",
];

const event: fc.Arbitrary<Record<string, unknown>> = fc.record({
  id: printableString(8).map((s) => `evt_${s}`),
  type: fc.constantFrom(...TYPES),
  livemode: fc.constantFrom<unknown>(true, false, "true", 1, null),
  data: fc.record({
    object: fc.record({ id: printableString(8).map((s) => `cs_${s}`), payment_status: fc.constantFrom<unknown>("paid", "unpaid", "no_payment_required", "PAID", "", null, 1),
      status: fc.constantFrom<unknown>("failed", "succeeded", "maybe", null),
      amount: fc.constantFrom<unknown>(15000, -1, 1.5),
      currency: fc.constantFrom<unknown>("cad", "CAD"),
    }),
  }),
});

/** A body Stripe could send, or text that only looks like one. */
const payload: fc.Arbitrary<string> = fc.oneof({ weight: 7, arbitrary: event.map((e) => JSON.stringify(e)) }, { weight: 3, arbitrary: nastyString(64) });

interface OneByte {
  key: string;
  body: string;
  header: string;
  inBody: boolean;
  changed: string;
}

const oneByte: fc.Arbitrary<OneByte> = fc
  .record({ key: secret, body: payload, age: fc.integer({ min: 0, max: 300 }), inBody: fc.boolean() })
  .chain(({ key, body, age, inBody }) => {
    const header = signStripePayload(body, key, NOW_SECONDS - age);
    const changeBody = inBody && body.length > 0;
    return flipByte(Buffer.from(changeBody ? body : header, "utf8")).map((bytes) => ({ key, body, header, inBody: changeBody, changed: bytes.toString("utf8") }));
  });

/** A lone surrogate is signed as U+FFFD, so changing one into U+FFFD changes no signed byte. */
const SAME_BYTES: OneByte = (() => {
  const key = "whsec_test_fixture_not_a_secret";
  const body = "a\ud800b";
  return { key, body, header: signStripePayload(body, key, NOW_SECONDS), inBody: true, changed: "a\ufffdb" };
})();

const garbageHeader: fc.Arbitrary<string | null | undefined> = fc.oneof(
  fc.constantFrom(null, undefined, ""),
  nastyString(80),
  fc
    .tuple(
      fc.array(
        fc.oneof(
          fc.oneof(fc.constantFrom(String(NOW_SECONDS), "", "-1", "1e9", "0x10", "9".repeat(13), " 1", String(NOW_SECONDS) + "\u0000"), nastyString(12)).map((t) => `t=${t}`),
          fc.oneof(fc.constantFrom("", "0".repeat(64), "F".repeat(64)), fc.string({ unit: fc.constantFrom("0", "a", "f", "g", "é"), maxLength: 64 })).map((v) => `v1=${v}`),
          nastyString(10),
        ),
        { maxLength: 6 },
      ),
      fc.constantFrom(",", ", ", ";", ",,"),
    )
    .map(([parts, separator]) => parts.join(separator)),
);

describe("fuzz: verifyStripeSignature", () => {
  it("accepts a signed body with noise in the header, under any secret it was signed with", async () => {
    await fuzz(
      fc.property(fc.array(secret, { minLength: 1, maxLength: 3 }), fc.integer({ min: 0, max: 600 }), payload, fc.gen(), (secrets, tolerance, body, g) => {
        const timestamp = NOW_SECONDS + int(g, -tolerance, tolerance);
        const v1 = signStripePayload(body, pick(g, secrets), timestamp).split(",")[1]!;
        const parts = [`t=${timestamp}`, v1];
        for (let n = int(g, 0, 3); n > 0; n--) parts.push(pick(g, [`v1=${"0".repeat(64)}`, `v0=${g(noise, 8)}`, "noise", `k=${g(noise, 4)}`, ""]));
        const header = g(fc.shuffledSubarray, parts, { minLength: parts.length })
          .map((p) => (int(g, 0, 4) === 0 ? ` ${p} ` : p))
          .join(",");
        const offered = int(g, 0, 4) === 0 ? ["", ...secrets] : secrets;
        const result = verifyStripeSignature({ payload: body, header, secrets: offered, now: NOW, toleranceSeconds: tolerance });
        assert.equal(result.ok, true, JSON.stringify(result));
      }),
    );
  });

  it("refuses a body or header with any single byte changed", async () => {
    await fuzz(
      fc.property(oneByte, ({ key, body, header, inBody, changed }) => {
        // A broken UTF-8 sequence can decode to the same bytes: the signature covers bytes, and
        // those did not change (SAME_BYTES).
        if (Buffer.from(changed, "utf8").equals(Buffer.from(inBody ? body : header, "utf8"))) return;
        const result = verifyStripeSignature({ payload: inBody ? changed : body, header: inBody ? header : changed, secrets: [key], now: NOW });
        assertShape(result);
        assert.equal(result.ok, false);
      }),
      { examples: [[SAME_BYTES]] },
    );
  });

  it("refuses garbage headers, secrets and clocks with a reason, and never throws on a valid tolerance", async () => {
    await fuzz(
      fc.property(
        fc.record({
          body: nastyString(40),
          header: garbageHeader,
          secrets: fc.array(fc.oneof(fc.constant(""), secret), { maxLength: 3 }),
          now: fc.oneof(fc.constantFrom(NOW.getTime(), 0, -1, 8.64e15), fc.integer({ min: 0, max: 2 ** 40 }).map((s) => s * 1000)).map((ms) => new Date(ms)),
          toleranceSeconds: fc.constantFrom(undefined, 0, 1, 300, 86_400, -1, 1.5, 86_401, Number.NaN, Infinity),
        }),
        (input) => {
          const check = () => verifyStripeSignature({ payload: input.body, header: input.header, secrets: input.secrets, now: input.now, ...(input.toleranceSeconds === undefined ? {} : { toleranceSeconds: input.toleranceSeconds }) });
          // A tolerance that is not an integer from 0 to 86,400 is the host's mistake, refused
          // whatever the request: a NaN one would otherwise turn the window off.
          const tolerance = input.toleranceSeconds;
          if (tolerance !== undefined && !(Number.isInteger(tolerance) && tolerance >= 0 && tolerance <= 86_400)) {
            assert.throws(check, (e: unknown) => e instanceof EngineError && e.code === "invalid_input");
            return;
          }
          const result = check();
          assertShape(result);
          assert.equal(result.ok, false, "no garbage header carries a signature over this body");
        },
      ),
    );
  });
});

describe("fuzz: parseStripeEvent", () => {
  it("maps any body to a well-formed outcome or to null, and never throws", async () => {
    // A type of `__proto__` was once read from Object.prototype and became an identity outcome; the
    // fixed body below and the next test keep that case.
    const body = fc.oneof(
      event.map((e) => JSON.stringify(e)),
      fc.tuple(event, fc.gen()).map(([e, g]) => JSON.stringify(mutate(g, mutate(g, e))) ?? ""),
      jsonValue(3).map((v) => JSON.stringify(v)),
      nastyString(60),
      event.chain((e) => flipByte(Buffer.from(JSON.stringify(e))).map((bytes) => bytes.toString("utf8"))),
      fc.constant(`{"id":"evt_1","type":"__proto__","data":{"object":{"id":"cs_1","__proto__":{"payment_status":"paid"}}}}`),
    );
    await fuzz(
      fc.property(body, (body) => {
        const parsed = parseStripeEvent(body);
        if (parsed === null) return;
        const raw = JSON.parse(body) as { id: unknown; type: unknown; livemode: unknown; data: { object: { id: unknown; payment_status?: unknown } } };
        assert.equal(parsed.eventId, raw.id);
        assert.equal(parsed.livemode, raw.livemode === true);
        assert.equal(typeof raw.type, "string");
        const linkId = raw.data.object.id;
        assert.equal(typeof linkId, "string");
        switch (parsed.kind) {
          case "identity":
            assert.deepEqual(parsed.outcome, { sessionId: linkId, status: (raw.type as string).split(".").at(-1) });
            break;
          case "payment":
            assert.equal(parsed.outcome.linkId, linkId);
            if (parsed.outcome.kind === "completed") {
              assert.equal(raw.type, "checkout.session.completed");
              assert.ok(["paid", "unpaid", "no_payment_required"].includes(parsed.outcome.paymentStatus));
              assert.equal(Object.hasOwn(raw.data.object, "payment_status"), true);
            } else assert.equal(raw.type, `checkout.session.${{ async_succeeded: "async_payment_succeeded", async_failed: "async_payment_failed", expired: "expired" }[parsed.outcome.kind]}`);
            break;
          case "dispute":
            assert.ok((raw.type as string).startsWith("charge.dispute."), raw.type as string);
            break;
          case "refund":
            assert.ok(["refund.updated", "refund.failed", "charge.refund.updated"].includes(raw.type as string), raw.type as string);
            assert.equal(parsed.outcome.providerRef, linkId);
            break;
          default:
            assert.equal(parsed.type, raw.type);
            assert.ok(!TYPES.slice(0, 7).includes(parsed.type));
        }
      }),
    );
  });

  it("does not read event types from Object.prototype (found by fuzzing)", () => {
    for (const type of ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"]) {
      const body = JSON.stringify({ id: "evt_1", type, data: { object: { id: "vs_1" } } });
      assert.deepEqual(parseStripeEvent(body), { eventId: "evt_1", livemode: false, kind: "ignored", type });
    }
  });
});
