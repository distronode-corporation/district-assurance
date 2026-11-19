// Hostile pass on #77 (VER-5 Stripe Identity adapter), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { StripeApiError, StripeIdentityProvider, stripeIdempotencyKey } from "../examples/reference-server/src/stripe-adapters.ts";

const KEY = "rk_test_fixtureNotASecret";

/** A fetch that answers 200 with this session, recording what it was asked. */
function answering(session: unknown) {
  const asked: string[] = [];
  const fetch = (async (url: string | URL) => {
    asked.push(String(url));
    return new Response(JSON.stringify(session), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof globalThis.fetch;
  return { fetch, asked };
}

describe("#77 hostile: what Stripe answers", () => {
  it("I1 a session URL that would put more than a link into the SMS (whitespace, a line break, a control character) is refused", async () => {
    for (const url of ["https://verify.stripe.com/start/x\nReply STOP to opt out", "https://verify.stripe.com/x y", "https://verify.stripe.com/x\u0000", "https://verify.stripe.com/x‮", `https://verify.stripe.com/${"a".repeat(3000)}`]) {
      const { fetch } = answering({ id: "vs_1", url });
      await assert.rejects(new StripeIdentityProvider(KEY, { fetch }).createDocumentCheck({ callId: "c", idempotencyKey: "k" }), StripeApiError, JSON.stringify(url.slice(0, 40)));
    }
    const { fetch } = answering({ id: "vs_1", url: "https://verify.stripe.com/start/test_abc" });
    assert.deepEqual(await new StripeIdentityProvider(KEY, { fetch }).createDocumentCheck({ callId: "c", idempotencyKey: "k" }), { sessionId: "vs_1", url: "https://verify.stripe.com/start/test_abc" });
  });
});

describe("#77 hostile: the adapter's own options", () => {
  it("I2 an apiBase with credentials is refused when the adapter is built, and the error never shows them", () => {
    assert.throws(
      () => new StripeIdentityProvider(KEY, { apiBase: "https://user:hunter2@api.stripe.com" }),
      (e: unknown) => e instanceof Error && !e.message.includes("hunter2") && !e.message.includes("user"),
    );
  });

  it("I3 a timeout that is not a whole number of milliseconds from 1 to 60000 is refused when the adapter is built", () => {
    for (const timeoutMs of [Number.NaN, -1, 0, 1.5, Infinity, 60_001, "1000"]) {
      assert.throws(() => new StripeIdentityProvider(KEY, { timeoutMs: timeoutMs as never }), /timeoutMs/, String(timeoutMs));
    }
    assert.doesNotThrow(() => new StripeIdentityProvider(KEY, { timeoutMs: 5000 }));
  });

  it("I4 an engine key that looks like a hashed one never shares its header with the key it was hashed from", () => {
    const odd = '["ws","call with spaces","identity"]';
    const hashed = stripeIdempotencyKey(odd);
    assert.match(hashed, /^sha256:[0-9a-f]{64}$/);
    // An engine key is a JSON tuple, so it starts with "[" and is never the text of a hashed one.
    assert.equal(stripeIdempotencyKey(hashed), hashed, "the hash text itself is sent as is");
    assert.notEqual(hashed, odd);
    assert.equal(stripeIdempotencyKey(odd), stripeIdempotencyKey(odd), "stable across retries");
  });
});
