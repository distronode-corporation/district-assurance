// Hostile pass on #77 (VER-5 Stripe Identity adapter), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { StripeApiError, StripeIdentityProvider, stripeIdempotencyKey, stripeMetadataCallId } from "../examples/reference-server/src/stripe-adapters.ts";

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

  it("I6 options are read once when the adapter is built: changing them later, or a getter, never moves the key off https", async () => {
    const { fetch, asked } = answering({ id: "vs_1", url: "https://verify.stripe.com/start/test_abc" });
    const options: { apiBase?: string; fetch?: typeof globalThis.fetch } = { apiBase: "https://api.stripe.com", fetch };
    const provider = new StripeIdentityProvider(KEY, options);
    options.apiBase = "http://stripe-proxy.example";
    options.fetch = (async () => assert.fail("a fetch swapped in after the adapter was built")) as typeof globalThis.fetch;
    await provider.createDocumentCheck({ callId: "c", idempotencyKey: "k" });
    let reads = 0;
    const shifty = { fetch, get apiBase() { return reads++ === 0 ? "https://api.stripe.com" : "http://stripe-proxy.example"; } };
    await new StripeIdentityProvider(KEY, shifty).createDocumentCheck({ callId: "c", idempotencyKey: "k" });
    assert.deepEqual(asked, ["https://api.stripe.com/v1/identity/verification_sessions", "https://api.stripe.com/v1/identity/verification_sessions"]);
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

describe("#77 hostile: a call id longer than Stripe's metadata limit", () => {
  /** A fetch that answers like Stripe: 400 for a metadata value over 500 characters, else a session. */
  function stripeLike() {
    const sent: string[] = [];
    const fetch = (async (_url: string | URL, init?: RequestInit) => {
      const value = new URLSearchParams(String(init?.body)).get("metadata[call_id]") ?? "";
      sent.push(value);
      if ([...value].length > 500) {
        return new Response(JSON.stringify({ error: { type: "invalid_request_error", code: "parameter_invalid_string_length", param: "metadata[call_id]" } }), { status: 400, headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({ id: "vs_1", url: "https://verify.stripe.com/start/test_abc" }), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof globalThis.fetch;
    return { fetch, sent };
  }

  it("I5 a call id over 500 characters goes as sha256: and its hex SHA-256, the same every time; one of 500 goes as is", async () => {
    const { createHash } = await import("node:crypto");
    const { fetch, sent } = stripeLike();
    const provider = new StripeIdentityProvider(KEY, { fetch });
    for (const callId of ["c".repeat(501), "c".repeat(5000), "é".repeat(400), "😀".repeat(300)]) {
      const hashed = `sha256:${createHash("sha256").update(callId, "utf8").digest("hex")}`;
      assert.equal(stripeMetadataCallId(callId), hashed);
      assert.deepEqual(await provider.createDocumentCheck({ callId, idempotencyKey: "k" }), { sessionId: "vs_1", url: "https://verify.stripe.com/start/test_abc" }, `${callId.length} long`);
      await provider.createDocumentCheck({ callId, idempotencyKey: "k" });
      assert.deepEqual(sent.slice(-2), [hashed, hashed], "the same value on a retry");
    }
    assert.notEqual(stripeMetadataCallId("c".repeat(501)), stripeMetadataCallId("c".repeat(502)));
    for (const callId of ["call_1", "c".repeat(500), "é".repeat(250)]) {
      assert.equal(stripeMetadataCallId(callId), callId);
      await provider.createDocumentCheck({ callId, idempotencyKey: "k" });
      assert.equal(sent.at(-1), callId);
    }
  });
});
