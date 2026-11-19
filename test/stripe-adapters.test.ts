// The Stripe Identity adapter (VER-5), against a local fake of Stripe's API on 127.0.0.1 that
// replays the fixtures in test/fixtures/stripe-identity, and the reference server's trial call end
// to end: a check created through the adapter, then a signed `identity.verification_session.verified`
// event applied by the identity webhook. No request leaves the machine.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { createServe } from "../examples/reference-server/src/main.ts";
import {
  STRIPE_API_VERSION,
  StripeApiError,
  StripeCheckoutLinks,
  StripeIdentityProvider,
  stripeIdempotencyKey,
} from "../examples/reference-server/src/stripe-adapters.ts";
import { NotImplementedError, signStripePayload } from "../src/index.ts";
import { FixedClock, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject } from "../src/testing/index.ts";

const KEY = "rk_test_fixtureNotASecret";
const WEBHOOK_SECRET = "whsec_test_not_a_secret";
const fixture = (name: string) => readFileSync(new URL(`fixtures/stripe-identity/${name}.json`, import.meta.url), "utf8");
const CREATED = JSON.parse(fixture("verification-session-created")) as Record<string, unknown>;

interface Seen {
  method: string;
  url: string;
  headers: IncomingMessage["headers"];
  form: URLSearchParams;
}

/** A fake of Stripe's VerificationSession endpoint: one session per idempotency key, like Stripe. */
class FakeStripe {
  readonly seen: Seen[] = [];
  readonly #byKey = new Map<string, string>();
  /** Set to answer the next request with this status and raw body instead. */
  next: { status: number; body: string } | null = null;
  /** Set to never answer. */
  hang = false;
  base = "";
  #server: Server | null = null;

  async start(): Promise<void> {
    this.#server = createServer((req, res) => this.#handle(req, res));
    await new Promise<void>((resolve) => this.#server!.listen(0, "127.0.0.1", resolve));
    this.base = `http://127.0.0.1:${(this.#server.address() as AddressInfo).port}`;
  }

  /** The session id this fake handed out for an idempotency key. */
  sessionFor(key: string): string {
    return (JSON.parse(this.#byKey.get(key)!) as { id: string }).id;
  }

  async stop(): Promise<void> {
    this.#server!.closeAllConnections();
    await new Promise<void>((resolve) => this.#server!.close(() => resolve()));
  }

  #handle(req: IncomingMessage, res: ServerResponse): void {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      this.seen.push({ method: req.method!, url: req.url!, headers: req.headers, form });
      if (this.hang) return;
      if (this.next !== null) {
        const { status, body } = this.next;
        this.next = null;
        res.writeHead(status, { "content-type": "application/json" });
        res.end(body);
        return;
      }
      const key = String(req.headers["idempotency-key"]);
      let body = this.#byKey.get(key);
      if (body === undefined) {
        const n = this.#byKey.size + 1;
        const id = `vs_1Qfixture${String(n).padStart(17, "0")}`;
        body = JSON.stringify({ ...CREATED, id, url: `https://verify.stripe.com/start/test_fixture_link_${n}`, metadata: { call_id: form.get("metadata[call_id]") } });
        this.#byKey.set(key, body);
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
    });
  }
}

/** Runs `fn` with every console method watched; answers what was written. */
async function captureOutput(fn: () => Promise<unknown>): Promise<string[]> {
  const written: string[] = [];
  const methods = ["log", "info", "warn", "error", "debug", "trace"] as const;
  const saved = methods.map((m) => console[m]);
  for (const m of methods) console[m] = (...args: unknown[]) => void written.push(args.map(String).join(" "));
  try {
    await fn().catch(() => undefined);
  } finally {
    methods.forEach((m, i) => (console[m] = saved[i]!));
  }
  return written;
}

describe("StripeIdentityProvider", () => {
  const stripe = new FakeStripe();
  before(() => stripe.start());
  after(() => stripe.stop());
  const provider = () => new StripeIdentityProvider(KEY, { apiBase: stripe.base });

  it("creates a document VerificationSession with a matching selfie and the call id in metadata", async () => {
    const check = await provider().createDocumentCheck({ callId: "call_1", idempotencyKey: "key-shape" });
    const req = stripe.seen.at(-1)!;
    assert.equal(req.method, "POST");
    assert.equal(req.url, "/v1/identity/verification_sessions");
    assert.deepEqual([...req.form.entries()], [
      ["type", "document"],
      ["options[document][require_matching_selfie]", "true"],
      ["metadata[call_id]", "call_1"],
    ]);
    assert.match(check.sessionId, /^vs_1Qfixture/);
    assert.match(check.url, /^https:\/\/verify\.stripe\.com\/start\/test_fixture_link_\d+$/);
  });

  it("sends the restricted key, the engine's idempotency key, a pinned API version and a form body", async () => {
    await provider().createDocumentCheck({ callId: "call_1", idempotencyKey: '["ws_test","call_1","identity"]' });
    const { headers } = stripe.seen.at(-1)!;
    assert.equal(headers.authorization, `Bearer ${KEY}`);
    assert.equal(headers["idempotency-key"], '["ws_test","call_1","identity"]');
    assert.equal(headers["stripe-version"], STRIPE_API_VERSION);
    assert.equal(headers["content-type"], "application/x-www-form-urlencoded");
  });

  it("returns the same session for the same idempotency key, and a new one for another", async () => {
    const a = await provider().createDocumentCheck({ callId: "call_2", idempotencyKey: "key-same" });
    const b = await provider().createDocumentCheck({ callId: "call_2", idempotencyKey: "key-same" });
    const c = await provider().createDocumentCheck({ callId: "call_3", idempotencyKey: "key-other" });
    assert.deepEqual(a, b);
    assert.notEqual(c.sessionId, a.sessionId);
  });

  it("is the engine's identity adapter: a retry after a failed text resumes with the same key and session", async () => {
    const t = createTestEngine({ adapters: { identity: provider() } });
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "12345678", phoneOnFile: "+15555550100", knowledge: { dob: "19850214" } }));
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: "12345678" });
    await t.engine.submitKeypad(callId, { dob: "19850214" });
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    const before = stripe.seen.length;
    await assert.rejects(t.engine.startPhotoId(callId), /carrier down/);
    t.messages.sendText = send;
    assert.deepEqual(await t.engine.startPhotoId(callId), { sent: true });
    const calls = stripe.seen.slice(before);
    assert.equal(calls.length, 2);
    assert.deepEqual(calls.map((c) => c.headers["idempotency-key"]), [JSON.stringify(["ws_test", callId, "identity"]), JSON.stringify(["ws_test", callId, "identity"])]);
    assert.equal(calls[0]!.form.get("metadata[call_id]"), callId);
    assert.equal(t.messages.sent.length, 1, "one link, texted once");
    assert.match(t.messages.sent[0]!.body, /https:\/\/verify\.stripe\.com\/start\/test_fixture_link_\d+$/);
  });

  it("hashes an idempotency key Stripe would not accept as is, the same way every time", () => {
    for (const key of ["has space", "non-ascii-é", "k".repeat(256)]) {
      const header = stripeIdempotencyKey(key);
      assert.match(header, /^sha256:[0-9a-f]{64}$/);
      assert.equal(stripeIdempotencyKey(key), header);
    }
    assert.notEqual(stripeIdempotencyKey("has space"), stripeIdempotencyKey("has  space"));
    assert.equal(stripeIdempotencyKey("k".repeat(255)), "k".repeat(255));
  });

  it("sends a hashed key when the engine's key has characters a header cannot carry", async () => {
    await provider().createDocumentCheck({ callId: "call_é", idempotencyKey: '["ws é","call_é","identity"]' });
    assert.equal(stripe.seen.at(-1)!.headers["idempotency-key"], stripeIdempotencyKey('["ws é","call_é","identity"]'));
    assert.equal(stripe.seen.at(-1)!.form.get("metadata[call_id]"), "call_é");
  });

  it("calls api.stripe.com by default", async () => {
    let seen = "";
    const fetchSpy = (async (url: string | URL | Request) => {
      seen = String(url);
      return new Response(JSON.stringify(CREATED), { status: 200 });
    }) as typeof fetch;
    await new StripeIdentityProvider(KEY, { fetch: fetchSpy }).createDocumentCheck({ callId: "call_1", idempotencyKey: "k" });
    assert.equal(seen, "https://api.stripe.com/v1/identity/verification_sessions");
  });

  it("refuses an apiBase that would send the key in cleartext, before any request", () => {
    let fetched = 0;
    const fetchSpy = (async () => {
      fetched++;
      return new Response("{}");
    }) as typeof fetch;
    for (const apiBase of ["http://stripe-proxy.example", "http://10.0.0.1:8080", "ftp://api.stripe.com", "not a url", "http://localhost.example.com"]) {
      assert.throws(() => new StripeIdentityProvider(KEY, { apiBase, fetch: fetchSpy }), {
        message: "StripeIdentityProvider needs an https: apiBase (http: only on a loopback host)",
      });
    }
    assert.equal(fetched, 0);
    for (const apiBase of ["https://stripe-proxy.example", "http://127.0.0.1:12111", "http://localhost:12111", "http://[::1]:12111"]) {
      new StripeIdentityProvider(KEY, { apiBase });
    }
  });

  it("takes restricted keys only", () => {
    for (const key of ["", "sk_test_abc", "sk_live_abc", "pk_test_abc", "rk_prod_abc", "rk_test_", "rk_test_a b"]) {
      assert.throws(() => new StripeIdentityProvider(key), { message: "StripeIdentityProvider needs a restricted key (rk_test_... or rk_live_...)" }, "the message never echoes the key");
    }
    new StripeIdentityProvider("rk_live_abc");
  });

  it("throws StripeApiError with the status, type and code only, never Stripe's message", async () => {
    stripe.next = { status: 403, body: fixture("error-permission") };
    await assert.rejects(provider().createDocumentCheck({ callId: "c", idempotencyKey: "e1" }), (e: unknown) => {
      assert.ok(e instanceof StripeApiError);
      assert.deepEqual([e.status, e.type, e.code, e.message], [403, "invalid_request_error", null, "Stripe answered 403 (invalid_request_error)"]);
      return true;
    });
    stripe.next = { status: 400, body: JSON.stringify({ error: { type: "invalid_request_error", code: "parameter_invalid_empty", param: "metadata[call_id]" } }) };
    await assert.rejects(provider().createDocumentCheck({ callId: "c", idempotencyKey: "e2" }), { message: "Stripe answered 400 (invalid_request_error/parameter_invalid_empty)" });
    stripe.next = { status: 400, body: JSON.stringify({ error: { type: "Sneaky https://verify.stripe.com/x", code: 7 } }) };
    await assert.rejects(provider().createDocumentCheck({ callId: "c", idempotencyKey: "e3" }), { message: "Stripe answered 400 (unknown)" });
    stripe.next = { status: 502, body: "<html>bad gateway</html>" };
    await assert.rejects(provider().createDocumentCheck({ callId: "c", idempotencyKey: "e4" }), { status: 502, type: "unknown" });
  });

  it("refuses an answer that is not a session with an https link, without echoing it", async () => {
    const bodies = [
      "not json",
      "[1]",
      JSON.stringify({ ...CREATED, url: null }),
      JSON.stringify({ ...CREATED, url: "http://verify.stripe.com/start/test_x" }),
      JSON.stringify({ ...CREATED, id: "cs_1Qwrong" }),
      JSON.stringify({ ...CREATED, id: 42 }),
    ];
    for (const body of bodies) {
      stripe.next = { status: 200, body };
      await assert.rejects(provider().createDocumentCheck({ callId: "c", idempotencyKey: "m" }), (e: unknown) => {
        assert.ok(e instanceof StripeApiError);
        assert.equal(e.message, "Stripe answered 200 (malformed_response)");
        return true;
      });
    }
  });

  it("gives up after its timeout", async () => {
    stripe.hang = true;
    try {
      await assert.rejects(new StripeIdentityProvider(KEY, { apiBase: stripe.base, timeoutMs: 50 }).createDocumentCheck({ callId: "c", idempotencyKey: "t" }), { name: "TimeoutError" });
    } finally {
      stripe.hang = false;
    }
  });

  it("never logs the link, on success or failure", async () => {
    let url = "";
    const written = await captureOutput(async () => {
      url = (await provider().createDocumentCheck({ callId: "call_log", idempotencyKey: "log-1" })).url;
      stripe.next = { status: 200, body: JSON.stringify({ ...CREATED, id: "bad", url }) };
      await provider().createDocumentCheck({ callId: "call_log", idempotencyKey: "log-2" });
    });
    assert.match(url, /^https:/);
    assert.deepEqual(written, []);
  });
});

describe("the reference server with Stripe Identity (npm run serve)", () => {
  const stripe = new FakeStripe();
  before(() => stripe.start());
  after(() => stripe.stop());

  const listen = async (server: Server) => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return {
      base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
  };

  it("creates the trial call's check in Stripe and applies the signed verified event end to end", async () => {
    const printed: string[] = [];
    const env = { STRIPE_IDENTITY_KEY: KEY, STRIPE_IDENTITY_WEBHOOK_SECRET: WEBHOOK_SECRET };
    const clock = new FixedClock();
    const serve = createServe({ env, print: (line) => printed.push(line), stripe: { apiBase: stripe.base }, clock });
    const { base, close } = await listen(serve.server);
    try {
      const { callId, sessionId } = await serve.startTrialCall!();
      assert.equal(stripe.seen.at(-1)!.form.get("metadata[call_id]"), callId);
      const phone = printed.filter((line) => line.startsWith("stand-in phone"));
      assert.equal(phone.length, 1);
      assert.match(phone[0]!, /^stand-in phone \+15555550100 received: Your one-time identity check link: https:\/\/verify\.stripe\.com\/start\//);
      assert.equal(printed.filter((line) => line.includes("https://")).length, 1, "the link appears once, on the stand-in phone only");
      assert.ok(printed.includes(`${callId} identity.link_sent {}`));

      const event = JSON.parse(fixture("event-verified")) as { data: { object: Record<string, unknown> } };
      event.data.object = { ...event.data.object, id: sessionId, metadata: { call_id: callId } };
      const payload = JSON.stringify(event);
      const post = () =>
        fetch(`${base}/webhooks/stripe/identity`, {
          method: "POST",
          body: payload,
          headers: { "stripe-signature": signStripePayload(payload, WEBHOOK_SECRET, Math.floor(clock.now().getTime() / 1000)) },
        }).then((r) => r.json());
      assert.deepEqual(await post(), { received: true, applied: true });
      assert.deepEqual(await post(), { received: true, duplicate: true });
      assert.equal(printed.at(-1), `${callId} verification.factor {"kind":"photo_id","passed":true,"status":"verified"}`);
      const state = await serve.t.engine.state(callId);
      assert.deepEqual(state.factors.map((f) => [f.kind, f.passed]), [["keypad_knowledge", true], ["photo_id", true]]);
      assert.equal((await serve.t.engine.finishVerification(callId)).level, 3);
    } finally {
      await close();
    }
  });

  it("pairs each overlapping trial call with its own session", async () => {
    const serve = createServe({ env: { STRIPE_IDENTITY_KEY: KEY }, print: () => {}, stripe: { apiBase: stripe.base } });
    const [a, b] = await Promise.all([serve.startTrialCall!(), serve.startTrialCall!()]);
    assert.notEqual(a.callId, b.callId);
    assert.notEqual(a.sessionId, b.sessionId);
    for (const { callId, sessionId } of [a, b]) {
      const created = stripe.seen.find((s) => s.form.get("metadata[call_id]") === callId);
      assert.ok(created);
      assert.equal(stripe.sessionFor(created.headers["idempotency-key"] as string), sessionId);
    }
  });

  it("runs on fakes without a key, and refuses a key that is not a restricted test-mode key", () => {
    const serve = createServe({ env: {} });
    assert.equal(serve.startTrialCall, null);
    for (const key of ["rk_live_abc", "sk_test_abc"]) {
      assert.throws(() => createServe({ env: { STRIPE_IDENTITY_KEY: key } }), /restricted test-mode key/);
    }
  });
});

describe("StripeCheckoutLinks", () => {
  it("is planned, not built", async () => {
    await assert.rejects(
      new StripeCheckoutLinks("rk_test").createLink({ callId: "c", paymentId: "p", amountMinor: 1, currency: "cad", description: "d", idempotencyKey: "k" }),
      (e: unknown) => e instanceof NotImplementedError && e.issue === "PAY-1",
    );
  });
});
