// Record delivery (FIL-3): signed webhooks, retries with backoff, one idempotency key per record
// and destination, and ledger entries without the payload. On the fixed clock and the fakes, plus
// the reference server's sample receiver on 127.0.0.1.
import { strict as assert } from "node:assert";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";

import { createReferenceServer, type ReferenceServerOptions } from "../examples/reference-server/src/app.ts";
import type { RecordDelivery } from "../src/core/adapters.ts";
import * as root from "../src/index.ts";
import {
  DEFAULT_DELIVERY_RETRY,
  DELIVERY_SIGNATURE_HEADER,
  deliverRecord,
  deliveryDelay,
  deliveryIdempotencyKey,
  isRetryableStatus,
  signDelivery,
  timerSleep,
  type DeliverRecordInput,
  type DeliveryDestination,
  type RecordDeliveryBody,
} from "../src/file/delivery.ts";
import { verifyChain } from "../src/prove/ledger.ts";
import { FakeRecordDelivery, type TestEngine } from "../src/testing/index.ts";
import { verifyStripeSignature } from "../src/webhooks/stripe.ts";
import { rejects, setup, verifiedCall } from "./helpers.ts";

const SECRET = "whsec_delivery_test_not_a_secret";
const destination = { destinationId: "crm", url: "https://hooks.example.test/records", secret: SECRET };

/** A confirmed record from a real call on the test engine. */
async function confirmedRecord(t: TestEngine): Promise<string> {
  const callId = await verifiedCall(t);
  await t.engine.startIntake(callId, "repair");
  await t.engine.setIntakeField(callId, "issue", "Leaking tap in the kitchen");
  return (await t.engine.confirmIntake(callId, { confirmedBy: "voice" })).recordId;
}

/** Inputs for `deliverRecord` on the test engine's adapters; `sleep` moves the fixed clock and notes each wait. */
function inputs(t: TestEngine, recordId: string, delivery: RecordDelivery, waits: number[] = []): DeliverRecordInput {
  return {
    workspaceId: "ws_test",
    recordId,
    destination,
    records: t.records,
    delivery,
    ledger: t.ledger,
    clock: t.clock,
    sleep: async (ms) => {
      waits.push(ms);
      t.clock.advance(ms);
    },
  };
}

async function deliveryEntries(t: TestEngine) {
  return (await t.ledger.list()).filter((e) => e.event === "delivery.attempted");
}

describe("deliverRecord", () => {
  it("posts the record once, signed in the Stripe scheme, and records the attempt without the payload", async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    const fake = new FakeRecordDelivery();
    const result = await deliverRecord(inputs(t, recordId, fake));
    const key = deliveryIdempotencyKey("ws_test", recordId, "crm");
    assert.deepEqual(result, { delivered: true, attempts: 1, status: 200, idempotencyKey: key });

    assert.equal(fake.posts.length, 1);
    const post = fake.posts[0]!;
    assert.equal(post.url, destination.url);
    assert.equal(post.headers["content-type"], "application/json");
    assert.equal(post.headers["idempotency-key"], key);
    const header = post.headers[DELIVERY_SIGNATURE_HEADER];
    const t0 = Math.floor(t.clock.now().getTime() / 1000);
    assert.equal(header, signDelivery(post.body, SECRET, t0));
    assert.deepEqual(verifyStripeSignature({ payload: post.body, header, secrets: [SECRET], now: t.clock.now() }), { ok: true, timestamp: t0 });

    const body = JSON.parse(post.body) as RecordDeliveryBody;
    assert.deepEqual(body, { v: 1, type: "record.confirmed", idempotencyKey: key, destinationId: "crm", record: (await t.records.getIntakeRecord("ws_test", recordId))! });

    const entries = await deliveryEntries(t);
    assert.equal(entries.length, 1);
    assert.equal(entries[0]!.callId, body.record.callId);
    assert.equal(entries[0]!.actor, "system");
    assert.equal(entries[0]!.at, t.clock.now().toISOString());
    assert.deepEqual(entries[0]!.detail, { recordId, destination: "crm", attempt: 1, outcome: "delivered", status: 200 });
    const text = JSON.stringify(entries);
    for (const leak of ["Leaking tap", SECRET, "hooks.example.test", header!]) assert.equal(text.includes(leak), false, leak);
    assert.equal(verifyChain(await t.ledger.list()).ok, true);
  });

  it("retries no answer, 408, 429 and 5xx with doubling waits, re-signing each attempt over the same body", async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    const fake = new FakeRecordDelivery(["no_answer", 503, 429, 408, 204]);
    const waits: number[] = [];
    const start = Math.floor(t.clock.now().getTime() / 1000);
    const result = await deliverRecord(inputs(t, recordId, fake, waits));
    assert.deepEqual(result, { delivered: true, attempts: 5, status: 204, idempotencyKey: deliveryIdempotencyKey("ws_test", recordId, "crm") });
    assert.deepEqual(waits, [1000, 2000, 4000, 8000]);
    assert.equal(new Set(fake.posts.map((p) => p.body)).size, 1, "every attempt carries the same bytes");
    assert.equal(new Set(fake.posts.map((p) => p.headers["idempotency-key"])).size, 1);
    const stamps = [0, 1, 3, 7, 15].map((s) => start + s);
    assert.deepEqual(
      fake.posts.map((p) => p.headers[DELIVERY_SIGNATURE_HEADER]),
      stamps.map((s) => signDelivery(fake.posts[0]!.body, SECRET, s)),
    );
    assert.deepEqual(
      (await deliveryEntries(t)).map((e) => [e.detail.attempt, e.detail.outcome, e.detail.status]),
      [
        [1, "retry", null],
        [2, "retry", 503],
        [3, "retry", 429],
        [4, "retry", 408],
        [5, "delivered", 204],
      ],
    );
  });

  it("gives up after maxAttempts, and waits no longer than maxDelayMs", async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    const fake = new FakeRecordDelivery([500, 500, 500, 500]);
    const waits: number[] = [];
    const result = await deliverRecord({ ...inputs(t, recordId, fake, waits), retry: { maxAttempts: 4, baseDelayMs: 500, maxDelayMs: 1500 } });
    assert.deepEqual([result.delivered, result.attempts, result.status], [false, 4, 500]);
    assert.deepEqual(waits, [500, 1000, 1500]);
    assert.deepEqual((await deliveryEntries(t)).map((e) => e.detail.outcome), ["retry", "retry", "retry", "failed"]);
  });

  it("fails at once on an answer that is not worth another try, and on no answer with one attempt", async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    for (const status of [400, 401, 404, 302, 101]) {
      const result = await deliverRecord(inputs(t, recordId, new FakeRecordDelivery([status])));
      assert.deepEqual([result.delivered, result.attempts, result.status], [false, 1, status]);
    }
    const once = await deliverRecord({ ...inputs(t, recordId, new FakeRecordDelivery(["no_answer"])), retry: { maxAttempts: 1 } });
    assert.deepEqual([once.delivered, once.attempts, once.status], [false, 1, null]);
    assert.deepEqual((await deliveryEntries(t)).map((e) => e.detail.outcome), ["failed", "failed", "failed", "failed", "failed", "failed"]);
  });

  it("keeps one idempotency key per record and destination, whoever delivers and how often", async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    const a = await deliverRecord(inputs(t, recordId, new FakeRecordDelivery()));
    const b = await deliverRecord(inputs(t, recordId, new FakeRecordDelivery()));
    const other = await deliverRecord({ ...inputs(t, recordId, new FakeRecordDelivery()), destination: { ...destination, destinationId: "erp" } });
    assert.equal(a.idempotencyKey, b.idempotencyKey);
    assert.notEqual(a.idempotencyKey, other.idempotencyKey);
    assert.notEqual(deliveryIdempotencyKey("ws_other", recordId, "crm"), a.idempotencyKey);
    assert.match(a.idempotencyKey, /^[0-9a-f]{64}$/);
  });

  it("refuses a bad destination, a bad retry setting or an unknown record before posting anything", async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    const fake = new FakeRecordDelivery();
    const base = inputs(t, recordId, fake);
    const bad: Array<[Partial<DeliverRecordInput>, RegExp]> = [
      [{ destination: { ...destination, destinationId: "CRM" } }, /destinationId/],
      [{ destination: { ...destination, secret: "short" } }, /at least 16/],
      [{ destination: { ...destination, url: "not a url" } }, /not a URL/],
      [{ destination: { ...destination, url: "https://user:pass@hooks.example.test/" } }, /credentials/],
      [{ destination: { ...destination, url: "https://user@hooks.example.test/" } }, /credentials/],
      [{ destination: { ...destination, url: "http://hooks.example.test/" } }, /https/],
      [{ destination: { ...destination, url: "ftp://127.0.0.1/" } }, /https/],
      [{ retry: { maxAttempts: 0 } }, /maxAttempts/],
      [{ retry: { maxAttempts: 11 } }, /maxAttempts/],
      [{ retry: { baseDelayMs: -1 } }, /baseDelayMs/],
      [{ retry: { baseDelayMs: 0.5 } }, /baseDelayMs/],
      [{ retry: { baseDelayMs: 5000, maxDelayMs: 4000 } }, /maxDelayMs/],
      [{ retry: { maxDelayMs: 3_600_001 } }, /maxDelayMs/],
      // From the host's configuration, so anything at all: never a TypeError, never a number as a secret.
      [{ destination: null as unknown as DeliveryDestination }, /destination must be/],
      [{ destination: { ...destination, secret: 1234567890123456 as unknown as string } }, /secret must be/],
      [{ destination: { ...destination, secret: Array.from({ length: 16 }, () => "x") as unknown as string } }, /secret must be/],
      [{ destination: { ...destination, url: 42 as unknown as string } }, /url must be/],
      [{ destination: { ...destination, destinationId: ["crm"] as unknown as string } }, /destinationId/],
      [{ recordId: "rec_404" }, /no record rec_404/],
      [{ workspaceId: "ws_other" }, /no record/],
    ];
    for (const [patch, message] of bad) {
      await assert.rejects(deliverRecord({ ...base, ...patch }), rejects("invalid_input", message), String(message));
    }
    assert.equal(fake.posts.length, 0);
    assert.equal((await deliveryEntries(t)).length, 0);
    for (const url of ["http://127.0.0.1:9/r", "http://localhost/r", "http://[::1]:9/r"]) {
      assert.equal((await deliverRecord({ ...base, destination: { ...destination, url } })).delivered, true, url);
    }
    await assert.rejects(deliverRecord({ ...base, destination: { ...destination, secret: "short" } }), (e: unknown) => !String(e).includes("short"));
  });

  it("passes a ledger failure through, after the post", async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    const fake = new FakeRecordDelivery();
    const ledger = { ...t.ledger, append: async () => Promise.reject(new Error("ledger down")), head: () => t.ledger.head(), list: () => t.ledger.list() };
    await assert.rejects(deliverRecord({ ...inputs(t, recordId, fake), ledger }), /ledger down/);
    assert.equal(fake.posts.length, 1);
  });

  it("waits on a real timer by default", async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    const { sleep: _unused, ...rest } = inputs(t, recordId, new FakeRecordDelivery([503]));
    const result = await deliverRecord({ ...rest, retry: { baseDelayMs: 1 } });
    assert.deepEqual([result.delivered, result.attempts], [true, 2]);
    await timerSleep(0);
  });
});

describe("delivery helpers", () => {
  it("back off by doubling, capped, from the defaults", () => {
    assert.deepEqual(DEFAULT_DELIVERY_RETRY, { maxAttempts: 5, baseDelayMs: 1000, maxDelayMs: 60_000 });
    assert.deepEqual([1, 2, 3, 6, 7, 10].map((n) => deliveryDelay(DEFAULT_DELIVERY_RETRY, n)), [1000, 2000, 4000, 32_000, 60_000, 60_000]);
  });

  it("retry only a timeout, a rate limit and server errors", () => {
    assert.deepEqual([408, 429, 500, 503, 599].map(isRetryableStatus), [true, true, true, true, true]);
    assert.deepEqual([200, 301, 400, 401, 404, 409, 422].map(isRetryableStatus), [false, false, false, false, false, false, false]);
  });

  it("are exported from the root, and the planned stub is gone", () => {
    for (const name of ["deliverRecord", "deliveryIdempotencyKey", "signDelivery", "DELIVERY_SIGNATURE_HEADER"]) assert.ok(name in root, name);
    assert.ok(root.ENGINE_EVENTS.includes("delivery.attempted"));
  });
});

describe("the reference server's sample receiver", () => {
  /** A RecordDelivery over fetch, as a host would write one. */
  const fetchDelivery: RecordDelivery = {
    async post(input) {
      const res = await fetch(input.url, { method: "POST", headers: input.headers, body: input.body });
      await res.arrayBuffer();
      return { status: res.status };
    },
  };

  async function serve(t: TestEngine, records?: ReferenceServerOptions["records"]) {
    const server = createReferenceServer({ engine: t.engine, clock: t.clock, stripeSecrets: { identity: [], payments: [] }, ...(records === undefined ? {} : { records }) });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/webhooks/records`;
    return { url, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
  }

  it("verifies the signature, applies each record once, and answers a duplicate with 200", async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    const received: RecordDeliveryBody[] = [];
    const { url, close } = await serve(t, { secrets: ["whsec_old_not_a_secret", SECRET], onRecord: (d) => {
        received.push(d);
      },
    });
    try {
      const to = { ...destination, url };
      const first = await deliverRecord({ ...inputs(t, recordId, fetchDelivery), destination: to });
      assert.deepEqual([first.delivered, first.status], [true, 200]);
      const again = await deliverRecord({ ...inputs(t, recordId, fetchDelivery), destination: to });
      assert.deepEqual([again.delivered, again.status], [true, 200]);
      assert.equal(received.length, 1, "the second delivery is a duplicate");
      assert.equal(received[0]!.record.recordId, recordId);

      const wrong = await deliverRecord({ ...inputs(t, recordId, fetchDelivery), destination: { ...to, destinationId: "erp", secret: "whsec_wrong_not_a_secret" } });
      assert.deepEqual([wrong.delivered, wrong.attempts, wrong.status], [false, 1, 400], "a bad signature is final, not retried");

      const body = JSON.stringify({ v: 1, type: "record.confirmed", idempotencyKey: "k" });
      const res = await fetch(url, { method: "POST", body, headers: { [DELIVERY_SIGNATURE_HEADER]: signDelivery(body, SECRET, Math.floor(t.clock.now().getTime() / 1000)) } });
      assert.deepEqual([res.status, await res.json()], [400, { error: "malformed_delivery" }]);
      const unsigned = await fetch(url, { method: "POST", body });
      assert.deepEqual(await unsigned.json(), { error: "signature", reason: "missing_header" });
      assert.equal((await fetch(url)).status, 405);
    } finally {
      await close();
    }
  });

  it("refuses everything without secrets, and accepts without a handler", async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    const none = await serve(t);
    try {
      const result = await deliverRecord({ ...inputs(t, recordId, fetchDelivery), destination: { ...destination, url: none.url } });
      assert.deepEqual([result.delivered, result.status], [false, 400]);
    } finally {
      await none.close();
    }
    const quiet = await serve(t, { secrets: [SECRET] });
    try {
      assert.equal((await deliverRecord({ ...inputs(t, recordId, fetchDelivery), destination: { ...destination, url: quiet.url } })).delivered, true);
    } finally {
      await quiet.close();
    }
  });

  it("answers 500 when the handler throws or rejects, so the retry applies the record", async () => {
    for (const fail of [
      () => {
        throw new Error("sync failure");
      },
      () => Promise.reject(new Error("async failure")),
    ]) {
      const t = setup();
      const recordId = await confirmedRecord(t);
      const applied: string[] = [];
      let failures = 1;
      const onRecord = (d: RecordDeliveryBody): void | Promise<void> => {
        if (failures-- > 0) return fail();
        applied.push(d.record.recordId);
      };
      const { url, close } = await serve(t, { secrets: [SECRET], onRecord });
      try {
        const result = await deliverRecord({ ...inputs(t, recordId, fetchDelivery), destination: { ...destination, url } });
        assert.deepEqual([result.delivered, result.attempts, result.status], [true, 2, 200]);
        assert.deepEqual(applied, [recordId], "the retry is applied, not taken for a duplicate");
        const entries = await deliveryEntries(t);
        assert.deepEqual(entries.map((e) => e.detail.status), [500, 200]);
      } finally {
        await close();
      }
    }
  });

  it("applies a delivery once when a duplicate arrives while the first is still running", { timeout: 10_000 }, async () => {
    const t = setup();
    const recordId = await confirmedRecord(t);
    const applied: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let started!: () => void;
    const running = new Promise<void>((resolve) => (started = resolve));
    const duplicates: string[] = [];
    const { url, close } = await serve(t, {
      secrets: [SECRET],
      onRecord: async (d) => {
        started();
        await gate;
        applied.push(d.record.recordId);
      },
      // The first delivery is held in its handler until the duplicate reaches the pending wait:
      // only then is it released, so the duplicate can only have taken the pending path.
      onDuplicate: (_key, state) => {
        duplicates.push(state);
        if (state === "pending") release();
      },
    });
    try {
      const to = { ...destination, url };
      const first = deliverRecord({ ...inputs(t, recordId, fetchDelivery), destination: to });
      await running;
      const second = deliverRecord({ ...inputs(t, recordId, fetchDelivery), destination: to });
      const [a, b] = await Promise.all([first, second]);
      assert.deepEqual([a.status, b.status], [200, 200]);
      assert.deepEqual(applied, [recordId]);
      assert.deepEqual(duplicates, ["pending"], "the duplicate waited on the delivery in flight");
      // After it succeeded, a third delivery is a plain duplicate.
      await deliverRecord({ ...inputs(t, recordId, fetchDelivery), destination: to });
      assert.deepEqual(duplicates, ["pending", "received"]);
      assert.deepEqual(applied, [recordId]);
    } finally {
      await close();
    }
  });

  it("refuses bodies that are not deliveries", async () => {
    const t = setup();
    const { url, close } = await serve(t, { secrets: [SECRET] });
    const now = Math.floor(t.clock.now().getTime() / 1000);
    try {
      for (const body of [
        "not json",
        "null",
        "1",
        JSON.stringify({ v: 2, type: "record.confirmed", idempotencyKey: "k", destinationId: "crm", record: { recordId: "r" } }),
        JSON.stringify({ v: 1, type: "other", idempotencyKey: "k", destinationId: "crm", record: { recordId: "r" } }),
        JSON.stringify({ v: 1, type: "record.confirmed", idempotencyKey: 1, destinationId: "crm", record: { recordId: "r" } }),
        JSON.stringify({ v: 1, type: "record.confirmed", idempotencyKey: "k", record: { recordId: "r" } }),
        JSON.stringify({ v: 1, type: "record.confirmed", idempotencyKey: "k", destinationId: 1, record: { recordId: "r" } }),
        JSON.stringify({ v: 1, type: "record.confirmed", idempotencyKey: "k", destinationId: "crm", record: null }),
        JSON.stringify({ v: 1, type: "record.confirmed", idempotencyKey: "k", destinationId: "crm", record: { recordId: 1 } }),
      ]) {
        const res = await fetch(url, { method: "POST", body, headers: { [DELIVERY_SIGNATURE_HEADER]: signDelivery(body, SECRET, now) } });
        assert.deepEqual([res.status, await res.json()], [400, { error: "malformed_delivery" }], body);
      }
    } finally {
      await close();
    }
  });
});
