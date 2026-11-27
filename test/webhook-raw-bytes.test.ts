// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The Stripe webhooks and the record-delivery receiver check the signature over the bytes on the
// wire, before anything decodes or parses them: a body under a bad signature is refused without
// ever being read as text, and two different bodies that decode to one string never verify under
// one signature.
import { strict as assert } from "node:assert";
import { createHmac } from "node:crypto";
import type { AddressInfo } from "node:net";
import { describe, it, type TestContext } from "node:test";
import { TextDecoder } from "node:util";

import { createReferenceServer } from "../examples/reference-server/src/app.ts";
import { DELIVERY_SIGNATURE_HEADER } from "../src/file/delivery.ts";
import { createTestEngine } from "../src/testing/index.ts";
import { signStripePayload, verifyStripeSignature } from "../src/webhooks/stripe.ts";

const SECRET = "whsec_test_not_a_secret";
const MARKER = "poison-7f3a";

// Not UTF-8 (a lone 0xFF) and not JSON (unclosed): decoding it costs a replacement, parsing it throws.
const POISON = Buffer.concat([Buffer.from(`{"${MARKER}": "`), Buffer.from([0xff]), Buffer.from("[[[[[[[[")]);

/** Stripe's header over raw bytes: HMAC-SHA256 of `<t>.<bytes>`. */
function signBytes(bytes: Uint8Array, secret: string, t: number): string {
  return `t=${t},v1=${createHmac("sha256", secret).update(Buffer.concat([Buffer.from(`${t}.`), bytes])).digest("hex")}`;
}

/** The same JSON text, once with a real U+FFFD (EF BF BD) and once with a lone 0xFF in its place. */
function twins(json: string): [Buffer, Buffer] {
  const signed = Buffer.from(json, "utf8");
  const at = signed.indexOf(Buffer.from("\u{fffd}", "utf8"));
  const forged = Buffer.concat([signed.subarray(0, at), Buffer.from([0xff]), signed.subarray(at + 3)]);
  return [signed, forged];
}

interface Reads {
  decoded: number;
  parsed: number;
}

/**
 * Counts, while `run` runs, every UTF-8 decode (Buffer toString, TextDecoder) of bytes holding the
 * marker and every JSON.parse of text holding it.
 */
async function watchReads(run: () => Promise<unknown>): Promise<Reads> {
  const reads: Reads = { decoded: 0, parsed: 0 };
  const marker = Buffer.from(MARKER);
  const toString = Buffer.prototype.toString;
  const decode = TextDecoder.prototype.decode;
  const parse = JSON.parse;
  Buffer.prototype.toString = function (this: Buffer, ...args: unknown[]) {
    if (this.indexOf(marker) >= 0) reads.decoded += 1;
    return (toString as (...a: unknown[]) => string).apply(this, args);
  } as typeof toString;
  TextDecoder.prototype.decode = function (this: TextDecoder, ...args: Parameters<TextDecoder["decode"]>) {
    const [input] = args;
    const view = input === undefined || input === null ? new Uint8Array() : ArrayBuffer.isView(input) ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength) : new Uint8Array(input);
    if (Buffer.from(view).indexOf(marker) >= 0) reads.decoded += 1;
    return decode.apply(this, args);
  };
  JSON.parse = function (text: string, reviver?: (this: unknown, key: string, value: unknown) => unknown) {
    if (typeof text === "string" && text.includes(MARKER)) reads.parsed += 1;
    return parse(text, reviver);
  };
  try {
    await run();
  } finally {
    Buffer.prototype.toString = toString;
    TextDecoder.prototype.decode = decode;
    JSON.parse = parse;
  }
  return reads;
}

async function serve(ctx: TestContext) {
  const t = createTestEngine();
  const records: string[] = [];
  const server = createReferenceServer({
    engine: t.engine,
    stripeSecrets: { identity: [SECRET], payments: [SECRET], connect: [SECRET] },
    clock: t.clock,
    records: { secrets: [SECRET], onRecord: (d) => void records.push(d.record.recordId) },
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  ctx.after(
    () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  );
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const at = Math.floor(t.clock.now().getTime() / 1000);
  return {
    at,
    records,
    post: async (path: string, body: Uint8Array, headers: Record<string, string>): Promise<[number, unknown]> => {
      const res = await fetch(`${base}${path}`, { method: "POST", body, headers: { "content-type": "application/json", ...headers } });
      const text = await res.text();
      return [res.status, parseWithoutWatch(text)];
    },
  };
}

// The answer's own JSON never holds the marker, so reading it is not counted either way.
const parseWithoutWatch = (text: string): unknown => JSON.parse(text);

describe("the read watcher", () => {
  it("counts each decode and parse of the marked bytes, and nothing else", async () => {
    const reads = await watchReads(async () => {
      const text = POISON.toString("utf8");
      new TextDecoder().decode(POISON);
      new TextDecoder().decode(POISON.buffer.slice(POISON.byteOffset, POISON.byteOffset + POISON.length));
      Buffer.from("unmarked").toString("utf8");
      assert.throws(() => JSON.parse(text));
      JSON.parse('{"unmarked":1}');
    });
    assert.deepEqual(reads, { decoded: 3, parsed: 1 });
  });
});

describe("Stripe webhook: the signature is checked over the raw bytes first", () => {
  it("a bad signature is refused and the body is never decoded or parsed", async (ctx) => {
    const s = await serve(ctx);
    let answer: [number, unknown] | undefined;
    const reads = await watchReads(async () => {
      answer = await s.post("/webhooks/stripe/payments", POISON, { "stripe-signature": signBytes(Buffer.from("other"), SECRET, s.at) });
    });
    assert.deepEqual(answer, [400, { error: "signature", reason: "no_matching_signature" }]);
    assert.deepEqual(reads, { decoded: 0, parsed: 0 });
  });

  it("a body that decodes to the signed text, but whose bytes differ, is refused", async (ctx) => {
    const s = await serve(ctx);
    const [signed, forged] = twins('{"id":"evt_\u{fffd}","type":"ignored.event","data":{"object":{"id":"obj_1"}}}');
    assert.equal(signed.toString("utf8"), forged.toString("utf8"));
    const headers = { "stripe-signature": signBytes(signed, SECRET, s.at) };
    assert.deepEqual(await s.post("/webhooks/stripe/payments", forged, headers), [400, { error: "signature", reason: "no_matching_signature" }]);
    assert.deepEqual(await s.post("/webhooks/stripe/payments", signed, headers), [200, { received: true, applied: false, handled: false }]);
  });
});

describe("record-delivery webhook: the signature is checked over the raw bytes first", () => {
  it("a bad signature is refused and the body is never decoded or parsed", async (ctx) => {
    const s = await serve(ctx);
    let answer: [number, unknown] | undefined;
    const reads = await watchReads(async () => {
      answer = await s.post("/webhooks/records", POISON, { [DELIVERY_SIGNATURE_HEADER]: signBytes(Buffer.from("other"), SECRET, s.at) });
    });
    assert.deepEqual(answer, [400, { error: "signature", reason: "no_matching_signature" }]);
    assert.deepEqual(reads, { decoded: 0, parsed: 0 });
  });

  it("a body that decodes to the signed text, but whose bytes differ, is refused", async (ctx) => {
    const s = await serve(ctx);
    const [signed, forged] = twins('{"v":1,"type":"record.confirmed","idempotencyKey":"k1","destinationId":"d1","record":{"recordId":"rec_\u{fffd}"}}');
    const headers = { [DELIVERY_SIGNATURE_HEADER]: signBytes(signed, SECRET, s.at) };
    assert.deepEqual(await s.post("/webhooks/records", forged, headers), [400, { error: "signature", reason: "no_matching_signature" }]);
    assert.deepEqual(s.records, []);
    assert.deepEqual(await s.post("/webhooks/records", signed, headers), [200, { received: true, recordId: "rec_\u{fffd}" }]);
    assert.deepEqual(s.records, ["rec_\u{fffd}"]);
  });
});

describe("verifyStripeSignature over bytes", () => {
  const now = new Date("2026-01-01T00:00:00Z");
  const t = Math.floor(now.getTime() / 1000);
  const [signed, forged] = twins('{"name":"\u{fffd}"}');

  it("verifies the bytes it was signed over, and refuses other bytes that decode the same", () => {
    const header = signBytes(signed, SECRET, t);
    assert.deepEqual(verifyStripeSignature({ payload: signed, header, secrets: [SECRET], now }), { ok: true, timestamp: t });
    assert.deepEqual(verifyStripeSignature({ payload: forged, header, secrets: [SECRET], now }), { ok: false, reason: "no_matching_signature" });
    assert.deepEqual(verifyStripeSignature({ payload: forged, header: signBytes(forged, SECRET, t), secrets: [SECRET], now }), { ok: true, timestamp: t }, "signed as sent");
  });

  it("a string payload is its UTF-8 bytes, as before", () => {
    const header = signStripePayload('{"name":"\u{fffd}"}', SECRET, t);
    assert.deepEqual(verifyStripeSignature({ payload: signed, header, secrets: [SECRET], now }), { ok: true, timestamp: t });
    assert.deepEqual(verifyStripeSignature({ payload: '{"name":"\u{fffd}"}', header, secrets: [SECRET], now }), { ok: true, timestamp: t });
  });
});
