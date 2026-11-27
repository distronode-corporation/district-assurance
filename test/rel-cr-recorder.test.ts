// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// CodeRabbit's review of the 0.1.0 release diff (#149): the Stripe recorder kept the reference
// server's 500 or 503 answer to a webhook as the recorded delivery and still told `stripe listen`
// 200, so a run could write a fixture for an event that was never applied. A failed answer now
// fails the run, and `stripe listen` is told the server's own status.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { type Delivery, type PendingDelivery, forwardingFailed, receiverStatus, settledDelivery } from "./fixtures/stripe-real/deliveries.ts";

const delivery = (status: number, objectId = "cs_test_redacted0001", type = "checkout.session.completed", body: unknown = { received: true, applied: true }): Delivery => ({
  listener: "account",
  route: "payments",
  type,
  objectId,
  body: "{}",
  signatureVerified: true,
  answer: { status, body },
});

describe("the Stripe recorder keeps only applied deliveries (#149 review)", () => {
  it("answers `stripe listen` with the reference server's status when it is not 2xx, and 200 otherwise", () => {
    assert.equal(receiverStatus(200), 200);
    assert.equal(receiverStatus(204), 200);
    for (const status of [400, 500, 503]) assert.equal(receiverStatus(status), status);
  });

  it("returns the 2xx delivery of the object and type, and nothing while none has arrived", () => {
    assert.equal(settledDelivery([], "cs_test_redacted0001", "checkout.session.completed"), undefined);
    const ok = delivery(200);
    assert.equal(settledDelivery([delivery(200, "cs_test_redacted0002"), delivery(200, "cs_test_redacted0001", "checkout.session.expired"), ok], "cs_test_redacted0001", "checkout.session.completed"), ok);
  });

  it("fails loudly on a 2xx answer that did not apply the event, and ignores a later duplicate (#148 review)", () => {
    const unapplied = { received: true, applied: false, handled: false };
    assert.throws(() => settledDelivery([delivery(200, undefined, undefined, unapplied)], "cs_test_redacted0001", "checkout.session.completed"), /did not apply/);
    assert.throws(() => settledDelivery([delivery(200, undefined, undefined, { received: true })], "cs_test_redacted0001", "checkout.session.completed"), /did not apply/);
    const applied = delivery(200);
    assert.equal(settledDelivery([applied, delivery(200, undefined, undefined, { received: true, duplicate: true })], "cs_test_redacted0001", "checkout.session.completed"), applied);
  });

  it("picks the first delivery by arrival, waiting while its answer is pending, whichever answer finished first (#148 review)", () => {
    const first = { ...delivery(200), answer: null };
    const duplicate = delivery(200, undefined, undefined, { received: true, duplicate: true });
    const log: PendingDelivery[] = [first, duplicate];
    assert.equal(settledDelivery(log, "cs_test_redacted0001", "checkout.session.completed"), undefined, "the first to arrive has no answer yet");
    const answered = { ...first, answer: { status: 200, body: { received: true, applied: true } } };
    assert.equal(settledDelivery([answered, duplicate], "cs_test_redacted0001", "checkout.session.completed"), answered);
    assert.throws(() => settledDelivery([first, delivery(503)], "cs_test_redacted0001", "checkout.session.completed"), /answered 503/, "a failed answer still fails the run at once");
  });

  it("fails at once when forwarding a delivery to the reference server failed, never waiting on it (CodeRabbit CLI)", () => {
    const entry: PendingDelivery = { ...delivery(200), answer: null };
    forwardingFailed(entry);
    assert.deepEqual(entry.answer, { status: 502, body: { forwarded: false } });
    assert.throws(() => settledDelivery([entry, delivery(200)], "cs_test_redacted0001", "checkout.session.completed"), /answered 502/);
  });

  it("fails loudly on a 500, 503 or 400 answer for the object and type, never recording it", () => {
    for (const status of [400, 500, 503]) {
      assert.throws(() => settledDelivery([delivery(status)], "cs_test_redacted0001", "checkout.session.completed"), new RegExp(`answered ${status}`));
      assert.throws(() => settledDelivery([delivery(status), delivery(200)], "cs_test_redacted0001", "checkout.session.completed"), new RegExp(`answered ${status}`), "a failed answer fails the run even if a later one passed");
    }
  });
});
