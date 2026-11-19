// deliverRecord reads its input once: a getter (or a host changing the object while the record is
// read) can never fetch one record and key or deliver it as another.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { deliverRecord, deliveryIdempotencyKey } from "../src/file/delivery.ts";
import { FakeRecordDelivery } from "../src/testing/index.ts";
import { setup, verifiedCall } from "./helpers.ts";

function flipping<T extends object>(base: T, key: string, first: unknown, then: unknown, n = 1): T {
  let reads = 0;
  return Object.defineProperty({ ...base }, key, {
    enumerable: true,
    get() {
      reads += 1;
      return reads <= n ? first : then;
    },
  });
}

describe("delivery: deliverRecord reads its input once", () => {
  it("keys the delivery to the record and workspace it fetched", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "Leak");
    const { recordId } = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    const destination = { destinationId: "crm", url: "https://hooks.example.test/records", secret: "whsec_delivery_test_not_a_secret" };
    const base = { destination, records: t.records, delivery: new FakeRecordDelivery(), ledger: t.ledger, clock: t.clock, sleep: async () => undefined };
    const swapped = flipping(base, "recordId", recordId, "rec_other");
    let wsReads = 0;
    Object.defineProperty(swapped, "workspaceId", { enumerable: true, get: () => (++wsReads === 1 ? "ws_test" : "ws_other") });
    const result = await deliverRecord(swapped as never);
    assert.equal(result.idempotencyKey, deliveryIdempotencyKey("ws_test", recordId, "crm"));
  });
});
