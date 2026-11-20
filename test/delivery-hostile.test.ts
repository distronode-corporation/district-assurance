// Hostile pass on #81 (FIL-3 record delivery), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { RecordDelivery } from "../src/core/adapters.ts";
import { deliverRecord, type DeliverRecordInput } from "../src/file/delivery.ts";
import type { TestEngine } from "../src/testing/index.ts";
import { PHONE_ON_FILE, heard, setup, verifiedCall } from "./helpers.ts";

const destination = { destinationId: "crm", url: "https://hooks.example.test/records", secret: "whsec_delivery_test_not_a_secret" };

async function confirmedRecord(t: TestEngine): Promise<string> {
  const callId = await verifiedCall(t);
  await t.engine.startIntake(callId, "repair");
  await t.engine.setIntakeField(callId, "issue", "Leaking tap in the kitchen");
  return (await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) })).recordId;
}

function inputs(t: TestEngine, recordId: string, delivery: RecordDelivery): DeliverRecordInput {
  return { workspaceId: "ws_test", recordId, destination, records: t.records, delivery, ledger: t.ledger, clock: t.clock, sleep: async (ms) => t.clock.advance(ms), retry: { maxAttempts: 2 } };
}

describe("#81 hostile: what the delivery adapter answers", () => {
  it("L1 an answer that is not an HTTP status never reaches the ledger and never throws: it is no answer, retried", async () => {
    for (const answer of [{ status: PHONE_ON_FILE }, { status: 2e10 }, { status: 250.5 }, { status: Number.NaN }, { status: "200" }, null, undefined, {}]) {
      const t = setup();
      const recordId = await confirmedRecord(t);
      const result = await deliverRecord(inputs(t, recordId, { post: async () => answer as never }));
      assert.deepEqual([result.delivered, result.status, result.attempts], [false, null, 2], JSON.stringify(answer));
      const statuses = (await t.ledger.list()).filter((e) => e.event === "delivery.attempted").map((e) => e.detail.status);
      assert.deepEqual(statuses, [null, null], JSON.stringify(answer));
      assert.equal(JSON.stringify(await t.ledger.list()).includes(PHONE_ON_FILE.slice(2)), false);
    }
  });

  it("L2 a real status still counts: 204 delivers, 409 fails at once, 503 retries", async () => {
    for (const [status, delivered, attempts] of [
      [204, true, 1],
      [409, false, 1],
      [503, false, 2],
    ] as const) {
      const t = setup();
      const recordId = await confirmedRecord(t);
      const result = await deliverRecord(inputs(t, recordId, { post: async () => ({ status }) }));
      assert.deepEqual([result.delivered, result.attempts, result.status], [delivered, attempts, status]);
    }
  });
});

describe("#81 hostile: the sample receiver's limits are documented", () => {
  it("D3 the reference server README says received keys live in memory only, so a real receiver stores them durably", async () => {
    const { readFile } = await import("node:fs/promises");
    const readme = (await readFile(new URL("../examples/reference-server/README.md", import.meta.url), "utf8")).replace(/\s+/g, " ");
    assert.match(readme, /sample receiver[^.]*keeps the idempotency keys it has received in memory only/);
    assert.match(readme, /real receiver must store them durably/);
  });
});
