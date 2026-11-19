// confirmIntake reads its input once: a getter (or a host changing the object while the engine
// waits) can never pass the read-back check with one value or file a channel other than the one given.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { PHONE_ON_FILE, heard, setup, verifiedCall } from "./helpers.ts";

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

describe("intake: confirmIntake reads its input once", () => {
  it("compares the read-back it was given, and files the channel it was given", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    const digest = await heard(t, callId);
    const input = flipping({ readBack: digest }, "confirmedBy", "voice", PHONE_ON_FILE);
    const pending = t.engine.confirmIntake(callId, input as never);
    const record = await pending;
    assert.equal(record.confirmedBy, "voice");
    assert.equal(JSON.stringify(await t.ledger.list()).includes(PHONE_ON_FILE.slice(2)), false);
    const second = await verifiedCall(t);
    await t.engine.startIntake(second, "repair");
    await t.engine.setIntakeField(second, "issue", "leak");
    const swapped = flipping({ confirmedBy: "keypad" }, "readBack", await heard(t, second), { length: 64 });
    assert.equal((await t.engine.confirmIntake(second, swapped as never)).confirmedBy, "keypad", "no TypeError from a read-back that changed after its type check");
  });
});
