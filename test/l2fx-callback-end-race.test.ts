// Two callback requests on one call that both reach the end of the asking call: the one that ends
// it second is not an error (engine.requestCallback). Held at endCall so both get there for certain.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { ACCOUNT, PIN, setup, testConfig } from "./helpers.ts";

describe("requestCallback: two requests reach the end of the asking call together", () => {
  it("both resolve, the call ends once, and the line rings once", async () => {
    const t = setup({
      config: testConfig((c) => {
        c.modules.badge = { settings: { factors: ["keypad_knowledge", "pin", "carrier_identity_match", "callback"], pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 } } };
        c.policy.levels[1]!.anyOf.push(["pin", "callback"]);
      }),
    });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: "+15555550199" });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    const endCall = t.engine.endCall.bind(t.engine);
    let arrived = 0;
    let firstHere!: () => void;
    let bothHere!: () => void;
    const first = new Promise<void>((resolve) => (firstHere = resolve));
    const together = new Promise<void>((resolve) => (bothHere = resolve));
    t.engine.endCall = async (id) => {
      if (++arrived === 1) firstHere();
      else bothHere();
      await together;
      return endCall(id);
    };
    // The first is held at the end of the asking call; the second finds its callback placed and,
    // with the call not ended yet, reaches the end too.
    const a = t.engine.requestCallback(callId);
    await first;
    const results = await Promise.all([a, t.engine.requestCallback(callId)]);
    assert.deepEqual(results, [undefined, undefined]);
    assert.equal(arrived, 2, "both requests reached the end of the asking call");
    assert.equal((await t.engine.state(callId)).phase, "ended");
    assert.equal((await t.ledger.list()).filter((e) => e.callId === callId && e.event === "call.ended").length, 1);
    assert.equal(t.dialer.dialed.length, 1);
  });
});
