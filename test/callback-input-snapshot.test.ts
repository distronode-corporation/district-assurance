// applyCallbackOutcome reads the outcome once: the answer that decided the factor is the one the
// ledger's callback_finished entry names, and the reference looked up is the one applied.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { ACCOUNT, PIN, setup, testConfig } from "./helpers.ts";

function callbackConfig(): FlowConfig {
  return testConfig((c) => {
    c.modules.badge = {
      settings: {
        factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "callback"],
        pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 },
      },
    };
    c.policy.levels[1]!.anyOf.push(["pin", "callback"]);
  });
}

describe("callback: the outcome is read once", () => {
  it("names the outcome that decided the factor", async () => {
    const t = setup({ config: callbackConfig() });
    const { callId } = await t.engine.startCall({});
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: "+15555550199" });
    await t.engine.submitPin(callId, PIN);
    await t.engine.requestCallback(callId);
    const { ref } = t.dialer.dialed.at(-1)!;
    let reads = 0;
    const outcome = {
      ref,
      confirmed: false,
      get answered() {
        reads += 1;
        return reads === 1;
      },
    };
    assert.equal((await t.engine.applyCallbackOutcome(outcome)).applied, true);
    const finished = (await t.ledger.list()).find((e) => e.event === "verification.callback_finished")!;
    assert.equal((finished.detail as { outcome: string }).outcome, "no_confirmation", "answered, not confirmed: as first read");
  });
});
