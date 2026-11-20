// Consent inputs are read once: a getter (or a host changing the object while the engine waits)
// can never pass a check with one value and have another one stored, recorded or ledgered.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { MemoryConsentStore } from "../src/testing/fakes.ts";
import { PHONE_ON_FILE, rejects, setup, testConfig, verifiedCall, wording } from "./helpers.ts";

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

describe("consents: inputs are read once", () => {
  it("recordConsent checks the flow step against the purpose it found a wording for", async () => {
    const t = setup({
      config: testConfig((c) => {
        (c.modules.trace!.settings as { wordings: unknown[] }).wordings.push({ ...wording, purpose: "marketing" });
        c.flows = { consent: { steps: [{ type: "trace.consent", purpose: "texts" }] } };
      }),
    });
    const { callId } = await t.engine.startCall({ flow: "consent" });
    await assert.rejects(t.engine.recordConsent(callId, flipping({ answer: "yes" }, "purpose", "marketing", "texts") as never), rejects("precondition_failed", /asks for consent to texts/));
  });

  it("revokeConsent records the channel it checked, for the consent it looked up", async () => {
    const consents = new MemoryConsentStore();
    const t = setup({ adapters: { consents } });
    const callId = await verifiedCall(t);
    const yes = await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    await t.engine.endCall(callId);
    const revoked = await t.engine.revokeConsent(flipping({ consentId: yes.consentId }, "via", "text", PHONE_ON_FILE) as never);
    assert.equal(revoked.via, "text");
    assert.equal(JSON.stringify(await t.ledger.list()).includes(PHONE_ON_FILE.slice(2)), false);
    const again = flipping({ via: "web" }, "consentId", yes.consentId, "", 2);
    assert.deepEqual(await t.engine.revokeConsent(again as never), revoked, "the id checked is the one looked up");
  });
});
