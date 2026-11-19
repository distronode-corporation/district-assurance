// Hostile pass on #80 (PRV-3 consent records and revocation), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { MemoryConsentStore } from "../src/testing/fakes.ts";
import { PHONE_ON_FILE, rejects, setup, verifiedCall } from "./helpers.ts";

describe("#80 hostile: what a consent may hold", () => {
  it("V1 an answer that is not yes or no, or a channel that is not call, text or web, is refused before anything is reserved, stored or ledgered", async () => {
    const consents = new MemoryConsentStore();
    const t = setup({ adapters: { consents } });
    const callId = await verifiedCall(t);
    const before = (await t.ledger.list()).length;
    for (const input of [
      { purpose: "texts", answer: PHONE_ON_FILE },
      { purpose: "texts", answer: "maybe" },
      { purpose: "texts", answer: true },
      { purpose: "texts", answer: "yes", channel: "fax" },
      { purpose: "texts", answer: "yes", channel: PHONE_ON_FILE },
      { purpose: "texts", answer: "yes", channel: null },
    ]) {
      await assert.rejects(t.engine.recordConsent(callId, input as never), rejects("invalid_input"), JSON.stringify(input));
    }
    assert.equal((await t.ledger.list()).length, before, "nothing ledgered");
    assert.equal(JSON.stringify(await t.ledger.list()).includes(PHONE_ON_FILE.slice(2)), false);
    // The call is not left with a reservation it cannot finish: a good consent goes through at once.
    assert.equal((await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" })).answer, "yes");
  });

  it("V2 a consent revoked twice by different channels keeps the first, and the ledger has one entry", async () => {
    const consents = new MemoryConsentStore();
    const t = setup({ adapters: { consents } });
    const callId = await verifiedCall(t);
    const yes = await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    const [a, b] = await Promise.all([t.engine.revokeConsent({ consentId: yes.consentId, via: "text" }), t.engine.revokeConsent({ consentId: yes.consentId, via: "web" })]);
    assert.deepEqual(a, b);
    assert.equal((await t.ledger.list()).filter((e) => e.event === "consent.revoked").length, 1);
  });

  it("V3 another workspace's consent id on a shared store is unknown here", async () => {
    const consents = new MemoryConsentStore();
    const a = setup({ adapters: { consents } });
    const callId = await verifiedCall(a);
    const yes = await a.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    const { createTestEngine } = await import("../src/testing/index.ts");
    const b = createTestEngine({ workspaceId: "ws_other", adapters: { consents } });
    await assert.rejects(b.engine.revokeConsent({ consentId: yes.consentId, via: "web" }), rejects("invalid_input", /no such consent/));
  });
});
