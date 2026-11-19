// The public entry points load, and export what the documents name.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import * as root from "../src/index.ts";
import * as testing from "../src/testing/index.ts";
import { ENGINE_EVENTS } from "../src/core/events.ts";

describe("entry points", () => {
  it("the root exports the engine, the core, every module and the webhooks", () => {
    for (const name of [
      "createEngine",
      "Engine",
      "EngineError",
      "NotImplementedError",
      "canonicalJson",
      "evaluateAssurance",
      "validatePolicy",
      "defaultVerificationPolicy",
      "reduce",
      "cardNumberRedactor",
      "luhnValid",
      "judgeKeypadFactors",
      "normaliseFieldValue",
      "settlementFor",
      "MemoryAuditLedger",
      "verifyChain",
      "signReceipt",
      "verifyReceipt",
      "checkReceipt",
      "keyPairSigner",
      "derToP1363",
      "knowledgeHmac",
      "verifyStripeSignature",
      "parseStripeEvent",
      "ENGINE_EVENTS",
      "ModuleRegistry",
      "validateConfig",
      "ConfigError",
      "defaultConfig",
      "builtInModules",
      "badgeModule",
      "dossierModule",
      "paylinkModule",
      "traceModule",
      "gateModule",
      "MemorySessionStore",
      "pinDigest",
      "PAYMENT_MODES",
      "formatAmount",
    ]) {
      assert.ok(name in root, name);
    }
  });

  it("testing exports the fakes and a ready engine", () => {
    for (const name of [
      "createTestEngine",
      "FixedClock",
      "SequentialIds",
      "FakeIdentityProvider",
      "FakeCarrierSignals",
      "FakeMessageSender",
      "FakePaymentLinks",
      "MemoryRecordStore",
      "testSubject",
      "generateTestSigner",
      "TEST_KNOWLEDGE_KEY",
      "FakePinVerifier",
      "sessionStoreContract",
    ]) {
      assert.ok(name in testing, name);
    }
  });

  it("keeps the runtime functions of the modules out of the root", () => {
    for (const name of ["submitFactor", "beginVerification", "requestPayment", "startIntake", "recordConsent"]) assert.equal(name in root, false, name);
  });

  it("event names are unique and dotted", () => {
    assert.equal(new Set(ENGINE_EVENTS).size, ENGINE_EVENTS.length);
    for (const name of ENGINE_EVENTS) assert.match(name, /^[a-z]+\.[a-z_]+$/);
  });
});

describe("fakes", () => {
  it("the fixed clock moves only when told to", () => {
    const clock = new testing.FixedClock("2026-05-01T00:00:00.000Z");
    assert.equal(clock.now().toISOString(), "2026-05-01T00:00:00.000Z");
    clock.advance(1500);
    assert.equal(clock.now().toISOString(), "2026-05-01T00:00:01.500Z");
    assert.equal(new testing.FixedClock().now().toISOString(), "2026-01-01T00:00:00.000Z");
  });

  it("ids count per prefix", () => {
    const ids = new testing.SequentialIds();
    assert.deepEqual([ids.next("a"), ids.next("a"), ids.next("b")], ["a_1", "a_2", "b_1"]);
  });

  it("payment links honour idempotency keys", async () => {
    const links = new testing.FakePaymentLinks();
    const input = { callId: "c", paymentId: "p", amountMinor: 1, currency: "cad", description: "d", idempotencyKey: "k" };
    const a = await links.createLink(input);
    assert.deepEqual(await links.createLink(input), a);
    assert.notDeepEqual(await links.createLink({ ...input, idempotencyKey: "k2" }), a);
    assert.equal(links.created.length, 2);
  });

  it("the record store returns copies and nothing for unknown keys", async () => {
    const store = new testing.MemoryRecordStore();
    const subject = testing.testSubject("k".repeat(16), { accountNumber: "1", phoneOnFile: "+15555550100", knowledge: { dob: "1" } });
    store.putSubject("w", subject);
    const got = await store.getSubject("w", subject.subjectKey);
    assert.deepEqual(got, subject);
    got!.phoneOnFile = "changed";
    assert.equal((await store.getSubject("w", subject.subjectKey))!.phoneOnFile, "+15555550100");
    assert.equal(await store.getSubject("other", subject.subjectKey), null);
  });

  it("the carrier fake answers per number or with its fallback", async () => {
    const carrier = new testing.FakeCarrierSignals({ checked: false });
    carrier.set("+1", { identityMatch: "match" });
    assert.equal((await carrier.check({ phoneNumber: "+1" })).identityMatch, "match");
    assert.equal((await carrier.check({ phoneNumber: "+1" })).checked, false);
    assert.equal((await carrier.check({ phoneNumber: "+2" })).identityMatch, "unavailable");
    assert.deepEqual(carrier.checked, ["+1", "+1", "+2"]);
  });
});
