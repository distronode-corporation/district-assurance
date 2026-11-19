import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { ConfigError } from "../src/core/config.ts";
import { NotImplementedError } from "../src/core/errors.ts";
import type { EngineEvent } from "../src/core/events.ts";
import { defaultVerificationPolicy } from "../src/core/policy.ts";
import { createEngine } from "../src/engine.ts";
import { defaultConfig } from "../src/modules.ts";
import type { AmountLookup, AmountSource } from "../src/core/runtime.ts";
import { PriceListAmounts, buildAmountReadBack } from "../src/pay/amount.ts";
import { formatAmount, type PaylinkSlice } from "../src/pay/paylink.ts";
import { MemoryAuditLedger, verifyChain } from "../src/prove/ledger.ts";
import { verifyReceipt } from "../src/prove/receipt.ts";
import { FakeCarrierSignals, FakeIdentityProvider, FakeMessageSender, FakePaymentLinks, MemoryRecordStore, generateTestSigner } from "../src/testing/fakes.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, confirmAmount, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

describe("Engine construction", () => {
  it("refuses a short key, an empty workspace, a missing ledger and a bad config", () => {
    const base = { workspaceId: "w", knowledgeKey: TEST_KNOWLEDGE_KEY, adapters: { ledger: new MemoryAuditLedger() }, config: { ...defaultConfig(), modules: { trace: { settings: { receipts: false } } } } };
    assert.throws(() => createEngine({ ...base, knowledgeKey: "short" }), /at least 16 bytes/);
    assert.throws(() => createEngine({ ...base, knowledgeKey: new Uint8Array(15) }), /at least 16 bytes/);
    assert.throws(() => createEngine({ ...base, workspaceId: "" }), rejects("invalid_input", /workspaceId is empty/));
    assert.throws(() => createEngine({ ...base, adapters: {} as never }), /the ledger adapter is required/);
    assert.throws(
      () => createEngine({ ...base, config: { ...defaultConfig(), policy: { ...defaultVerificationPolicy(), keypadFields: [] } } }),
      (e: unknown) => e instanceof ConfigError && e.code === "invalid_input" && e.problems.includes("policy: keypadFields is empty"),
    );
    // The default config needs every adapter its modules use.
    assert.throws(() => createEngine({ ...base, config: undefined }), (e: unknown) => e instanceof ConfigError && e.problems.includes("modules.badge: needs the records adapter, which the engine does not have"));
    const engine = createEngine({ ...base, knowledgeKey: new Uint8Array(16) });
    assert.equal(engine.workspaceId, "w");
    assert.deepEqual(engine.policy, defaultVerificationPolicy());
    assert.deepEqual(engine.config.modules, { trace: { settings: { receipts: false } } });
    assert.equal(engine.isEnabled("trace"), true, "the ledger is always on");
    assert.equal(engine.isEnabled("badge"), false);
    assert.deepEqual(engine.receiptKeys(), []);
  });

  it("checks a null config instead of using the default, and refuses one that is not plain data", () => {
    const adapters = { ledger: new MemoryAuditLedger() };
    assert.throws(() => createEngine({ workspaceId: "w", knowledgeKey: TEST_KNOWLEDGE_KEY, adapters, config: null }), (e: unknown) => e instanceof ConfigError && e.problems[0] === "the config must be an object");
    assert.throws(
      () => createEngine({ workspaceId: "w", knowledgeKey: TEST_KNOWLEDGE_KEY, adapters, config: { ...defaultConfig(), revision: () => "x" } }),
      (e: unknown) => e instanceof ConfigError && e.problems[0] === "the config must be plain JSON data",
    );
  });

  it("catches a listener's rejected promise", async () => {
    let rejected = 0;
    const t = setup({
      onEvent: () => {
        rejected++;
        return Promise.reject(new Error("async listener bug")) as unknown as void;
      },
    });
    const { callId } = await t.engine.startCall();
    await t.engine.markUntrusted(callId, "x");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(rejected, 2);
    assert.equal((await t.ledger.list()).length, 2);
  });

  it("keeps writing the ledger when the listener throws", async () => {
    const t = setup({
      onEvent: () => {
        throw new Error("listener bug");
      },
    });
    const { callId } = await t.engine.startCall();
    await t.engine.markUntrusted(callId, "x");
    assert.deepEqual((await t.ledger.list()).map((e) => e.event), ["call.started", "session.tainted"]);
  });

  it("runs on the system clock, random ids and an in-memory session store by default", async () => {
    const engine = createEngine({
      workspaceId: "w",
      knowledgeKey: TEST_KNOWLEDGE_KEY,
      adapters: {
        identity: new FakeIdentityProvider(),
        carrier: new FakeCarrierSignals(),
        messages: new FakeMessageSender(),
        payments: new FakePaymentLinks(),
        records: new MemoryRecordStore(),
        ledger: new MemoryAuditLedger(),
        signer: generateTestSigner(),
      },
    });
    const state = await engine.startCall();
    assert.match(state.callId, /^call_[A-Za-z0-9_-]{16}$/);
    assert.ok(Math.abs(Date.parse(state.startedAt) - Date.now()) < 5000);
    // The default redactor is the card-number redactor.
    assert.equal((await engine.redact(state.callId, "4242424242424242")).interrupt, true);
  });
});

describe("Engine sessions", () => {
  it("starts calls, refuses a duplicate id and an unknown call", async () => {
    const t = setup();
    const state = await t.engine.startCall({ callId: "c1" });
    assert.equal(state.phase, "open");
    await assert.rejects(t.engine.startCall({ callId: "c1" }), rejects("invalid_input"));
    await assert.rejects(t.engine.state("nope"), rejects("unknown_call"));
    await assert.rejects(t.engine.redact("nope", "hello"), rejects("unknown_call"));
    await assert.rejects(t.engine.markUntrusted("nope", "x"), rejects("unknown_call"));
    assert.equal((await t.engine.state("c1")).callId, "c1");
  });

  it("reports every event to the listener and the ledger, in order, with the config revision", async () => {
    const events: EngineEvent[] = [];
    const t = setup({ onEvent: (e) => events.push(e) });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.openSensitive(callId, "keypad"), rejects("invalid_transition"));
    await t.engine.markUntrusted(callId, "business_endpoint");
    assert.deepEqual(
      events.map((e) => e.name),
      ["call.started", "session.tainted"],
    );
    assert.deepEqual(events[0]!.detail, { locale: "en", revision: "default" });
    assert.deepEqual(events[1]!.detail, { source: "business_endpoint" });
    const entries = await t.ledger.list();
    assert.deepEqual(entries.map((e) => e.event), ["call.started", "session.tainted"]);
    assert.equal((await t.engine.state(callId)).tainted, true);
  });

  it("opens and closes the keypad segment during verification", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.openSensitive(callId, "keypad"), rejects("invalid_transition"));
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.openSensitive(callId, "keypad");
    assert.equal((await t.engine.state(callId)).sensitive, "keypad");
    await t.engine.closeSensitive(callId);
    assert.equal((await t.engine.state(callId)).sensitive, null);
  });

  it("redacts text and counts findings by kind, without logging the text", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    assert.deepEqual(await t.engine.redact(callId, "hello"), { text: "hello", findings: [], interrupt: false });
    const result = await t.engine.redact(callId, "4242424242424242 and 5555 5555 5555 4444");
    assert.equal(result.text, "[card number removed] and [card number removed]");
    assert.equal(result.interrupt, true);
    const entry = (await t.ledger.list()).at(-1)!;
    assert.equal(entry.event, "redaction.applied");
    assert.deepEqual(entry.detail, { kinds: { card_number: 2 } });
  });
});

describe("Engine verify", () => {
  it("reaches level 3 with keypad and photo ID, texting the link to the number on file only", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const state = await t.engine.state(callId);
    assert.equal(state.level, 3);
    assert.deepEqual(state.grant?.scopes, ["contact.update", "intake.file", "payment.request", "payout.update", "status.read"]);
    assert.equal(state.grant?.expiresAt, "2026-01-01T00:15:00.000Z");
    assert.deepEqual(t.messages.sent.map((m) => [m.to, m.purpose]), [[PHONE_ON_FILE, "identity_link"]]);
    assert.match(t.messages.sent[0]!.body, /^Your one-time identity check link: https:\/\/identity\.example\.test\//);
    const entries = await t.ledger.list();
    assert.deepEqual(entries.map((e) => e.event), [
      "call.started",
      "verification.started",
      "verification.factor",
      "identity.link_sent",
      "verification.factor",
      "verification.finished",
      "grant.issued",
    ]);
    assert.deepEqual(entries[1]!.detail, { subject: "account" });
  });

  it("gives the same answer for an unknown account, a wrong value and a non-keypad entry", async () => {
    for (const [account, dob] of [["99999999", DOB], [ACCOUNT, "19850215"], ["12a", DOB]]) {
      const t = setup();
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { accountNumber: account! });
      assert.deepEqual(await t.engine.submitKeypad(callId, { dob: dob! }), { matched: false, locked: false });
      const detail = (await t.ledger.list()).at(-1)!.detail;
      assert.deepEqual(detail, { kind: "keypad_knowledge", passed: false });
      assert.deepEqual(await t.engine.finishVerification(callId), { level: 0, scopes: [] });
      assert.equal((await t.engine.state(callId)).grant, null);
    }
  });

  it("locks keypad judging after the policy's attempts", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.submitKeypad(callId, { dob: DOB }), rejects("invalid_transition"));
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: "1" }), { matched: false, locked: false });
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: "2" }), { matched: false, locked: true });
    // Even the right answer is not judged now.
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: false, locked: true });
    assert.equal((await t.engine.state(callId)).factors.length, 2);
  });

  it("asks the carrier about the number on file after a match, and records identity match", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.checkCarrier(callId), rejects("precondition_failed"));
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.deepEqual(await t.engine.checkCarrier(callId), { textCodeTrusted: true });
    assert.deepEqual(t.carrier.checked, [PHONE_ON_FILE]);
    assert.equal((await t.engine.state(callId)).factors.length, 1, "identity match unavailable records nothing");
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match", lastSimSwapHoursAgo: 3 });
    assert.deepEqual(await t.engine.checkCarrier(callId), { textCodeTrusted: false });
    assert.deepEqual(await t.engine.finishVerification(callId), {
      level: 2,
      scopes: ["intake.file", "payment.request", "status.read"],
    });
    const carrierEvent = (await t.ledger.list()).find((e) => e.event === "verification.carrier_checked" && e.detail.identityMatch === "match");
    assert.deepEqual(carrierEvent?.detail, { checked: true, textCodeTrusted: false, identityMatch: "match" });
    await assert.rejects(t.engine.checkCarrier(callId), rejects("invalid_transition"), "only while verifying");
  });

  it("records a carrier identity mismatch as a failed factor", async () => {
    const t = setup();
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "no_match" });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    assert.deepEqual((await t.engine.state(callId)).factors.map((f) => [f.kind, f.passed]), [
      ["keypad_knowledge", true],
      ["carrier_identity_match", false],
    ]);
  });

  it("keeps factors for a step-up on the same account and drops them for another", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.startPhotoId(callId);
    await assert.rejects(t.engine.beginVerification(callId, { accountNumber: "87654321" }), rejects("invalid_transition"));
    const s = await t.engine.state(callId);
    assert.equal(s.phase, "verifying");
    assert.equal(s.factors.length, 1, "the step-up kept the keypad factor");
  });

  it("starts over on another account number", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: "87654321" });
    assert.equal((await t.engine.state(callId)).factors.length, 0);
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"));
  });

  it("sends photo ID links only after a match, once per call, in the caller's language", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall({ locale: "fr" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"));
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    assert.match(t.messages.sent[0]!.body, /^Votre lien de vérification d'identité, à usage unique : https:/);
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"));
  });

  it("applies identity outcomes once, only while verifying, and ignores unknown sessions", async () => {
    const t = setup();
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId: "vs_unknown", status: "verified" }), { applied: false });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    const sessionId = t.identity.created[0]!.sessionId;
    await t.engine.finishVerification(callId);
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: false }, "late: verification finished");
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "requires_input" }), { applied: true, callId });
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: false }, "single use");
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
  });

  it("has a planned texted code, refused before a match", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.sendTextCode(callId), rejects("precondition_failed"));
    await t.engine.submitKeypad(callId, { dob: DOB });
    await assert.rejects(t.engine.sendTextCode(callId), (e: unknown) => e instanceof NotImplementedError && e.issue === "VER-2");
  });

  it("refuses factors that are turned off, and entries for factors the caller does not enter", async () => {
    const t = setup({ config: testConfig((c) => (c.modules.badge = { settings: { factors: ["keypad_knowledge"] } })) });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.submitPin(callId, "4826"), rejects("precondition_failed", /pin factor is turned off/));
    await assert.rejects(t.engine.submitFactor(callId, "photo_id", "x"), rejects("invalid_input", /not a factor the caller enters/));
    await assert.rejects(t.engine.submitFactor(callId, "spoken_knowledge", "x"), rejects("precondition_failed", /turned off/));
    await t.engine.submitKeypad(callId, { dob: DOB });
    await assert.rejects(t.engine.checkCarrier(callId), rejects("precondition_failed", /carrier_identity_match factor is turned off/));
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed", /photo_id factor is turned off/));
    assert.deepEqual(t.carrier.checked, [], "the carrier is never asked for a factor that is off");
  });
});

describe("Engine authorize", () => {
  it("refuses unknown scopes, ended calls, missing and expired grants", async () => {
    const t = setup({
      config: testConfig((c) => {
        c.policy.scopes["hours.read"] = 0;
        c.policy.scopeClasses = { "hours.read": "none" };
        (c.modules.badge!.settings as { grantTtlSeconds?: number }).grantTtlSeconds = 60;
      }),
    });
    const { callId } = await t.engine.startCall();
    assert.equal(await t.engine.authorize(callId, "hours.read"), true);
    assert.equal(await t.engine.authorize(callId, "status.read"), false);
    assert.equal(await t.engine.authorize(callId, "made.up"), false);
    assert.equal(await t.engine.authorize(callId, "constructor"), false, "not an inherited property");
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    assert.equal(await t.engine.authorize(callId, "status.read"), true);
    assert.equal(await t.engine.authorize(callId, "payment.request"), false);
    t.clock.advance(60_000);
    assert.equal(await t.engine.authorize(callId, "status.read"), false, "expired");
    await t.engine.endCall(callId);
    assert.equal(await t.engine.authorize(callId, "hours.read"), false);
  });

  it("holds an issued grant to a stricter minimum set later (review item 9)", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    assert.equal(await t.engine.authorize(callId, "status.read"), true);
    t.engine.configure(testConfig((c) => (c.policy.scopes["status.read"] = 2)));
    assert.equal(await t.engine.authorize(callId, "status.read"), false, "a level 1 grant no longer covers a level 2 scope");
  });

  it("drops the grant when untrusted text enters, and re-verification starts from nothing", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.markUntrusted(callId, "document");
    assert.equal(await t.engine.authorize(callId, "status.read"), false);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.state(callId)).factors.length, 0);
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"), "the match before the taint no longer counts");
  });

  it("ignores a photo ID outcome for a link sent before the taint", async () => {
    const t = setup();
    const other = await t.engine.startCall();
    await t.engine.beginVerification(other.callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(other.callId, { dob: DOB });
    await t.engine.startPhotoId(other.callId);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    await t.engine.markUntrusted(callId, "document");
    assert.equal((await t.engine.state(callId)).phase, "verifying");
    const sessionId = t.identity.created.at(-1)!.sessionId;
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: false });
    const otherSession = t.identity.created[0]!.sessionId;
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId: otherSession, status: "verified" }), { applied: true, callId: other.callId }, "other calls keep theirs");
  });

  it("voids a photo ID link reserved before the taint and created after it", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    const original = t.identity.createDocumentCheck.bind(t.identity);
    t.identity.createDocumentCheck = async (input) => {
      await t.engine.markUntrusted(callId, "document");
      return original(input);
    };
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed", /untrusted content/));
    assert.equal(t.messages.sent.length, 0, "a link that could never count is never texted");
    const sessionId = t.identity.created[0]!.sessionId;
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: false });
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"), "one link per call still holds");
  });
});

describe("Engine file", () => {
  it("files a confirmed record with its digest", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    assert.deepEqual(await t.engine.setIntakeField(callId, "issue", "4242 4242 4242 4242"), { ok: false, reason: "card_number" });
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), /required fields missing: issue/);
    assert.deepEqual(await t.engine.setIntakeField(callId, "issue", " Leak under sink "), { ok: true, value: "Leak under sink" });
    await t.engine.setIntakeField(callId, "urgent", "yes");
    await assert.rejects(t.engine.setIntakeField(callId, "nope", "x"), rejects("invalid_input"));
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad" });
    assert.deepEqual(record.values, { issue: "Leak under sink", urgent: true });
    assert.deepEqual(await t.records.getIntakeRecord("ws_test", record.recordId), record);
    assert.equal(await t.records.getIntakeRecord("ws_test", "rec_404"), null);
    assert.deepEqual((await t.engine.state(callId)).recordIds, [record.recordId]);
    await assert.rejects(t.engine.setIntakeField(callId, "issue", "x"), rejects("invalid_transition"));
  });

  it("refuses intake without the scope, an unknown form, and abandons", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.startIntake(callId, "repair"), rejects("scope_denied"));
    const verified = await verifiedCall(t);
    await assert.rejects(t.engine.startIntake(verified, "nope"), rejects("invalid_input", /no form nope/));
    await assert.rejects(t.engine.abandonIntake(verified), rejects("invalid_transition"));
    await t.engine.startIntake(verified, "repair");
    await t.engine.abandonIntake(verified);
    assert.equal((await t.engine.state(verified)).phase, "open");
    await assert.rejects(t.engine.confirmIntake(verified, { confirmedBy: "voice" }), rejects("invalid_transition"));
  });

  it("files one record when two confirmations of the same draft run at once", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    const put = t.records.putIntakeRecord.bind(t.records);
    let second: Promise<unknown> | null = null;
    let calls = 0;
    t.records.putIntakeRecord = async (record) => {
      // The first write waits for a second confirmation, which resumes the same record and files it first.
      if (++calls === 1) {
        second = t.engine.confirmIntake(callId, { confirmedBy: "keypad" });
        await second;
      }
      return put(record);
    };
    const first = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    assert.deepEqual(await second, first, "the second one resumed the same record");
    assert.deepEqual((await t.engine.state(callId)).recordIds, ["rec_1"]);
    assert.equal((await t.ledger.list()).filter((e) => e.event === "intake.confirmed").length, 1);
  });

  it("re-checks the grant at confirmation", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    t.clock.advance(15 * 60_000);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), rejects("scope_denied"));
  });

  it("holds the draft while it is filed, and keeps it reserved for the same record when the store fails", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    const put = t.records.putIntakeRecord.bind(t.records);
    let during: unknown[] = [];
    t.records.putIntakeRecord = async () => {
      during = await Promise.allSettled([t.engine.setIntakeField(callId, "issue", "x"), t.engine.abandonIntake(callId)]);
      throw new Error("database down");
    };
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), /database down/);
    assert.ok(during.every((r) => (r as PromiseSettledResult<unknown>).status === "rejected" && rejects("precondition_failed")((r as PromiseRejectedResult).reason)));
    t.records.putIntakeRecord = put;
    await assert.rejects(t.engine.setIntakeField(callId, "issue", "changed"), rejects("precondition_failed"), "still reserved after the failed write");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad" });
    assert.deepEqual([record.recordId, record.values.issue, record.confirmedBy], ["rec_1", "leak", "voice"], "the same record, written again");
  });
});

describe("Engine pay", () => {
  const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };

  it("texts a link to the number on file and settles only on paid", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const { paymentId } = await t.engine.requestPayment(callId, request);
    const state = await t.engine.state(callId);
    assert.equal(state.phase, "paying");
    assert.equal(state.sensitive, "payment");
    const text = t.messages.sent.at(-1)!;
    assert.equal(text.to, PHONE_ON_FILE);
    assert.equal(text.purpose, "payment_link");
    assert.equal(text.body, "Your secure payment link for $150.00: https://pay.example.test/c/cs_fake_1");
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("invalid_transition"));
    const linkId = t.payments.created[0]!.linkId;
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId, paymentStatus: "unpaid" }), { applied: false });
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "async_succeeded", linkId }), { applied: true, callId, status: "paid" });
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "async_failed", linkId }), { applied: false }, "settled once");
    assert.equal((await t.engine.state(callId)).phase, "open");
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "expired", linkId: "cs_unknown" }), { applied: false });
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.payments, [{ paymentId, status: "paid", amountMinor: 15000, currency: "cad", providerRef: linkId }]);
  });

  it("settles a payment after the call ended without moving the session", async () => {
    const t = setup();
    const callId = await verifiedCall(t, "fr");
    await confirmAmount(t.engine, callId, { ...request, amountMinor: 150, currency: "jpy" });
    await t.engine.requestPayment(callId, { ...request, amountMinor: 150, currency: "jpy" });
    assert.equal(t.messages.sent.at(-1)!.body, `Votre lien de paiement sécurisé pour ${formatAmount("fr", 150, "jpy")} : https://pay.example.test/c/cs_fake_1`);
    await t.engine.endCall(callId);
    const result = await t.engine.applyPaymentOutcome({ kind: "expired", linkId: "cs_fake_1" });
    assert.deepEqual(result, { applied: true, callId, status: "expired" });
    assert.equal((await t.engine.state(callId)).phase, "ended");
  });

  it("refuses without the scope, without an amount, and refuses bad amounts and descriptions at the read-back", async () => {
    const t = setup({ config: testConfig((c) => (c.modules.paylink = { settings: { maxAmountMinor: 10000 } })) });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("scope_denied"));
    await assert.rejects(t.engine.readBackPayment(callId, request), rejects("scope_denied"));
    const verified = await verifiedCall(t);
    await assert.rejects(t.engine.readBackPayment(verified), rejects("invalid_input", /outside a flow/));
    await assert.rejects(t.engine.requestPayment(verified), rejects("precondition_failed", /read back and confirmed before/));
    await assert.rejects(t.engine.readBackPayment(verified, request), /above the limit/);
    await assert.rejects(t.engine.readBackPayment(verified, { ...request, amountMinor: 100, description: "  " }), /description/);
    await assert.rejects(t.engine.readBackPayment(verified, { ...request, amountMinor: 100, description: "x".repeat(201) }), /description/);
    await assert.rejects(t.engine.readBackPayment(verified, { ...request, amountMinor: 100, amountSource: "model" as never }), /amountSource/);
    await assert.rejects(t.engine.readBackPayment(verified, { ...request, amountMinor: "100" as never }), /amountMinor and currency are required/);
  });

  it("keeps a request open when creating or texting its link fails, and resumes it with the same keys", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const create = t.payments.createLink.bind(t.payments);
    t.payments.createLink = async () => {
      throw new Error("provider timed out");
    };
    await confirmAmount(t.engine, callId, request);
    await assert.rejects(t.engine.requestPayment(callId, request), /provider timed out/);
    assert.equal((await t.engine.state(callId)).phase, "paying", "the provider may have created it: not failed");
    t.payments.createLink = create;
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.requestPayment(callId), /carrier down/, "resumed without input");
    await assert.rejects(t.engine.requestPayment(callId, { ...request, amountMinor: 1 }), rejects("invalid_input", /same amount/));
    t.messages.sendText = send;
    assert.deepEqual(await t.engine.requestPayment(callId, request), { paymentId: "pay_1", status: "open" });
    assert.equal(t.payments.created.length, 1, "one link for the request, through every retry");
    assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 1);
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("invalid_transition"), "delivered: no second link");
    // A provider that settles while the text is on its way: the result says so.
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" });
    await confirmAmount(t.engine, callId, request);
    t.messages.sendText = async (input) => {
      await t.engine.applyPaymentOutcome({ kind: "completed", linkId: t.payments.created.at(-1)!.linkId, paymentStatus: "paid" });
      return send(input);
    };
    assert.equal((await t.engine.requestPayment(callId, request)).status, "paid");
    t.messages.sendText = send;
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.payments.map((p) => p.status), ["paid", "paid"]);
  });

  it("runs paylink without settings, at the package's own limit", async () => {
    const t = setup({ config: testConfig((c) => (c.modules.paylink = {})) });
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, { ...request, amountMinor: 1_000_000 });
    assert.equal((await t.engine.requestPayment(callId, { ...request, amountMinor: 1_000_000 })).status, "open");
  });

  it("formats amounts with the currency's own decimals", () => {
    assert.equal(formatAmount("en", 15000, "cad"), "$150.00");
    assert.match(formatAmount("en", 150, "jpy"), /^JP¥150$|^¥150$/u);
    assert.match(formatAmount("fr", 15000, "cad"), /^150,00\s\$$/u);
  });
});

describe("Engine pay: amounts from code, read back first (PAY-2)", () => {
  const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
  const byRef = { amountRef: "deposit.standard", description: "Repair deposit", amountSource: "price_list" as const };
  const prices = () => new PriceListAmounts({ "deposit.standard": { amountMinor: 12500, currency: "cad" } });

  /** A flow that verifies to level 3 and then asks for the price list's deposit. */
  function refFlow(amounts: AmountSource) {
    return setup({
      adapters: { amounts },
      config: testConfig((c) => {
        c.flows = {
          deposit: {
            steps: [
              { type: "badge.verify", level: 3, factors: ["keypad_knowledge", "photo_id"], scopes: ["payment.request"] },
              { type: "paylink.request", ...byRef },
            ],
          },
        };
      }),
    });
  }

  async function verify(t: TestEngine, callId: string): Promise<void> {
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    await t.engine.applyIdentityOutcome({ sessionId: t.identity.created.at(-1)!.sessionId, status: "verified" });
    await t.engine.finishVerification(callId);
  }

  it("never texts a link the caller has not heard and confirmed, whether the amount is fixed or not", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /read back and confirmed before/), "a fixed amount from the host");
    await assert.rejects(t.engine.requestPayment(callId), rejects("precondition_failed", /read back and confirmed before/), "no request at all");
    const back = await t.engine.readBackPayment(callId, request);
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /not confirmed/), "read back, not yet confirmed");
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "voice" });
    assert.equal((await t.engine.requestPayment(callId, request)).status, "open");
    // A fixed amount in a flow step is read back too.
    const f = setup({
      config: testConfig((c) => {
        c.flows = { pay: { steps: [{ type: "badge.verify", level: 3, factors: ["keypad_knowledge", "photo_id"], scopes: ["payment.request"] }, { type: "paylink.request", ...request }] } };
      }),
    });
    const { callId: inFlow } = await f.engine.startCall({ flow: "pay" });
    await verify(f, inFlow);
    await assert.rejects(f.engine.requestPayment(inFlow), rejects("precondition_failed", /read back and confirmed before/), "the step's own fixed amount");
    assert.deepEqual(f.payments.created, [], "no link was created");
    assert.deepEqual(f.messages.sent.map((m) => m.purpose), ["identity_link"], "and none was texted");
  });

  it("reads a fixed amount back and sends the link only for the amount the caller confirmed", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, request);
    assert.equal(back.text, "The amount to pay is $150.00, for Deposit. Is that correct?");
    assert.deepEqual(back, buildAmountReadBack("en", { amountMinor: 15000, currency: "cad", description: "Deposit" }));
    assert.match(back.digest, /^[0-9a-f]{64}$/);
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /not confirmed/));
    await assert.rejects(t.engine.requestPayment(callId, { ...request, amountMinor: 100 }), rejects("precondition_failed", /not the amount read back/));
    await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest: "0".repeat(64), confirmedBy: "keypad" }), rejects("precondition_failed", /not the amount last read back/));
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "keypad" });
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "keypad" });
    assert.deepEqual(await t.engine.requestPayment(callId), { paymentId: "pay_1", status: "open" }, "outside a flow, the confirmed read-back is the request");
    assert.equal(t.messages.sent.at(-1)!.body, "Your secure payment link for $150.00: https://pay.example.test/c/cs_fake_1");
    await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "voice" }), rejects("precondition_failed", /no amount was read back/), "a read-back serves one link");
    await assert.rejects(t.engine.readBackPayment(callId, request), rejects("invalid_transition", /while paying/));
    const entries = await t.ledger.list();
    assert.deepEqual(entries.filter((e) => e.event.startsWith("payment.")).map((e) => [e.event, e.detail]), [
      ["payment.amount_read_back", { amountMinor: 15000, currency: "cad", amountSource: "price_list", digest: back.digest }],
      ["payment.amount_confirmed", { digest: back.digest, confirmedBy: "keypad" }],
      ["payment.link_sent", { paymentId: "pay_1", linkId: "cs_fake_1", amountMinor: 15000, currency: "cad", amountSource: "price_list" }],
    ]);
    assert.equal(entries.find((e) => e.event === "payment.amount_confirmed")!.actor, "caller");
  });

  it("refuses a confirmation by anything but voice or keypad, so the host's text never reaches the ledger", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, request);
    for (const confirmedBy of [PHONE_ON_FILE, "Jane Doe 1985-02-14", "", undefined, null, 42, { by: "voice" }, ["voice"]]) {
      await assert.rejects(
        t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: confirmedBy as unknown as "voice" }),
        rejects("invalid_input", /confirmedBy must be voice or keypad/),
        JSON.stringify(confirmedBy),
      );
    }
    for (const digest of [undefined, null, 42, { digest: back.digest }]) {
      await assert.rejects(
        t.engine.confirmPaymentAmount(callId, { digest: digest as unknown as string, confirmedBy: "voice" }),
        rejects("invalid_input", /digest must be/),
        JSON.stringify(digest),
      );
    }
    await assert.rejects(t.engine.confirmPaymentAmount(callId, null as unknown as { digest: string; confirmedBy: "voice" }), rejects("invalid_input"));
    await assert.rejects(t.engine.requestPayment(callId), rejects("precondition_failed", /not confirmed/), "nothing was confirmed");
    const entries = JSON.stringify(await t.ledger.list());
    assert.equal(entries.includes("payment.amount_confirmed"), false);
    assert.equal(entries.includes("5555550100"), false);
    assert.equal(entries.includes("Jane"), false);
  });

  it("builds the read-back in French, and a new read-back replaces the one before", async () => {
    const t = setup();
    const callId = await verifiedCall(t, "fr");
    const first = await t.engine.readBackPayment(callId, request);
    assert.match(first.text, /^Le montant à payer est de 150,00\s\$, pour Deposit\. Est-ce exact \?$/u);
    const second = await t.engine.readBackPayment(callId, { ...request, amountMinor: 9900, description: "  Repair  " });
    assert.equal(second.description, "Repair");
    await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest: first.digest, confirmedBy: "voice" }), rejects("precondition_failed"));
    await t.engine.confirmPaymentAmount(callId, { digest: second.digest, confirmedBy: "voice" });
    // The confirmed amount still has to fit the limit in force when the link is sent.
    t.engine.configure(testConfig((c) => (c.modules.paylink = { settings: { maxAmountMinor: 5000 } })));
    await assert.rejects(t.engine.requestPayment(callId), rejects("invalid_input", /above the limit/));
    const bare = setup({ config: testConfig((c) => (c.modules.paylink = {})) });
    const big = await verifiedCall(bare);
    assert.equal((await bare.engine.readBackPayment(big, { ...request, amountMinor: 1_000_000 })).amountMinor, 1_000_000, "no settings: the package's own limit");
  });

  it("resolves a flow step's amountRef, reads it back and texts the link only after the caller confirmed", async () => {
    const lookups: AmountLookup[] = [];
    const list = prices();
    const t = refFlow({ resolve: (input) => (lookups.push(input), list.resolve(input)) });
    const { callId } = await t.engine.startCall({ locale: "fr", flow: "deposit" });
    await assert.rejects(t.engine.readBackPayment(callId), rejects("precondition_failed", /badge\.verify/));
    await verify(t, callId);
    await assert.rejects(t.engine.requestPayment(callId), rejects("precondition_failed", /read back and confirmed before/));
    await assert.rejects(t.engine.readBackPayment(callId, request), rejects("invalid_input", /pass no input/));
    const back = await t.engine.readBackPayment(callId);
    assert.match(back.text, /^Le montant à payer est de 125,00\s\$, pour Repair deposit\. Est-ce exact \?$/u);
    assert.deepEqual(lookups, [
      { workspaceId: "ws_test", callId, source: "price_list", reference: "deposit.standard", subjectKey: subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT), recordIds: [] },
    ]);
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "voice" });
    assert.equal((await t.engine.requestPayment(callId)).status, "open");
    assert.equal(t.payments.created[0]!.amountMinor, 12500);
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" });
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");
    const sent = (await t.ledger.list()).find((e) => e.event === "payment.link_sent")!;
    assert.deepEqual([sent.detail.amountMinor, sent.detail.currency], [12500, "cad"]);
    assert.equal(JSON.stringify(await t.ledger.list()).includes("deposit.standard"), false, "the reference stays out of the ledger");
  });

  it("refuses an amountRef nobody can resolve, a bad answer, and a link without a read-back", async () => {
    const plain = setup();
    const call = await verifiedCall(plain);
    await assert.rejects(plain.engine.readBackPayment(call, byRef), rejects("precondition_failed", /amounts adapter/));
    await assert.rejects(plain.engine.requestPayment(call, byRef), rejects("precondition_failed", /read back and confirmed before/));
    await assert.rejects(plain.engine.readBackPayment(call), rejects("invalid_input", /outside a flow/));
    await assert.rejects(plain.engine.readBackPayment(call, { ...byRef, amountRef: "two words" }), rejects("invalid_input", /amountRef must be/));
    await assert.rejects(plain.engine.readBackPayment(call, { ...byRef, ...request }), rejects("invalid_input", /not both/));
    const unverified = await plain.engine.startCall();
    await assert.rejects(plain.engine.readBackPayment(unverified.callId, request), rejects("scope_denied"));
    await assert.rejects(plain.engine.confirmPaymentAmount(unverified.callId, { digest: "0".repeat(64), confirmedBy: "voice" }), rejects("scope_denied"));

    let answer: { amountMinor: number; currency: string } | null = { amountMinor: 0, currency: "CAD" };
    const t = setup({
      adapters: { amounts: { resolve: async () => answer } },
      config: testConfig((c) => (c.modules.paylink = { settings: { maxAmountMinor: 10000 } })),
    });
    const callId = await verifiedCall(t);
    await assert.rejects(
      t.engine.readBackPayment(callId, byRef),
      rejects("invalid_input", /^the amount source answered with a bad amount: amountMinor must be a positive integer; currency must be a lower-case ISO 4217 code$/),
    );
    answer = { amountMinor: 10001, currency: "cad" };
    await assert.rejects(t.engine.readBackPayment(callId, byRef), rejects("invalid_input", /above the limit/));
    answer = null;
    await assert.rejects(t.engine.readBackPayment(callId, byRef), rejects("precondition_failed", /no amount for this reference/));
    assert.equal((await t.ledger.list()).some((e) => e.event === "payment.amount_read_back"), false);

    const list = prices();
    assert.deepEqual(await list.resolve({ workspaceId: "w", callId: "c", source: "price_list", reference: "deposit.standard", subjectKey: "s", recordIds: [] }), { amountMinor: 12500, currency: "cad" });
    assert.equal(await list.resolve({ workspaceId: "w", callId: "c", source: "price_list", reference: "other", subjectKey: "s", recordIds: [] }), null);
    assert.equal(await list.resolve({ workspaceId: "w", callId: "c", source: "business_endpoint", reference: "deposit.standard", subjectKey: "s", recordIds: [] }), null);
  });

  it("checks the call again after the lookup, and drops a confirmation when untrusted text arrives", async () => {
    let t: TestEngine;
    let ending = false;
    t = setup({
      adapters: {
        amounts: {
          resolve: async (input) => {
            if (ending) await t.engine.endCall(input.callId);
            return prices().resolve(input);
          },
        },
      },
    });
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, byRef);
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "keypad" });
    await t.engine.markUntrusted(callId, "crm_note");
    const stored = await t.sessions.get("ws_test", callId);
    assert.equal((stored!.record as unknown as { modules: { paylink: PaylinkSlice } }).modules.paylink.quote, null);

    const other = await verifiedCall(t);
    ending = true;
    await assert.rejects(t.engine.readBackPayment(other, byRef), rejects("scope_denied"), "the call ended while the amount was looked up");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "payment.amount_read_back").length, 1);
  });

  it("binds a read-back to the subject the lookup was for", async () => {
    const OTHER = "87654321";
    const reverify = async (t: TestEngine, callId: string) => {
      await t.engine.beginVerification(callId, { accountNumber: OTHER });
      await t.engine.submitKeypad(callId, { dob: "19900101" });
      await t.engine.checkCarrier(callId);
      assert.equal((await t.engine.finishVerification(callId)).scopes.includes("payment.request"), true);
    };
    let t: TestEngine;
    let switching = false;
    t = setup({
      adapters: {
        amounts: {
          resolve: async (input) => {
            if (switching) await reverify(t, input.callId);
            return prices().resolve(input);
          },
        },
      },
    });
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: OTHER, phoneOnFile: "+15555550199", knowledge: { dob: "19900101" }, pin: "1111" }));
    t.carrier.set("+15555550199", { identityMatch: "match" });
    const raced = await verifiedCall(t);
    switching = true;
    await assert.rejects(t.engine.readBackPayment(raced, byRef), rejects("precondition_failed", /subject changed while the amount was looked up/));
    switching = false;
    assert.equal((await t.ledger.list()).some((e) => e.event === "payment.amount_read_back"), false);

    const later = await verifiedCall(t);
    const back = await t.engine.readBackPayment(later, byRef);
    await t.engine.confirmPaymentAmount(later, { digest: back.digest, confirmedBy: "keypad" });
    await reverify(t, later);
    await assert.rejects(t.engine.requestPayment(later, byRef), rejects("precondition_failed", /read back for another subject/));
    assert.equal(t.payments.created.length, 0);
  });

  it("treats a call saved without a quote as one with no read-back", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as unknown as { modules: { paylink: Partial<PaylinkSlice> } };
    delete record.modules.paylink.quote;
    assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never)).ok, true);
    await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest: "0".repeat(64), confirmedBy: "voice" }), rejects("precondition_failed", /no amount was read back/));
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /read back and confirmed before/), "no read-back, no link, on an older call too");
    await confirmAmount(t.engine, callId, request);
    assert.deepEqual(await t.engine.requestPayment(callId, request), { paymentId: "pay_1", status: "open" }, "a read-back works on an older call");
  });

  it("resumes a referenced payment with the same amountRef", async () => {
    const t = setup({ adapters: { amounts: prices() } });
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, byRef);
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "voice" });
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.requestPayment(callId, byRef), /carrier down/);
    await assert.rejects(t.engine.requestPayment(callId, { ...byRef, amountRef: "deposit.other" }), rejects("invalid_input", /same amount or amountRef/));
    t.messages.sendText = send;
    assert.deepEqual(await t.engine.requestPayment(callId, byRef), { paymentId: "pay_1", status: "open" });
    assert.equal(t.payments.created.length, 1);
    assert.equal(t.payments.created[0]!.amountMinor, 12500);

    // A read-back confirmed and sent without input: the read-back's request is the one to resume.
    const plain = setup({ adapters: { amounts: prices() } });
    const call = await verifiedCall(plain);
    const heard = await plain.engine.readBackPayment(call, byRef);
    await plain.engine.confirmPaymentAmount(call, { digest: heard.digest, confirmedBy: "voice" });
    plain.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(plain.engine.requestPayment(call), /carrier down/);
    plain.messages.sendText = send;
    assert.equal((await plain.engine.requestPayment(call, byRef)).paymentId, "pay_1");
  });
});

describe("Engine prove", () => {
  it("records consent and ends with a signed receipt that carries the ledger head", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    assert.equal(await t.engine.receipt(callId), null);
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "nope", answer: "yes" }), rejects("invalid_input"));
    const consent = await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    assert.equal(consent.channel, "call");
    assert.equal((await t.engine.recordConsent(callId, { purpose: "texts", answer: "no", channel: "text" })).channel, "text");
    const receipt = (await t.engine.endCall(callId))!;
    assert.equal(verifyReceipt(receipt, t.engine.receiptKeys()), true);
    assert.deepEqual(await t.engine.receipt(callId), receipt);
    assert.deepEqual(receipt.body.verification, { level: 3, methods: ["keypad_knowledge", "photo_id"] });
    assert.equal(receipt.body.consents.length, 2);
    const entries = await t.ledger.list();
    assert.equal(verifyChain(entries).ok, true);
    const ended = entries.find((e) => e.event === "call.ended")!;
    assert.deepEqual(receipt.body.ledger, { seq: ended.seq, hash: ended.hash });
    assert.equal(entries.at(-1)!.event, "receipt.issued");
    await assert.rejects(t.engine.endCall(callId), rejects("invalid_transition"));
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" }), rejects("invalid_transition"));
  });

  it("lists no methods on a receipt for an unverified call", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: "1" });
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.verification, { level: 0, methods: [] });
  });

  it("issues the receipt of an ended call when signing failed the first time, with the same ledger head", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    const signer = generateTestSigner();
    let fail = true;
    const flaky = { ...signer, keyId: signer.keyId, algorithm: signer.algorithm, publicJwk: () => signer.publicJwk(), sign: async (p: Uint8Array) => {
      if (fail) throw new Error("kms down");
      return signer.sign(p);
    } };
    const u = setup({ adapters: { signer: flaky } });
    const call = await u.engine.startCall();
    await assert.rejects(u.engine.endCall(call.callId), /kms down/);
    assert.equal(await u.engine.receipt(call.callId), null);
    fail = false;
    const receipt = (await u.engine.endCall(call.callId))!;
    const ended = (await u.ledger.list()).find((e) => e.event === "call.ended")!;
    assert.deepEqual(receipt.body.ledger, { seq: ended.seq, hash: ended.hash });
    assert.equal((await u.ledger.list()).filter((e) => e.event === "call.ended").length, 1, "ended once");
    await assert.rejects(u.engine.endCall(call.callId), rejects("invalid_transition"), "and only once");
    assert.equal(await t.engine.endCall(callId).then((r) => r !== null), true);
  });

  it("keeps the consent wordings a call started with when the config changes", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    t.engine.configure(testConfig((c) => (c.modules.trace = { settings: { wordings: [{ purpose: "marketing", version: "1", text: { en: "a", fr: "b" } }] } })));
    assert.equal((await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" })).purpose, "texts");
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "marketing", answer: "yes" }), rejects("invalid_input"));
  });

  it("issues no receipt when receipts are off, and keeps the ledger", async () => {
    const t = createTestEngine({ config: testConfig((c) => (c.modules.trace = { settings: { receipts: false } })), adapters: { signer: undefined } });
    const { callId } = await t.engine.startCall();
    assert.equal(await t.engine.endCall(callId), null);
    assert.deepEqual((await t.ledger.list()).map((e) => e.event), ["call.started", "call.ended"]);
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" }), rejects("invalid_input"), "no wordings");
  });

  it("builds a receipt from the modules that are on", async () => {
    const t = createTestEngine({ config: { ...defaultConfig(), modules: {} }, adapters: { records: undefined } });
    const { callId } = await t.engine.startCall();
    const receipt = (await t.engine.endCall(callId))!;
    assert.deepEqual([receipt.body.verification, receipt.body.records, receipt.body.payments, receipt.body.consents], [{ level: 0, methods: [] }, [], [], []]);
  });

  it("never writes a keyed value, an answer on file or a phone number to the ledger", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, { amountMinor: 100, currency: "cad", description: "x", amountSource: "intake_record" });
    await t.engine.requestPayment(callId, { amountMinor: 100, currency: "cad", description: "x", amountSource: "intake_record" });
    await t.engine.endCall(callId);
    const ledgerText = JSON.stringify(await t.ledger.list());
    for (const secret of [ACCOUNT, DOB, PHONE_ON_FILE, "identity.example.test", "pay.example.test"]) {
      assert.equal(ledgerText.includes(secret), false, secret);
    }
  });
});
