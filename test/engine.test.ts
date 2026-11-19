import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { ConfigError } from "../src/core/config.ts";
import { NotImplementedError } from "../src/core/errors.ts";
import type { EngineEvent } from "../src/core/events.ts";
import { defaultVerificationPolicy } from "../src/core/policy.ts";
import { INTERRUPT_LINES, bankAccountRedactor, cardNumberRedactor, composeRedactors, healthCardRedactor, sinRedactor } from "../src/core/redaction.ts";
import { createEngine } from "../src/engine.ts";
import { defaultConfig } from "../src/modules.ts";
import { formatAmount } from "../src/pay/paylink.ts";
import { MemoryAuditLedger, verifyChain } from "../src/prove/ledger.ts";
import { verifyReceipt } from "../src/prove/receipt.ts";
import { FakeCarrierSignals, FakeIdentityProvider, FakeMessageSender, FakePaymentLinks, MemoryRecordStore, generateTestSigner } from "../src/testing/fakes.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

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

  it("speaks the line for what was found, in the call's language", async () => {
    const redactor = composeRedactors(cardNumberRedactor, healthCardRedactor, sinRedactor, bankAccountRedactor);
    const t = setup({ redactor });
    const en = (await t.engine.startCall()).callId;
    const fr = (await t.engine.startCall({ locale: "fr" })).callId;
    assert.equal((await t.engine.redact(en, "my SIN is 046 454 286")).line, INTERRUPT_LINES.sin.en);
    assert.equal((await t.engine.redact(fr, "mon NAS est le 046 454 286")).line, INTERRUPT_LINES.sin.fr);
    assert.equal((await t.engine.redact(fr, "carte santé 1234 567 897")).line, INTERRUPT_LINES.health_card.fr);
    assert.equal((await t.engine.redact(en, "account 1234567")).line, INTERRUPT_LINES.bank_account.en);
    assert.equal((await t.engine.redact(en, "account 1234567, card 4242 4242 4242 4242")).line, INTERRUPT_LINES.card_number.en, "a card number's line comes first");
    assert.equal((await t.engine.redact(en, "nothing here")).line, null);
    for (const lines of Object.values(INTERRUPT_LINES)) assert.ok(lines.en !== "" && lines.fr !== "" && lines.en !== lines.fr);
    assert.equal(INTERRUPT_LINES.sin.en.includes("card"), false, "no card wording for a SIN");
  });

  it("redacts text and counts findings by kind, without logging the text", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    assert.deepEqual(await t.engine.redact(callId, "hello"), { text: "hello", findings: [], interrupt: false, line: null });
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
    await t.engine.requestPayment(callId, { ...request, amountMinor: 150, currency: "jpy" });
    assert.equal(t.messages.sent.at(-1)!.body, `Votre lien de paiement sécurisé pour ${formatAmount("fr", 150, "jpy")} : https://pay.example.test/c/cs_fake_1`);
    await t.engine.endCall(callId);
    const result = await t.engine.applyPaymentOutcome({ kind: "expired", linkId: "cs_fake_1" });
    assert.deepEqual(result, { applied: true, callId, status: "expired" });
    assert.equal((await t.engine.state(callId)).phase, "ended");
  });

  it("refuses without the scope, without an amount, and refuses bad amounts and descriptions", async () => {
    const t = setup({ config: testConfig((c) => (c.modules.paylink = { settings: { maxAmountMinor: 10000 } })) });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("scope_denied"));
    const verified = await verifiedCall(t);
    await assert.rejects(t.engine.requestPayment(verified), rejects("invalid_input", /outside a flow/));
    await assert.rejects(t.engine.requestPayment(verified, request), /above the limit/);
    await assert.rejects(t.engine.requestPayment(verified, { ...request, amountMinor: 100, description: "  " }), /description/);
    await assert.rejects(t.engine.requestPayment(verified, { ...request, amountMinor: 100, description: "x".repeat(201) }), /description/);
    await assert.rejects(t.engine.requestPayment(verified, { ...request, amountMinor: 100, amountSource: "model" as never }), /amountSource/);
    await assert.rejects(t.engine.requestPayment(verified, { ...request, amountMinor: "100" as never }), /amountMinor and currency are required/);
  });

  it("keeps a request open when creating or texting its link fails, and resumes it with the same keys", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const create = t.payments.createLink.bind(t.payments);
    t.payments.createLink = async () => {
      throw new Error("provider timed out");
    };
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
    assert.equal((await t.engine.requestPayment(callId, { ...request, amountMinor: 1_000_000 })).status, "open");
  });

  it("formats amounts with the currency's own decimals", () => {
    assert.equal(formatAmount("en", 15000, "cad"), "$150.00");
    assert.match(formatAmount("en", 150, "jpy"), /^JP¥150$|^¥150$/u);
    assert.match(formatAmount("fr", 15000, "cad"), /^150,00\s\$$/u);
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
    await t.engine.requestPayment(callId, { amountMinor: 100, currency: "cad", description: "x", amountSource: "intake_record" });
    await t.engine.endCall(callId);
    const ledgerText = JSON.stringify(await t.ledger.list());
    for (const secret of [ACCOUNT, DOB, PHONE_ON_FILE, "identity.example.test", "pay.example.test"]) {
      assert.equal(ledgerText.includes(secret), false, secret);
    }
  });
});
