import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { EngineError, NotImplementedError, type EngineErrorCode } from "../src/core/errors.ts";
import type { EngineEvent } from "../src/core/events.ts";
import { defaultVerificationPolicy } from "../src/core/policy.ts";
import { createEngine, formatAmount } from "../src/engine.ts";
import type { IntakeForm } from "../src/file/intake.ts";
import { verifyChain } from "../src/prove/ledger.ts";
import { verifyReceipt } from "../src/prove/receipt.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { FakeCarrierSignals, FakeIdentityProvider, FakeMessageSender, FakePaymentLinks, MemoryRecordStore, generateTestSigner } from "../src/testing/fakes.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";

const ACCOUNT = "12345678";
const DOB = "19850214";
const PHONE_ON_FILE = "+15555550100";

const form: IntakeForm = {
  formId: "repair",
  version: "1",
  fields: [
    { key: "issue", label: { en: "Issue", fr: "Problème" }, type: "text", required: true },
    { key: "urgent", label: { en: "Urgent", fr: "Urgent" }, type: "yes_no", required: false },
  ],
};

const wording = { purpose: "texts", version: "1", text: { en: "May we text you?", fr: "Pouvons-nous vous texter?" } };

function setup(options: Parameters<typeof createTestEngine>[0] = {}): TestEngine {
  const t = createTestEngine(options);
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } }));
  return t;
}

const rejects = (code: EngineErrorCode) => (e: unknown) => e instanceof EngineError && e.code === code;

/** A call verified to level 3 by keypad and photo ID, in the open phase. */
async function verifiedCall(t: TestEngine, locale: "en" | "fr" = "en"): Promise<string> {
  const { callId } = await t.engine.startCall({ locale });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
  await t.engine.startPhotoId(callId);
  const sessionId = t.identity.created.at(-1)!.sessionId;
  assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: true, callId });
  assert.equal((await t.engine.finishVerification(callId)).level, 3);
  return callId;
}

describe("Engine construction", () => {
  it("refuses a bad policy, a short key, a bad grant lifetime and an empty workspace", () => {
    const adapters = createTestEngine();
    const base = {
      workspaceId: "w",
      knowledgeKey: TEST_KNOWLEDGE_KEY,
      adapters: {
        identity: adapters.identity,
        carrier: adapters.carrier,
        messages: adapters.messages,
        payments: adapters.payments,
        records: adapters.records,
        ledger: adapters.ledger,
        signer: generateTestSigner(),
      },
    };
    assert.throws(() => createEngine({ ...base, policy: { ...defaultVerificationPolicy(), keypadFields: [] } }), /keypadFields is empty/);
    assert.throws(() => createEngine({ ...base, knowledgeKey: "short" }), /at least 16 bytes/);
    assert.throws(() => createEngine({ ...base, knowledgeKey: new Uint8Array(15) }), /at least 16 bytes/);
    assert.throws(() => createEngine({ ...base, grantTtlSeconds: 0 }), /grantTtlSeconds/);
    assert.throws(() => createEngine({ ...base, grantTtlSeconds: 3601 }), /grantTtlSeconds/);
    assert.throws(() => createEngine({ ...base, grantTtlSeconds: 1.5 }), /grantTtlSeconds/);
    assert.throws(() => createEngine({ ...base, workspaceId: "" }), rejects("invalid_input"));
    const engine = createEngine({ ...base, knowledgeKey: new Uint8Array(16) });
    assert.equal(engine.workspaceId, "w");
    assert.deepEqual(engine.policy, defaultVerificationPolicy());
  });

  it("runs on the system clock and random ids by default", async () => {
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
    assert.throws(() => t.engine.state("nope"), rejects("unknown_call"));
    assert.equal(t.engine.state("c1").callId, "c1");
  });

  it("reports every event to the listener and the ledger, in order", async () => {
    const events: EngineEvent[] = [];
    const t = setup({ onEvent: (e) => events.push(e) });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.openSensitive(callId, "keypad"), rejects("invalid_transition"));
    await t.engine.markUntrusted(callId, "business_endpoint");
    assert.deepEqual(
      events.map((e) => e.name),
      ["call.started", "session.tainted"],
    );
    assert.deepEqual(events[1]!.detail, { source: "business_endpoint" });
    const entries = await t.ledger.list();
    assert.deepEqual(entries.map((e) => e.event), ["call.started", "session.tainted"]);
    assert.equal(t.engine.state(callId).tainted, true);
  });

  it("opens and closes the keypad segment during verification", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.openSensitive(callId, "keypad"), rejects("invalid_transition"));
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.openSensitive(callId, "keypad");
    assert.equal(t.engine.state(callId).sensitive, "keypad");
    await t.engine.closeSensitive(callId);
    assert.equal(t.engine.state(callId).sensitive, null);
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
    const state = t.engine.state(callId);
    assert.equal(state.level, 3);
    assert.deepEqual(state.grant?.scopes, ["contact.update", "intake.file", "payment.request", "payout.update", "status.read"]);
    assert.equal(state.grant?.expiresAt, "2026-01-01T00:15:00.000Z");
    assert.deepEqual(t.messages.sent.map((m) => [m.to, m.purpose]), [[PHONE_ON_FILE, "identity_link"]]);
    assert.match(t.messages.sent[0]!.body, /^Your one-time identity check link: https:\/\/identity\.example\.test\//);
    const events = (await t.ledger.list()).map((e) => e.event);
    assert.deepEqual(events, [
      "call.started",
      "verification.started",
      "verification.factor",
      "identity.link_sent",
      "verification.factor",
      "verification.finished",
      "grant.issued",
    ]);
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
      assert.equal(t.engine.state(callId).grant, null);
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
    assert.equal(t.engine.state(callId).factors.length, 2);
  });

  it("asks the carrier about the number on file after a match, and records identity match", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.checkCarrier(callId), rejects("precondition_failed"));
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.deepEqual(await t.engine.checkCarrier(callId), { textCodeTrusted: true });
    assert.deepEqual(t.carrier.checked, [PHONE_ON_FILE]);
    assert.equal(t.engine.state(callId).factors.length, 1, "identity match unavailable records nothing");
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match", lastSimSwapHoursAgo: 3 });
    assert.deepEqual(await t.engine.checkCarrier(callId), { textCodeTrusted: false });
    assert.deepEqual(await t.engine.finishVerification(callId), {
      level: 2,
      scopes: ["intake.file", "payment.request", "status.read"],
    });
    const carrierEvent = (await t.ledger.list()).find((e) => e.event === "verification.carrier_checked" && e.detail.identityMatch === "match");
    assert.deepEqual(carrierEvent?.detail, { checked: true, textCodeTrusted: false, identityMatch: "match" });
  });

  it("records a carrier identity mismatch as a failed factor", async () => {
    const t = setup();
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "no_match" });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    assert.deepEqual(t.engine.state(callId).factors.map((f) => [f.kind, f.passed]), [
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
    assert.equal(t.engine.state(callId).phase, "verifying");
    const s = t.engine.state(callId);
    assert.equal(s.factors.length, 1, "the step-up kept the keypad factor");
  });

  it("starts over on another account number", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: "87654321" });
    assert.equal(t.engine.state(callId).factors.length, 0);
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
});

describe("Engine authorize", () => {
  it("refuses unknown scopes, ended calls, missing and expired grants", async () => {
    const policy = { ...defaultVerificationPolicy(), scopes: { ...defaultVerificationPolicy().scopes, "hours.read": 0 as const } };
    const t = setup({ policy, grantTtlSeconds: 60 });
    const { callId } = await t.engine.startCall();
    assert.equal(t.engine.authorize(callId, "hours.read"), true);
    assert.equal(t.engine.authorize(callId, "status.read"), false);
    assert.equal(t.engine.authorize(callId, "made.up"), false);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    assert.equal(t.engine.authorize(callId, "status.read"), true);
    assert.equal(t.engine.authorize(callId, "payment.request"), false);
    t.clock.advance(60_000);
    assert.equal(t.engine.authorize(callId, "status.read"), false, "expired");
    await t.engine.endCall(callId);
    assert.equal(t.engine.authorize(callId, "hours.read"), false);
  });

  it("drops the grant when untrusted text enters, and re-verification starts from nothing", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.markUntrusted(callId, "document");
    assert.equal(t.engine.authorize(callId, "status.read"), false);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal(t.engine.state(callId).factors.length, 0);
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
    assert.equal(t.engine.state(callId).phase, "verifying");
    const sessionId = t.identity.created.at(-1)!.sessionId;
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: false });
    const otherSession = t.identity.created[0]!.sessionId;
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId: otherSession, status: "verified" }), { applied: true, callId: other.callId }, "other calls keep theirs");
  });
});

describe("Engine file", () => {
  it("files a confirmed record with its digest", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, form);
    assert.deepEqual(t.engine.setIntakeField(callId, "issue", "4242 4242 4242 4242"), { ok: false, reason: "card_number" });
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), /required fields missing: issue/);
    assert.deepEqual(t.engine.setIntakeField(callId, "issue", " Leak under sink "), { ok: true, value: "Leak under sink" });
    t.engine.setIntakeField(callId, "urgent", "yes");
    assert.throws(() => t.engine.setIntakeField(callId, "nope", "x"), rejects("invalid_input"));
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad" });
    assert.deepEqual(record.values, { issue: "Leak under sink", urgent: true });
    assert.deepEqual(await t.records.getIntakeRecord("ws_test", record.recordId), record);
    assert.equal(await t.records.getIntakeRecord("ws_test", "rec_404"), null);
    assert.deepEqual(t.engine.state(callId).recordIds, [record.recordId]);
    assert.throws(() => t.engine.setIntakeField(callId, "issue", "x"), rejects("invalid_transition"));
  });

  it("refuses intake without the scope, a bad form, and sensitive fields until encryption exists", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.startIntake(callId, form), rejects("scope_denied"));
    const verified = await verifiedCall(t);
    await assert.rejects(t.engine.startIntake(verified, { ...form, fields: [] }), rejects("invalid_input"));
    const sensitive = { ...form, fields: [{ ...form.fields[0]!, sensitive: true }] };
    await assert.rejects(t.engine.startIntake(verified, sensitive), (e: unknown) => e instanceof NotImplementedError && e.issue === "FIL-2");
    await t.engine.startIntake(verified, form);
    await t.engine.abandonIntake(verified);
    assert.equal(t.engine.state(verified).phase, "open");
    await assert.rejects(t.engine.confirmIntake(verified, { confirmedBy: "voice" }), rejects("invalid_transition"));
  });

  it("re-checks the grant at confirmation", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, form);
    t.engine.setIntakeField(callId, "issue", "leak");
    t.clock.advance(15 * 60_000);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), rejects("scope_denied"));
  });
});

describe("Engine pay", () => {
  const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };

  it("texts a link to the number on file and settles only on paid", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const { paymentId } = await t.engine.requestPayment(callId, request);
    assert.equal(t.engine.state(callId).phase, "paying");
    assert.equal(t.engine.state(callId).sensitive, "payment");
    const text = t.messages.sent.at(-1)!;
    assert.equal(text.to, PHONE_ON_FILE);
    assert.equal(text.purpose, "payment_link");
    assert.equal(text.body, "Your secure payment link for $150.00: https://pay.example.test/c/cs_fake_1");
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("invalid_transition"));
    const linkId = t.payments.created[0]!.linkId;
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId, paymentStatus: "unpaid" }), { applied: false });
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "async_succeeded", linkId }), { applied: true, callId, status: "paid" });
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "async_failed", linkId }), { applied: false }, "settled once");
    assert.equal(t.engine.state(callId).phase, "open");
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "expired", linkId: "cs_unknown" }), { applied: false });
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt.body.payments, [{ paymentId, status: "paid", amountMinor: 15000, currency: "cad", providerRef: linkId }]);
  });

  it("settles a payment after the call ended without moving the session", async () => {
    const t = setup();
    const callId = await verifiedCall(t, "fr");
    await t.engine.requestPayment(callId, { ...request, amountMinor: 150, currency: "jpy" });
    assert.equal(t.messages.sent.at(-1)!.body, `Votre lien de paiement sécurisé pour ${formatAmount("fr", 150, "jpy")} : https://pay.example.test/c/cs_fake_1`);
    await t.engine.endCall(callId);
    const result = await t.engine.applyPaymentOutcome({ kind: "expired", linkId: "cs_fake_1" });
    assert.deepEqual(result, { applied: true, callId, status: "expired" });
    assert.equal(t.engine.state(callId).phase, "ended");
  });

  it("refuses without the scope, and refuses bad amounts and descriptions", async () => {
    const t = setup({ maxPaymentMinor: 10000 });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("scope_denied"));
    const verified = await verifiedCall(t);
    await assert.rejects(t.engine.requestPayment(verified, request), /above the limit/);
    await assert.rejects(t.engine.requestPayment(verified, { ...request, amountMinor: 100, description: "  " }), /description/);
    await assert.rejects(t.engine.requestPayment(verified, { ...request, amountMinor: 100, description: "x".repeat(201) }), /description/);
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
    assert.equal(t.engine.receipt(callId), null);
    const consent = await t.engine.recordConsent(callId, { wording, answer: "yes" });
    assert.equal(consent.channel, "call");
    assert.equal((await t.engine.recordConsent(callId, { wording, answer: "no", channel: "text" })).channel, "text");
    const receipt = await t.engine.endCall(callId);
    assert.equal(verifyReceipt(receipt, t.engine.receiptKeys()), true);
    assert.deepEqual(t.engine.receipt(callId), receipt);
    assert.deepEqual(receipt.body.verification, { level: 3, methods: ["keypad_knowledge", "photo_id"] });
    assert.equal(receipt.body.consents.length, 2);
    const entries = await t.ledger.list();
    const check = verifyChain(entries);
    assert.equal(check.ok, true);
    const ended = entries.find((e) => e.event === "call.ended")!;
    assert.deepEqual(receipt.body.ledger, { seq: ended.seq, hash: ended.hash });
    assert.equal(entries.at(-1)!.event, "receipt.issued");
    await assert.rejects(t.engine.endCall(callId), rejects("invalid_transition"));
    await assert.rejects(t.engine.recordConsent(callId, { wording, answer: "yes" }), rejects("invalid_transition"));
  });

  it("lists no methods on a receipt for an unverified call", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: "1" });
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt.body.verification, { level: 0, methods: [] });
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
