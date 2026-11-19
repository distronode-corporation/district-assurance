import { strict as assert } from "node:assert";
import { createHmac } from "node:crypto";
import { describe, it } from "node:test";

import type { IntakeRecord, PaymentLinks } from "../src/core/adapters.ts";
import { canonicalJson, type JsonValue } from "../src/core/canonical.ts";
import { ConfigError } from "../src/core/config.ts";
import { hmacSha256Hex } from "../src/core/hash.ts";
import type { EngineEvent } from "../src/core/events.ts";
import { defaultVerificationPolicy } from "../src/core/policy.ts";
import { createEngine } from "../src/engine.ts";
import { intakeDigest, type IntakeForm } from "../src/file/intake.ts";
import { defaultConfig } from "../src/modules.ts";
import { formatAmount } from "../src/pay/paylink.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { MemoryAuditLedger, verifyChain } from "../src/prove/ledger.ts";
import { verifyReceipt } from "../src/prove/receipt.ts";
import { FakeCarrierSignals, FakeFieldCipher, FakeIdentityProvider, FakeMessageSender, FakePaymentLinks, MemoryAttemptCounters, MemoryRecordStore, generateTestSigner } from "../src/testing/fakes.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine } from "../src/testing/index.ts";
import { ACCOUNT, confirmAmount, DOB, PHONE_ON_FILE, PIN, form, heard, rejects, setup, testConfig, verifiedCall, waitOut } from "./helpers.ts";

/** The digest of the read-back the caller heard, or any digest once no draft is open (a filed or released intake asks for none). */
async function readBackOf(t: { engine: { intakeReadBack(callId: string): Promise<{ digest: string }> } }, callId: string): Promise<string> {
  return t.engine.intakeReadBack(callId).then((r) => r.digest, () => "0".repeat(64));
}

describe("Engine construction", () => {
  it("refuses a short key, an empty workspace, a missing ledger and a bad config", () => {
    const base = { workspaceId: "w", knowledgeKey: TEST_KNOWLEDGE_KEY, adapters: { ledger: new MemoryAuditLedger() }, config: { ...defaultConfig(), modules: { trace: { settings: { receipts: false } } } } };
    assert.throws(() => createEngine({ ...base, knowledgeKey: "short" }), /at least 16 bytes/);
    assert.throws(() => createEngine({ ...base, knowledgeKey: new Uint8Array(15) }), /at least 16 bytes/);
    assert.throws(() => createEngine({ ...base, workspaceId: "" }), rejects("invalid_input", /workspaceId must be a non-empty string/));
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

  it("takes the knowledge key as an asynchronous HMAC function (a KMS), and uses it for its own hashing too", async () => {
    // A stand-in for a key management service: every answer comes back on a later turn of the
    // event loop, as a network call's would, and the engine gets the function, never the key.
    const asked: string[] = [];
    const kms = async (data: string): Promise<string> => {
      asked.push(data.split(":")[0]!);
      await new Promise((resolve) => setImmediate(resolve));
      return createHmac("sha256", TEST_KNOWLEDGE_KEY).update(data).digest("hex");
    };
    const t = setup({ knowledgeKey: kms });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: true, locked: false });
    // The duress digest (VER-12) and the PIN entry's keyed tag go through it too.
    assert.deepEqual(asked.slice(0, 4), ["subject", "field", "pin", "duress"], "the subject key, the keypad field and the PIN all went through the function");
    assert.equal(asked.length, 5);
    assert.ok(asked[4]!.startsWith('["pin.tag",'), "the PIN entry's tag");
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    assert.equal(JSON.stringify(await t.ledger.list()).includes(DOB), false);

    // A wrong PIN through the KMS is a wrong answer, judged the same way.
    const other = await t.engine.startCall();
    await t.engine.beginVerification(other.callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitPin(other.callId, "9999"), { matched: false, locked: false });
  });

  it("fails closed when the KMS rejects: no factor, the attempt counted, and nothing it was asked in the ledger or the events", async () => {
    let down = false;
    const asked: string[] = [];
    const kms = async (data: string): Promise<string> => {
      await new Promise((resolve) => setImmediate(resolve));
      if (down && !data.startsWith("subject:")) {
        asked.push(data);
        throw new Error("kms unavailable");
      }
      return createHmac("sha256", TEST_KNOWLEDGE_KEY).update(data).digest("hex");
    };
    const seen: unknown[] = [];
    const t = setup({ knowledgeKey: kms, onEvent: (event) => void seen.push(event) });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    down = true;
    await assert.rejects(t.engine.submitKeypad(callId, { dob: DOB }), /kms unavailable/);
    await assert.rejects(t.engine.submitPin(callId, PIN), /kms unavailable/);
    assert.equal(asked.length, 2, "the KMS was asked for the keypad field and the PIN");
    const entries = await t.ledger.list();
    const events = entries.map((e) => e.event);
    assert.deepEqual(events.slice(-2), ["verification.factor_error", "verification.factor_error"]);
    assert.equal(events.includes("verification.factor"), false, "a failure is never a factor");
    assert.equal((await t.engine.state(callId)).factors.length, 0);
    const written = JSON.stringify([entries, seen]);
    for (const secret of [DOB, PIN, ...asked, ...asked.map((d) => createHmac("sha256", TEST_KNOWLEDGE_KEY).update(d).digest("hex"))]) {
      assert.equal(written.includes(secret), false, "no entry, digest or question of the KMS is written");
    }
    // The failed attempts are not refunded: the PIN has 2 of its 3 left once the KMS is back.
    down = false;
    // Each failure starts a wait across calls (VER-1): waited out before each try.
    waitOut(t);
    assert.deepEqual(await t.engine.submitPin(callId, "9999"), { matched: false, locked: false });
    waitOut(t);
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: true, locked: false });

    // An outage that uses up every keypad attempt locks the call, even after the KMS recovers.
    const second = await t.engine.startCall();
    await t.engine.beginVerification(second.callId, { accountNumber: ACCOUNT });
    down = true;
    for (let i = 0; i < 2; i++) {
      waitOut(t);
      await assert.rejects(t.engine.submitKeypad(second.callId, { dob: DOB }), /kms unavailable/);
    }
    down = false;
    waitOut(t);
    assert.deepEqual(await t.engine.submitKeypad(second.callId, { dob: DOB }), { matched: false, locked: true });
  });

  it("refuses an HMAC function whose answer is not 64 lower-case hex characters, without quoting it", async () => {
    for (const answer of ["AB".repeat(32), "ab".repeat(31), 42 as unknown as string]) {
      const t = setup({ knowledgeKey: async () => answer });
      const { callId } = await t.engine.startCall();
      await assert.rejects(t.engine.beginVerification(callId, { accountNumber: ACCOUNT }), (e: unknown) => rejects("invalid_input", /knowledge HMAC function/)(e) && !(e as Error).message.includes(String(answer)));
    }
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
        counters: new MemoryAttemptCounters(),
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
    assert.deepEqual(events[0]!.detail, { locale: "en", revision: "default", attestation: "none" });
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
    waitOut(t);
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: "2" }), { matched: false, locked: true });
    waitOut(t);
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

  it("lets the texted session apply its outcome when a resume gets a new session, without duplicating a repeated one", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.startPhotoId(callId), /carrier down/);
    // Same key, same session (within the provider's retention window): still one entry.
    await assert.rejects(t.engine.startPhotoId(callId), /carrier down/);
    const first = t.identity.created[0]!.sessionId;
    // The provider pruned the key: a later resume gets a new session, and that link is texted.
    const create = t.identity.createDocumentCheck.bind(t.identity);
    t.identity.createDocumentCheck = (input) => create({ ...input, idempotencyKey: `${input.idempotencyKey}:pruned` });
    t.messages.sendText = send;
    await t.engine.startPhotoId(callId);
    const texted = t.identity.created[1]!.sessionId;
    assert.notEqual(texted, first);
    assert.ok(t.messages.sent.at(-1)!.body.endsWith(texted));
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId: texted, status: "verified" }), { applied: true, callId });
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId: texted, status: "verified" }), { applied: false }, "single use");
  });

  it("texts no code before a keypad match, nor after a wrong entry or for an unknown account", async () => {
    const t = setup({ config: testConfig((c) => {
      c.modules.badge = { settings: { factors: ["keypad_knowledge", "text_code"] } };
      c.policy.textCodeCountryCodes = ["1"];
    }) });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.sendTextCode(callId), rejects("precondition_failed"), "before verification");
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.sendTextCode(callId), rejects("precondition_failed"), "before any entry");
    await t.engine.submitKeypad(callId, { dob: "19000101" });
    await assert.rejects(t.engine.sendTextCode(callId), rejects("precondition_failed"), "after a wrong entry");
    const other = await t.engine.startCall();
    await t.engine.beginVerification(other.callId, { accountNumber: "99999999" });
    await t.engine.submitKeypad(other.callId, { dob: DOB });
    await assert.rejects(t.engine.sendTextCode(other.callId), rejects("precondition_failed"), "unknown account");
    assert.equal(t.messages.sent.length, 0);
    // Past the wait VER-1 puts after the wrong entry.
    waitOut(t);
    assert.equal((await t.engine.submitKeypad(callId, { dob: DOB })).matched, true);
    assert.deepEqual(await t.engine.sendTextCode(callId), { sent: true });
    for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve));
    assert.equal(t.messages.sent.length, 1);
    assert.deepEqual({ to: t.messages.sent[0]!.to, purpose: t.messages.sent[0]!.purpose }, { to: PHONE_ON_FILE, purpose: "one_time_code" });
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

  it("sends nothing out on a match made before the taint, until a fresh verification matches", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.markUntrusted(callId, "crm_note");
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"), "no identity link on the old match");
    await assert.rejects(t.engine.checkCarrier(callId), rejects("precondition_failed"), "no carrier check on the old match");
    assert.equal(t.messages.sent.length, 0);
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    assert.equal(t.messages.sent.length, 1, "a fresh match unlocks the link again");
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

describe("Engine file: text the record cannot carry", () => {
  it("refuses a field value with a lone surrogate at setIntakeField, so confirmIntake never throws (review of 1d52bfb, A5)", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    // #76: a lone surrogate is a refused answer (`not_text`), not a host error.
    assert.deepEqual(await t.engine.setIntakeField(callId, "issue", "leak \ud83d"), { ok: false, reason: "not_text" });
    await assert.rejects(t.engine.setIntakeField(callId, "issue", 7 as never), rejects("invalid_input"));
    assert.deepEqual(await t.engine.setIntakeField(callId, "issue", "leak \ud83d\ude00"), { ok: true, value: "leak \ud83d\ude00" }, "a valid pair is fine");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
    assert.equal(record.values.issue, "leak \ud83d\ude00");
  });
});

describe("Engine file", () => {
  it("files a confirmed record with its digest", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    assert.deepEqual(await t.engine.setIntakeField(callId, "issue", "4242 4242 4242 4242"), { ok: false, reason: "card_number" });
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), /required fields missing: issue/);
    assert.deepEqual(await t.engine.setIntakeField(callId, "issue", " Leak under sink "), { ok: true, value: "Leak under sink" });
    await t.engine.setIntakeField(callId, "urgent", "yes");
    await assert.rejects(t.engine.setIntakeField(callId, "nope", "x"), rejects("invalid_input"));
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad", readBack: await heard(t, callId) });
    assert.deepEqual(record.values, { issue: "Leak under sink", urgent: true });
    assert.deepEqual(await t.records.getIntakeRecord("ws_test", record.recordId), record);
    assert.equal(await t.records.getIntakeRecord("ws_test", "rec_404"), null);
    assert.deepEqual((await t.engine.state(callId)).recordIds, [record.recordId]);
    await assert.rejects(t.engine.setIntakeField(callId, "issue", "x"), rejects("invalid_transition"));
  });

  it("reads the draft back in the call's locale, and refuses a confirmation of a draft changed since", async () => {
    const t = setup();
    const callId = await verifiedCall(t, "fr");
    await assert.rejects(t.engine.intakeReadBack(callId), rejects("invalid_transition"));
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "Fuite");
    const before = await t.engine.intakeReadBack(callId);
    assert.equal(before.text, "Voici ce que nous allons enregistrer. Problème : Fuite. Est-ce exact? Dites oui ou appuyez sur le 1 pour confirmer.");
    await t.engine.setIntakeField(callId, "urgent", "oui");
    const changed = rejects("precondition_failed", /changed since the caller heard its read-back/);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: before.digest }), changed);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: before.digest.toUpperCase() }), changed);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: undefined as unknown as string }), changed);
    assert.deepEqual((await t.engine.state(callId)).recordIds, [], "nothing filed");
    assert.equal((await t.ledger.list()).some((e) => e.event === "intake.confirmed"), false);
    const after = await t.engine.intakeReadBack(callId);
    assert.match(after.text, /Urgent : oui\./);
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: after.digest });
    assert.deepEqual(record.values, { issue: "Fuite", urgent: true });
    assert.equal(record.digest, intakeDigest(form, record.values));
  });

  it("asks, reads back and files a conditional field only while its showIf holds", async () => {
    const branching: IntakeForm = {
      formId: "repair",
      version: "1",
      fields: [
        ...form.fields,
        { key: "since", label: { en: "Since", fr: "Depuis" }, type: "date", required: true, showIf: { field: "urgent", equals: true }, min: "2026-01-01" },
      ],
    };
    const t = setup({ config: testConfig((c) => (c.modules.dossier = { settings: { forms: [branching] } as unknown as JsonValue })) });
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    await assert.rejects(t.engine.setIntakeField(callId, "since", "2026-09-01"), rejects("precondition_failed", /since is not asked/));
    await t.engine.setIntakeField(callId, "urgent", "yes");
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), rejects("invalid_input", /required fields missing: since/));
    assert.deepEqual(await t.engine.setIntakeField(callId, "since", "2025-12-31"), { ok: false, reason: "below_min" });
    await t.engine.setIntakeField(callId, "since", "2026-09-01");
    assert.match((await t.engine.intakeReadBack(callId)).text, /Since: Tuesday, September 1, 2026\./);
    await t.engine.setIntakeField(callId, "urgent", "no");
    const readBack = await t.engine.intakeReadBack(callId);
    assert.doesNotMatch(readBack.text, /Since/, "a hidden field is not read back");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: readBack.digest });
    assert.deepEqual(record.values, { issue: "leak", urgent: false }, "nor filed");
    assert.equal(record.digest, intakeDigest(branching, record.values));
  });

  it("refuses a read-back on a call that started without Dossier", async () => {
    const t = setup({ config: testConfig((c) => (c.modules.dossier = { enabled: false })) });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.intakeReadBack(callId), rejects("module_disabled", /turned off/));
    t.engine.configure(testConfig());
    await assert.rejects(t.engine.intakeReadBack(callId), rejects("module_disabled", /was off when this call started/));
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
    await assert.rejects(t.engine.confirmIntake(verified, { confirmedBy: "voice", readBack: "0".repeat(64) }), rejects("invalid_transition"));
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
        second = t.engine.confirmIntake(callId, { confirmedBy: "keypad", readBack: await heard(t, callId) });
        await second;
      }
      return put(record);
    };
    const first = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
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
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), rejects("scope_denied"));
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
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), /database down/);
    assert.ok(during.every((r) => (r as PromiseSettledResult<unknown>).status === "rejected" && rejects("precondition_failed")((r as PromiseRejectedResult).reason)));
    t.records.putIntakeRecord = put;
    await assert.rejects(t.engine.setIntakeField(callId, "issue", "changed"), rejects("precondition_failed"), "still reserved after the failed write");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad", readBack: await heard(t, callId) });
    assert.deepEqual([record.recordId, record.values.issue, record.confirmedBy], ["rec_1", "leak", "voice"], "the same record, written again");
  });

  describe("sensitive fields", () => {
    // Not a SIN: #76 refuses a field that names one, so FIL-2 is shown on a policy number (rehearsal).
    const SIN = "046 454 286"; // a made-up number, not a secret
    const secure: IntakeForm = {
      formId: "secure",
      version: "1",
      fields: [
        { key: "issue", label: { en: "Issue", fr: "Problème" }, type: "text", required: true },
        { key: "policy", label: { en: "Policy number", fr: "Numéro de police" }, type: "text", required: true, sensitive: true },
        { key: "pets", label: { en: "Pets", fr: "Animaux" }, type: "number", required: false, sensitive: true },
      ],
    };
    const withSecure = () => testConfig((c) => (c.modules.dossier = { settings: { forms: [structuredClone(form), structuredClone(secure)] } as unknown as JsonValue }));
    /** The digest the engine must give: the plaintext, with each sensitive value as an HMAC bound to the record and field. */
    const expectedDigest = (recordId: string, values: Record<string, string | number>) => {
      const covered: Record<string, string | number> = { ...values };
      for (const key of ["policy", "pets"]) if (key in values) covered[key] = hmacSha256Hex(TEST_KNOWLEDGE_KEY, canonicalJson(["intake", recordId, key, values[key]!]));
      return intakeDigest(secure, covered);
    };

    it("stores ciphertext, with a digest that does not depend on it and that stays the same on a retry", async () => {
      const cipher = new FakeFieldCipher();
      const t = setup({ config: withSecure(), adapters: { fieldCipher: cipher } });
      const callId = await verifiedCall(t);
      await t.engine.startIntake(callId, "secure");
      await t.engine.setIntakeField(callId, "issue", "Leak");
      await t.engine.setIntakeField(callId, "policy", SIN);
      const put = t.records.putIntakeRecord.bind(t.records);
      const attempts: IntakeRecord[] = [];
      t.records.putIntakeRecord = async (record) => {
        attempts.push(structuredClone(record));
        if (attempts.length === 1) throw new Error("database down");
        return put(record);
      };
      await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) }), /database down/);
      const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) });
      assert.equal(record.values.issue, "Leak", "a field that is not sensitive stays in the clear");
      assert.equal(Object.hasOwn(record.values, "pets"), false, "an optional sensitive field left empty is not encrypted");
      assert.match(String(record.values.policy), /^fake-cipher:2:/);
      assert.equal(cipher.decrypt(String(record.values.policy)), SIN);
      assert.deepEqual(cipher.encrypted, [1, 2].map(() => ({ workspaceId: "ws_test", recordId: record.recordId, field: "policy" })), "encrypted again on the retry");
      assert.notEqual(attempts[0]!.values.policy, attempts[1]!.values.policy, "a different ciphertext each time");
      assert.equal(attempts[0]!.digest, attempts[1]!.digest, "the same digest each time");
      assert.equal(record.digest, expectedDigest(record.recordId, { issue: "Leak", policy: SIN }));
      assert.notEqual(record.digest, intakeDigest(secure, { issue: "Leak", policy: SIN }), "a receipt is no oracle for the plain value");
      assert.notEqual(record.digest, intakeDigest(secure, { issue: "Leak", policy: String(record.values.policy) }), "nor the ciphertext");
      assert.deepEqual(await t.records.getIntakeRecord("ws_test", record.recordId), record);
      // Filed: the intake is closed, so no read-back is asked for (any digest).
      assert.equal(await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: "0".repeat(64) }).then((r) => r.values.policy), record.values.policy, "a retry after filing returns the stored record");
      const receipt = (await t.engine.endCall(callId))!;
      assert.equal(receipt.body.records[0]!.digest, record.digest);
      const stored = JSON.stringify([await t.sessions.get("ws_test", callId), await t.ledger.list(), receipt]);
      assert.equal(stored.includes(SIN), false, "the call record, the ledger and the receipt keep no plain value");
    });

    it("drops an open draft's plain values when the call ends before it is filed", async () => {
      const t = setup({ config: withSecure(), adapters: { fieldCipher: new FakeFieldCipher() } });
      const callId = await verifiedCall(t);
      await t.engine.startIntake(callId, "secure");
      await t.engine.setIntakeField(callId, "policy", SIN);
      const before = (await t.ledger.list()).map((e) => e.event);
      await t.engine.endCall(callId);
      const stored = JSON.stringify([await t.sessions.get("ws_test", callId), await t.ledger.list()]);
      assert.equal(stored.includes(SIN), false, "the ended call record keeps no plain value");
      assert.deepEqual((await t.ledger.list()).map((e) => e.event).slice(before.length), ["call.ended", "receipt.issued"], "dropping the draft writes no event of its own");
      await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: "0".repeat(64) }));
    });

    it("refuses to file when the cipher answers with nothing or with the plain value, and names no value", async () => {
      for (const answer of ["", SIN, undefined]) {
        const cipher = new FakeFieldCipher();
        cipher.encrypt = async () => answer as string;
        const t = setup({ config: withSecure(), adapters: { fieldCipher: cipher } });
        const callId = await verifiedCall(t);
        await t.engine.startIntake(callId, "secure");
        await t.engine.setIntakeField(callId, "issue", "Leak");
        await t.engine.setIntakeField(callId, "policy", SIN);
        await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), (e: unknown) => {
          assert.ok(e instanceof Error && e.message.includes("(no_ciphertext)") && !e.message.includes(SIN), String(answer));
          return true;
        });
        assert.equal(await t.records.getIntakeRecord("ws_test", "rec_1"), null, "nothing stored");
      }
    });

    it("encrypts a number as text", async () => {
      const cipher = new FakeFieldCipher();
      const t = setup({ config: withSecure(), adapters: { fieldCipher: cipher } });
      const callId = await verifiedCall(t);
      await t.engine.startIntake(callId, "secure");
      for (const [key, value] of [["issue", "Leak"], ["policy", SIN], ["pets", "2"]]) await t.engine.setIntakeField(callId, key!, value!);
      const record = await t.engine.confirmIntake(callId, { confirmedBy: "keypad", readBack: await heard(t, callId) });
      assert.deepEqual([cipher.decrypt(String(record.values.policy)), cipher.decrypt(String(record.values.pets))], [SIN, "2"]);
      assert.equal(record.digest, expectedDigest(record.recordId, { issue: "Leak", policy: SIN, pets: 2 }));
    });

    it("files a form whose optional sensitive field is named like an Object property and left empty", async () => {
      const proto: IntakeForm = {
        formId: "proto",
        version: "1",
        fields: [
          { key: "issue", label: { en: "Issue", fr: "Problème" }, type: "text", required: true },
          { key: "constructor", label: { en: "Note", fr: "Note" }, type: "text", required: false, sensitive: true },
        ],
      };
      const config = testConfig((c) => (c.modules.dossier = { settings: { forms: [structuredClone(form), proto] } as unknown as JsonValue }));
      const cipher = new FakeFieldCipher();
      const t = setup({ config, adapters: { fieldCipher: cipher } });
      const callId = await verifiedCall(t);
      await t.engine.startIntake(callId, "proto");
      await t.engine.setIntakeField(callId, "issue", "Leak");
      const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(t, callId) });
      assert.equal(Object.hasOwn(record.values, "constructor"), false);
      assert.deepEqual(cipher.encrypted, []);
      assert.equal(record.digest, intakeDigest(proto, { issue: "Leak" }));
    });

    it("refuses a sensitive form without the cipher, and an engine without one never files it", async () => {
      assert.throws(() => setup({ config: withSecure() }), (e: unknown) => e instanceof ConfigError && e.problems.includes("modules.dossier: needs the fieldCipher adapter, which the engine does not have"));
      // Two engines on one store: the call keeps the secure form, the second engine has no cipher.
      const a = setup({ config: withSecure(), adapters: { fieldCipher: new FakeFieldCipher() } });
      const b = setup({ adapters: { sessions: a.sessions, records: a.records } });
      const callId = await verifiedCall(a);
      await a.engine.startIntake(callId, "secure");
      await a.engine.setIntakeField(callId, "issue", "Leak");
      await a.engine.setIntakeField(callId, "policy", SIN);
      await assert.rejects(b.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(b, callId) }), rejects("precondition_failed", /needs the fieldCipher adapter/));
      assert.equal(await a.records.getIntakeRecord("ws_test", "rec_1"), null, "nothing stored");
      const record = await a.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await readBackOf(a, callId) });
      assert.equal(record.recordId, "rec_1", "the reservation is resumed by an engine with a cipher");
      assert.notEqual((await a.records.getIntakeRecord("ws_test", "rec_1"))!.values.policy, SIN);
    });
  });
});

describe("Engine ledger detail", () => {
  it("refuses at startCall every host value the ledger could not hash, before anything is saved (review of 1d52bfb, A1 and A2)", async () => {
    const t = setup();
    for (const [input, why] of [
      [{ callId: "call_\ud800" }, /callId/],
      [{ callId: "" }, /callId/],
      [{ callId: "x".repeat(201) }, /callId/],
      [{ callId: 7 }, /callId/],
      [{ locale: "e\ud800" }, /locale/],
      [{ locale: "de" }, /locale/],
      [{ flow: 7 }, /flow/],
    ] as const) {
      await assert.rejects(t.engine.startCall(input as never), rejects("invalid_input", why), JSON.stringify(input));
    }
    await assert.rejects(t.engine.state("call_\ud800"), rejects("unknown_call"), "nothing was saved");
    assert.deepEqual(await t.ledger.list(), []);
    // The ledger still takes the next call.
    const { callId } = await t.engine.startCall({ callId: "call_ok", locale: "fr" });
    await t.engine.markUntrusted(callId, "crm_note");
    assert.deepEqual((await t.ledger.list()).map((e) => e.event), ["call.started", "session.tainted"]);
    assert.throws(() => setup({ workspaceId: "ws_\ud800" }), /workspaceId must be a non-empty string the ledger can carry/);
  });

  it("refuses detail the ledger could not hash before it is saved, so the call's ledger never blocks (CodeRabbit on 699637f)", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    // The taint always lands (#75, PRV-2): its label is repaired, never a reason to refuse.
    await t.engine.markUntrusted(callId, "x\ud800");
    assert.equal((await t.engine.state(callId)).tainted, true);
    // The call's ledger still takes entries.
    await t.engine.markUntrusted(callId, "crm_note");
    const entries = await t.ledger.list();
    assert.deepEqual(entries.map((e) => e.event), ["call.started", "session.tainted", "session.tainted"]);
    assert.deepEqual(entries[1]!.detail, { source: "x\uFFFD" });
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
    assert.deepEqual(receipt!.body.payments, [{ paymentId, status: "paid", amountMinor: 15000, currency: "cad", mode: "platform", providerRef: linkId }]);
  });

  it("expires an open link when the call ends, and records a late payment as paid, flagged", async () => {
    const t = setup();
    const callId = await verifiedCall(t, "fr");
    await confirmAmount(t.engine, callId, { ...request, amountMinor: 150, currency: "jpy" });
    const { paymentId } = await t.engine.requestPayment(callId, { ...request, amountMinor: 150, currency: "jpy" });
    assert.equal(t.messages.sent.at(-1)!.body, `Votre lien de paiement sécurisé pour ${formatAmount("fr", 150, "jpy")} : https://pay.example.test/c/cs_fake_1`);
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(t.payments.expired, [{ linkId: "cs_fake_1", mode: "platform" }], "closed at the provider");
    assert.deepEqual(receipt!.body.payments.map((p) => p.status), ["expired"]);
    const entries = await t.ledger.list();
    const ended = entries.findIndex((e) => e.event === "call.ended");
    assert.deepEqual(
      entries.slice(ended).map((e) => [e.event, e.detail]),
      [
        ["call.ended", {}],
        ["payment.link_expired", { paymentId, provider: "expired", reason: "call_ended" }],
        ["payment.settled", { paymentId, status: "expired" }],
        ["receipt.issued", entries.at(-1)!.detail],
      ],
    );
    assert.equal(receipt!.body.ledger.seq, entries.at(-2)!.seq, "the receipt's head includes the expired link");
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "expired", linkId: "cs_fake_1" }), { applied: false }, "settled once");
    // A caller already on the page paid as the call ended: the money moved, so it is recorded.
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" }), { applied: true, callId, status: "paid" });
    assert.deepEqual((await t.ledger.list()).at(-1)!.detail, { paymentId, status: "paid", late: true });
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "async_succeeded", linkId: "cs_fake_1" }), { applied: false }, "recorded once");
    assert.equal((await t.engine.state(callId)).phase, "ended");
    assert.deepEqual(await t.engine.receipt(callId), receipt, "the signed receipt is not changed; the ledger has the late payment");
    assert.equal(verifyChain(await t.ledger.list()).ok, true);
  });

  it("settles a link the provider no longer holds as expired when the call ends", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const { paymentId } = await t.engine.requestPayment(callId, request);
    t.payments.settle("cs_fake_1");
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.payments.map((p) => p.status), ["expired"]);
    assert.ok((await t.ledger.list()).some((e) => e.event === "payment.link_expired" && e.detail.provider === "not_open" && e.detail.paymentId === paymentId));
    // Its webhook says why: an expiry changes nothing, a payment is recorded late.
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "async_failed", linkId: "cs_fake_1" }), { applied: false });
    assert.equal((await t.engine.applyPaymentOutcome({ kind: "async_succeeded", linkId: "cs_fake_1" })).applied, true);
  });

  it("ends the call even when the provider fails to expire a link, and expires it on the next endCall", async () => {
    for (const receipts of [true, false]) {
      const t = setup({ config: testConfig((c) => (c.modules.trace = { settings: { receipts } })) });
      const callId = await verifiedCall(t);
      await confirmAmount(t.engine, callId, request);
      await t.engine.requestPayment(callId, request);
      const expire = t.payments.expireLink.bind(t.payments);
      t.payments.expireLink = async () => {
        throw new Error("provider down");
      };
      await assert.rejects(t.engine.endCall(callId), /provider down/);
      assert.equal((await t.engine.state(callId)).phase, "ended");
      assert.equal(await t.engine.receipt(callId), null, "no receipt while a link is open");
      t.payments.expireLink = expire;
      const receipt = await t.engine.endCall(callId);
      assert.deepEqual(receipt?.body.payments.map((p) => p.status) ?? null, receipts ? ["expired"] : null);
      assert.equal(t.payments.expired.length, 1);
      await assert.rejects(t.engine.endCall(callId), rejects("invalid_transition"), "nothing left to do");
    }
  });

  it("cancels a link through expireLink, once, and the session leaves paying", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const { paymentId } = await t.engine.requestPayment(callId, request);
    await assert.rejects(t.engine.cancelPaymentLink(callId, "pay_unknown"), rejects("invalid_input", /no payment with that id/));
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, paymentId), { paymentId, status: "expired" });
    assert.deepEqual(t.payments.expired, [{ linkId: "cs_fake_1", mode: "platform" }]);
    const state = await t.engine.state(callId);
    assert.equal(state.phase, "open");
    assert.equal(state.sensitive, null);
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, paymentId), { paymentId, status: "expired" }, "already closed: nothing changes");
    assert.equal(t.payments.expired.length, 1);
    const entries = await t.ledger.list();
    assert.deepEqual(entries.filter((e) => e.event === "payment.link_expired").map((e) => e.detail), [{ paymentId, provider: "expired", reason: "cancelled" }]);
    // The caller paid on the page anyway: recorded as paid, flagged, and the call has moved on.
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" }), { applied: true, callId, status: "paid" });
    assert.deepEqual((await t.ledger.list()).at(-1)!.detail, { paymentId, status: "paid", late: true });
    assert.equal((await t.engine.state(callId)).phase, "open");
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, paymentId), { paymentId, status: "paid" }, "a paid payment stays paid");
    // A new payment can be asked for once the first is closed.
    await confirmAmount(t.engine, callId, request);
    const second = await t.engine.requestPayment(callId, request);
    assert.equal(second.status, "open");
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.payments.map((p) => p.status), ["paid", "expired"]);
  });

  it("cancels through the adapter's cancel method when it has one, with its own key", async () => {
    const t = setup({ config: testConfig((c) => (c.modules.paylink = { settings: { mode: "connect", connectedAccountId: "acct_biz" } })) });
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const { paymentId } = await t.engine.requestPayment(callId, request);
    const asked: unknown[] = [];
    (t.payments as PaymentLinks).cancel = async (input) => {
      asked.push(input);
      return { state: "not_open" };
    };
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, paymentId), { paymentId, status: "expired" });
    assert.deepEqual(asked, [{ linkId: "cs_fake_1", mode: "connect", connectedAccountId: "acct_biz", idempotencyKey: JSON.stringify(["ws_test", callId, paymentId, "cancel", "connect"]) }]);
    assert.deepEqual(t.payments.expired, [], "not through expireLink");
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "payment.link_expired").at(-1)!.detail, { paymentId, provider: "not_open", reason: "cancelled" });
  });

  it("leaves a payment paid while its cancel was at the provider", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const { paymentId } = await t.engine.requestPayment(callId, request);
    const expire = t.payments.expireLink.bind(t.payments);
    t.payments.expireLink = async (input) => {
      await t.engine.applyPaymentOutcome({ kind: "completed", linkId: input.linkId, paymentStatus: "paid" });
      return expire(input);
    };
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, paymentId), { paymentId, status: "paid" });
    assert.equal((await t.ledger.list()).some((e) => e.event === "payment.link_expired"), false);
  });

  it("closes a request whose link is not created yet, and the link that comes back is never texted", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const create = t.payments.createLink.bind(t.payments);
    t.payments.createLink = async () => {
      throw new Error("provider timed out");
    };
    await confirmAmount(t.engine, callId, request);
    await assert.rejects(t.engine.requestPayment(callId, request), /provider timed out/);
    // A create that was never answered: nothing to close at the provider, and nobody has the link.
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, "pay_1"), { paymentId: "pay_1", status: "expired" });
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "payment.link_expired").map((e) => e.detail), [{ paymentId: "pay_1", provider: "not_created", reason: "cancelled" }]);
    // Cancelled while the provider creates the link: it is closed at the provider as it comes back.
    t.payments.createLink = async (input) => {
      assert.deepEqual(await t.engine.cancelPaymentLink(callId, input.paymentId), { paymentId: input.paymentId, status: "expired" });
      return create(input);
    };
    await confirmAmount(t.engine, callId, request);
    const texts = t.messages.sent.length;
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /closed while its link was created/));
    assert.equal(t.messages.sent.length, texts, "never texted");
    assert.deepEqual(t.payments.expired, [{ linkId: "cs_fake_1", mode: "platform" }]);
    assert.equal((await t.engine.state(callId)).phase, "open");
    // A late payment on it is still recorded.
    assert.equal((await t.engine.applyPaymentOutcome({ kind: "async_succeeded", linkId: "cs_fake_1" })).applied, true);
  });

  /** Holds the payment text until told: the sender holds its lease meanwhile. */
  function holdText(t: ReturnType<typeof setup>) {
    let go: () => void = () => undefined;
    let reached: () => void = () => undefined;
    const atText = new Promise<void>((resolve) => (reached = resolve));
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async (input) => {
      reached();
      await new Promise<void>((resolve) => (go = resolve));
      return send(input);
    };
    return { atText, go: () => go() };
  }

  it("refuses to cancel a link or end the call while the link is being texted, and closes it once the text is recorded", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const held = holdText(t);
    await confirmAmount(t.engine, callId, request);
    const sending = t.engine.requestPayment(callId, request);
    await held.atText;
    await assert.rejects(t.engine.cancelPaymentLink(callId, "pay_1"), rejects("precondition_failed", /being texted/));
    await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed", /being texted/));
    assert.equal((await t.engine.state(callId)).phase, "paying", "the call did not end");
    assert.deepEqual(t.payments.expired, [], "nothing closed under the sender");
    held.go();
    assert.equal((await sending).status, "open");
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.payments.map((p) => p.status), ["expired"]);
    const events = (await t.ledger.list()).map((e) => e.event);
    assert.ok(events.indexOf("payment.link_sent") < events.indexOf("call.ended"));
  });

  /** A session store whose next payment binding waits until told. */
  class StallingStore extends MemorySessionStore {
    stall: Promise<void> | null = null;
    reached: () => void = () => undefined;
    override async bindRef(workspaceId: string, ref: string, callId: string): Promise<boolean> {
      if (this.stall !== null && ref.startsWith("payment:")) {
        const wait = this.stall;
        this.stall = null;
        this.reached();
        await wait;
      }
      return super.bindRef(workspaceId, ref, callId);
    }
  }

  it("never texts a link whose binding stalled past the lease while the call ended and its expiry failed", async () => {
    const sessions = new StallingStore();
    let release: () => void = () => undefined;
    sessions.stall = new Promise<void>((resolve) => (release = resolve));
    const reached = new Promise<void>((resolve) => (sessions.reached = resolve));
    const t = setup({ adapters: { sessions } });
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const sending = t.engine.requestPayment(callId, request).catch((e: unknown) => e);
    await reached;
    t.clock.advance(60_000);
    const expire = t.payments.expireLink.bind(t.payments);
    t.payments.expireLink = async () => {
      throw new Error("provider down");
    };
    await assert.rejects(t.engine.endCall(callId), /provider down/);
    assert.equal((await t.engine.state(callId)).phase, "ended");
    t.payments.expireLink = expire;
    release();
    assert.ok(rejects("precondition_failed", /closed while its link was being sent/)(await sending));
    assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 0, "never texted after the call ended");
    assert.deepEqual(t.payments.expired, [{ linkId: "cs_fake_1", mode: "platform" }], "expired at the provider by the sender");
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.payments.map((p) => p.status), ["expired"]);
  });

  it("stops a sender whose binding stalled while another resumed the send and took the lease", async () => {
    const sessions = new StallingStore();
    let release: () => void = () => undefined;
    sessions.stall = new Promise<void>((resolve) => (release = resolve));
    const reached = new Promise<void>((resolve) => (sessions.reached = resolve));
    const t = setup({ adapters: { sessions } });
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const first = t.engine.requestPayment(callId, request).catch((e: unknown) => e);
    await reached;
    t.clock.advance(60_000);
    assert.equal((await t.engine.requestPayment(callId, request)).status, "open", "the resume texted it");
    release();
    assert.ok(rejects("precondition_failed", /another process took over/)(await first));
    assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 1, "texted once");
  });

  it("keeps its lease when an unrelated write wins the renewal's compare-and-set", async () => {
    // Right after the binding, one unrelated write lands first: the renewal retries from a fresh read.
    class RacingStore extends MemorySessionStore {
      raceNext = false;
      armed = false;
      onBind: () => void = () => undefined;
      override async bindRef(workspaceId: string, ref: string, callId: string): Promise<boolean> {
        if (this.armed && ref.startsWith("payment:")) {
          this.raceNext = true;
          this.onBind();
        }
        return super.bindRef(workspaceId, ref, callId);
      }
      override async compareAndSet(w: string, c: string, v: number, r: JsonValue) {
        if (this.raceNext) {
          this.raceNext = false;
          const current = (await this.get(w, c))!;
          await super.compareAndSet(w, c, current.version, current.record);
        }
        return super.compareAndSet(w, c, v, r);
      }
    }
    const sessions = new RacingStore();
    const t = setup({ adapters: { sessions } });
    const callId = await verifiedCall(t);
    sessions.armed = true;
    // Time moves between the claim and the renewal, so the renewed lease differs from the held one.
    sessions.onBind = () => t.clock.advance(1_000);
    await confirmAmount(t.engine, callId, request);
    assert.equal((await t.engine.requestPayment(callId, request)).status, "open", "texted after the retried renewal");
    assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 1);
  });

  it("appends entries a failed append left pending before it takes the receipt's ledger head", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    await t.engine.requestPayment(callId, request);
    const append = t.ledger.append.bind(t.ledger);
    let down = true;
    t.ledger.append = async (...args: Parameters<typeof append>) => {
      if (down && args[0].event === "payment.link_expired") throw new Error("ledger down");
      return append(...args);
    };
    await assert.rejects(t.engine.endCall(callId), /ledger down/);
    down = false;
    const receipt = (await t.engine.endCall(callId))!;
    const entries = await t.ledger.list();
    const expired = entries.find((e) => e.event === "payment.link_expired")!;
    assert.ok(expired.seq <= receipt.body.ledger.seq, "the head covers the expired link");
    assert.equal(entries.at(-1)!.event, "receipt.issued");
  });

  it("ends the call once a stopped sender's lease lapsed, and that sender records nothing after the receipt", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const held = holdText(t);
    await confirmAmount(t.engine, callId, request);
    const sending = t.engine.requestPayment(callId, request);
    await held.atText;
    t.clock.advance(60_000);
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.payments.map((p) => p.status), ["expired"]);
    assert.deepEqual(t.payments.expired, [{ linkId: "cs_fake_1", mode: "platform" }], "closed at the provider before the text");
    const before = (await t.ledger.list()).length;
    held.go();
    assert.deepEqual(await sending, { paymentId: "pay_1", status: "expired", expiresAt: null });
    assert.equal((await t.ledger.list()).length, before, "no entry after the receipt");
    assert.equal((await t.ledger.list()).at(-1)!.event, "receipt.issued");
  });

  it("never texts a link whose create comes back after the call ended", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const create = t.payments.createLink.bind(t.payments);
    let release: () => void = () => undefined;
    let creating: () => void = () => undefined;
    const atCreate = new Promise<void>((resolve) => (creating = resolve));
    t.payments.createLink = async (input) => {
      creating();
      await new Promise<void>((resolve) => (release = resolve));
      return create(input);
    };
    await confirmAmount(t.engine, callId, request);
    const sending = t.engine.requestPayment(callId, request);
    await atCreate;
    // The create answers right after the call's ending write, before the end closes the request.
    const ledgerAppend = t.ledger.append.bind(t.ledger);
    let raced: Promise<unknown> | null = null;
    t.ledger.append = async (...args: Parameters<typeof ledgerAppend>) => {
      const entry = await ledgerAppend(...args);
      if (raced === null && entry.event === "call.ended") {
        release();
        raced = sending.catch((e: unknown) => e);
        await raced;
      }
      return entry;
    };
    const receipt = await t.engine.endCall(callId);
    assert.ok(rejects("precondition_failed", /closed while its link was created/)(await raced));
    assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 0, "never texted");
    assert.deepEqual(t.payments.expired, [{ linkId: "cs_fake_1", mode: "platform" }]);
    assert.deepEqual(receipt!.body.payments.map((p) => p.status), ["expired"]);
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
    assert.deepEqual(await t.engine.requestPayment(callId, request), { paymentId: "pay_1", status: "open", expiresAt: "2026-01-01T00:15:00.000Z" });
    assert.equal(t.payments.created.length, 1, "one link for the request, through every retry");
    assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 1);
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("invalid_transition"), "delivered: no second link");
    // A provider that settles while the text is on its way: the result says so.
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" });
    t.messages.sendText = async (input) => {
      await t.engine.applyPaymentOutcome({ kind: "completed", linkId: t.payments.created.at(-1)!.linkId, paymentStatus: "paid" });
      return send(input);
    };
    await confirmAmount(t.engine, callId, request);
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
    assert.deepEqual(receipt.body.verification, { level: 3, methods: ["keypad_knowledge", "photo_id"], policyVersion: "default-1", configRevision: "default" });
    assert.equal(receipt.body.consents.length, 2);
    const entries = await t.ledger.list();
    assert.equal(verifyChain(entries).ok, true);
    const ended = entries.find((e) => e.event === "call.ended")!;
    assert.deepEqual(receipt.body.ledger, { seq: ended.seq, hash: ended.hash });
    assert.equal(entries.at(-1)!.event, "receipt.issued");
    await assert.rejects(t.engine.endCall(callId), rejects("invalid_transition"));
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" }), rejects("invalid_transition"));
  });

  it("names the policy version and config revision that judged the caller in the grant, the events and the receipt", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    const first = (await t.engine.state(callId)).grant!;
    assert.deepEqual([first.policyVersion, first.configRevision], ["default-1", "default"]);
    // A newer config judges the next verification: the call keeps the revision it started under, the grant names the newer one.
    t.engine.configure(testConfig((c) => {
      c.revision = "2026-11-18.2";
      c.policy.version = "custom-2";
    }));
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    const second = (await t.engine.state(callId)).grant!;
    assert.deepEqual([second.policyVersion, second.configRevision], ["custom-2", "2026-11-18.2"]);
    const receipt = (await t.engine.endCall(callId))!;
    assert.deepEqual(receipt.body.verification, { level: 1, methods: ["keypad_knowledge"], policyVersion: "custom-2", configRevision: "2026-11-18.2" });
    assert.equal(verifyReceipt(receipt, t.engine.receiptKeys()), true);
    assert.equal(receipt.body.v, 1, "the fields are optional, so the format stays at version 1");
    const entries = await t.ledger.list();
    assert.deepEqual(entries.find((e) => e.event === "call.started")!.detail, { locale: "en", revision: "default", attestation: "none" });
    assert.deepEqual(
      entries.filter((e) => e.event === "verification.finished").map((e) => [e.detail.policyVersion, e.detail.configRevision]),
      [["default-1", "default"], ["custom-2", "2026-11-18.2"]],
    );
    assert.deepEqual(
      entries.filter((e) => e.event === "grant.issued").map((e) => [e.detail.policyVersion, e.detail.configRevision]),
      [["default-1", "default"], ["custom-2", "2026-11-18.2"]],
    );
  });

  it("names the policy that judged a verification that reached no level", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: "1" });
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 0, scopes: [] });
    assert.equal((await t.engine.state(callId)).grant, null);
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.verification, { level: 0, methods: [], policyVersion: "default-1", configRevision: "default" });
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

describe("Engine in Spanish (FIL-6)", () => {
  const spanishForm: IntakeForm = {
    ...form,
    fields: form.fields.map((f) => ({ ...f, label: { ...f.label, es: f.key === "issue" ? "Problema" : "Urgente" } })),
  };
  const englishAndFrench = { en: "May we text you?", fr: "Pouvons-nous vous texter?" };
  const spanishWording = { purpose: "texts", version: "1", text: { ...englishAndFrench, es: "¿Podemos enviarle mensajes de texto?" } };
  /** A level 1 flow with a form and a wording; `spanish` says which of them have Spanish text. */
  const flowSetup = (spanish: { form: boolean; wording: boolean }) =>
    setup({
      config: testConfig((c) => {
        c.modules.dossier = { settings: { forms: [structuredClone(spanish.form ? spanishForm : form)] } as unknown as JsonValue };
        c.modules.trace = { settings: { receipts: true, wordings: [spanish.wording ? structuredClone(spanishWording) : { ...spanishWording, text: englishAndFrench }] } };
        c.flows = {
          intake: { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "dossier.collect", form: "repair" }, { type: "trace.consent", purpose: "texts" }] },
          verify: { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }] },
        };
      }),
    });

  it("starts a call in en, fr or es and refuses any other locale", async () => {
    const t = setup();
    await assert.rejects(t.engine.startCall({ locale: "de" as "en" }), rejects("invalid_input", /locale must be one of en, fr, es/));
    await t.engine.startCall({ callId: "call_es", locale: "es" });
    assert.deepEqual((await t.ledger.list()).map((e) => [e.event, e.detail.locale]), [["call.started", "es"]]);
  });

  it("refuses a Spanish call whose flow needs a form or a wording with no Spanish text, and runs it when both have it", async () => {
    await assert.rejects(
      flowSetup({ form: false, wording: true }).engine.startCall({ locale: "es", flow: "intake" }),
      rejects("precondition_failed", /dossier\.collect cannot run on this call: form repair has no es label/),
    );
    await assert.rejects(
      flowSetup({ form: true, wording: false }).engine.startCall({ locale: "es", flow: "intake" }),
      rejects("precondition_failed", /trace\.consent cannot run on this call: the wording for texts has no es text/),
    );
    // Spanish is optional: English and French calls run the same flow without it.
    for (const locale of ["en", "fr"] as const) assert.equal((await flowSetup({ form: false, wording: false }).engine.startCall({ locale, flow: "intake" })).phase, "open");
    // A flow that needs neither runs in Spanish; one attached later is held to the same rule.
    const t = flowSetup({ form: false, wording: false });
    assert.equal((await t.engine.startCall({ locale: "es", flow: "verify" })).phase, "open");
    const { callId } = await t.engine.startCall({ locale: "es" });
    await assert.rejects(t.engine.startFlow(callId, "intake"), rejects("precondition_failed", /no es label/));
    const both = flowSetup({ form: true, wording: true });
    const started = await both.engine.startCall({ locale: "es" });
    assert.equal((await both.engine.startFlow(started.callId, "intake")).status, "running");
  });

  it("files and consents in Spanish: a keypad yes, a Spanish read-back, the call's locale on the consent", async () => {
    const t = flowSetup({ form: true, wording: true });
    const { callId } = await t.engine.startCall({ locale: "es", flow: "intake" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "Fuga bajo el fregadero");
    assert.deepEqual(await t.engine.setIntakeField(callId, "urgent", "yes"), { ok: true, value: true });
    const readBack = await t.engine.intakeReadBack(callId);
    assert.equal(readBack.text, "Esto es lo que vamos a registrar. Problema: Fuga bajo el fregadero. Urgente: sí. ¿Es correcto? Oprima el 1 para confirmar.");
    await t.engine.confirmIntake(callId, { confirmedBy: "keypad", readBack: readBack.digest });
    const consent = await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    assert.equal(consent.locale, "es");
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");
  });

  it("refuses, outside a flow, a Spanish intake or consent with no Spanish text", async () => {
    const t = flowSetup({ form: false, wording: false });
    const callId = await verifiedCall(t, "es");
    await assert.rejects(t.engine.startIntake(callId, "repair"), rejects("precondition_failed", /form repair has no es label for every field/));
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" }), rejects("precondition_failed", /the wording for texts has no es text/));
    assert.equal((await t.engine.state(callId)).phase, "open");
  });

  it("texts identity and payment links in Spanish, with the amount as a Spanish speaker in the United States reads it", async () => {
    const t = setup();
    const callId = await verifiedCall(t, "es");
    assert.match(t.messages.sent[0]!.body, /^Su enlace de verificación de identidad, de un solo uso: https:/);
    const deposit = { amountMinor: 150050, currency: "usd", description: "Depósito", amountSource: "price_list" } as const;
    await confirmAmount(t.engine, callId, deposit);
    await t.engine.requestPayment(callId, deposit);
    assert.equal(t.messages.sent.at(-1)!.body, "Su enlace de pago seguro por $1,500.50: https://pay.example.test/c/cs_fake_1");
  });
});
