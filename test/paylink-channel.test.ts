// A payment link by text or by email (0.3.0): the channel step, the keypress that is the caller's
// consent to the channel, the email to the verified address on file and nowhere else, and the same
// single-use link, deadline, send lease and close for both channels.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { ConsentStore, EmailSender } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { validateConfig } from "../src/core/config.ts";
import { isEmailAddress } from "../src/core/email.ts";
import { ModuleRegistry } from "../src/core/module.ts";
import type { CallRecord } from "../src/core/runtime.ts";
import { builtInModules } from "../src/modules.ts";
import { wordingDigest } from "../src/prove/consent.ts";
import { PAYMENT_CHANNEL_KEYS, PAYMENT_CHANNEL_PURPOSES, PAYMENT_EMAIL, formatAmount, paylinkModule, type PaylinkSlice } from "../src/pay/paylink.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { FakeEmailSender, MemoryConsentStore, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine, type TestEngineOptions } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, confirmAmount, rejects, testConfig, wording } from "./helpers.ts";

const EMAIL = "pat.caller@example.test";
const BUSINESS = "Maple Property Management";
const textWording = { purpose: "payment_link_text", version: "2", text: { en: "To get your payment link by text message,", fr: "Pour recevoir votre lien de paiement par texto,", es: "Para recibir su enlace de pago por mensaje de texto," } };
const emailWording = { purpose: "payment_link_email", version: "3", text: { en: "To get it by email at the address on file,", fr: "Pour le recevoir par courriel à l'adresse au dossier,", es: "Para recibirlo por correo electrónico en la dirección registrada," } };
const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] };
const channel = { type: "paylink.channel" };
const pay = { type: "paylink.request", amountMinor: 5000, currency: "cad", description: "Deposit", amountSource: "price_list" };
/** The same request, from the host's code, outside a flow. */
const request = { amountMinor: 5000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };

function channelConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.modules.paylink = { settings: { mode: "platform", channels: ["text", "email"] } };
    c.modules.trace = { settings: { receipts: true, wordings: [structuredClone(wording), textWording, emailWording], businessName: BUSINESS } };
    c.flows = { deposit: { steps: structuredClone([verify, channel, pay, { type: "trace.receipt" }]) as never } };
    patch(c);
  });
}

/** A test engine with one subject on file, with a verified email address unless `email` is null. */
function setupWith(email: string | null = EMAIL, options: TestEngineOptions = {}): TestEngine {
  const t = createTestEngine({ config: channelConfig(), ...options });
  const subject = testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } });
  if (email !== null) subject.emailOnFile = email;
  t.records.putSubject("ws_test", subject);
  return t;
}

/** A call verified to level 2 (keypad and carrier match), on the deposit flow's channel step, or on no flow. */
async function verified(t: TestEngine, options: { flow?: string; locale?: "en" | "fr" | "es" } = { flow: "deposit" }): Promise<string> {
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  const { callId } = await t.engine.startCall({ ...(options.flow === undefined ? {} : { flow: options.flow }), locale: options.locale ?? "en" });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

async function slice(t: TestEngine, callId: string): Promise<PaylinkSlice> {
  const record = (await t.sessions.get("ws_test", callId))!.record as unknown as CallRecord;
  return record.modules.paylink as unknown as PaylinkSlice;
}

const registry = (adapters: string[]) => new ModuleRegistry({ adapters, modules: builtInModules() });
const ALL = ["ledger", "records", "carrier", "identity", "messages", "emails", "payments", "signer", "counters"];

describe("email addresses on file", () => {
  it("takes only a plain address: one @, a dot-atom local part, a domain of DNS labels", () => {
    for (const ok of [EMAIL, "a@b.co", "first.last+tag@sub.example.test", "o'neil@example.test", "x@xn--bcher-kva.example", `${"a".repeat(64)}@example.test`]) assert.equal(isEmailAddress(ok), true, ok);
    for (const bad of [
      undefined,
      null,
      42,
      ["a@b.co"],
      "",
      "plain",
      "@example.test",
      "a@",
      "a@b",
      "a@@b.co",
      "a@b@c.co",
      ".a@b.co",
      "a.@b.co",
      "a..b@c.co",
      "a b@c.co",
      '"quoted"@example.test',
      "a@[192.0.2.1]",
      "a@-b.co",
      "a@b-.co",
      "a@b.c0",
      "a@b.c",
      "a@exämple.test",
      "pat@example.test\r\nBcc: other@example.test",
      "pat@example.test,other@example.test",
      `${"a".repeat(65)}@example.test`,
      `a@${"b".repeat(64)}.test`,
      `${"a".repeat(64)}@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.test`,
    ]) {
      assert.equal(isEmailAddress(bad), false, String(bad));
    }
  });
});

describe("paylink channel: config", () => {
  it("is valid with the emails adapter, both wordings and the business name", () => {
    assert.deepEqual(validateConfig(channelConfig(), registry(ALL)), []);
  });

  it("names what a channel step needs, and refuses a field it does not have", () => {
    const at = (config: FlowConfig, adapters = ALL) => validateConfig(config, registry(adapters)).map((p) => p.replace(/^flows\.deposit\.steps\[1\] \(paylink\.channel\): /, ""));
    assert.deepEqual(at(channelConfig(), ALL.filter((a) => a !== "emails")), ["modules.paylink: needs the emails adapter, which the engine does not have"]);
    assert.deepEqual(at(channelConfig((c) => (c.modules.paylink = { settings: { mode: "platform" } }))), ['the channel choice needs "email" in Paylink\'s channels setting']);
    // Paylink's settings refused are reported once, and the step is not checked against them.
    assert.deepEqual(at(channelConfig((c) => (c.modules.paylink = { settings: { mode: "platform", channels: ["email"] } }))), [
      "modules.paylink.settings: channels must include text: it is how a link goes when no verified address is on file",
    ]);
    assert.deepEqual(
      at(
        channelConfig((c) => {
          c.modules.trace = { settings: { receipts: true } };
          (c.flows.deposit!.steps[1] as unknown as Record<string, unknown>).to = EMAIL;
        }),
      ),
      [
        "to is not a field of this step",
        "the channel choice needs a wording for payment_link_text in the trace settings",
        "the channel choice needs a wording for payment_link_email in the trace settings",
        "the email channel needs businessName in the trace settings",
      ],
    );
    assert.deepEqual(at(channelConfig((c) => delete c.modules.trace)), [
      "the channel choice needs a wording for payment_link_text in the trace settings",
      "the channel choice needs a wording for payment_link_email in the trace settings",
      "the email channel needs businessName in the trace settings",
    ], "Trace on with no settings at all");
    // Trace's settings refused are reported once, and the step is not checked against them.
    assert.deepEqual(at(channelConfig((c) => (c.modules.trace = { settings: { businessName: "" } }))), ["modules.trace.settings: businessName must be 1 to 64 characters on one line"]);
    // Outside validateConfig there is no other module's settings to check against.
    assert.deepEqual(paylinkModule.validateStep(channel, { settings: { channels: ["text", "email"] }, policy: null, adapters: new Set(["emails"]), capabilities: {} }), []);
  });

  it("checks the channels setting, and needs the emails adapter only with email on", () => {
    const at = (channels: unknown) => paylinkModule.validateSettings({ channels });
    assert.deepEqual(at(["text"]), []);
    assert.deepEqual(at(["email", "text"]), []);
    for (const bad of [null, "email", ["sms"], [1], ["text", "fax"]]) assert.deepEqual(at(bad), ["channels must list text, and email or not"], String(bad));
    assert.deepEqual(at([]), ["channels must include text: it is how a link goes when no verified address is on file"]);
    assert.deepEqual(at(["text", "text"]), ["channels has duplicates"]);
    assert.deepEqual(paylinkModule.requiredAdapters({ channels: ["text", "email"] }), ["payments", "messages", "emails"]);
    assert.deepEqual(paylinkModule.requiredAdapters({ channels: ["text"] }), ["payments", "messages"]);
    assert.deepEqual(paylinkModule.requiredAdapters(undefined), ["payments", "messages"]);
  });

  it("needs each channel step to come before the payment it chooses for", () => {
    const at = (steps: unknown[]) => validateConfig(channelConfig((c) => (c.flows.deposit = { steps: structuredClone(steps) as never })), registry(ALL)).map((p) => p.replace(/^flows\.deposit \(paylink\): /, ""));
    assert.deepEqual(at([verify, pay, channel]), ["a paylink.channel step must be followed by the paylink.request step it chooses for"]);
    assert.deepEqual(at([verify, channel, channel, pay]), ["steps[2]: a second paylink.channel step before the paylink.request the first one is for"]);
    assert.deepEqual(at([verify, channel, pay, channel, pay]), []);
    assert.deepEqual(at([verify, pay]), [], "a flow without a channel step texts, as before");
    const refused = (i: number) => `steps[${i}]: a paylink.channel step comes after a badge.verify step that grants payment.request, since it needs that scope when it runs`;
    assert.deepEqual(at([channel, verify, pay]), [refused(0)]);
    const levelOne = { type: "badge.verify", level: 1, factors: ["keypad_knowledge"] };
    assert.deepEqual(at([levelOne, channel, verify, pay]), [refused(1)], "a level 1 verification does not reach payment.request");
    assert.deepEqual(at([{ ...verify, scopes: ["intake.file"] }, channel, verify, pay]), [refused(1)], "a verification that does not grant it");
    assert.deepEqual(at([verify, levelOne, channel, pay]).at(-1), refused(2), "the later verification is the one the call holds");
    assert.deepEqual(at([{ ...verify, scopes: undefined }, channel, pay]).filter((p) => p.includes("paylink.channel step comes")), [], "every scope the level reaches");
    assert.deepEqual(
      validateConfig(channelConfig((c) => delete c.policy.scopes["payment.request"]), registry(ALL)).filter((p) => p.includes("paylink.channel step comes")),
      ["flows.deposit (paylink): " + refused(1)],
      "a policy without the scope",
    );
    assert.deepEqual(paylinkModule.validateFlow!([verify, channel, pay] as never, { settings: {}, policy: null, adapters: new Set(), capabilities: {} }), [], "no policy in view");
  });
});

describe("paylink channel: email to the verified address on file", () => {
  it("offers text and email with the prompt read from both wordings, and writes nothing until the caller keys", async () => {
    const t = setupWith();
    const callId = await verified(t);
    const before = (await t.ledger.list()).length;
    const offer = await t.engine.offerPaymentChannels(callId);
    assert.deepEqual(offer, {
      channels: [
        { channel: "text", key: "1" },
        { channel: "email", key: "2" },
      ],
      prompt: "To get your payment link by text message, Press 1. To get it by email at the address on file, Press 2.",
      chosen: null,
    });
    assert.equal((await t.ledger.list()).length, before);
    assert.deepEqual(PAYMENT_CHANNEL_KEYS, { text: "1", email: "2" });
    const fr = await verified(t, { flow: "deposit", locale: "fr" });
    assert.equal((await t.engine.offerPaymentChannels(fr)).prompt, "Pour recevoir votre lien de paiement par texto, Appuyez sur 1. Pour le recevoir par courriel à l'adresse au dossier, Appuyez sur 2.");
  });

  it("records the key as consent to email under its wording, then emails the link there and texts nothing", async () => {
    const t = setupWith();
    const callId = await verified(t);
    await t.engine.offerPaymentChannels(callId);
    assert.deepEqual(await t.engine.choosePaymentChannel(callId, { key: "2" }), { channel: "email" });
    assert.equal((await t.engine.state(callId)).phase, "open");
    const entries = await t.ledger.list();
    const consent = entries.find((e) => e.event === "consent.recorded")!;
    assert.deepEqual(consent.detail, {
      consentId: consent.detail.consentId,
      purpose: PAYMENT_CHANNEL_PURPOSES.email,
      wordingVersion: "3",
      wordingDigest: wordingDigest(emailWording),
      locale: "en",
      answer: "yes",
    });
    const chosen = entries.find((e) => e.event === "payment.channel_chosen")!;
    assert.deepEqual([chosen.actor, chosen.detail], ["caller", { channel: "email", offered: ["text", "email"], consentId: consent.detail.consentId }]);
    assert.deepEqual(
      entries.filter((e) => e.event === "flow.step_completed").map((e) => e.detail.type),
      ["badge.verify", "paylink.channel"],
    );
    const texts = t.messages.sent.length;
    await confirmAmount(t.engine, callId);
    const result = await t.engine.requestPayment(callId);
    assert.equal(result.status, "open");
    assert.equal(t.messages.sent.length, texts, "nothing texted");
    assert.deepEqual(t.emails.sent, [
      {
        to: EMAIL,
        subject: `Your secure payment link from ${BUSINESS}`,
        body: `${BUSINESS} sent you a secure payment link for $50.00. It works once and expires in 15 minutes.\n\nhttps://pay.example.test/c/cs_fake_1\n\nIf you did not ask for this payment, do not use the link.`,
        locale: "en",
        purpose: "payment_link",
        messageId: "email_fake_1",
      },
    ]);
    const sent = (await t.ledger.list()).find((e) => e.event === "payment.link_sent")!;
    assert.equal(sent.detail.channel, "email");
    // The address is in no ledger entry and no receipt; the consent is in the receipt by its digest.
    assert.deepEqual(await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" }), { applied: true, callId, status: "paid" });
    const receipt = (await t.engine.endCall(callId))!;
    assert.ok(receipt.body.consents.some((c) => c.purpose === "payment_link_email" && c.answer === "yes" && c.wordingDigest === wordingDigest(emailWording)));
    const everything = JSON.stringify([await t.ledger.list(), receipt]);
    assert.equal(everything.includes(EMAIL), false);
    assert.equal(everything.includes("pat.caller"), false);
  });

  it("emails in the call's language, never promising more life than the provider has left", async () => {
    const t = setupWith();
    const callId = await verified(t, { flow: "deposit", locale: "es" });
    await t.engine.choosePaymentChannel(callId, { key: "2" });
    await confirmAmount(t.engine, callId);
    // The provider keeps a link 15 minutes at most, and its create takes 3 of them.
    t.payments.capabilities.minLinkMinutes = 5;
    t.payments.capabilities.maxLinkMinutes = 15;
    const create = t.payments.createLink.bind(t.payments);
    t.payments.createLink = async (input) => {
      t.clock.advance(3 * 60_000);
      return create(input);
    };
    const { expiresAt } = await t.engine.requestPayment(callId);
    assert.equal(expiresAt, "2026-01-01T00:15:00.000Z");
    assert.deepEqual(
      [t.emails.sent[0]!.locale, t.emails.sent[0]!.subject, t.emails.sent[0]!.body],
      ["es", PAYMENT_EMAIL.es.subject(BUSINESS), PAYMENT_EMAIL.es.body(BUSINESS, formatAmount("es", 5000, "cad"), 12, "https://pay.example.test/c/cs_fake_1")],
    );
  });

  it("texts when the caller keys 1, with the consent to text recorded", async () => {
    const t = setupWith();
    const callId = await verified(t);
    assert.deepEqual(await t.engine.choosePaymentChannel(callId, { key: "1" }), { channel: "text" });
    await confirmAmount(t.engine, callId);
    await t.engine.requestPayment(callId);
    assert.equal(t.emails.sent.length, 0);
    assert.equal(t.messages.sent.at(-1)!.to, PHONE_ON_FILE);
    const entries = await t.ledger.list();
    assert.equal(entries.find((e) => e.event === "consent.recorded")!.detail.purpose, "payment_link_text");
    assert.equal(entries.find((e) => e.event === "payment.link_sent")!.detail.channel, "text");
  });

  it("refuses a key that is not one offered, or not a string, before anything is written", async () => {
    const t = setupWith();
    const callId = await verified(t);
    const before = (await t.ledger.list()).length;
    for (const bad of [undefined, null, "x", { key: 2 }, { key: ["2"] }]) {
      await assert.rejects(t.engine.choosePaymentChannel(callId, bad as never), rejects("invalid_input", /key must be the digit the caller keyed/), String(bad));
    }
    for (const key of ["", "3", "0", "12", " 2"]) await assert.rejects(t.engine.choosePaymentChannel(callId, { key }), rejects("invalid_input", /key must be one of 1, 2/), key);
    assert.equal((await t.ledger.list()).length, before);
  });
});

describe("paylink channel: without a verified address, text", () => {
  it("offers nothing and chooses text without an address, or with one the check refuses", async () => {
    for (const email of [null, "pat@example.test\r\nBcc: other@example.test", ""]) {
      const t = setupWith(email);
      const callId = await verified(t);
      assert.deepEqual(await t.engine.offerPaymentChannels(callId), { channels: [{ channel: "text", key: "1" }], prompt: null, chosen: "text" }, String(email));
      const chosen = (await t.ledger.list()).find((e) => e.event === "payment.channel_chosen")!;
      assert.deepEqual([chosen.actor, chosen.detail], ["code", { channel: "text", offered: ["text"] }]);
      assert.equal((await t.ledger.list()).some((e) => e.event === "consent.recorded"), false, "no choice, no consent");
      await confirmAmount(t.engine, callId);
      await t.engine.requestPayment(callId);
      assert.equal(t.emails.sent.length, 0);
      assert.equal(t.messages.sent.at(-1)!.to, PHONE_ON_FILE);
    }
  });

  it("refuses key 2 when email is not offered, and takes key 1 outside a flow", async () => {
    const t = setupWith(null);
    const callId = await verified(t, {});
    await assert.rejects(t.engine.choosePaymentChannel(callId, { key: "2" }), rejects("invalid_input", /key must be one of 1$/));
    assert.deepEqual(await t.engine.choosePaymentChannel(callId, { key: "1" }), { channel: "text" });
    assert.deepEqual((await slice(t, callId)).channel?.consentId, null);
  });

  it("offers only text while Paylink's channels leave email out, address or not", async () => {
    const t = setupWith(EMAIL, { config: channelConfig((c) => ((c.flows = {}), (c.modules.paylink = { settings: { mode: "platform" } }))), adapters: { emails: undefined } });
    const callId = await verified(t, {});
    assert.equal((await t.engine.offerPaymentChannels(callId)).chosen, "text");
  });
});

describe("paylink channel: refusals and changes", () => {
  it("needs the scope, a match and an open call, and only on its own step in a flow", async () => {
    const t = setupWith();
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await assert.rejects(t.engine.offerPaymentChannels(callId), rejects("precondition_failed", /flow is on step badge.verify/));
    const bare = (await t.engine.startCall({})).callId;
    await assert.rejects(t.engine.offerPaymentChannels(bare), rejects("scope_denied"));
    await t.engine.beginVerification(bare, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.choosePaymentChannel(bare, { key: "1" }), rejects("invalid_transition", /while verifying/));
    const paying = await verified(t);
    await t.engine.choosePaymentChannel(paying, { key: "2" });
    await assert.rejects(t.engine.offerPaymentChannels(paying), rejects("precondition_failed", /flow is on step paylink.request/));
    await t.engine.markUntrusted(paying, "a webhook reply");
    assert.equal((await slice(t, paying)).channel, null, "a taint drops the choice");
  });

  it("refuses an emailed link once the caller says no to the email consent, and for a subject matched since", async () => {
    const t = setupWith();
    const callId = await verified(t, {});
    await t.engine.choosePaymentChannel(callId, { key: "2" });
    await t.engine.recordConsent(callId, { purpose: "payment_link_email", answer: "no" });
    await confirmAmount(t.engine, callId, request);
    await assert.rejects(t.engine.requestPayment(callId), rejects("precondition_failed", /withdrew their consent/));
    await t.engine.recordConsent(callId, { purpose: "payment_link_email", answer: "yes" });
    await t.engine.requestPayment(callId);
    assert.equal(t.emails.sent.length, 1);

    const other = setupWith();
    other.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "87654321", phoneOnFile: "+15555550101", knowledge: { dob: DOB } }));
    const call = await verified(other, {});
    other.carrier.set("+15555550101", { identityMatch: "match" });
    await other.engine.choosePaymentChannel(call, { key: "2" });
    await other.engine.beginVerification(call, { accountNumber: "87654321" });
    await other.engine.submitKeypad(call, { dob: DOB });
    await other.engine.checkCarrier(call);
    await other.engine.finishVerification(call);
    await confirmAmount(other.engine, call, request);
    await assert.rejects(other.engine.requestPayment(call), rejects("precondition_failed", /chosen for another subject/));
  });

  it("fails closed when the call lacks a wording in its language or the business name", async () => {
    const t = setupWith(EMAIL, {
      config: channelConfig((c) => {
        c.flows = {};
        c.modules.trace = { settings: { receipts: true, wordings: [textWording, { ...emailWording, text: { en: "Email?", fr: "Courriel?" } }] } };
      }),
    });
    const es = await verified(t, { locale: "es" });
    await assert.rejects(t.engine.offerPaymentChannels(es), rejects("precondition_failed", /needs a es wording for payment_link_email/));
    const en = await verified(t, {});
    await assert.rejects(t.engine.choosePaymentChannel(en, { key: "2" }), rejects("precondition_failed", /needs the business's name/));
  });

  it("refuses to choose text alone when an address came on file between the read and the write", async () => {
    const t = setupWith(null);
    const callId = await verified(t, {});
    const real = t.sessions.get.bind(t.sessions);
    let reads = 0;
    t.sessions.get = async (ws, id) => {
      const got = await real(ws, id);
      if (++reads === 2) ((got!.record as unknown as CallRecord).modules.badge as unknown as { subject: { emailOnFile?: string } }).subject.emailOnFile = EMAIL;
      return got;
    };
    await assert.rejects(t.engine.offerPaymentChannels(callId), rejects("precondition_failed", /channels changed/));
  });

  it("refuses a choice when the call moved on while its consent was stored", async () => {
    const store = new MemoryConsentStore();
    let during: (() => Promise<void>) | null = null;
    const consents: ConsentStore = {
      async putConsent(ws, record) {
        const run = during;
        during = null;
        await run?.();
        return store.putConsent(ws, record);
      },
      getConsent: (ws, id) => store.getConsent(ws, id),
      revokeConsent: (ws, revocation) => store.revokeConsent(ws, revocation),
    };
    const t = setupWith(EMAIL, { config: channelConfig((c) => (c.flows = {})), adapters: { consents } });
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "87654321", phoneOnFile: "+15555550101", knowledge: { dob: DOB } }));
    t.carrier.set("+15555550101", { identityMatch: "match" });
    const callId = await verified(t, {});
    during = async () => {
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    };
    await assert.rejects(t.engine.choosePaymentChannel(callId, { key: "2" }), rejects("invalid_transition", /while verifying/));
    await t.engine.finishVerification(callId);
    during = async () => {
      await t.engine.beginVerification(callId, { accountNumber: "87654321" });
      await t.engine.submitKeypad(callId, { dob: DOB });
      await t.engine.checkCarrier(callId);
      await t.engine.finishVerification(callId);
    };
    await assert.rejects(t.engine.choosePaymentChannel(callId, { key: "2" }), rejects("precondition_failed", /call changed while the choice was recorded/));
  });
});

describe("paylink channel: the same link for both channels", () => {
  it("keeps an emailed request open when the email fails, and resumes it with the same keys", async () => {
    const emails = new FakeEmailSender();
    let fail = true;
    const keys: string[] = [];
    const flaky: EmailSender = {
      async sendEmail(input) {
        keys.push(input.idempotencyKey);
        if (fail) throw new Error("email provider down");
        return emails.sendEmail(input);
      },
    };
    const t = setupWith(EMAIL, { adapters: { emails: flaky } });
    const callId = await verified(t);
    await t.engine.choosePaymentChannel(callId, { key: "2" });
    await confirmAmount(t.engine, callId);
    await assert.rejects(t.engine.requestPayment(callId), /email provider down/);
    fail = false;
    assert.equal((await t.engine.requestPayment(callId)).status, "open", "resumed at once: the lease was given back");
    assert.deepEqual(keys, [JSON.stringify(["ws_test", callId, "pay_1", "email"]), JSON.stringify(["ws_test", callId, "pay_1", "email"])]);
    assert.equal(emails.sent.length, 1);
    assert.equal(t.payments.created.length, 1, "one link");
  });

  it("refuses to resume an emailed request once the caller says no to the email consent, and the link can be cancelled", async () => {
    let fail = true;
    const emails = new FakeEmailSender();
    const flaky: EmailSender = {
      async sendEmail(input) {
        if (fail) throw new Error("email provider down");
        return emails.sendEmail(input);
      },
    };
    const t = setupWith(EMAIL, { config: channelConfig((c) => (c.flows = {})), adapters: { emails: flaky } });
    const callId = await verified(t, {});
    await t.engine.choosePaymentChannel(callId, { key: "2" });
    await confirmAmount(t.engine, callId, request);
    await assert.rejects(t.engine.requestPayment(callId), /email provider down/);
    await t.engine.recordConsent(callId, { purpose: "payment_link_email", answer: "no" });
    fail = false;
    await assert.rejects(t.engine.requestPayment(callId), rejects("precondition_failed", /withdrew their consent.*cancel the payment/));
    assert.equal(emails.sent.length, 0, "nothing emailed after the no");
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, "pay_1"), { paymentId: "pay_1", status: "expired" });
    assert.equal(emails.sent.length, 0);
    // A text request that recorded no consent (nothing was offered) resumes as before.
    const plain = setupWith(null, { config: channelConfig((c) => (c.flows = {})) });
    const other = await verified(plain, {});
    await plain.engine.offerPaymentChannels(other);
    await confirmAmount(plain.engine, other, request);
    const create = plain.payments.createLink.bind(plain.payments);
    let down = true;
    plain.payments.createLink = async (input) => {
      if (down) {
        down = false;
        throw new Error("provider down");
      }
      return create(input);
    };
    await assert.rejects(plain.engine.requestPayment(other), /provider down/);
    assert.equal((await plain.engine.requestPayment(other)).status, "open");
  });

  it("sends nothing when the caller says no to the channel's consent while the link is created", async () => {
    const t = setupWith(EMAIL, { config: channelConfig((c) => (c.flows = {})) });
    const callId = await verified(t, {});
    await t.engine.choosePaymentChannel(callId, { key: "2" });
    await confirmAmount(t.engine, callId, request);
    const create = t.payments.createLink.bind(t.payments);
    t.payments.createLink = async (input) => {
      await t.engine.recordConsent(callId, { purpose: "payment_link_email", answer: "no" });
      return create(input);
    };
    await assert.rejects(t.engine.requestPayment(callId), rejects("precondition_failed", /withdrew their consent.*cancel the payment/));
    assert.equal(t.emails.sent.length, 0);
    assert.equal((await slice(t, callId)).payments[0]!.sendingSince, null, "the lease is given back");
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, "pay_1"), { paymentId: "pay_1", status: "expired" });
    assert.deepEqual(t.payments.expired.map((e) => e.linkId), ["cs_fake_1"]);
  });

  it("refuses to resume an emailed request on an engine with the email channel off", async () => {
    const sessions = new MemorySessionStore();
    let fail = true;
    const flaky: EmailSender = {
      async sendEmail() {
        if (fail) throw new Error("down");
        return { messageId: "m" };
      },
    };
    const t = setupWith(EMAIL, { config: channelConfig((c) => (c.flows = {})), adapters: { sessions, emails: flaky } });
    const callId = await verified(t, {});
    await t.engine.choosePaymentChannel(callId, { key: "2" });
    await confirmAmount(t.engine, callId, request);
    await assert.rejects(t.engine.requestPayment(callId), /down/);
    fail = false;
    const plain = setupWith(EMAIL, {
      config: channelConfig((c) => ((c.flows = {}), (c.modules.paylink = { settings: { mode: "platform" } }))),
      adapters: { sessions, emails: undefined, ledger: t.ledger, payments: t.payments },
    });
    await assert.rejects(plain.engine.requestPayment(callId), rejects("precondition_failed", /the email channel is off/));
  });

  it("refuses an emailed link once the address is gone from the call's copy of the subject", async () => {
    const t = setupWith();
    const callId = await verified(t, {});
    await t.engine.choosePaymentChannel(callId, { key: "2" });
    await confirmAmount(t.engine, callId, request);
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as unknown as CallRecord;
    delete (record.modules.badge as unknown as { subject: { emailOnFile?: string } }).subject.emailOnFile;
    await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never);
    await assert.rejects(t.engine.requestPayment(callId), rejects("precondition_failed", /no verified address is on file now/));
  });

  it("cancels and expires an emailed link like a texted one, and a choice serves one link", async () => {
    const t = setupWith();
    const callId = await verified(t, {});
    await t.engine.choosePaymentChannel(callId, { key: "2" });
    await confirmAmount(t.engine, callId, request);
    const { paymentId, expiresAt } = await t.engine.requestPayment(callId);
    assert.equal(expiresAt, "2026-01-01T00:15:00.000Z");
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, paymentId), { paymentId, status: "expired" });
    assert.deepEqual(t.payments.expired.map((e) => e.linkId), ["cs_fake_1"]);
    assert.equal((await slice(t, callId)).channel, null, "the choice was used by that link");
    await confirmAmount(t.engine, callId, request);
    const second = await t.engine.requestPayment(callId);
    assert.equal(t.messages.sent.at(-1)!.to, PHONE_ON_FILE, "the next link goes by text unless chosen again");
    t.clock.advance(16 * 60_000);
    assert.deepEqual(await t.engine.expirePaymentLinks(callId), { expired: [second.paymentId] });
    assert.equal(t.emails.sent.length, 1);
  });
});

describe("paylink channel: calls saved before channels existed", () => {
  /** Rewrites the stored record of a call, as a call saved by an earlier version would read. */
  async function rewrite(t: TestEngine, callId: string, change: (record: CallRecord) => void): Promise<void> {
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as unknown as CallRecord;
    change(record);
    assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never)).ok, true);
  }

  it("counts a first choice on a slice with no count, and texts a resumed request that names no channel", async () => {
    const t = setupWith(null);
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await rewrite(t, callId, (r) => {
      const slice = r.modules.paylink as unknown as Record<string, unknown>;
      delete slice.choices;
      delete slice.channel;
    });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.finishVerification(callId);
    assert.equal((await t.engine.offerPaymentChannels(callId)).chosen, "text");
    assert.equal((await slice(t, callId)).choices, 1);
    await confirmAmount(t.engine, callId);
    const create = t.payments.createLink.bind(t.payments);
    let fail = true;
    t.payments.createLink = async (input) => {
      if (fail) {
        fail = false;
        throw new Error("provider down");
      }
      return create(input);
    };
    await assert.rejects(t.engine.requestPayment(callId), /provider down/);
    await rewrite(t, callId, (r) => delete (r.modules.paylink as unknown as PaylinkSlice).payments[0]!.channel);
    await t.engine.requestPayment(callId);
    assert.equal(t.messages.sent.at(-1)!.to, PHONE_ON_FILE);
    assert.equal((await t.ledger.list()).find((e) => e.event === "payment.link_sent")!.detail.channel, "text");
  });
});

describe("FakeEmailSender", () => {
  it("delivers each idempotency key once", async () => {
    const emails = new FakeEmailSender();
    const input = { to: EMAIL, subject: "s", body: "b", locale: "en" as const, purpose: "payment_link" as const, idempotencyKey: "k" };
    const first = await emails.sendEmail(input);
    assert.deepEqual(await emails.sendEmail(input), first);
    assert.notDeepEqual(await emails.sendEmail({ ...input, idempotencyKey: "k2" }), first);
    assert.equal(emails.sent.length, 2);
  });
});
