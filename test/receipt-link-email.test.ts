// A receipt link by email (#161): the channel the caller chose for their payment link carried to
// the receipt, to the verified address on file only, off by default, and a "no" that stops it with
// no fallback to text. Mirrors 0.3.0's payment link email (ADR-32).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { ConsentRecord, ConsentStore, EmailPurpose, EmailSender, MessagePurpose, MessageSender } from "../src/core/adapters.ts";
import type { AssuranceModule } from "../src/core/module.ts";
import { validateConfig, type FlowConfig } from "../src/core/config.ts";
import { ModuleRegistry } from "../src/core/module.ts";
import { builtInModules } from "../src/modules.ts";
import { RECEIPT_EMAIL_PURPOSE, traceModule } from "../src/prove/trace.ts";
import { FakeEmailSender, FakeMessageSender, MemoryConsentStore, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, confirmAmount, rejects, testConfig, wording } from "./helpers.ts";

const EMAIL = "pat.caller@example.test";
const BUSINESS = "Maple Property Management";
const LINK = "https://receipts.example.test/r/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const textWording = { purpose: "payment_link_text", version: "1", text: { en: "To get your payment link by text message,", fr: "Pour recevoir votre lien de paiement par texto," } };
const emailWording = { purpose: "payment_link_email", version: "1", text: { en: "To get it by email at the address on file,", fr: "Pour le recevoir par courriel à l'adresse au dossier," } };
const receiptEmailWording = { purpose: "receipt_email", version: "1", text: { en: "May we email you a link to your receipt?", fr: "Pouvons-nous vous envoyer votre reçu par courriel?" } };
const receiptTextsWording = { purpose: "receipt_texts", version: "1", text: { en: "May we text you a receipt?", fr: "Pouvons-nous vous texter un reçu?" } };
const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] };
const verifyContact = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["contact.update"] };
const NEW_PHONE = "+15555550199";

/** A host's outside module: a step that changes contact details in the host's own systems. */
function acmeModule(): AssuranceModule {
  return {
    manifest: {
      name: "acme",
      version: "1",
      summary: "Changes contact details in the host's own systems.",
      provides: { factors: [], steps: ["acme.change_phone"], outcomes: [] },
      scopes: { grants: [], needs: { "acme.change_phone": "contact.update" } },
      adapters: [],
    },
    validateSettings: () => [],
    requiredAdapters: () => [],
    validateStep: () => [],
    initCall: () => ({ done: 0 }),
    enterStep: (_step, slice) => (slice as { done: number }).done,
    stepStatus: (_step, view) => ((view.slice as { done: number }).done > (view.mark as number) ? "complete" : "pending"),
  };
}
const channel = { type: "paylink.channel" } as const;
const pay = { type: "paylink.request", amountMinor: 5000, currency: "cad", description: "Deposit", amountSource: "price_list" } as const;
const askEmail = { type: "trace.consent", purpose: "receipt_email", require: "answer" } as const;
const askTexts = { type: "trace.consent", purpose: "receipt_texts", require: "answer" } as const;
const receipt = { type: "trace.receipt", textLink: { consent: "receipt_texts" } } as const;

function config(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.modules.paylink = { settings: { mode: "platform", channels: ["text", "email"] } };
    c.modules.trace = {
      settings: {
        receipts: true,
        wordings: [structuredClone(wording), textWording, emailWording, receiptEmailWording, receiptTextsWording],
        businessName: BUSINESS,
        channels: ["text", "email"],
      },
    };
    c.policy.scopes["contact.update"] = 2;
    c.modules.acme = { settings: {} };
    c.flows = {
      deposit: { steps: [verify, channel, pay, askEmail, askTexts, receipt] },
      "deposit-twice": { steps: [verify, channel, pay, askEmail, askTexts, channel, pay, receipt] },
      "change-only": { steps: [verifyContact, { type: "acme.change_phone" }, askTexts, receipt] },
      "deposit-asked-twice": { steps: [verify, channel, pay, askEmail, askEmail, askTexts, receipt] },
      "deposit-no-choice": { steps: [verify, pay, askTexts, receipt] },
      "deposit-unasked": { steps: [verify, channel, pay, askTexts, receipt] },
      "deposit-quiet": { steps: [verify, channel, pay, askEmail, { type: "trace.receipt" }] },
      // A keypad recheck after the payment, as a flow that re-reads the subject on file (PRV-10's repay).
      "deposit-recheck": { steps: [verify, channel, pay, askEmail, askTexts, { type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, receipt] },
    };
    patch(c);
  });
}

/** An engine with one subject on file, with a verified email address unless `email` is null. */
function engine(email: string | null = EMAIL, patch?: (c: FlowConfig) => void, options: { consents?: ConsentStore } = {}): TestEngine {
  const t = createTestEngine({
    config: config(patch),
    modules: [acmeModule()],
    ...(options.consents === undefined ? {} : { adapters: { consents: options.consents } }),
  });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  const subject = testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } });
  if (email !== null) subject.emailOnFile = email;
  t.records.putSubject("ws_test", subject);
  return t;
}

/** A verified call on the flow's first step, in the locale given. */
async function verified(t: TestEngine, flow = "deposit", locale: "en" | "fr" = "en"): Promise<string> {
  const { callId } = await t.engine.startCall({ flow, locale });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

/** A paid call that chose `key` for its payment link, ending on the receipt_email consent step. */
async function paidCall(t: TestEngine, key: "1" | "2", flow = "deposit", locale: "en" | "fr" = "en"): Promise<string> {
  const callId = await verified(t, flow, locale);
  const offer = await t.engine.offerPaymentChannels(callId);
  assert.deepEqual(offer.channels, [
    { channel: "text", key: "1" },
    { channel: "email", key: "2" },
  ]);
  await t.engine.choosePaymentChannel(callId, { key });
  await confirmAmount(t.engine, callId);
  await t.engine.requestPayment(callId);
  await t.engine.applyPaymentOutcome({ kind: "completed", linkId: t.payments.created.at(-1)!.linkId, paymentStatus: "paid" });
  return callId;
}

/** A paid call whose flow has no channel step: the payment went by text, chosen by default. */
async function paidWithoutChoice(t: TestEngine, flow = "deposit-no-choice"): Promise<string> {
  const callId = await verified(t, flow);
  await confirmAmount(t.engine, callId);
  await t.engine.requestPayment(callId);
  await t.engine.applyPaymentOutcome({ kind: "completed", linkId: t.payments.created.at(-1)!.linkId, paymentStatus: "paid" });
  return callId;
}

/** A paid, consented, ended call: the receipt link is ready to send. */
async function emailedCall(
  t: TestEngine,
  answers: { receipt_email?: "yes" | "no"; receipt_texts?: "yes" | "no" } = { receipt_email: "yes" },
  flow = "deposit",
  locale: "en" | "fr" = "en",
): Promise<string> {
  const callId = await paidCall(t, "2", flow, locale);
  if (answers.receipt_email !== undefined) await t.engine.recordConsent(callId, { purpose: "receipt_email", answer: answers.receipt_email });
  if (answers.receipt_texts !== undefined) await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: answers.receipt_texts });
  assert.notEqual(await t.engine.endCall(callId), null);
  return callId;
}

const emails = (t: TestEngine, purpose: EmailPurpose) => t.emails.sent.filter((m) => m.purpose === purpose);
const texts = (t: TestEngine, purpose: MessagePurpose) => t.messages.sent.filter((m) => m.purpose === purpose);
const events = async (t: TestEngine, name: string) => (await t.ledger.list()).filter((e) => e.event === name);

describe("receipt link email", () => {
  it("goes by the channel the caller chose for their payment link, to the verified address on file, once", async () => {
    const t = engine();
    const callId = await emailedCall(t);
    assert.equal(emails(t, "payment_link").length, 1, "the payment link went by email");
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: true, channel: "email" });
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: false, channel: null }, "at most one per call");
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: false }, "the text path counts it too");
    const [sent] = emails(t, "receipt_link");
    assert.equal(sent!.to, EMAIL);
    assert.equal(sent!.locale, "en");
    assert.equal(sent!.subject, `Your receipt from ${BUSINESS}`);
    assert.equal(sent!.body, `${BUSINESS} sent you a receipt for a payment on your call.\n\n${LINK}\n\nIf you did not have this call, do not use the link.`);
    for (const value of ["150", "5000", ACCOUNT, DOB, PHONE_ON_FILE, "cad"]) assert.ok(!sent!.body.includes(value), value);
    assert.equal(texts(t, "receipt_link").length, 0, "nothing is texted");
    assert.deepEqual((await events(t, "receipt.link_emailed")).map((e) => e.detail), [{ actions: ["money"] }]);
    assert.equal((await events(t, "receipt.link_texted")).length, 0);
    assert.ok(!JSON.stringify(await t.ledger.list()).includes("receipts.example.test"), "the link never reaches the ledger");
  });

  it("is built in the call's locale", async () => {
    const t = engine();
    const callId = await emailedCall(t, { receipt_email: "yes" }, "deposit", "fr");
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: true, channel: "email" });
    const [sent] = emails(t, "receipt_link");
    assert.equal(sent!.locale, "fr");
    assert.equal(sent!.subject, `Votre reçu de ${BUSINESS}`);
    assert.equal(sent!.body, `${BUSINESS} vous a envoyé un reçu pour un paiement lors de votre appel.\n\n${LINK}\n\nSi vous n'avez pas passé cet appel, n'utilisez pas le lien.`);
  });

  it("is off by default: without the email channel in Trace's settings, nothing is ever emailed", async () => {
    const t = engine(EMAIL, (c) => delete (c.modules.trace as { settings: { channels?: unknown } }).settings.channels);
    const callId = await emailedCall(t, { receipt_email: "yes", receipt_texts: "yes" });
    assert.equal(emails(t, "payment_link").length, 1, "the payment link still went by email: that channel is Paylink's own setting");
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: true, channel: "text" }, "the receipt link follows the text rules");
    assert.equal(emails(t, "receipt_link").length, 0);
    assert.equal(texts(t, "receipt_link").length, 1);
  });

  it("never falls back to text: an email choice without its own yes sends nothing, and the ask is the answer, not a textLink", async () => {
    const t = engine();
    const callId = await emailedCall(t, { receipt_texts: "yes" }, "deposit-unasked");
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: false, channel: null }, "no answer to receipt_email");
    assert.equal(emails(t, "receipt_link").length, 0);
    assert.equal(texts(t, "receipt_link").length, 0, "never by text instead");
    const quiet = await emailedCall(t, { receipt_email: "yes" }, "deposit-quiet");
    assert.deepEqual(await t.engine.sendReceiptLink(quiet, LINK), { sent: true, channel: "email" }, "a flow whose receipt step has no textLink still emails");
  });

  it("stops at a later no to receipt_email, and sends nothing", async () => {
    const t = engine();
    const callId = await emailedCall(t, { receipt_email: "yes" }, "deposit-asked-twice");
    const again = await paidCall(t, "2", "deposit-asked-twice");
    await t.engine.recordConsent(again, { purpose: "receipt_email", answer: "yes" });
    await t.engine.recordConsent(again, { purpose: "receipt_email", answer: "no" });
    await t.engine.endCall(again);
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: true, channel: "email" }, "the first call's yes stood");
    assert.deepEqual(await t.engine.sendReceiptLink(again, LINK), { sent: false, channel: null }, "the latest answer wins");
    assert.equal(emails(t, "receipt_link").length, 1, "only the first call's");
    assert.equal(texts(t, "receipt_link").length, 0, "a no to email is not a yes to text");
  });

  it("sends nothing while an answer is still being stored, which may be a no (fail closed)", async () => {
    const consents = new (class extends MemoryConsentStore {
      failNext = 0;
      override async putConsent(workspaceId: string, record: ConsentRecord): Promise<void> {
        if (this.failNext > 0) {
          this.failNext--;
          throw new Error("consent store down");
        }
        return super.putConsent(workspaceId, record);
      }
    })();
    const t = engine(EMAIL, undefined, { consents });
    const callId = await paidCall(t, "2");
    consents.failNext = 1;
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "receipt_email", answer: "yes" }), /consent store down/);
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: false, channel: null });
    assert.equal(emails(t, "receipt_link").length, 0);
    assert.equal(texts(t, "receipt_link").length, 0);
  });

  it("sends nothing for a yes the caller has since revoked in the store", async () => {
    const consents = new MemoryConsentStore();
    const t = engine(EMAIL, undefined, { consents });
    const callId = await paidCall(t, "2");
    const consent = await t.engine.recordConsent(callId, { purpose: "receipt_email", answer: "yes" });
    await t.engine.endCall(callId);
    await t.engine.revokeConsent({ consentId: consent.consentId, via: "web" });
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: false, channel: null });
    assert.equal(emails(t, "receipt_link").length, 0);
    assert.equal(texts(t, "receipt_link").length, 0);
  });

  it("goes by text, as textReceiptLink does, when the caller chose text or nothing for their payment link", async () => {
    const t = engine();
    const byText = await paidCall(t, "1", "deposit-unasked");
    await t.engine.recordConsent(byText, { purpose: "receipt_texts", answer: "yes" });
    await t.engine.endCall(byText);
    assert.deepEqual(await t.engine.sendReceiptLink(byText, LINK), { sent: true, channel: "text" });
    assert.equal(emails(t, "receipt_link").length, 0, "no email without the email choice");
    assert.equal(texts(t, "receipt_link").length, 1);
    const unchosen = await paidWithoutChoice(t);
    await t.engine.recordConsent(unchosen, { purpose: "receipt_texts", answer: "yes" });
    await t.engine.endCall(unchosen);
    assert.deepEqual(await t.engine.sendReceiptLink(unchosen, LINK), { sent: true, channel: "text" }, "no choice defaults to text");
    assert.equal(emails(t, "receipt_link").length, 0);
  });

  it("needs an address on file: a subject read again without its address sends nothing", async () => {
    const t = engine();
    const callId = await paidCall(t, "2", "deposit-recheck");
    await t.engine.recordConsent(callId, { purpose: "receipt_email", answer: "yes" });
    await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "yes" });
    // The host drops the address in its own records, and the recheck step reads the subject again.
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } }));
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: false, channel: null });
    assert.equal(emails(t, "receipt_link").length, 0);
    assert.equal(texts(t, "receipt_link").length, 0, "never by text instead");
  });

  it("sends nothing once the keypad or PIN match no longer stands", async () => {
    const t = engine();
    const callId = await paidCall(t, "2");
    await t.engine.recordConsent(callId, { purpose: "receipt_email", answer: "yes" });
    await t.engine.markUntrusted(callId, "crm_note");
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: false, channel: null });
    assert.equal(emails(t, "receipt_link").length, 0);
    assert.equal(texts(t, "receipt_link").length, 0);
  });

  it("two sends at once email once by their key and log one entry", async () => {
    const t = engine();
    const callId = await emailedCall(t);
    const keys: string[] = [];
    const send = t.emails.sendEmail.bind(t.emails);
    t.emails.sendEmail = async (input) => (keys.push(input.idempotencyKey), send(input));
    const results = await Promise.all([t.engine.sendReceiptLink(callId, LINK), t.engine.sendReceiptLink(callId, LINK)]);
    assert.deepEqual(results, [
      { sent: true, channel: "email" },
      { sent: true, channel: "email" },
    ]);
    assert.deepEqual([keys.length, new Set(keys).size], [2, 1], "both sends carry one idempotency key");
    assert.equal((await events(t, "receipt.link_emailed")).length, 1);
  });

  it("counts a link texted before channels existed as already sent", async () => {
    const t = engine();
    const callId = await emailedCall(t, { receipt_email: "yes", receipt_texts: "yes" });
    // A call record written by 0.3.0 holds "sent" for a link it texted.
    const stored = (await t.sessions.get("ws_test", callId))!;
    (stored.record as { modules: { trace: { texts: { receiptLink: string } } } }).modules.trace.texts.receiptLink = "sent";
    assert.deepEqual(await t.sessions.compareAndSet("ws_test", callId, stored.version, stored.record), { ok: true, version: stored.version + 1 });
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: false });
    assert.deepEqual(await t.engine.sendReceiptLink(callId, LINK), { sent: false, channel: null });
    assert.equal(texts(t, "receipt_link").length, 0);
  });

  it("goes by text on a call that paid nothing, and a text channel that is not consented to sends nothing", async () => {
    const t = engine();
    const changePhone = async (callId: string): Promise<void> => {
      t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: NEW_PHONE, knowledge: { dob: DOB } }));
      await t.engine.updateModule(callId, "acme", (s) => ({ done: (s as { done: number }).done + 1 }));
    };
    t.carrier.set(NEW_PHONE, { identityMatch: "match" });
    const unanswered = await verified(t, "change-only");
    await changePhone(unanswered);
    await t.engine.endCall(unanswered);
    assert.deepEqual(await t.engine.sendReceiptLink(unanswered, LINK), { sent: false, channel: null }, "a contact action with no payment and no text consent");
    const answered = await verified(t, "change-only");
    await changePhone(answered);
    await t.engine.recordConsent(answered, { purpose: "receipt_texts", answer: "yes" });
    await t.engine.endCall(answered);
    assert.deepEqual(await t.engine.sendReceiptLink(answered, LINK), { sent: true, channel: "text" }, "no payment on the call: the channel is text");
    assert.equal(emails(t, "receipt_link").length, 0);
    assert.equal(texts(t, "receipt_link").length, 1);
  });

  it("follows the last link the caller actually received, never a request whose send failed", async () => {
    // The provider adapters fail only where the test wants a request whose link was never delivered.
    const sent = { emails: new FakeEmailSender(), messages: new FakeMessageSender() };
    const down = { emails: false, messages: false };
    const flaky: { emails: EmailSender; messages: MessageSender } = {
      emails: { async sendEmail(input) { if (down.emails) throw new Error("email provider down"); return sent.emails.sendEmail(input); } },
      messages: { async sendText(input) { if (down.messages) throw new Error("carrier down"); return sent.messages.sendText(input); } },
    };
    const wired = (adapters: { emails: EmailSender; messages: MessageSender }): TestEngine => {
      const t = createTestEngine({ config: config(), modules: [acmeModule()], adapters: { emails: adapters.emails, messages: adapters.messages } });
      t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
      const subject = testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } });
      subject.emailOnFile = EMAIL;
      t.records.putSubject("ws_test", subject);
      return t;
    };
    const paidThenFailed = async (t: TestEngine, first: "1" | "2", second: "1" | "2", answers: { receipt_email?: "yes" | "no"; receipt_texts?: "yes" | "no" }): Promise<string> => {
      const callId = await verified(t, "deposit-twice");
      const offer = await t.engine.offerPaymentChannels(callId);
      assert.equal(offer.channels.length, 2);
      await t.engine.choosePaymentChannel(callId, { key: first });
      await confirmAmount(t.engine, callId);
      await t.engine.requestPayment(callId);
      await t.engine.applyPaymentOutcome({ kind: "completed", linkId: t.payments.created.at(-1)!.linkId, paymentStatus: "paid" });
      await t.engine.recordConsent(callId, { purpose: "receipt_email", answer: answers.receipt_email ?? "no" });
      await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: answers.receipt_texts ?? "no" });
      await t.engine.offerPaymentChannels(callId);
      await t.engine.choosePaymentChannel(callId, { key: second });
      await confirmAmount(t.engine, callId);
      down[first === "2" ? "messages" : "emails"] = true;
      await assert.rejects(t.engine.requestPayment(callId), first === "2" ? /carrier down/ : /email provider down/);
      down.emails = false;
      down.messages = false;
      await t.engine.endCall(callId);
      return callId;
    };
    // The email link was received; the text request after it failed, and the receipt still goes by email.
    const byEmail = wired(flaky);
    const emailed = await paidThenFailed(byEmail, "2", "1", { receipt_email: "yes" });
    assert.deepEqual(await byEmail.engine.sendReceiptLink(emailed, LINK), { sent: true, channel: "email" });
    assert.equal(sent.emails.sent.filter((m) => m.purpose === "receipt_link").length, 1, "the delivered email link's channel");
    assert.equal(sent.messages.sent.filter((m) => m.purpose === "receipt_link").length, 0, "the failed text request never becomes the receipt channel");
    // The reverse: a text link received, an email request after it that failed.
    const byText = wired(flaky);
    const texted = await paidThenFailed(byText, "1", "2", { receipt_texts: "yes" });
    assert.equal(sent.emails.sent.filter((m) => m.purpose === "receipt_link").length, 1, "still only the first call's");
    assert.deepEqual(await byText.engine.sendReceiptLink(texted, LINK), { sent: true, channel: "text" });
    assert.equal(sent.messages.sent.filter((m) => m.purpose === "receipt_link").length, 1, "the delivered text link's channel");
    assert.equal(sent.emails.sent.filter((m) => m.purpose === "receipt_link").length, 1, "the failed email request never becomes the receipt channel");
  });

  it("refuses a bad link, a call that has not ended, or one without a receipt", async () => {
    const t = engine();
    const open = await paidCall(t, "2");
    await assert.rejects(t.engine.sendReceiptLink(open, "http://receipts.example.test/r/1"), rejects("invalid_input", /https URL/));
    await assert.rejects(t.engine.sendReceiptLink(open, LINK), rejects("precondition_failed", /has ended/));
    const callId = await emailedCall(t);
    for (const bad of ["", "receipts.example.test", `https://receipts.example.test/r/${"A".repeat(513)}`, "https://receipts.example.test/r/a b", `https://receipts.example.test/r/${"A".repeat(42)}\u0000`]) {
      await assert.rejects(t.engine.sendReceiptLink(callId, bad), rejects("invalid_input", /https URL/), JSON.stringify(bad));
    }
    assert.equal(emails(t, "receipt_link").length, 0, "nothing went out while refusing");
  });
});

describe("receipt email channels config", () => {
  const registry = (adapters: string[]) => new ModuleRegistry({ adapters, modules: builtInModules() });
  const ALL = ["ledger", "records", "carrier", "identity", "messages", "emails", "payments", "signer", "counters"];

  it("the channels setting is validated, and email needs its wording", () => {
    const at = (channels: unknown, wordings: unknown = [structuredClone(wording), receiptEmailWording, receiptTextsWording]) =>
      validateConfig(
        config((c) => {
          const settings = c.modules.trace as { settings: { channels?: unknown; wordings?: unknown } };
          settings.settings.channels = channels;
          settings.settings.wordings = wordings;
        }),
        registry(ALL),
      ).filter((p) => p.startsWith("modules.trace"));
    assert.deepEqual(at(["text"]), []);
    assert.deepEqual(at(["text", "email"]), []);
    assert.deepEqual(at(["email", "text"]), []);
    assert.deepEqual(at(["text", "email"], [structuredClone(wording), receiptTextsWording]), [
      "modules.trace.settings: the email channel needs a receipt_email wording in the trace settings",
    ]);
    for (const [channels, problem] of [
      ["text and email", "channels must list text, and email or not"],
      [["text", "text"], "channels has duplicates"],
      [["email"], "channels must include text: it is how a receipt link goes when the caller chose text, or nothing, for their payment link"],
      [["text", "phone"], "channels must list text, and email or not"],
    ] as const) {
      assert.deepEqual(at(channels), [`modules.trace.settings: ${problem}`], JSON.stringify(channels));
    }
  });

  it("the email channel needs the emails adapter when the config is saved", () => {
    assert.deepEqual(validateConfig(config(), registry(ALL.filter((a) => a !== "emails"))).filter((p) => p.startsWith("modules.trace")), [
      "modules.trace: needs the emails adapter, which the engine does not have",
    ]);
    const textOnly = (c: FlowConfig) => {
      (c.modules.paylink as { settings: { channels?: unknown } }).settings.channels = ["text"];
      delete (c.modules.trace as { settings: { channels?: unknown } }).settings.channels;
    };
    assert.deepEqual(validateConfig(config(textOnly), registry(ALL.filter((a) => a !== "emails"))).filter((p) => p.includes("emails")), [], "the text channel alone does not");
    assert.deepEqual(traceModule.requiredAdapters({ channels: ["text", "email"] }), ["ledger", "signer", "emails"]);
    assert.deepEqual(traceModule.requiredAdapters({}), ["ledger", "signer"]);
    assert.equal(RECEIPT_EMAIL_PURPOSE, "receipt_email");
  });
});
