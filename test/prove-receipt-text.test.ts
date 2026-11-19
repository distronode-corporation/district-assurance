// PRV-10: the receipt link texted to the caller after a money, contact or access step, and the
// security notice after a contact change.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { MessagePurpose } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { validateConfig, type FlowConfig } from "../src/core/config.ts";
import type { AssuranceModule } from "../src/core/module.ts";
import { contactNoticeText, receiptLinkText } from "../src/prove/trace.ts";
import { TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig, wording } from "./helpers.ts";

const NEW_PHONE = "+15555550199";
const BUSINESS = "Maple Property Management";
const TOKEN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const LINK = `https://receipts.example.test/r/${TOKEN}`;
const OTHER_ACCOUNT = "87654321";
const OTHER_DOB = "19700101";
const OTHER_PHONE = "+15555550142";
const consentWording = { purpose: "receipt_texts", version: "1", text: { en: "May we text you a receipt?", fr: "Pouvons-nous vous texter un reçu?" } };
const pay = { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" } as const;
const verify = (scopes: string[]) => ({ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes });
const consent = { type: "trace.consent", purpose: "receipt_texts", require: "answer" } as const;
const textedReceipt = { type: "trace.receipt", textLink: { consent: "receipt_texts" } } as const;

/** A host's outside module: steps the host completes after it changed contact details or opened a door. */
function acmeModule(): AssuranceModule {
  return {
    manifest: {
      name: "acme",
      version: "1",
      summary: "Changes contact details and opens doors, in the host's own systems.",
      provides: { factors: [], steps: ["acme.change_phone", "acme.change_email", "acme.open_door"], outcomes: [] },
      scopes: { grants: [], needs: { "acme.change_phone": "contact.update", "acme.change_email": "contact.update", "acme.open_door": "access.door" } },
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

function config(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.scopes["contact.update"] = 2;
    c.policy.scopes["access.door"] = 2;
    c.modules.acme = { settings: {} };
    c.modules.trace = { settings: { receipts: true, wordings: [structuredClone(wording), consentWording], businessName: BUSINESS } };
    c.flows = {
      deposit: { steps: [verify(["payment.request"]), pay, consent, textedReceipt] },
      "deposit-quiet": { steps: [verify(["payment.request"]), pay, consent, { type: "trace.receipt" }] },
      change: {
        steps: [
          verify(["contact.update", "access.door", "payment.request"]),
          { type: "acme.change_phone" },
          { type: "acme.change_email" },
          { type: "acme.open_door" },
          pay,
          consent,
          textedReceipt,
        ],
      },
      "change-only": { steps: [verify(["contact.update"]), { type: "acme.change_phone" }] },
      repay: { steps: [verify(["payment.request"]), pay, consent, { type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, textedReceipt] },
      // A contact change for one subject, then a second verification and a payment for another.
      "two-subjects": { steps: [verify(["contact.update"]), { type: "acme.change_phone" }, verify(["contact.update", "payment.request"]), { type: "acme.change_email" }, pay, consent, textedReceipt] },
      "change-then-other": { steps: [verify(["contact.update"]), { type: "acme.change_phone" }, verify(["payment.request"]), pay, consent, textedReceipt] },
    };
    patch(c);
  });
}

function engine(patch?: (c: FlowConfig) => void, options: Parameters<typeof setup>[0] = {}): TestEngine {
  const t = setup({ config: config(patch), modules: [acmeModule()], ...options });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  t.carrier.set(OTHER_PHONE, { identityMatch: "match" });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: OTHER_ACCOUNT, phoneOnFile: OTHER_PHONE, knowledge: { dob: OTHER_DOB } }));
  return t;
}

/** A second verification on the same call, for the other subject. */
async function verifyOther(t: TestEngine, callId: string): Promise<void> {
  await t.engine.beginVerification(callId, { accountNumber: OTHER_ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: OTHER_DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
}

async function verified(t: TestEngine, flow: string, locale: "en" | "fr" = "en"): Promise<string> {
  const { callId } = await t.engine.startCall({ flow, locale });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

async function paid(t: TestEngine, callId: string): Promise<void> {
  await t.engine.requestPayment(callId);
  await t.engine.applyPaymentOutcome({ kind: "completed", linkId: t.payments.created.at(-1)!.linkId, paymentStatus: "paid" });
}

/** The host changes the phone on file in its own records, then completes its step. */
async function changePhone(t: TestEngine, callId: string): Promise<void> {
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: NEW_PHONE, knowledge: { dob: DOB } }));
  await t.engine.updateModule(callId, "acme", (s) => ({ done: (s as { done: number }).done + 1 }));
}

async function depositCall(t: TestEngine, answer: "yes" | "no", locale: "en" | "fr" = "en"): Promise<string> {
  const callId = await verified(t, "deposit", locale);
  await paid(t, callId);
  await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer });
  assert.notEqual(await t.engine.endCall(callId), null);
  return callId;
}

const texts = (t: TestEngine, purpose: MessagePurpose) => t.messages.sent.filter((m) => m.purpose === purpose);
const events = async (t: TestEngine, name: string) => (await t.ledger.list()).filter((e) => e.event === name);

describe("receipt link text", () => {
  it("is sent after a money flow, with consent, to the number on file, once, and carries no values", async () => {
    const t = engine();
    const callId = await depositCall(t, "yes");
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: true });
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: false }, "at most one per call");
    const sent = texts(t, "receipt_link");
    assert.equal(sent.length, 1);
    assert.equal(sent[0]!.to, PHONE_ON_FILE);
    assert.equal(sent[0]!.body, `Receipt from ${BUSINESS} for a payment on your call: ${LINK}`);
    for (const value of ["150", "15000", ACCOUNT, DOB, PHONE_ON_FILE, "cad"]) assert.ok(!sent[0]!.body.replace(LINK, "").includes(value), value);
    const logged = await events(t, "receipt.link_texted");
    assert.deepEqual(logged.map((e) => e.detail), [{ actions: ["money"] }]);
    assert.ok(!JSON.stringify(await t.ledger.list()).includes(TOKEN), "the link never reaches the ledger");
    assert.equal(texts(t, "contact_changed").length, 0, "no notice without a contact change");
  });

  it("is built in the call's locale", async () => {
    const t = engine();
    const callId = await depositCall(t, "yes", "fr");
    await t.engine.textReceiptLink(callId, LINK);
    assert.equal(texts(t, "receipt_link")[0]!.body, `Reçu de ${BUSINESS} pour un paiement lors de votre appel : ${LINK}`);
  });

  it("is not sent without consent, or when the flow does not ask for it", async () => {
    const t = engine();
    assert.deepEqual(await t.engine.textReceiptLink(await depositCall(t, "no"), LINK), { texted: false });
    const quiet = await verified(t, "deposit-quiet");
    await paid(t, quiet);
    await t.engine.recordConsent(quiet, { purpose: "receipt_texts", answer: "yes" });
    await t.engine.endCall(quiet);
    assert.deepEqual(await t.engine.textReceiptLink(quiet, LINK), { texted: false });
    const { callId: noFlow } = await t.engine.startCall();
    await t.engine.endCall(noFlow);
    assert.deepEqual(await t.engine.textReceiptLink(noFlow, LINK), { texted: false });
    assert.equal(texts(t, "receipt_link").length, 0);
  });

  it("is not sent before a scoped step completed, or once the keypad or PIN match no longer stands", async () => {
    const t = engine();
    // The keypad answer is wrong: the flow fails at verification, nothing was done.
    const { callId: failed } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.beginVerification(failed, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(failed, { dob: "19000101" });
    await t.engine.finishVerification(failed);
    await t.engine.endCall(failed);
    assert.deepEqual(await t.engine.textReceiptLink(failed, LINK), { texted: false });
    // Paid and consented, then untrusted text and a new verification from nothing that never matched.
    const callId = await verified(t, "repay");
    await paid(t, callId);
    await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "yes" });
    await t.engine.markUntrusted(callId, "crm_note");
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.finishVerification(callId);
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: false });
    assert.equal(texts(t, "receipt_link").length, 0);
  });

  it("is not sent when the caller's latest answer withdrew an earlier yes", async () => {
    const t = engine();
    // A "yes" recorded before the flow started, while no step was active, then a "no" at the step.
    const { callId } = await t.engine.startCall();
    await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "yes" });
    await t.engine.startFlow(callId, "deposit");
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.finishVerification(callId);
    await paid(t, callId);
    await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "no" });
    assert.notEqual(await t.engine.endCall(callId), null);
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: false });
    assert.equal(texts(t, "receipt_link").length, 0);
  });

  it("is not sent after a later verification for an unknown account", async () => {
    const t = engine();
    const callId = await verified(t, "repay");
    await paid(t, callId);
    await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "yes" });
    await t.engine.markUntrusted(callId, "crm_note");
    await t.engine.beginVerification(callId, { accountNumber: "99999999" });
    await t.engine.finishVerification(callId);
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: false });
  });

  it("refuses a bad link, a call still running and a call without a receipt", async () => {
    const t = engine((c) => {
      c.modules.trace!.settings = { receipts: false, wordings: [consentWording] };
      c.flows = {};
    });
    const { callId } = await t.engine.startCall();
    for (const bad of ["http://receipts.example.test/r/x", "https://a.example.test/ x", `https://a.example.test/${"x".repeat(512)}`, "not a url"]) {
      await assert.rejects(t.engine.textReceiptLink(callId, bad), rejects("invalid_input"));
    }
    await assert.rejects(t.engine.textReceiptLink(callId, LINK), rejects("precondition_failed", /once the call has ended/));
    await t.engine.endCall(callId);
    await assert.rejects(t.engine.textReceiptLink(callId, LINK), rejects("precondition_failed", /no receipt yet/));
  });

  it("records one text when two processes send it at once", async () => {
    const t = engine();
    const callId = await depositCall(t, "yes");
    let inner: Promise<{ texted: boolean }> | null = null;
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async (input) => {
      if (inner === null) {
        inner = t.engine.textReceiptLink(callId, LINK);
        await inner;
      }
      return send(input);
    };
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: true });
    assert.deepEqual(await inner, { texted: true });
    assert.equal((await events(t, "receipt.link_texted")).length, 1);
  });
});

describe("contact change security notice", () => {
  it("goes to the number on file when the call started, and so does the receipt link", async () => {
    const t = engine();
    const callId = await verified(t, "change");
    await changePhone(t, callId);
    await changePhone(t, callId);
    await t.engine.updateModule(callId, "acme", (s) => ({ done: (s as { done: number }).done + 1 }));
    await paid(t, callId);
    assert.equal(t.messages.sent.at(-1)!.to, PHONE_ON_FILE, "the payment link went to the number Badge matched");
    await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "yes" });
    await t.engine.endCall(callId);
    const notices = texts(t, "contact_changed");
    assert.equal(notices.length, 1, "one notice: both contact steps changed the same subject's same number on file");
    assert.equal(notices[0]!.to, PHONE_ON_FILE);
    assert.equal(notices[0]!.body, contactNoticeText("en", BUSINESS));
    assert.equal(notices[0]!.body, `${BUSINESS}: the contact details on your account were changed during a call. If it was not you, contact us right away.`);
    assert.ok(!notices[0]!.body.includes(NEW_PHONE) && !notices[0]!.body.includes(PHONE_ON_FILE));
    assert.deepEqual((await events(t, "contact.notice_sent")).map((e) => e.detail), [{}]);
    await t.engine.textReceiptLink(callId, LINK);
    const receipt = texts(t, "receipt_link")[0]!;
    assert.equal(receipt.to, PHONE_ON_FILE);
    assert.equal(receipt.body, `Receipt from ${BUSINESS} for a change to your contact details, an access request and a payment on your call: ${LINK}`);
    assert.ok(t.messages.sent.every((m) => m.to !== NEW_PHONE), "nothing goes to the new number");
  });

  it("always goes, whatever the caller answered and with no receipt at all", async () => {
    const t = engine();
    const declined = await verified(t, "change");
    await changePhone(t, declined);
    // The flow is abandoned before its consent step: the notice goes anyway, and not twice.
    await assert.rejects(t.engine.endCall(declined).then(() => t.engine.endCall(declined)), rejects("invalid_transition"));
    assert.deepEqual(texts(t, "contact_changed").map((n) => n.to), [PHONE_ON_FILE]);
    assert.deepEqual(await t.engine.textReceiptLink(declined, LINK), { texted: false });
    const u = engine();
    const only = await verified(u, "change-only", "fr");
    await changePhone(u, only);
    assert.equal(await u.engine.endCall(only), null);
    const notices = texts(u, "contact_changed");
    assert.deepEqual(notices.map((n) => n.to), [PHONE_ON_FILE]);
    assert.equal(notices[0]!.body, contactNoticeText("fr", BUSINESS));
  });

  it("is sent again by endCall after a failed text, without ending the call again", async () => {
    const t = engine((c) => {
      c.modules.trace!.settings = { receipts: true, wordings: [consentWording] };
      c.flows = { "change-only": c.flows["change-only"]! };
    });
    const callId = await verified(t, "change-only");
    await changePhone(t, callId);
    const send = t.messages.sendText.bind(t.messages);
    let fail = true;
    t.messages.sendText = async (input) => {
      if (fail) {
        fail = false;
        throw new Error("carrier down");
      }
      return send(input);
    };
    await assert.rejects(t.engine.endCall(callId), /carrier down/);
    assert.equal((await t.engine.state(callId)).phase, "ended");
    assert.equal(await t.engine.endCall(callId), null);
    assert.equal(texts(t, "contact_changed")[0]!.body, contactNoticeText("en", null));
    assert.equal((await events(t, "call.ended")).length, 1);
    await assert.rejects(t.engine.endCall(callId), rejects("invalid_transition"));
  });

  it("goes for each subject whose contact details changed, and the receipt link only to its own subject", async () => {
    const t = engine();
    const callId = await verified(t, "two-subjects");
    await changePhone(t, callId);
    await verifyOther(t, callId);
    await t.engine.updateModule(callId, "acme", (s) => ({ done: (s as { done: number }).done + 1 }));
    await paid(t, callId);
    await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "yes" });
    await t.engine.endCall(callId);
    assert.deepEqual(texts(t, "contact_changed").map((n) => n.to), [PHONE_ON_FILE, OTHER_PHONE]);
    assert.equal((await events(t, "contact.notice_sent")).length, 2);
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: true });
    assert.deepEqual(texts(t, "receipt_link").map((m) => m.to), [OTHER_PHONE]);
  });

  it("never sends another subject's receipt link to the number kept for a contact change", async () => {
    const t = engine();
    const callId = await verified(t, "change-then-other");
    await changePhone(t, callId);
    await verifyOther(t, callId);
    await paid(t, callId);
    await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "yes" });
    await t.engine.endCall(callId);
    assert.deepEqual(texts(t, "contact_changed").map((n) => n.to), [PHONE_ON_FILE], "the notice still goes to the first subject's earlier number");
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: true });
    assert.deepEqual(texts(t, "receipt_link").map((m) => m.to), [OTHER_PHONE], "the receipt goes to its own subject's number");
  });

  it("finishes after the notice was sent but its ledger entry failed, without ending or texting again", async () => {
    const t = engine();
    const callId = await verified(t, "change-only");
    await changePhone(t, callId);
    const append = t.ledger.append.bind(t.ledger);
    t.ledger.append = async (input) => {
      if (input.event === "contact.notice_sent") {
        t.ledger.append = append;
        throw new Error("ledger down");
      }
      return append(input);
    };
    await assert.rejects(t.engine.endCall(callId), /ledger down/);
    assert.equal(await t.engine.endCall(callId), null);
    assert.equal(texts(t, "contact_changed").length, 1);
    assert.equal((await events(t, "contact.notice_sent")).length, 1);
    assert.equal((await events(t, "call.ended")).length, 1);
    await assert.rejects(t.engine.endCall(callId), rejects("invalid_transition"));
  });

  it("returns the receipt kept when its ledger entry failed, without signing again", async () => {
    const t = engine();
    const callId = await verified(t, "deposit");
    await paid(t, callId);
    await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "yes" });
    const append = t.ledger.append.bind(t.ledger);
    t.ledger.append = async (input) => {
      if (input.event === "receipt.issued") {
        t.ledger.append = append;
        throw new Error("ledger down");
      }
      return append(input);
    };
    await assert.rejects(t.engine.endCall(callId), /ledger down/);
    const kept = await t.engine.receipt(callId);
    assert.notEqual(kept, null);
    assert.deepEqual(await t.engine.endCall(callId), kept);
    assert.equal((await events(t, "receipt.issued")).length, 1);
  });

  it("records one notice when two processes send it at once", async () => {
    const t = engine();
    const callId = await verified(t, "change-only");
    await changePhone(t, callId);
    let inner: Promise<unknown> | null = null;
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async (input) => {
      if (inner === null) {
        inner = t.engine.endCall(callId);
        await inner;
      }
      return send(input);
    };
    await t.engine.endCall(callId);
    assert.equal((await events(t, "contact.notice_sent")).length, 1);
  });
});

describe("text wording", () => {
  it("names the business and the kinds of action, in English and French", () => {
    assert.equal(receiptLinkText("en", "B", ["money", "contact"], LINK), `Receipt from B for a payment and a change to your contact details on your call: ${LINK}`);
    assert.equal(receiptLinkText("fr", "B", ["access"], LINK), `Reçu de B pour une demande d'accès lors de votre appel : ${LINK}`);
    assert.equal(contactNoticeText("fr", null).startsWith("Avis de sécurité : "), true);
  });
});

describe("receipt text config", () => {
  const problems = (t: TestEngine, patch: (c: FlowConfig) => void) => validateConfig(config(patch), t.engine.registry);

  it("checks textLink, the consent wording, the business name and the messages adapter", () => {
    const t = engine();
    const receiptStep = (c: FlowConfig, step: JsonValue) => {
      c.flows = { f: { steps: [step as never] } };
    };
    assert.deepEqual(problems(t, (c) => receiptStep(c, { type: "trace.receipt", textLink: "yes" })), ["flows.f.steps[0] (trace.receipt): textLink must be { consent: <a wording purpose> }"]);
    assert.deepEqual(problems(t, (c) => receiptStep(c, { type: "trace.receipt", textLink: { consent: "x", more: 1 } })), ["flows.f.steps[0] (trace.receipt): textLink must be { consent: <a wording purpose> }"]);
    assert.deepEqual(problems(t, (c) => receiptStep(c, { type: "trace.receipt", textLink: { consent: "other" } })), ["flows.f.steps[0] (trace.receipt): no wording for other in the trace settings"]);
    assert.deepEqual(
      problems(t, (c) => {
        receiptStep(c, textedReceipt);
        c.modules.trace = {};
      }),
      ["flows.f.steps[0] (trace.receipt): no wording for receipt_texts in the trace settings", "flows.f.steps[0] (trace.receipt): a texted receipt link needs businessName in the trace settings"],
    );
    assert.deepEqual(
      problems(t, (c) => {
        receiptStep(c, textedReceipt);
        c.modules.trace = { settings: { businessName: "" } };
      }),
      ["modules.trace.settings: businessName must be 1 to 64 characters on one line"],
    );
    for (const name of [3, "   ", "A\nB", "x".repeat(65)]) {
      assert.deepEqual(problems(t, (c) => (c.modules.trace = { settings: { businessName: name as never } })), ["modules.trace.settings: businessName must be 1 to 64 characters on one line"]);
    }
    const withoutTexts = (c: FlowConfig) => {
      c.modules.badge!.settings = { factors: ["keypad_knowledge", "carrier_identity_match"] };
      c.modules.paylink = { enabled: false };
      c.flows = {};
    };
    const noMessages = engine(withoutTexts, { adapters: { messages: undefined } });
    const missing = problems(noMessages, (c) => {
      withoutTexts(c);
      c.flows = { f: { steps: [textedReceipt] }, g: { steps: [verify(["contact.update"]), { type: "acme.change_phone" }] } };
    });
    assert.deepEqual(missing, [
      "flows.f.steps[0] (trace.receipt): a texted receipt link needs the messages adapter, which the engine does not have",
      "flows.g.steps[1] (acme.change_phone): changes contact details, so it needs the messages adapter for the security notice, which the engine does not have",
    ]);
  });

  it("refuses to attach a texting flow to a call that kept no business name", async () => {
    const t = engine((c) => {
      c.modules.trace!.settings = { receipts: true, wordings: [consentWording] };
      c.flows = {};
    });
    const { callId } = await t.engine.startCall();
    t.engine.configure(config());
    await assert.rejects(t.engine.startFlow(callId, "deposit"), rejects("precondition_failed", /no business name/));
    await t.engine.startFlow(callId, "deposit-quiet");
  });
});
