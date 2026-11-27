// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile pass on #112 (PRV-10 receipt link text and contact change notice), kept as regressions:
// each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { MessagePurpose } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import type { AssuranceModule } from "../src/core/module.ts";
import { TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, confirmAmount, DOB, PHONE_ON_FILE, rejects, setup, testConfig, wording } from "./helpers.ts";

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

async function verified(t: TestEngine, flow: string, locale: "en" | "fr" = "en"): Promise<string> {
  const { callId } = await t.engine.startCall({ flow, locale });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

async function paid(t: TestEngine, callId: string): Promise<void> {
  await confirmAmount(t.engine, callId);
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

describe("#112 hostile: the receipt link", () => {
  it("R1 a link with a control, format or bidi character (NEL, NUL, ZWSP, RLO, an isolate, a BOM) is refused and nothing is texted", async () => {
    const t = engine();
    const callId = await depositCall(t, "yes");
    for (const ch of ["\u0085", "\u0000", "\u007f", "\u200b", "\u202e", "\u2066", "\u2069", "\ufeff", "\u00ad", "\u061c"]) {
      const url = `${LINK}${ch}Reply-STOP`;
      await assert.rejects(t.engine.textReceiptLink(callId, url), rejects("invalid_input"), JSON.stringify(ch));
    }
    assert.equal(texts(t, "receipt_link").length, 0);
    assert.deepEqual(await t.engine.textReceiptLink(callId, `${LINK}?lang=fr#top`), { texted: true }, "a plain link still goes");
  });

  it("R2 two link texts at once send one text by its key and log it once", async () => {
    const t = engine();
    const callId = await depositCall(t, "yes");
    const keys: string[] = [];
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async (input) => (keys.push(input.idempotencyKey), send(input));
    const results = await Promise.all([t.engine.textReceiptLink(callId, LINK), t.engine.textReceiptLink(callId, LINK)]);
    assert.deepEqual(results, [{ texted: true }, { texted: true }]);
    assert.deepEqual([keys.length, new Set(keys).size], [2, 1], "both sends carry one idempotency key");
    assert.equal((await events(t, "receipt.link_texted")).length, 1);
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: false });
  });
});

describe("#112 hostile: sweepAlerts", () => {
  it("S1 two workspaces with the same call ids on shared stores: a sweep sends only its own workspace's notices", async () => {
    const t = engine();
    const other = setup({ config: config(), modules: [acmeModule()], workspaceId: "ws_other", adapters: { sessions: t.sessions, ledger: t.ledger, messages: t.messages } });
    other.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    other.records.putSubject("ws_other", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: OTHER_PHONE, knowledge: { dob: DOB } }));
    other.carrier.set(OTHER_PHONE, { identityMatch: "match" });
    const send = t.messages.sendText.bind(t.messages);
    let down = true;
    t.messages.sendText = async (input) => {
      if (down) throw new Error("carrier down");
      return send(input);
    };
    const { callId } = await other.engine.startCall({ flow: "change-only" });
    await other.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await other.engine.submitKeypad(callId, { dob: DOB });
    await other.engine.checkCarrier(callId);
    await other.engine.finishVerification(callId);
    await other.engine.updateModule(callId, "acme", (s) => ({ done: (s as { done: number }).done + 1 }));
    const mine = await verified(t, "change-only");
    assert.equal(mine, callId, "the same call id in both workspaces");
    await changePhone(t, mine);
    down = false;
    assert.deepEqual(await t.engine.sweepAlerts(), { sent: [mine], failed: [] });
    assert.deepEqual(texts(t, "contact_changed").map((m) => m.to), [PHONE_ON_FILE], "only this workspace's number");
    assert.deepEqual(await other.engine.sweepAlerts(), { sent: [callId], failed: [] });
    assert.deepEqual(texts(t, "contact_changed").map((m) => m.to), [PHONE_ON_FILE, OTHER_PHONE]);
  });
});

describe("#112 hostile: a notice owed on a call the host's retention removed", () => {
  it("S2 is reported as failed on every sweep, never as sent and never silently dropped", async () => {
    const t = engine();
    const callId = await verified(t, "change-only");
    const send = t.messages.sendText.bind(t.messages);
    let down = true;
    t.messages.sendText = async (input) => {
      if (down) throw new Error("carrier down");
      return send(input);
    };
    await changePhone(t, callId);
    down = false;
    const get = t.sessions.get.bind(t.sessions);
    t.sessions.get = async (ws, id) => (id === callId ? null : get(ws, id));
    for (let i = 0; i < 2; i++) assert.deepEqual(await t.engine.sweepAlerts(), { sent: [], failed: [callId] });
    assert.equal(texts(t, "contact_changed").length, 0);
  });
});
