// PAY-2 (#88): amounts from code, read back to the caller and confirmed before every payment link.
// Ported from #88's engine.test.ts block onto the merged Paylink (modes, link life, deadlines).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AmountLookup, AmountSource } from "../src/core/adapters.ts";
import { PriceListAmounts, buildAmountReadBack } from "../src/pay/amount.ts";
import type { PaylinkSlice } from "../src/pay/paylink.ts";
import { TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, confirmAmount, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

/** A request's id and status; its deadline depends on the clock and is tested in paylink-modes. */
const idAndStatus = ({ paymentId, status }: { paymentId: string; status: string }) => ({ paymentId, status });

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
    assert.deepEqual(back, buildAmountReadBack("en", { amountMinor: 15000, currency: "cad", description: "Deposit" }, "amt_1"));
    assert.match(back.digest, /^[0-9a-f]{64}$/);
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /not confirmed/));
    await assert.rejects(t.engine.requestPayment(callId, { ...request, amountMinor: 100 }), rejects("precondition_failed", /not the amount read back/));
    await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest: "0".repeat(64), confirmedBy: "keypad" }), rejects("precondition_failed", /not the amount last read back/));
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "keypad" });
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "keypad" });
    assert.deepEqual(idAndStatus(await t.engine.requestPayment(callId)), { paymentId: "pay_1", status: "open" }, "outside a flow, the confirmed read-back is the request");
    assert.equal(t.messages.sent.at(-1)!.body, "Your secure payment link for $150.00: https://pay.example.test/c/cs_fake_1");
    await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "voice" }), rejects("precondition_failed", /no amount was read back/), "a read-back serves one link");
    await assert.rejects(t.engine.readBackPayment(callId, request), rejects("invalid_transition", /while paying/));
    const entries = await t.ledger.list();
    assert.deepEqual(entries.filter((e) => e.event.startsWith("payment.")).map((e) => [e.event, e.detail]), [
      ["payment.amount_read_back", { amountMinor: 15000, currency: "cad", amountSource: "price_list", digest: back.digest }],
      ["payment.amount_confirmed", { digest: back.digest, confirmedBy: "keypad" }],
      ["payment.link_sent", { paymentId: "pay_1", linkId: "cs_fake_1", amountMinor: 15000, currency: "cad", amountSource: "price_list", mode: "platform", channel: "text", expiresAt: "2026-01-01T00:15:00.000Z" }],
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

  it("reads an AmountSource that answers nothing at all as no amount, not as a crash", async () => {
    // An async resolve that falls through returns undefined, not the null the interface asks for.
    for (const nothing of [undefined, null]) {
      const t = setup({ adapters: { amounts: { resolve: async () => nothing as unknown as null } } });
      const callId = await verifiedCall(t);
      await assert.rejects(t.engine.readBackPayment(callId, byRef), rejects("precondition_failed", /no amount for this reference/), String(nothing));
    }
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
    assert.deepEqual(idAndStatus(await t.engine.requestPayment(callId, request)), { paymentId: "pay_1", status: "open" }, "a read-back works on an older call");
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
    assert.deepEqual(idAndStatus(await t.engine.requestPayment(callId, byRef)), { paymentId: "pay_1", status: "open" });
    assert.equal(t.payments.created.length, 1);
    assert.equal(t.payments.created[0]!.amountMinor, 12500);

    // A read-back confirmed and sent without input: the read-back's request is the one to resume.
    const plain = setup({ adapters: { amounts: prices() } });
    const call = await verifiedCall(plain);
    const heard = await plain.engine.readBackPayment(call, byRef);
    await plain.engine.confirmPaymentAmount(call, { digest: heard.digest, confirmedBy: "voice" });
    const plainSend = plain.messages.sendText.bind(plain.messages);
    plain.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(plain.engine.requestPayment(call), /carrier down/);
    plain.messages.sendText = plainSend;
    const sentBefore = plain.messages.sent.length;
    assert.equal((await plain.engine.requestPayment(call, byRef)).paymentId, "pay_1");
    assert.equal(plain.messages.sent.length, sentBefore + 1, "the retry texted through this fixture's own sender");
  });
});

