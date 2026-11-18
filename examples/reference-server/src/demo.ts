// `npm run demo`: one scripted call, end to end, on fake adapters and a server on 127.0.0.1.
// No network beyond the loopback, no keys, no real people: the account, date of birth and phone
// numbers are made up (555 numbers), and the Stripe webhooks are signed here with a demo secret.
import type { JsonWebKey } from "node:crypto";
import type { AddressInfo } from "node:net";

import { signStripePayload, verifyChain, verifyReceipt, type SignedReceipt } from "../../../src/index.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject } from "../../../src/testing/index.ts";
import { createReferenceServer } from "./app.ts";

const DEMO_SECRET = "whsec_demo_not_a_secret";
const log = (step: string, detail = "") => console.log(`  ${step.padEnd(34)} ${detail}`);

export async function runDemo(print = true): Promise<{ receipt: SignedReceipt; tamperedFails: boolean; chainOk: boolean }> {
  const say = print ? log : () => undefined;
  const t = createTestEngine();
  t.records.putSubject(
    "ws_test",
    testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "12345678", phoneOnFile: "+15555550100", knowledge: { dob: "19850214" } }),
  );
  const server = createReferenceServer({
    engine: t.engine,
    stripeSecrets: { identity: [DEMO_SECRET], payments: [DEMO_SECRET] },
    clock: t.clock,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  let n = 0;
  const stripe = async (path: string, type: string, object: Record<string, unknown>) => {
    const payload = JSON.stringify({ id: `evt_demo_${++n}`, type, livemode: false, data: { object } });
    const header = signStripePayload(payload, DEMO_SECRET, Math.floor(t.clock.now().getTime() / 1000));
    const res = await fetch(`${base}${path}`, { method: "POST", headers: { "stripe-signature": header }, body: payload });
    return (await res.json()) as Record<string, unknown>;
  };

  try {
    say("District Assurance demo (fake adapters, no network)");
    const { callId } = await t.engine.startCall({ locale: "en" });
    say("call started", callId);

    // Verify: keypad first, then the photo ID link to the number on file.
    await t.engine.beginVerification(callId, { accountNumber: "12345678" });
    await t.engine.openSensitive(callId, "keypad");
    const keypad = await t.engine.submitKeypad(callId, { dob: "19850214" });
    await t.engine.closeSensitive(callId);
    say("verify: keypad checks", keypad.matched ? "matched (one answer for all fields)" : "no match");
    const carrier = await t.engine.checkCarrier(callId);
    say("verify: carrier signals", `texted code trusted: ${carrier.textCodeTrusted}`);
    await t.engine.startPhotoId(callId);
    say("verify: photo ID link texted", `to ${t.messages.sent.at(-1)!.to} (the number on file)`);
    const sessionId = t.identity.created.at(-1)!.sessionId;
    const idHook = await stripe("/webhooks/stripe/identity", "identity.verification_session.verified", { id: sessionId });
    say("webhook: identity verified", `signed, applied: ${String(idHook.applied)}`);
    const verified = await t.engine.finishVerification(callId);
    say("verify: finished", `level ${verified.level}, scopes ${verified.scopes.join(", ")}`);

    // File: a short intake the caller confirms.
    await t.engine.startIntake(callId, {
      formId: "maintenance",
      version: "1",
      fields: [
        { key: "issue", label: { en: "What is the problem?", fr: "Quel est le problème?" }, type: "text", required: true },
        { key: "urgent", label: { en: "Is it urgent?", fr: "Est-ce urgent?" }, type: "yes_no", required: true },
      ],
    });
    t.engine.setIntakeField(callId, "issue", "Water leak under the kitchen sink");
    t.engine.setIntakeField(callId, "urgent", "yes");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    say("file: record confirmed", `${record.recordId}, digest ${record.digest.slice(0, 16)}...`);

    // Guardrail: a card number read aloud is removed and interrupts.
    const heard = await t.engine.redact(callId, "my card is four two four two four two four two four two four two four two four two");
    say("guard: transcript redacted", `"${heard.text}", interrupt: ${heard.interrupt}`);

    // Pay: a link by text; Stripe says paid by webhook.
    const payment = await t.engine.requestPayment(callId, { amountMinor: 15000, currency: "cad", description: "Repair deposit", amountSource: "price_list" });
    say("pay: link texted", `${payment.paymentId}: "${t.messages.sent.at(-1)!.body}"`);
    const linkId = t.payments.created.at(-1)!.linkId;
    const payHook = await stripe("/webhooks/stripe/payments", "checkout.session.completed", { id: linkId, payment_status: "paid" });
    say("webhook: payment completed", `signed, applied: ${String(payHook.applied)}`);
    const replay = await stripe("/webhooks/stripe/payments", "checkout.session.completed", { id: linkId, payment_status: "paid" });
    say("webhook: same outcome again", `applied: ${String(replay.applied)} (settled once)`);

    // Prove: consent, then the signed receipt, checked with the public key only.
    await t.engine.recordConsent(callId, {
      wording: { purpose: "repair_texts", version: "1", text: { en: "May the office text you about this repair?", fr: "Le bureau peut-il vous texter au sujet de cette réparation?" } },
      answer: "yes",
    });
    say("prove: consent recorded", "wording fingerprinted, answer yes");
    await t.engine.endCall(callId);
    const receipt = (await (await fetch(`${base}/receipts/${callId}`)).json()) as SignedReceipt;
    const { keys } = (await (await fetch(`${base}/.well-known/receipt-keys.json`)).json()) as { keys: JsonWebKey[] };
    const valid = verifyReceipt(receipt, keys);
    const tampered = structuredClone(receipt);
    tampered.body.payments[0]!.amountMinor = 1;
    const tamperedFails = !verifyReceipt(tampered, keys);
    say("prove: receipt signature", valid ? "valid" : "INVALID");
    say("prove: receipt with one change", tamperedFails ? "rejected" : "ACCEPTED");
    const chain = verifyChain(await t.ledger.list());
    say("prove: audit ledger", chain.ok ? `${chain.head.seq} entries, hash chain intact` : "BROKEN");
    if (!valid || !tamperedFails || !chain.ok) throw new Error("the demo's checks failed");
    return { receipt, tamperedFails, chainOk: chain.ok };
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

if (import.meta.main) {
  const { receipt } = await runDemo();
  console.log("\nReceipt body:\n" + JSON.stringify(receipt.body, null, 2));
}
