// `npm run demo`: two scripted calls, end to end, on fake adapters and a server on 127.0.0.1.
// No network beyond the loopback, no keys, no real people: the accounts, the PIN, the date of birth
// and the phone numbers are made up (555 numbers), and the Stripe webhook is signed here with a
// demo secret.
//
// 1. `owner-command`: the owner's PIN only, on two engines that share one session store (as two
//    processes of a host would). One wrong PIN, then the right one.
// 2. `deposit`: keypad knowledge and a carrier match to level 2, a repair form, a deposit by link
//    settled by a signed webhook, a consent, and a signed receipt checked with the public key.
import type { JsonWebKey } from "node:crypto";
import type { AddressInfo } from "node:net";

import { createEngine, signStripePayload, subjectKeyFor, verifyChain, verifyReceipt, type SignedReceipt } from "../../../src/index.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, generateTestSigner, testSubject } from "../../../src/testing/index.ts";
import { createReferenceServer } from "./app.ts";
import { demoConfig } from "./flows.ts";

const DEMO_SECRET = "whsec_demo_not_a_secret";
const OWNER_ACCOUNT = "10000001";
const OWNER_PIN = "4826";
const log = (step: string, detail = "") => console.log(`  ${step.padEnd(36)} ${detail}`);

export interface DemoResult {
  ownerAuthorized: boolean;
  ownerReceipt: SignedReceipt | null;
  receipt: SignedReceipt;
  tamperedFails: boolean;
  chainOk: boolean;
}

export async function runDemo(print = true): Promise<DemoResult> {
  const say = print ? log : () => undefined;
  const t = createTestEngine({ config: demoConfig() });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: OWNER_ACCOUNT, phoneOnFile: "+15555550101", knowledge: {}, pin: OWNER_PIN }));
  t.records.putSubject(
    "ws_test",
    testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "12345678", phoneOnFile: "+15555550100", knowledge: { dob: "19850214" } }),
  );
  t.carrier.set("+15555550100", { identityMatch: "match" });
  // A second engine on the same session store and ledger: another process of the same host.
  const other = createEngine({
    workspaceId: "ws_test",
    knowledgeKey: TEST_KNOWLEDGE_KEY,
    config: demoConfig(),
    clock: t.clock,
    ids: t.ids,
    adapters: { ledger: t.ledger, sessions: t.sessions, records: t.records, identity: t.identity, carrier: t.carrier, messages: t.messages, payments: t.payments, signer: generateTestSigner() },
  });
  const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [DEMO_SECRET], payments: [DEMO_SECRET] }, clock: t.clock });
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

    // 1. owner-command: process A answers, process B checks the PIN, both on one session store.
    const owner = await t.engine.startCall({ flow: "owner-command" });
    say("owner-command: call started", `${owner.callId} on process A`);
    await other.beginVerification(owner.callId, { subjectKey: subjectKeyFor(TEST_KNOWLEDGE_KEY, OWNER_ACCOUNT) });
    await other.openSensitive(owner.callId, "keypad");
    const wrong = await other.submitPin(owner.callId, "1111");
    say("owner-command: PIN on process B", wrong.matched ? "matched" : "no match (one attempt used)");
    const right = await t.engine.submitPin(owner.callId, OWNER_PIN);
    say("owner-command: PIN on process A", right.matched ? "matched" : "no match");
    const ownerLevel = await other.finishVerification(owner.callId);
    const position = await t.engine.flowPosition(owner.callId);
    say("owner-command: verified", `level ${ownerLevel.level}, flow ${position!.status}`);
    const ownerAuthorized = await t.engine.authorize(owner.callId, "owner.command");
    const moneyRefused = !(await t.engine.authorize(owner.callId, "payment.request"));
    say("owner-command: scopes", `owner.command ${ownerAuthorized ? "allowed" : "REFUSED"}, payment.request ${moneyRefused ? "refused (floor 2)" : "ALLOWED"}`);
    const ownerReceipt = await t.engine.endCall(owner.callId);
    say("owner-command: call ended", ownerReceipt === null ? "no receipt in this flow, the ledger has it all" : "receipt issued");

    // 2. deposit: the flow decides the steps, the factors and the amount.
    const { callId } = await t.engine.startCall({ locale: "en", flow: "deposit" });
    say("deposit: call started", callId);
    const ownerScopeOnDeposit = () => t.engine.authorize(callId, "owner.command");
    await t.engine.beginVerification(callId, { accountNumber: "12345678" });
    await t.engine.openSensitive(callId, "keypad");
    const keypad = await t.engine.submitKeypad(callId, { dob: "19850214" });
    await t.engine.closeSensitive(callId);
    say("verify: keypad checks", keypad.matched ? "matched (one answer for all fields)" : "no match");
    const carrier = await t.engine.checkCarrier(callId);
    say("verify: carrier signals", `identity match recorded, texted code trusted: ${carrier.textCodeTrusted}`);
    const verified = await t.engine.finishVerification(callId);
    say("verify: finished", `level ${verified.level}, scopes ${verified.scopes.join(", ")}`);
    const noOwnerScope = !(await ownerScopeOnDeposit());

    await t.engine.startIntake(callId, "maintenance");
    await t.engine.setIntakeField(callId, "issue", "Water leak under the kitchen sink");
    await t.engine.setIntakeField(callId, "urgent", "yes");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    say("file: record confirmed", `${record.recordId}, digest ${record.digest.slice(0, 16)}...`);

    const heard = await t.engine.redact(callId, "my card is four two four two four two four two four two four two four two four two");
    say("guard: transcript redacted", `"${heard.text}", interrupt: ${heard.interrupt}`);

    const payment = await t.engine.requestPayment(callId);
    say("pay: link texted, amount from flow", `${payment.paymentId}: "${t.messages.sent.at(-1)!.body}"`);
    const linkId = t.payments.created.at(-1)!.linkId;
    const payHook = await stripe("/webhooks/stripe/payments", "checkout.session.completed", { id: linkId, payment_status: "paid" });
    say("webhook: payment completed", `signed, applied: ${String(payHook.applied)}`);
    const replay = await stripe("/webhooks/stripe/payments", "checkout.session.completed", { id: linkId, payment_status: "paid" });
    say("webhook: same outcome again", `applied: ${String(replay.applied)} (settled once)`);

    await t.engine.recordConsent(callId, { purpose: "repair_texts", answer: "yes" });
    say("prove: consent recorded", "wording fingerprinted, answer yes");
    const done = await t.engine.flowPosition(callId);
    say("deposit: flow", `${done!.status} (${done!.index} steps)`);
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
    say("prove: audit ledger (both calls)", chain.ok ? `${chain.head.seq} entries, hash chain intact` : "BROKEN");
    if (!ownerAuthorized || !moneyRefused || !noOwnerScope || !valid || !tamperedFails || !chain.ok) throw new Error("the demo's checks failed");
    return { ownerAuthorized, ownerReceipt, receipt, tamperedFails, chainOk: chain.ok };
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

if (import.meta.main) {
  const { receipt } = await runDemo();
  console.log("\nDeposit receipt body:\n" + JSON.stringify(receipt.body, null, 2));
}
