// The calls the recorded Stripe test-mode runs make (record.ts) and the tests replay
// (test/stripe-real.test.ts): one config and one driver, so the replay asks Stripe exactly what the
// recording did. Two paid deposits, each verified to level 2 first: `record-platform` on the
// platform's own account, `record-connect` as a direct charge on a connected account, offering
// cards and both wallets; and `record-connect-link`, cards and Link on the connected account, a
// link the caller cancels (the adapter closes it on the connected account).
import type { FlowConfig } from "../../../src/index.ts";
import { demoConfig } from "../../../examples/reference-server/src/flows.ts";
import { verifyToLevel2, type DemoWorld, type ScriptRun } from "../../../examples/reference-server/src/script.ts";

export type RecordedFlow = "record-platform" | "record-connect" | "record-connect-link";

/** The demo's config with the two recorded flows, and `account` as the paylink's connected account. */
export function recordedConfig(account: string): FlowConfig {
  const config = demoConfig();
  config.modules.paylink = { settings: { maxAmountMinor: 50000, mode: "platform", connectedAccountId: account } };
  config.flows["record-platform"] = {
    summary: "Verify to level 2, take a deposit by a Stripe test-mode link on the platform's account, sign a receipt.",
    steps: [
      { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] },
      { type: "paylink.request", amountMinor: 2500, currency: "cad", description: "Recorded deposit (platform, Stripe test mode)", amountSource: "price_list", mode: "platform" },
      { type: "trace.receipt" },
    ],
  };
  config.flows["record-connect"] = {
    summary: "Verify to level 2, take a deposit as a direct charge on the business's connected account, sign a receipt.",
    steps: [
      { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] },
      {
        type: "paylink.request",
        amountMinor: 3500,
        currency: "cad",
        description: "Recorded deposit (connect, Stripe test mode)",
        amountSource: "price_list",
        mode: "connect",
        paymentMethods: ["card", "apple_pay", "google_pay"],
      },
      { type: "trace.receipt" },
    ],
  };
  config.flows["record-connect-link"] = {
    summary: "Verify to level 2, then a deposit link with cards and Link on the business's connected account.",
    steps: [
      { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] },
      {
        type: "paylink.request",
        amountMinor: 1500,
        currency: "cad",
        description: "Recorded deposit (connect, cards and Link, Stripe test mode)",
        amountSource: "price_list",
        mode: "connect",
        paymentMethods: ["card", "link"],
      },
      { type: "trace.receipt" },
    ],
  };
  return config;
}

/** Starts the flow, verifies to level 2, confirms the amount and requests the link. Answers the call and its link. */
export async function requestRecordedLink(w: DemoWorld, flow: RecordedFlow): Promise<{ call: ScriptRun; link: { paymentId: string; linkId: string; url: string } }> {
  const call: ScriptRun = { callId: "", linkId: "", receipt: null, receiptToken: null };
  call.callId = (await w.engine.startCall({ locale: "en", flow })).callId;
  const verified = await verifyToLevel2(w, call, "payment.request");
  if (!verified.ok) throw new Error(`verification did not reach level 2: ${verified.detail}`);
  const back = await w.engine.readBackPayment(call.callId);
  await w.engine.confirmPaymentAmount(call.callId, { digest: back.digest, confirmedBy: "keypad" });
  const payment = await w.engine.requestPayment(call.callId);
  const link = w.links.find((l) => l.paymentId === payment.paymentId)!;
  call.linkId = link.linkId;
  return { call, link: { paymentId: payment.paymentId, linkId: link.linkId, url: link.url } };
}
