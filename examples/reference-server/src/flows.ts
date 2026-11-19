// The demo's FlowConfig: one workspace with five flows. Gate must be installed with
// `modules: [gateModule(...)]` for it to validate (its targets name the gate's "lobby" controller).
//
// - `owner-command`: the line's owner keys their PIN; Badge checks it against a keyed hash and
//   nothing else counts. The grant covers `owner.command` only. The ledger records it (Trace is
//   always on). Scopes are granted by level, so every verify step names the scopes it is for: a
//   caller verified for a deposit never holds `owner.command`.
// - `deposit`: keypad knowledge plus a carrier identity match (level 2, the floor for payments),
//   a maintenance form the caller confirms, a payment link texted to the number on file, a consent,
//   and a signed receipt. The money goes to the platform's own account (`platform` mode).
// - `deposit-connect`: the same verification and a deposit on the business's own account
//   (`connect` mode, a made-up connected account), with a 10-minute link and cards and wallets only.
// - `entry`: verification to level 2 for `entry.open` (an access scope, never below level 2), then
//   a signed, 30-second access grant for the front door.
// - `visit`: the live demo's call (`npm run demo:e2e`): level 2, a deposit by a real Stripe
//   test-mode Checkout link on the platform's account, the front door once it is paid, a receipt.
import { defaultVerificationPolicy, type FlowConfig } from "../../../src/index.ts";

export function demoConfig(): FlowConfig {
  const policy = defaultVerificationPolicy();
  policy.version = "demo-1";
  policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["pin"]] };
  policy.scopes["owner.command"] = 1;
  // An owner's own command moves no money and changes no contact details; its floor is 0.
  policy.scopeClasses = { "owner.command": "none" };
  policy.scopes["entry.open"] = 2;
  return {
    version: 1,
    revision: "demo-2026-11",
    policy,
    modules: {
      badge: {
        settings: {
          factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id"],
          pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 },
        },
      },
      dossier: {
        settings: {
          forms: [
            {
              formId: "maintenance",
              version: "1",
              fields: [
                { key: "issue", label: { en: "What is the problem?", fr: "Quel est le problème?" }, type: "text", required: true },
                { key: "urgent", label: { en: "Is it urgent?", fr: "Est-ce urgent?" }, type: "yes_no", required: true },
              ],
            },
          ],
        },
      },
      paylink: { settings: { maxAmountMinor: 50000, mode: "platform", connectedAccountId: "acct_demo_business" } },
      gate: { settings: { targets: [{ id: "front-door", controller: "lobby", ref: "door-1" }] } },
      trace: {
        settings: {
          receipts: true,
          wordings: [
            {
              purpose: "repair_texts",
              version: "1",
              text: { en: "May the office text you about this repair?", fr: "Le bureau peut-il vous texter au sujet de cette réparation?" },
            },
          ],
        },
      },
    },
    flows: {
      "owner-command": {
        summary: "The owner's PIN, and nothing else, before an owner command.",
        steps: [{ type: "badge.verify", level: 1, factors: ["pin"], scopes: ["owner.command"] }],
      },
      deposit: {
        summary: "Verify to level 2, file a repair, take a deposit by link, ask consent, sign a receipt.",
        steps: [
          { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["intake.file", "payment.request"] },
          { type: "dossier.collect", form: "maintenance" },
          { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Repair deposit", amountSource: "price_list", mode: "platform" },
          { type: "trace.consent", purpose: "repair_texts" },
          { type: "trace.receipt" },
        ],
      },
      "deposit-connect": {
        summary: "Verify to level 2 and take a deposit on the business's own account.",
        steps: [
          { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] },
          {
            type: "paylink.request",
            amountMinor: 5000,
            currency: "cad",
            description: "Booking deposit",
            amountSource: "price_list",
            mode: "connect",
            linkLifeMinutes: 10,
            paymentMethods: ["card", "apple_pay", "google_pay"],
          },
          { type: "trace.receipt" },
        ],
      },
      entry: {
        summary: "Verify to level 2, then a signed 30-second grant for the front door.",
        steps: [
          { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["entry.open"] },
          { type: "gate.grant", target: "front-door", lifetimeSeconds: 30 },
        ],
      },
      visit: {
        summary: "Verify to level 2, take a deposit by a Stripe test-mode link, open the front door once paid, sign a receipt.",
        steps: [
          { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request", "entry.open"] },
          { type: "paylink.request", amountMinor: 2500, currency: "cad", description: "Visit deposit (Stripe test mode)", amountSource: "price_list", mode: "platform" },
          { type: "gate.grant", target: "front-door", lifetimeSeconds: 30 },
          { type: "trace.receipt" },
        ],
      },
    },
  };
}
