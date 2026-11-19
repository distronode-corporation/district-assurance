// `npm run serve`: the reference server on a port, for trying the webhook routes with your OWN
// Stripe test-mode account (for example `stripe listen --forward-to localhost:8787/webhooks/stripe/identity`).
//
// Environment:
//   PORT                              default 8787, bound to 127.0.0.1
//   STRIPE_IDENTITY_KEY               a restricted test-mode key (rk_test_...) that can write Identity
//                                     VerificationSessions; turns on Stripe Identity and the trial call
//   STRIPE_IDENTITY_WEBHOOK_SECRET    the signing secret of your Identity webhook endpoint
//   STRIPE_PAYMENTS_WEBHOOK_SECRET    the signing secret of your Checkout webhook endpoint
//
// With STRIPE_IDENTITY_KEY, the engine creates photo ID checks in your Stripe test account, and
// one made-up trial call is verified by keypad and asks for one at start-up. Its text, with the
// single-use link, goes to a stand-in phone that prints it here, since the trial caller's number
// on file is a 555 number nothing is texted to; open the link, complete Stripe's test check, and
// the signed `identity.verification_session.*` event that `stripe listen` forwards is applied to
// the call. The engine's events for the trial (which hold no values) are printed too, so the
// applied outcome shows as a `verification.factor` line. Everything else runs on fake adapters until its Stripe adapter is built (PAY-1).
import type { Server } from "node:http";

import { systemClock, type MessagePurpose, type MessageSender } from "../../../src/index.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine, type TestEngineOptions } from "../../../src/testing/index.ts";

import { createReferenceServer } from "./app.ts";
import { StripeIdentityProvider, type StripeAdapterOptions } from "./stripe-adapters.ts";

const TRIAL_ACCOUNT = "12345678";
const TRIAL_DOB = "19850214";
const TRIAL_PHONE = "+15555550100";

/** The trial caller's phone: prints each text, the only place the trial's link appears. */
class StandInPhone implements MessageSender {
  readonly #print: (line: string) => void;
  #sent = 0;

  constructor(print: (line: string) => void) {
    this.#print = print;
  }

  async sendText(input: { to: string; body: string; purpose: MessagePurpose; idempotencyKey: string }): Promise<{ messageId: string }> {
    this.#print(`stand-in phone ${input.to} received: ${input.body}`);
    return { messageId: `msg_stand_in_${++this.#sent}` };
  }
}

export interface ServeOptions {
  env: Readonly<Record<string, string | undefined>>;
  /** Where the stand-in phone prints. Default `console.log`. */
  print?: (line: string) => void;
  /** For tests: a local fake in place of api.stripe.com. */
  stripe?: StripeAdapterOptions;
}

export interface Serve {
  server: Server;
  t: TestEngine;
  /** With STRIPE_IDENTITY_KEY only: starts the trial call and creates its Stripe Identity check. */
  startTrialCall: (() => Promise<{ callId: string; sessionId: string }>) | null;
}

export function createServe(options: ServeOptions): Serve {
  const { env } = options;
  const secret = (name: string) => (env[name] ?? "").split(",").filter((s) => s !== "");
  const key = env.STRIPE_IDENTITY_KEY ?? "";
  // A local server for trying things: a live key never belongs here.
  if (key !== "" && !key.startsWith("rk_test_")) throw new Error("STRIPE_IDENTITY_KEY must be a restricted test-mode key (rk_test_...)");
  const print = options.print ?? console.log;
  const sessions: string[] = [];
  let trial: TestEngineOptions = {};
  if (key !== "") {
    const stripe = new StripeIdentityProvider(key, options.stripe);
    trial = {
      adapters: {
        identity: {
          async createDocumentCheck(input: { callId: string; idempotencyKey: string }) {
            const check = await stripe.createDocumentCheck(input);
            sessions.push(check.sessionId);
            return check;
          },
        },
        messages: new StandInPhone(print),
      },
      // The engine's events carry what happened and how, never a value, so they can be printed.
      onEvent: (event) => print(`${event.callId} ${event.name} ${JSON.stringify(event.detail)}`),
    };
  }
  const t = createTestEngine({ clock: systemClock, ...trial });
  const server = createReferenceServer({
    engine: t.engine,
    clock: systemClock,
    stripeSecrets: { identity: secret("STRIPE_IDENTITY_WEBHOOK_SECRET"), payments: secret("STRIPE_PAYMENTS_WEBHOOK_SECRET") },
  });
  const startTrialCall = async () => {
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: TRIAL_ACCOUNT, phoneOnFile: TRIAL_PHONE, knowledge: { dob: TRIAL_DOB } }));
    const { callId } = await t.engine.startCall({ locale: "en" });
    await t.engine.beginVerification(callId, { accountNumber: TRIAL_ACCOUNT });
    await t.engine.openSensitive(callId, "keypad");
    await t.engine.submitKeypad(callId, { dob: TRIAL_DOB });
    await t.engine.closeSensitive(callId);
    await t.engine.startPhotoId(callId);
    return { callId, sessionId: sessions.at(-1)! };
  };
  return { server, t, startTrialCall: key === "" ? null : startTrialCall };
}

if (import.meta.main) {
  const port = Number(process.env.PORT ?? 8787);
  const { server, startTrialCall } = createServe({ env: process.env });
  server.listen(port, "127.0.0.1", () => {
    console.log(`reference server on http://127.0.0.1:${port} (pre-alpha, fake adapters${startTrialCall === null ? "" : " but Stripe Identity"})`);
    startTrialCall?.().then(
      ({ callId, sessionId }) => console.log(`trial call ${callId}: Stripe Identity check ${sessionId} created, waiting for its webhook`),
      (error: unknown) => console.error(`trial call failed: ${error instanceof Error ? error.message : "unknown error"}`),
    );
  });
}
