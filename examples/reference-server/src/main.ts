// `npm run serve`: the reference server on a port, for trying the webhook routes with your OWN
// Stripe test-mode account (for example `stripe listen --forward-to localhost:8787/webhooks/stripe/identity`).
//
// Environment:
//   PORT                              default 8787, bound to 127.0.0.1 (0: any free port, named in
//                                     the first line)
//   STRIPE_IDENTITY_KEY               a restricted test-mode key (rk_test_...) that can write Identity
//                                     VerificationSessions; turns on Stripe Identity and the trial call
//   STRIPE_IDENTITY_WEBHOOK_SECRET    the signing secret of your Identity webhook endpoint
//   STRIPE_PAYMENTS_WEBHOOK_SECRET    the signing secret of your Checkout webhook endpoint (platform mode)
//   STRIPE_CONNECT_WEBHOOK_SECRET     the signing secret of your Connect endpoint (connect mode;
//                                     `stripe listen --forward-connect-to localhost:8787/webhooks/stripe/connect`)
//
// With STRIPE_IDENTITY_KEY, the engine creates photo ID checks in your Stripe test account, and
// one made-up trial call is verified by keypad and asks for one at start-up. Its text, with the
// single-use link, goes to a stand-in phone that prints it here, since the trial caller's number
// on file is a 555 number nothing is texted to; open the link, complete Stripe's test check, and
// the signed `identity.verification_session.*` event that `stripe listen` forwards is applied to
// the call. The engine's events for the trial (which hold no values) are printed too, so the
// applied outcome shows as a `verification.factor` line. Each answered request is logged as one
// JSON line (route pattern, status, time; never a path, header or body). Everything else runs on
// fake adapters; payments by a real Checkout link are `npm run demo:e2e`.
import { realpathSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";

import { systemClock, type Clock, type IdGenerator, type MessagePurpose, type MessageSender } from "../../../src/index.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine, type TestEngineOptions } from "../../../src/testing/index.ts";

import { createReferenceServer, logJsonLines, type JsonLinesLog, type RequestLog } from "./app.ts";
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
  /** For tests: the clock for the engine and the webhook signature window. Default the system clock. */
  clock?: Clock;
  /**
   * The engine's ids. Default the test engine's sequential ones (`call_1`, ...). A run against
   * Stripe that is repeated within a day passes ids of its own: the engine's idempotency keys are
   * built from them, and Stripe answers a key it has seen in the last 24 hours with the first
   * answer (an earlier run's session, already used).
   */
  ids?: IdGenerator;
  /** Where each answered request's log entry goes. Default one JSON line each on standard output. */
  log?: (entry: RequestLog) => void;
}

export interface Serve {
  server: Server;
  t: TestEngine;
  /** With STRIPE_IDENTITY_KEY only: starts the trial call and creates its Stripe Identity check. */
  startTrialCall: (() => Promise<{ callId: string; sessionId: string }>) | null;
}

/**
 * Takes the error events of the stream a log writes to, and stops the log on the first. An EPIPE
 * on standard output (its reader went away) arrives as an `error` event, which with no listener
 * would end the process. Registered once, before the server starts.
 */
export function guardLogStream(stream: { on(event: "error", listener: (error: Error) => void): unknown }, log: Pick<JsonLinesLog, "stop">): void {
  stream.on("error", () => log.stop());
}

export function createServe(options: ServeOptions): Serve {
  const { env } = options;
  const secret = (name: string) => (env[name] ?? "").split(",").filter((s) => s !== "");
  const key = env.STRIPE_IDENTITY_KEY ?? "";
  // A local server for trying things: a live key never belongs here.
  if (key !== "" && !key.startsWith("rk_test_")) throw new Error("STRIPE_IDENTITY_KEY must be a restricted test-mode key (rk_test_...)");
  const print = options.print ?? console.log;
  // By call id, so overlapping trial calls each read their own session.
  const sessions = new Map<string, string>();
  let trial: TestEngineOptions = {};
  if (key !== "") {
    const stripe = new StripeIdentityProvider(key, options.stripe);
    trial = {
      adapters: {
        identity: {
          async createDocumentCheck(input: { callId: string; idempotencyKey: string }) {
            const check = await stripe.createDocumentCheck(input);
            sessions.set(input.callId, check.sessionId);
            return check;
          },
        },
        messages: new StandInPhone(print),
      },
      // The engine's events carry what happened and how, never a value, so they can be printed.
      onEvent: (event) => print(`${event.callId} ${event.name} ${JSON.stringify(event.detail)}`),
    };
  }
  const clock = options.clock ?? systemClock;
  const t = createTestEngine({ clock, ...(options.ids === undefined ? {} : { ids: options.ids }), ...trial });
  const server = createReferenceServer({
    engine: t.engine,
    clock,
    stripeSecrets: { identity: secret("STRIPE_IDENTITY_WEBHOOK_SECRET"), payments: secret("STRIPE_PAYMENTS_WEBHOOK_SECRET"), connect: secret("STRIPE_CONNECT_WEBHOOK_SECRET") },
    log: options.log ?? logJsonLines,
  });
  const startTrialCall = async () => {
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: TRIAL_ACCOUNT, phoneOnFile: TRIAL_PHONE, knowledge: { dob: TRIAL_DOB } }));
    const { callId } = await t.engine.startCall({ locale: "en" });
    await t.engine.beginVerification(callId, { accountNumber: TRIAL_ACCOUNT });
    await t.engine.openSensitive(callId, "keypad");
    await t.engine.submitKeypad(callId, { dob: TRIAL_DOB });
    await t.engine.closeSensitive(callId);
    await t.engine.startPhotoId(callId);
    return { callId, sessionId: sessions.get(callId)! };
  };
  return { server, t, startTrialCall: key === "" ? null : startTrialCall };
}

/**
 * Whether the module at `moduleUrl` is the program node was started with (`entry`, its argv[1]).
 * Not `import.meta.main`: on Node.js 24.2 (the floor before 24.19) it is false for a `.ts`
 * entry, so `npm run serve` exited at once without listening. Both paths are resolved through
 * symlinks; importing this module from anywhere else does not start the server.
 */
export function isProgram(entry: string | undefined, moduleUrl: string): boolean {
  if (entry === undefined) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

if (isProgram(process.argv[1], import.meta.url)) {
  guardLogStream(process.stdout, logJsonLines);
  const port = Number(process.env.PORT ?? 8787);
  const { server, startTrialCall } = createServe({ env: process.env });
  server.listen(port, "127.0.0.1", () => {
    console.log(`reference server on http://127.0.0.1:${(server.address() as AddressInfo).port} (pre-alpha, fake adapters${startTrialCall === null ? "" : " but Stripe Identity"})`);
    startTrialCall?.().then(
      ({ callId, sessionId }) => console.log(`trial call ${callId}: Stripe Identity check ${sessionId} created, waiting for its webhook`),
      (error: unknown) => console.error(`trial call failed: ${error instanceof Error ? error.message : "unknown error"}`),
    );
  });
}
