// `npm run demo:e2e`: the demo UI with one real piece, a Stripe Checkout Session in TEST MODE.
// Everything else stays local and made up: the caller, the carrier, the texts, the ledger, and
// the example door relay on another loopback port. No production system is involved.
//
// Two scripted calls, run from the page one click at a time:
//   1. `owner-command`: the owner's PIN on the keypad, to Badge level 1.
//   2. `visit`: keypad knowledge and a carrier match to level 2; Paylink in platform mode creates a
//      real test-mode Checkout Session; you pay it in the browser with a Stripe test card; the demo
//      reads the session back from Stripe (read only) until it is paid and settles the payment;
//      the engine's Gate signs a grant, the relay checks it (ES256, workspace, audience, window, replay) and
//      opens the pretend door; the call ends with a signed receipt the page verifies.
//
// Payment completion is a read-only poll of the Checkout Session, not a webhook: no `stripe
// listen`, nothing for Stripe to reach on this machine.
//
// Environment, read once at start-up and then removed from this process's environment:
//   STRIPE_TEST_SECRET_KEY   a Stripe secret key for TEST MODE (sk_test_...). Anything else,
//                            a live or restricted key included, is refused before anything runs.
//   PORT                     default 8787, bound to 127.0.0.1
import type { Server } from "node:http";

import { EngineError, randomIds, systemClock, type FlowConfig, type SignedReceipt } from "../../../src/index.ts";
import { createReferenceServer } from "./app.ts";
import { DemoRuns } from "./demo-runs.ts";
import { isProgram } from "./main.ts";
import { demoConfig } from "./flows.ts";
import { SCRIPTS, createDemoWorld, pass, verifyToLevel2, type DemoWorld, type ScriptStep, type Scripts, type StepOutcome } from "./script.ts";
import { StripeAdapterError, type CheckoutSessionStatus, type StripeCheckoutLinks } from "../../../src/stripe/index.ts";
import { assertTestModeSecretKey, testModeCheckout } from "./stripe-adapters.ts";

/** A session id shortened for the screen and the log: its `cs_test_` prefix and a few characters. */
export function shortSessionId(id: string): string {
  return `${id.slice(0, 14)}...`;
}

/**
 * The demo's config without `deposit-connect`, which names a made-up connected account and a
 * 10-minute link (below Checkout's 30): this demo pays on the platform's account. Connect mode is
 * proven by the recorded test-mode run in test/fixtures/stripe-real/ instead.
 */
export function e2eConfig(): FlowConfig {
  const config = demoConfig();
  delete config.flows["deposit-connect"];
  return config;
}

/**
 * Ends the call. The engine refuses (`precondition_failed`) while a door may still act on a grant,
 * so the host asks again for a few seconds; after that the refusal stands.
 */
async function endCallWhenDoorsSettle(w: DemoWorld, callId: string): Promise<SignedReceipt | null> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await w.engine.endCall(callId);
    } catch (error) {
      if (!(error instanceof EngineError && error.code === "precondition_failed") || attempt >= 10) throw error;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
}

/** A lost read (no answer, a dropped body) or Stripe busy or failing on its side. */
function isTransient(error: unknown): boolean {
  return !(error instanceof StripeAdapterError) || error.retryable;
}

/**
 * Reads the session just created, asking again (up to 5 times, a second apart) after a transient
 * failure: the link exists, so the run must not fail on one lost read.
 */
async function readUntilAnswered(stripe: StripeCheckoutLinks, linkId: string, signal: AbortSignal | undefined): Promise<CheckoutSessionStatus> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await stripe.readLink(linkId, undefined, signal);
    } catch (error) {
      if (signal?.aborted === true || !isTransient(error) || attempt >= 5) throw error;
      await sleep(1000, signal);
    }
  }
}

/** Waits `ms`, or less when `signal` aborts. */
function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve) => {
    // An abort that came before the wait (during a read) has already fired its one event.
    if (signal?.aborted === true) return resolve();
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
    function done(): void {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    }
  });
}

export interface E2eOptions {
  /**
   * The longest the payment step waits for the test payment. It never waits past the engine's
   * deadline for the link (the text plus the flow's link life, 15 minutes), which is the default.
   */
  waitMs?: number;
  /** How often it reads the session back. Default 3 seconds. */
  pollMs?: number;
  /** Hears each step's line, for the terminal. */
  log?: (label: string, detail: string) => void;
  /** Stops a payment step that is waiting, when the demo shuts down. */
  signal?: AbortSignal;
}

/** The live demo's scripts: owner-command as in the fake demo, and `visit` on real Stripe test mode. */
export function e2eScripts(stripe: StripeCheckoutLinks, options: E2eOptions = {}): Scripts {
  const waitMs = options.waitMs ?? Number.POSITIVE_INFINITY;
  const pollMs = options.pollMs ?? 3000;
  const visit: ScriptStep[] = [
    {
      label: "visit: call started",
      async run(w, call) {
        call.callId = (await w.engine.startCall({ locale: "en", flow: "visit" })).callId;
        return pass(call.callId);
      },
    },
    { label: "verify: level 2", run: (w, call) => verifyToLevel2(w, call, "payment.request") },
    {
      label: "pay: Checkout link created (Stripe test mode)",
      async run(w, call) {
        // The amount is read back and confirmed first, as for every link (PAY-2).
        const back = await w.engine.readBackPayment(call.callId);
        await w.engine.confirmPaymentAmount(call.callId, { digest: back.digest, confirmedBy: "keypad" });
        const payment = await w.engine.requestPayment(call.callId);
        const link = w.links.find((l) => l.paymentId === payment.paymentId)!;
        call.linkId = link.linkId;
        call.paymentExpiresAt = payment.expiresAt;
        const paymentId = payment.paymentId;
        const session = await readUntilAnswered(stripe, link.linkId, options.signal);
        return {
          detail: `${paymentId}: Checkout Session ${shortSessionId(link.linkId)} created, livemode ${session.livemode}, status ${session.status}. Open it and pay with the test card 4242 4242 4242 4242.`,
          ok: !session.livemode && session.status === "open",
          link: { href: link.url, text: "Open the Stripe Checkout page (test mode)" },
        };
      },
    },
    {
      label: "pay: test payment read back from Stripe",
      async run(w, call) {
        const paid = (session: CheckoutSessionStatus) => session.status === "complete" && session.paymentStatus === "paid";
        const settle = async (session: CheckoutSessionStatus): Promise<StepOutcome> => {
          const applied = await w.engine.applyPaymentOutcome({ kind: "completed", linkId: call.linkId, paymentStatus: "paid" });
          return { detail: `session ${session.status}, payment ${session.paymentStatus}, livemode ${session.livemode}; settled: ${applied.applied}`, ok: applied.applied };
        };
        // Until the engine's own deadline for the link (the text plus the flow's link life).
        const now = () => w.clock.now().getTime();
        const engineDeadline = Date.parse(call.paymentExpiresAt ?? "") || now();
        const until = Math.min(engineDeadline + 1000, now() + waitMs);
        // A function, so a check after an await reads the signal again.
        const stopping = (): boolean => options.signal?.aborted === true;
        const stopped: StepOutcome = { detail: "stopped: the demo is shutting down", ok: false };
        for (;;) {
          if (stopping()) return stopped;
          let session: CheckoutSessionStatus | null = null;
          try {
            session = await stripe.readLink(call.linkId, undefined, options.signal);
          } catch (error) {
            if (stopping()) return stopped;
            // A lost read, or Stripe busy or failing on its side: ask again. A refusal or an answer
            // this adapter cannot trust ends the step.
            if (!isTransient(error)) throw error;
          }
          if (session !== null && paid(session)) return settle(session);
          if (session?.status === "expired") return { detail: "the session expired unpaid", ok: false };
          if (now() >= until) break;
          // Never past the end of the wait: a long poll interval still stops on time.
          await sleep(Math.min(pollMs, until - now()), options.signal);
        }
        // Out of time: close the link at Stripe through the engine (it settles the request as
        // expired), so the old page cannot take a payment nobody reads: at the link's deadline by
        // expiring it, and before it (the wait ended first) by cancelling it. A page Stripe says is
        // no longer open may have been paid at the last moment: read it once more.
        const { expired } = await w.engine.expirePaymentLinks(call.callId);
        if (expired.length === 0) {
          await w.engine.cancelPaymentLink(call.callId, w.links.find((l) => l.linkId === call.linkId)!.paymentId);
          const last = await stripe.readLink(call.linkId);
          if (paid(last)) return settle(last);
        }
        return { detail: "not paid in time: the Checkout page is closed, start a new run", ok: false };
      },
    },
    {
      label: "gate: door opened",
      async run(w, call) {
        const opened = w.doorsOpened.length;
        const access = await w.engine.grantAccess(call.callId);
        call.grantId = access.grantId;
        return {
          detail: `${access.grantId}, ${access.status}, door moved: ${access.confirmed}, opened ${w.doorsOpened.slice(opened).join(", ")}`,
          ok: access.status === "delivered" && access.confirmed,
        };
      },
    },
    {
      label: "visit: call ended",
      async run(w, call) {
        const done = await w.engine.flowPosition(call.callId);
        call.receipt = await endCallWhenDoorsSettle(w, call.callId);
        return { detail: `flow ${done!.status} (${done!.index} steps), receipt ${call.receipt === null ? "MISSING" : "signed"}`, ok: call.receipt !== null };
      },
    },
  ];
  const scripts: Record<string, readonly ScriptStep[]> = { "owner-command": SCRIPTS["owner-command"], visit };
  const log = options.log;
  if (log === undefined) return scripts;
  // The terminal hears each step as the page runs it.
  const logged: Record<string, readonly ScriptStep[]> = {};
  for (const [flow, steps] of Object.entries(scripts)) {
    logged[flow] = steps.map((step) => ({
      label: step.label,
      async run(w, call) {
        let outcome;
        try {
          outcome = await step.run(w, call);
        } catch (error) {
          // The adapter's errors carry Stripe's status, type and code, never a key or a URL.
          log(step.label, `FAILED: ${error instanceof Error ? error.message : "unknown error"}`);
          throw error;
        }
        log(step.label, `${outcome.ok ? "" : "CHECK FAILED: "}${outcome.detail}`);
        return outcome;
      },
    }));
  }
  return logged;
}

export interface E2eDemo {
  server: Server;
  /** The example door relay's unlock URL, on 127.0.0.1. */
  relayUrl: string;
  base: string;
  close(): Promise<void>;
}

/**
 * Starts the door relay and the reference server with the UI on 127.0.0.1. Refuses a key that is
 * not `sk_test_`, and port 0 (Checkout's return URL names the port).
 */
export async function startE2eDemo(apiKey: string, port: number, options: Omit<E2eOptions, "signal"> & { apiBase?: string } = {}): Promise<E2eDemo> {
  assertTestModeSecretKey(apiKey);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new RangeError("port must be an integer from 1 to 65535");
  const log = options.log ?? (() => undefined);
  const base = `http://127.0.0.1:${port}`;
  const stripe = testModeCheckout(apiKey, { successUrl: `${base}/`, ...(options.apiBase === undefined ? {} : { apiBase: options.apiBase }) });
  const world = createDemoWorld({
    payments: stripe,
    clock: systemClock,
    ids: randomIds,
    config: e2eConfig(),
    onDoorOpened: (target) => log("door relay", `door opened: ${target} (grant checked: ES256 signature, workspace, audience, window, not seen before)`),
  });
  const stop = new AbortController();
  // Started now rather than at the first grant, so the terminal can say where it listens.
  const relayUrl = await world.relayUrl();
  const closeRelay = () => world.close();
  let server: Server;
  try {
    server = createReferenceServer({
      engine: world.engine,
      clock: systemClock,
      // No webhook in this demo: payment completion is read back from Stripe.
      stripeSecrets: { identity: [], payments: [], connect: [] },
      ui: new DemoRuns(world, 20, e2eScripts(stripe, { ...options, signal: stop.signal })),
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", resolve);
    });
  } catch (error) {
    // The UI did not load or the port is taken: stop the relay too, so nothing is left listening.
    await closeRelay();
    throw error;
  }
  world.base = base;
  return {
    server,
    relayUrl,
    base,
    close: async () => {
      // A payment step that is waiting answers at once, so the server can close.
      stop.abort();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await closeRelay();
    },
  };
}

// Not `import.meta.main`, which Node.js 24.2 sets false for a .ts entry (see `isProgram`).
if (isProgram(process.argv[1], import.meta.url)) {
  // Read once, then dropped from the environment so nothing started later inherits it.
  const key = process.env.STRIPE_TEST_SECRET_KEY;
  delete process.env.STRIPE_TEST_SECRET_KEY;
  try {
    assertTestModeSecretKey(key);
  } catch (error) {
    console.error(`demo:e2e: ${(error as Error).message}`);
    process.exit(1);
  }
  const log = (label: string, detail: string) => console.log(`  ${label.padEnd(44)} ${detail}`);
  const demo = await startE2eDemo(key, Number(process.env.PORT ?? 8787), { log });
  console.log(`District Assurance end-to-end demo on ${demo.base}/ (Stripe TEST MODE; everything else local and made up)`);
  console.log("  Pick owner-command, run it; then pick visit, run it, open the Checkout page and pay with 4242 4242 4242 4242.");
  console.log("  Ctrl-C stops the server and the door relay.");
  process.once("SIGINT", () => void demo.close().then(() => process.exit(0)));
}
