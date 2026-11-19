// `npm run demo:e2e`: the demo UI with one real piece, a Stripe Checkout Session in TEST MODE.
// Everything else stays local and made up: the caller, the carrier, the texts, the ledger, and
// the example door relay on another loopback port. No production system is involved.
//
// Two scripted calls, run from the page one click at a time:
//   1. `owner-command`: the owner's PIN on the keypad, to Badge level 1.
//   2. `visit`: keypad knowledge and a carrier match to level 2; Paylink in platform mode creates a
//      real test-mode Checkout Session; you pay it in the browser with a Stripe test card; the demo
//      reads the session back from Stripe (read only) until it is paid and settles the payment;
//      Gate signs a grant, the relay checks it (ES256, workspace, audience, window, replay) and
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

import { randomIds, systemClock, type FlowConfig } from "../../../src/index.ts";
import { createReferenceServer } from "./app.ts";
import { DemoRuns } from "./demo-runs.ts";
import { demoConfig } from "./flows.ts";
import { SCRIPTS, createDemoWorld, endWithReceipt, openDoor, requestLink, startDoorRelay, verifyToLevel2, type ScriptStep, type Scripts, type StepOutcome } from "./script.ts";
import { StripeApiError, StripeCheckoutLinks, assertTestModeSecretKey, type CheckoutSessionStatus } from "./stripe-adapters.ts";

/** A session id shortened for the screen and the log: its `cs_test_` prefix and a few characters. */
export function shortSessionId(id: string): string {
  return `${id.slice(0, 14)}...`;
}

/** The demo's config without `deposit-connect`: this adapter takes platform payments only. */
export function e2eConfig(): FlowConfig {
  const config = demoConfig();
  delete config.flows["deposit-connect"];
  return config;
}

/** Waits `ms`, or less when `signal` aborts. */
function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve) => {
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
    ...verifyToLevel2("visit"),
    {
      label: "pay: Checkout link created (Stripe test mode)",
      async run(w, call) {
        const { paymentId, link } = await requestLink(w, call);
        const session = await stripe.readLink(link.linkId);
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
        for (;;) {
          if (options.signal?.aborted === true) return { detail: "stopped: the demo is shutting down", ok: false };
          let session: CheckoutSessionStatus | null = null;
          try {
            session = await stripe.readLink(call.linkId);
          } catch (error) {
            // A lost read, or Stripe busy or failing on its side: ask again. A refusal or an answer
            // this adapter cannot trust ends the step.
            if (error instanceof StripeApiError && !error.retryable) throw error;
          }
          if (session !== null && paid(session)) return settle(session);
          if (session?.status === "expired") return { detail: "the session expired unpaid", ok: false };
          if (now() >= until) break;
          await sleep(pollMs, options.signal);
        }
        // Out of time: close the link at Stripe through the engine (it settles the request as
        // expired), so the old page cannot take a payment nobody reads. A page Stripe says is no
        // longer open may have been paid at the last moment: read it once more.
        const { expired } = await w.engine.expirePaymentLinks(call.callId);
        if (expired.length === 0) {
          const last = await stripe.readLink(call.linkId);
          if (paid(last)) return settle(last);
        }
        return {
          detail: expired.length === 0 ? "not paid in time: start a new run" : "not paid before the link's deadline: the Checkout page is closed, start a new run",
          ok: false,
        };
      },
    },
    { ...openDoor, label: "gate: door opened" },
    endWithReceipt("visit"),
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
  relay: Server;
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
  const stripe = new StripeCheckoutLinks(apiKey, { successUrl: `${base}/`, ...(options.apiBase === undefined ? {} : { apiBase: options.apiBase }) });
  const world = createDemoWorld({ payments: stripe, clock: systemClock, ids: randomIds, config: e2eConfig() });
  const stop = new AbortController();
  const relay = await startDoorRelay(world, 0, (target) => log("door relay", `door opened: ${target} (grant checked: ES256 signature, workspace, audience, window, not seen before)`));
  const closeRelay = () => new Promise<void>((resolve) => relay.close(() => resolve()));
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
    relay,
    base,
    close: async () => {
      // A payment step that is waiting answers at once, so the server can close.
      stop.abort();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await closeRelay();
    },
  };
}

if (import.meta.main) {
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
