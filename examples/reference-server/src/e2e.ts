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
import { SCRIPTS, createDemoWorld, endWithReceipt, openDoor, requestLink, startDoorRelay, verifyToLevel2, type ScriptStep, type Scripts } from "./script.ts";
import { StripeCheckoutLinks, assertTestModeSecretKey } from "./stripe-adapters.ts";

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

export interface E2eOptions {
  /** How long the payment step waits for the test payment. Default 10 minutes. */
  waitMs?: number;
  /** How often it reads the session back. Default 3 seconds. */
  pollMs?: number;
  /** Hears each step's line, for the terminal. */
  log?: (label: string, detail: string) => void;
}

/** The live demo's scripts: owner-command as in the fake demo, and `visit` on real Stripe test mode. */
export function e2eScripts(stripe: StripeCheckoutLinks, options: E2eOptions = {}): Scripts {
  const waitMs = options.waitMs ?? 10 * 60_000;
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
        const deadline = Date.now() + waitMs;
        for (;;) {
          const session = await stripe.readLink(call.linkId);
          if (session.status === "complete" && session.paymentStatus === "paid") {
            const applied = await w.engine.applyPaymentOutcome({ kind: "completed", linkId: call.linkId, paymentStatus: "paid" });
            return { detail: `session ${session.status}, payment ${session.paymentStatus}, livemode ${session.livemode}; settled: ${applied.applied}`, ok: applied.applied };
          }
          if (session.status === "expired") return { detail: "the session expired unpaid", ok: false };
          if (Date.now() >= deadline) return { detail: `not paid within ${Math.round(waitMs / 60_000)} minutes: start a new run`, ok: false };
          await new Promise((resolve) => setTimeout(resolve, pollMs));
        }
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

/** Starts the door relay and the reference server with the UI on 127.0.0.1. Refuses a key that is not `sk_test_`. */
export async function startE2eDemo(apiKey: string, port: number, options: E2eOptions & { apiBase?: string } = {}): Promise<E2eDemo> {
  assertTestModeSecretKey(apiKey);
  const log = options.log ?? (() => undefined);
  const base = `http://127.0.0.1:${port}`;
  const stripe = new StripeCheckoutLinks(apiKey, { successUrl: `${base}/`, ...(options.apiBase === undefined ? {} : { apiBase: options.apiBase }) });
  const world = createDemoWorld({ payments: stripe, clock: systemClock, ids: randomIds, config: e2eConfig() });
  const relay = await startDoorRelay(world, 0, (target) => log("door relay", `door opened: ${target} (grant checked: ES256 signature, workspace, audience, window, not seen before)`));
  const server = createReferenceServer({
    engine: world.engine,
    clock: systemClock,
    // No webhook in this demo: payment completion is read back from Stripe.
    stripeSecrets: { identity: [], payments: [], connect: [] },
    ui: new DemoRuns(world, 20, e2eScripts(stripe, options)),
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", resolve);
    });
  } catch (error) {
    // The port is taken: stop the relay too, so nothing is left listening.
    await new Promise<void>((resolve) => relay.close(() => resolve()));
    throw error;
  }
  world.base = base;
  return {
    server,
    relay,
    base,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await new Promise<void>((resolve) => relay.close(() => resolve()));
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
