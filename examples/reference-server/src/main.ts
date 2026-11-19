// `npm run serve`: the reference server on a port, for trying the webhook routes with your OWN
// Stripe test-mode account (for example `stripe listen --forward-to localhost:8787/webhooks/stripe/payments`).
//
// Environment:
//   PORT                              default 8787, bound to 127.0.0.1
//   STRIPE_IDENTITY_WEBHOOK_SECRET    the signing secret of your Identity webhook endpoint
//   STRIPE_PAYMENTS_WEBHOOK_SECRET    the signing secret of your Checkout webhook endpoint (platform mode)
//   STRIPE_CONNECT_WEBHOOK_SECRET     the signing secret of your Connect endpoint (connect mode;
//                                     `stripe listen --forward-connect-to localhost:8787/webhooks/stripe/connect`)
//
// The engine runs on fake adapters until the Stripe adapters (VER-5, PAY-1) are built, so real
// events verify their signatures and then name sessions this engine does not know (applied: false).
import { systemClock } from "../../../src/index.ts";
import { createTestEngine } from "../../../src/testing/index.ts";
import { createReferenceServer } from "./app.ts";

const port = Number(process.env.PORT ?? 8787);
const secret = (name: string) => (process.env[name] ?? "").split(",").filter((s) => s !== "");
const { engine } = createTestEngine({ clock: systemClock });
const server = createReferenceServer({
  engine,
  clock: systemClock,
  stripeSecrets: { identity: secret("STRIPE_IDENTITY_WEBHOOK_SECRET"), payments: secret("STRIPE_PAYMENTS_WEBHOOK_SECRET"), connect: secret("STRIPE_CONNECT_WEBHOOK_SECRET") },
});
server.listen(port, "127.0.0.1", () => {
  console.log(`reference server on http://127.0.0.1:${port} (pre-alpha, fake adapters)`);
});
