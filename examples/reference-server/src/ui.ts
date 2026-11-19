// `npm run ui`: the reference server with the demo's browser UI, on 127.0.0.1 only. Pick a flow,
// run the scripted call one step at a time, and watch the session state, the ledger entries and
// the signed receipt, which the page checks itself against /.well-known/receipt-keys.json. The
// example door relay for the `entry` flow runs beside it on another loopback port.
//
// Environment:
//   PORT    default 8787, bound to 127.0.0.1
//
// Fake adapters and made-up records only (script.ts). The Stripe webhook routes accept only the
// demo's published signing secrets here, so this is not the server to point `stripe listen` at;
// `npm run serve` is. `npm run demo:e2e` is this page with a real Stripe test-mode Checkout.
import type { AddressInfo } from "node:net";

import { createReferenceServer } from "./app.ts";
import { DemoRuns } from "./demo-runs.ts";
import { DEMO_CONNECT_SECRET, DEMO_SECRET, createDemoWorld, startDoorRelay } from "./script.ts";

const port = Number(process.env.PORT ?? 8787);
const world = createDemoWorld();
await startDoorRelay(world);
const server = createReferenceServer({
  engine: world.engine,
  clock: world.clock,
  stripeSecrets: { identity: [DEMO_SECRET], payments: [DEMO_SECRET], connect: [DEMO_CONNECT_SECRET] },
  ui: new DemoRuns(world),
});
server.listen(port, "127.0.0.1", () => {
  world.base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  console.log(`District Assurance demo UI on ${world.base}/ (pre-alpha, fake adapters)`);
});
