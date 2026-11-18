# Reference server

A small `node:http` server around one engine, for trying district-assurance end to end. It
imports the package sources directly and has no dependencies or `package.json` of its own; run it
from the repository root. Not hardened for production (ROADMAP.md, M5).

```sh
npm run demo    # owner-command, deposit in each mode and entry, on fake adapters and loopback servers, then exits
npm run serve   # the server on 127.0.0.1:8787 until stopped
```

## Files

| File | |
|---|---|
| `src/app.ts` | `createReferenceServer({ engine, stripeSecrets, clock })`: the routes |
| `src/demo.ts` | the scripted calls; `runDemo(false)` is also run by the test suite |
| `src/door-relay.ts` | an example door relay for Gate's `webhookRelay` adapter: checks the grant with Gate's public key, refuses replays, works the door |
| `src/flows.ts` | the demo's FlowConfig: the `owner-command`, `deposit`, `deposit-connect` and `entry` flows |
| `src/main.ts` | `npm run serve`: reads the environment, starts the server |
| `src/stripe-adapters.ts` | Stripe Identity and Checkout adapters, planned (VER-5, PAY-1) |

## Trying it with your own Stripe test account

1. In the Stripe dashboard (test mode), or with `stripe listen`, get a signing secret for an
   endpoint that receives `identity.verification_session.*` events and one for `checkout.session.*`;
   for connect mode, also a Connect endpoint ("Events from: Connected accounts"), which has its
   own secret (`stripe listen --forward-connect-to localhost:8787/webhooks/stripe/connect`).
2. Start the server with them:

   ```sh
   STRIPE_IDENTITY_WEBHOOK_SECRET=whsec_... STRIPE_PAYMENTS_WEBHOOK_SECRET=whsec_... STRIPE_CONNECT_WEBHOOK_SECRET=whsec_... npm run serve
   stripe listen --forward-to localhost:8787/webhooks/stripe/payments
   ```

3. Trigger a test event (`stripe trigger checkout.session.completed`). The server checks the
   signature and answers `{"received": true, "applied": false}`: the signature is good, and the
   session is unknown to this engine because the Stripe adapters are not built yet. A wrong secret
   answers `400` with the reason.

Use test-mode keys only. Never commit a secret; the server reads them from the environment.

## Carrier signals

Planned (VER-4), Twilio and Telnyx. What each offers, to be confirmed per country when the adapters
are built. `CarrierSignals` is vendor-neutral, so another carrier can be added as its own adapter.

| Carrier | SIM swap | Porting | Identity match | One-time codes |
|---|---|---|---|---|
| Twilio (Lookup, Verify) | yes, with carrier approval | yes | yes, with carrier approval | SMS, voice, WhatsApp |
| Telnyx (Number Lookup, Verify) | not found | porting status and date, carrier | caller identity (name, address) | SMS, voice, flash call, WhatsApp |
