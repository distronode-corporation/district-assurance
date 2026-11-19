# Reference server

A small `node:http` server around one engine, for trying district-assurance end to end. It
imports the package sources directly and has no dependencies or `package.json` of its own; run it
from the repository root. Not hardened for production (ROADMAP.md, M5).

```sh
npm run demo    # owner-command, deposit in each mode and entry, on fake adapters and loopback servers, then exits
npm run ui      # the same scripted calls in a browser, one step at a time, on 127.0.0.1:8787
npm run serve   # the server on 127.0.0.1:8787 until stopped, for your own Stripe test events
```

## The demo UI

`npm run ui`, then open `http://127.0.0.1:8787/`. Pick a flow, then run its scripted steps one at
a time (or the rest in one go). After each step the page shows the call's session state, its
entries in the audit ledger, and whether the whole ledger's hash chain is intact. When a flow with
a `trace.receipt` step ends, the page fetches the receipt from `/receipts/:callId` and the key set
from `/.well-known/receipt-keys.json` and checks the ES256 signature itself, with Web Crypto, over
its own canonical JSON of the body; a button changes one character and checks again, which fails.
The page also recomputes each ledger entry's hash.

Plain HTML, CSS and JavaScript in `public/`: no framework, no build step, no dependency. Light and
dark follow the system setting. Step results are announced through a polite live region, focus
moves to the run when it starts and to the receipt when it ends, and everything works from the
keyboard.

The routes, on this server only (not on `npm run serve`):

| Route | |
|---|---|
| `GET /`, `/app.js`, `/receipt-check.js`, `/style.css` | the page, from a fixed allow-list |
| `GET /demo/flows` | the flows and their step names |
| `POST /demo/runs` | `{"flow": "deposit"}` starts a run (`201`); nothing runs yet |
| `GET /demo/runs/:runId` | the run: its step results, session state, flow position, ledger entries |
| `POST /demo/runs/:runId/next` | runs the next step and answers the run (`409` when done or busy) |

How the page is kept small and safe:

- The script is fixed. A run can only replay `src/script.ts`; the browser sends a flow's name and
  nothing else that reaches the engine.
- The files are an allow-list read once at start-up (`src/static.ts`). A request path is a key into
  that list and never reaches the file system, so there is no traversal and no listing.
- A strict Content Security Policy: `default-src 'none'; script-src 'self'; style-src 'self';
  connect-src 'self'`, no inline script or style, no framing, plus `nosniff` and `no-referrer`.
  The page writes every value as text, never as markup.
- On every route, receipts, key set and webhooks included, only a Host of `127.0.0.1`,
  `localhost` or `[::1]` with the server's own port is served (a rebound DNS name or another port
  gets `403`), and a run
  is started or stepped only by a JSON `POST` from the page's own origin, which another site cannot
  send without a preflight this server never answers.
- No secret reaches the browser: it sees session states, ledger entries, the receipt and the public
  key set, all of which hold no values the caller keyed. The Stripe routes on this server accept
  only the demo's published secret, so point `stripe listen` at `npm run serve` instead.
- The server keeps the newest 20 runs. Like the rest of this server it is a local demo, not hardened
  for production.

## Files

| File | |
|---|---|
| `src/app.ts` | `createReferenceServer({ engine, stripeSecrets, clock })`: the routes |
| `src/script.ts` | the scripted calls, one step at a time, and the demo's records, engines, Gate and door relay |
| `src/demo.ts` | `npm run demo`: every step in a row; `runDemo(false)` is also run by the test suite |
| `src/demo-runs.ts` | the UI's runs: one step per request, and the run's state, ledger and chain check |
| `src/door-relay.ts` | an example door relay for Gate's `webhookRelay` adapter: checks the grant with Gate's public key, refuses replays, works the door |
| `src/static.ts` | the UI's file allow-list and its headers |
| `src/flows.ts` | the demo's FlowConfig: the `owner-command`, `deposit`, `deposit-connect` and `entry` flows |
| `src/main.ts` | `npm run serve`: reads the environment, starts the server |
| `src/ui.ts` | `npm run ui`: the server with the demo UI |
| `public/` | the page: `index.html`, `style.css`, `app.js`, and `receipt-check.js` (no DOM, tested in Node) |
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
   stripe listen --forward-to localhost:8787/webhooks/stripe/identity   # in a second terminal, its own secret
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
