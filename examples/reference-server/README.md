# Reference server

A small `node:http` server around one engine, for trying district-assurance end to end. It
imports the package sources directly and has no dependencies or `package.json` of its own; run it
from the repository root. Not hardened for production (ROADMAP.md, M5).

```sh
npm run demo    # owner-command and deposit, on fake adapters and a loopback server, then exits
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
| `GET /demo/flows` | the two flows and their step names |
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
| `src/script.ts` | the scripted calls, one step at a time, and the demo's records and engines |
| `src/demo.ts` | `npm run demo`: every step in a row; `runDemo(false)` is also run by the test suite |
| `src/demo-runs.ts` | the UI's runs: one step per request, and the run's state, ledger and chain check |
| `src/static.ts` | the UI's file allow-list and its headers |
| `src/flows.ts` | the demo's FlowConfig: the `owner-command` and `deposit` flows |
| `src/main.ts` | `npm run serve`: reads the environment, starts the server |
| `src/ui.ts` | `npm run ui`: the server with the demo UI |
| `public/` | the page: `index.html`, `style.css`, `app.js`, and `receipt-check.js` (no DOM, tested in Node) |
| `src/stripe-adapters.ts` | Stripe Identity and Checkout adapters, planned (VER-5, PAY-1) |
| `src/carrier-adapters.ts` | Twilio Lookup and Telnyx Number Lookup carrier signal adapters (VER-4) |

## Trying it with your own Stripe test account

1. In the Stripe dashboard (test mode), or with `stripe listen`, get a signing secret for an
   endpoint that receives `identity.verification_session.*` events and one for `checkout.session.*`.
2. Start the server with them:

   ```sh
   STRIPE_IDENTITY_WEBHOOK_SECRET=whsec_... STRIPE_PAYMENTS_WEBHOOK_SECRET=whsec_... npm run serve
   stripe listen --forward-to localhost:8787/webhooks/stripe/payments
   ```

3. Trigger a test event (`stripe trigger checkout.session.completed`). The server checks the
   signature and answers `{"received": true, "applied": false}`: the signature is good, and the
   session is unknown to this engine because the Stripe adapters are not built yet. A wrong secret
   answers `400` with the reason.

Use test-mode keys only. Never commit a secret; the server reads them from the environment.

## Carrier signals

`src/carrier-adapters.ts` (VER-4) has two `CarrierSignals` adapters. They call the vendors' REST
APIs with `fetch`, and their tests replay fixture responses from a local fake server, never the
network. `CarrierSignals` is vendor-neutral, so another carrier (Sinch, for example) can be added
as its own adapter.

| Signal | Twilio Lookup v2 (`TwilioLookupSignals`) | Telnyx Number Lookup (`TelnyxNumberLookupSignals`) |
|---|---|---|
| SIM swap (`simSwapChecked`, `lastSimSwapHoursAgo`) | yes, the `sim_swap` field (`simSwapChecked: true`); needs Twilio's approval and the carrier's, per country | no: `simSwapChecked: false`, hours null, so a texted code never counts on this report alone |
| Porting (`lastPortHoursAgo`) | not used: always null | yes, `portability.ported_status` and `ported_date`; no approval |
| Identity match (`identityMatch`) | yes, the `identity_match` field, when the host gives the identity on file; needs Twilio's approval, per country | no: always `unavailable` |
| Carrier | not used | yes, name and line type, from `lookup()`, outside the report |
| Countries this account may use | `TWILIO_LOOKUP_COUNTRIES`, `US` by default | `TELNYX_LOOKUP_COUNTRIES`, `US` by default; list a country only once your account may look it up |

How the answers are read:

- **SIM swap:** hours since `last_sim_swap_date` (an ISO 8601 time only; anything else is no
  date), but when `swapped_in_period` is true never older than `swapped_period`, and 0 without a
  date that fits it; else, when it is false, the length of `swapped_period` (an ISO 8601 duration,
  refused when too long to be a number) as a lower bound.
  `swapped_period` is the window Twilio looked at, not the age of a change, so it is never read as
  one when the change fell inside it. Anything else is no answer.
- **Identity match:** `match` when `summary_score` is at least `identityMinScore` (1 to 100, 80
  by default; anything else throws when the adapter is built), else `no_match`. The identity
  comes from the host's `identityFor(phoneNumber)`; without it only SIM Swap is asked. Twilio
  takes the identity in the query string.
- **Porting:** `N` is none known; `Y` gives the hours from the last moment the port date ends
  anywhere (Telnyx gives a day, with no time or zone, so noon UTC the next day), or 0 without a
  date; anything else is no answer.
- Hours are rounded down and never negative.

Every failure answers `checked: false` with nothing known, and never throws into the call: a
number that is not E.164, an answer for a country outside the allow-list, a timeout (`timeoutMs`,
3000 by default, over the whole exchange), a network or HTTP error, a field error (a feature the
account is not approved for, or a country it does not cover), or an answer that cannot be read. A
Twilio report is `checked` only when every field asked for answered. The optional `onUnavailable`
listener hears why (`vendor`, `reason`, the HTTP `status` and the vendor's error `code`), never
the number, the identity or a credential; it may be async, and its errors, thrown or rejected, are
ignored without holding back the report.

A `baseUrl` override must be `https:`; plain `http:` is accepted only on a loopback host (a local
fake server), so credentials never cross a network in clear text (on loopback they stay on the
host, unencrypted). Any other origin throws when the adapter
is built, before a credential is used, and so does a `timeoutMs` that is not a whole number from 1
to 60000. A number on file that is not a string is not E.164.

Telnyx alone reports no SIM change, so its `checked: true` report says `simSwapChecked: false`, and
the policy never counts a texted code on it, whatever `trustTextCodeWithoutCarrierCheck` says. Its
port signal stays in the report. A host that turns texted codes on (VER-2) takes SIM swap from
Twilio.

Credentials come from the environment only:

```sh
TWILIO_API_KEY=SK... TWILIO_API_SECRET=...       # or TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN
TELNYX_API_KEY=KEY...
```

`twilioLookupFromEnv()` and `telnyxLookupFromEnv()` return the adapter, or null when its
credentials are not set. The reference server itself still runs on the fake carrier.
