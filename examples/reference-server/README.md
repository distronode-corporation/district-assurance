# Reference server

A small `node:http` server around one engine, for trying district-assurance end to end. It
imports the package sources directly and has no dependencies or `package.json` of its own; run it
from the repository root. Not hardened for production (ROADMAP.md, M5).

```sh
npm run demo    # owner-command, deposit in each mode and entry, on fake adapters and loopback servers, then exits
npm run ui      # the same scripted calls in a browser, one step at a time, on 127.0.0.1:8787
npm run serve   # the server on 127.0.0.1:8787 until stopped, for your own Stripe test events
npm run demo:e2e  # the UI with a real Stripe Checkout in test mode (STRIPE_TEST_SECRET_KEY=sk_test_...)
```

## The demo UI

`npm run ui`, then open `http://127.0.0.1:8787/`. Pick a flow, then run its scripted steps one at
a time (or the rest in one go). After each step the page shows the call's session state, its
entries in the audit ledger, and whether the whole ledger's hash chain is intact. When a flow with
a `trace.receipt` step ends, the script issues the receipt's capability link (`/r/:token`; the
link store keeps only the token's hash, but the demo run itself holds the raw token in memory so
later views of the run can show the link, which a real host would not do), and the page fetches the receipt from `/r/:token.json` and the key set
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
- The sample receiver of record deliveries (`POST /webhooks/records`) keeps the idempotency keys it
  has received in memory only, so a restart forgets them and a redelivered record is applied again.
  A real receiver must store them durably, and mark a key received in the same transaction that
  applies the record.

## Files

| File | |
|---|---|
| `src/app.ts` | `createReferenceServer({ engine, stripeSecrets, clock })`: the routes |
| `src/script.ts` | the scripted calls, one step at a time, and the demo's records, engines and door relay |
| `src/app.ts` | `createReferenceServer({ engine, stripeSecrets, clock, receiptLinks })`: the routes, `ReceiptLinks` and the receipt page |
| `src/script.ts` | the scripted calls, one step at a time, and the demo's records and engines |
| `src/demo.ts` | `npm run demo`: every step in a row; `runDemo(false)` is also run by the test suite |
| `src/demo-runs.ts` | the UI's runs: one step per request, and the run's state, ledger and chain check |
| `src/static.ts` | the UI's file allow-list and its headers |
| `src/door-relay.ts` | an example door relay for Gate's `webhookRelay` adapter: checks the grant with Gate's public key and its workspace, refuses replays, works the door |
| `src/flows.ts` | the demo's FlowConfig: the `owner-command`, `deposit`, `deposit-connect`, `entry` and `visit` flows |
| `src/main.ts` | `npm run serve`: reads the environment, starts the server |
| `src/ui.ts` | `npm run ui`: the server with the demo UI |
| `public/` | the page: `index.html`, `style.css`, `app.js`, and `receipt-check.js` (no DOM, tested in Node) |
| `src/e2e.ts` | `npm run demo:e2e`: the UI, the door relay and a real Stripe Checkout in test mode; `owner-command` and `visit` |
| `src/stripe-adapters.ts` | `StripeCheckoutLinks`, a minimal PAY-1 Checkout adapter (test-mode keys only, platform mode, built-in fetch), and `StripeIdentityProvider`, the Stripe Identity adapter (VER-5) |
| `src/carrier-adapters.ts` | Twilio Lookup and Telnyx Number Lookup carrier signal adapters (VER-4) |

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
   signature and answers `503` with `{"received": true, "applied": false, "retry": true}`: the
   signature is good, and no call holds the session because `npm run serve` runs on fake adapters
   (for a real Checkout Session in test mode, use `npm run demo:e2e`), so the server asks Stripe to
   deliver it again, as it would for a link still being bound. A wrong secret
   answers `400` with the reason. Then prove the Connect side the same way, with a test connected
   account: `stripe trigger checkout.session.completed --stripe-account acct_...`, and check that
   `/webhooks/stripe/connect` (not `/payments`) answered it. Filter each listener to its own event
   types (`--events checkout.session.completed,...`), so an event never reaches an endpoint that
   does not handle it.

For a photo ID check that goes to Stripe Identity and back, applied to a call, follow "Trying
Stripe Identity with your own test account" in the repository's README.md.

Use test-mode keys only. Never commit a secret; the server reads them from the environment.

## Caller ID attestation

The host passes the call's STIR/SHAKEN result to `startCall({ attestation })` when the call
starts. The engine never reads a carrier's value itself; the host maps it as below. A value this
table does not list, a missing value and a value the host cannot read all map to `none`.

| Carrier value | `attestation` |
|---|---|
| Twilio `StirVerstat`: `TN-Validation-Passed-A`, `-B`, `-C` | `A`, `B`, `C` |
| Twilio `StirVerstat`: `TN-Validation-Failed-A`, `-B`, `-C`, `TN-Validation-Failed`, `NULL` | `failed` |
| Twilio `StirVerstat`: `TN-Validation-Failed-A-Diverted`, `-B-Diverted`, `-C-Diverted` | `failed` |
| Twilio `StirVerstat`: `TN-Validation-Failed-A-Passthrough`, `-B-Passthrough`, `-C-Passthrough` | `failed` |
| Twilio `StirVerstat`: `TN-Validation-Passed-A-Diverted`, `-B-Diverted`, `-C-Diverted` | `none` |
| Twilio `StirVerstat`: `TN-Validation-Passed-A-Passthrough`, `-B-Passthrough`, `-C-Passthrough` | `none` |
| Twilio `StirVerstat`: `No-TN-Validation`, or no `StirVerstat` | `none` |
| Telnyx SIP `verstat=TN-Validation-Passed` | `A` |
| Telnyx SIP `verstat=TN-Validation-Passed-B` | `B` |
| Telnyx SIP `verstat=TN-Validation-Passed-C` | `C` |
| Telnyx SIP `verstat=TN-Validation-Failed` | `failed` |
| Telnyx SIP `verstat=No-TN-Validation`, or no `verstat` | `none` |
| Telnyx TeXML `ShakenStirAttestation` `A`, `B`, `C` with `ShakenStirValidated` true | `A`, `B`, `C` |
| Telnyx TeXML `ShakenStirAttestation` with `ShakenStirValidated` false | `failed` |
| Telnyx TeXML without `ShakenStirAttestation` | `none` |

`A`, `B` or `C` means the receiving carrier's check of the signature passed; never pass a level
from a signature that was not checked, or whose check failed. A Twilio Passed value with `-Diverted` or
`-Passthrough` is `none`: Twilio checked a diverting provider's signature, or one passed through,
not the original signer's attestation end to end. A level reported without its check
result, such as `shaken_stir_attestation` in the Voice API's `call.initiated` screening result,
is not listed here, so it maps to `none`; and a TeXML `ShakenStirAttestation` is never read
without `ShakenStirValidated`. The Telnyx rows follow Telnyx's SIP header parameters page
(`TN-Validation-Passed` is A, `-B` and `-C` are B and C) and its TeXML callback fields. Twilio documents `StirVerstat` for
the United States and France. Coverage for Canadian numbers is checked per carrier before it is
documented here.

In Canada and the United States, `C` or no attestation is common for genuine callers: calls from
abroad, and calls whose signature was lost on an older, non-IP part of the network. An attestation
speaks to the calling number only, never to who is speaking. That is why it is never a factor, and
why the policy has no `attestationCaps` by default (DECISIONS.md, ADR-26): a business that wants
them sets them, for example `{ "C": 2, "none": 2, "failed": 1 }`.

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
  by default; anything else throws when the adapter is built), else `no_match`; a
  `summary_score` outside 0 to 100 is no answer. The identity
  comes from the host's `identityFor(phoneNumber)`; without it only SIM Swap is asked. Twilio
  takes the identity in the query string.
- **Porting:** `N` is none known; `Y` gives the hours from the last moment the port date ends
  anywhere (Telnyx gives a day, with no time or zone, so noon UTC the next day), or 0 without a
  date; anything else is no answer.
- Hours are rounded down and never negative.

Every failure answers `checked: false` with nothing known, and never throws into the call: a
number that is not E.164, an answer for a country outside the allow-list, a timeout (`timeoutMs`,
3000 by default, over the whole exchange, the host's `identityFor` included), a network or HTTP error, a field error (a feature the
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
