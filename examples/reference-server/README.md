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

## security.txt

`createReferenceServer({ ..., securityTxt })` serves `GET /.well-known/security.txt` (RFC 9116)
as `text/plain; charset=utf-8`, built from the host's own settings:

```ts
createReferenceServer({
  engine,
  clock,
  stripeSecrets,
  securityTxt: {
    contact: ["mailto:security@example.test", "https://example.test/report"], // one or more
    expires: new Date("2027-06-30T00:00:00Z"), // exactly one
    policy: "https://example.test/disclosure", // optional
    canonical: "https://example.test/.well-known/security.txt", // optional
  },
  warn: (message) => log.warn(message), // optional, default console.warn
});
```

- Without `securityTxt` there is no such route (`404`). There is no default: a security.txt speaks
  only for the domain it is served from, so it is never this project's address. Reports about this
  code go through [SECURITY.md](../../SECURITY.md).
- A contact is a `mailto:`, `tel:` or `https:` URI; `policy` and `canonical` are `https:` URLs.
  Each must be one line of printable ASCII, so a value cannot add a field of its own.
- The settings are checked when the server is created, on its clock. An `expires` that is not in
  the future, or more than a year ahead (the RFC's advice), is refused with an error, so the server
  does not start. One within 30 days starts with a warning through `warn`. A server still running
  when `expires` passes stops serving the file.
- RFC 9116 requires HTTPS. This server speaks plain HTTP, so the host's TLS front end serves the
  file to the world. Signing it (an OpenPGP cleartext signature, which the RFC recommends) is the
  host's too: this server serves the file unsigned, and a host that signs it serves its signed
  copy from the front end instead.

## Files

| File | |
|---|---|
| `src/app.ts` | `createReferenceServer({ engine, stripeSecrets, clock })`: the routes, and the security.txt checks |
| `src/script.ts` | the scripted calls, one step at a time, and the demo's records and engines |
| `src/demo.ts` | `npm run demo`: every step in a row; `runDemo(false)` is also run by the test suite |
| `src/demo-runs.ts` | the UI's runs: one step per request, and the run's state, ledger and chain check |
| `src/static.ts` | the UI's file allow-list and its headers |
| `src/flows.ts` | the demo's FlowConfig: the `owner-command` and `deposit` flows |
| `src/main.ts` | `npm run serve`: reads the environment, starts the server |
| `src/ui.ts` | `npm run ui`: the server with the demo UI |
| `public/` | the page: `index.html`, `style.css`, `app.js`, and `receipt-check.js` (no DOM, tested in Node) |
| `src/stripe-adapters.ts` | Stripe Identity and Checkout adapters, planned (VER-5, PAY-1) |

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

Planned (VER-4), Twilio and Telnyx. What each offers, to be confirmed per country when the adapters
are built. `CarrierSignals` is vendor-neutral, so another carrier can be added as its own adapter.

| Carrier | SIM swap | Porting | Identity match | One-time codes |
|---|---|---|---|---|
| Twilio (Lookup, Verify) | yes, with carrier approval | yes | yes, with carrier approval | SMS, voice, WhatsApp |
| Telnyx (Number Lookup, Verify) | not found | porting status and date, carrier | caller identity (name, address) | SMS, voice, flash call, WhatsApp |
