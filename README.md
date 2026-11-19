# district-assurance

The engine behind District Assurance: TypeScript code that lets an automated phone line be trusted
with sensitive work. It checks who is calling, files what the caller confirms, takes payment
without ever touching a card number, and proves each step afterwards with a hash-chained audit
ledger and signed receipts. It is modular: a workspace turns on only what it needs, from a PIN
check before an owner's command to full verification with a payment during the call, or a verified
caller let in through a door. A small reference server and a scripted demo let you try it end to
end on your own machine.

> **Status: pre-alpha.** The API will change without notice, nothing is published to npm, and
> nothing here is certified: no PCI DSS attestation, no SOC 2 report, no regulated identity
> proofing. Do not put it in front of real callers.

## A core and five modules

The **core** holds the call session and its state machine (on a shared session store, so several
processes can run one call), the assurance policy and its levels, redaction, the module registry
and the audit ledger. Everything else is a module, and every module can be turned on, turned off,
added and removed per workspace config.

| Module | What it does | Today |
|---|---|---|
| **Badge** (verify) | Who is calling, in levels. Factors are plug-ins: a PIN (against a keyed hash, or the host's own PIN store), keypad knowledge checked against the organisation's records, carrier signals on the number on file, a photo ID plus selfie by a texted link, and any factor a host adds. A flow can use a PIN only or all of them. | Built on fakes. Texted codes, spoken answers and lockouts across calls are planned. |
| **Dossier** (file) | Intake the caller confirms: forms the organisation defines, values normalised by code, a structured record with a fingerprint. | Built. Read-backs, encrypted fields and delivery are planned. |
| **Paylink** (pay) | Payment by a secure link texted to the number on file (a hosted page such as Stripe Checkout), on the business's own account (`connect`) or the platform's (`platform`), chosen per flow. Only methods that settle during the call; the link lives 15 minutes after it is texted by default, and the host calls `expirePaymentLinks` at that deadline (a timer or a sweep) so the engine expires it. The engine never handles card numbers. | Built on fakes, both modes. The Stripe adapter is planned. |
| **Trace** (prove) | The hash-chained audit ledger, which is always on and cannot be turned off, plus optional signed receipts (ES256 over canonical JSON) and consent records with fingerprinted wording. | Built, in memory. Export, key rotation and revocation are planned. |
| **Gate** (entry) | The outcome after verification: a signed, time-limited access grant for a door, never sent twice. Installed with `engine.use(gateModule(...))`. | Built, with the signed-webhook relay adapter and a fake. One-time codes, web sign-in step-up, Seam and direct vendor adapters are planned. |

Outside modules plug in with `engine.use(module)`, and so does Gate, which runs on that same path. A module declares what it provides (factors,
flow steps, outcomes), the scopes it grants or needs, the adapters it requires and a validator for
its settings. The code keeps the plain names `verify`, `file`, `pay` and `prove` for the folders.

## Flows are config

A workspace's `FlowConfig` is one versioned JSON document: the policy, which modules are on with
their settings, and named flows, each an ordered list of steps.

```json
{
  "version": 1,
  "revision": "2026-11-18.1",
  "policy": { "...": "levels, scopes and their floors (SPEC.md, section 4)" },
  "modules": {
    "badge": { "settings": { "factors": ["pin", "keypad_knowledge", "carrier_identity_match"],
                             "pin": { "mode": "keyed_hash", "minDigits": 4, "maxDigits": 8, "maxAttemptsPerCall": 3 } } },
    "dossier": { "settings": { "forms": ["..."] } },
    "paylink": { "settings": { "maxAmountMinor": 50000, "connectedAccountId": "acct_..." } },
    "gate": { "settings": { "targets": [{ "id": "front-door", "controller": "lobby", "ref": "door-1" }] } },
    "trace": { "settings": { "receipts": true, "wordings": ["..."] } }
  },
  "flows": {
    "owner-command": { "steps": [{ "type": "badge.verify", "level": 1, "factors": ["pin"], "scopes": ["owner.command"] }] },
    "deposit": { "steps": [
      { "type": "badge.verify", "level": 2, "factors": ["keypad_knowledge", "carrier_identity_match"], "scopes": ["intake.file", "payment.request"] },
      { "type": "dossier.collect", "form": "maintenance" },
      { "type": "paylink.request", "amountMinor": 15000, "currency": "cad", "description": "Repair deposit", "amountSource": "price_list",
        "mode": "connect", "linkLifeMinutes": 15, "paymentMethods": ["card", "apple_pay", "google_pay", "link"] },
      { "type": "trace.consent", "purpose": "repair_texts" },
      { "type": "trace.receipt" }
    ] },
    "entry": { "steps": [
      { "type": "badge.verify", "level": 2, "factors": ["keypad_knowledge", "carrier_identity_match"], "scopes": ["entry.open"] },
      { "type": "gate.grant", "target": "front-door", "lifetimeSeconds": 30 }
    ] }
  }
}
```

`validateConfig(config, registry)` returns every problem at once (an unknown or switched-off
module, a level below a scope's floor, a missing adapter, a bad step), so a host refuses a config
when it is saved, never in the middle of a call. The engine runs a flow step by step and allows
only the current step's work, and none once the flow has ended. Money movement, contact changes and
access can never go below level 2, whatever a scope is called, and level 2 always needs a factor
that is not something the caller knows. Pay by link is level 2 by default. There is no configuration UI: config and API come first.
This config turns Gate on, so the engine must be built with Gate installed (`modules:
[gateModule(...)]`, as in "Using the engine" below): the validator refuses a module that is not
installed.

## Try it

Node.js 24.2 or later. The only dependencies are four development tools.

```sh
npm ci
npm test              # node:test over the TypeScript sources
npm run typecheck
npm run test:coverage # 100% lines, statements, functions and branches in every src/ file
npm run demo          # four scripted calls, end to end, on fake adapters and loopback servers
npm run ui            # the same calls in a browser, step by step, on http://127.0.0.1:8787/
npm run demo:e2e      # the browser demo with a real Stripe Checkout in test mode (below)
```

The demo runs `owner-command` first: the owner of a line keys a PIN, on two engines that share one
session store as two processes of a host would; one wrong PIN, then the right one, and a grant for
owner commands only. Then `deposit`: a made-up caller is verified to level 2 by keypad and a
carrier match, files a repair request, has a card number read aloud removed from the transcript,
receives a payment link for the amount the flow sets, pays (a signed Stripe webhook), consents, and
the signed receipt and the key set are fetched from the server and checked (and a one-byte change
fails); that money goes to the platform's account. `deposit-connect` takes a deposit on the
business's own account: a webhook without the connected account is ignored, the Connect one
settles it. Last, `entry`: a verified caller gets a signed 30-second access grant, the relay adapter
posts it to an example door relay, which checks it with Gate's public key and opens the pretend
door; the same grant sent again, and a changed copy, are refused. Nothing leaves the machine.

`npm run ui` serves a small page (plain HTML, CSS and JavaScript, no build step) that runs the
same script one step at a time and shows the session state, the ledger entries and the signed
receipt, which the page verifies itself against the public key set
([examples/reference-server/README.md](examples/reference-server/README.md)).

## Try the demo

`npm run demo:e2e` is the browser demo with one real piece: a Stripe Checkout Session in test
mode. Everything else stays on your machine and is made up (the caller, the carrier, the texts, the
ledger, and an example door relay on another loopback port). It takes a payment in Stripe's test
mode only and touches no production system.

1. Set `STRIPE_TEST_SECRET_KEY` to a secret key from your own Stripe account in test mode (it
   starts with `sk_test_`). The demo refuses any other key, live and restricted keys included,
   reads it once at start-up, and never prints it.
2. Run `npm run demo:e2e` and open `http://127.0.0.1:8787/`.
3. Pick `owner-command` and run it (a keypad PIN to level 1). Then pick `visit` and run it step by
   step: level 2, then "Open the Stripe Checkout page (test mode)" and pay with the test card
   `4242 4242 4242 4242` (any future date, any CVC). The next step reads the session back from
   Stripe until it is paid, then the door relay checks the signed grant and opens the pretend door,
   and the call ends with a signed receipt the page verifies, with its ledger entries below.

Payment completion is read back from Stripe (a read-only poll of the Checkout Session), not taken
from a webhook, so there is nothing to forward and no `stripe listen` to run.

## Using the engine

The host (your voice agent and web backend) calls the engine from code paths: keypad events, tool
handlers and webhook routes. The model never calls it and never sees what it compares.

```ts
import { createEngine, MemoryAuditLedger, keyPairSigner } from "district-assurance";

const engine = createEngine({
  workspaceId: "ws_123",
  knowledgeKey: process.env.KNOWLEDGE_KEY!, // per-workspace HMAC key, at least 16 bytes
  adapters: { ledger: new MemoryAuditLedger(), sessions, records, carrier, messages, payments, signer },
  config, // the workspace's FlowConfig; any problem throws a ConfigError listing all of them
  // A config that turns Gate on needs it installed first:
  // modules: [gateModule({ signer: gateSigner, controllers: { lobby: webhookRelay({ url }) } })],
});

const { callId } = await engine.startCall({ locale: "fr", flow: "owner-command" });
await engine.beginVerification(callId, { subjectKey: ownerSubjectKey }); // the host chose the subject
const { matched } = await engine.submitPin(callId, digitsFromKeypad);  // limited attempts per call
await engine.finishVerification(callId);                               // the flow moves on by itself
if (await engine.authorize(callId, "owner.command")) {
  // run the owner's command
}
await engine.endCall(callId); // in a flow, a receipt only with a trace.receipt step; without one, per Trace's receipts setting
```

`district-assurance/testing` has a fake for every adapter, the `sessionStoreContract` suite a
durable session store must pass, and `createTestEngine()`, which wires the fakes with a fixed clock
and sequential ids. [ARCHITECTURE.md](ARCHITECTURE.md) shows the pieces, [SPEC.md](SPEC.md) the
state machine, the config, the events and the formats.

## The reference server

`examples/reference-server/` is a small `node:http` server around one engine:

| Route | |
|---|---|
| `POST /webhooks/stripe/identity` | Stripe Identity outcomes, signature checked first |
| `POST /webhooks/stripe/payments` | Stripe Checkout outcomes on the platform's account, signature checked first, each event applied once |
| `POST /webhooks/stripe/connect` | Stripe Checkout outcomes from connected accounts (connect mode), with their own signing secret |
| `POST /webhooks/twilio`, `/telnyx` | `501` until carrier signature checks are built |
| `GET /receipts/:callId` | a call's signed receipt (demo only: real receipt links need capability tokens) |
| `GET /.well-known/receipt-keys.json` | the public key set for receipts |
| `GET /healthz` | liveness |

`npm run ui` adds the demo page and its `/demo/*` routes. `npm run serve` starts the server alone on `127.0.0.1:8787`. With `STRIPE_IDENTITY_WEBHOOK_SECRET`,
`STRIPE_PAYMENTS_WEBHOOK_SECRET` and `STRIPE_CONNECT_WEBHOOK_SECRET` set to your own test-mode endpoint secrets, `stripe listen` can
forward real test events to it; their signatures are checked, and since that server runs on fake
adapters, the sessions they name are unknown to the engine. It is not hardened for
production.

## Design rules

- **The model proposes, code decides.** Factors, levels, grants, read-backs, payment results and
  consents are code paths. Scoped actions are refused until code has issued a grant.
- **Compare, then discard.** Reference values and PINs are keyed hashes; the caller's digits are
  hashed, compared in constant time and dropped. Logs and the ledger carry what happened and how,
  never a value.
- **No oracle.** All keypad fields are judged together and give one answer; an unknown account
  looks exactly like a wrong answer, for keypad knowledge and the PIN alike.
- **Count before judging.** An attempt is recorded before it is judged, so a crash or a second
  process never gives a caller a free try.
- **Links and codes go to the number on file**, never to the calling number or one the model
  supplies, and only after a keypad or PIN match.
- **Caller ID is never a factor.** There is no factor kind for it, and no plug-in may take one.
- **Card numbers never enter.** Pay is by hosted link; transcripts are redacted; intake refuses a
  value that carries a card number; the ledger refuses detail that carries one.
- **Refuse at save time.** A config with any problem never runs; planned work is refused by the
  validator or throws `NotImplementedError` with its roadmap id instead of guessing.
- **Fail closed.** An unknown scope is refused, an expired grant is refused, an unsigned webhook is
  refused, a step outside the flow's current one is refused.
- **Never open a door twice.** An unlock is sent once; a lost answer is recorded as unknown, and
  opening again needs a fresh request.

## What it does not do

No call handling, speech, carrier routing or hosting: those belong to the host. No voice
biometrics. No recording. No storage beyond the in-memory reference adapters. No configuration UI.
No regulated identity proofing: it checks a caller against the organisation's own records.

## Documents

[ARCHITECTURE.md](ARCHITECTURE.md), [SPEC.md](SPEC.md), [SECURITY-MODEL.md](SECURITY-MODEL.md),
[DECISIONS.md](DECISIONS.md), [ROADMAP.md](ROADMAP.md), [ISSUES.md](ISSUES.md),
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
