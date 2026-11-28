<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/distronode-logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/assets/distronode-logo-light.png">
  <img alt="Distronode" src=".github/assets/distronode-logo-light.png" width="220">
</picture>

# district-assurance

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16957/badge)](https://www.bestpractices.dev/projects/16957)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/distronode-corporation/district-assurance/badge)](https://scorecard.dev/viewer/?uri=github.com/distronode-corporation/district-assurance)
[![Latest release](https://img.shields.io/github/v/release/distronode-corporation/district-assurance?label=release)](https://github.com/distronode-corporation/district-assurance/releases/latest)
[![npm](https://img.shields.io/npm/v/district-assurance)](https://www.npmjs.com/package/district-assurance)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/distronode-corporation/district-assurance/blob/main/LICENSE)
[![CI](https://github.com/distronode-corporation/district-assurance/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/distronode-corporation/district-assurance/actions/workflows/ci.yml?query=branch%3Amain)

**A modular TypeScript engine for trusted phone calls: verify the caller, file what they confirm,
take payment by link, and prove each step.**

```sh
npm install district-assurance   # the engine, for Node.js 24.19 or later
git clone https://github.com/distronode-corporation/district-assurance && cd district-assurance
npm ci && npm run demo           # four scripted calls, end to end, on your own machine
```

Made by [Distronode](https://www.distronode.com) · more open source at
[github.com/distronode-corporation](https://github.com/distronode-corporation) ·
[project page](https://www.distronode.com/district-assurance) ·
[CHANGELOG](CHANGELOG.md) · [Roadmap](ROADMAP.md)

## What it is

The engine behind District Assurance: TypeScript code that lets an automated phone line be trusted
with sensitive work. It checks who is calling, files what the caller confirms, takes payment
without ever touching a card number, and proves each step afterwards with a hash-chained audit
ledger and signed receipts. It is modular: a workspace turns on only what it needs, from a PIN
check before an owner's command to full verification with a payment during the call, or a verified
caller let in through a door. A small reference server and a scripted demo let you try it end to
end on your own machine.

> **Status: 1.0, a stable API.** Published to npm as `district-assurance`. From 1.0.0 on it
> follows Semantic Versioning: a breaking change to the public API comes only in a new major
> version ([What 1.0 promises](#what-10-promises)). Distronode runs it on real calls in District
> AI. Nothing here is certified: no PCI DSS attestation, no SOC 2 report, no regulated identity
> proofing. If you put it in front of your own callers, that is your decision, on your own review
> of [SECURITY-MODEL.md](SECURITY-MODEL.md) and what it leaves to the host.

## Quick start

Node.js 24.19 or later. The only dependencies are six development tools (stripe-node among them, for the type test and the byte comparison only; the package never imports it).

```sh
npm ci
npm test              # node:test over the TypeScript sources
npm run typecheck
npm run test:coverage # 100% lines, statements, functions and branches in every src/ file
npm run demo          # four scripted calls, end to end, on fake adapters and loopback servers
npm run ui            # the same calls in a browser, step by step, on http://127.0.0.1:8787/
npm run demo:e2e      # the browser demo with a real Stripe Checkout in test mode (below)
npm run simulate -- config.json --flow deposit --script pass   # one flow of your own config
```

`npm run simulate` (the `district-assurance simulate` command in the published package) runs
one flow of a FlowConfig file with a scripted caller on the in-memory adapters, and prints each
step, each decision, every event and the final receipt. Built-in scripts: `pass`, `wrong-pin`,
`lockout`, `consent-no`, `payment-paid`, `payment-expired`, `text-code-wrong`, `spoken-wrong`,
`callback-not-confirmed` and `door-refused`, or a JSON file of your own. A
config with any problem, or one that turns on an outside module, is refused with every reason
([SPEC.md](SPEC.md), section 28). Exit codes: 0 the flow ran, whatever its outcome; 1 a refused
config, flow or script; 2 bad usage; 3 a valid config whose flow reached a step the simulator has
no scripted caller for (a step an outside module adds, or a `badge.verify` step with a factor
plug-in): every built-in step type and factor has one. Exit 3 is not
a refusal: the run stops at that step, ends the call and prints what it did up to there.

The demo runs `owner-command` first: the owner of a line keys a PIN, on two engines that share one
session store as two processes of a host would; one wrong PIN, then the right one, and a grant for
owner commands only. Then `deposit`: a made-up caller is verified to level 2 by keypad and a
carrier match, files a repair request, has a card number read aloud removed from the transcript,
hears the amount the flow sets read back and confirms it, receives a payment link for that amount,
pays (a signed Stripe webhook), consents, and the signed receipt and the key set are fetched from
the server and checked (and a one-byte change fails); that money goes to the platform's account.
`deposit-connect` takes a deposit on the business's own account: a webhook without the connected
account is ignored, the Connect one settles it. Last, `entry`: a verified caller gets a signed 30-second access grant, the relay adapter
posts it to an example door relay, which checks it with Gate's public key and opens the pretend
door; the same grant sent again, and a changed copy, are refused. Nothing leaves the machine.

`npm run ui` serves a small page (plain HTML, CSS and JavaScript, no build step) that runs the
same script one step at a time and shows the session state, the ledger entries and the signed
receipt, which the page verifies itself against the public key set
([examples/reference-server/README.md](examples/reference-server/README.md)).

### The demo with a real Stripe Checkout

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

## Install

```sh
npm install district-assurance
```

Node.js 24.19 or later. The package has four entry points: `district-assurance` (the engine),
`district-assurance/testing` (fakes and test helpers), `district-assurance/stripe` and
`district-assurance/carrier` (described under [Using the engine](#using-the-engine)), plus the
JSON schema for FlowConfig, `district-assurance/schema/flow-config.v1.json`. It also installs the
`district-assurance simulate` command ([Quick start](#quick-start)).

### Verify a release

From 0.1.0 on, every version on npm is built and published by `.github/workflows/release.yml`,
with npm provenance, and from 0.2.0 on its tag is signed by that workflow, so you can check three
things before you trust it. (The placeholder version below 0.1.0 that reserved the name on npm
is not a release and holds no code.)

Which commit it is: the tag's gitsign signature. With
[gitsign](https://github.com/sigstore/gitsign) installed, in a clone with the tags fetched:

```sh
gitsign verify-tag vX.Y.Z \
  --certificate-identity https://github.com/distronode-corporation/district-assurance/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

It succeeds only when the signature is valid, its entry is in Sigstore's transparency log, and it
was made by that workflow file running on main of this repository. The release workflow runs the
same check, and builds and publishes nothing from a tag that fails it.

Where it came from: npm provenance, signed through Sigstore and logged in its public transparency
log, ties the tarball to the commit and the workflow run that built it, and the registry signs the
tarball too. In a project that has installed it:

```sh
npm install district-assurance
npm audit signatures   # registry signatures and provenance of everything installed
```

What is in it: a CycloneDX SBOM of the published package (development tools left out), with a
Sigstore-signed attestation whose subject is the tarball itself. Fetch the registry's tarball and
check the attestation against this repository, the release workflow and the tag:

```sh
npm pack district-assurance@X.Y.Z
gh attestation verify district-assurance-X.Y.Z.tgz \
  --repo distronode-corporation/district-assurance \
  --signer-workflow distronode-corporation/district-assurance/.github/workflows/release.yml \
  --source-ref refs/heads/main \
  --predicate-type https://cyclonedx.org/bom
```

From 0.2.0 on the release runs on main, so the source ref is `refs/heads/main`; for 0.1.0, which
was released from its tag, it is `--source-ref refs/tags/v0.1.0`.

Add `--format json --jq '.[].verificationResult.statement.predicate'` to print the SBOM that was
signed. The tag's GitHub release has the same tarball (with its SHA-256), the SBOM and the
attestation's Sigstore bundle; `--bundle district-assurance-X.Y.Z.tgz.sbom.sigstore.json` checks
against that bundle instead of looking the attestation up.

### Uninstall

```sh
npm uninstall district-assurance
```

A clone of this repository, for the demo, is removed by deleting its folder.

## A core and six modules

The **core** holds the call session and its state machine (on a shared session store, so several
processes can run one call), the assurance policy and its levels, redaction, the module registry
and the audit ledger. Everything else is a module. Trace's ledger is always on; every other module
can be turned on, turned off, added and removed per workspace config.

| Module | What it does | Today |
|---|---|---|
| **Badge** (verify) | Who is calling, in levels. Factors are plug-ins: a PIN (against a keyed hash, or the host's own PIN store), keypad knowledge checked against the organisation's records, spoken answers, a texted code, a callback to the number on file, carrier signals on that number, a photo ID plus selfie by a texted link, and any factor a host adds. A flow can use a PIN only or all of them. | Built on fakes, with lockouts across calls per subject and per calling number, PIN enrolment and an optional duress PIN, and Stripe Identity, Twilio Lookup and Telnyx Number Lookup adapters in the reference server. |
| **Dossier** (file) | Intake the caller confirms: forms the organisation defines, values normalised by code and read back before filing, a structured record with a fingerprint, encrypted sensitive fields, delivery to the organisation and documents by texted link. | Built. |
| **Paylink** (pay) | Payment by a secure link texted to the number on file, or emailed to the verified address on file when the caller chooses email (keypad 1 or 2, recorded as their consent) (a hosted page such as Stripe Checkout), on the business's own account (`connect`) or the platform's (`platform`), chosen per flow, for an amount the flow or the host's code sets and the caller hears read back. Only methods that settle during the call; the link lives 15 minutes after it is texted by default, and the host calls `expirePaymentLinks` at that deadline (a timer or a sweep) so the engine expires it. The engine never handles card numbers. | Built on fakes, both modes, with refunds and disputes in platform mode, and a Stripe Checkout adapter in the reference server for both modes, proven in Stripe test mode (`npm run demo:e2e`, and recorded runs replayed in `test/stripe-real.test.ts`). Charging a saved card (PAY-4) and keypad card capture (PAY-6) are planned. |
| **Trace** (prove) | The hash-chained audit ledger, which is always on and cannot be turned off, plus optional signed receipts (ES256 over canonical JSON) and consent records with fingerprinted wording. | Built, in memory, with receipt key rotation, consent revocation through a host `ConsentStore`, ledger export, public timestamp anchors, monthly reports, and access and deletion requests for one subject. |
| **Gate** (entry) | The outcome after verification: a signed, time-limited access grant for a door, never sent twice, whose outcome the engine itself records from the door controller's answer, or a one-time access code texted to the number on file. | Built, with the signed-webhook relay, Seam, Kisi and Verkada adapters, one-time access codes and a fake. |
| **Step-up** (entry) | Web sign-in step-up: a short-lived ES256 token, bound to the nonce a site showed, that the site exchanges once after the caller is verified. | Built. |

Outside modules plug in with `engine.use(module)`. A module declares what it provides (factors,
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
    "paylink": { "settings": { "maxAmountMinor": 50000, "mode": "connect", "connectedAccountId": "acct_..." } },
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
that is not something the caller knows. Pay by link is level 2 by default. There is no
configuration UI: config and API come first.

This config turns Gate on, so the engine needs Gate's adapters: its door controllers (`access`)
and its grant signer (`accessSigner`), as in "Using the engine" below. The validator refuses the
config without them, or with a target naming a controller the engine does not have.

## Using the engine

The host (your voice agent and web backend) calls the engine from code paths: keypad events, tool
handlers and webhook routes. The model never calls it and never sees what it compares.

```ts
import { createEngine, MemoryAuditLedger, keyPairSigner } from "district-assurance";

const engine = createEngine({
  workspaceId: "ws_123",
  knowledgeKey: process.env.KNOWLEDGE_KEY!, // per-workspace HMAC key, at least 16 bytes
  adapters: { ledger: new MemoryAuditLedger(), sessions, counters, records, carrier, messages, payments, signer },
  config, // the workspace's FlowConfig; any problem throws a ConfigError listing all of them
  // A config that turns Gate on needs its adapters among the others:
  // access: { lobby: webhookRelay({ url }) }, accessSigner,
});

const { callId } = await engine.startCall({ locale: "fr", flow: "owner-command" });
await engine.beginVerification(callId, { subjectKey: ownerSubjectKey, callingNumber }); // the host chose the subject
const { matched } = await engine.submitPin(callId, digitsFromKeypad);  // limited per call, and locked out across calls
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

`district-assurance/stripe` takes payments by link with Stripe Checkout, in test or live mode, as a
direct charge on the business's own connected account (Connect onboarding on Accounts v2) or on the
platform's account, and verifies the Connect webhook, whose mode is the signing secret's. It takes a
stripe-node client as it is, or `fetchStripeClient` with no SDK at all. `district-assurance/carrier`
reads Twilio and Telnyx Lookup answers as carrier signals. `StripeCheckoutLinks` keeps a link's
`expiresAt` inside Checkout's window by its own clock (wall time unless you pass `now`): give it your
engine's clock if that is not the wall clock. ⚠️ Pass it a client in the same Stripe mode as its
`mode`: it cannot ask a structural client for its key (`fetchStripeClient` checks the key against
the mode it is built for), and a client of the other mode would create the session at Stripe before
the adapter refuses the answer. Your host keeps the accounts, the keys,
the rate limits and the country policy (SPEC sections 31 and 32).

## The reference server

`examples/reference-server/` is a small `node:http` server around one engine:

| Route | |
|---|---|
| `POST /webhooks/stripe/identity` | Stripe Identity outcomes, signature checked first |
| `POST /webhooks/stripe/payments` | Stripe Checkout outcomes on the platform's account, signature checked first, each event applied once |
| `POST /webhooks/stripe/connect` | Stripe Checkout outcomes from connected accounts (connect mode), with their own signing secret |
| `POST /webhooks/records` | the sample receiver of record deliveries, signature checked first |
| `POST /webhooks/twilio`, `POST /webhooks/telnyx` | carrier webhooks, signature checked, then acknowledged (nothing is applied yet) |
| `GET /r/:token` | a receipt page in English and French (a Spanish reader gets the English page), with its signature check, by a capability token the host issued (`/r/:token.json`: the signed receipt) |
| `GET`, `POST /u/:token` | the single-use document upload page, when the server is given `uploads` |
| `GET /.well-known/receipt-keys.json` | the public key set for receipts |
| `GET /.well-known/security.txt` | the host's own security.txt, when the server is given `securityTxt` |
| `GET /healthz` | liveness |

`npm run ui` adds the demo page and its `/demo/*` routes. `npm run serve` starts the server alone
on `127.0.0.1:8787`. With `STRIPE_IDENTITY_WEBHOOK_SECRET`, `STRIPE_PAYMENTS_WEBHOOK_SECRET` and
`STRIPE_CONNECT_WEBHOOK_SECRET` set to your own test-mode endpoint secrets, `stripe listen` can
forward real test events to it, and their signatures are checked. The Stripe Identity adapter is
wired in (below). That server keeps fake payment adapters, so the Checkout sessions those events
name are unknown to the engine (`npm run demo:e2e` runs a real Checkout). It is not hardened for
production.

### Trying Stripe Identity with your own test account

`StripeIdentityProvider` (`examples/reference-server/src/stripe-adapters.ts`) creates a Stripe
Identity VerificationSession of type `document` with a matching selfie required, the call id in
its metadata and the engine's idempotency key, with `fetch` and a restricted key. It never logs the
single-use link. To see a photo ID check go from the engine to Stripe and back:

1. In the Stripe dashboard, in test mode, turn on Identity, then create a restricted key
   (`rk_test_...`) with write access to Identity verification sessions and nothing else.
2. Forward Identity events to the server, and note the signing secret `stripe listen` prints:

   ```sh
   stripe listen --events identity.verification_session.verified,identity.verification_session.requires_input,identity.verification_session.canceled \
     --forward-to localhost:8787/webhooks/stripe/identity
   ```

3. In another terminal, start the server with the key and the secret:

   ```sh
   STRIPE_IDENTITY_KEY=rk_test_... STRIPE_IDENTITY_WEBHOOK_SECRET=whsec_... npm run serve
   ```

   The server verifies a made-up trial caller by keypad and asks your Stripe account for a photo
   ID check. The text the caller would receive, with the link, is printed by a stand-in phone
   (the caller's number on file is a 555 number, and nothing is texted), followed by the trial
   call's id and the VerificationSession id.
4. Open the link and complete Stripe's test-mode check (test mode offers verified and failed
   outcomes without a real document).
5. `stripe listen` forwards the signed `identity.verification_session.verified` event; the server
   checks the signature, applies the outcome to the trial call, and prints
   `verification.factor {"kind":"photo_id","passed":true,"status":"verified"}`.

The server refuses a live key or a secret key: use a restricted test-mode key only, and never
commit it; the server reads it from the environment. Without `STRIPE_IDENTITY_KEY`, everything
runs on fakes.

The same trial call, and paid Checkout links in both payment modes, were recorded once in
Stripe test mode and are replayed offline by `test/stripe-real.test.ts` (recorder:
`test/fixtures/stripe-real/record.ts`, run by hand; every Stripe id in the files is redacted). The
recording did not use a restricted key: its loopback proxy sent the account's secret test key in
its place (a restricted key is made only in the Dashboard), so it proves the requests and Stripe's
answers, not a restricted key's permissions.

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
- **Refuse at save time.** A config with any problem never runs; planned work throws
  `NotImplementedError` with its roadmap id instead of guessing.
- **Fail closed.** An unknown scope is refused, an expired grant is refused, an unsigned webhook is
  refused, a step outside the flow's current one is refused.
- **Never open a door twice.** An unlock is sent once; a lost answer is recorded as unknown, and
  opening again needs a fresh request.

## What it does not do

No call handling, speech, carrier routing or hosting: those belong to the host. No voice
biometrics. No recording. No production storage: only the in-memory adapters and the reference
server's optional SQLite stores. No configuration UI.
No regulated identity proofing: it checks a caller against the organisation's own records.

## Releases

### What 1.0 promises

From 1.0.0 on, versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). These
are the public API, and a change that breaks any of them comes only in a new major version:

- The exports of the four entry points, `district-assurance`, `district-assurance/testing`,
  `district-assurance/stripe` and `district-assurance/carrier`, with their types, and the package's
  export map. `test/public-api.test.ts` pins the names.
- FlowConfig version 1 and its JSON Schema, `district-assurance/schema/flow-config.v1.json`: a
  config that is valid under 1.0.0 stays valid in every 1.x (but see the exception below).
- What the engine signs or writes for others to check: receipts (version 1), the ledger's entries
  and hash chain, ledger checkpoints and exports, monthly reports and subject exports, with their
  signatures, so a 1.x verifier checks what any 1.x engine wrote.
- The names of ledger events (`ENGINE_EVENTS`) and the codes of config problems.
- The `district-assurance simulate` command's arguments and exit codes.
- The supported Node.js versions: raising the minimum (24.19 today) is a major change.

A minor version may add to any of these: new exports, optional config settings, steps, event
names and problem codes. A patch version only fixes. The one exception: a fix for a security flaw
may refuse a config or an input that was accepted before (as 0.4.2 did for a number field holding
a card number), and CHANGELOG.md says so. Not covered:

- A function that throws `NotImplementedError` (today `chargeSavedCard` and
  `startKeypadCardCapture`) is a placeholder: building it in a minor version may change its shape.
- The Stripe API version the Stripe adapters send (`STRIPE_API_VERSION`) may move in a minor
  version when Stripe's own changes call for it, with a line in CHANGELOG.md.
- Anything not exported (a deep import into `dist/`), the reference server and the examples, which
  are not in the package, and the wording of messages, logs and spoken text.

### How releases work

One human gate: a release pull request, approved by the code owner, that sets `package.json`'s
version and dates its `## [X.Y.Z] - YYYY-MM-DD` section in CHANGELOG.md. When it merges,
`.github/workflows/release.yml` does the rest on its own, on that merge commit of main:

1. It releases only a version that has no tag `vX.Y.Z` and is not on npm; on every other push to
   main it does nothing. It refuses a commit that is not on main and a version with no dated
   CHANGELOG.md section.
2. It creates the annotated tag `vX.Y.Z` on that commit and signs it with
   [gitsign](https://github.com/sigstore/gitsign): keyless Sigstore signing under the workflow's
   own GitHub OIDC identity, with the signature and its transparency log entry in the tag. There
   is no long-lived signing key. It verifies the signature, pushes the tag, fetches it back and
   verifies it again; nothing is built from a tag that fails.
3. It builds, checks and publishes to npm with provenance, signs an SBOM attestation, and makes
   the tag's GitHub release with the tarball, the SBOM and the attestation's bundle.

Anyone with write access to this repository can create a `v*` tag, but only a version under a
tag that this workflow made and signed, running on main, is ever published: the release checks
the tag with `gitsign verify-tag` before it builds, and there is no tag trigger, so a tag pushed
by hand starts nothing. (A dry run, started by hand with `dry_run` ticked, builds and packs
without a tag or a signature, and never publishes.) A stray tag of the version, on another commit, stops the release (the run
fails, for a person to look at) and never ships. The repository's tag rules forbid moving or
deleting a `v*` tag (an admin can bypass them). Tags up to v0.1.0 were pushed by hand and are not
signed.

### Checking a release

Moved to [Verify a release](#verify-a-release).

## Documents

[ARCHITECTURE.md](ARCHITECTURE.md): the pieces. [SPEC.md](SPEC.md): the state machine, the config,
the events and the formats. [SECURITY-MODEL.md](SECURITY-MODEL.md): the threat model.
[DECISIONS.md](DECISIONS.md): the decisions and their reasons. [ISSUES.md](ISSUES.md), and
[BENCHMARKS.md](BENCHMARKS.md).

## Contributing, security and conduct

- [CONTRIBUTING.md](CONTRIBUTING.md): the principles, the setup and the whole local gate.
- [SECURITY.md](SECURITY.md): the supported versions, and how to report a vulnerability privately
  through
  [GitHub's private vulnerability reporting](https://github.com/distronode-corporation/district-assurance/security/advisories/new),
  not in a public issue.
- [ROADMAP.md](ROADMAP.md): what is planned.
- [GOVERNANCE.md](GOVERNANCE.md): who maintains the project, how a change is accepted, how a
  release is made, and how the project continues without any one person.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- [SUPPORT](.github/SUPPORT.md): bugs and feature requests go to
  [Issues](https://github.com/distronode-corporation/district-assurance/issues).
- [CHANGELOG.md](CHANGELOG.md).

## License and trademarks

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The licence grants no permission to use Distronode Corporation's trade names or trademarks, the
District Assurance name and the Distronode logo among them, except as reasonable and customary
use requires to describe where the work comes from (section 6 of the licence). Stripe, Twilio and
Telnyx are named only to describe interoperability; this project is not affiliated with or
endorsed by them.
