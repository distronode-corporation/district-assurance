# district-assurance

The engine behind District Assurance: TypeScript code that lets an automated phone
line be trusted with sensitive work. It checks who is calling, files what the caller confirms,
takes payment without ever touching a card number, and proves each step afterwards with a signed
receipt and a hash-chained audit ledger. A small reference server and a scripted demo let you try
it end to end on your own machine, and later with your own Stripe and carrier accounts.

> **Status: pre-alpha.** This is a skeleton with a coding roadmap. The API will change without
> notice, nothing is published to npm, and nothing here is certified: no PCI DSS attestation, no
> SOC 2 report, no regulated identity proofing. Do not put it in front of real callers.

## The four segments

District Assurance has four parts: **Badge** (verify), **Dossier** (file), **Paylink** (pay) and
**Trace** (prove). The code keeps the plain internal names `verify`, `file`, `pay` and `prove`.

| Segment | What it does | Today |
|---|---|---|
| **Badge** (verify) | Who is calling, in tiers: keypad knowledge checks against the organisation's own records; carrier signals on the number on file (SIM swap, porting, identity match); a photo ID plus selfie by a texted link (for example Stripe Identity) as the top tier. Each tier raises an assurance level, and a policy maps levels to what the caller may do. | Policy evaluation, keypad comparison, carrier signal handling, the photo ID flow on fakes. Texted codes and cross-call lockouts are planned. |
| **Dossier** (file) | Intake the caller confirms: a form the organisation defines, values normalised by code, a read-back, and a structured record with a fingerprint. | Forms, normalisation, confirmation and the record. The read-back library and delivery are planned. |
| **Paylink** (pay) | Payment by a secure link first (a hosted page such as Stripe Checkout, texted to the number on file). Keypad card capture comes later, only through a PCI-certified carrier service. The engine never handles card numbers. | Link requests and settlement on fakes, Stripe webhook verification. The Stripe adapter is planned. |
| **Trace** (prove) | Signed call receipts (ES256 over canonical JSON), an append-only hash-chained audit ledger, and consent records with fingerprinted wording. | All three, in memory. Export, key rotation and revocation are planned. |

Underneath them, a shared **core**: the call session and its state machine, the assurance policy,
engine events, a redaction interface with a card-number detector (Luhn, written and spoken digits
in English and French), canonical JSON, and an injected clock and id source.

## Try it

Node.js 24.2 or later. The only dependencies are four development tools.

```sh
npm ci
npm test              # node:test over the TypeScript sources
npm run typecheck
npm run test:coverage # 100% lines, statements, functions and branches in every src/ file
npm run demo          # one scripted call, end to end, on fake adapters and a loopback server
```

The demo verifies a made-up caller by keypad and photo ID, files a repair request, removes a card
number read aloud from the transcript, texts a payment link, receives signed Stripe webhooks for
the identity check and the payment, records consent, then fetches the signed receipt and the key
set from the server and checks both (and that a one-byte change fails). Nothing leaves the
machine.

## Using the engine

The host (your voice agent and web backend) calls the engine from code paths: keypad events, tool
handlers and webhook routes. The model never calls it and never sees what it compares.

```ts
import { createEngine, MemoryAuditLedger, keyPairSigner } from "district-assurance";

const engine = createEngine({
  workspaceId: "ws_123",
  knowledgeKey: process.env.KNOWLEDGE_KEY!, // per-workspace HMAC key, at least 16 bytes
  adapters: { identity, carrier, messages, payments, records, ledger: new MemoryAuditLedger(), signer },
});

const { callId } = await engine.startCall({ locale: "fr" });
await engine.beginVerification(callId, { accountNumber: digitsFromKeypad });
const { matched } = await engine.submitKeypad(callId, { dob: moreDigits }); // one answer for all fields
if (matched) await engine.startPhotoId(callId);                            // link to the number on file
// ... the identity webhook arrives: engine.applyIdentityOutcome(outcome)
const { level, scopes } = await engine.finishVerification(callId);
if (engine.authorize(callId, "payment.request")) {
  await engine.requestPayment(callId, { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" });
}
const receipt = await engine.endCall(callId);
```

`district-assurance/testing` has a fake for every adapter and `createTestEngine()`, which wires
them with a fixed clock and sequential ids. [ARCHITECTURE.md](ARCHITECTURE.md) shows the pieces,
[SPEC.md](SPEC.md) the state machine, events and formats.

## The reference server

`examples/reference-server/` is a small `node:http` server around one engine:

| Route | |
|---|---|
| `POST /webhooks/stripe/identity` | Stripe Identity outcomes, signature checked first |
| `POST /webhooks/stripe/payments` | Stripe Checkout outcomes, signature checked first, each event applied once |
| `POST /webhooks/twilio`, `/telnyx`, `/sinch` | `501` until carrier signature checks are built |
| `GET /receipts/:callId` | a call's signed receipt (demo only: real receipt links need capability tokens) |
| `GET /.well-known/receipt-keys.json` | the public key set for receipts |
| `GET /healthz` | liveness |

`npm run serve` starts it on `127.0.0.1:8787`. With `STRIPE_IDENTITY_WEBHOOK_SECRET` and
`STRIPE_PAYMENTS_WEBHOOK_SECRET` set to your own test-mode endpoint secrets, `stripe listen` can
forward real test events to it; their signatures are checked, and since the Stripe adapters are
not built yet, the sessions they name are unknown to the engine. It is not hardened for
production.

## Design rules

- **The model proposes, code decides.** Factors, levels, grants, read-backs, payment results and
  consents are code paths. Scoped actions are refused until code has issued a grant.
- **Compare, then discard.** Reference values are keyed hashes; the caller's digits are hashed,
  compared in constant time and dropped. Logs and the ledger carry what happened and how, never a
  value.
- **No oracle.** All keypad fields are judged together and give one answer; an unknown account
  looks exactly like a wrong answer.
- **Links and codes go to the number on file**, never to the calling number or one the model
  supplies, and only after the keypad checks matched.
- **Caller ID is never a factor.** There is no factor kind for it.
- **Card numbers never enter.** Pay is by hosted link; transcripts are redacted; intake refuses a
  value that carries a card number; the ledger refuses detail that carries one.
- **Fail closed.** An unknown scope is refused, an expired grant is refused, an unsigned webhook is
  refused, and planned work throws `NotImplementedError` instead of guessing.

## What it does not do

No call handling, speech, carrier routing or hosting: those belong to the host. No voice
biometrics. No recording. No storage beyond the in-memory reference adapters. No regulated
identity proofing: it checks a caller against the organisation's own records.

## Documents

[ARCHITECTURE.md](ARCHITECTURE.md), [SPEC.md](SPEC.md), [SECURITY-MODEL.md](SECURITY-MODEL.md),
[DECISIONS.md](DECISIONS.md), [ROADMAP.md](ROADMAP.md), [ISSUES.md](ISSUES.md),
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
