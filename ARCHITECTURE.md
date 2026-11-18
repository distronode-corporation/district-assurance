# Architecture

## Where it sits

```
  caller's phone
       |
  carrier + SIP + speech + model          <- the host: not in this repository
       |
  host code paths: keypad events, tool handlers, webhook routes
       |
  +----v----------------------------------------------------------+
  | Engine (src/engine.ts): one per workspace                     |
  |   verify/   file/   pay/   prove/        webhooks/            |
  |   core/: session state machine, policy, events, redaction,    |
  |          canonical JSON, hashing, clock and ids, adapters     |
  +----+----------------------------------------------------------+
       | adapter interfaces (src/core/adapters.ts)
  IdentityProvider  CarrierSignals  MessageSender  PaymentLinks
  RecordStore       AuditLedger     ReceiptSigner
       |
  Stripe Identity, Stripe Checkout, Twilio / Telnyx / Sinch, the host's database and key store
```

The engine is a library. It holds no sockets and reads no environment. The host creates one
`Engine` per workspace with that workspace's policy, knowledge key and adapters, and calls it from
code. The model is never given the engine, its inputs or its answers; it hears fixed lines the
host speaks on the engine's results.

## Modules

| Path | Holds | Real today |
|---|---|---|
| `src/core/session.ts` | `SessionState`, the events, `reduce` (pure) | yes |
| `src/core/policy.ts` | factor kinds, levels, `validatePolicy`, `evaluateAssurance`, scope floors | yes |
| `src/core/redaction.ts` | `Redactor`, Luhn, card numbers in digits and en/fr digit words | yes |
| `src/core/canonical.ts` | canonical JSON (RFC 8785 for the values used) | yes |
| `src/core/hash.ts`, `clock.ts`, `errors.ts`, `events.ts` | helpers, `EngineError`, `NotImplementedError`, event names | yes |
| `src/core/adapters.ts` | the seven adapter interfaces and record types | interfaces |
| `src/verify/knowledge.ts` | subject keys, keyed digests, judging all keypad fields at once | yes |
| `src/verify/later.ts` | texted codes, cross-call counters, spoken answers, returning-caller PIN | planned |
| `src/file/intake.ts` | forms, value normalisation, required fields, record digest | yes |
| `src/file/later.ts` | read-back library, field encryption, delivery, upload links | planned |
| `src/pay/payment.ts` | payment request, amount validation, settlement rules | yes |
| `src/pay/later.ts` | saved-card charges, keypad capture through a carrier, cancel | planned |
| `src/prove/ledger.ts` | hash chain, `verifyChain`, `MemoryAuditLedger` | yes |
| `src/prove/receipt.ts` | receipt body, ES256 sign and verify, `keyPairSigner` | yes |
| `src/prove/consent.ts` | consent records, wording fingerprints; revocation planned | partly |
| `src/webhooks/stripe.ts` | Stripe signature check, event mapping | yes |
| `src/webhooks/carrier.ts` | Twilio, Telnyx, Sinch signature checks | planned |
| `src/engine.ts` | `Engine`: composes the above per call | yes, on the real pieces |
| `src/testing/` | fakes for every adapter, `createTestEngine` | yes |
| `examples/reference-server/` | `node:http` server, demo, Stripe adapter stubs | yes, not hardened |

Every planned function exists with its final signature and throws `NotImplementedError` with the
ROADMAP.md issue id, so hosts can wire against it now and tests prove that each one fails closed.

## One call, step by step

1. `startCall` opens a session (`open`).
2. `beginVerification` takes the keyed account number; the engine derives the subject key and
   looks the subject up. A missing subject is remembered silently.
3. `openSensitive("keypad")`: the host pauses its transcript, cuts audio to speech-to-text and the
   model, and holds staff listen-in until `closeSensitive`.
4. `submitKeypad` judges every keypad field at once and records one `keypad_knowledge` factor.
5. `checkCarrier` asks about the number on file (never the calling number): SIM swap and port
   recency decide whether a texted code can count; identity match becomes a factor.
6. `startPhotoId` (only after a match) creates an identity check and texts its link to the number
   on file. The provider's webhook, verified by the host or the reference server, arrives at
   `applyIdentityOutcome` and records a `photo_id` factor.
7. `finishVerification` computes the level, issues a grant with the scopes the policy allows at
   that level, valid for 15 minutes by default.
8. `startIntake` / `setIntakeField` / `confirmIntake` need `intake.file`; the record is stored
   through `RecordStore` and its digest goes to the ledger and the receipt.
9. `requestPayment` needs `payment.request`; the link is texted to the number on file, the
   session enters `paying` (sensitive), and `applyPaymentOutcome` settles it only on `paid`.
10. `recordConsent` fingerprints the wording read and stores the answer.
11. `endCall` closes the session, takes the ledger head and signs the receipt.

Every step appends to the `AuditLedger`, and the optional `onEvent` listener sees the same event.

## Trust boundaries

- **Model output** is untrusted: it never reaches an engine argument that decides anything. Text
  from business endpoints or documents is marked with `markUntrusted`, which drops the grant.
- **Webhooks** are untrusted until their signature verifies; the reference server checks it before
  parsing, applies each event id once, and the engine applies each outcome once.
- **Adapters** are trusted to do what they say. A host's adapters are part of the host's security
  model, not this one. `SECURITY-MODEL.md` lists what is left to the host.

## Dependencies

None at runtime: `node:crypto` does the hashing, HMAC and ES256. Development uses TypeScript,
`@types/node`, oxlint and c8, pinned exactly. `DECISIONS.md` says why.
