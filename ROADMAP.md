# Roadmap

The coding roadmap for district-assurance, from this skeleton to a production-ready engine that a
host can run on live calls. It has no dates: an item is done when the pull request that does it
is merged, and it then moves to [CHANGELOG.md](CHANGELOG.md). Every issue id here is also the id a
`NotImplementedError` names in the code, and `test/stubs.test.ts` fails if one is missing from
this file. The first 26 issues are written out, ready to paste, in [ISSUES.md](ISSUES.md).

## How work is proven

- **Every pull request:** lint, typecheck, `npm run test:coverage` (100% lines, statements,
  functions and branches in every `src/` file) and `npm run demo`, on Linux, macOS and Windows.
- **Formats** (receipts, the ledger, canonical JSON, webhook signatures): tamper tests and, where
  a vendor publishes them, the vendor's own test vectors.
- **Vendor adapters** (Stripe, Twilio, Telnyx, Sinch): tested in CI against a local fake HTTP
  server replaying recorded responses, never the network; proven once by hand against the
  vendor's test mode with the contributor's own test keys, the run described in the pull request.
- **Behaviour under attack:** the adversarial suite (VER-7) in English and French.
- **Live calls** are proven in the host's own repository, not here: this repository has no phone
  line.

## Milestones at a glance

| Milestone | What it delivers | Issues |
|---|---|---|
| M0 Skeleton | This run: the engine, real core pieces, stubs, reference server, demo, CI | done |
| M1 Verify | Lockouts across calls, texted codes, spoken answers, carrier and Stripe Identity adapters, adversarial suite | VER-1 to VER-8 |
| M2 File | Read-backs, encrypted fields, delivery, conditional fields, documents by text | FIL-1 to FIL-5 |
| M3 Pay | Stripe Checkout, amounts from code, cancel and expiry, live detector; saved cards and keypad capture gated | PAY-1 to PAY-6 |
| M4 Prove | Key rotation, stand-alone verifier, consent revocation, ledger export, contract suites, more redactors | PRV-1 to PRV-6 |
| M5 Reference server hardening | Carrier signatures, limits, receipt links, persistent stores, release workflow | SRV-1 to SRV-5 |
| M6 Host integration points | Shared session storage, keypad and gating helpers, key store contracts, events, configuration | INT-1 to INT-6 |

## Order of work

Milestones overlap; the order below is by dependency, and items in the same wave touch different
files, so they can run in parallel.

1. **Wave 1:** INT-3 (session storage; every later engine change builds on its state shape),
   VER-1, VER-8, FIL-4, PAY-5, PRV-5, SRV-1, SRV-2, INT-1.
2. **Wave 2:** VER-2, VER-3, VER-4, VER-5, FIL-1, FIL-2, PAY-1, PRV-1, PRV-3, PRV-6.
3. **Wave 3:** VER-7, FIL-3, PAY-2, PAY-3, PRV-2, SRV-3, SRV-5, INT-2, INT-4.
4. **Wave 4:** VER-6, FIL-5, PAY-4, PRV-4, SRV-4, INT-5, INT-6.
5. **Gated, not scheduled:** PAY-6 starts only after an assessor's scoping and a buyer who needs it.

Dependencies: VER-2 needs VER-1; VER-6 needs VER-1; VER-7 needs VER-2; FIL-3 and PAY-2 need FIL-1;
FIL-5 needs SRV-2; PAY-3, PAY-6 need PAY-1; PAY-4 needs PAY-2; PRV-2, PRV-4, SRV-3 need PRV-1;
PRV-6 needs PAY-5; SRV-4 needs PRV-5.

## M0. Skeleton (done)

What exists and how it is proven:

| Piece | Where | Proof |
|---|---|---|
| Session state machine | `src/core/session.ts` | every event in every phase, allowed or refused (`test/session.test.ts`) |
| Assurance policy, floors, carrier rule | `src/core/policy.ts` | validation errors, levels, discounted texted codes (`test/policy.test.ts`) |
| Card-number redaction | `src/core/redaction.ts` | Luhn, digits, English and French digit words, separators (`test/redaction.test.ts`) |
| Canonical JSON | `src/core/canonical.ts` | key order, escaping, refusals (`test/core.test.ts`) |
| Keypad knowledge | `src/verify/knowledge.ts` | one answer for unknown, wrong and malformed (`test/modules.test.ts`) |
| Intake forms and values | `src/file/intake.ts` | each type, card refusal, digest (`test/modules.test.ts`) |
| Payment settlement | `src/pay/payment.ts` | paid only on paid (`test/modules.test.ts`) |
| Audit ledger | `src/prove/ledger.ts` | chain, tamper, copies, card refusal (`test/prove.test.ts`) |
| Receipts | `src/prove/receipt.ts` | sign, verify, one-byte change fails (`test/prove.test.ts`) |
| Stripe webhooks | `src/webhooks/stripe.ts` | the published scheme, every refusal reason (`test/webhooks.test.ts`) |
| Engine | `src/engine.ts` | full flows and refusals (`test/engine.test.ts`) |
| Fakes | `src/testing/` | `test/entry-points.test.ts` |
| Stubs | `src/*/later.ts`, `src/webhooks/carrier.ts` | each throws with an id listed here (`test/stubs.test.ts`) |
| Reference server and demo | `examples/reference-server/` | real socket, signatures, 413, 501, receipts (`test/reference-server.test.ts`), `npm run demo` |
| CI and Dependabot | `.github/` | lint, EditorConfig, no em dashes, typecheck, coverage, build, demo |

## Milestones and issues

### M1. Verify

Durable checks across calls, texted codes, real carrier and Stripe Identity adapters, and the adversarial evaluation.

**Proven by:** Unit and contract tests at 100%; the adversarial suite passes in English and French; each adapter proven against a local fake HTTP server in CI and once by hand against the vendor's test mode, with the run recorded in the pull request.

#### **VER-1** Durable failure counters and lockout per subject and per calling number

Today the keypad limit is per call; a caller can call again. Counters must survive across calls.

*Acceptance*

- An `AttemptCounters` adapter interface in `src/core/adapters.ts`: `get`, `recordFailure`, `reset`, keyed by workspace and either subject key or a hash of the calling number.
- `submitKeypad` consults the counters before judging and refuses to judge while locked (same `locked: true` answer).
- Backoff after failures (5, 15, 60, 300, 900 seconds) and a hard lock after 10 failures in 24 hours, both configurable in the policy with these as defaults and floors.
- A `verification.locked` event with the scope of the lock (`subject` or `number`), never the values.
- `recordSubjectFailure` in `src/verify/later.ts` is replaced by the real implementation.

*Files:* `src/core/adapters.ts`, `src/core/policy.ts`, `src/verify/counters.ts` (new), `src/engine.ts`, `src/testing/fakes.ts`  
*Tests:* test/verify-counters.test.ts: backoff and lock with the fixed clock; test/engine.test.ts: lock carries across two calls; unknown subjects are counted by number  
*Depends on:* none

#### **VER-2** Texted one-time codes with send limits

The second factor for level 2. Codes are also the easiest way to abuse a phone line, so the limits ship with the feature.

*Acceptance*

- `sendTextCode(callId)` sends a 6-digit code to the number on file only after the keypad checks matched; the code is stored as an HMAC, expires after 10 minutes, allows 5 tries, is single-use and bound to the call.
- Limits: 5 codes per subject per 24 hours, 60 seconds between sends, a per-calling-number limit, and a destination country allow-list in the policy; a refused send gives the same spoken result as a sent one.
- `checkTextCode(callId, code)` records a `text_code` factor; the policy's carrier rule decides whether it counts (already implemented).
- The texts are code-built in English and French; `Engine.sendTextCode` stops throwing.

*Files:* `src/verify/text-code.ts` (new), `src/verify/later.ts`, `src/core/adapters.ts` (a CodeStore interface), `src/engine.ts`, `src/testing/fakes.ts`  
*Tests:* test/verify-text-code.test.ts: expiry, tries, single use, limits, country allow-list; test/engine.test.ts: no text before a match; refused and sent sends look the same to the caller  
*Depends on:* VER-1

#### **VER-3** Spoken answers for values a keypad cannot enter

Canadian postal codes contain letters. A spoken check must be exact after normalisation, never fuzzy.

*Acceptance*

- `normaliseSpokenAnswer({field, transcript, locale})` for postal codes (Canada and US) and short alphanumeric references, handling letter names and the common spelling alphabets in English and French.
- Returns a normalised value or `unusable`; never a near match.
- A `spoken_knowledge` factor compared like keypad fields (keyed digest, constant time).
- The policy can use `spoken_knowledge` only at level 1 or combined with another factor.

*Files:* `src/verify/spoken.ts` (new), `src/verify/later.ts`, `src/core/policy.ts`, `src/engine.ts`  
*Tests:* test/verify-spoken.test.ts with a corpus of transcripts in both languages, including misrecognitions that must come out `unusable`  
*Depends on:* none

#### **VER-4** Carrier signal adapters: Twilio Lookup, Sinch Number Lookup, Telnyx Number Lookup

The SIM swap and port checks the policy already uses need real sources.

*Acceptance*

- Three `CarrierSignals` implementations in the reference server, each mapping the vendor's answer to `CarrierSignalReport`.
- Timeouts, errors, unsupported countries and unapproved features all return `checked: false` (fail closed); nothing throws into the call.
- Credentials from the environment only; no keys in code or tests.
- A table in the reference server README of which signal each vendor provides, and where approval is needed.

*Files:* `examples/reference-server/src/carrier-adapters.ts` (new), `examples/reference-server/README.md`  
*Tests:* test/carrier-adapters.test.ts against a local fake HTTP server replaying fixture responses  
*Depends on:* none

#### **VER-5** Stripe Identity adapter

The photo ID tier runs on fakes today.

*Acceptance*

- `StripeIdentityProvider.createDocumentCheck` creates a VerificationSession (`type: document`, matching selfie required) with the call id in metadata and the engine's idempotency key, using `fetch` and a restricted key.
- Returns the session id and the single-use URL; never logs the URL.
- The reference server's identity webhook applies the outcome end to end with a real test-mode event.
- README steps for trying it with your own Stripe test account.

*Files:* `examples/reference-server/src/stripe-adapters.ts`, `examples/reference-server/src/main.ts`, `README.md`  
*Tests:* test/stripe-adapters.test.ts: request shape, headers and idempotency against a local fake; A recorded manual run in Stripe test mode in the pull request  
*Depends on:* none

#### **VER-6** Returning-caller PIN

Faster checks for callers who verified strongly before, without making a PIN a full pass.

*Acceptance*

- Enrolment only on a level 2 or higher call; a 6-digit PIN hashed with scrypt; lockout through VER-1.
- A `returning_pin` factor that the policy can combine but never use alone for level 2 or above (already enforced by `validatePolicy`).
- Reset by the business only.

*Files:* `src/verify/pin.ts` (new), `src/verify/later.ts`, `src/core/adapters.ts`, `src/engine.ts`  
*Tests:* test/verify-pin.test.ts  
*Depends on:* VER-1

#### **VER-7** Adversarial evaluation suite in English and French

Social engineering is the main threat. The suite makes the rules executable.

*Acceptance*

- Scripted dialogues (urgency, authority, "skip it", partial answers, account probing, text flooding, injection in business data) drive the engine through a scripted host.
- Each script asserts: no grant without factors, no text before a match, identical answers for unknown and wrong, tainted sessions lose their grant.
- Runs in `npm test`; a new rule or factor adds scripts in both languages.

*Files:* `test/adversarial/*.test.ts` (new), `test/adversarial/scripts/*.json` (new)  
*Tests:* The suite itself  
*Depends on:* VER-2

#### **VER-8** Policy version in grants and receipts

A receipt should say which policy judged the caller.

*Acceptance*

- Grants and receipts carry `policyVersion`; the `verification.finished` event too.
- Receipt format version stays 1 if the field is optional, otherwise becomes 2 with SPEC.md updated.

*Files:* `src/core/session.ts`, `src/engine.ts`, `src/prove/receipt.ts`, `SPEC.md`  
*Tests:* test/engine.test.ts; test/prove.test.ts  
*Depends on:* none

### M2. File

The read-back library, encrypted sensitive fields, delivery with retries, richer fields, and documents by text.

**Proven by:** Unit tests at 100%; read-back strings snapshot-tested in both languages; delivery retries driven by the fixed clock; the demo files a record with a sensitive field.

#### **FIL-1** Read-back library in English and French

The caller must confirm exactly what will be filed, read by code.

*Acceptance*

- `buildReadBack(form, values, locale)` builds the line per field type (dates spoken in full, yes and no, numbers), with the fixed confirm prompt.
- `confirmIntake` takes the digest of the read-back the caller heard and refuses if the draft changed since.
- No value marked sensitive is read back.

*Files:* `src/file/readback.ts` (new), `src/file/later.ts`, `src/engine.ts`  
*Tests:* test/file-readback.test.ts: snapshots per type and locale; test/engine.test.ts: a changed draft refuses confirmation  
*Depends on:* none

#### **FIL-2** Encrypted sensitive fields

Forms with sensitive fields are refused today.

*Acceptance*

- A `FieldCipher` adapter (interface exists) passed to the engine; sensitive values are encrypted before `putIntakeRecord`.
- Without a cipher, sensitive fields stay refused.
- DECISIONS.md records whether the record digest covers plaintext or ciphertext, and why.

*Files:* `src/file/later.ts`, `src/engine.ts`, `src/testing/fakes.ts`, `DECISIONS.md`  
*Tests:* test/engine.test.ts with a fake cipher: stored values are ciphertext, the digest is stable  
*Depends on:* none

#### **FIL-3** Record delivery with signed webhooks, retries and idempotency

Confirmed records must reach the business's system reliably.

*Acceptance*

- `deliverRecord` through a `RecordDelivery` adapter; outbound webhooks signed with the same `t=,v1=` HMAC scheme the engine verifies for Stripe.
- Retries with backoff and an idempotency key per record and destination; delivery attempts are ledger events without the payload.
- A sample receiver in the reference server that verifies the signature.

*Files:* `src/file/delivery.ts` (new), `src/file/later.ts`, `src/core/adapters.ts`, `examples/reference-server/src/app.ts`  
*Tests:* test/file-delivery.test.ts with the fixed clock  
*Depends on:* FIL-1

#### **FIL-4** Conditional fields and validation rules

Real intake forms branch and validate.

*Acceptance*

- `showIf` on a field (another field's value), min and max for numbers and dates, a pattern for text.
- Form validation refuses a field whose label or key names a Social Insurance Number or a card, and refuses `showIf` cycles.

*Files:* `src/file/intake.ts`  
*Tests:* test/modules.test.ts  
*Depends on:* none

#### **FIL-5** Documents by text: single-use upload links

A photo or PDF into the record, without MMS.

*Acceptance*

- `createUploadLink` returns a capability token (only its hash stored), single use, 30-minute expiry, allowed types and a size cap, bound to the call and record.
- A `DocumentStore` adapter and a scanning hook interface; the reference server serves a minimal upload page in English and French.

*Files:* `src/file/upload.ts` (new), `src/file/later.ts`, `src/core/adapters.ts`, `examples/reference-server/src/app.ts`  
*Tests:* test/file-upload.test.ts: single use, expiry, type and size refusals  
*Depends on:* SRV-2

### M3. Pay

The Stripe Checkout adapter, amounts from code with a read-back, link cancellation, and the live card-number detector. Saved cards and keypad capture are gated.

**Proven by:** Unit tests at 100%; the Checkout adapter proven against a local fake and once in Stripe test mode; the detector corpus passes in both languages.

#### **PAY-1** Stripe Checkout adapter

Pay runs on fakes today.

*Acceptance*

- `StripeCheckoutLinks.createLink` creates a Checkout Session in payment mode, cards only, the amount and currency from the engine, a 30-minute expiry, the payment id in metadata, the engine's idempotency key, and the `Stripe-Account` header when a connected account is configured.
- Never logs the URL; returns the session id as `linkId`.
- The payments webhook settles it end to end with a real test-mode event.

*Files:* `examples/reference-server/src/stripe-adapters.ts`, `examples/reference-server/src/main.ts`  
*Tests:* test/stripe-adapters.test.ts against a local fake; A recorded manual run in Stripe test mode in the pull request  
*Depends on:* none

#### **PAY-2** Amounts from code, read back before the link is sent

The amount must come from a record, a price list or the business's endpoint, and the caller hears it first.

*Acceptance*

- An `AmountSource` adapter resolves an amount from a reference; `requestPayment` takes the reference, not a raw number.
- A code-built amount read-back and a confirmation before the link is texted.

*Files:* `src/pay/amount.ts` (new), `src/engine.ts`, `src/core/adapters.ts`  
*Tests:* test/engine.test.ts  
*Depends on:* FIL-1

#### **PAY-3** Cancel and expire open links

A link should not outlive its purpose.

*Acceptance*

- `cancelPaymentLink` through a `PaymentLinks.cancel` method; open links are expired when the call ends, and the receipt shows them as expired.
- A late `paid` after cancellation is still recorded as paid (the money moved) and flagged in the ledger.

*Files:* `src/pay/later.ts`, `src/core/adapters.ts`, `src/engine.ts`  
*Tests:* test/engine.test.ts  
*Depends on:* PAY-1

#### **PAY-4** Saved-card charges for level 2 callers (gated)

Charging a card the business already holds. Off by default, its own switch.

*Acceptance*

- `chargeSavedCard` through an adapter, only with a level 2 grant and a confirmed amount read-back; never enabled by default.

*Files:* `src/pay/later.ts`, `src/engine.ts`  
*Tests:* test/engine.test.ts  
*Depends on:* PAY-2

#### **PAY-5** Live card-number detector for partial and spoken numbers

Redaction catches whole numbers; the interrupt should fire while the caller is still reading.

*Acceptance*

- A streaming detector fed transcript chunks that signals an interrupt on a run of 8 or more digits, including number words ("forty two", "quarante-deux") and "double" forms.
- Redaction also handles number words; a shared JSON corpus is the test source so another language's implementation can use it.

*Files:* `src/core/redaction.ts`, `src/core/live-detector.ts` (new), `test/corpus/card-numbers.json` (new)  
*Tests:* test/redaction.test.ts over the corpus  
*Depends on:* none

#### **PAY-6** Keypad card capture through a certified carrier service (gated)

Some buyers will need it; it must never route tones through this engine.

*Acceptance*

- Starts only after an assessor's scoping. The engine calls a `CarrierPayments` adapter to start and end capture and receives only a token and a result.
- An architecture note in SECURITY-MODEL.md shows that no tone reaches the engine during capture.

*Files:* `src/pay/later.ts`, `src/core/adapters.ts`, `SECURITY-MODEL.md`  
*Tests:* test/engine.test.ts: the engine never receives digits  
*Depends on:* PAY-1

### M4. Prove

Key rotation, a stand-alone verifier, consent revocation, ledger export, adapter contract suites and more redactors.

**Proven by:** Unit tests at 100%; tamper tests on every signed artifact; the verifier runs with only a receipt and a key set; the contract suites run against the memory adapters in CI.

#### **PRV-1** Receipt key sets and rotation

Keys must rotate without breaking old receipts.

*Acceptance*

- Several signers with one active; the published key set keeps retired public keys; `verifyReceipt` already selects by `kid`.
- The reference server's key set route serves the history.

*Files:* `src/prove/receipt.ts`, `src/engine.ts`, `examples/reference-server/src/app.ts`  
*Tests:* test/prove.test.ts: a receipt signed before rotation still verifies  
*Depends on:* none

#### **PRV-2** Stand-alone receipt verifier

Anyone holding a receipt should check it without this package.

*Acceptance*

- A zero-dependency script (`scripts/verify-receipt.mjs`) that takes a receipt and a key set (file or URL) and prints valid or invalid.
- Documented in SPEC.md with a worked example.

*Files:* `scripts/verify-receipt.mjs` (new), `SPEC.md`  
*Tests:* test/verifier.test.ts runs the script on a valid and a tampered receipt  
*Depends on:* PRV-1

#### **PRV-3** Consent revocation

Consent must be revocable by voice, text or dashboard.

*Acceptance*

- `revokeConsent` through a `ConsentStore` adapter; revocation is a ledger event; STOP and its French forms map to revocation.

*Files:* `src/prove/consent.ts`, `src/core/adapters.ts`, `src/engine.ts`  
*Tests:* test/engine.test.ts  
*Depends on:* none

#### **PRV-4** Ledger export as signed NDJSON with a cursor

Auditors and SIEMs need the ledger outside the host.

*Acceptance*

- `exportLedger({fromSeq})` yields newline-delimited JSON entries and a signed trailer with the head; resumable by cursor.

*Files:* `src/prove/later.ts`, `src/prove/export.ts` (new)  
*Tests:* test/prove.test.ts: export, resume and tamper detection  
*Depends on:* PRV-1

#### **PRV-5** Adapter contract suites in district-assurance/testing

A host's durable stores must keep the same guarantees as the memory ones.

*Acceptance*

- `runAuditLedgerContract(factory)` and `runRecordStoreContract(factory)` exported from `district-assurance/testing`: ordering, copies, append-only, chain validity, concurrency of appends.
- The memory adapters pass them in CI.

*Files:* `src/testing/contracts.ts` (new), `src/testing/index.ts`  
*Tests:* test/contracts.test.ts  
*Depends on:* none

#### **PRV-6** More redactors: SIN, health card numbers, bank account numbers

Card numbers are not the only sensitive numbers read aloud.

*Acceptance*

- Canadian SIN (9 digits, Luhn), provincial health card formats, bank transit and account formats, each as its own `Redactor`, digits and spoken forms in both languages.
- The corpus is shared JSON (see PAY-5).

*Files:* `src/core/redaction.ts`, `test/corpus/*.json`  
*Tests:* test/redaction.test.ts  
*Depends on:* PAY-5

### M5. Reference server hardening

Carrier webhook signatures, limits, capability links for receipts, an optional persistent store, and the release workflow.

**Proven by:** Server tests over a real socket; vendor test vectors for each signature scheme; the release workflow dry-runs on a tag in a fork.

#### **SRV-1** Carrier webhook signature verification

Carrier routes answer 501 today.

*Acceptance*

- `verifyTwilioSignature` (HMAC-SHA1 of the URL and sorted form parameters), `verifyTelnyxSignature` (Ed25519 over timestamp and body, with a tolerance), `verifySinchSignature` (the scheme of the product used).
- Each tested against the vendor's published examples; the routes stop answering 501 only when the check is real.

*Files:* `src/webhooks/carrier.ts`, `examples/reference-server/src/app.ts`  
*Tests:* test/webhooks.test.ts with vendor test vectors  
*Depends on:* none

#### **SRV-2** Server limits and logging

The reference server is not hardened.

*Acceptance*

- Per-route body limits, request timeouts, a per-address rate limit, and structured logs that never include bodies or headers carrying secrets.

*Files:* `examples/reference-server/src/app.ts`  
*Tests:* test/reference-server.test.ts  
*Depends on:* none

#### **SRV-3** Receipt links by capability token, and a receipt page

`GET /receipts/:callId` is for the demo only; call ids are not secrets.

*Acceptance*

- Each receipt gets an unguessable link token (only its hash stored); `GET /r/:token` serves a small receipt page in English and French with the verification result; the call id route is removed.

*Files:* `examples/reference-server/src/app.ts`, `src/prove/receipt.ts`  
*Tests:* test/reference-server.test.ts  
*Depends on:* PRV-1

#### **SRV-4** Optional persistent stores for the reference server

The server forgets everything on restart.

*Acceptance*

- SQLite-backed `RecordStore` and `AuditLedger` on `node:sqlite` (no new dependency), passing the PRV-5 contract suites.

*Files:* `examples/reference-server/src/sqlite-stores.ts` (new)  
*Tests:* The PRV-5 contract suites  
*Depends on:* PRV-5

#### **SRV-5** Release workflow

Nothing is published yet, by decision.

*Acceptance*

- A release workflow modelled on our other public packages: the CI gate on the tag, a reproducible pack, an exports smoke test, npm provenance, and a supply-chain workflow (npm audit, osv-scanner).
- `private: true` is removed only in the pull request that decides the first release.

*Files:* `.github/workflows/release.yml` (new), `.github/workflows/supply-chain.yml` (new), `package.json`  
*Tests:* A dry run on a tag in a fork  
*Depends on:* none

### M6. Host integration points

What any host (District first) needs to run the engine in production: shared session storage, keypad and transcript helpers, key store contracts, event delivery and a configuration schema.

**Proven by:** Unit and contract tests at 100%; the demo runs with two engine instances sharing one session store; integration is proven in the host's own repository, not here.

#### **INT-1** Keypad collector helper

Every host needs the same digit buffer; getting it wrong leaks digits.

*Acceptance*

- A pure `KeypadCollector` that buffers tones until `#`, with a maximum length and an idle timeout, exposes no digits through `toString` or JSON, and hands the digits to one callback.

*Files:* `src/core/keypad.ts` (new)  
*Tests:* test/keypad.test.ts  
*Depends on:* none

#### **INT-2** Transcript and audio gating helper

Hosts must pause transcripts and cut audio while `sensitive` is set.

*Acceptance*

- `gateFor(state)` returns what the host may forward (transcript, audio to speech-to-text, audio to the model, listen-in) for the current session; documented as the single place a host asks.

*Files:* `src/core/gating.ts` (new), `ARCHITECTURE.md`  
*Tests:* test/session.test.ts  
*Depends on:* none

#### **INT-3** Session storage shared across processes

The engine keeps sessions in memory. A host whose voice agent and web backend are separate processes, or run several replicas, needs shared session state.

*Acceptance*

- A `SessionStore` adapter with a version number per session (compare-and-set); every engine method loads, applies and saves with the version, and retries or refuses on conflict.
- Identity session and payment link lookups move into the store.
- The memory implementation and a contract suite (PRV-5 style).

*Files:* `src/core/adapters.ts`, `src/engine.ts`, `src/testing/fakes.ts`, `src/testing/contracts.ts`  
*Tests:* test/engine.test.ts with two engines sharing one store; Conflict tests  
*Depends on:* none

#### **INT-4** Key store contracts for the knowledge key and the receipt signer

Production keys live in a KMS, not in process memory.

*Acceptance*

- Document and test the contract: `ReceiptSigner.sign` returns a 64-byte P1363 ES256 signature; a helper converts DER signatures (what most KMS APIs return) to P1363.
- The knowledge key can be an opaque HMAC function instead of bytes, so it never leaves the key store.

*Files:* `src/prove/receipt.ts`, `src/verify/knowledge.ts`, `src/engine.ts`  
*Tests:* test/prove.test.ts: DER to P1363 conversion against node:crypto output  
*Depends on:* none

#### **INT-5** Event delivery semantics

`onEvent` is synchronous and best effort today.

*Acceptance*

- An async listener with defined semantics: the ledger append is the source of truth, listener failures are reported and never block the call.

*Files:* `src/engine.ts`, `src/core/events.ts`  
*Tests:* test/engine.test.ts  
*Depends on:* none

#### **INT-6** Versioned configuration schema

Hosts store policies, forms and wordings per workspace.

*Acceptance*

- One `EngineConfig` document (policy, forms, wordings) with a version and a validator that returns every problem, so a host can validate on save.

*Files:* `src/core/config.ts` (new)  
*Tests:* test/config.test.ts  
*Depends on:* none

## Not planned

- Voice biometrics, call recording, and caller ID as a factor: excluded by design.
- A hosted service: this repository is a library and a reference server.
- Regulated identity proofing (the methods some regulated reporting entities must use): the engine
  checks a caller against the organisation's own records.
- A payment processor: money is taken by the organisation's own payment provider account.

A change to any of these would be proposed as an issue first.
