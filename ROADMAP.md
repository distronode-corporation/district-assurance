# Roadmap

The coding roadmap for district-assurance, from the modular core to a production-ready engine that
a host can run on live calls. It has no dates: an item is done when the pull request that does it
is merged, and it then moves to [CHANGELOG.md](CHANGELOG.md). Every issue id here is also the id a
`NotImplementedError` names in the code, or a validator names when it refuses planned work, and
`test/stubs.test.ts` fails if one is missing from this file. Every open issue with an id is
written out, ready to paste, in [ISSUES.md](ISSUES.md); an issue already open on GitHub is linked
instead.

The design: a small core (the session state machine on a shared session store, the policy and
its levels, redaction, the module registry and the audit ledger) and modules around it: Badge
(verify), Dossier (file), Paylink (pay), Trace (prove), Gate (entry), step-up (web sign-in), and
any outside module a host adds. Every module can be turned on, turned off, added and removed per workspace config,
and flows are config, not code. DECISIONS.md, ADR-13 to ADR-28, says why.

## How work is proven

- **Every pull request:** lint, typecheck, `npm run test:coverage` (100% lines, statements,
  functions and branches in every `src/` file) and `npm run demo`, on Linux, macOS and Windows.
- **Config:** every new setting or step gets `validateConfig` tests for each problem it can have,
  so a host refuses a bad config when it is saved, never in the middle of a call.
- **Formats** (receipts, access grants, the ledger, canonical JSON, webhook signatures): tamper
  tests and, where a vendor publishes them, the vendor's own test vectors.
- **Shared state:** a contract suite per durable adapter (`sessionStoreContract`,
  `attemptCountersContract`, `auditLedgerContract`, `codeStoreContract`, `recordStoreContract`,
  `recordStoreErasureContract`), run against the memory implementation in CI and by the host
  against its own.
- **Vendor adapters** (Stripe, Twilio, Telnyx, door controllers): tested in CI against a
  local fake HTTP server replaying recorded responses, never the network; proven once by hand
  against the vendor's test mode with the contributor's own test keys, the run described in the
  pull request.
- **Behaviour under attack:** the adversarial suite (VER-7) in English and French.
- **Live calls** are proven in the host's own repository, not here: this repository has no phone
  line.

## Milestones at a glance

| Milestone | What it delivers | Open issues |
|---|---|---|
| M0 Skeleton | The engine, real core pieces, stubs, reference server, demo, CI | done |
| M1 Modular core | Module registry, Badge, Dossier, Paylink and Trace as modules, factor plug-ins and the PIN factor, FlowConfig with `validateConfig` and flow execution, the shared SessionStore, the ledger always on | done |
| M2 Owner command | Lockouts across calls (the hard gate before a live PIN), the ledger and record store contracts, policy and config revision in receipts, the keypad collector, key store contracts, PIN enrolment and reset | done |
| M3 Gate and payment modes | The Gate module with signed access grants, the signed-webhook relay, Seam, Kisi and Verkada, one-time access codes, web sign-in step-up; Paylink's `connect` and `platform` modes, link life and instant methods | done |
| M4 Badge | Texted codes, spoken answers, carrier and Stripe Identity adapters, the adversarial suite, and the later Badge work (callback, caller ID attestation, the accessible path, duress PIN, risk-based step-up, synthetic voice, limits across flows, lockout alerts) | done |
| M5 Dossier | Read-backs, encrypted fields, delivery, conditional fields, documents by text, Spanish | done |
| M6 Paylink | Amounts from code, cancel and expiry, the live detector, refunds; the Stripe Checkout adapter in platform mode. Open: the Checkout adapter's connect mode; saved cards and keypad capture gated | PAY-1, PAY-4, PAY-6 |
| M7 Trace | Key rotation, the stand-alone verifier, consent revocation, ledger export, more redactors, subject requests, monthly reports, a public timestamp anchor, receipt links by text | done |
| M8 Reference server hardening | Carrier signatures, limits and logs, receipt links, persistent stores, the release workflow, signed releases, fuzz tests, the threat tables, security.txt, benchmarks. Open: the release dry run in a fork and the first release | SRV-5 |
| M9 Host integration and module authors | Transcript forwarding, event delivery, the module author kit, the FlowConfig JSON Schema, factors added after construction, the flow simulator, with a scripted caller for every built-in step | done |

## What is left

1. **PAY-1:** the Stripe Checkout adapter's connect mode and wallet methods, proven in Stripe test
   mode.
2. **SRV-5:** the release workflow's dry run on a tag in a fork, and the checks on the first real
   release.
3. **Gated, not scheduled:** PAY-4 (saved-card charges) and PAY-6 (keypad card capture); PAY-6
   starts only after an assessor's scoping and a buyer who needs it.

Dependencies: PAY-6 needs PAY-1.

## M0. Skeleton (done)

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
| Reference server | `examples/reference-server/` | real socket, signatures, 413, 501, receipts (`test/reference-server.test.ts`) |
| CI and Dependabot | `.github/` | lint, EditorConfig, no em dashes, typecheck, coverage, build, demo |

## M1. Modular core (done)

INT-3 (shared session storage) and INT-6 (a versioned configuration document) of the first
roadmap are done here.

| Piece | Where | Proof |
|---|---|---|
| Module interface and registry | `src/core/module.ts` | manifests, clashes, reserved names, the ledger's module cannot be removed (`test/config.test.ts`) |
| FlowConfig and `validateConfig` | `src/core/config.ts` | every problem with its path: modules, settings, adapters, policy, steps, floors, granted scopes (`test/config.test.ts`) |
| Flow execution | `src/engine.ts`, `src/core/flow.ts` | step by step, only the current step's work, failure, abandonment, config changes mid-call (`test/flows.test.ts`) |
| SessionStore (INT-3) | `src/core/adapters.ts`, `src/core/session-store.ts`, `src/testing/contracts.ts` | the contract suite, two engines on one store, retries and `conflict` (`test/session-store.test.ts`) |
| Badge as a module, factor plug-ins | `src/verify/badge.ts`, `src/verify/factors.ts` | factors on and off, attempts counted before judging, plug-ins see only the keyed hash (`test/pin.test.ts`, `test/engine.test.ts`) |
| The PIN factor | `src/verify/factors.ts` | keyed hash and host verifier, malformed and unknown look the same, limited attempts (`test/pin.test.ts`) |
| Dossier, Paylink, Trace as modules | `src/file/dossier.ts`, `src/pay/paylink.ts`, `src/prove/trace.ts` | forms and wordings from config, the amount from the flow step, receipts per flow (`test/engine.test.ts`, `test/flows.test.ts`) |
| Ledger always on | `src/prove/trace.ts`, `src/core/config.ts` | Trace cannot be turned off or removed, an engine without a ledger is refused (`test/config.test.ts`, `test/engine.test.ts`) |
| Outside modules | `Engine.use`, `Engine.updateModule` | an outside step in a flow, its ledger events, guards (`test/flows.test.ts`) |
| Demo | `examples/reference-server/src/demo.ts`, `flows.ts` | `owner-command` on two engines sharing one store, then `deposit` end to end (`test/reference-server.test.ts`, `npm run demo`) |
| Demo UI | `examples/reference-server/src/script.ts`, `demo-runs.ts`, `static.ts`, `public/` | every demo flow step by step over a real socket, the file allow-list, traversal refused, CSP and host checks, the page's receipt and ledger checks against the engine's (`test/reference-ui.test.ts`) |

## Milestones and issues

Each milestone lists what is built, with the tests that prove it, and then its open issues. Ids
beyond the first roadmap (VER-9 onwards, FIL-6, INT-7, PRV-7 onwards, PAY-8, SRV-6 onwards, MOD-4)
were added as the work was planned and are built.

### M2. Owner command (done)

The first live use: the `owner-command` flow (Badge with a PIN only, plus Trace) replaces a host's
own owner PIN check. The live call is proven in the host's own repository.

| Piece | Where | Proof |
|---|---|---|
| Lockouts across calls (VER-1), the hard gate before a live PIN | `src/verify/counters.ts` | waits of 5, 15, 60, 300 and 900 seconds and a hard lock after 10 failures in 24 hours, checked before a factor is judged (`test/verify-counters.test.ts`); a PIN lock carries across two calls and two engines (`test/pin.test.ts`) |
| Ledger and record store contracts (PRV-5) | `src/testing/contracts.ts` | `auditLedgerContract` and `recordStoreContract` pass on the memory adapters (`test/contracts.test.ts`) and catch broken stores (`test/store-contracts-hostile.test.ts`) |
| Policy version and config revision (VER-8) | `src/core/session.ts`, `src/prove/receipt.ts` | grants, `verification.finished` and receipts name `policyVersion` and `configRevision`; receipts stay at `v: 1` (`test/engine.test.ts`, `test/judged-by-hostile.test.ts`) |
| Keypad collector (INT-1) | `src/core/keypad.ts` | no digit through `toString`, JSON or inspect, the buffer wiped before the callback (`test/keypad.test.ts`) |
| Key store contracts (INT-4) | `src/prove/receipt.ts`, `src/verify/knowledge.ts` | DER to P1363 conversion, the knowledge key as an opaque HMAC function (`test/prove.test.ts`, `test/knowledge-key-hostile.test.ts`) |
| PIN enrolment and reset (VER-6) | `src/verify/pin.ts` | enrolment only at level 2 on the call, weak PINs refused, reset by the business only (`test/pin.test.ts`, `test/pin-enrol-hostile.test.ts`, `test/pin-enrol-races.test.ts`) |

### M3. Gate and payment modes (done)

| Piece | Where | Proof |
|---|---|---|
| Gate module (GAT-1) | `src/gate/gate.ts`, `src/gate/access.ts`, `src/engine.ts` | the engine owns every grant and outcome (ADR-25); refused without `entry.open`, a grant verified with the public key only, a changed byte refused, never past the verification grant, every grant and outcome in the ledger (`test/gate.test.ts`) |
| Unlocks never retried | `src/gate/gate.ts` | a lost answer is `unknown`, sent once, a fresh request is a new grant, one in flight per call, a limit per call (`test/gate.test.ts`) |
| Signed-webhook relay (GAT-2) | `src/gate/relay.ts`, `examples/reference-server/src/door-relay.ts` | against a loopback HTTP server: 2xx, 4xx, 5xx, redirects, timeouts (`test/gate-relay.test.ts`); replay and tamper refused by the example relay (`npm run demo`) |
| One-time access codes (GAT-3) | `src/gate/codes.ts` | codes texted to the number on file, stored as keyed hashes, single use, revoked when a call is tainted (`test/gate.test.ts`, `test/gate-codes-hostile.test.ts`) |
| Web sign-in step-up (GAT-4) | `src/gate/step-up.ts` | an ES256 JWT bound to the site's nonce, its JWKS, one exchange per token (`test/gate-step-up.test.ts`, `test/gate-step-up-hostile.test.ts`) |
| Seam (GAT-5) | `src/gate/seam.ts` | against a local fake HTTP server: remote unlock checked first, `confirmed` only on the device's confirmation, never retried (`test/gate-seam.test.ts`, `test/gate-seam-hosts.test.ts`) |
| Kisi and Verkada (GAT-6) | `src/gate/vendors.ts` | each vendor's unlock call against a local fake HTTP server, never retried (`test/gate-vendors.test.ts`, `test/gate-vendors-hosts.test.ts`) |
| Payment modes (PAY-7) | `src/pay/paylink.ts`, `src/core/adapters.ts` | `connect` and `platform` per step, the account on the request, outcomes from another account ignored (`test/paylink-modes.test.ts`) |
| Link life and instant methods | `src/pay/paylink.ts`, `src/pay/payment.ts` | 5 to 60 minutes (default 15) from the text, expired by the engine at its deadline; only card, Apple Pay, Google Pay and Link (`test/paylink-modes.test.ts`) |
| Demo | `examples/reference-server/src/demo.ts` | a deposit in each mode and a Gate unlock through the relay (`npm run demo`) |

The vendor adapters are tested against local fakes; a host runs each once against the vendor's
own sandbox before it goes live. A momentary unlock that opened its door has nothing to revoke
(ADR-22); a controller that can withdraw a grant not yet acted on offers the optional `revoke`,
which the engine calls when a call is tainted (SPEC.md section 17), and access codes have it.

### M4. Badge (done)

| Piece | Where | Proof |
|---|---|---|
| Texted codes with send limits (VER-2) | `src/verify/text-code.ts` | expiry, tries, single use, limits per subject and per calling number, the country allow-list, a refused send that answers like a sent one (`test/verify-text-code.test.ts`, `test/verify-text-code-hostile.test.ts`) |
| Spoken answers (VER-3) | `src/verify/spoken.ts` | normalised by code, unusable answers counted, never unlocks texts (`test/verify-spoken.test.ts`, `test/verify-spoken-hostile.test.ts`) |
| Carrier adapters (VER-4) | `examples/reference-server/src/carrier-adapters.ts` | Twilio Lookup and Telnyx Number Lookup against a local fake, failing closed (`test/carrier-adapters.test.ts`, `test/carrier-adapters-hostile.test.ts`) |
| Stripe Identity (VER-5) | `examples/reference-server/src/stripe-adapters.ts` | sessions, retries under one key, the signed verified event end to end (`test/stripe-identity.test.ts`, `test/stripe-identity-hostile.test.ts`) |
| Adversarial suite (VER-7) | `test/adversarial/` | scripted dialogues in English and Canadian French: no grant without factors, no text before a match, one answer for unknown and wrong, no grant after a taint (`test/adversarial/adversarial.test.ts`) |
| Callback (VER-9), caller ID attestation (VER-10), the accessible path (VER-11) | `src/verify/callback.ts`, `src/core/policy.ts`, `src/verify/badge.ts` | `test/verify-callback.test.ts`, `test/verify-attestation.test.ts`, `test/verify-accessibility.test.ts` |
| Duress PIN (VER-12), risk-based step-up (VER-13), synthetic voice (VER-14) | `src/verify/pin.ts`, `src/verify/duress-flag.ts`, `src/verify/badge.ts` | `test/verify-duress.test.ts`, `test/verify-step-up.test.ts`, `test/verify-synthetic-voice.test.ts` |
| Limits across flows (VER-15), lockout alerts (INT-7) | `src/verify/counters.ts` | `test/verify-cross-flow-limits.test.ts`, `test/verify-lockout-alerts.test.ts` |

Each vendor adapter is tested against a local fake; a host runs it once against the vendor's test
mode before it goes live.

### M5. Dossier (done)

| Piece | Where | Proof |
|---|---|---|
| Read-backs (FIL-1) | `src/file/readback.ts` | each field by type, no sensitive value read, a changed draft refused (`test/file-readback.test.ts`, `test/intake-readback-hostile.test.ts`) |
| Encrypted sensitive fields (FIL-2) | `src/file/dossier.ts`, the `fieldCipher` adapter | stored values are ciphertext, the digest keys them (ADR-27) (`test/field-cipher-hostile.test.ts`) |
| Record delivery (FIL-3) | `src/file/delivery.ts` | signed posts, retries with backoff, one idempotency key per record and destination (`test/file-delivery.test.ts`, `test/delivery-hostile.test.ts`) |
| Conditional fields and rules (FIL-4) | `src/file/intake.ts` | `showIf`, `min`, `max`, `pattern`, every bad rule reported (`test/modules.test.ts`, `test/config.test.ts`) |
| Documents by text (FIL-5) | `src/file/upload.ts` | single-use 30-minute links, only a hash stored, type and size refused (`test/file-upload.test.ts`, `test/file-upload-hostile.test.ts`) |
| Spanish (FIL-6) | `src/core/runtime.ts`, `src/file/readback.ts` | an `es` locale for read-backs, texts and card redaction, with a parity test over every code-built string (`test/locales.test.ts`, `test/locale-es-hostile.test.ts`) |

### M6. Paylink

| Piece | Where | Proof |
|---|---|---|
| Amounts from code, read back (PAY-2) | `src/pay/amount.ts`, `src/pay/paylink.ts` | the amount from the step's source, read back before the link is sent (`test/paylink-amounts.test.ts`, `test/paylink-amounts-hostile.test.ts`) |
| Cancel and expire open links (PAY-3) | `src/pay/paylink.ts`, `src/engine.ts` | `cancelPaymentLink`, `expirePaymentLinks`, a link expired when the call ends (`test/engine.test.ts`, `test/pay-close-hostile.test.ts`) |
| Live card-number detector (PAY-5) | `src/core/live-detector.ts`, `src/core/redaction.ts` | partial and spoken numbers over the shared corpus in `test/corpus/` (`test/redaction.test.ts`, `test/redaction-hostile.test.ts`) |
| Refunds and disputes in platform mode (PAY-8) | `src/pay/refunds.ts` | `test/pay-refunds.test.ts`, `test/pay-refunds-hostile.test.ts` |
| A pending refund's later outcome (PAY-9, #132) | `src/pay/refunds.ts`, `src/webhooks/stripe.ts` | `test/pay-refund-updates.test.ts` |
| Stripe Checkout in platform mode (part of PAY-1) | `examples/reference-server/src/stripe-adapters.ts` | `StripeCheckoutLinks` against a local fake (`test/stripe-adapters.test.ts`), and `npm run demo:e2e` with a real Checkout Session in test mode |

**Proven by:** Unit tests at 100%; the Checkout adapter against a local fake, and in Stripe test
mode in platform mode (`npm run demo:e2e`). Proving connect mode in test mode is PAY-1, below.

#### **PAY-1** Stripe Checkout adapter: connect mode and wallet methods

`StripeCheckoutLinks` runs in platform mode, proven in Stripe test mode by `npm run demo:e2e`. In
connect mode it sends the `Stripe-Account` header, but that has not been proven against Stripe.

*Acceptance*

- In `connect` mode, a direct charge on the connected account, proven in Stripe test mode, and `expireLink` on the connected account.
- How Apple Pay, Google Pay and Link map to Checkout's parameters is proven in test mode, not assumed.
- Connect-mode events come from the Connect endpoint, with its own signing secret, carry the connected account, and settle the payment end to end with a real test-mode event.

*Files:* `examples/reference-server/src/stripe-adapters.ts`, `examples/reference-server/src/main.ts`  
*Tests:* test/stripe-adapters.test.ts against a local fake; A recorded manual run in Stripe test mode in the pull request  
*Depends on:* none

#### **PAY-4** Saved-card charges for level 2 callers (gated)

Charging a card the business already holds. Off by default, its own switch.

*Acceptance*

- `chargeSavedCard` through an adapter, only with a level 2 grant and a confirmed amount read-back; never enabled by default.

*Files:* `src/pay/later.ts`, `src/pay/paylink.ts`  
*Tests:* test/engine.test.ts  
*Depends on:* PAY-2

#### **PAY-6** Keypad card capture through a certified carrier service (gated)

Some buyers will need it; it must never route tones through this engine.

*Acceptance*

- Starts only after an assessor's scoping. The engine calls a `CarrierPayments` adapter to start and end capture and receives only a token and a result.
- An architecture note in SECURITY-MODEL.md shows that no tone reaches the engine during capture.

*Files:* `src/pay/later.ts`, `src/core/adapters.ts`, `SECURITY-MODEL.md`  
*Tests:* test/engine.test.ts: the engine never receives digits  
*Depends on:* PAY-1

### M7. Trace (done)

| Piece | Where | Proof |
|---|---|---|
| Receipt key sets and rotation (PRV-1) | `src/prove/receipt.ts` | a receipt signed before rotation still verifies, a retired key is marked (`test/prove.test.ts`, `test/receipt-rotation-hostile.test.ts`) |
| Stand-alone receipt verifier (PRV-2) | `scripts/verify-receipt.mjs` | valid and tampered receipts, from a file, standard input or a URL (`test/verifier.test.ts`) |
| Consent revocation (PRV-3) | `src/prove/consent.ts`, `src/prove/trace.ts` | `revokeConsent` by voice, text or dashboard through a `ConsentStore`, STOP and its French forms (`test/engine.test.ts`, `test/consent-hostile.test.ts`) |
| Ledger export (PRV-4) | `src/prove/export.ts` | signed NDJSON runs that resume by cursor, tamper detected (`test/prove.test.ts`, `test/ledger-export-hostile.test.ts`) |
| More redactors (PRV-6) | `src/core/redaction.ts` | SIN, health card and bank account numbers over the shared corpus (`test/redaction.test.ts`, `test/redaction-more-hostile.test.ts`) |
| Subject requests (PRV-7) | `src/prove/subject.ts` | a signed export and an erasure that keeps the ledger whole (ADR-28) (`test/prove-subject.test.ts`, `test/subject-requests-hostile.test.ts`) |
| Monthly reports (PRV-8), a public timestamp anchor (PRV-9), receipt links by text (PRV-10) | `src/prove/report.ts`, `src/prove/anchor.ts`, `src/prove/trace.ts` | `test/prove-report.test.ts`, `test/prove-anchor.test.ts`, `test/prove-receipt-text.test.ts` |

### M8. Reference server hardening

| Piece | Where | Proof |
|---|---|---|
| Carrier webhook signatures (SRV-1) | `src/webhooks/carrier.ts` | Twilio and Telnyx checks against the vendors' published examples (`test/webhooks.test.ts`, `test/carrier-signature-hostile.test.ts`) |
| Limits and logs (SRV-2) | `examples/reference-server/src/app.ts` | body limits, timeouts, a per-address rate limit, logs without bodies or secrets (`test/reference-server.test.ts`, `test/reference-server-log-sink.test.ts`) |
| Receipt links by capability token (SRV-3) | `examples/reference-server/src/app.ts` | `GET /r/:token`, only the token's hash kept, no route by call id (`test/reference-server.test.ts`) |
| Persistent stores (SRV-4) | `examples/reference-server/src/sqlite-stores.ts` | on `node:sqlite`, passing the PRV-5 contracts (`test/sqlite-stores.test.ts`); opt-in, `npm run serve` stays in memory |
| Release workflow and signed releases (SRV-5, SRV-6) | `.github/workflows/release.yml`, `.github/workflows/supply-chain.yml` | a reproducible pack, an exports smoke test, an SBOM (`test/release-workflow.test.ts`, `test/release-steps.test.ts`, `test/pack.test.ts`) |
| Fuzz and property tests (SRV-7), the threat tables and audit pack (SRV-8) | `test/fuzz/`, `SECURITY-MODEL.md`, `scripts/audit-pack.mjs` | `test/security-model.test.ts`, `test/audit-pack-out.test.ts` |
| security.txt (SRV-9), benchmarks (SRV-10) | `examples/reference-server/src/app.ts`, `bench/` | `test/security-txt-review.test.ts`, `test/bench.test.ts` |

**Proven by:** Server tests over a real socket; vendor test vectors for each signature scheme;
the release workflow's tests. Its dry run on a tag in a fork has not been done yet: that is SRV-5,
below.

#### **SRV-5** Release workflow: the dry run in a fork and the first release

The release workflow is built, and nothing is published yet, by decision: `package.json` keeps
`"private": true`.

*Acceptance*

- The workflow's dry run on a tag in a fork, recorded in the pull request (also asked for by signed releases, SRV-6).
- `private: true` is removed only in the pull request that decides the first release, and that release is checked against the reviewed source.

*Files:* `.github/workflows/release.yml`, `package.json`  
*Tests:* A dry run on a tag in a fork  
*Depends on:* none

### M9. Host integration and module authors

| Piece | Where | Proof |
|---|---|---|
| Transcript and audio forwarding (INT-2) | `src/core/forwarding.ts` | the transcript, audio to speech-to-text, audio to the model and listen-in, all held while `sensitive` is set and after the call (`test/session.test.ts`, `test/forwarding-hostile.test.ts`); the host must still ask it and obey |
| Event delivery (INT-5) | `src/engine.ts` | the listener told at least once after each append, never awaited, its errors to `onListenerError` (`test/engine.test.ts`, `test/event-delivery-hostile.test.ts`) |
| Module author kit (MOD-1) | `src/testing/contracts.ts`, `examples/modules/callback.ts` | `moduleContract` and an example outside module (`test/module-contract.test.ts`, `test/module-contract-hostile.test.ts`) |
| JSON Schema for FlowConfig (MOD-2) | `schema/flow-config.v1.json` | every config `validateConfig` accepts passes the schema (`test/config-schema.test.ts`) |
| Factors added after construction (MOD-3) | `src/engine.ts`, `src/verify/badge.ts` | `engine.useFactor` and modules that provide factors (`test/factor-plugins-hostile.test.ts`, `test/pin.test.ts`) |
| Flow simulator (MOD-4) | `src/cli/simulate.ts` | scripted callers on the fakes (`test/simulate.test.ts`) |
| Simulator callers for every built-in step (#134) | `src/cli/simulate.ts` | Gate, step-up, callback, texted code and spoken answers (`test/simulate-all-steps.test.ts`) |

## Not planned

- Voice biometrics, call recording, and caller ID as a factor: excluded by design.
- A hosted service: this repository is a library and a reference server.
- A configuration UI: flows are config and API first; a host builds its own editor on `validateConfig`.
- Regulated identity proofing (the methods some regulated reporting entities must use): the engine
  checks a caller against the organisation's own records.
- A payment processor: money is taken by a Stripe account, the business's own or the platform's.

A change to any of these would be proposed as an issue first.
