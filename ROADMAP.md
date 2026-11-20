# Roadmap

The coding roadmap for district-assurance, from the modular core to a production-ready engine that
a host can run on live calls. It has no dates: an item is done when the pull request that does it
is merged, and it then moves to [CHANGELOG.md](CHANGELOG.md). Every issue id here is also the id a
`NotImplementedError` names in the code, or a validator names when it refuses planned work, and
`test/stubs.test.ts` fails if one is missing from this file. Every open issue is written out,
ready to paste, in [ISSUES.md](ISSUES.md).

The design: a small core (the session state machine on a shared session store, the policy and
its levels, redaction, the module registry and the audit ledger) and modules around it: Badge
(verify), Dossier (file), Paylink (pay), Trace (prove), Gate (entry), and any outside module
a host adds. Every module can be turned on, turned off, added and removed per workspace config,
and flows are config, not code. DECISIONS.md, ADR-13 to ADR-28, says why.

## How work is proven

- **Every pull request:** lint, typecheck, `npm run test:coverage` (100% lines, statements,
  functions and branches in every `src/` file) and `npm run demo`, on Linux, macOS and Windows.
- **Config:** every new setting or step gets `validateConfig` tests for each problem it can have,
  so a host refuses a bad config when it is saved, never in the middle of a call.
- **Formats** (receipts, access grants, the ledger, canonical JSON, webhook signatures): tamper
  tests and, where a vendor publishes them, the vendor's own test vectors.
- **Shared state:** a contract suite per durable adapter (`sessionStoreContract` today), run
  against the memory implementation in CI and by the host against its own.
- **Vendor adapters** (Stripe, Twilio, Telnyx, door controllers): tested in CI against a
  local fake HTTP server replaying recorded responses, never the network; proven once by hand
  against the vendor's test mode with the contributor's own test keys, the run described in the
  pull request.
- **Behaviour under attack:** the adversarial suite (VER-7) in English and French.
- **Live calls** are proven in the host's own repository, not here: this repository has no phone
  line.

## Milestones at a glance

| Milestone | What it delivers | Issues |
|---|---|---|
| M0 Skeleton | The engine, real core pieces, stubs, reference server, demo, CI | done |
| M1 Modular core | Module registry, Badge, Dossier, Paylink and Trace as modules, factor plug-ins and the PIN factor, FlowConfig with `validateConfig` and flow execution, the shared SessionStore, the ledger always on | done |
| M2 Owner command | What the first live use (`owner-command`) still needs. VER-1 (lockouts across calls), the hard gate before it goes live in any host, is built, and so are the ledger and record store contracts (PRV-5). Also: policy and config revision in receipts, the keypad collector, key store contracts, PIN enrolment | VER-1, VER-8, INT-1, INT-4, PRV-5, VER-6 |
| M3 Gate and payment modes | Done: the Gate module with signed access grants, the signed-webhook relay, Paylink's `connect` and `platform` modes, link life and instant methods; built, acceptance open: one-time codes, web step-up, Seam, direct vendor adapters | GAT-3 to GAT-6 |
| M4 Badge | Texted codes, spoken answers, carrier and Stripe Identity adapters, adversarial suite | VER-2 to VER-5, VER-7 |
| M5 Dossier | Read-backs, encrypted fields, delivery, conditional fields, documents by text | FIL-1 to FIL-5 |
| M6 Paylink | Stripe Checkout, amounts from code, cancel and expiry, live detector; saved cards and keypad capture gated | PAY-1 to PAY-6 |
| M7 Trace | Key rotation, stand-alone verifier, consent revocation, ledger export, more redactors | PRV-1 to PRV-4, PRV-6 |
| M8 Reference server hardening | Carrier signatures, limits, receipt links, release workflow; built: persistent stores (SRV-4) | SRV-1 to SRV-5 |
| M9 Host integration and module authors | A module author kit, a JSON Schema for FlowConfig, factors added after construction; built: transcript forwarding (INT-2) and event delivery (INT-5) | INT-2, INT-5, MOD-1 to MOD-3 |

## Order of work

Milestones overlap; the order below is by dependency, owner-command first. Items in the same wave
touch different files, so they can run in parallel.

1. **Wave 1, owner-command:** VER-1, VER-8, INT-1, INT-4, PRV-5. **VER-1 was the hard gate** for owner-command and any PIN
   factor on a live line; it is built.
2. **Wave 2:** VER-6, VER-2, VER-4, VER-5, FIL-1, FIL-2, PAY-1, PAY-5, PRV-1, PRV-3, SRV-1, SRV-2,
   MOD-1.
3. **Wave 3:** VER-3, VER-7, FIL-3, FIL-4, PAY-2, PAY-3, PRV-2, PRV-6, SRV-3, SRV-5, INT-2, GAT-3,
   GAT-5, MOD-2, MOD-3.
4. **Wave 4:** FIL-5, PAY-4, PRV-4, SRV-4, INT-5, GAT-4, GAT-6.
5. **Gated, not scheduled:** PAY-6 starts only after an assessor's scoping and a buyer who needs it.

Dependencies: VER-2 and VER-6 need VER-1; VER-7 needs VER-2; FIL-3 and PAY-2 need FIL-1; FIL-5
needs SRV-2; PAY-3 and PAY-6 need PAY-1; PAY-4 needs PAY-2; PRV-2, PRV-4 and
SRV-3 need PRV-1; PRV-6 needs PAY-5; SRV-4 needs PRV-5; GAT-3 needs VER-2.

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

### M2. Owner command

The first live use: the `owner-command` flow (Badge with a PIN only, plus Trace) replaces a host's own owner PIN check. What it still needs before a live call. VER-1, the hard gate before any live PIN, is built.

**Proven by:** Unit and contract tests at 100%; the PIN lockout proven across two calls and two engines on one session store; the live call is proven in the host's own repository.

Built: durable failure counters and lockout per subject and per calling number (VER-1). An
`AttemptCounters` adapter shared by every engine of a workspace, waits of 5, 15, 60, 300 and 900
seconds after a failure and a hard lock after 10 failures in 24 hours, checked before a factor is
judged (`test/verify-counters.test.ts`); a PIN lock carries across two calls and two engines
(`test/pin.test.ts`).

Built: adapter contract suites in `district-assurance/testing` (PRV-5). `auditLedgerContract` and
`recordStoreContract` check ordering, pages, copies, append-only entries, chain validity, one entry
per event id (replayed and concurrent appends too) and keys kept apart across workspaces; the
memory adapters pass them in CI (`test/contracts.test.ts`), and the suites catch broken stores
(`test/store-contracts-hostile.test.ts`).

#### **VER-8** Policy version and config revision in grants and receipts

A receipt should say which policy and which revision of the workspace's FlowConfig judged the caller. `call.started` already carries the revision; the grant and the receipt do not.

*Acceptance*

- Grants and receipts carry `policyVersion` and `configRevision`; the `verification.finished` event too.
- Receipt format version stays 1 if the fields are optional, otherwise becomes 2 with SPEC.md updated.

*Files:* `src/core/session.ts`, `src/verify/badge.ts`, `src/prove/trace.ts`, `src/prove/receipt.ts`, `SPEC.md`  
*Tests:* test/engine.test.ts; test/prove.test.ts  
*Depends on:* none

#### **INT-1** Keypad collector helper

Every host needs the same digit buffer; getting it wrong leaks digits.

*Acceptance*

- A pure `KeypadCollector` that buffers tones until `#`, with a maximum length and an idle timeout, exposes no digits through `toString` or JSON, and hands the digits to one callback.

*Files:* `src/core/keypad.ts` (new)  
*Tests:* test/keypad.test.ts  
*Depends on:* none

#### **INT-4** Key store contracts for the knowledge key and the receipt signer

Production keys live in a KMS, not in process memory.

*Acceptance*

- Document and test the contract: `ReceiptSigner.sign` returns a 64-byte P1363 ES256 signature; a helper converts DER signatures (what most KMS APIs return) to P1363.
- The knowledge key can be an opaque HMAC function instead of bytes, so it never leaves the key store. Factor plug-ins already receive only `hmac`; the engine's own use moves to the same function.

*Files:* `src/prove/receipt.ts`, `src/verify/knowledge.ts`, `src/engine.ts`  
*Tests:* test/prove.test.ts: DER to P1363 conversion against node:crypto output  
*Depends on:* none

#### **VER-6** PIN enrolment and reset

The `pin` factor checks a PIN against a keyed hash on file or the host's own verifier. Nothing yet lets a caller choose one on the line.

*Acceptance*

- `enrolPin` (in `src/verify/later.ts` today) lets a caller who verified to level 2 or above on this call choose a PIN, keyed twice and compared, then stored through a new `RecordStore.putPinDigest` as `pinDigest(knowledgeKey, subjectKey, pin)`.
- Refuses PINs that are all one digit, a run (1234, 4321) or the subject's keypad knowledge; the length comes from Badge's PIN settings.
- Reset by the business only (a host call, not a caller one). In `verifier` mode the host's own store enrols, and `enrolPin` refuses.
- A `pin.enrolled` event, never the digits.

*Files:* `src/verify/pin.ts` (new), `src/verify/later.ts`, `src/core/adapters.ts`, `src/verify/badge.ts`, `src/engine.ts`  
*Tests:* test/pin.test.ts: enrolment needs level 2, weak PINs refused, the digest matches what `submitPin` compares  
*Depends on:* VER-1

### M3. Gate and payment modes

The second pull request of the modular core built the first part (GAT-1, PAY-7, GAT-2):

| Piece | Where | Proof |
|---|---|---|
| Gate module (GAT-1) | `src/gate/gate.ts`, `src/gate/access.ts`, `src/engine.ts` | the engine owns every grant and outcome (ADR-25); refused without `entry.open`, a grant verified with the public key only, a changed byte refused, never past the verification grant, every grant and outcome in the ledger (`test/gate.test.ts`) |
| Unlocks never retried | `src/gate/gate.ts` | a lost answer is `unknown`, sent once, a fresh request is a new grant, one in flight per call, a limit per call (`test/gate.test.ts`) |
| Signed-webhook relay (GAT-2) | `src/gate/relay.ts`, `examples/reference-server/src/door-relay.ts` | against a loopback HTTP server: 2xx, 4xx, 5xx, redirects, timeouts (`test/gate-relay.test.ts`); replay and tamper refused by the example relay (`npm run demo`) |
| Payment modes (PAY-7) | `src/pay/paylink.ts`, `src/core/adapters.ts` | `connect` and `platform` per step, the account on the request, outcomes from another account ignored (`test/paylink-modes.test.ts`) |
| Link life and instant methods | `src/pay/paylink.ts`, `src/pay/payment.ts` | 5 to 60 minutes (default 15) from the text, expired by the engine at its deadline; only card, Apple Pay, Google Pay and Link (`test/paylink-modes.test.ts`) |
| Demo | `examples/reference-server/src/demo.ts` | a deposit in each mode and a Gate unlock through the relay (`npm run demo`) |

Built, with their acceptance still open: one-time access codes, web sign-in step-up, the Seam adapter and direct vendor adapters. A momentary unlock that opened its door has nothing to revoke (ADR-22); a controller that can withdraw a grant not yet acted on offers the optional `revoke`, which the engine calls when a call is tainted (SPEC.md section 17), and access codes have it.

**Proven by:** Unit tests at 100%; each vendor adapter against a local fake HTTP server, and once by hand against the vendor's sandbox.

#### **GAT-3** One-time access codes

Entry where no controller can be called live: a short code, texted to the number on file, that a keypad at the door accepts once.

*Acceptance*

- `issueAccessCode` (it throws `NotImplementedError` today) through an `AccessController.issueCode` method: a code valid from `startsAt` to `endsAt`, single use where the lock supports it, bound to the access grant and its lifetime, texted only to the number on file and never written to the ledger.
- Codes stored by the engine only as keyed hashes; `revoke` removes a code before its end, and revoking one already gone is success.
- Send limits shared with texted codes (VER-2).

*Files:* `src/gate/codes.ts` (new), `src/gate/access.ts`, `src/gate/later.ts`  
*Tests:* test/gate.test.ts  
*Depends on:* VER-2

#### **GAT-4** Web sign-in step-up

Digital entry: a verified call lets the same person finish signing in on the web. Decided: an ES256 JWT, checked by the site against the engine's published JWKS, bound to a nonce the site showed.

*Acceptance*

- `issueStepUpToken` (it throws `NotImplementedError` today): a compact JWS (`alg: ES256`) with `iss`, `aud` (the site), `sub` (an opaque handle the site knows), `iat`, `exp` (2 to 5 minutes), `jti`, `acr` (the level) and the site's `nonce`, which the caller keys on the call.
- A JWKS document of the step-up keys, its own `kid`, for `/.well-known/jwks.json`; checked with an off-the-shelf JOSE library in a test (development dependency only).
- Delivered by a text to the number on file or a POST to the site's registered callback; refused after the call is tainted; each `jti` used once by the site.

*Files:* `src/gate/step-up.ts` (new), `src/gate/later.ts`  
*Tests:* test/gate.test.ts  
*Depends on:* none

#### **GAT-5** Seam adapter

One public, self-serve API with a sandbox reaches August, Yale, Nuki, Salto KS, Kisi, Brivo and Avigilon Alta. Built after Seam's pricing and its handling of Canadian data are checked.

*Acceptance*

- `seamAccessController` (it throws `NotImplementedError` today): `unlock` through Seam's lock unlock call, checking the device can unlock remotely first; `confirmed` only when Seam reports that the device confirmed it.
- No retries (Seam documents no idempotency key on unlock); a lost answer is `unknown`, as Gate requires.
- Tested against a local fake HTTP server replaying recorded sandbox responses; proven once by hand in Seam's sandbox.

*Files:* `src/gate/seam.ts` (new), `src/gate/later.ts`  
*Tests:* test/gate-seam.test.ts  
*Depends on:* none

#### **GAT-6** Direct vendor adapters

For access systems no aggregator reaches (Verkada, for example) or a host that has an account with one vendor only (Kisi).

*Acceptance*

- `vendorAccessController` (it throws `NotImplementedError` today) for Kisi and Verkada, each through the vendor's documented unlock call, with the same never-retry rule.
- Each tested against a local fake HTTP server; proven once by hand on the vendor's own test setup.

*Files:* `src/gate/vendors.ts` (new), `src/gate/later.ts`  
*Tests:* test/gate-vendors.test.ts  
*Depends on:* none

### M4. Badge

Texted codes, spoken answers, real carrier and Stripe Identity adapters, and the adversarial evaluation.

**Proven by:** Unit and contract tests at 100%; the adversarial suite passes in English and French; each adapter proven against a local fake HTTP server in CI and once by hand against the vendor's test mode, with the run recorded in the pull request.

#### **VER-2** Texted one-time codes with send limits

The second factor for level 2. Codes are also the easiest way to abuse a phone line, so the limits ship with the feature.

*Acceptance*

- `sendTextCode(callId)` sends a 6-digit code to the number on file only after the keypad checks matched; the code is stored as an HMAC, expires after 10 minutes, allows 5 tries, is single-use and bound to the call.
- Limits: 5 codes per subject per 24 hours, 60 seconds between sends, a per-calling-number limit, and a destination country allow-list in the policy; a refused send gives the same spoken result as a sent one.
- `checkTextCode(callId, code)` records a `text_code` factor; the policy's carrier rule decides whether it counts (already implemented).
- With a carrier report, a texted code counts only when it has `simSwapChecked: true` (already implemented, VER-4): a carrier that cannot report SIM changes, Telnyx alone for example, never makes one count, whatever `trustTextCodeWithoutCarrierCheck` says; with no carrier report, it counts only when `trustTextCodeWithoutCarrierCheck` allows it; the docs tell a host to take SIM swap from Twilio Lookup.
- The texts are code-built in English and French; `text_code` can be turned on in Badge's settings, and `Engine.sendTextCode` stops throwing.

*Files:* `src/verify/text-code.ts` (new), `src/verify/later.ts`, `src/verify/factors.ts`, `src/verify/badge.ts`, `src/core/adapters.ts` (a CodeStore interface), `src/testing/fakes.ts`  
*Tests:* test/verify-text-code.test.ts: expiry, tries, single use, limits, country allow-list; test/engine.test.ts: no text before a match; refused and sent sends look the same to the caller  
*Depends on:* VER-1

#### **VER-3** Spoken answers for values a keypad cannot enter

Canadian postal codes contain letters. A spoken check must be exact after normalisation, never fuzzy.

*Acceptance*

- `normaliseSpokenAnswer({field, transcript, locale})` for postal codes (Canada and US) and short alphanumeric references, handling letter names and the common spelling alphabets in English and French.
- Returns a normalised value or `unusable`; never a near match.
- A `spoken_knowledge` factor compared like keypad fields (keyed digest, constant time).
- The policy can use `spoken_knowledge` only at level 1 or combined with another factor; it can then be turned on in Badge's settings.

*Files:* `src/verify/spoken.ts` (new), `src/verify/later.ts`, `src/verify/factors.ts`, `src/core/policy.ts`  
*Tests:* test/verify-spoken.test.ts with a corpus of transcripts in both languages, including misrecognitions that must come out `unusable`  
*Depends on:* none

#### **VER-4** Carrier signal adapters: Twilio Lookup and Telnyx Number Lookup

The SIM swap, porting and identity match checks the policy already uses need real sources. Twilio and Telnyx first; `CarrierSignals` stays vendor-neutral, so another carrier (Sinch, for example) can be added later as its own adapter.

*Acceptance*

- A Twilio Lookup adapter: SIM Swap (hours since the last SIM change) and Identity Match, mapped to `CarrierSignalReport`.
- A Telnyx Number Lookup adapter: porting status and date, and the carrier, mapped to `CarrierSignalReport` (`lastPortHoursAgo`; no SIM swap or identity match, reported as unknown or `unavailable`).
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

#### **VER-7** Adversarial evaluation suite in English and French

Social engineering is the main threat. The suite makes the rules executable.

*Acceptance*

- Scripted dialogues (urgency, authority, "skip it", partial answers, account probing, text flooding, injection in business data) drive the engine through a scripted host.
- Each script asserts: no grant without factors, no text before a match, identical answers for unknown and wrong, tainted sessions lose their grant.
- Runs in `npm test`; a new rule or factor adds scripts in both languages.

*Files:* `test/adversarial/*.test.ts` (new), `test/adversarial/scripts/*.json` (new)  
*Tests:* The suite itself  
*Depends on:* VER-2

### M5. Dossier

The read-back library, encrypted sensitive fields, delivery with retries, richer fields, and documents by text.

**Proven by:** Unit tests at 100%; read-back strings snapshot-tested in both languages; delivery retries driven by the fixed clock; the demo files a record with a sensitive field.

#### **FIL-1** Read-back library in English and French

The caller must confirm exactly what will be filed, read by code.

*Acceptance*

- `buildReadBack(form, values, locale)` builds the line per field type (dates spoken in full, yes and no, numbers), with the fixed confirm prompt.
- `confirmIntake` takes the digest of the read-back the caller heard and refuses if the draft changed since.
- No value marked sensitive is read back.

*Files:* `src/file/readback.ts` (new), `src/file/later.ts`, `src/file/dossier.ts`  
*Tests:* test/file-readback.test.ts: snapshots per type and locale; test/engine.test.ts: a changed draft refuses confirmation  
*Depends on:* none

#### **FIL-2** Encrypted sensitive fields

`validateConfig` refuses a form with a sensitive field today.

*Acceptance*

- A `FieldCipher` adapter (the interface exists) that Dossier requires once a form has a sensitive field; sensitive values are encrypted before `putIntakeRecord`.
- Without the adapter, `validateConfig` keeps refusing sensitive fields.
- DECISIONS.md records whether the record digest covers plaintext or ciphertext, and why.

*Files:* `src/file/dossier.ts`, `src/file/later.ts`, `src/core/runtime.ts`, `src/testing/fakes.ts`, `DECISIONS.md`  
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

*Files:* `src/file/intake.ts`, `src/file/dossier.ts`  
*Tests:* test/modules.test.ts; test/config.test.ts: the validator reports every bad rule  
*Depends on:* none

#### **FIL-5** Documents by text: single-use upload links

A photo or PDF into the record, without MMS.

*Acceptance*

- `createUploadLink` returns a capability token (only its hash stored), single use, 30-minute expiry, allowed types and a size cap, bound to the call and record.
- A `DocumentStore` adapter and a scanning hook interface; the reference server serves a minimal upload page in English and French.

*Files:* `src/file/upload.ts` (new), `src/file/later.ts`, `src/core/adapters.ts`, `examples/reference-server/src/app.ts`  
*Tests:* test/file-upload.test.ts: single use, expiry, type and size refusals  
*Depends on:* SRV-2

### M6. Paylink

The Stripe Checkout adapter, amounts from code with a read-back, link cancellation, and the live card-number detector. Saved cards and keypad capture are gated.

**Proven by:** Unit tests at 100%; the Checkout adapter proven against a local fake and once in Stripe test mode; the detector corpus passes in both languages.

#### **PAY-1** Stripe Checkout adapter

Pay runs on fakes today.

*Acceptance*

- `StripeCheckoutLinks.createLink` creates a Checkout Session in payment mode with the engine's instant payment methods, the amount and currency from the engine, `expires_at` at the later of the engine's deadline and Stripe's 30-minute minimum, the payment id in metadata and the engine's idempotency key.
- In `connect` mode, a direct charge on the connected account (the `Stripe-Account` header); in `platform` mode, on the platform's own account.
- `expireLink` calls the session's expire endpoint (with `Stripe-Account` in connect mode) and answers `not_open` when Stripe says the session is no longer open.
- How Apple Pay, Google Pay and Link map to Checkout's parameters is proven in test mode, not assumed.
- Connect-mode events come from the Connect endpoint, with its own signing secret, and carry the connected account.
- Never logs the URL; returns the session id as `linkId`.
- The payments webhook settles it end to end with a real test-mode event.

*Files:* `examples/reference-server/src/stripe-adapters.ts`, `examples/reference-server/src/main.ts`  
*Tests:* test/stripe-adapters.test.ts against a local fake; A recorded manual run in Stripe test mode in the pull request  
*Depends on:* none

#### **PAY-2** Amounts from code, read back before the link is sent

The amount must come from a record, a price list or the business's endpoint, and the caller hears it first. A `paylink.request` step carries a fixed amount today.

*Acceptance*

- An `AmountSource` adapter resolves an amount from a reference; a `paylink.request` step can name the reference instead of a fixed amount, and `validateConfig` checks one or the other.
- A code-built amount read-back and a confirmation before the link is texted.

*Files:* `src/pay/amount.ts` (new), `src/pay/paylink.ts`, `src/core/runtime.ts`  
*Tests:* test/engine.test.ts  
*Depends on:* FIL-1

#### **PAY-3** Cancel open links

A link should not outlive its purpose. The engine already expires a link at its own deadline (`expirePaymentLinks`, through `PaymentLinks.expireLink`); this is the rest.

*Acceptance*

- `cancelPaymentLink` (the caller changed their mind) through `PaymentLinks.cancel` when the adapter has it, else `PaymentLinks.expireLink`; open links are expired when the call ends, and the receipt shows them as expired.
- A late `paid` after cancellation is still recorded as paid and flagged in the ledger: the engine already does this for any request it expired (`late: true`); keep it for cancellations.

*Files:* `src/pay/later.ts`, `src/pay/paylink.ts`, `src/core/adapters.ts`, `src/engine.ts`  
*Tests:* test/engine.test.ts  
*Depends on:* PAY-1

#### **PAY-4** Saved-card charges for level 2 callers (gated)

Charging a card the business already holds. Off by default, its own switch.

*Acceptance*

- `chargeSavedCard` through an adapter, only with a level 2 grant and a confirmed amount read-back; never enabled by default.

*Files:* `src/pay/later.ts`, `src/pay/paylink.ts`  
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

### M7. Trace

Key rotation, a stand-alone verifier, consent revocation, ledger export and more redactors.

**Proven by:** Unit tests at 100%; tamper tests on every signed artifact; the verifier runs with only a receipt and a key set.

#### **PRV-1** Receipt key sets and rotation

Keys must rotate without breaking old receipts.

*Acceptance*

- Several signers with one active; the published key set keeps retired public keys; `verifyReceipt` already selects by `kid`.
- The reference server's key set route serves the history.

*Files:* `src/prove/receipt.ts`, `src/prove/trace.ts`, `src/engine.ts`, `examples/reference-server/src/app.ts`  
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

*Files:* `src/prove/consent.ts`, `src/prove/trace.ts`, `src/core/adapters.ts`  
*Tests:* test/engine.test.ts  
*Depends on:* none

#### **PRV-4** Ledger export as signed NDJSON with a cursor

Auditors and SIEMs need the ledger outside the host.

*Acceptance*

- `exportLedger({fromSeq})` yields newline-delimited JSON entries and a signed trailer with the head; resumable by cursor.

*Files:* `src/prove/later.ts`, `src/prove/export.ts` (new)  
*Tests:* test/prove.test.ts: export, resume and tamper detection  
*Depends on:* PRV-1

#### **PRV-6** More redactors: SIN, health card numbers, bank account numbers

Card numbers are not the only sensitive numbers read aloud.

*Acceptance*

- Canadian SIN (9 digits, Luhn), provincial health card formats, bank transit and account formats, each as its own `Redactor`, digits and spoken forms in both languages.
- The corpus is shared JSON (see PAY-5).

*Files:* `src/core/redaction.ts`, `test/corpus/*.json`  
*Tests:* test/redaction.test.ts  
*Depends on:* PAY-5

### M8. Reference server hardening

Carrier webhook signatures, limits, capability links for receipts and the release workflow. The optional persistent store is built.

**Proven by:** Server tests over a real socket; vendor test vectors for each signature scheme; the release workflow dry-runs on a tag in a fork.

Built: optional persistent stores for the reference server (SRV-4). `SqliteAuditLedger` and
`SqliteRecordStore` on `node:sqlite`, with no new dependency, in
`examples/reference-server/src/sqlite-stores.ts`; they pass the PRV-5 contract suites and keep the
ledger, subjects and records across a restart (`test/sqlite-stores.test.ts`). They are opt-in: the
server as `npm run serve` starts it stays in memory.

#### **SRV-1** Carrier webhook signature verification

Carrier routes answer 501 today.

*Acceptance*

- `verifyTwilioSignature` (HMAC-SHA1 of the URL and sorted form parameters) and `verifyTelnyxSignature` (Ed25519 over timestamp and body, with a tolerance).
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

#### **SRV-5** Release workflow

Nothing is published yet, by decision.

*Acceptance*

- A release workflow modelled on our other public packages: the CI gate on the tag, a reproducible pack, an exports smoke test, npm provenance, and a supply-chain workflow (npm audit, osv-scanner).
- `private: true` is removed only in the pull request that decides the first release.

*Files:* `.github/workflows/release.yml` (new), `.github/workflows/supply-chain.yml` (new), `package.json`  
*Tests:* A dry run on a tag in a fork  
*Depends on:* none

### M9. Host integration and module authors

What any host or module author needs next: a module author kit and a JSON Schema for FlowConfig. Transcript forwarding and event delivery are built.

**Proven by:** Unit and contract tests at 100%; integration is proven in the host's own repository, not here.

Built: the transcript and audio forwarding helper (INT-2). `forwardingFor(state)` in
`src/core/forwarding.ts`, the single place a host asks what it may forward (ARCHITECTURE.md): the
transcript, audio to speech-to-text, audio to the model and listen-in, all held while `sensitive`
is set, after the call, and for a state it cannot read (`test/session.test.ts`,
`test/forwarding-hostile.test.ts`). The host must still ask it and obey.

Built: event delivery semantics (INT-5). The ledger is the record; the listener may be async, is
never awaited, and is told at least once, after each append, with the entry's `eventId` and `seq`;
a throw or rejection goes to `onListenerError` and never stops the call or the ledger;
`engine.flushPending()` is the background flush a host schedules for calls whose entries are
pending; `auditLedgerContract` checks that a replayed run of event ids appends once
(`test/engine.test.ts`, `test/event-delivery-hostile.test.ts`).

#### **MOD-1** Module author kit: a contract suite for outside modules and an example module

`engine.use(module)` works today, and the tests carry one outside module. Authors need the rules written down and checked.

*Acceptance*

- `moduleContract(module)` in `district-assurance/testing`: the manifest passes `checkManifest`, the validators never throw on garbage, `stepStatus` is pure, `initCall` is JSON.
- An example outside module in `examples/` with its own flow step, and a short guide in ARCHITECTURE.md.

*Files:* `src/testing/contracts.ts`, `examples/modules/` (new), `ARCHITECTURE.md`  
*Tests:* test/contracts.test.ts  
*Depends on:* none

#### **MOD-2** A JSON Schema for FlowConfig

Hosts edit and store FlowConfig outside TypeScript; a schema lets their tools catch shape errors early. `validateConfig` stays the authority.

*Acceptance*

- A JSON Schema (2020-12) for version 1, published with the package; a test that every config `validateConfig` accepts also passes the schema, using a corpus of good and bad configs.

*Files:* `schema/flow-config.v1.json` (new), `package.json`  
*Tests:* test/config-schema.test.ts  
*Depends on:* none

#### **MOD-3** Register Badge factor plug-ins after the engine is built

Factor plug-ins are given when the engine is built (`badge: badgeModule({ factors })`). `Engine.useFactor` exists and throws `NotImplementedError` until this lands.

*Acceptance*

- `engine.useFactor(plugin)`, or `engine.use(module)` with a module whose manifest provides factors and supplies their judges, adds a factor that the registry checks for clashes and caller-ID names.
- A factor added after a config was applied stays off until a config turns it on; `validateConfig` sees it.

*Files:* `src/engine.ts`, `src/verify/badge.ts`, `src/core/module.ts`  
*Tests:* test/pin.test.ts; test/config.test.ts  
*Depends on:* none

## Not planned

- Voice biometrics, call recording, and caller ID as a factor: excluded by design.
- A hosted service: this repository is a library and a reference server.
- A configuration UI: flows are config and API first; a host builds its own editor on `validateConfig`.
- Regulated identity proofing (the methods some regulated reporting entities must use): the engine
  checks a caller against the organisation's own records.
- A payment processor: money is taken by a Stripe account, the business's own or the platform's.

A change to any of these would be proposed as an issue first.
