# Issues

Every open issue of [ROADMAP.md](ROADMAP.md), 41 of them, ready to paste into GitHub: the heading is the title, the fenced block is the body. They are in milestone order, owner-command first; open them in that order. ROADMAP.md has the waves and the dependencies, and `test/stubs.test.ts` fails if an id here is missing there.

### VER-1: Durable failure counters and lockout per subject and per calling number (hard gate before owner-command goes live)

**Labels:** `badge`, `m2`  
**Milestone:** M2 Owner command  
**Depends on:** none

```markdown
## Why

Attempt limits are per call today, for keypad knowledge, the PIN and plug-in factors alike; a caller can call again, and a 4-digit PIN with 3 attempts per call falls within about 3,300 calls. **Hard gate:** no host runs the owner-command flow, or any PIN factor, on a live line before this is merged.

## Acceptance criteria

- [ ] An `AttemptCounters` adapter interface in `src/core/adapters.ts`: `get`, `recordFailure`, `reset`, keyed by workspace, factor kind and either subject key or a hash of the calling number.
- [ ] `submitFactor` (and so `submitKeypad` and `submitPin`) consults the counters before counting the attempt, and refuses to judge while locked (the same `locked: true` answer).
- [ ] Backoff after failures (5, 15, 60, 300, 900 seconds) and a hard lock after 10 failures in 24 hours, in Badge's settings with these as defaults and floors, checked by `validateConfig`.
- [ ] A `verification.locked` event with the scope of the lock (`subject` or `number`) and the factor kind, never the values.
- [ ] Badge requires the adapter when any entered factor is on; `recordSubjectFailure` in `src/verify/later.ts` is replaced by the real implementation.

## Files

- src/core/adapters.ts
- src/verify/counters.ts (new)
- src/verify/badge.ts
- src/verify/later.ts
- src/testing/fakes.ts
- src/testing/contracts.ts

## Tests

- test/verify-counters.test.ts: backoff and lock with the fixed clock, and a contract suite for the adapter
- test/pin.test.ts: a PIN lock carries across two calls and two engines; unknown subjects are counted by number

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### VER-8: Policy version and config revision in grants and receipts

**Labels:** `badge`, `m2`  
**Milestone:** M2 Owner command  
**Depends on:** none

```markdown
## Why

A receipt should say which policy and which revision of the workspace's FlowConfig judged the caller. `call.started` already carries the revision; the grant and the receipt do not.

## Acceptance criteria

- [ ] Grants and receipts carry `policyVersion` and `configRevision`; the `verification.finished` event too.
- [ ] Receipt format version stays 1 if the fields are optional, otherwise becomes 2 with SPEC.md updated.

## Files

- src/core/session.ts
- src/verify/badge.ts
- src/prove/trace.ts
- src/prove/receipt.ts
- SPEC.md

## Tests

- test/engine.test.ts
- test/prove.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### INT-1: Keypad collector helper

**Labels:** `integration`, `m2`  
**Milestone:** M2 Owner command  
**Depends on:** none

```markdown
## Why

Every host needs the same digit buffer; getting it wrong leaks digits.

## Acceptance criteria

- [ ] A pure `KeypadCollector` that buffers tones until `#`, with a maximum length and an idle timeout, exposes no digits through `toString` or JSON, and hands the digits to one callback.

## Files

- src/core/keypad.ts (new)

## Tests

- test/keypad.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### INT-4: Key store contracts for the knowledge key and the receipt signer

**Labels:** `integration`, `m2`  
**Milestone:** M2 Owner command  
**Depends on:** none

```markdown
## Why

Production keys live in a KMS, not in process memory.

## Acceptance criteria

- [ ] Document and test the contract: `ReceiptSigner.sign` returns a 64-byte P1363 ES256 signature; a helper converts DER signatures (what most KMS APIs return) to P1363.
- [ ] The knowledge key can be an opaque HMAC function instead of bytes, so it never leaves the key store. Factor plug-ins already receive only `hmac`; the engine's own use moves to the same function.

## Files

- src/prove/receipt.ts
- src/verify/knowledge.ts
- src/engine.ts

## Tests

- test/prove.test.ts: DER to P1363 conversion against node:crypto output

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PRV-5: Adapter contract suites in district-assurance/testing

**Labels:** `trace`, `m2`  
**Milestone:** M2 Owner command  
**Depends on:** none

```markdown
## Why

A host's durable stores must keep the same guarantees as the memory ones.

## Acceptance criteria

- [ ] `auditLedgerContract(factory)` and `recordStoreContract(factory)` exported from `district-assurance/testing`, in the style of `sessionStoreContract`: ordering, copies, append-only, chain validity, concurrency of appends.
- [ ] The memory adapters pass them in CI.

## Files

- src/testing/contracts.ts
- src/testing/index.ts

## Tests

- test/contracts.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### VER-6: PIN enrolment and reset

**Labels:** `badge`, `m2`  
**Milestone:** M2 Owner command  
**Depends on:** VER-1

```markdown
## Why

The `pin` factor checks a PIN against a keyed hash on file or the host's own verifier. Nothing yet lets a caller choose one on the line.

## Acceptance criteria

- [ ] `enrolPin` (in `src/verify/later.ts` today) lets a caller who verified to level 2 or above on this call choose a PIN, keyed twice and compared, then stored through a new `RecordStore.putPinDigest` as `pinDigest(knowledgeKey, subjectKey, pin)`.
- [ ] Refuses PINs that are all one digit, a run (1234, 4321) or the subject's keypad knowledge; the length comes from Badge's PIN settings.
- [ ] Reset by the business only (a host call, not a caller one). In `verifier` mode the host's own store enrols, and `enrolPin` refuses.
- [ ] A `pin.enrolled` event, never the digits.

## Files

- src/verify/pin.ts (new)
- src/verify/later.ts
- src/core/adapters.ts
- src/verify/badge.ts
- src/engine.ts

## Tests

- test/pin.test.ts: enrolment needs level 2, weak PINs refused, the digest matches what `submitPin` compares

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### GAT-3: One-time access codes

**Labels:** `gate`, `m3`  
**Milestone:** M3 Gate and payment modes  
**Depends on:** VER-2

```markdown
## Why

Entry where no controller can be called live: a short code, texted to the number on file, that a keypad at the door accepts once.

## Acceptance criteria

- [ ] `issueAccessCode` (it throws `NotImplementedError` today) through an `AccessController.issueCode` method: a code valid from `startsAt` to `endsAt`, single use where the lock supports it, bound to the access grant and its lifetime, texted only to the number on file and never written to the ledger.
- [ ] Codes stored by the engine only as keyed hashes; `revoke` removes a code before its end, and revoking one already gone is success.
- [ ] Send limits shared with texted codes (VER-2).

## Files

- src/gate/codes.ts (new)
- src/gate/access.ts
- src/gate/later.ts

## Tests

- test/gate.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### GAT-4: Web sign-in step-up

**Labels:** `gate`, `m3`  
**Milestone:** M3 Gate and payment modes  
**Depends on:** none

```markdown
## Why

Digital entry: a verified call lets the same person finish signing in on the web. Decided: an ES256 JWT, checked by the site against the engine's published JWKS, bound to a nonce the site showed.

## Acceptance criteria

- [ ] `issueStepUpToken` (it throws `NotImplementedError` today): a compact JWS (`alg: ES256`) with `iss`, `aud` (the site), `sub` (an opaque handle the site knows), `iat`, `exp` (2 to 5 minutes), `jti`, `acr` (the level) and the site's `nonce`, which the caller keys on the call.
- [ ] A JWKS document of the step-up keys, its own `kid`, for `/.well-known/jwks.json`; checked with an off-the-shelf JOSE library in a test (development dependency only).
- [ ] Delivered by a text to the number on file or a POST to the site's registered callback; refused after the call is tainted; each `jti` used once by the site.

## Files

- src/gate/step-up.ts (new)
- src/gate/later.ts

## Tests

- test/gate.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### GAT-5: Seam adapter

**Labels:** `gate`, `m3`  
**Milestone:** M3 Gate and payment modes  
**Depends on:** none

```markdown
## Why

One public, self-serve API with a sandbox reaches August, Yale, Nuki, Salto KS, Kisi, Brivo and Avigilon Alta. Built after Seam's pricing and its handling of Canadian data are checked.

## Acceptance criteria

- [ ] `seamAccessController` (it throws `NotImplementedError` today): `unlock` through Seam's lock unlock call, checking the device can unlock remotely first; `confirmed` only when Seam reports that the device confirmed it.
- [ ] No retries (Seam documents no idempotency key on unlock); a lost answer is `unknown`, as Gate requires.
- [ ] Tested against a local fake HTTP server replaying recorded sandbox responses; proven once by hand in Seam's sandbox.

## Files

- src/gate/seam.ts (new)
- src/gate/later.ts

## Tests

- test/gate-seam.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### GAT-6: Direct vendor adapters

**Labels:** `gate`, `m3`  
**Milestone:** M3 Gate and payment modes  
**Depends on:** none

```markdown
## Why

For access systems no aggregator reaches (Verkada, for example) or a host that has an account with one vendor only (Kisi).

## Acceptance criteria

- [ ] `vendorAccessController` (it throws `NotImplementedError` today) for Kisi and Verkada, each through the vendor's documented unlock call, with the same never-retry rule.
- [ ] Each tested against a local fake HTTP server; proven once by hand on the vendor's own test setup.

## Files

- src/gate/vendors.ts (new)
- src/gate/later.ts

## Tests

- test/gate-vendors.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### VER-2: Texted one-time codes with send limits

**Labels:** `badge`, `m4`  
**Milestone:** M4 Badge  
**Depends on:** VER-1

```markdown
## Why

The second factor for level 2. Codes are also the easiest way to abuse a phone line, so the limits ship with the feature.

## Acceptance criteria

- [ ] `sendTextCode(callId)` sends a 6-digit code to the number on file only after the keypad checks matched; the code is stored as an HMAC, expires after 10 minutes, allows 5 tries, is single-use and bound to the call.
- [ ] Limits: 5 codes per subject per 24 hours, 60 seconds between sends, a per-calling-number limit, and a destination country allow-list in the policy; a refused send gives the same spoken result as a sent one.
- [ ] `checkTextCode(callId, code)` records a `text_code` factor; the policy's carrier rule decides whether it counts (already implemented).
- [ ] The texts are code-built in English and French; `text_code` can be turned on in Badge's settings, and `Engine.sendTextCode` stops throwing.

## Files

- src/verify/text-code.ts (new)
- src/verify/later.ts
- src/verify/factors.ts
- src/verify/badge.ts
- src/core/adapters.ts (a CodeStore interface)
- src/testing/fakes.ts

## Tests

- test/verify-text-code.test.ts: expiry, tries, single use, limits, country allow-list
- test/engine.test.ts: no text before a match
- refused and sent sends look the same to the caller

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### VER-3: Spoken answers for values a keypad cannot enter

**Labels:** `badge`, `m4`  
**Milestone:** M4 Badge  
**Depends on:** none

```markdown
## Why

Canadian postal codes contain letters. A spoken check must be exact after normalisation, never fuzzy.

## Acceptance criteria

- [ ] `normaliseSpokenAnswer({field, transcript, locale})` for postal codes (Canada and US) and short alphanumeric references, handling letter names and the common spelling alphabets in English and French.
- [ ] Returns a normalised value or `unusable`; never a near match.
- [ ] A `spoken_knowledge` factor compared like keypad fields (keyed digest, constant time).
- [ ] The policy can use `spoken_knowledge` only at level 1 or combined with another factor; it can then be turned on in Badge's settings.

## Files

- src/verify/spoken.ts (new)
- src/verify/later.ts
- src/verify/factors.ts
- src/core/policy.ts

## Tests

- test/verify-spoken.test.ts with a corpus of transcripts in both languages, including misrecognitions that must come out `unusable`

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### VER-4: Carrier signal adapters: Twilio Lookup and Telnyx Number Lookup

**Labels:** `badge`, `m4`  
**Milestone:** M4 Badge  
**Depends on:** none

```markdown
## Why

The SIM swap, porting and identity match checks the policy already uses need real sources. Twilio and Telnyx first; `CarrierSignals` stays vendor-neutral, so another carrier (Sinch, for example) can be added later as its own adapter.

## Acceptance criteria

- [ ] A Twilio Lookup adapter: SIM Swap (hours since the last SIM change) and Identity Match, mapped to `CarrierSignalReport`.
- [ ] A Telnyx Number Lookup adapter: porting status and date, and the carrier, mapped to `CarrierSignalReport` (`lastPortHoursAgo`; no SIM swap or identity match, reported as unknown or `unavailable`).
- [ ] Timeouts, errors, unsupported countries and unapproved features all return `checked: false` (fail closed); nothing throws into the call.
- [ ] Credentials from the environment only; no keys in code or tests.
- [ ] A table in the reference server README of which signal each vendor provides, and where approval is needed.

## Files

- examples/reference-server/src/carrier-adapters.ts (new)
- examples/reference-server/README.md

## Tests

- test/carrier-adapters.test.ts against a local fake HTTP server replaying fixture responses

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### VER-5: Stripe Identity adapter

**Labels:** `badge`, `m4`  
**Milestone:** M4 Badge  
**Depends on:** none

```markdown
## Why

The photo ID tier runs on fakes today.

## Acceptance criteria

- [ ] `StripeIdentityProvider.createDocumentCheck` creates a VerificationSession (`type: document`, matching selfie required) with the call id in metadata and the engine's idempotency key, using `fetch` and a restricted key.
- [ ] Returns the session id and the single-use URL; never logs the URL.
- [ ] The reference server's identity webhook applies the outcome end to end with a real test-mode event.
- [ ] README steps for trying it with your own Stripe test account.

## Files

- examples/reference-server/src/stripe-adapters.ts
- examples/reference-server/src/main.ts
- README.md

## Tests

- test/stripe-adapters.test.ts: request shape, headers and idempotency against a local fake
- A recorded manual run in Stripe test mode in the pull request

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### VER-7: Adversarial evaluation suite in English and French

**Labels:** `badge`, `m4`  
**Milestone:** M4 Badge  
**Depends on:** VER-2

```markdown
## Why

Social engineering is the main threat. The suite makes the rules executable.

## Acceptance criteria

- [ ] Scripted dialogues (urgency, authority, "skip it", partial answers, account probing, text flooding, injection in business data) drive the engine through a scripted host.
- [ ] Each script asserts: no grant without factors, no text before a match, identical answers for unknown and wrong, tainted sessions lose their grant.
- [ ] Runs in `npm test`; a new rule or factor adds scripts in both languages.

## Files

- test/adversarial/*.test.ts (new)
- test/adversarial/scripts/*.json (new)

## Tests

- The suite itself

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### FIL-1: Read-back library in English and French

**Labels:** `dossier`, `m5`  
**Milestone:** M5 Dossier  
**Depends on:** none

```markdown
## Why

The caller must confirm exactly what will be filed, read by code.

## Acceptance criteria

- [ ] `buildReadBack(form, values, locale)` builds the line per field type (dates spoken in full, yes and no, numbers), with the fixed confirm prompt.
- [ ] `confirmIntake` takes the digest of the read-back the caller heard and refuses if the draft changed since.
- [ ] No value marked sensitive is read back.

## Files

- src/file/readback.ts (new)
- src/file/later.ts
- src/file/dossier.ts

## Tests

- test/file-readback.test.ts: snapshots per type and locale
- test/engine.test.ts: a changed draft refuses confirmation

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### FIL-2: Encrypted sensitive fields

**Labels:** `dossier`, `m5`  
**Milestone:** M5 Dossier  
**Depends on:** none

```markdown
## Why

`validateConfig` refuses a form with a sensitive field today.

## Acceptance criteria

- [ ] A `FieldCipher` adapter (the interface exists) that Dossier requires once a form has a sensitive field; sensitive values are encrypted before `putIntakeRecord`.
- [ ] Without the adapter, `validateConfig` keeps refusing sensitive fields.
- [ ] DECISIONS.md records whether the record digest covers plaintext or ciphertext, and why.

## Files

- src/file/dossier.ts
- src/file/later.ts
- src/core/runtime.ts
- src/testing/fakes.ts
- DECISIONS.md

## Tests

- test/engine.test.ts with a fake cipher: stored values are ciphertext, the digest is stable

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### FIL-3: Record delivery with signed webhooks, retries and idempotency

**Labels:** `dossier`, `m5`  
**Milestone:** M5 Dossier  
**Depends on:** FIL-1

```markdown
## Why

Confirmed records must reach the business's system reliably.

## Acceptance criteria

- [ ] `deliverRecord` through a `RecordDelivery` adapter; outbound webhooks signed with the same `t=,v1=` HMAC scheme the engine verifies for Stripe.
- [ ] Retries with backoff and an idempotency key per record and destination; delivery attempts are ledger events without the payload.
- [ ] A sample receiver in the reference server that verifies the signature.

## Files

- src/file/delivery.ts (new)
- src/file/later.ts
- src/core/adapters.ts
- examples/reference-server/src/app.ts

## Tests

- test/file-delivery.test.ts with the fixed clock

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### FIL-4: Conditional fields and validation rules

**Labels:** `dossier`, `m5`  
**Milestone:** M5 Dossier  
**Depends on:** none

```markdown
## Why

Real intake forms branch and validate.

## Acceptance criteria

- [ ] `showIf` on a field (another field's value), min and max for numbers and dates, a pattern for text.
- [ ] Form validation refuses a field whose label or key names a Social Insurance Number or a card, and refuses `showIf` cycles.

## Files

- src/file/intake.ts
- src/file/dossier.ts

## Tests

- test/modules.test.ts
- test/config.test.ts: the validator reports every bad rule

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### FIL-5: Documents by text: single-use upload links

**Labels:** `dossier`, `m5`  
**Milestone:** M5 Dossier  
**Depends on:** SRV-2

```markdown
## Why

A photo or PDF into the record, without MMS.

## Acceptance criteria

- [ ] `createUploadLink` returns a capability token (only its hash stored), single use, 30-minute expiry, allowed types and a size cap, bound to the call and record.
- [ ] A `DocumentStore` adapter and a scanning hook interface; the reference server serves a minimal upload page in English and French.

## Files

- src/file/upload.ts (new)
- src/file/later.ts
- src/core/adapters.ts
- examples/reference-server/src/app.ts

## Tests

- test/file-upload.test.ts: single use, expiry, type and size refusals

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-1: Stripe Checkout adapter

**Labels:** `paylink`, `m6`  
**Milestone:** M6 Paylink  
**Depends on:** none

```markdown
## Why

Pay runs on fakes today.

## Acceptance criteria

- [ ] `StripeCheckoutLinks.createLink` creates a Checkout Session in payment mode with the engine's instant payment methods, the amount and currency from the engine, `expires_at` at the later of the engine's deadline and Stripe's 30-minute minimum, the payment id in metadata and the engine's idempotency key.
- [ ] In `connect` mode, a direct charge on the connected account (the `Stripe-Account` header); in `platform` mode, on the platform's own account.
- [ ] `expireLink` calls the session's expire endpoint (with `Stripe-Account` in connect mode) and answers `not_open` when Stripe says the session is no longer open.
- [ ] How Apple Pay, Google Pay and Link map to Checkout's parameters is proven in test mode, not assumed.
- [ ] Connect-mode events come from the Connect endpoint, with its own signing secret, and carry the connected account.
- [ ] Never logs the URL; returns the session id as `linkId`.
- [ ] The payments webhook settles it end to end with a real test-mode event.

## Files

- examples/reference-server/src/stripe-adapters.ts
- examples/reference-server/src/main.ts

## Tests

- test/stripe-adapters.test.ts against a local fake
- A recorded manual run in Stripe test mode in the pull request

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-2: Amounts from code, read back before the link is sent

**Labels:** `paylink`, `m6`  
**Milestone:** M6 Paylink  
**Depends on:** FIL-1

```markdown
## Why

The amount must come from a record, a price list or the business's endpoint, and the caller hears it first. A `paylink.request` step carries a fixed amount today.

## Acceptance criteria

- [ ] An `AmountSource` adapter resolves an amount from a reference; a `paylink.request` step can name the reference instead of a fixed amount, and `validateConfig` checks one or the other.
- [ ] A code-built amount read-back and a confirmation before the link is texted.

## Files

- src/pay/amount.ts (new)
- src/pay/paylink.ts
- src/core/runtime.ts

## Tests

- test/engine.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-3: Cancel open links

**Labels:** `paylink`, `m6`  
**Milestone:** M6 Paylink  
**Depends on:** PAY-1

```markdown
## Why

A link should not outlive its purpose. The engine already expires a link at its own deadline (`expirePaymentLinks`, through `PaymentLinks.expireLink`); this is the rest.

## Acceptance criteria

- [ ] `cancelPaymentLink` (the caller changed their mind) through `PaymentLinks.expireLink`; open links are expired when the call ends, and the receipt shows them as expired.
- [ ] A late `paid` after cancellation is still recorded as paid (the money moved) and flagged in the ledger.

## Files

- src/pay/later.ts
- src/pay/paylink.ts
- src/engine.ts

## Tests

- test/engine.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-4: Saved-card charges for level 2 callers (gated)

**Labels:** `paylink`, `m6`  
**Milestone:** M6 Paylink  
**Depends on:** PAY-2

```markdown
## Why

Charging a card the business already holds. Off by default, its own switch.

## Acceptance criteria

- [ ] `chargeSavedCard` through an adapter, only with a level 2 grant and a confirmed amount read-back; never enabled by default.

## Files

- src/pay/later.ts
- src/pay/paylink.ts

## Tests

- test/engine.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-5: Live card-number detector for partial and spoken numbers

**Labels:** `paylink`, `m6`  
**Milestone:** M6 Paylink  
**Depends on:** none

```markdown
## Why

Redaction catches whole numbers; the interrupt should fire while the caller is still reading.

## Acceptance criteria

- [ ] A streaming detector fed transcript chunks that signals an interrupt on a run of 8 or more digits, including number words ("forty two", "quarante-deux") and "double" forms.
- [ ] Redaction also handles number words; a shared JSON corpus is the test source so another language's implementation can use it.

## Files

- src/core/redaction.ts
- src/core/live-detector.ts (new)
- test/corpus/card-numbers.json (new)

## Tests

- test/redaction.test.ts over the corpus

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-6: Keypad card capture through a certified carrier service (gated)

**Labels:** `paylink`, `m6`  
**Milestone:** M6 Paylink  
**Depends on:** PAY-1

```markdown
## Why

Some buyers will need it; it must never route tones through this engine.

## Acceptance criteria

- [ ] Starts only after an assessor's scoping. The engine calls a `CarrierPayments` adapter to start and end capture and receives only a token and a result.
- [ ] An architecture note in SECURITY-MODEL.md shows that no tone reaches the engine during capture.

## Files

- src/pay/later.ts
- src/core/adapters.ts
- SECURITY-MODEL.md

## Tests

- test/engine.test.ts: the engine never receives digits

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PRV-1: Receipt key sets and rotation

**Labels:** `trace`, `m7`  
**Milestone:** M7 Trace  
**Depends on:** none

```markdown
## Why

Keys must rotate without breaking old receipts.

## Acceptance criteria

- [ ] Several signers with one active; the published key set keeps retired public keys; `verifyReceipt` already selects by `kid`.
- [ ] The reference server's key set route serves the history.

## Files

- src/prove/receipt.ts
- src/prove/trace.ts
- src/engine.ts
- examples/reference-server/src/app.ts

## Tests

- test/prove.test.ts: a receipt signed before rotation still verifies

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PRV-2: Stand-alone receipt verifier

**Labels:** `trace`, `m7`  
**Milestone:** M7 Trace  
**Depends on:** PRV-1

```markdown
## Why

Anyone holding a receipt should check it without this package.

## Acceptance criteria

- [ ] A zero-dependency script (`scripts/verify-receipt.mjs`) that takes a receipt and a key set (file or URL) and prints valid or invalid.
- [ ] Documented in SPEC.md with a worked example.

## Files

- scripts/verify-receipt.mjs (new)
- SPEC.md

## Tests

- test/verifier.test.ts runs the script on a valid and a tampered receipt

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PRV-3: Consent revocation

**Labels:** `trace`, `m7`  
**Milestone:** M7 Trace  
**Depends on:** none

```markdown
## Why

Consent must be revocable by voice, text or dashboard.

## Acceptance criteria

- [ ] `revokeConsent` through a `ConsentStore` adapter; revocation is a ledger event; STOP and its French forms map to revocation.

## Files

- src/prove/consent.ts
- src/prove/trace.ts
- src/core/adapters.ts

## Tests

- test/engine.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PRV-4: Ledger export as signed NDJSON with a cursor

**Labels:** `trace`, `m7`  
**Milestone:** M7 Trace  
**Depends on:** PRV-1

```markdown
## Why

Auditors and SIEMs need the ledger outside the host.

## Acceptance criteria

- [ ] `exportLedger({fromSeq})` yields newline-delimited JSON entries and a signed trailer with the head; resumable by cursor.

## Files

- src/prove/later.ts
- src/prove/export.ts (new)

## Tests

- test/prove.test.ts: export, resume and tamper detection

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PRV-6: More redactors: SIN, health card numbers, bank account numbers

**Labels:** `trace`, `m7`  
**Milestone:** M7 Trace  
**Depends on:** PAY-5

```markdown
## Why

Card numbers are not the only sensitive numbers read aloud.

## Acceptance criteria

- [ ] Canadian SIN (9 digits, Luhn), provincial health card formats, bank transit and account formats, each as its own `Redactor`, digits and spoken forms in both languages.
- [ ] The corpus is shared JSON (see PAY-5).

## Files

- src/core/redaction.ts
- test/corpus/*.json

## Tests

- test/redaction.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### SRV-1: Carrier webhook signature verification

**Labels:** `reference-server`, `m8`  
**Milestone:** M8 Reference server hardening  
**Depends on:** none

```markdown
## Why

Carrier routes answer 501 today.

## Acceptance criteria

- [ ] `verifyTwilioSignature` (HMAC-SHA1 of the URL and sorted form parameters) and `verifyTelnyxSignature` (Ed25519 over timestamp and body, with a tolerance).
- [ ] Each tested against the vendor's published examples; the routes stop answering 501 only when the check is real.

## Files

- src/webhooks/carrier.ts
- examples/reference-server/src/app.ts

## Tests

- test/webhooks.test.ts with vendor test vectors

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### SRV-2: Server limits and logging

**Labels:** `reference-server`, `m8`  
**Milestone:** M8 Reference server hardening  
**Depends on:** none

```markdown
## Why

The reference server is not hardened.

## Acceptance criteria

- [ ] Per-route body limits, request timeouts, a per-address rate limit, and structured logs that never include bodies or headers carrying secrets.

## Files

- examples/reference-server/src/app.ts

## Tests

- test/reference-server.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### SRV-3: Receipt links by capability token, and a receipt page

**Labels:** `reference-server`, `m8`  
**Milestone:** M8 Reference server hardening  
**Depends on:** PRV-1

```markdown
## Why

`GET /receipts/:callId` is for the demo only; call ids are not secrets.

## Acceptance criteria

- [ ] Each receipt gets an unguessable link token (only its hash stored); `GET /r/:token` serves a small receipt page in English and French with the verification result; the call id route is removed.

## Files

- examples/reference-server/src/app.ts
- src/prove/receipt.ts

## Tests

- test/reference-server.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### SRV-4: Optional persistent stores for the reference server

**Labels:** `reference-server`, `m8`  
**Milestone:** M8 Reference server hardening  
**Depends on:** PRV-5

```markdown
## Why

The server forgets everything on restart.

## Acceptance criteria

- [ ] SQLite-backed `RecordStore` and `AuditLedger` on `node:sqlite` (no new dependency), passing the PRV-5 contract suites.

## Files

- examples/reference-server/src/sqlite-stores.ts (new)

## Tests

- The PRV-5 contract suites

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### SRV-5: Release workflow

**Labels:** `reference-server`, `m8`  
**Milestone:** M8 Reference server hardening  
**Depends on:** none

```markdown
## Why

Nothing is published yet, by decision.

## Acceptance criteria

- [ ] A release workflow modelled on our other public packages: the CI gate on the tag, a reproducible pack, an exports smoke test, npm provenance, and a supply-chain workflow (npm audit, osv-scanner).
- [ ] `private: true` is removed only in the pull request that decides the first release.

## Files

- .github/workflows/release.yml (new)
- .github/workflows/supply-chain.yml (new)
- package.json

## Tests

- A dry run on a tag in a fork

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### INT-2: Transcript and audio forwarding helper

**Labels:** `integration`, `m9`  
**Milestone:** M9 Host integration and module authors  
**Depends on:** none

```markdown
## Why

Hosts must pause transcripts and cut audio while `sensitive` is set.

## Acceptance criteria

- [ ] `forwardingFor(state)` returns what the host may forward (transcript, audio to speech-to-text, audio to the model, listen-in) for the current session; documented as the single place a host asks.

## Files

- src/core/forwarding.ts (new)
- ARCHITECTURE.md

## Tests

- test/session.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### INT-5: Event delivery semantics

**Labels:** `integration`, `m9`  
**Milestone:** M9 Host integration and module authors  
**Depends on:** none

```markdown
## Why

Ledger entries are saved with each step (an outbox in the call record) and appended idempotently by event id; a failed append is retried by the next write or `flushLedger`. The listener is still synchronous and told at least once, best effort.

## Acceptance criteria

- [ ] An async listener with defined semantics: the ledger is the source of truth; listener failures are reported (an `onListenerError` hook) and never block the call or the ledger.
- [ ] A background flush a host can schedule for calls whose outbox is not empty, and an `auditLedgerContract` case (PRV-5) for idempotent appends.

## Files

- src/engine.ts
- src/core/events.ts
- src/core/adapters.ts

## Tests

- test/engine.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### MOD-1: Module author kit: a contract suite for outside modules and an example module

**Labels:** `core`, `m9`  
**Milestone:** M9 Host integration and module authors  
**Depends on:** none

```markdown
## Why

`engine.use(module)` works today, and the tests carry one outside module. Authors need the rules written down and checked.

## Acceptance criteria

- [ ] `moduleContract(module)` in `district-assurance/testing`: the manifest passes `checkManifest`, the validators never throw on garbage, `stepStatus` is pure, `initCall` is JSON.
- [ ] An example outside module in `examples/` with its own flow step, and a short guide in ARCHITECTURE.md.

## Files

- src/testing/contracts.ts
- examples/modules/ (new)
- ARCHITECTURE.md

## Tests

- test/contracts.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### MOD-2: A JSON Schema for FlowConfig

**Labels:** `core`, `m9`  
**Milestone:** M9 Host integration and module authors  
**Depends on:** none

```markdown
## Why

Hosts edit and store FlowConfig outside TypeScript; a schema lets their tools catch shape errors early. `validateConfig` stays the authority.

## Acceptance criteria

- [ ] A JSON Schema (2020-12) for version 1, published with the package; a test that every config `validateConfig` accepts also passes the schema, using a corpus of good and bad configs.

## Files

- schema/flow-config.v1.json (new)
- package.json

## Tests

- test/config-schema.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### MOD-3: Register Badge factor plug-ins after the engine is built

**Labels:** `core`, `m9`  
**Milestone:** M9 Host integration and module authors  
**Depends on:** none

```markdown
## Why

Factor plug-ins are given when the engine is built (`badge: badgeModule({ factors })`). `Engine.useFactor` exists and throws `NotImplementedError` until this lands.

## Acceptance criteria

- [ ] `engine.useFactor(plugin)`, or `engine.use(module)` with a module whose manifest provides factors and supplies their judges, adds a factor that the registry checks for clashes and caller-ID names.
- [ ] A factor added after a config was applied stays off until a config turns it on; `validateConfig` sees it.

## Files

- src/engine.ts
- src/verify/badge.ts
- src/core/module.ts

## Tests

- test/pin.test.ts
- test/config.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```
