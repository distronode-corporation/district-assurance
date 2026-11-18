# Issues

The first 26 issues, ready to paste into GitHub: the heading is the title, the fenced block is the body. ROADMAP.md has the full list, the ordering and the dependencies. Open them in the order of ROADMAP.md, "Order of work".

### VER-1: Durable failure counters and lockout per subject and per calling number

**Labels:** `verify`, `m1`  
**Milestone:** M1 Verify  
**Depends on:** none

```markdown
## Why

Today the keypad limit is per call; a caller can call again. Counters must survive across calls.

## Acceptance criteria

- [ ] An `AttemptCounters` adapter interface in `src/core/adapters.ts`: `get`, `recordFailure`, `reset`, keyed by workspace and either subject key or a hash of the calling number.
- [ ] `submitKeypad` consults the counters before judging and refuses to judge while locked (same `locked: true` answer).
- [ ] Backoff after failures (5, 15, 60, 300, 900 seconds) and a hard lock after 10 failures in 24 hours, both configurable in the policy with these as defaults and floors.
- [ ] A `verification.locked` event with the scope of the lock (`subject` or `number`), never the values.
- [ ] `recordSubjectFailure` in `src/verify/later.ts` is replaced by the real implementation.

## Files

- src/core/adapters.ts
- src/core/policy.ts
- src/verify/counters.ts (new)
- src/engine.ts
- src/testing/fakes.ts

## Tests

- test/verify-counters.test.ts: backoff and lock with the fixed clock
- test/engine.test.ts: lock carries across two calls; unknown subjects are counted by number

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### VER-2: Texted one-time codes with send limits

**Labels:** `verify`, `m1`  
**Milestone:** M1 Verify  
**Depends on:** VER-1

```markdown
## Why

The second factor for level 2. Codes are also the easiest way to abuse a phone line, so the limits ship with the feature.

## Acceptance criteria

- [ ] `sendTextCode(callId)` sends a 6-digit code to the number on file only after the keypad checks matched; the code is stored as an HMAC, expires after 10 minutes, allows 5 tries, is single-use and bound to the call.
- [ ] Limits: 5 codes per subject per 24 hours, 60 seconds between sends, a per-calling-number limit, and a destination country allow-list in the policy; a refused send gives the same spoken result as a sent one.
- [ ] `checkTextCode(callId, code)` records a `text_code` factor; the policy's carrier rule decides whether it counts (already implemented).
- [ ] The texts are code-built in English and French; `Engine.sendTextCode` stops throwing.

## Files

- src/verify/text-code.ts (new)
- src/verify/later.ts
- src/core/adapters.ts (a CodeStore interface)
- src/engine.ts
- src/testing/fakes.ts

## Tests

- test/verify-text-code.test.ts: expiry, tries, single use, limits, country allow-list
- test/engine.test.ts: no text before a match; refused and sent sends look the same to the caller

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### VER-3: Spoken answers for values a keypad cannot enter

**Labels:** `verify`, `m1`  
**Milestone:** M1 Verify  
**Depends on:** none

```markdown
## Why

Canadian postal codes contain letters. A spoken check must be exact after normalisation, never fuzzy.

## Acceptance criteria

- [ ] `normaliseSpokenAnswer({field, transcript, locale})` for postal codes (Canada and US) and short alphanumeric references, handling letter names and the common spelling alphabets in English and French.
- [ ] Returns a normalised value or `unusable`; never a near match.
- [ ] A `spoken_knowledge` factor compared like keypad fields (keyed digest, constant time).
- [ ] The policy can use `spoken_knowledge` only at level 1 or combined with another factor.

## Files

- src/verify/spoken.ts (new)
- src/verify/later.ts
- src/core/policy.ts
- src/engine.ts

## Tests

- test/verify-spoken.test.ts with a corpus of transcripts in both languages, including misrecognitions that must come out `unusable`

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### VER-4: Carrier signal adapters: Twilio Lookup, Sinch Number Lookup, Telnyx Number Lookup

**Labels:** `verify`, `m1`  
**Milestone:** M1 Verify  
**Depends on:** none

```markdown
## Why

The SIM swap and port checks the policy already uses need real sources.

## Acceptance criteria

- [ ] Three `CarrierSignals` implementations in the reference server, each mapping the vendor's answer to `CarrierSignalReport`.
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

**Labels:** `verify`, `m1`  
**Milestone:** M1 Verify  
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

**Labels:** `verify`, `m1`  
**Milestone:** M1 Verify  
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

### VER-8: Policy version in grants and receipts

**Labels:** `verify`, `m1`  
**Milestone:** M1 Verify  
**Depends on:** none

```markdown
## Why

A receipt should say which policy judged the caller.

## Acceptance criteria

- [ ] Grants and receipts carry `policyVersion`; the `verification.finished` event too.
- [ ] Receipt format version stays 1 if the field is optional, otherwise becomes 2 with SPEC.md updated.

## Files

- src/core/session.ts
- src/engine.ts
- src/prove/receipt.ts
- SPEC.md

## Tests

- test/engine.test.ts
- test/prove.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### FIL-1: Read-back library in English and French

**Labels:** `file`, `m2`  
**Milestone:** M2 File  
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
- src/engine.ts

## Tests

- test/file-readback.test.ts: snapshots per type and locale
- test/engine.test.ts: a changed draft refuses confirmation

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### FIL-2: Encrypted sensitive fields

**Labels:** `file`, `m2`  
**Milestone:** M2 File  
**Depends on:** none

```markdown
## Why

Forms with sensitive fields are refused today.

## Acceptance criteria

- [ ] A `FieldCipher` adapter (interface exists) passed to the engine; sensitive values are encrypted before `putIntakeRecord`.
- [ ] Without a cipher, sensitive fields stay refused.
- [ ] DECISIONS.md records whether the record digest covers plaintext or ciphertext, and why.

## Files

- src/file/later.ts
- src/engine.ts
- src/testing/fakes.ts
- DECISIONS.md

## Tests

- test/engine.test.ts with a fake cipher: stored values are ciphertext, the digest is stable

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### FIL-3: Record delivery with signed webhooks, retries and idempotency

**Labels:** `file`, `m2`  
**Milestone:** M2 File  
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

**Labels:** `file`, `m2`  
**Milestone:** M2 File  
**Depends on:** none

```markdown
## Why

Real intake forms branch and validate.

## Acceptance criteria

- [ ] `showIf` on a field (another field's value), min and max for numbers and dates, a pattern for text.
- [ ] Form validation refuses a field whose label or key names a Social Insurance Number or a card, and refuses `showIf` cycles.

## Files

- src/file/intake.ts

## Tests

- test/modules.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-1: Stripe Checkout adapter

**Labels:** `pay`, `m3`  
**Milestone:** M3 Pay  
**Depends on:** none

```markdown
## Why

Pay runs on fakes today.

## Acceptance criteria

- [ ] `StripeCheckoutLinks.createLink` creates a Checkout Session in payment mode, cards only, the amount and currency from the engine, a 30-minute expiry, the payment id in metadata, the engine's idempotency key, and the `Stripe-Account` header when a connected account is configured.
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

**Labels:** `pay`, `m3`  
**Milestone:** M3 Pay  
**Depends on:** FIL-1

```markdown
## Why

The amount must come from a record, a price list or the business's endpoint, and the caller hears it first.

## Acceptance criteria

- [ ] An `AmountSource` adapter resolves an amount from a reference; `requestPayment` takes the reference, not a raw number.
- [ ] A code-built amount read-back and a confirmation before the link is texted.

## Files

- src/pay/amount.ts (new)
- src/engine.ts
- src/core/adapters.ts

## Tests

- test/engine.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-3: Cancel and expire open links

**Labels:** `pay`, `m3`  
**Milestone:** M3 Pay  
**Depends on:** PAY-1

```markdown
## Why

A link should not outlive its purpose.

## Acceptance criteria

- [ ] `cancelPaymentLink` through a `PaymentLinks.cancel` method; open links are expired when the call ends, and the receipt shows them as expired.
- [ ] A late `paid` after cancellation is still recorded as paid (the money moved) and flagged in the ledger.

## Files

- src/pay/later.ts
- src/core/adapters.ts
- src/engine.ts

## Tests

- test/engine.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-5: Live card-number detector for partial and spoken numbers

**Labels:** `pay`, `m3`  
**Milestone:** M3 Pay  
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

### PRV-1: Receipt key sets and rotation

**Labels:** `prove`, `m4`  
**Milestone:** M4 Prove  
**Depends on:** none

```markdown
## Why

Keys must rotate without breaking old receipts.

## Acceptance criteria

- [ ] Several signers with one active; the published key set keeps retired public keys; `verifyReceipt` already selects by `kid`.
- [ ] The reference server's key set route serves the history.

## Files

- src/prove/receipt.ts
- src/engine.ts
- examples/reference-server/src/app.ts

## Tests

- test/prove.test.ts: a receipt signed before rotation still verifies

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PRV-2: Stand-alone receipt verifier

**Labels:** `prove`, `m4`  
**Milestone:** M4 Prove  
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

**Labels:** `prove`, `m4`  
**Milestone:** M4 Prove  
**Depends on:** none

```markdown
## Why

Consent must be revocable by voice, text or dashboard.

## Acceptance criteria

- [ ] `revokeConsent` through a `ConsentStore` adapter; revocation is a ledger event; STOP and its French forms map to revocation.

## Files

- src/prove/consent.ts
- src/core/adapters.ts
- src/engine.ts

## Tests

- test/engine.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PRV-5: Adapter contract suites in district-assurance/testing

**Labels:** `prove`, `m4`  
**Milestone:** M4 Prove  
**Depends on:** none

```markdown
## Why

A host's durable stores must keep the same guarantees as the memory ones.

## Acceptance criteria

- [ ] `runAuditLedgerContract(factory)` and `runRecordStoreContract(factory)` exported from `district-assurance/testing`: ordering, copies, append-only, chain validity, concurrency of appends.
- [ ] The memory adapters pass them in CI.

## Files

- src/testing/contracts.ts (new)
- src/testing/index.ts

## Tests

- test/contracts.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PRV-6: More redactors: SIN, health card numbers, bank account numbers

**Labels:** `prove`, `m4`  
**Milestone:** M4 Prove  
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

**Labels:** `reference-server`, `m5`  
**Milestone:** M5 Reference server hardening  
**Depends on:** none

```markdown
## Why

Carrier routes answer 501 today.

## Acceptance criteria

- [ ] `verifyTwilioSignature` (HMAC-SHA1 of the URL and sorted form parameters), `verifyTelnyxSignature` (Ed25519 over timestamp and body, with a tolerance), `verifySinchSignature` (the scheme of the product used).
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

**Labels:** `reference-server`, `m5`  
**Milestone:** M5 Reference server hardening  
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

**Labels:** `reference-server`, `m5`  
**Milestone:** M5 Reference server hardening  
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

### SRV-5: Release workflow

**Labels:** `reference-server`, `m5`  
**Milestone:** M5 Reference server hardening  
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

### INT-1: Keypad collector helper

**Labels:** `integration`, `m6`  
**Milestone:** M6 Host integration points  
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

### INT-3: Session storage shared across processes

**Labels:** `integration`, `m6`  
**Milestone:** M6 Host integration points  
**Depends on:** none

```markdown
## Why

The engine keeps sessions in memory. A host whose voice agent and web backend are separate processes, or run several replicas, needs shared session state.

## Acceptance criteria

- [ ] A `SessionStore` adapter with a version number per session (compare-and-set); every engine method loads, applies and saves with the version, and retries or refuses on conflict.
- [ ] Identity session and payment link lookups move into the store.
- [ ] The memory implementation and a contract suite (PRV-5 style).

## Files

- src/core/adapters.ts
- src/engine.ts
- src/testing/fakes.ts
- src/testing/contracts.ts

## Tests

- test/engine.test.ts with two engines sharing one store
- Conflict tests

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```
