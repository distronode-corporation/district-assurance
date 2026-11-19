# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The callback factor (VER-9): a built-in `callback` kind; `requestCallback` ends the call and, after a keypad or PIN match, has a new `CallbackDialer` adapter ring the number on file on a new callback call, where `applyCallbackOutcome` records it only for a keyed confirmation; possession like `text_code` in the policy; one per call, 3 per subject a day, failures counted in `AttemptCounters`; `verification.callback_started` and `verification.callback_finished` events; a scripted callback in the demo.
- Lockout alerts (INT-7): a `Notifier` adapter (`FakeNotifier`) told of each lock's counter, factor kind and end after its ledger entry, once per lock and at most 20 an hour per workspace for hard locks and 20 for waits, best effort; `engine.unlock({ workspaceId, factor, scope, key, memberId })` clears one counter and writes `verification.unlocked`.
- Limits across flows (VER-15): failure counters are pinned to subject or number and factor kind,
  never flow or call; flows that need a money, contact or access scope are limited per hour (10
  per calling number, 5 per subject, Badge's `lockout.flowStartsPerHour`, defaults as ceilings),
  refused with one `rate_limited` answer (`RateLimitedError`, with the call's id) and a `flow.rate_limited` event; `startCall` and
  `startFlow` take `callingNumber`.
- Lockouts across calls (VER-1): an `AttemptCounters` adapter (`MemoryAttemptCounters`,
  `attemptCountersContract`) counts failures of every entered factor per subject and per calling
  number (`beginVerification({ callingNumber })`, kept as a keyed hash), before judging; a wait of
  5, 15, 60, 300 and 900 seconds and a hard lock after 10 failures in 24 hours, in Badge's
  `lockout` setting as defaults and floors; a `verification.locked` event. Badge needs `counters`
  when a factor the caller enters is on. A pass takes its own failure off the calling number with
  `AttemptCounters.removeFailure`, one atomic step. `recordSubjectFailure` is gone.
- Amounts from code, read back first (PAY-2): an `AmountSource` adapter (`amounts`, reference
  `PriceListAmounts`) resolves a `paylink.request` step's `amountRef`; `readBackPayment` builds the
  amount read-back in the call's locale (`AMOUNT_READBACK_TEXT`) and `confirmPaymentAmount` records
  the caller's yes before the link is texted.
- `SUPPORTED_LOCALES` (`["en", "fr"]`, frozen; its members are the `Locale` type) and
  `isSupportedLocale`: `startCall` checks a locale against it, and the texts the engine sends, the
  amount formats and the spoken digit words are `Record<Locale, ...>` catalogs (`IDENTITY_TEXT`,
  `PAYMENT_TEXT`, `AMOUNT_REGION`, `DIGIT_WORDS_BY_LOCALE`) that a test holds to every supported locale.
- Web sign-in step-up (GAT-4), the sixth built-in module (`step-up`, step `step-up.issue`, scope
  `entry.sign_in`): a 2 to 5 minute ES256 JWT bound to the site's nonce, the verified subject and
  the verification grant, with an OpenID Connect `acr`. The engine issues it and records its one
  exchange itself (ADR-25): `Engine.issueStepUpToken`, `exchangeStepUpToken`, `stepUpTokens` and
  `stepUpKeys` (the JWKS); the `stepUpSigner` adapter, its own key; `stepup.*` ledger events.
  Refused after the call is tainted or verified again, including when the call ends: the end
  refuses every token its call no longer vouches for. Receipts list a call's tokens (`stepUp`,
  optional, so receipts stay at `v: 1`).
- `validateConfig` refuses a flow with more `step-up.issue` steps than the step-up
  `maxTokensPerCall`, which could never complete; modules gain an optional `validateFlow` hook for
  such whole-flow checks.
- Published key sets (`receiptKeys`, `accessKeys`, `stepUpKeys`) carry only public key members.
- Gate, the fifth built-in module (GAT-1, ADR-25): signed, time-limited access grants (ES256 over
  canonical JSON, like receipts) after verification to `entry.open` (level 2 or more), delivered
  once through an `AccessController`. The engine owns every grant and outcome: it reserves, signs,
  computes the digest, calls the controller and records its answer. `Engine.grantAccess`,
  `accessGrants` and `accessKeys`; the `access` and `accessSigner` adapters; `access.*` ledger
  events. `verifyAccessGrant` (bound to a workspace) and `SeenGrants` for the access side.
- Cancel and expire open payment links (PAY-3): `Engine.cancelPaymentLink`, through the optional
  `PaymentLinks.cancel` (else `expireLink`); `endCall` expires every open link, so the receipt shows
  it `expired`; a payment made after the engine closed its link is recorded as paid, flagged `late`.
- The signed-webhook relay adapter (GAT-2), `webhookRelay`, and an example door relay. An unlock
  is never retried; a lost answer is `unknown`.
- The Seam adapter (GAT-5), `seamAccessController`: checks the device can unlock remotely, unlocks once with no retry, `confirmed` only when Seam reports success, a lost answer `unknown`.
- Direct vendor adapters (GAT-6), `vendorAccessController` for Kisi and Verkada, through each vendor's documented unlock call; never retried, a lost answer is `unknown`.
- `FakeAccessController` in `district-assurance/testing`.
- One-time access codes (GAT-3): `accessCodes(...)`, an `AccessController` that texts an 8-digit
  code for an access grant to the number on file instead of working a door; codes kept only as
  keyed hashes (`AccessCodeStore`, `MemoryAccessCodeStore`), redeemed once within the grant's
  lifetime for the signed grant, revocable; texts counted against VER-2's per-subject limit in its
  `CodeStore`; `Engine.numberOnFile`.
- Paylink's two modes (PAY-7), `connect` and `platform`, per flow step; `linkLifeMinutes` (5 to 60,
  default 15) with the engine expiring links itself (`expirePaymentLinks`, `PaymentLinks.expireLink`);
  an allow-list of instant payment methods (card, Apple Pay, Google Pay, Link). Outcomes from
  another account than the payment's are ignored.
- Refunds and disputes in platform mode (PAY-8): `refundPayment` (full or partial, a host call for
  the business, refused while a dispute is open), `PaymentLinks.refund`, Stripe's `charge.dispute.*`
  events found by payment intent, `payment.refunded` and `payment.disputed` ledger entries; a
  `PaymentLinks.refund` is optional, so a host without it keeps its platform payment flows.
- Outside modules see the current step, the clock and an id source; outside a flow, their
  `updateModule` is held to every scope their manifest needs.
- `PaymentLinks.capabilities` (modes, shortest and longest link life), checked when the engine is
  built and when a config is saved. Connect-mode payments are bound per connected account.
- The reference server's Connect webhook route; the demo takes a deposit in each mode and opens a
  door through the relay.
- ADR-21 to ADR-25.
- Grants, `verification.finished`, `grant.issued` and receipts name the `policyVersion` and
  `configRevision` that judged the caller (VER-8); optional on receipts, which stay at `v: 1`.
- `npm run demo:e2e`: the demo UI with a real Stripe Checkout Session in test mode, through a
  minimal PAY-1 adapter (`StripeCheckoutLinks`: platform mode, built-in fetch, `sk_test_` keys
  only, live and restricted keys refused). The payment is read back from Stripe; Gate's grant goes
  to the example door relay; the call ends with a receipt the page verifies.

- Texted one-time codes (VER-2): `Engine.sendTextCode` and `Engine.checkTextCode`, the `text_code`
  factor in Badge's settings, a `CodeStore` adapter (`MemoryCodeStore`, `codeStoreContract`) for
  send limits per subject and per calling number, and `textCodeCountryCodes` in the policy; a
  refused send answers like a sent one.
- The modular core. A module registry and module interface (what a module provides, the scopes it
  grants or needs, the adapters it requires, its settings validator); Badge, Dossier, Paylink and
  Trace as modules, switched on and off per workspace config; outside modules with `engine.use`.
- FlowConfig, a versioned JSON document per workspace, and `validateConfig(config, registry)`, which
  returns every problem with its path. Flow execution: a call runs its flow step by step, and only
  the current step's work is allowed.
- Badge factor plug-ins, and the `pin` factor (a keyed hash bound to the subject, or the host's own
  `PinVerifier`), with attempts counted before they are judged.
- `SessionStore` with compare-and-set (INT-3), `MemorySessionStore`, and `sessionStoreContract` in
  `district-assurance/testing`. Several engines can run one call.
- The demo runs `owner-command` (a PIN only, on two engines sharing one store) and `deposit`.
- ROADMAP.md and ISSUES.md for the modular design, owner-command first; ADR-13 to ADR-20.
- A demo UI on the reference server (`npm run ui`): pick a flow, run the scripted call one step at a
  time, and see the session state, the ledger entries and the signed receipt, verified in the
  browser against `/.well-known/receipt-keys.json`. Plain HTML, CSS and JavaScript, a fixed file
  allow-list, a strict CSP, no new dependency. The demo's script moves to `script.ts`, shared by
  `npm run demo` and the UI.
- The Stripe Identity adapter for the reference server (VER-5): `StripeIdentityProvider` creates a
  document VerificationSession with a matching selfie by `fetch` and a restricted key, and
  `npm run serve` with `STRIPE_IDENTITY_KEY` runs a trial call whose check comes back through the
  identity webhook.
- Key store contracts (INT-4): the knowledge key can be an opaque, asynchronous HMAC function (a
  key management service) that the engine and every factor hash through, `signReceipt` refuses a
  signature that is not 64-byte P1363, and `derToP1363` converts a key store's DER signature. A
  factor judge that throws or rejects (a key store outage) records no factor and writes
  `verification.factor_error`; the attempt stays counted.
- Spoken answers (VER-3): `normaliseSpokenAnswer` reads Canadian postal codes, US ZIP codes and short references spoken in English or French, exactly or `unusable`, and the `spoken_knowledge` factor compares them like keypad fields under the policy's new `spoken` fields.
- PIN enrolment and reset (VER-6): `enrolPin` lets a caller verified to level 2 on the call choose a PIN, keyed twice, weak PINs refused, stored through the new `RecordStore.putPinDigest`; `resetPin` is the business's host call; `pin.enrolled` and `pin.reset` events.
- Receipt key sets and rotation (PRV-1): `receiptKeyRing` holds several signers with one active and
  publishes retired public keys, `engine.receiptKeys()` and the reference server's key set route
  serve the whole history, so a receipt signed before a rotation still verifies. A retired key is
  published with `retired: true` and its `retiredAt`; `checkReceipt`, the stand-alone verifier and
  the demo page call such a receipt "valid, signed with a retired key (retired <time>)", and a
  receipt the retired key signed at or after its retirement invalid.
- A stand-alone receipt verifier (PRV-2): `scripts/verify-receipt.mjs`, with no dependencies, checks
  a receipt against a key set file or URL and prints valid or invalid; SPEC.md has a worked example.
- Duress PIN (VER-12), off by default (`pin.duress`): the business enrols it with `enrolDuressPin`, stored through the new `RecordStore.putDuressDigest`; a duress entry passes like the PIN to the caller while `authorize` refuses money, contact, access and `refuseScopes`, and the new `DuressNotifier` adapter is told of every duress entry from an alert owed in the call record until it answers (`deliverDuressAlerts` and `sweepAlerts` are the host's sweeps); a duress entry flags its subject until `clearDuress` (a host-privileged call; a `duress.cleared` ledger entry with an opaque member id and a keyed digest of the subject, never the subject key), the flag holds when the duress PIN is turned off and is set again on the alert's delivery unless the subject was cleared since, a flagged subject's passes alert once a call, and its failures stay counted in a hidden counter, which a PIN reset clears; every PIN ledger entry carries a keyed `tag` that `readPinTag` reads, and ledger event ids are numbered by the call's writes that queue entries (not the store version), so an alert's acknowledgement leaves no gap; `sweepAlerts` reports a call it cannot read as failed and goes on; a duress PIN entry whose own write fails still flags its subject; `clearDuress` clears the hidden counters of every installed factor.
- Carrier signal adapters for the reference server (VER-4): Twilio Lookup (SIM Swap, Identity
  Match) and Telnyx Number Lookup (porting status and date, the carrier), credentials from the
  environment, failing closed with `checked: false`; tested against a local fake server.
- An adversarial suite in English and Canadian French (VER-7): scripted dialogues run through a
  scripted host, checking no grant without factors, no text before a match, identical answers for
  unknown and wrong, and no grant after a taint.
- Badge factor plug-ins after the engine is built (MOD-3): `engine.useFactor(plugin)`, and outside
  modules that supply `factorPlugins` for the factors their manifest provides. The registry checks
  them for clashes and caller-ID names; they stay off until a config turns them on.
- Caller ID attestation (VER-10): `startCall({ attestation })` records the call's STIR/SHAKEN
  result (`A`, `B`, `C`, `failed`, default `none`) in `call.started` and the receipt (an optional
  field, format version 1), and the policy's optional `attestationCaps` can only lower a level. A
  callback call, which the engine dialled, is never capped.
- `KeypadCollector` (INT-1): a pure buffer for keypad tones until `#`, with a maximum length and an
  idle timeout, that shows no digit through `toString`, JSON or `util.inspect` and hands each entry
  to one callback. An overflowed or rejected entry is ignored to its end, and unknown options are
  refused.
- `auditLedgerContract` and `recordStoreContract` in `district-assurance/testing` (PRV-5), which
  the memory adapters pass; `MemoryRecordStore` now keys by JSON tuples, so two workspace and id
  pairs can no longer share a key. The session, ledger and record contracts keep keys that differ
  only in a lone UTF-16 surrogate apart, which a store encoding keys as UTF-8 would collapse.
  `AuditLedger.list(fromSeq?, limit?)` reads one page of at most `limit` entries, and the ledger
  contract checks it: a ledger that ignores `limit`, or takes one that is not an integer of 1 or
  more, now fails `auditLedgerContract`.
- Read-backs in English and French (FIL-1): `buildReadBack` and `engine.intakeReadBack` speak each
  field by type (dates in full, yes and no, numbers) with a fixed confirm prompt and never read a
  sensitive value; `confirmIntake` refuses a draft changed since the caller heard it.
- Conditional fields and validation rules (FIL-4): `showIf` (asked, read back and filed only while
  another field holds a value), `min` and `max` for numbers and dates, and a bounded `pattern` for
  text; `validateConfig` refuses unknown field settings, `showIf` cycles, and fields that name a card or a SIN.
- Spanish (FIL-6): an `es` locale for read-backs (US numbers and dates), identity and payment texts (amounts as `es-US`), optional Spanish form labels and consent wordings (a wording without one keeps its digest), Spanish digit words in card redaction, no Spanish spoken answers (a yes/no field takes no `sí`, and a Spanish call confirms its read-back on the keypad, until a reviewed Spanish vocabulary exists), a call in `es` refused when its flow needs a form or wording without Spanish, `startCall` refusing an unknown locale, and a parity test over every code-built string.
- Receipt links by capability token (SRV-3): `newReceiptLinkToken` and `receiptLinkTokenHash`; the
  reference server keeps only token hashes and serves `GET /r/:token`, a receipt page in English
  and French with its signature check, and `/r/:token.json`. `GET /receipts/:callId` is removed.
- Receipt link texted to the caller (PRV-10): `textReceiptLink(callId, url)` after a money, contact
  or access step, when the flow's `trace.receipt` step has `textLink` and the caller consented, at
  most once, to the number on file; each contact change always texts a security notice to the
  changed subject's number on file before the change, never twice to the same subject and number.
  The notice is owed in the same write as the change (a flow step, or an outside module's
  `ModuleCallView.contactChanged()` in or outside a flow), sent right after it, and retried by the
  call's next write, `endCall` and `Engine.sweepAlerts()`, so a call that never ends still alerts.
  New message purposes `receipt_link` and `contact_changed`, Trace's `businessName` setting, events
  `receipt.link_texted`, `contact.notice_owed` and `contact.notice_sent`.
- Encrypted sensitive intake fields (FIL-2): a `fieldCipher` adapter (`FieldCipher`, now in the
  core, and `FakeFieldCipher`) that Dossier needs once a form has a sensitive field; values are
  encrypted before `putIntakeRecord`, and the record digest keys them (ADR-27). A cipher that
  throws, or answers empty, not a string or the value itself, releases the filing as failed
  (`record.filing_failed`, field names and a reason code only) and drops the draft, so it never
  holds a call open; `endCall` drops an open draft, so its values never outlive the call in the clear.
- Consent revocation (PRV-3): `Engine.revokeConsent` by voice, text or dashboard through a new
  `ConsentStore` adapter (`consents`; `MemoryConsentStore` in the fakes), a `consent.revoked`
  ledger event written once per consent and never before its `consent.recorded`, and
  `isStopRequest` for STOP, STOPALL, UNSUBSCRIBE, CANCEL, END, QUIT, ARRÊT, ARRÊTE and ARRÊTER. A
  consent still being stored when its call ends settles as not recorded (no consent):
  `consent.unrecorded` in the ledger, `answer: "not_recorded"` on the receipt.
- Record delivery (FIL-3): `deliverRecord` posts a confirmed record through a `RecordDelivery`
  adapter, signed in the `t=,v1=` HMAC scheme used for Stripe, retried with capped exponential
  backoff under one idempotency key per record and destination, with a `delivery.attempted` ledger
  entry per attempt and no payload in it; `FakeRecordDelivery` in `district-assurance/testing`;
  a sample receiver on the reference server at `POST /webhooks/records`.
- Documents by text (FIL-5): `createUploadLink` makes a single-use, 30-minute link bound to a call
  and a confirmed record, with allowed types and a size cap, storing only its token's hash;
  `acceptUpload` checks type, size and leading bytes, spends the link and asks the host's
  `DocumentScanner`; a `DocumentStore` adapter with `MemoryDocumentStore`; the reference server
  serves an upload page in English and French at `/u/:token`.

### Changed

- Breaking: `CarrierSignalReport` has a required `simSwapChecked`, true only when the carrier was
  asked about SIM changes and answered, and `textCodeTrusted` never trusts a texted code on a
  report without it, whatever the policy says (VER-4). The Telnyx adapter answers false; every
  `CarrierSignals` adapter has to set it.
- `PaymentLinks.createLink` takes a `PaymentLinkRequest` (mode, connected account, payment methods,
  expiry); `requestPayment` also returns `expiresAt`; receipts' payments carry `mode`.
- `confirmIntake` refuses a `confirmedBy` other than `voice` or `keypad` (`invalid_input`) before
  anything is written, so no host value reaches the record or the ledger unchecked.
- `verifyStripeSignature` throws `invalid_input` for a `toleranceSeconds` that is not an integer
  from 0 to 86,400, or a `now` that is not a valid `Date`: either could make a replay of any age
  pass.
- The reference server remembers webhook event ids for 4 days (Stripe retries for 3) and at most
  10,000 of them, least recently seen first out, instead of in a set that grew without end.
- Breaking: the `AmountSource` string type (`intake_record`, `business_endpoint`, `price_list`) is
  renamed `AmountSourceKind`, and `AmountSource` is now the adapter interface (PAY-2).
- Breaking: `requestPayment` sends no link without a read-back the caller confirmed, for a fixed
  amount too. A host that calls it directly calls `readBackPayment`, speaks the text, and calls
  `confirmPaymentAmount` on the caller's yes first (PAY-2). The demo's deposit, connect-mode and
  live e2e flows read their amounts back first.
- `canonicalJson` refuses a string or property name holding a lone surrogate (RFC 8785, section
  3.2.2.2), as do the stand-alone verifier and the demo page; an intake text value holding one is
  refused as `not_text`. A step whose ledger detail canonical JSON refuses (a lone surrogate, a
  `Date`) is refused before it is saved, `markUntrusted` repairs a lone surrogate in its label, and
  `validateConfig` refuses a config holding one.
- A taint now voids the keypad or PIN match made before it: `startPhotoId`, `checkCarrier` and a
  payment link refuse until a fresh verification matches (found by the adversarial suite).
- `confirmIntake` requires `readBack`, the digest of the read-back the caller heard (FIL-1), and
  the `buildReadBack` stub in `file/later.ts` is replaced by `file/readback.ts`. A host that
  confirmed without a read-back must call `intakeReadBack` first.
- A text field value holding a lone surrogate is refused with the new normalise reason `not_text`
  (`NormaliseResult`), since no record, digest or read-back can hold it faithfully: a host that
  switches over the reasons must add it.
- The `revokeConsent` stub in `prove/consent.ts` is replaced by `Engine.revokeConsent`, and
  `ConsentRecord` moves to the adapter types (still exported from the root).
- The `deliverRecord` stub in `file/later.ts` is replaced by `deliverRecord` in `file/delivery.ts`,
  which takes the destination, the stores, the clock and the retry settings (SPEC.md, Record
  delivery).
- A live card-number detector (`LiveCardNumberDetector`, PAY-5) that tells the host to interrupt
  once a run of 8 or more digits is read, numerals or spoken; redaction now reads spoken numbers
  ("forty two", "quarante-deux", "double four") through `digitRuns`, tested over a shared JSON
  corpus, `test/corpus/card-numbers.json`.
- Spanish number words in redaction and the live detector: digit words, 10 to 29, the tens with
  "y", the hundreds and "mil" ("cuarenta y uno", "cuatro mil ciento once"), for #122's Spanish
  calls (PAY-5).
- `SEPARATOR_CLASS`, the characters that may lie between the groups of one number (spaces, any
  dash, the minus sign, dots, commas, slashes, underscores, middle dots, format characters and
  combining marks), and `NUMBER_LANGUAGES`, `NUMBER_CONNECTORS`, `numberLanguagesFor` and `NumberLanguage`, exported
  from `district-assurance`. `LEXEME` matches every script's decimal digits, read by their values.
- `RedactionContext`: `Redactor.redact(text, context?)` takes the call's `locale`, and
  `LiveCardNumberDetector` a `locale` option.

### Changed

- English and French number words are read on every call; Spanish words only on a Spanish call, so
  on an English call "once", "dos" and "y" are words, not numbers (`Engine.redact` passes the
  call's locale, `numberLanguagesFor`). Text redacted with no call reads every language, the safe
  side.
- More redactors (PRV-6): `sinRedactor`, `healthCardRedactor` (Ontario, British Columbia, Quebec)
  and `bankAccountRedactor`, each its own `Redactor` over digits and English or French digit
  words, tested over a shared JSON corpus in `test/corpus/`; compose health card numbers before
  SINs. Bank words are English, French and Spanish, read on every call.
- `SEPARATOR_CLASS`, exported from `district-assurance`: the characters that may lie between the
  groups of one number (spaces, any dash, the minus sign, dots, commas, slashes, underscores, middle
  dots, format characters and combining marks). Numerals in every script's decimal digits are read
  by their values (PRV-6).

### Changed

- `Engine.redact` also returns `line`, the fixed interrupt line for the kind found, in English or
  French (`INTERRUPT_LINES`), so a SIN or banking details never get the card number wording (PRV-6).
- `composeRedactors` reports finding offsets into the original input, no longer into the text each
  redactor saw (PRV-6).
- `applyFindings` takes findings in any order: it sorts them by position and merges overlapping
  ones before it applies them (PRV-6).
- Carriers are Twilio and Telnyx: the Sinch webhook signature stub and its reference server route
  are removed. `CarrierSignals` stays vendor-neutral.

- The ledger is always on: Trace cannot be turned off or removed, and an engine needs a ledger.
  Receipts are per flow (`trace.receipt`) or Trace's `receipts` setting; `endCall` returns null
  when a call gets none.
- The policy, forms, consent wordings, grant lifetime and payment limit moved into FlowConfig;
  `startIntake` takes a form id and `recordConsent` a purpose.
- `state`, `authorize`, `setIntakeField` and `receipt` are asynchronous (the session store).
- A factor plug-in's `hmac(data)` is asynchronous (a `Promise` of the hex digest), so the knowledge
  key can live in a key management service. `subjectKeyFor`, `knowledgeDigest`, `pinDigest` and
  `judgeKeypadFactors` return a `Promise` when given an HMAC function; `judgeKeypadWith` always does.
- `returning_pin` is now `pin`; `returningCallerPin` is `enrolPin` (VER-6).
- Once a call's flow has ended, no step work runs on that call. A consent answered "no" fails its
  step unless the step says `require: "answer"`. Outside modules' steps are held to their scopes
  by the engine. Grants are checked against the config in force.
- Scope classes (money, contact, access, none) set the floors; level 2 needs a factor that is not
  knowledge; keypad attempts are capped at 5.
- Ledger entries are saved with each step and appended idempotently by `eventId`
  (`flushLedger`); `AuditLedger.append` is idempotent by `eventId`.

- M0 skeleton. The engine (`createEngine`) with the call session state machine, the assurance
  policy (levels, scope floors, carrier signal handling), keypad knowledge comparison, the photo
  ID flow, intake forms and confirmed records, payment links and settlement, consent records,
  the hash-chained audit ledger and signed ES256 receipts over canonical JSON.
- Card-number redaction (Luhn; digits and English or French digit words).
- Stripe webhook signature verification and event mapping.
- `district-assurance/testing`: fakes for every adapter and `createTestEngine`.
- `examples/reference-server`: a `node:http` server with Stripe webhook routes, receipt and key
  set routes, `501` carrier routes, and `npm run demo`.
- Planned entry points that throw `NotImplementedError` with their ROADMAP.md issue ids.

### Fixed

- Integration review of the Gate and payments landing (L1):
  - `accessKeys()` and `receiptKeys()` publish each key under its signer's `keyId`, as
    `stepUpKeys()` does, so a signer whose JWK has no `kid` no longer makes its grants and
    receipts unverifiable.
  - `validateConfig` refuses a flow with more `gate.grant` steps than `maxGrantsPerCall`.
  - Gate reads the call again right before the send, so a taint written after the reservation
    check stops it; a controller answer of the wrong shape is recorded `unknown`
    (`malformed_answer`), never `refused`.
  - The Seam adapter refuses a grant signed for another device (`target_mismatch`); Seam, Kisi and
    Verkada refuse an unreadable clock or expiry (`grant_expiring`).
  - `exchangeStepUpToken` and `applyPaymentOutcome` snapshot their input before they wait.
  - A spent access code stays held, spent, until its `access.code_spent` entry is appended, so a
    failed append is made again on the next wrong guess (`AccessCodeStore.miss` marks entries
    spent instead of removing them).
  - The amount read-back's digest includes a read-back id, so a late yes to an identical earlier
    read-back never confirms a new one.
  - A resume never takes over a live send lease; a failed sender gives its lease back; a cancel
    or call end claims the close before asking the provider, so a resume never texts that link.
  - A dispute event older than the status recorded (by Stripe's event time, or by stage) never
    replaces it, so a late inquiry snapshot cannot reopen `warning_closed`.
