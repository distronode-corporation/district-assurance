# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Releases are made by `release.yml` on its own when a release pull request merges: on a push to
  main whose `package.json` version has no tag and is not on npm (any other push is a no-op), it
  creates the annotated tag `vX.Y.Z` on that commit, signs it with gitsign (keyless, under the
  workflow's GitHub OIDC identity), verifies it against `release.yml@refs/heads/main`, pushes it,
  and then builds and publishes as before. There is no tag trigger, so a hand-pushed tag starts
  nothing, and only a version under a tag the workflow made and signed on main is ever published
  (a manual dry run builds without a tag and never publishes); a stray tag of the version stops
  the release and never ships. The `npm-publish` environment admits main only and needs no reviewer: the approved
  release pull request is the gate. README.md has "How releases work" and the `gitsign verify-tag`
  command; the SBOM attestation's source ref is `refs/heads/main` from 0.2.0 on.

## [0.2.0] - 2026-11-22

### Added

- `district-assurance/stripe` (ADR-30, SPEC section 31): `StripeCheckoutLinks` in test or live mode
  over a structural `StripeClientLike` (a stripe-node instance fits it as it is) or
  `fetchStripeClient`, on API version `2026-09-30.endive` with `allowed_payment_method_types`;
  `assertStripeKey` (a mode's `sk_` or `rk_` key only); `cs_test_` and `cs_live_` ids and every
  answer's `livemode` held to the mode; `expire` reading back `expired`, `already_expired`,
  `complete` (paid won the race) or `open` after any answer, sent with no idempotency key (Stripe
  saves a key's failed result for every retry), with a session still open after a 5xx, 429 or lost
  answer retryable; `expiresAt` kept to 30 minutes to 24 hours, the default 35 (`checkoutExpiresAt`);
  an empty method list refused; reads asked again after a lost answer up to `maxNetworkRetries`
  (at most 2) on `fetchStripeClient`; an onboarding link refused unless it names the requested
  account; Connect
  onboarding on Accounts v2 (`connectAccountCreateParams`, `createConnectAccount`,
  `createOnboardingLink`, `readConnectStatus`, `connectStatusOf`); `verifyConnectEvent`, whose mode
  is the verifying secret's (both modes verifying is invalid, a `livemode` of the other mode is
  `wrong_mode`), and `connectEventAccount`; `StripeAdapterError`, `StripeHttpError` and
  `StripeKeyRefused`, none of which carries Stripe's message or any part of a key.
- `connectStatusOf` (and so `createConnectAccount` and `readConnectStatus`) reads
  `detailsSubmitted` true only once Stripe has requested a merchant capability, which it does after
  onboarding collects the business's details, and no requirement due from the business restricts a
  payment capability: a freshly created account reads false, never "nothing due, so submitted".
  Pinned with real test-mode v2 Account shapes (`test/fixtures/stripe-v2-accounts/`).
- `STRIPE_CHECKOUT_CAPABILITIES` and `stripeCheckoutCapabilities(modes)`: Checkout's frozen
  `PaymentLinkCapabilities`. `StripeCheckoutLinks` checks `expiresAt` against its own clock (wall
  time unless `now` is given), so a host engine on another clock passes it.
- `district-assurance/carrier` (SPEC section 32): `twilioSimSwapHours`, `twilioIdentityMatch`,
  `telnyxPortHours`, `durationHours`, `isCarrierAnswer` and `uncheckedReport`.
- `receiptKeysDocument(signers)` and `RECEIPT_KEYS_CACHE_CONTROL`: the public receipt-keys document,
  each `kid` once, two different keys under one `kid` refused.
- `createOwnerPin({ engine, hmac, records, counters, now? })` from the package root: the owner PIN
  of the `owner-command` flow (ADR-20, ADR-31). `status`, `setPin`, `clearPin` and `liftLock` over
  the engine's own stores, with the owner as the subject `ownerSubjectKey(hmac, workspaceId)` and
  its PIN counters (the subject's and the line's). A set or clear is one compare-and-set: of two
  at once exactly one lands and the other throws `OwnerPinConflictError` (code `conflict`, no PIN
  in it). Every set that lands refreshes the owner's number on file in the same step. The PIN
  length and lockout come only from the engine's config. `records` also needs `createSubject`
  (`SubjectWriter`: create if absent, atomically), which `MemoryRecordStore` now has.
- `Engine.replacePin(subjectKey, { from, to, phoneOnFile? })` and
  `RecordStore.replacePinDigest(workspaceId, subjectKey, from, to, phoneOnFile?)`: the business
  replaces or removes a PIN in one compare-and-set against the record on file, with the number on
  file in the same step. A landed change from a PIN on file forgets the subject's PIN failures
  recorded before it began, never one at or after, and appends `pin.reset`; a first PIN (`from`
  null) forgets nothing and appends nothing. A counter cleanup or `pin.reset` that fails after the change landed
  throws `PinChangeUnfinishedError` (with `at` and `change`), and
  `Engine.finishPinChange(subjectKey, error)` (the owner PIN's `finishChange(error)`) finishes it,
  whatever changed since, appending its `pin.reset` once. A new required `RecordStore` method: a
  host's own store adds it (`recordStoreContract` has a case for it). `MemoryRecordStore` and the reference server's
  `SqliteRecordStore` have it.

### Changed

- The reference server's Checkout adapter is the package's `StripeCheckoutLinks` (its own copy is
  gone), and its carrier adapters use the package's parsers. The recorded Checkout runs replay on
  `2025-03-31.basil`, which the adapter accepts in test mode only.
- The Seam adapter (GAT-5) checked against Seam's current API reference: its requests and the
  fields it reads (`device_id`, `can_remotely_unlock`, `properties.online`, the action attempt's
  `status` and `result.was_confirmed_by_device`) are the documented ones, and a test now replays
  the reference's own published examples. Its sandbox run is still owed (#48).
- ROADMAP.md no longer marks M3 done with no open issues: the Seam sandbox proof (#48) and the
  Kisi and Verkada runs (#140) are listed as what is left.

## [0.1.0] - 2026-11-20

The first published release.

### Added

- `isWeakPin(pin)` from the package root: the digits-only rule `enrolPin` and `enrolDuressPin`
  refuse as `weak` (every digit the same, or a run up or down with 0 following 9, as in 1111, 1234,
  4321 or 7890), so a host that takes PINs itself refuses the same ones. It fails closed: a value
  that is not one to 32 ASCII digits, or not a string, is weak and never coerced.
- Stripe test-mode proofs for VER-5 (#18) and PAY-1 (#25), recorded once through the reference
  server's own adapters and webhook routes and replayed offline (`test/stripe-real.test.ts`,
  recorder `test/fixtures/stripe-real/record.ts`, every Stripe id redacted): a Stripe Identity
  VerificationSession and Stripe's signed `identity.verification_session.verified` event applied to
  the trial call; a Checkout Session paid in platform mode and one paid as a direct charge on a
  connected account, each settled by Stripe's signed `checkout.session.completed` on its own
  endpoint (the Connect one names the account); a connect link cancelled and expired on the
  connected account; and Stripe's answers on the payment method mapping.
- Simulator callers for the rest of the built-in steps (#134): `gate.grant` (the fake door, as
  every controller the config's Gate targets name, opens or refuses), `step-up.issue` (a token
  issued and exchanged), and Badge's `text_code`, `spoken_knowledge` and `callback` (the caller
  goes on on the callback call); script fields `textCode`, `spoken`, `callback` and `door`, and the
  built-in scripts `text-code-wrong`, `spoken-wrong`, `callback-not-confirmed` and `door-refused`.
  A flow with every built-in step type runs to the end with exit code 0; nothing keyed or said is
  printed.
- A pending refund's later outcome (PAY-9, #117, #132): `applyRefundOutcome` applies Stripe's
  signed `refund.updated`, `refund.failed` and `charge.refund.updated` (`parseStripeEvent` kind
  `refund`; the reference server's payments endpoint), found by the provider's refund id. A pending
  refund that succeeds stays counted; one that fails (or is canceled) is released, so the business
  can refund that amount again, and a succeeded one that fails later is released too; a
  `payment.refund_updated` entry each time, never one for an event that changes nothing. A failed
  refund stays failed; the receipt is never changed.
- M0 skeleton. The engine (`createEngine`) with the call session state machine, the assurance policy
  (levels, scope floors, carrier signal handling), keypad knowledge comparison, the photo ID flow,
  intake forms and confirmed records, payment links and settlement, consent records, the
  hash-chained audit ledger and signed ES256 receipts over canonical JSON.
- Card-number redaction (Luhn).
- Stripe webhook signature verification and event mapping.
- `district-assurance/testing`: fakes for every adapter and `createTestEngine`.
- `examples/reference-server`: a `node:http` server with Stripe webhook routes, receipt and key set
  routes, carrier routes, and `npm run demo`.
- Planned entry points that throw `NotImplementedError` with their ROADMAP.md issue ids.
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
- The demo runs `owner-command` (a PIN only, on two engines sharing one store), `deposit` and
  `deposit-connect` (one per payment mode), and `entry`, which opens a door through the relay.
- The reference server's Connect webhook route.
- ROADMAP.md and ISSUES.md for the modular design, owner-command first; ADR-13 to ADR-29.
- The callback factor (VER-9): a built-in `callback` kind; `requestCallback` ends the call and,
  after a keypad or PIN match, has a new `CallbackDialer` adapter ring the number on file on a new
  callback call, where `applyCallbackOutcome` records it only for a keyed confirmation; possession
  like `text_code` in the policy; one per call, 3 per subject a day, failures counted in
  `AttemptCounters`; `verification.callback_started` and `verification.callback_finished` events; a
  scripted callback in the demo.
- Lockout alerts (INT-7): a `Notifier` adapter (`FakeNotifier`) told of each lock's counter, factor
  kind and end after its ledger entry, once per lock and at most 20 an hour per workspace for hard
  locks and 20 for waits, best effort; `engine.unlock({ workspaceId, factor, scope, key,
  memberId })` clears one counter and writes `verification.unlocked`.
- Limits across flows (VER-15): failure counters are pinned to subject or number and factor kind,
  never flow or call; flows that need a money, contact or access scope are limited per hour (10 per
  calling number, 5 per subject, Badge's `lockout.flowStartsPerHour`, defaults as ceilings), refused
  with one `rate_limited` answer (`RateLimitedError`, with the call's id) and a `flow.rate_limited`
  event; `startCall` and `startFlow` take `callingNumber`.
- Lockouts across calls (VER-1): an `AttemptCounters` adapter (`MemoryAttemptCounters`,
  `attemptCountersContract`) counts failures of every entered factor per subject and per calling
  number (`beginVerification({ callingNumber })`, kept as a keyed hash), before judging; a wait of
  5, 15, 60, 300 and 900 seconds and a hard lock after 10 failures in 24 hours, in Badge's `lockout`
  setting as defaults and floors; a `verification.locked` event. Badge needs `counters` when a
  factor the caller enters is on. A pass takes its own failure off the calling number with
  `AttemptCounters.removeFailure`, one atomic step.
- The accessible verification path (VER-11): keypad fields said instead of keyed through
  `spoken_knowledge` (never the PIN; read as 1 to 32 digits with `normaliseSpokenKeypadEntry`; each
  spoken try also uses a keypad attempt), `repeat` and `slower` request keys and a lengthened idle
  timeout on INT-1's `KeypadCollector` (`requestKeys`, `maxIdleTimeoutMs`, `lengthenIdleTimeout`;
  `Engine.keypadTiming`), and relay or TTY calls (`startCall({access})`) with longer timeouts and no
  other change.
- Risk-based step-up rules (VER-13): the policy's `stepUp` raises a scope's minimum on the amount,
  the time of day in its `timeZone`, or a signal the host raises with `raiseSignal`;
  `authorize(callId, scope, amount?)` and every step's own check (`requireScope`) use the raised
  minimum, a flow step it lifts fails naming the rule, and `policy.step_up` records the rule by
  name. The JSON Schema gains `timeZone`, `stepUp` and `stepUpRule`.
- Amounts from code, read back first (PAY-2): an `AmountSource` adapter (`amounts`, reference
  `PriceListAmounts`) resolves a `paylink.request` step's `amountRef`; `readBackPayment` builds the
  amount read-back in the call's locale (`AMOUNT_READBACK_TEXT`) and `confirmPaymentAmount` records
  the caller's yes before the link is texted.
- `SUPPORTED_LOCALES` (`["en", "fr", "es"]`, frozen; its members are the `Locale` type) and
  `isSupportedLocale`: `startCall` checks a locale against it, and the texts the engine sends and
  the amount formats are `Record<Locale, ...>` catalogs (`IDENTITY_TEXT`, `PAYMENT_TEXT`,
  `AMOUNT_REGION` and the others) that a test holds to every supported locale.
- Web sign-in step-up (GAT-4), the sixth built-in module (`step-up`, step `step-up.issue`, scope
  `entry.sign_in`): a 2 to 5 minute ES256 JWT bound to the site's nonce, the verified subject and
  the verification grant, with an OpenID Connect `acr`. The engine issues it and records its one
  exchange itself (ADR-25): `Engine.issueStepUpToken`, `exchangeStepUpToken`, `stepUpTokens` and
  `stepUpKeys` (the JWKS); the `stepUpSigner` adapter, its own key; `stepup.*` ledger events.
  Refused after the call is tainted or verified again, including when the call ends: the end refuses
  every token its call no longer vouches for. Receipts list a call's tokens (`stepUp`, optional, so
  receipts stay at `v: 1`).
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
- The signed-webhook relay adapter (GAT-2), `webhookRelay`, and an example door relay. An unlock is
  never retried; a lost answer is `unknown`.
- The Seam adapter (GAT-5), `seamAccessController`: checks the device can unlock remotely, unlocks
  once with no retry, `confirmed` only when Seam reports success, a lost answer `unknown`.
- Direct vendor adapters (GAT-6), `vendorAccessController` for Kisi and Verkada, through each
  vendor's documented unlock call; never retried, a lost answer is `unknown`.
- `FakeAccessController` in `district-assurance/testing`.
- One-time access codes (GAT-3): `accessCodes(...)`, an `AccessController` that texts an 8-digit
  code for an access grant to the number on file instead of working a door; codes kept only as keyed
  hashes (`AccessCodeStore`, `MemoryAccessCodeStore`), redeemed once within the grant's lifetime for
  the signed grant, revocable; texts counted against VER-2's per-subject limit in its `CodeStore`;
  `Engine.numberOnFile`.
- Paylink's two modes (PAY-7), `connect` and `platform`, per flow step; `linkLifeMinutes` (5 to 60,
  default 15) with the engine expiring links itself (`expirePaymentLinks`,
  `PaymentLinks.expireLink`); an allow-list of instant payment methods (card, Apple Pay, Google Pay,
  Link). Outcomes from another account than the payment's are ignored.
- Refunds and disputes in platform mode (PAY-8): `refundPayment` (full or partial, a host call for
  the business, refused while a dispute is open), `PaymentLinks.refund`, Stripe's `charge.dispute.*`
  events found by payment intent, `payment.refunded` and `payment.disputed` ledger entries; a
  `PaymentLinks.refund` is optional, so a host without it keeps its platform payment flows.
- Outside modules see the current step, the clock and an id source; outside a flow, their
  `updateModule` is held to every scope their manifest needs.
- `PaymentLinks.capabilities` (modes, shortest and longest link life), checked when the engine is
  built and when a config is saved. Connect-mode payments are bound per connected account.
- Grants, `verification.finished`, `grant.issued` and receipts name the `policyVersion` and
  `configRevision` that judged the caller (VER-8); optional on receipts, which stay at `v: 1`.
- `npm run demo:e2e`: the demo UI with a real Stripe Checkout Session in test mode, through a
  minimal PAY-1 adapter (`StripeCheckoutLinks`: platform mode, built-in fetch, `sk_test_` keys only,
  live and restricted keys refused). The payment is read back from Stripe; Gate's grant goes to the
  example door relay; the call ends with a receipt the page verifies.
- Texted one-time codes (VER-2): `Engine.sendTextCode` and `Engine.checkTextCode`, the `text_code`
  factor in Badge's settings, a `CodeStore` adapter (`MemoryCodeStore`, `codeStoreContract`) for
  send limits per subject and per calling number, and `textCodeCountryCodes` in the policy; a
  refused send answers like a sent one.
- Monthly report per business (PRV-8): `monthlyReport` counts one workspace's month from the ledger,
  in the host's time zone, as JSON and CSV signed with the receipt key under domain separation
  (`signReportJson`, `signReportCsv`, `verifyReport`). Counts and totals only.
- A demo UI on the reference server (`npm run ui`): pick a flow, run the scripted call one step at a
  time, and see the session state, the ledger entries and the signed receipt, verified in the
  browser against `/.well-known/receipt-keys.json`. Plain HTML, CSS and JavaScript, a fixed file
  allow-list, a strict CSP, no new dependency. The demo's script moves to `script.ts`, shared by
  `npm run demo` and the UI.
- The Stripe Identity adapter for the reference server (VER-5): `StripeIdentityProvider` creates a
  document VerificationSession with a matching selfie by `fetch` and a restricted key, and `npm run
  serve` with `STRIPE_IDENTITY_KEY` runs a trial call whose check comes back through the identity
  webhook.
- Key store contracts (INT-4): the knowledge key can be an opaque, asynchronous HMAC function (a key
  management service) that the engine and every factor hash through, `signReceipt` refuses a
  signature that is not 64-byte P1363, and `derToP1363` converts a key store's DER signature. A
  factor judge that throws or rejects (a key store outage) records no factor and writes
  `verification.factor_error`; the attempt stays counted.
- Spoken answers (VER-3): `normaliseSpokenAnswer` reads Canadian postal codes, US ZIP codes and
  short references spoken in English or French, exactly or `unusable`, and the `spoken_knowledge`
  factor compares them like keypad fields under the policy's new `spoken` fields.
- PIN enrolment and reset (VER-6): `enrolPin` lets a caller verified to level 2 on the call choose a
  PIN, keyed twice, weak PINs refused, stored through the new `RecordStore.putPinDigest`; `resetPin`
  is the business's host call; `pin.enrolled` and `pin.reset` events.
- Receipt key sets and rotation (PRV-1): `receiptKeyRing` holds several signers with one active and
  publishes retired public keys, `engine.receiptKeys()` and the reference server's key set route
  serve the whole history, so a receipt signed before a rotation still verifies. A retired key is
  published with `retired: true` and its `retiredAt`; `checkReceipt`, the stand-alone verifier and
  the demo page call such a receipt "valid, signed with a retired key (retired <time>)", and a
  receipt the retired key signed at or after its retirement invalid.
- A stand-alone receipt verifier (PRV-2): `scripts/verify-receipt.mjs`, with no dependencies, checks
  a receipt against a key set file or URL and prints valid or invalid; SPEC.md has a worked example.
- Duress PIN (VER-12), off by default (`pin.duress`): the business enrols it with `enrolDuressPin`,
  stored through the new `RecordStore.putDuressDigest`; a duress entry passes like the PIN to the
  caller while `authorize` refuses money, contact, access and `refuseScopes`, and the new
  `DuressNotifier` adapter is told of every duress entry from an alert owed in the call record until
  it answers (`deliverDuressAlerts` and `sweepAlerts` are the host's sweeps); a duress entry flags
  its subject until `clearDuress` (a host-privileged call; a `duress.cleared` ledger entry with an
  opaque member id and a keyed digest of the subject, never the subject key), the flag holds when
  the duress PIN is turned off and is set again on the alert's delivery unless the subject was
  cleared since, a flagged subject's passes alert once a call, and its failures stay counted in a
  hidden counter, which a PIN reset clears; every PIN ledger entry carries a keyed `tag` that
  `readPinTag` reads, and ledger event ids are numbered by the call's writes that queue entries (not
  the store version), so an alert's acknowledgement leaves no gap; `sweepAlerts` reports a call it
  cannot read as failed and goes on; a duress PIN entry whose own write fails still flags its
  subject; `clearDuress` clears the hidden counters of every installed factor.
- Carrier signal adapters for the reference server (VER-4): Twilio Lookup (SIM Swap, Identity Match)
  and Telnyx Number Lookup (porting status and date, the carrier), credentials from the environment,
  failing closed with `checked: false`; tested against a local fake server.
- An adversarial suite in English and Canadian French (VER-7): scripted dialogues run through a
  scripted host, checking no grant without factors, no text before a match, identical answers for
  unknown and wrong, and no grant after a taint.
- Badge factor plug-ins after the engine is built (MOD-3): `engine.useFactor(plugin)`, and outside
  modules that supply `factorPlugins` for the factors their manifest provides. The registry checks
  them for clashes and caller-ID names; they stay off until a config turns them on.
- Caller ID attestation (VER-10): `startCall({ attestation })` records the call's STIR/SHAKEN result
  (`A`, `B`, `C`, `failed`, default `none`) in `call.started` and the receipt (an optional field,
  format version 1), and the policy's optional `attestationCaps` can only lower a level. A callback
  call, which the engine dialled, is never capped.
- `KeypadCollector` (INT-1): a pure buffer for keypad tones until `#`, with a maximum length and an
  idle timeout, that shows no digit through `toString`, JSON or `util.inspect` and hands each entry
  to one callback. An overflowed or rejected entry is ignored to its end, and unknown options are
  refused.
- `auditLedgerContract` and `recordStoreContract` in `district-assurance/testing` (PRV-5), which the
  memory adapters pass; `MemoryRecordStore` now keys by JSON tuples, so two workspace and id pairs
  can no longer share a key. The session, ledger and record contracts keep keys that differ only in
  a lone UTF-16 surrogate apart, which a store encoding keys as UTF-8 would collapse.
- Read-backs (FIL-1; in Spanish too with FIL-6): `buildReadBack` and `engine.intakeReadBack` speak
  each field by type (dates in full, yes and no, numbers) with a fixed confirm prompt and never read
  a sensitive value; `confirmIntake` refuses a draft changed since the caller heard it.
- Conditional fields and validation rules (FIL-4): `showIf` (asked, read back and filed only while
  another field holds a value), `min` and `max` for numbers and dates, and a bounded `pattern` for
  text; `validateConfig` refuses unknown field settings, `showIf` cycles, and fields that name a
  card or a SIN.
- Spanish (FIL-6): an `es` locale for read-backs (US numbers and dates), identity and payment texts
  (amounts as `es-US`), optional Spanish form labels and consent wordings (a wording without one
  keeps its digest), Spanish digit words in card redaction, no Spanish spoken answers (a yes/no
  field takes no `sí`, and a Spanish call confirms its read-back on the keypad, until a reviewed
  Spanish vocabulary exists), a call in `es` refused when its flow needs a form or wording without
  Spanish, `startCall` refusing an unknown locale, and a parity test over every code-built string.
- Receipt links by capability token (SRV-3): `newReceiptLinkToken` and `receiptLinkTokenHash`; the
  reference server keeps only token hashes and serves `GET /r/:token`, a receipt page in English and
  French with its signature check, and `/r/:token.json`.
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
  holds a call open; `endCall` drops an open draft, so its values never outlive the call in the
  clear.
- Consent revocation (PRV-3): `Engine.revokeConsent` by voice, text or dashboard through a new
  `ConsentStore` adapter (`consents`; `MemoryConsentStore` in the fakes), a `consent.revoked` ledger
  event written once per consent and never before its `consent.recorded`, and `isStopRequest` for
  STOP, STOPALL, UNSUBSCRIBE, CANCEL, END, QUIT, ARRÊT, ARRÊTE and ARRÊTER. A consent still being
  stored when its call ends settles as not recorded (no consent): `consent.unrecorded` in the
  ledger, `answer: "not_recorded"` on the receipt.
- Record delivery (FIL-3): `deliverRecord` posts a confirmed record through a `RecordDelivery`
  adapter, signed in the `t=,v1=` HMAC scheme used for Stripe, retried with capped exponential
  backoff under one idempotency key per record and destination, with a `delivery.attempted` ledger
  entry per attempt and no payload in it; `FakeRecordDelivery` in `district-assurance/testing`; a
  sample receiver on the reference server at `POST /webhooks/records`.
- Documents by text (FIL-5): `createUploadLink` makes a single-use, 30-minute link bound to a call
  and a confirmed record, with allowed types and a size cap, storing only its token's hash;
  `acceptUpload` checks type, size and leading bytes, spends the link and asks the host's
  `DocumentScanner`; a `DocumentStore` adapter with `MemoryDocumentStore`; the reference server
  serves an upload page in English and French at `/u/:token`.
- Access and deletion requests for one subject (PRV-7): intake records carry the matched
  `subjectKey`, `RecordStore` gains `listIntakeRecords`, `deleteIntakeRecords`, `deletePinDigest`,
  `markSubjectErased` and `subjectErasures` (with `recordStoreErasureContract` in
  `district-assurance/testing`), and `putIntakeRecord` an optional `erasuresSeen`;
  `Engine.exportSubject` returns a signed export (its own domain, never a receipt;
  `verifySubjectExport`), and `Engine.eraseSubject` deletes the records and the PIN digest and
  appends `subject.erased`, leaving the ledger and receipts whole (ADR-28). A consent carries the
  matched `subjectKey` and an export lists only that subject's consents; a deleted record id is
  never stored again; each erasure gets its own entry, closed by `subject.erasure_completed`, and a
  retry after a partial delete finishes the same one.
- Carrier webhook signatures (SRV-1): `verifyTwilioSignature` and `verifyTelnyxSignature`, tested
  against Twilio's published examples and RFC 8032's Ed25519 vector; the reference server's
  `/webhooks/twilio` and `/webhooks/telnyx` routes check them instead of answering 501.
- Optional SQLite stores for the reference server (SRV-4): `SqliteRecordStore` and an append-only
  `SqliteAuditLedger` on `node:sqlite`, with no new dependency, that pass the PRV-5 contract suites
  and keep their data across a restart. `SqliteAuditLedger.list(fromSeq?, limit?)` reads one page of
  at most `limit` rows and refuses a `limit` that is not an integer of 1 or more, as the ledger
  contract (PRV-5) asks.
- `forwardingFor(state)` (INT-2): the single place a host asks whether it may forward the
  transcript, audio to speech-to-text, audio to the model and listen-in; all held while `sensitive`
  is set and after the call ends.
- Event delivery semantics (INT-5): the listener may be async, is never awaited, gets each entry's
  `eventId` and `seq`, and its failures go to `onListenerError`; `engine.flushPending()` is a
  background flush over the calls a session store lists with the optional `pendingCalls` (from
  `ledgerPending` write hints); an `auditLedgerContract` case for replayed event ids.
- security.txt (SRV-9): the reference server serves the host's own `/.well-known/security.txt` (RFC
  9116) from its `securityTxt` settings, refusing at start an `Expires` in the past or over a year
  ahead, or this project's own reporting address, and warning within 30 days (also once when a
  running server gets there, and once at expiry); SECURITY.md adds the scope and a thanks list.
- Public timestamp anchors for the ledger (PRV-9): `anchorLedger()` appends a `ledger.anchored`
  entry with a proof from an `Anchor` adapter, `verifyAnchor` checks it offline, and the reference
  server has an RFC 3161 time-stamp authority adapter and a Rekor v2 one; no new dependency.
- Anchors proven against real services (PRV-9): one anchor of a throwaway ledger, made through
  `anchorLedger()` with DigiCert's public time-stamp authority and Sigstore's Rekor v2 log
  (log2025-1), recorded in `test/fixtures/anchor/real/` by `test/fixtures/anchor/record-real.ts`
  and verified offline in `test/prove-anchor-real.test.ts`, including after the certificates expire.
- A flow simulator (MOD-4): `district-assurance simulate <config.json> --flow <name> --script <name
  or file>` (`npm run simulate --` here) runs a flow on the fakes with a scripted caller (`pass`,
  `wrong-pin`, `lockout`, `consent-no`, `payment-paid`, `payment-expired`, or a JSON file) and
  prints each step, decision, event and the receipt; a bad config or an outside module is refused.
- STRIDE tables in SECURITY-MODEL.md, one per module and adapter, each row naming its control and
  the test that proves it or its open issue, checked by `test/security-model.test.ts`; and an audit
  pack (`node scripts/audit-pack.mjs`, built in CI) with the test, coverage and contract suite
  reports, an SBOM and the documents (SRV-8).
- Reference server limits and logging (SRV-2): a body limit per route (`bodyLimits`: the three
  Stripe endpoints, the record receiver, Twilio, Telnyx and the demo runs; an upload keeps its
  link's cap), request timeouts (408 and 503), a per-address rate limit (429), and structured
  request logs by route pattern with no headers, bodies or link tokens (`logJsonLines`, on in `npm
  run serve`).
- A release workflow (SRV-5): a version tag on main runs CI and the supply-chain checks, a
  reproducible pack, a file list check and an exports smoke test as a dry run. Only a manual run on
  the tag with `publish` ticked, upstream and after an environment approval, publishes with npm
  provenance by trusted publishing. The package stays private (ADR-12). A local `npm pack` or `npm
  publish` builds first (`prepack`), so it never ships the documents without dist/; the workflow
  packs with install scripts off after its own clean build.
- Signed releases (SRV-6): each release has a CycloneDX SBOM of the published package with a
  Sigstore-signed attestation, attached to the tag's GitHub release; README.md shows how to check a
  release with `npm audit signatures` and `gh attestation verify`.
- Performance benchmarks (SRV-10): `npm run bench` measures the owner-command flow, a level 2
  verification, ledger appends, receipt signing and verifying, and `validateConfig` on a large
  config, on the memory adapters with `node:perf_hooks` only, and writes JSON with the machine and
  commit. CI runs it on a small budget; each release compares with the previous release on the same
  runner and reports a case over 20% slower in the run summary, never failing. BENCHMARKS.md.
- Property and fuzz tests (SRV-7, `test/property`, `test/fuzz`) for the ledger, the keypad
  collector, `validateConfig`, `canonicalJson`, the Stripe checks, the carrier signature checks and
  the reference server, on `fast-check` (a development dependency only), in CI and nightly
  (`fuzz.yml`); they found, and this fixes, `parseStripeEvent` reading event types like
  `constructor` from `Object.prototype` and `verifyChain` throwing on a stored entry changed to hold
  `1e999` instead of reporting the break.
- Ledger export (PRV-4): `exportLedger` yields the ledger as NDJSON from a `fromSeq` or a cursor,
  closed by an ES256-signed trailer with the run's start, end and the head; `verifyLedgerExport`
  checks a run and that it continues the previous one.
- `moduleContract(module)` in `district-assurance/testing`, the suite an outside module should pass
  (MOD-1), an example outside module (`examples/modules/callback.ts`) and a guide to writing one in
  ARCHITECTURE.md.
- A JSON Schema (2020-12) for FlowConfig version 1, `schema/flow-config.v1.json`, published with the
  package; tested against the TypeScript types and never stricter than `validateConfig` (MOD-2).
- A synthetic voice signal (VER-14): `reportSyntheticVoice(callId, {score, vendor})` and per-vendor
  thresholds in Badge's `syntheticVoice` setting stop spoken answers counting or hold the call to
  level 1, at once and for grants already issued; the ledger records the vendor and band, never the
  score, and the receipt neither.
- A live card-number detector (`LiveCardNumberDetector`, PAY-5) that tells the host to interrupt
  once a run of 8 or more digits is read, numerals or spoken; redaction now reads spoken numbers
  ("forty two", "quarante-deux", "double four") through `digitRuns`, tested over a shared JSON
  corpus, `test/corpus/card-numbers.json`.
- Spanish number words in redaction and the live detector: digit words, 10 to 29, the tens with "y",
  the hundreds and "mil" ("cuarenta y uno", "cuatro mil ciento once"), for Spanish calls (PAY-5).
- `SEPARATOR_CLASS`, the characters that may lie between the groups of one number (spaces, any dash,
  the minus sign, dots, commas, slashes, underscores, middle dots, format characters and combining
  marks), and `NUMBER_LANGUAGES`, `NUMBER_CONNECTORS`, `numberLanguagesFor` and `NumberLanguage`,
  exported from `district-assurance`. `LEXEME` matches every script's decimal digits, read by their
  values.
- More redactors (PRV-6): `sinRedactor`, `healthCardRedactor` (Ontario, British Columbia, Quebec)
  and `bankAccountRedactor`, each its own `Redactor` over the same digit runs as card numbers,
  tested over a shared JSON corpus in `test/corpus/`; compose health card numbers before SINs. Bank
  words are English, French and Spanish, read in the languages the call reads number words in:
  English and French on every call, Spanish on a Spanish call and on text with no call.
- README badges for the OpenSSF Scorecard, the licence and CI on main, and a section in
  CONTRIBUTING.md on reporting bugs and asking for features through GitHub issues.
- A README badge for the OpenSSF Best Practices badge (project 16957, passing).

### Changed

- The package is published: `package.json` no longer has `"private": true` (ADR-12), and 0.1.0 is
  the first version `release.yml` publishes to npm, with provenance. The publish job's
  `setup-node` names the npm registry (`registry-url`), as npm's trusted publishing guide has it.
- Breaking for hosts on Node.js older than 24.19: `engines` is `>=24.19` (was `>=24.2`), the first
  Node 24 where `crypto.argon2` is stable (it arrived in 24.7.0 as a release candidate), which PIN
  records use (ADR-4, ADR-29). CI runs 24.19 and the latest 24.
- Breaking for record stores: `RecordStore` has `upgradePinDigest(workspaceId, subjectKey, field,
  from, to)`, which replaces `pinDigest` or `duressDigest` only while it is still `from`, atomically
  (in `MemoryRecordStore`, `SqliteRecordStore` and `recordStoreContract`).
- Host-facing: `pinDigest` and `duressDigest` return an Argon2id record with a fresh salt, so two
  calls for the same PIN give different strings that both verify; compare records by checking, never
  by equality.
- `StripeCheckoutLinks` takes connect mode (`capabilities.modes` is now `["platform", "connect"]`):
  a direct charge on the connected account by the `Stripe-Account` header only, as Stripe's
  direct-charges guide has it. A connect request needs a well-formed `acct_` id and a platform
  request may name none, both checked before anything is sent; `readLink` checks the account too.
  Link alone is refused before anything is sent, since Checkout takes `link` only beside `card`
  (Stripe's recorded answer); Apple Pay and Google Pay still go as `card`.
- `createServe` (`npm run serve`) takes `ids`, for a run against Stripe repeated within a day.
- Host-facing: a call record is removed through `Engine.removeCall(callId)`, never in the session
  store directly. It is refused while the call has not ended and while its outbox holds ledger
  entries not yet appended (it flushes them first; `flushPending` keeps listing the call), while it
  still owes a duress alert, a contact notice or its receipt, while a payment link is still open
  or a refund is not yet final, and while a filed record's confirmed mark is owed (it makes the
  mark first), so a
  pending entry such as `consent.recorded` is never lost with its record. `SessionStore` has an
  optional `remove(workspaceId, callId, expectedVersion)` (in `MemorySessionStore` and
  `sessionStoreContract`).
- Breaking for record stores: `RecordStore` has `confirmIntakeRecord(workspaceId, recordId)` and
  `isIntakeRecordConfirmed(workspaceId, recordId)`. A record is stored unconfirmed and marked once
  the confirmation that filed it committed; `deliverRecord`, `exportSubject` and `createUploadLink`
  skip a record without the mark (one a refusal left behind when its delete failed), and an
  erasure still deletes it. A host store keeps the mark beside each record, and records it stored
  before this change read as unconfirmed until the host marks them. `MemoryRecordStore`, the
  reference server's `SqliteRecordStore` (a `confirmed_records` table) and `recordStoreContract`
  are updated.
- Breaking, reference server: the `maxBodyBytes` option of `createReferenceServer` is replaced by
  `bodyLimits`, one limit per route that reads a body (SRV-2).
- Breaking: `CarrierSignalReport` has a required `simSwapChecked`, true only when the carrier was
  asked about SIM changes and answered, and `textCodeTrusted` never trusts a texted code on a report
  without it, whatever the policy says (VER-4). The Telnyx adapter answers false; every
  `CarrierSignals` adapter has to set it.
- Breaking: the `AmountSource` string type (`intake_record`, `business_endpoint`, `price_list`) is
  renamed `AmountSourceKind`, and `AmountSource` is now the adapter interface (PAY-2).
- Breaking: `requestPayment` sends no link without a read-back the caller confirmed, for a fixed
  amount too. A host that calls it directly calls `readBackPayment`, speaks the text, and calls
  `confirmPaymentAmount` on the caller's yes first (PAY-2). The demo's deposit, connect-mode and
  live e2e flows read their amounts back first.
- Breaking for ledger adapters: `AuditLedger.list(fromSeq?, limit?)` reads one page of at most
  `limit` entries, and an adapter must honour it: `auditLedgerContract` fails a ledger that ignores
  `limit` or takes one that is not an integer of 1 or more. `MemoryAuditLedger` does, and
  `exportLedger` reads each run as one page instead of the rest of the ledger.
- Breaking, reference server: `timestampRequest(payload, nonce)` takes the nonce.
  `TimestampAuthorityAnchor` sends a fresh nonce with each request (a `nonce` option for tests) and
  refuses a token that does not echo it or whose imprint is not SHA-256; both anchor adapters read
  at most `maxReplyBytes` of a reply (`MAX_REPLY_BYTES`, 256 KiB) and never read an error answer's
  body; `RekorAnchor` asks the authority before Rekor, so a refused time-stamp writes nothing to the
  public log.
- Breaking for hosts, before v1: `refundPayment` requires a `sequence` (the refund's number for the
  payment, an integer of 1 or more; anything else is `invalid_input` before any write): the
  refund's key is the payment and that number, saved before the provider is asked, so a retry after
  a lost answer resumes the same key or gets the saved result back, and refunds once, when the
  retry reuses the same number.
- `PaymentLinks.createLink` takes a `PaymentLinkRequest` (mode, connected account, payment methods,
  expiry); `requestPayment` also returns `expiresAt`; receipts' payments carry `mode`.
- `canonicalJson` refuses a string or property name holding a lone surrogate (RFC 8785, section
  3.2.2.2), as do the stand-alone verifier and the demo page; an intake text value holding one is
  refused with the new normalise reason `not_text` (`NormaliseResult`), since no record, digest or
  read-back can hold it faithfully: a host that switches over the reasons must add it. A step whose
  ledger detail canonical JSON refuses (a lone surrogate, a `Date`) is refused before it is saved,
  `markUntrusted` repairs a lone surrogate in its label, and `validateConfig` refuses a config
  holding one.
- `confirmIntake` requires `readBack`, the digest of the read-back the caller heard (FIL-1), and the
  `buildReadBack` stub in `file/later.ts` is replaced by `file/readback.ts`. A host that confirmed
  without a read-back must call `intakeReadBack` first.
- The `revokeConsent` stub in `prove/consent.ts` is replaced by `Engine.revokeConsent`, and
  `ConsentRecord` moves to the adapter types (still exported from the root).
- The `deliverRecord` stub in `file/later.ts` is replaced by `deliverRecord` in `file/delivery.ts`,
  which takes the destination, the stores, the clock and the retry settings (SPEC.md, section 22).
- `RedactionContext`: `Redactor.redact(text, context?)` takes the call's `locale`, and
  `LiveCardNumberDetector` a `locale` option.
- English and French number words are read on every call; Spanish words only on a Spanish call, so
  on an English call "once", "dos" and "y" are words, not numbers (`Engine.redact` passes the call's
  locale, `numberLanguagesFor`). Text redacted with no call reads every language, the safe side.
- `Engine.redact` also returns `line`, the fixed interrupt line for the kind found, in the call's
  language (`INTERRUPT_LINES`), so a SIN or banking details never get the card number wording
  (PRV-6).
- `composeRedactors` reports finding offsets into the original input, no longer into the text each
  redactor saw (PRV-6).
- `applyFindings` takes findings in any order: it sorts them by position and merges overlapping ones
  before it applies them (PRV-6).
- `abandonIntake` releases a reserved filing: it deletes the record by id first
  (`RecordStore.deleteIntakeRecords`), so a later write of that id stores nothing, then drops the
  draft. A reserved filing resumes only while `intake.file` is still granted (VER-13 with FIL-1).
- The ledger is always on: Trace cannot be turned off or removed, and an engine needs a ledger.
  Receipts are per flow (`trace.receipt`) or Trace's `receipts` setting; `endCall` returns null when
  a call gets none.
- The policy, forms, consent wordings, grant lifetime and payment limit moved into FlowConfig;
  `startIntake` takes a form id and `recordConsent` a purpose.
- `state`, `authorize`, `setIntakeField` and `receipt` are asynchronous (the session store).
- A factor plug-in's `hmac(data)` is asynchronous (a `Promise` of the hex digest), so the knowledge
  key can live in a key management service. `subjectKeyFor`, `knowledgeDigest`, `pinDigest` and
  `judgeKeypadFactors` return a `Promise` when given an HMAC function; `judgeKeypadWith` always
  does.
- `returning_pin` is now `pin`; `returningCallerPin` is `enrolPin` (VER-6).
- Once a call's flow has ended, no step work runs on that call. A consent answered "no" fails its
  step unless the step says `require: "answer"`. Outside modules' steps are held to their scopes by
  the engine. Grants are checked against the config in force.
- Scope classes (money, contact, access, none) set the floors; level 2 needs a factor that is not
  knowledge; keypad attempts are capped at 5.
- Ledger entries are saved with each step and appended idempotently by `eventId` (`flushLedger`);
  `AuditLedger.append` is idempotent by `eventId`.

### Removed

- The Sinch webhook signature stub and its reference server route: the carriers are Twilio and
  Telnyx, and `CarrierSignals` stays vendor-neutral.
- `recordSubjectFailure`, replaced by `AttemptCounters` (VER-1).
- The reference server's `GET /receipts/:callId`, replaced by receipt links by capability token
  (SRV-3).

### Fixed

- `MemoryRecordStore.putIntakeRecord` keeps the first filing of a `recordId`, as the SQLite store
  does: a later put with other contents used to replace a confirmed record and keep its mark.
  `recordStoreContract` checks it.
- SECURITY-MODEL.md gives a duress PIN record its own namespace, `HMAC-SHA256(knowledgeKey,
  "duress:" + subjectKey + ":" + pin)`, as the engine keys it; it used to show `"pin:"` for both.
- The reference server remembers webhook event ids for 4 days (Stripe retries for 3) and at most
  10,000 of them, least recently seen first out, instead of in a set that grew without end.
- `validateConfig` refuses a policy list with a hole (a sparse `levels[].anyOf`, factor set or
  `keypadFields`) as a sentence; one used to throw a TypeError, found by the config fuzz suite.
- `verifyLedgerExport` answers `malformed` for an entry line that is not an object again, now that
  `verifyChain` reports such an entry as a break instead of throwing.
- The FlowConfig schema describes Gate's and step-up's settings and steps, and a receipt step's
  `textLink`; the release tarball allows and requires the schema.
- `RecordStore.deletePinDigest` also removes `pinEnrolmentId`, as a reset does, in the memory and
  SQLite stores, and `recordStoreContract` checks it.
- Reference server: `jsonLinesLog(stream)` (behind `logJsonLines`) drops entries while the stream is
  backpressured and writes one `log_entries_dropped` line on drain, and `stop()` ends it; `npm run
  serve` registers `guardLogStream`, so an error on standard output stops logging instead of ending
  the process. On Node.js 24.2, where `import.meta.main` is false for a `.ts` entry, `npm run
  serve`, `npm run demo` and `npm run demo:e2e` exited without running; their entry check
  (`isProgram`) now compares the resolved `argv[1]` with the module's own path. An upload that spent
  its link keeps its outcome until the link expires, so a retry gets the same answer (a received
  page names the document), and a retry while the first upload still runs gets 503 with
  `Retry-After`. Kept outcomes are never evicted before they expire: when `uploads.keptMax` (default
  10,000) are held, a new upload gets 503 with `Retry-After` before it claims its link, and is not
  scanned. A request whose connection closes before its answer is neither answered nor logged later.
  A client error behind pipelined requests waits for their answers. A `tel:` security.txt contact
  must be `+` and digits (with `-`, `.`, `(`, `)`), and a `warn` that throws no longer breaks the
  route.
- Monthly reports (PRV-8): payment totals are summed exactly, and a total past
  `Number.MAX_SAFE_INTEGER` refuses the report (`precondition_failed`), as `signReportJson` and
  `signReportCsv` refuse a report holding one; a `payment.link_sent` without a payment id counts as
  malformed.
- Simulator (MOD-4): after each wrong entry the caller waits out the backoff Badge's `lockout`
  setting gives, and a `badge.verify` step with a factor it has no caller for exits 3.
- The listener's copy of a `ledger.anchored` event is made inside the listener guard: a detail that
  cannot be copied skips the listener and is reported to `onListenerError`.
- Audit pack (SRV-8): a supplied SBOM goes in `sbom/supplied/`, so it never overwrites a manifest,
  and the coverage data goes in a new temporary folder that never overlaps `--out`.
- `accessKeys()` and `receiptKeys()` publish each key under its signer's `keyId`, as `stepUpKeys()`
  does, so a signer whose JWK has no `kid` no longer makes its grants and receipts unverifiable.
- `validateConfig` refuses a flow with more `gate.grant` steps than `maxGrantsPerCall`.
- `exchangeStepUpToken` and `applyPaymentOutcome` snapshot their input before they wait.
- A spent access code stays held, spent, until its `access.code_spent` entry is appended, so a
  failed append is made again on the next wrong guess (`AccessCodeStore.miss` marks entries spent
  instead of removing them).
- The amount read-back's digest includes a read-back id, so a late yes to an identical earlier
  read-back never confirms a new one.
- A resume never takes over a live send lease; a failed sender gives its lease back; a cancel or
  call end claims the close before asking the provider, so a resume never texts that link.
- A dispute event older than the status recorded (by Stripe's event time, or by stage) never
  replaces it, so a late inquiry snapshot cannot reopen `warning_closed`.
- `codes.issue` refuses a target that `codes.controller` does not work, before anything is reserved
  (`grantAccess` takes an optional `{controller}` guard); a limiter that throws is `refused`
  (`send_limit_unavailable`), never `unknown`.
- `access.code_spent` event ids carry the call id, and `AccessCodeStore.revoke` takes an optional
  `callId`, so two calls that share a grant id never lose each other's records or codes. A failed
  `access.code_spent` append is also made when the call ends and on `engine.sweepAccess()`
  (`AccessController.flush`, `AccessCodeStore.spent`).
- A newer dispute snapshot that changes nothing still moves its time on; a Stripe event whose
  `created` is past what a `Date` holds is malformed, not a throw.
- `requestPayment` checks a saved step's mode and link life against this engine's adapter, returns
  early when another resume already recorded the text, checks the link's life again after the lease
  is renewed, and tells the host to wait when a late link is `not_open`.
- `applyPaymentOutcome` answers `unbound` for a link no call holds yet, and the reference server has
  Stripe deliver it again (503).
- Reference server: Checkout's `expireLink` confirms Stripe expired that very session, Checkout and
  Identity URLs must parse as https, a long call id is hashed in Checkout metadata, every Checkout
  request pins `Stripe-Version`, the e2e payment wait closes its link at Stripe when it ends early
  and never sleeps past it, and `recordLinks` wraps a frozen adapter.

### Security

- PINs and duress PINs on file are Argon2id over the keyed HMAC (ADR-29):
  `$pin1$argon2id$v=19$m=19456,t=2,p=1$<salt>$<tag>`, with a random salt, the cost in the record,
  one Argon2id run per check whatever is on file, and a constant-time compare. A record at any
  cost but today's, or changed in any field, never matches, so a dearer record never takes longer
  to check than an unknown subject's stand-in. Records of the earlier
  format (the bare keyed HMAC) still verify and are replaced by an Argon2id record on the next match.
  Lockouts are unchanged.
- A taint now voids the keypad or PIN match made before it: `startPhotoId`, `checkCarrier` and a
  payment link refuse until a fresh verification matches (found by the adversarial suite).
- `sensitive_closed` (`closeSensitive`) is refused while a payment is open (`invalid_transition`):
  the payment hold ends only when the payment settles or fails, or the call ends, so a host cannot
  resume forwarding while the caller may be reading out card details.
- `confirmIntake` refuses a `confirmedBy` other than `voice` or `keypad` (`invalid_input`) before
  anything is written, so no host value reaches the record or the ledger unchecked.
- `verifyStripeSignature` throws `invalid_input` for a `toleranceSeconds` that is not an integer
  from 0 to 86,400, or a `now` that is not a valid `Date`: either could make a replay of any age
  pass.
- `verifyTelnyxSignature` refuses (`malformed_header`) a signature header whose unused trailing
  base64 bits are set: the decoder dropped them, so one valid signature had 16 spellings.
- Carrier webhooks: `verifyTwilioSignature` and `verifyTelnyxSignature` take the raw body as a
  `Uint8Array` too, and the reference server passes the bytes received, so two invalid UTF-8 bodies
  never verify under one signature; a Telnyx public key that is not a string is skipped.
- Stripe and record-delivery webhooks: `verifyStripeSignature` takes the raw body as a `Uint8Array`
  too, and the reference server's `/webhooks/stripe/*` and `/webhooks/records` routes verify the
  bytes received before decoding or parsing them, so a body under a bad signature is refused (400
  `signature`, as before) without being read, and two invalid UTF-8 bodies never verify under one
  signature.
- Anchors (PRV-9): `checkTimestamp` and `verifyAnchor` require the token's signed SigningCertificate
  or SigningCertificateV2 to name the authority's signing certificate (`certificate` otherwise; a
  token with neither, or one that does not read, is `token`). `checkRekorEntry` takes the index from
  the entry's top-level `logIndex` and the tree size and root from the signed checkpoint; the
  inclusion proof's own copies may be left out, as proto3 JSON leaves out defaults, and must agree
  when present. `isAnchorProof` counts only a proof's own keys, and `verifyAnchor` answers
  `malformed`, never throws, for an export holding null where an entry should be. New:
  `timestampTokenFields(token)`, the imprint hash and nonce a token carries. Offline verification
  otherwise checks what it did.
- SQLite stores (SRV-4): an existing file is checked by path (`lstat`), never opened outside SQLite,
  which would drop another connection's locks; a new file is created exclusively with mode 0600; a
  `-journal` file is checked as `-wal` and `-shm` are; a symbolic link (at the path or beside it)
  and anything that is not a regular file are refused; a database file on Windows is refused, since
  the mode sets no ACL there (`:memory:` still opens); -0 is kept through an escaped encoding; a
  failed open or schema closes the connection; a transaction SQLite already rolled back, or whose
  ROLLBACK fails, rejects with the error that caused it.
- Gate reads the call again right before the send, so a taint written after the reservation check
  stops it; a controller answer of the wrong shape is recorded `unknown` (`malformed_answer`), never
  `refused`.
- The Seam adapter refuses a grant signed for another device (`target_mismatch`); Seam, Kisi and
  Verkada refuse an unreadable clock or expiry (`grant_expiring`).
- A taint that lands while an access grant may still be acted on is ledgered against the grant
  (`access.tainted`), and the controller is asked to withdraw it through the new optional
  `AccessController.revoke` (`access.revoked`); access codes implement it. A grant already delivered
  and acted on cannot be pulled back. An access code is never texted to a call tainted while it was
  stored.
