# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
  `CodeStore` (`CodeStore`, `CodeSendKey` and `MemoryCodeStore` are a stand-in copy of VER-2's
  shape until it lands); `Engine.numberOnFile`.
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

### Changed

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

- Carriers are Twilio and Telnyx: the Sinch webhook signature stub and its reference server route
  are removed. `CarrierSignals` stays vendor-neutral.

- The ledger is always on: Trace cannot be turned off or removed, and an engine needs a ledger.
  Receipts are per flow (`trace.receipt`) or Trace's `receipts` setting; `endCall` returns null
  when a call gets none.
- The policy, forms, consent wordings, grant lifetime and payment limit moved into FlowConfig;
  `startIntake` takes a form id and `recordConsent` a purpose.
- `state`, `authorize`, `setIntakeField` and `receipt` are asynchronous (the session store).
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
- Integration review, round 2 (L1):
  - A taint that lands while an access grant may still be acted on is ledgered against the grant
    (`access.tainted`), and the controller is asked to withdraw it through the new optional
    `AccessController.revoke` (`access.revoked`); access codes implement it. A grant already
    delivered and acted on cannot be pulled back. An access code is never texted to a call tainted
    while it was stored.
  - `codes.issue` refuses a target that `codes.controller` does not work, before anything is
    reserved (`grantAccess` takes an optional `{controller}` guard); a limiter that throws is
    `refused` (`send_limit_unavailable`), never `unknown`.
  - `access.code_spent` event ids carry the call id, and `AccessCodeStore.revoke` takes an optional
    `callId`, so two calls that share a grant id never lose each other's records or codes. A failed
    `access.code_spent` append is also made when the call ends and on `engine.sweepAccess()`
    (`AccessController.flush`, `AccessCodeStore.spent`).
  - `refundPayment` takes an optional `sequence`: the refund's key is the payment and that number,
    saved before the provider is asked, so a retry after a lost answer resumes the same key or gets
    the saved result back, and refunds once.
  - A newer dispute snapshot that changes nothing still moves its time on; a Stripe event whose
    `created` is past what a `Date` holds is malformed, not a throw.
  - `requestPayment` checks a saved step's mode and link life against this engine's adapter,
    returns early when another resume already recorded the text, checks the link's life again
    after the lease is renewed, and tells the host to wait when a late link is `not_open`.
  - `applyPaymentOutcome` answers `unbound` for a link no call holds yet, and the reference server
    has Stripe deliver it again (503).
  - Reference server: Checkout's `expireLink` confirms Stripe expired that very session, Checkout
    and Identity URLs must parse as https, a long call id is hashed in Checkout metadata, every
    Checkout request pins `Stripe-Version`, the e2e payment wait closes its link at Stripe when it
    ends early and never sleeps past it, and `recordLinks` wraps a frozen adapter.
