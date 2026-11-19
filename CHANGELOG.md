# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Gate, the fifth built-in module (GAT-1, ADR-25): signed, time-limited access grants (ES256 over
  canonical JSON, like receipts) after verification to `entry.open` (level 2 or more), delivered
  once through an `AccessController`. The engine owns every grant and outcome: it reserves, signs,
  computes the digest, calls the controller and records its answer. `Engine.grantAccess`,
  `accessGrants` and `accessKeys`; the `access` and `accessSigner` adapters; `access.*` ledger
  events. `verifyAccessGrant` (bound to a workspace) and `SeenGrants` for the access side.
- The signed-webhook relay adapter (GAT-2), `webhookRelay`, and an example door relay. An unlock
  is never retried; a lost answer is `unknown`.
- `FakeAccessController` in `district-assurance/testing`.
- Paylink's two modes (PAY-7), `connect` and `platform`, per flow step; `linkLifeMinutes` (5 to 60,
  default 15) with the engine expiring links itself (`expirePaymentLinks`, `PaymentLinks.expireLink`);
  an allow-list of instant payment methods (card, Apple Pay, Google Pay, Link). Outcomes from
  another account than the payment's are ignored.
- Refunds and disputes in platform mode (PAY-8): `refundPayment` (full or partial, a host call for
  the business, refused while a dispute is open), `PaymentLinks.refund`, Stripe's `charge.dispute.*`
  events found by payment intent, `payment.refunded` and `payment.disputed` ledger entries; a
  platform payment needs a payments adapter with `refund`.
- Outside modules see the current step, the clock and an id source; outside a flow, their
  `updateModule` is held to every scope their manifest needs.
- `PaymentLinks.capabilities` (modes, shortest and longest link life), checked when the engine is
  built and when a config is saved. Connect-mode payments are bound per connected account.
- The reference server's Connect webhook route; the demo takes a deposit in each mode and opens a
  door through the relay.
- ADR-21 to ADR-25.

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

### Changed

- `PaymentLinks.createLink` takes a `PaymentLinkRequest` (mode, connected account, payment methods,
  expiry); `requestPayment` also returns `expiresAt`; receipts' payments carry `mode`.

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
