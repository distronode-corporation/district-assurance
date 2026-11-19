# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
- Key store contracts (INT-4): the knowledge key can be an opaque, asynchronous HMAC function (a
  key management service) that the engine and every factor hash through, `signReceipt` refuses a
  signature that is not 64-byte P1363, and `derToP1363` converts a key store's DER signature. A
  factor judge that throws or rejects (a key store outage) records no factor and writes
  `verification.factor_error`; the attempt stays counted.
- Receipt key sets and rotation (PRV-1): `receiptKeyRing` holds several signers with one active and
  publishes retired public keys, `engine.receiptKeys()` and the reference server's key set route
  serve the whole history, so a receipt signed before a rotation still verifies. A retired key is
  published with `retired: true` and its `retiredAt`; `checkReceipt`, the stand-alone verifier and
  the demo page call such a receipt "valid, signed with a retired key (retired <time>)", and a
  receipt the retired key signed at or after its retirement invalid.
- A stand-alone receipt verifier (PRV-2): `scripts/verify-receipt.mjs`, with no dependencies, checks
  a receipt against a key set file or URL and prints valid or invalid; SPEC.md has a worked example.

### Changed

- `canonicalJson` refuses a string or property name holding a lone surrogate (RFC 8785, section
  3.2.2.2), as do the stand-alone verifier and the demo page; an intake text value holding one is
  refused as `not_text`. A step whose ledger detail canonical JSON refuses (a lone surrogate, a
  `Date`) is refused before it is saved, `markUntrusted` repairs a lone surrogate in its label, and
  `validateConfig` refuses a config holding one.
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
