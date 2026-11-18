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

### Changed

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
