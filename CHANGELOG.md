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
- `KeypadCollector` (INT-1): a pure buffer for keypad tones until `#`, with a maximum length and an
  idle timeout, that shows no digit through `toString`, JSON or `util.inspect` and hands each entry
  to one callback.
- `auditLedgerContract` and `recordStoreContract` in `district-assurance/testing` (PRV-5), which
  the memory adapters pass; `MemoryRecordStore` now keys by JSON tuples, so two workspace and id
  pairs can no longer share a key.
- Read-backs in English and French (FIL-1): `buildReadBack` and `engine.intakeReadBack` speak each
  field by type (dates in full, yes and no, numbers) with a fixed confirm prompt and never read a
  sensitive value; `confirmIntake` now requires the read-back's digest and refuses a draft changed since.
- Conditional fields and validation rules (FIL-4): `showIf` (asked, read back and filed only while
  another field holds a value), `min` and `max` for numbers and dates, and a bounded `pattern` for
  text; `validateConfig` refuses unknown field settings, `showIf` cycles, and fields that name a card or a SIN.
- Spanish (FIL-6): an `es` locale for read-backs (US numbers and dates), identity and payment texts (amounts as `es-US`), optional Spanish form labels and consent wordings (a wording without one keeps its digest), Spanish digit words in card redaction, `sí` and `si` in intake, a call in `es` refused when its flow needs a form or wording without Spanish, `startCall` refusing an unknown locale, and a parity test over every code-built string.

### Changed

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
