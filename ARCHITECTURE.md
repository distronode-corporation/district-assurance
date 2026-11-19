# Architecture

## Where it sits

```
  caller's phone
       |
  carrier + SIP + speech + model          <- the host: not in this repository
       |
  host code paths: keypad events, tool handlers, webhook routes (any process, any replica)
       |
  +----v----------------------------------------------------------------+
  | Engine (src/engine.ts): one per workspace, per process              |
  |                                                                     |
  |   core/: session state machine, policy and levels, redaction,      |
  |          module registry, FlowConfig and validateConfig, flows,     |
  |          canonical JSON, hashing, clock and ids, adapters           |
  |                                                                     |
  |   modules (on or off per FlowConfig):                               |
  |     Badge verify/   Dossier file/   Paylink pay/   Trace prove/     |
  |     Gate gate/ (planned)            outside modules: engine.use()   |
  |                                                                     |
  |   webhooks/: Stripe signatures and event mapping                    |
  +----+----------------------------------------------------------------+
       | adapter interfaces (src/core/adapters.ts, EngineAdapters)
  SessionStore  AuditLedger  RecordStore  PinVerifier  IdentityProvider
  CarrierSignals  MessageSender  PaymentLinks  ReceiptSigner
       |
  the host's database and key store, Stripe, Twilio / Telnyx
```

The engine is a library. It holds no sockets and reads no environment. The host creates an
`Engine` per workspace with that workspace's FlowConfig, knowledge key and adapters, in every
process that handles the workspace's calls, and calls it from code. The model is never given the
engine, its inputs or its answers; it hears fixed lines the host speaks on the engine's results.

## The core

| Path | Holds |
|---|---|
| `src/core/session.ts` | `SessionState`, the events, `reduce` (pure) |
| `src/core/policy.ts` | factor kinds, levels, `validatePolicy`, `evaluateAssurance`, scope floors |
| `src/core/redaction.ts` | `Redactor`, Luhn, card numbers in digits and en/fr digit words |
| `src/core/module.ts` | the module interface (`AssuranceModule`, `ModuleManifest`) and `ModuleRegistry` |
| `src/core/config.ts` | `FlowConfig`, `validateConfig`, `ConfigError` |
| `src/core/flow.ts` | the current step of a call, and the rule that only it may run |
| `src/core/runtime.ts` | `EngineAdapters`, the call record, and what the built-in modules see of the engine |
| `src/core/session-store.ts` | `MemorySessionStore`, the reference `SessionStore` |
| `src/core/adapters.ts` | the adapter interfaces and record types |
| `src/core/canonical.ts`, `hash.ts`, `clock.ts`, `errors.ts`, `events.ts`, `shape.ts` | canonical JSON, hashing, injected time and ids, `EngineError` and `NotImplementedError`, event names, input checks |
| `src/engine.ts` | `Engine`: the call lifecycle, compare-and-set writes, flow execution, the module facade |

## The modules

| Module | Path | Provides | Needs | Adapters |
|---|---|---|---|---|
| Badge | `src/verify/badge.ts`, `factors.ts`, `knowledge.ts` | factors (`keypad_knowledge`, `pin`, `carrier_identity_match`, `photo_id`, planned `text_code` and `spoken_knowledge`, plug-ins), the `badge.verify` step, grants | | `records`, plus per factor: `carrier`; `identity` and `messages`; `pinVerifier` in verifier mode |
| Dossier | `src/file/dossier.ts`, `intake.ts` | the `dossier.collect` step, records | `intake.file` | `records` |
| Paylink | `src/pay/paylink.ts`, `payment.ts` | the `paylink.request` step, payments | `payment.request` | `payments`, `messages` |
| Trace | `src/prove/trace.ts`, `ledger.ts`, `receipt.ts`, `consent.ts` | the ledger (always on), the `trace.consent` and `trace.receipt` steps, receipts, consents | | `ledger`, `signer` while receipts are on, and optionally `consents` to revoke consents |
| Gate | `src/gate/` | planned (GAT-1): the `gate.grant` step, signed access grants | `entry.*` | `accessController` |

Each module is an object with a manifest and a few pure functions: `validateSettings`,
`requiredAdapters`, `validateStep`, `initCall` (its part of a new call record), `enterStep` and
`stepStatus` (where its current flow step stands), and optionally `stepLevel`, `stepGrants`,
`onUntrusted` and `receiptPart`. The registry refuses a manifest whose name, steps or factors clash
with an installed module. The built-in modules' runtime functions (Badge's `submitFactor`,
Paylink's `requestPayment` and so on) take the engine's internal runtime; hosts reach them through
the `Engine` methods.

Module boundaries: the core imports no module. Badge, Dossier and Trace import only the core.
Paylink imports Badge's `matchedSubject`, because a payment link goes to the number on file that
Badge matched. `src/modules.ts` lists the built-in modules and the default config, and
`src/engine.ts` composes everything.

### Outside modules

A host installs its own module with `engine.use(module)` (or `modules: [...]` at construction) and
turns it on in the config. Its steps can appear in flows, its settings are checked by its own
validator, and `validateConfig` holds its steps to the scopes its manifest says they need. At run
time the host's code changes the module's part of a call with `engine.updateModule(callId, name,
fn)`, one compare-and-set write, and reads it with `engine.moduleState`. `fn` sees the session
state, can ask whether a scope is authorized, and can write `module.event` ledger entries. A
running flow moves on when the module's `stepStatus` says its step is complete.

## One call, step by step

1. `startCall({ flow })` creates the call record in the SessionStore at version 1 and, with a flow,
   copies that flow's steps into the record and enters the first one.
2. Badge: `beginVerification` takes the keyed account number, or a subject key the host's code
   chose (for example the owner of the line). `openSensitive("keypad")` tells the host to pause its
   transcript and cut audio to speech-to-text and the model.
3. `submitKeypad`, `submitPin` or `submitFactor` count the attempt in one write, judge it, and
   record one factor in the next. `checkCarrier` asks about the number on file; `startPhotoId`
   reserves the call's one link, creates the check and texts the link to the number on file, and
   the provider's webhook arrives at `applyIdentityOutcome`.
4. `finishVerification` computes the level from the factors the current step allows, and issues a
   grant with the scopes the level reaches (only those the step names, when it names them), valid
   for 15 minutes by default. The flow moves on.
5. Dossier: `startIntake(formId)`, `setIntakeField`, `confirmIntake` need `intake.file`; the
   record is stored through `RecordStore` and its digest goes to the ledger and the receipt.
6. Paylink: `requestPayment` needs `payment.request`; in a flow the step sets the amount. The link
   is texted to the number on file, the call enters `paying`, and `applyPaymentOutcome` settles it
   only on `paid`. The flow moves on when it is paid, and fails when it failed or expired.
7. Trace: `recordConsent(purpose)` fingerprints the configured wording and stores the answer (in
   the host's `ConsentStore` too, when it has one); `revokeConsent` withdraws it later by voice,
   text or dashboard and writes `consent.revoked`.
8. `endCall` closes the session (abandoning a flow still running) and, when the call gets a
   receipt, takes the ledger head and signs it.

Every step appends to the `AuditLedger`, and the optional `onEvent` listener sees the same event.
While a flow runs, any work that is not the current step's is refused.

## Shared state across processes

A host whose voice agent and web backend are separate processes, or that runs several replicas,
gives every engine the same `SessionStore`. Each change to a call is one read, one pure change and
one compare-and-set write on the session's version; when another process wrote first, the change
is retried from a fresh read (five attempts, then `conflict`). Ledger entries for a change are
written only after its write succeeded. Work with side effects (a text, a provider call) is
reserved in one write and committed in another, so two processes cannot both send. Provider
references (identity sessions, payment links) are bound in the store, so a webhook can land on any
process.

## Trust boundaries

- **Model output** is untrusted: it never reaches an engine argument that decides anything. Text
  from business endpoints or documents is marked with `markUntrusted`, which drops the grant.
- **Webhooks** are untrusted until their signature verifies; the reference server checks it before
  parsing, applies each event id once, and the engine applies each outcome once.
- **Config** is untrusted until `validateConfig` passes: it comes from the host's storage and an
  operator's editor, and is checked field by field.
- **Adapters and outside modules** are trusted to do what they say. A host's adapters and modules
  are part of the host's security model, not this one. `SECURITY-MODEL.md` lists what is left to
  the host.

## Dependencies

None at runtime: `node:crypto` does the hashing, HMAC and ES256. Development uses TypeScript,
`@types/node`, oxlint and c8, pinned exactly. `DECISIONS.md` says why.
