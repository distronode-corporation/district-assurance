# Specification

Version 0 (pre-alpha). This document describes what the code in `src/` does today; anything
marked *planned* names its ROADMAP.md issue.

## 1. Session state machine

A session has a **phase** and, orthogonal to it, a **sensitive** flag, a **tainted** flag, the
recorded **factors**, the current **level** and an optional **grant**.

```
            verification_started                 intake_started
  +-----------+  <--------------  +------+  -------------->  +--------+
  | verifying |                   | open |                    | filing |
  +-----------+  -------------->  +------+  <--------------  +--------+
          verification_finished    |    ^   intake_confirmed, intake_abandoned
                                   |    |
                payment_requested  v    |  payment_settled
                                +--------+
                                | paying |
                                +--------+

  call_ended, from any phase but ended  ->  ended (final)
```

| Event | Allowed in | Effect |
|---|---|---|
| `verification_started {reset}` | open | phase `verifying`; factors cleared if `reset` or the session is tainted |
| `factor_recorded {factor}` | verifying | factor appended |
| `verification_finished {level, grant}` | verifying | phase `open`, level and grant set, sensitive cleared |
| `sensitive_opened {reason: keypad}` | verifying | sensitive `keypad` |
| `sensitive_closed` | verifying, paying | sensitive cleared |
| `intake_started` | open | phase `filing` |
| `intake_confirmed {recordId}` | filing | phase `open`, record id appended |
| `intake_abandoned` | filing | phase `open` |
| `payment_requested {paymentId}` | open | phase `paying`, sensitive `payment`, payment id appended |
| `payment_settled {paymentId}` | paying | phase `open`, sensitive cleared |
| `untrusted_content {source}` | any but ended | tainted (sticky), level 0, grant dropped |
| `call_ended {at}` | any but ended | phase `ended`, grant dropped, sensitive cleared |

Any other combination throws `EngineError("invalid_transition")`. `reduce` is pure; the engine is
the only caller in the package.

**Sensitive** means: the host pauses the live transcript and stored transcript, cuts audio to
speech-to-text and the model, and holds staff listen-in. The engine tracks the flag; the host
enforces it.

## 2. The call record and the SessionStore

A call is one JSON record: `{v: 1, state, locale, revision, flow, modules}`, where `state` is the
session above, `revision` the FlowConfig revision the call started under, `flow` the cursor of the
flow it runs (or null), and `modules` each enabled module's own part, created by its `initCall`
when the call starts. A module turned on after a call started has no part in it and is refused on
that call (`module_disabled`).

The record lives in a `SessionStore`:

- `create(workspaceId, callId, record, hint?)` stores it at version 1, or answers false if the id exists.
- `get` returns `{version, record}` or null.
- `compareAndSet(workspaceId, callId, expectedVersion, record, hint?)` writes only if the stored version is
  `expectedVersion`, and the new version is `expectedVersion + 1`; otherwise `{ok: false}`.
- `bindRef(workspaceId, ref, callId)` points a provider reference (`identity:<session id>`,
  `payment:<link id>`) at a call, first binding wins; `resolveRef` reads it.
- Optional: `pendingCalls(workspaceId, limit)` lists up to `limit` calls whose latest write had the
  hint `{ledgerPending: true}` (its outbox is not empty, section 9). The engine sends the hint with
  every write; a store that lists keeps the mark in the same write as the record, and a write
  without a hint leaves the mark as it was. A store lists the calls listed least recently first:
  the in-memory store rotates the list (listed calls go to the back), so a call that keeps failing
  cannot starve the others, and a durable store that always listed the same first `limit` would
  let up to `limit` failing calls hold back every other one. The contract checks that repeated small
  reads reach every pending call: three reads of one, and two reads of two, each reach all three of
  three pending calls.

Every engine step reads the record, applies one pure change, and writes it with compare-and-set.
On `{ok: false}` the step starts again from a fresh read, up to 5 attempts (`MAX_WRITE_ATTEMPTS`),
then throws `EngineError("conflict")`. Ledger entries and listener events for a step are written
only after its write succeeded. Steps with side effects use two writes or more: an attempt is
counted before it is judged; a photo ID link and a payment link are reserved before the provider
is called. `sessionStoreContract(factory)` in `district-assurance/testing` is the suite a store
must pass; `MemorySessionStore` is the reference.

## 3. Modules

A module is an `AssuranceModule`: a `manifest` and pure functions.

| Manifest field | |
|---|---|
| `name` | 2 to 32 of `a-z`, `0-9`, `-`, starting with a letter; not `core`, `engine`, `flow`, `module` |
| `provides.factors`, `.steps`, `.outcomes` | factor kinds (Badge), step types `<name>.<snake_case>`, outcomes |
| `scopes.grants`, `scopes.needs` | scopes it issues grants for; step type to the scope its step needs |
| `adapters` | the adapter names it always needs |
| `alwaysOn` | true only for Trace, which holds the ledger |

`ModuleRegistry.use` refuses a manifest with a bad or reserved name, a name or factor already
installed, a step not prefixed with the module's name, a scope need for a step it does not
provide, or a second `alwaysOn` module. `remove` refuses Trace. `Engine.remove` also refuses a
module the config has on.

| Built-in | Steps | Needs | Adapters |
|---|---|---|---|
| `badge` | `badge.verify` | | `records`; `carrier` with `carrier_identity_match`; `identity`, `messages` with `photo_id`; `pinVerifier` with `pin` in verifier mode |
| `dossier` | `dossier.collect` | `intake.file` | `records` |
| `paylink` | `paylink.request` | `payment.request` | `payments`, `messages` |
| `trace` | `trace.consent`, `trace.receipt` | | `ledger`; `signer` unless `receipts` is false |

## 4. Factors, levels and scopes

Built-in factor kinds: `keypad_knowledge`, `pin`, `carrier_identity_match`, `photo_id`,
`text_code` (planned, VER-2) and `spoken_knowledge` (planned, VER-3). A **factor plug-in** adds a
kind the caller enters and code judges: `{kind, summary, maxAttemptsPerCall (1 to 5), adapters,
judge}`, installed with `badgeModule({ factors })`. Its kind is snake_case, 3 to 32 characters, not
a built-in kind, and never `caller_id`, `calling_number`, `ani` or `cli`. Its judge gets the
subject, the entry and `hmac(data)` under the knowledge key, never the key. Caller ID is not a
kind.

A policy lists, per level 1 to 3, sets of factor kinds; a level is reached when every kind in one
of its sets has passed. `validatePolicy(policy, knownFactors)` refuses:

- a level outside 1 to 3, a level defined twice, an empty set, an unknown or repeated kind;
- at level 2 or 3, a set with fewer than two different kinds;
- at level 3, a set without `photo_id`;
- a set that is `text_code` alone;
- a set at level 2 or 3 made only of things the caller knows: it needs `text_code`,
  `carrier_identity_match` or `photo_id` (keypad knowledge, the PIN, spoken answers and plug-ins
  are knowledge);
- a scope with no class, or below its class's floor. A scope's class is the strictest of what its
  name implies (`payment.`, `payout.`, `refund.`, `transfer.`, `charge.`: money; `contact.`:
  contact; `entry.`, `access.`: access; `status.`, `intake.`: none), what an installed module's
  manifest declares (`scopes.classes`), and the policy's own `scopeClasses`. Money, contact and
  access are at least level 2; none is at least 0;
- `maxKeypadAttemptsPerCall` outside 1 to 5.

It checks every part in one pass: a malformed part is reported and the others are still checked.

The default policy: level 1 is keypad knowledge; level 2 is keypad plus a trusted texted code, or
keypad plus carrier identity match, or a PIN plus a texted code; level 3 is keypad plus photo ID.
Scopes: `status.read` 1, `intake.file` 1, `payment.request` 2, `contact.update` 3, `payout.update`
3. Two keypad attempts per call. A texted code counts only when the carrier answered and reported
no SIM change or port in the last 72 hours.

Badge's settings turn factors on (`factors`, at least one), set the grant lifetime
(`grantTtlSeconds`, default 900, at most 3600) and, when `pin` is on, the PIN settings (section 6).
A factor that is off is refused at every entry point. A planned factor cannot be turned on.

A **grant** carries the level, the scopes at or below it (narrowed to the verify step's `scopes`
when the step lists them), and an expiry. `authorize(callId, scope)` is true only for a scope the
policy lists, on a call that has not ended, whose minimum is 0 or whose grant includes it, has not
expired, and has a level at or above the scope's minimum under the config in force now.

Links go only to the subject's number on file, and only after a `keypad_knowledge` or `pin`
factor passed since verification last started from nothing. A plug-in's pass does not unlock
texts.

## 5. Keypad knowledge

- Subject key: `HMAC-SHA256(knowledgeKey, "subject:" + accountNumber)`, hex. A host may instead
  start verification with a subject key its own code chose (`{subjectKey}`, 64 lower-case hex);
  choosing the subject is not a factor.
- Field digest: `HMAC-SHA256(knowledgeKey, "field:" + field + ":" + value)`, hex.
- An entry counts only if it is 1 to 32 ASCII digits.
- `submitKeypad` compares every configured field, in constant time per field, even after a
  mismatch, and records one factor: passed only if the subject exists and every field matched.
- After `maxKeypadAttemptsPerCall` judged attempts, further submissions return `locked` without
  judging.

## 6. PIN

Settings: `{mode, minDigits (4 to 12), maxDigits (minDigits to 12), maxAttemptsPerCall (1 to 5)}`.

- An entry is well formed when it is ASCII digits with a length from `minDigits` to `maxDigits`.
  A malformed entry is still an attempt, and fails.
- `keyed_hash` mode: the stored digest is `pinDigest(knowledgeKey, subjectKey, pin)` =
  `HMAC-SHA256(knowledgeKey, "pin:" + subjectKey + ":" + pin)`, in `SubjectRecord.pinDigest`. The
  entry is hashed the same way and compared in constant time; an unknown subject, a subject without
  a digest and a malformed entry do the same work and give the same answer.
- `verifier` mode: the host's `PinVerifier.verify({workspaceId, subjectKey, pin})` decides; the
  PIN is passed once and kept nowhere. It is asked for every attempt: for a malformed entry or an
  account a keypad cannot produce, with a stand-in (`minDigits` zeros, an HMAC subject key) whose
  answer is ignored. A subject the `RecordStore` does not have never passes, whatever it says.
- Each attempt is counted in its own write before it is judged. Every `beginVerification` starts a
  new epoch; a factor result, a carrier report or a photo ID check from an earlier epoch is never
  applied (`precondition_failed`), and a change of subject drops pending photo ID checks.
- The photo ID link is reserved, created, enrolled and texted in turn; after a failure,
  `startPhotoId` resumes with the same idempotency keys, so a call never has two links. After `maxAttemptsPerCall`,
  `submitPin` returns `locked` without judging. Across calls: planned (VER-1). Enrolment: planned
  (VER-6).

## 7. FlowConfig

```json
{
  "version": 1,
  "revision": "2026-11-18.1",
  "policy": { "version": "...", "levels": [], "scopes": {}, "keypadFields": [], "maxKeypadAttemptsPerCall": 2,
              "simSwapWindowHours": 72, "trustTextCodeWithoutCarrierCheck": false },
  "modules": { "<name>": { "enabled": true, "settings": {} } },
  "flows": { "<name>": { "summary": "...", "steps": [{ "type": "<module>.<step>" }] } }
}
```

- `version` is 1. `revision` is the host's label, 1 to 64 of letters, digits, `.`, `:`, `-`, `_`;
  it is written in `call.started` and `flow.started`.
- A module listed and not `enabled: false` is on; an installed module not listed is off; Trace is
  always on and `enabled: false` on it is a problem.
- Flow names are lower-case letters, digits and hyphens, at most 64. A flow has at least one step.

`validateConfig(config, registry)` never throws and returns every problem, each starting with its
path (`modules.badge.settings: ...`, `flows.deposit.steps[2] (paylink.request): ...`). It checks
unknown fields at every level, the policy's shape and then its rules against the installed
factors, every module's switch and settings, every adapter an enabled module's settings need,
every step's module (installed and on) and the step itself, and, walking each flow in order, that
every step needing a scope comes after a `badge.verify` step whose level reaches that scope's
minimum and whose `scopes`, if listed, include it. Cross-checks against a module's settings or the
policy are skipped when those did not validate (their own problems are reported). The engine
refuses a config with any problem (`ConfigError`, code `invalid_input`, with `problems`).

| Step | Fields |
|---|---|
| `badge.verify` | `level` 1 to 3; `factors`, at least one, each on in Badge's settings, together reaching `level` under the policy; optional `scopes`, each in the policy at or below `level` |
| `dossier.collect` | `form`, a form id in Dossier's settings |
| `paylink.request` | `amountMinor`, `currency`, `description`, `amountSource` (section 14); `mode` is refused until PAY-7 |
| `trace.consent` | `purpose`, a wording in Trace's settings; `require`: `"yes"` (default) or `"answer"` |
| `trace.receipt` | none; needs the `signer` adapter |

Settings: Badge (section 4 and 6); Dossier `{forms}` (section 13, ids unique, no sensitive field
until FIL-2); Paylink `{maxAmountMinor?}` (1 to 1,000,000); Trace `{receipts?, wordings?}`
(`receipts` default true; wordings `{purpose (snake_case), version, text: {en, fr}}`, purposes
unique).

## 8. Flow execution

`startCall({flow})` or `startFlow(callId, name)`, on an open call that has not run a flow, copies
the flow's steps into the call record, so a later config change never moves a call. The first step
is entered: its module's `enterStep` returns a mark. After every change to the call, the engine
asks the current step's module for `stepStatus(step, {state, slice, mark})`:

- `pending`: the call stays on the step.
- `complete`: `flow.step_completed`, the next step is entered (and judged at once, so a
  `trace.receipt` step passes immediately); after the last, `flow.completed`.
- `failed`: `flow.failed`, and the flow stops.

| Step | Complete when | Failed when |
|---|---|---|
| `badge.verify` | a verification finished during the step at `level` or above | it finished below `level` |
| `dossier.collect` | a record of the step's form was confirmed during the step | never (abandon and start again) |
| `paylink.request` | the step's payment settled `paid` | it settled `failed` or `expired` |
| `trace.consent` | a consent for `purpose` was recorded during the step: "yes", or any answer with `require: "answer"` | the answer was "no" (default `require: "yes"`) |
| `trace.receipt` | at once | never |

While a flow runs, work that is not the current step's is refused with `precondition_failed`:
verification inputs outside a `badge.verify` step or for a factor it does not list, intake of a
form other than the step's, a payment outside its step or with an amount of its own (the step sets
it), a consent for another purpose. During a `badge.verify` step, only its factors count toward
the level. Once the flow has ended (completed, failed or abandoned), every step method is refused
on that call, an identity outcome is ignored, and an outside module's `updateModule` is refused;
grants the flow issued stand, and a payment link already sent can still settle. An outside
module's step is held by the engine to the scope its manifest needs. A step whose module was
removed while the call ran fails. `endCall` abandons a running
flow (`flow.abandoned`). `flowPosition(callId)` returns `{flow, revision, status, index, step}`.

## 9. Engine events

Each event is one ledger entry: `name`, `callId`, `actor` (`caller`, `ai`, `code`, `member`,
`system`), `at`, and a `detail` object that never carries a value the caller keyed, a PIN, an
answer on file, a phone number, a link or card data.

| Event | Detail |
|---|---|
| `call.started` | `locale`, `revision` |
| `flow.started` | `flow`, `revision`, `steps` (count) |
| `flow.step_completed` / `flow.failed` | `flow`, `step` (index), `type` |
| `flow.completed` | `flow`, `steps` |
| `flow.abandoned` | `flow`, `step` |
| `verification.started` | `subject`: `account` or `host` |
| `verification.factor` | `kind`, `passed` (and `status` for photo ID) |
| `verification.carrier_checked` | `checked`, `textCodeTrusted`, `identityMatch` |
| `identity.link_sent` | none |
| `verification.finished` | `level`, `methods`, `discounted` |
| `grant.issued` | `grantId`, `level`, `scopes`, `expiresAt` |
| `session.tainted` | `source` |
| `sensitive.opened` / `sensitive.closed` | `reason` / none |
| `intake.started` | `formId`, `version` |
| `intake.confirmed` | `recordId`, `formId`, `digest`, `confirmedBy` |
| `intake.abandoned` | none |
| `redaction.applied` | `kinds` (counts per kind) |
| `payment.link_sent` | `paymentId`, `linkId`, `amountMinor`, `currency`, `amountSource` |
| `payment.settled` | `paymentId`, `status` |
| `consent.recorded` | `consentId`, `purpose`, `wordingVersion`, `wordingDigest`, `answer`, `locale` |
| `call.ended` | none |
| `receipt.issued` | `receiptId`, `digest`, `kid` |
| `module.event` | `module`, `event`, `detail` (written by an outside module) |

The ledger is always on: every engine needs a `ledger` adapter, and Trace cannot be turned off.
A step's entries are saved in the call record's `outbox` by the same compare-and-set write, each
with an `eventId` (the JSON tuple `[workspaceId, callId, version, index]`, unique on a ledger that
several workspaces share), then appended in order; an entry the ledger would refuse (card data) is
refused before it is saved; the outbox is cleared by
a further write if nobody wrote since. A failed append leaves them pending, and the next write or
`flushLedger(callId)` appends them. A ledger appends an `eventId` once (a second append returns the
first entry), so nothing is lost or doubled.

`flushPending(limit = 100)` is the background flush a host schedules (for example every minute, in
any process): it asks the store's `pendingCalls` for up to `limit` calls and flushes each in turn,
returning `{flushed, failed}` (call ids); a call that fails stays pending for the next run, and
the others go on. A listed call with nothing pending (a write that sent no hint, from an engine
before INT-5, emptied its outbox and left the mark) is unmarked by a write with
`{ledgerPending: false}`; `flushLedger` itself writes nothing on an empty outbox. Two runs at once
append nothing twice. It throws `invalid_input` for a limit
that is not a positive integer, and `precondition_failed` when the store has no `pendingCalls`.
`auditLedgerContract(factory)` in `district-assurance/testing` checks that a ledger appends a
replayed run of event ids once, as a retried flush sends it.

The ledger is the source of truth; the `onEvent` listener is a notification. It is told of an entry
after the ledger has it, with the entry's `eventId` and `seq`, at least once and best effort: the
same event comes again, with the same `eventId`, when a flush replays it (after a lost clear, or
from another process), and one is missed when the process stops between the append and the call.
The engine calls the listener inline and never awaits it; a listener with slow work returns a
promise. A throw or a rejection is passed to `onListenerError(error, event)`, and a failure of
that hook is ignored: nothing the listener does stops the call, the write or the ledger. Any
returned value whose `then` is a function counts as a promise (one from another realm, or a
library's own thenable), and a `then` that throws when read is a listener failure too.

## 10. Audit ledger

Entry: `{seq, prevHash, eventId?, callId, actor, event, at, detail, hash}`. `seq` starts at 1; the first
`prevHash` is 64 zeros; `hash` is SHA-256 over the canonical JSON of every other field.
`verifyChain(entries, from?)` reports the first entry whose `seq`, `prevHash` or `hash` is wrong.
`chainEntry` refuses a detail in which any string (other than a 64-character hex digest) contains
a card number.

## 11. Canonical JSON

Object keys sorted by UTF-16 code units, no whitespace, strings and numbers as ECMAScript
`JSON.stringify` writes them. Refused: `undefined`, functions, symbols, bigints, non-finite
numbers, sparse array holes, and objects whose prototype is not `Object.prototype` or `null`.

## 12. Receipts

```json
{
  "body": {
    "v": 1, "receiptId": "...", "callId": "...", "workspaceId": "...",
    "startedAt": "...", "endedAt": "...", "issuedAt": "...",
    "verification": { "level": 3, "methods": ["keypad_knowledge", "photo_id"] },
    "records":  [{ "recordId": "...", "formId": "...", "digest": "<sha256 hex>" }],
    "payments": [{ "paymentId": "...", "status": "paid", "amountMinor": 15000, "currency": "cad", "providerRef": "cs_..." }],
    "consents": [{ "purpose": "...", "wordingVersion": "1", "wordingDigest": "<sha256 hex>", "answer": "yes" }],
    "ledger":   { "seq": 17, "hash": "<sha256 hex>" }
  },
  "alg": "ES256",
  "kid": "...",
  "signature": "<base64url of the 64-byte r||s signature over canonicalJson(body)>"
}
```

A call gets a receipt when its flow has a `trace.receipt` step (wherever it is, and whether
or not the flow finished), or, for a call that ran no flow, when Trace's `receipts` setting is not
false. `endCall` returns it, or null. `verification` comes from Badge, `records` from Dossier,
`payments` from Paylink and `consents` from Trace; a module that is off contributes an empty
part. `ledger` is the head after `call.ended`, kept in the call record. If signing fails, `endCall` on
the ended call issues the receipt later with the same head, without ending the call again. `verifyReceipt(receipt, keys)` picks the key by `kid`
and returns false for any change, a wrong algorithm, a malformed signature or an unknown key.
Record digests are `SHA-256(canonicalJson({formId, version, values}))`; wording digests are
`SHA-256(canonicalJson({purpose, version, text: {en, fr}}))`.

## 13. Intake values

| Type | Accepted | Stored as |
|---|---|---|
| `text` | trimmed, non-empty, at most `maxLength` (500), and no card number | string |
| `number` | `-?\d+(\.\d+)?` | number |
| `date` | `YYYY-MM-DD` naming a real day | string |
| `yes_no` | `yes`, `y`, `oui` / `no`, `n`, `non`, any case | boolean |

Forms live in Dossier's settings: a `formId` (lower case, digits, `-`, `_`), a `version` and
fields with snake_case unique keys, a known type and an English and a French label.
`validateConfig` refuses fields marked `sensitive` until field encryption exists (FIL-2).
`startIntake(callId, formId)` names the form, and the draft keeps the form as it was then, so a
config change mid-intake never changes what is filed; a call also keeps the forms (and Trace the
wordings) in force when it started. A draft being filed refuses changes. A filing that failed
after its reservation (the store refused it, or the last write was lost) stays reserved and
resumes with the same record on the next `confirmIntake`, so `RecordStore.putIntakeRecord` must be
idempotent by `recordId`; two confirmations at once file one record. A confirmation retried after its record was
filed (its ledger entry failed) returns the same record. `endCall` is refused while a record is
being filed. Provider idempotency keys are JSON tuples of the workspace, the call and the
operation, so workspaces sharing an adapter never share a key. A flow attached to a running call
is refused when a step needs a form or a wording the call did not keep.

## 14. Payments

`requestPayment` needs `payment.request`, a positive integer amount in minor units up to
Paylink's `maxAmountMinor` (at most 1,000,000), a lower-case ISO 4217 currency, a 1 to 200
character description and an `amountSource` (`intake_record`, `business_endpoint` or
`price_list`). In a flow they come from the `paylink.request` step and the host passes none;
outside a flow the host's code passes them. One link at a time per call. If creating or texting the
link fails, the request stays open (a provider can create a link and still fail to answer), and
calling `requestPayment` again resumes it with the same payment id and idempotency keys; a
different amount is refused. Only the provider settles a request. `requestPayment` returns the
status it saw last. Whose
account takes the money (`connect` or `platform`) is planned (PAY-7). Settlement:

| Provider outcome | Status |
|---|---|
| completed, `payment_status: paid` | paid |
| completed, `unpaid` | none yet (wait for the asynchronous result) |
| completed, `no_payment_required` | failed |
| async payment succeeded | paid |
| async payment failed | failed |
| expired | expired |

A request settles once; later outcomes are ignored.

## 15. Stripe webhooks

`verifyStripeSignature` follows Stripe's published scheme: the `Stripe-Signature` header has
`t=<unix seconds>` and one or more `v1=<hex>`; each `v1` is `HMAC-SHA256(secret, t + "." + raw
body)`. The check passes if any `v1` matches any configured secret and `t` is within 300 seconds
of now, either way. `parseStripeEvent` maps
`identity.verification_session.{verified,requires_input,canceled}` and
`checkout.session.{completed,async_payment_succeeded,async_payment_failed,expired}`; other types
are reported as ignored, and a body that is not a well-formed event is `null`.

## 16. Texts

Code builds every text, in the call's locale (English or French). The destination is always the
subject's number on file. Identity link: "Your one-time identity check link: URL" / "Votre lien
de vérification d'identité, à usage unique : URL". Payment link: "Your secure payment link for
AMOUNT: URL" / "Votre lien de paiement sécurisé pour AMOUNT : URL", with the amount formatted in
the currency's own decimals.
