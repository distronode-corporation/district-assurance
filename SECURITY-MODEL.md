# Security model

What the engine protects, what it trusts, the threats it is designed against, and what it leaves
to the host. Pre-alpha: these are design intentions backed by tests where marked, not an audited
claim.

## Assets

- The organisation's reference values (account numbers, dates of birth and similar) and PINs.
- What a verified caller may do: read status, file a record, request a payment, change contact
  or payout details.
- Card data, which the engine must never receive.
- The record of what happened on a call: the ledger and the receipts.
- The workspace's FlowConfig: which modules run, which factors count, which scopes a flow grants.

## Trusted and untrusted

| Trusted | Untrusted |
|---|---|
| The host's code paths that call the engine | Everything the caller says |
| The adapters the host plugs in | Everything the model says or proposes |
| The knowledge key and the receipt signing key | Caller ID and any number given on the call |
| The clock and id source | Webhook bodies until their signature verifies |
| The outside modules the host installs | Text from business endpoints, CRMs and documents |
| The SessionStore's compare-and-set | A FlowConfig until `validateConfig` passes |

## Threats and controls

### Social engineering of the AI

"I'm calling for my mother", urgency, authority, partial answers. **Control:** the model has no
path to a factor, a level or a grant. Scoped actions are refused by `authorize` until code issued
a grant (tested in `engine.test.ts`, "Engine authorize"). The host speaks fixed lines on refusals.
Planned: an adversarial evaluation set in English and French gating each release (VER-7).

### Account probing

Trying account numbers to learn which exist, or learning which factor failed. **Controls:** all
keypad fields are judged together and give one answer; an unknown account, a wrong value and a
non-keypad entry give the same result and the same ledger detail (tested), and the same holds for
the PIN: an unknown subject, a subject with no PIN and a malformed entry do the same keyed-hash work
and answer the same (tested); every field is compared even after a mismatch; nothing reads back a value on file; links go out only after a match, so a
text never confirms an account. Planned: per-subject and per-number counters across calls (VER-1).

### Guessing

**Controls:** a per-call limit on judged attempts for every factor the caller enters (keypad
knowledge, the PIN at 1 to 5, plug-ins at 1 to 5), after which the line stops judging, even the
right answer (tested). Each attempt is counted in its own write before it is judged, so a crash, a
failing PIN verifier or a second process never gives a free try (tested, two engines on one
store). PINs are at least 4 digits, and keypad attempts are capped at 5 per call like the PIN's.
**Hard gate:** durable lockout across calls (VER-1) must be merged before any host runs the
owner-command flow, or any PIN factor, on a live line. Without it, a 4-digit PIN with 3 attempts
per call falls within about 3,300 calls, half that on average. In `verifier` mode the host's PIN
store is asked for every attempt, with a stand-in for a malformed entry, so timing does not tell
them apart.

### SIM swap and port-out

An attacker who took over the number on file receives the texted code or link. **Controls:** a
texted code counts only when the carrier answered and reported no SIM change or port inside the
policy window (72 hours by default); without a carrier answer it does not count unless the policy
says so (tested). A texted code is never a factor alone, and level 3 requires a photo ID plus
selfie, which a stolen SIM alone does not pass. Contact and payout scopes default to level 3.

### Text flooding and SMS pumping

Repeated calls triggering texts to a real customer, or to premium numbers. **Controls:** texts go
only to the number on file, only after a keypad match, and at most one photo ID link per call
(tested). Planned: rate limits per subject and per calling number, and a destination country
allow-list, before texted codes ship (VER-2).

### Replay

Replayed webhooks, reused links, replayed tones. **Controls:** Stripe signatures are checked with a
300-second window and constant-time comparison (tested); the reference server applies each event
id once; the engine applies each identity session and each payment settlement once (tested).
Identity links are single-use by the provider. Left to the host: whether keypad tones arrive as
out-of-band events or as in-band audio on each carrier bridge, since in-band tones can be replayed
acoustically and can reach speech-to-text.

### Skipping steps and widening grants

A host bug or a manipulated tool path calling the engine out of order, or a grant for one purpose
used for another. **Controls:** while a flow runs, only its current step's work is accepted, and
only the step's factors count toward its level; once a call's flow has ended (completed, failed or
abandoned), no step work runs on that call at all, so a failed PIN cannot be followed by a fresh
verification outside the flow (tested). With the default `require: "yes"`, a consent answered "no"
fails its step, so the flow never reaches a payment after a refusal (tested); a step set to
`require: "answer"` moves on either way, by the config's choice. An outside module's step is held to the scope its
manifest needs by the engine itself (tested). An issued grant is checked against today's minimum
too, so a stricter config applies at once (tested). A `badge.verify` step can name the scopes
its grant covers, and the demo flows do, so a caller verified for a deposit never holds
`owner.command` (tested). `validateConfig` refuses a flow whose step needs a scope its earlier
verification does not reach or grant, and the policy's floors hold whatever a config says: every
scope has a class (by its name, a module's manifest, or the policy's `scopeClasses`, the strictest
winning), money, contact and access are never below level 2, and a scope with no class is refused
(tested). Level 2 and above need a factor that is not something the caller knows (tested).

### Config tampering

Someone who can edit a workspace's FlowConfig. **Controls:** the engine refuses any config with a
problem, Trace (the ledger) cannot be turned off, the floors cannot be lowered, planned factors
and payment modes cannot be turned on, and every call's ledger entries carry the config revision
it ran under. Who may edit a config, and how its history is kept, is the host's (left to the host).

### Races across processes

Two processes acting on one call at once. **Controls:** every change is a compare-and-set on the
call's version, retried from a fresh read; links are reserved before they are created, so two
processes cannot both send one; a lost race writes nothing to the ledger (tested). A durable store
must pass `sessionStoreContract`.

### Prompt injection

A webhook reply, a CRM note or a document says "ignore the rules". **Controls:** `markUntrusted`
taints the session, drops the grant and sets the level to 0; the next verification starts from no
factors, and a photo ID link sent before the taint no longer counts (tested). Fetched text never chooses a tool, a recipient or an amount: amounts come from
the host's code with an `amountSource`, and destinations come from the subject record.

### Card data and PCI DSS scope

**Controls:** Pay is by a hosted payment page; the engine sees a link id and a status, never a card
number. Card numbers in transcripts are detected (Luhn, digits and English or French digit words)
and replaced, and the host is told to interrupt (tested). Intake refuses a value carrying a card
number, and the ledger refuses detail carrying one (tested). Keypad card capture is planned only
through a PCI-certified carrier service on a call path where tones never reach this engine
(PAY-6), after an assessor's scoping. Nothing here is a PCI DSS attestation; a host's scope
depends on its whole call path.

### Tampering with the record

**Controls:** the ledger is hash-chained, and any changed, removed or reordered entry is detected
(tested). Receipts are signed with ES256 over canonical JSON and carry the ledger head; one changed
byte fails verification (tested). Planned: key rotation and a published key set history (PRV-1).
A step's ledger entries are saved with the step itself (an outbox in the call record) and
appended by event id, once each; a ledger that fails leaves them pending, and the next write or
`flushLedger` appends them, so no saved step is ever missing from the ledger for good (tested).

### Breach of stored data

**Controls:** reference values are HMACs under a per-workspace key, because a plain hash of a date
of birth is reversed by trying every date; the caller's entries are never stored. Sensitive intake
fields are refused by `validateConfig` until field encryption exists (FIL-2). PINs on file are
HMACs bound to their subject, or stay in the host's own PIN store (`verifier` mode).

## STRIDE tables

One table per module and per adapter, plus the core, the webhook checks, the reference server and
the release. Each row is one way to attack that part, sorted by STRIDE: **S**poofing,
**T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of
privilege.

- **Status** is `covered` or `open`. A `covered` row's control is built, and **Proof** names the
  tests that prove it, as `file`: "test name" (a file under `test/`, and the name of an `it` or a
  `describe` in it). An `open` row's control is not built yet, and **Proof** names the ROADMAP.md
  issue that builds it. A row is never `covered` on the strength of an issue.
- `test/security-model.test.ts` checks every table: each named test exists, each open row names an
  open issue in ROADMAP.md, no covered row cites an issue as its proof, and every built-in module
  and every adapter in `EngineAdapters` has a table.
- What the host must do itself is in "Left to the host" below, not in these tables. A row here may
  still name the engine's part of a host duty (for example, never passing an unknown subject
  whatever the host's `PinVerifier` says).
- When a control changes, its row changes in the same pull request. When an issue closes, its rows
  become `covered` with their tests.

`scripts/audit-pack.mjs` gathers these tables with the test, coverage and contract suite reports,
the SBOM and the documents, for an outside audit.

### Core

The session state machine, the policy and its levels, FlowConfig and `validateConfig`, the module
registry, flows, redaction, canonical JSON and hashing (`src/core/`, `src/engine.ts`).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| core-1 | E | The model, or a manipulated tool path, runs scoped work before any verification. | `authorize` refuses an unknown scope, an ended call, and a missing or expired grant. | covered | `engine.test.ts`: "refuses unknown scopes, ended calls, missing and expired grants" |
| core-2 | T | An event applied in a phase that does not allow it moves the call to a state it should not reach. | `reduce` accepts each event only in its listed phases. | covered | `session.test.ts`: "allows each event only in its listed phases, in every phase" |
| core-3 | E | A host bug calls the engine out of order to skip a step, or verifies again after a failed flow. | Only the current step's work runs, only its factors count, and nothing runs after the flow ended. | covered | `flows.test.ts`: "refuses every step on a call whose flow ended (review blocker 1: no escalation after a failed PIN)"; `flows.test.ts`: "counts only the step's factors toward its level" |
| core-4 | E | A config puts a money scope below level 2, renames it to dodge the floor, or reaches level 2 with two things the caller knows. | Scope classes set floors that a config cannot lower; a scope with no class is refused; level 2 needs a factor that is not knowledge. | covered | `policy.test.ts`: "holds money scopes at level 2 whatever they are called, and refuses a scope with no class"; `policy.test.ts`: "refuses level 2 from two things the caller knows (keypad and PIN)"; `policy.test.ts`: "never lets a class loosen what a name or a module says" |
| core-5 | T | Someone who can edit a FlowConfig turns the ledger off, adds an unknown module or a malformed step. | `validateConfig` names every problem and never throws; the engine refuses a config with any problem. | covered | `config.test.ts`: "refuses unknown modules, malformed entries, unknown fields, and turning the ledger off"; `config.test.ts`: "never throws on garbage, and names every problem with its path"; `engine.test.ts`: "refuses a short key, an empty workspace, a missing ledger and a bad config" |
| core-6 | E | A grant issued under a looser config is used after the config was made stricter. | An issued grant is checked against the minimum in force today. | covered | `engine.test.ts`: "holds an issued grant to a stricter minimum set later (review item 9)" |
| core-7 | T | A config change in the middle of a call moves that call to other steps. | A call copies its flow's steps when it starts and keeps them. | covered | `flows.test.ts`: "keeps a call on the steps it started with when the config changes, and refuses bad configs" |
| core-8 | E | Text from a CRM, a document or a webhook reply tells the model to ignore the rules, and a grant survives it. | `markUntrusted` taints the session, drops the grant and sets the level to 0; the next verification starts from no factors. | covered | `engine.test.ts`: "drops the grant when untrusted text enters, and re-verification starts from nothing"; `session.test.ts`: "keeps factors across a step-up and drops them on reset or after taint" |
| core-9 | E | An outside module's step runs without the scope its manifest needs. | The engine holds every outside step to its manifest's scope, whether or not the module asks. | covered | `flows.test.ts`: "holds an outside module's step to its scope even when the module never asks (review item 3)" |
| core-10 | S | An outside module or a factor plug-in takes a built-in name, or makes caller ID a factor. | The registry refuses clashing manifests and plug-ins, and any factor named for caller ID. | covered | `config.test.ts`: "refuses bad and clashing manifests, with every problem"; `config.test.ts`: "refuses bad factor plug-ins" |
| core-11 | T | Two encodings of the same data hash or sign differently, or a value JSON cannot carry is signed. | Canonical JSON sorts keys and refuses values it cannot carry faithfully. | covered | `core.test.ts`: "sorts keys, drops whitespace and serialises like JSON.stringify"; `core.test.ts`: "refuses values JSON cannot carry faithfully, naming the path" |
| core-12 | I | Comparison timing tells a caller how much of a digest matched. | Digests are compared in constant time. | covered | `core.test.ts`: "compares digests in constant time and refuses anything that is not lower-case hex" |
| core-13 | I | A card number read aloud reaches the transcript, the model or a log. | The redactor finds card numbers in digits and English or French digit words, and the engine counts findings without logging the text. | covered | `redaction.test.ts`: "finds numbers spoken as digit words in English and French"; `engine.test.ts`: "redacts text and counts findings by kind, without logging the text" |
| core-14 | I | A card number spoken in pieces, or only partly, slips past the redactor. | A live detector for partial and spoken numbers. | open | PAY-5 |
| core-15 | I | Other identifiers (social insurance, health card and bank account numbers) reach the transcript. | More redactors. | open | PRV-6 |
| core-16 | I | An outside module's ledger detail carries a card number. | The entry is refused before anything is saved. | covered | `flows.test.ts`: "refuses an outside module's entry that carries a card number, before anything is saved" |
| core-17 | D | A host's event listener that throws or rejects stops the call or the ledger. | Listener failures are caught; the ledger is written regardless. | covered | `engine.test.ts`: "keeps writing the ledger when the listener throws"; `engine.test.ts`: "catches a listener's rejected promise" |
| core-18 | R | A host's listener misses an event and nobody is told. | Defined delivery semantics and an `onListenerError` hook. | open | INT-5 |
| core-19 | E | The model is talked into acting for someone else (urgency, authority, "calling for my mother"). | An adversarial evaluation set in English and French gating each release. The model already has no path to a factor, a level or a grant (core-1). | open | VER-7 |
| core-20 | I | A host keeps forwarding audio or transcript to the model while keypad digits or a payment are in progress. | One helper that says what a host may forward for the current session. | open | INT-2 |
| core-21 | T | An outside module's validators throw on garbage, or its step status is not pure, and a bad config passes. | A contract suite for outside modules. | open | MOD-1 |

### Badge

Who is calling, in levels (`src/verify/`).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| badge-1 | S | A caller guesses keypad knowledge or a PIN within one call. | A per-call limit on judged attempts for every entered factor; after it, even the right answer is not judged. | covered | `engine.test.ts`: "locks keypad judging after the policy's attempts"; `pin.test.ts`: "counts malformed, wrong and unknown-subject entries the same way, and locks after the limit"; `policy.test.ts`: "caps keypad attempts like the PIN" |
| badge-2 | S | A caller guesses a PIN across many calls (a 4-digit PIN with 3 attempts per call falls within about 3,300 calls). | Durable failure counters and lockout per subject and per calling number. Hard gate before any live PIN. | open | VER-1 |
| badge-3 | S | A crash, a failing PIN verifier or a second process gives a caller a free try. | Each attempt is counted in its own write before it is judged. | covered | `pin.test.ts`: "counts the attempt before asking, so a verifier that fails still uses it"; `session-store.test.ts`: "gives two concurrent attempts on one call one counted attempt each, never more than the limit" |
| badge-4 | I | A caller learns which accounts exist, or which field was wrong. | All keypad fields are judged together; an unknown account, a wrong value and a non-keypad entry answer the same, and so do the PIN's cases. | covered | `engine.test.ts`: "gives the same answer for an unknown account, a wrong value and a non-keypad entry"; `modules.test.ts`: "never passes a non-keypad entry, even one whose digest is on file"; `pin.test.ts`: "counts malformed, wrong and unknown-subject entries the same way, and locks after the limit" |
| badge-5 | I | Stored reference values or PIN digests are reversed, or two equal PINs show as equal digests. | Keyed HMACs per workspace key, field and value; PIN digests are bound to their subject. | covered | `modules.test.ts`: "derives stable keyed digests that differ per key, field and value"; `pin.test.ts`: "binds the digest to the subject" |
| badge-6 | I | A factor plug-in reads the knowledge key. | Plug-ins get `hmac(data)`, never the key, and their attempts are limited. | covered | `pin.test.ts`: "judges a host's own factor with the keyed hash, never the key, and limits its attempts" |
| badge-7 | S | An attacker who took over the number on file (SIM swap, port-out) passes as the caller. | A carrier answer is needed, and a recent SIM change or port inside the window discredits a texted code; a carrier mismatch is a failed factor. | covered | `policy.test.ts`: "needs a carrier answer by default"; `policy.test.ts`: "refuses a recent SIM swap or port, inside the window"; `policy.test.ts`: "does not count a texted code the carrier signals discredit"; `engine.test.ts`: "records a carrier identity mismatch as a failed factor" |
| badge-8 | E | A result judged for one subject (a factor, a carrier report, a photo ID outcome) is applied after verification restarted for another. | Results are bound to the subject they were judged for, and late outcomes are ignored. | covered | `pin.test.ts`: "never applies a factor judged for a verification that restarted for another subject"; `flows.test.ts`: "ignores a photo ID outcome that arrives after the flow moved on"; `engine.test.ts`: "ignores a photo ID outcome for a link sent before the taint" |
| badge-9 | E | A caller who failed for one account keeps those factors after switching to another. | Factors are kept for a step-up on the same account and dropped for another. | covered | `engine.test.ts`: "keeps factors for a step-up on the same account and drops them for another"; `engine.test.ts`: "starts over on another account number" |
| badge-10 | E | A caller enters a factor that is turned off, or one the caller does not enter. | Such entries are refused. | covered | `engine.test.ts`: "refuses factors that are turned off, and entries for factors the caller does not enter" |
| badge-11 | S | A weakly verified caller chooses or resets the owner's PIN on the line. | Enrolment only at level 2 on the call, weak PINs refused, reset by the business only. Today there is no enrolment at all. | open | VER-6 |
| badge-12 | S | A spoken answer is misheard or injected into speech-to-text. | Spoken answers normalised by code, with their own limits. | open | VER-3 |
| badge-13 | I | Keypad digits leak from the host's buffer into a log or a string. | A keypad collector that exposes no digits. | open | INT-1 |

### Dossier

Intake the caller confirms (`src/file/`).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| dossier-1 | E | A caller files a record without the `intake.file` scope, or after the grant lapsed. | Intake needs the scope at start and again at confirmation. | covered | `engine.test.ts`: "refuses intake without the scope, an unknown form, and abandons"; `engine.test.ts`: "re-checks the grant at confirmation" |
| dossier-2 | T | Two confirmations of one draft, or a lost write, file two records. | One record per draft, reserved while it is filed and resumed with the same id. | covered | `engine.test.ts`: "files one record when two confirmations of the same draft run at once"; `session-store.test.ts`: "resumes a filing whose last write was lost, with the same record" |
| dossier-3 | I | A caller reads a card number into an intake field. | Intake refuses a value that carries a card number. | covered | `modules.test.ts`: "normalises each field type" |
| dossier-4 | I | A sensitive field (a social insurance number) is stored in the clear. | `validateConfig` refuses sensitive fields until encrypted fields exist (FIL-2). | covered | `config.test.ts`: "checks dossier settings" |
| dossier-5 | T | A form edited in the middle of a draft changes what the caller is confirming. | A draft keeps the form it started with. | covered | `flows.test.ts`: "keeps the form a draft started with when the config changes the form" |
| dossier-6 | R | A caller disputes a value because it was never read back to them. | Read-backs in English and French before confirmation. | open | FIL-1 |
| dossier-7 | T | A record delivered to the business is forged, changed or replayed on the way. | Signed delivery webhooks with retries and idempotency. | open | FIL-3 |
| dossier-8 | S | A document upload link is guessed or reused. | Single-use upload links. | open | FIL-5 |

### Paylink

Payment by a link texted to the number on file (`src/pay/`).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| paylink-1 | E | A payment is requested without the `payment.request` scope, or with a bad amount. | The scope is required; amounts and descriptions are checked. | covered | `engine.test.ts`: "refuses without the scope, without an amount, and refuses bad amounts and descriptions"; `modules.test.ts`: "validates amounts and currencies" |
| paylink-2 | T | The model or the caller chooses the amount. | In a flow, the step sets the amount. | covered | `flows.test.ts`: "runs deposit end to end, with the amount from the flow and a receipt" |
| paylink-3 | R | The caller disputes an amount that was never read back before the link was sent. | Amounts from code, read back first. | open | PAY-2 |
| paylink-4 | S | A payment link goes to the calling number or one the model supplied. | The link goes to the number on file only. | covered | `engine.test.ts`: "texts a link to the number on file and settles only on paid" |
| paylink-5 | T | A failed, expired or forged outcome settles a payment. | A payment settles only on `paid`, and once. | covered | `modules.test.ts`: "settles as paid only when the provider says paid"; `flows.test.ts`: "refuses the wrong form or consent purpose for the step, and fails on an unpaid link" |
| paylink-6 | E | A caller who refused consent is still taken to a payment. | A consent of no fails its step before any money step. | covered | `flows.test.ts`: "fails the flow on a consent of no, before any money step (review blocker 2)" |
| paylink-7 | E | A link stays payable after the call or after it should have been withdrawn. | Cancel and expire open links. | open | PAY-3 |
| paylink-8 | E | A payment lands in the wrong Stripe account (the business's or the platform's). | `connect` and `platform` modes; until then `validateConfig` refuses a step with a mode. | open | PAY-7 |
| paylink-9 | I | Card numbers keyed on the phone reach the engine. | Keypad card capture only through a certified carrier service, gated on an assessor's scoping. Today there is no keypad card capture at all. | open | PAY-6 |
| paylink-10 | E | A saved card is charged for a weakly verified caller. | Saved-card charges gated on level 2 and amounts from code. Not built. | open | PAY-4 |

### Trace

The hash-chained ledger, receipts and consent (`src/prove/`).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| trace-1 | T | A ledger entry is changed, removed or reordered, or a caller rewrites history through a shared reference. | A SHA-256 chain over canonical JSON, verified end to end; the ledger stores copies. | covered | `prove.test.ts`: "detects a changed, removed or reordered entry"; `prove.test.ts`: "stores copies, so a caller cannot rewrite history" |
| trace-2 | T | A receipt is forged or changed. | ES256 over canonical JSON, with the ledger head; any change, a wrong key or an unknown `kid` fails. | covered | `prove.test.ts`: "fails on any change, a wrong key, an unknown kid or a malformed signature" |
| trace-3 | R | A step is saved but its ledger entry is lost when the ledger fails. | Entries are saved with the step (an outbox) and appended once by event id on the next write. | covered | `session-store.test.ts`: "keeps a step's entries when the ledger fails, and appends them once, in order, on the next write"; `session-store.test.ts`: "appends nothing twice when the clear after a flush is lost, and flushLedger catches up" |
| trace-4 | I | The ledger carries a keyed value, an answer on file, a phone number or a card number. | Ledger detail says what happened and how, never a value; detail carrying a card number is refused. | covered | `engine.test.ts`: "never writes a keyed value, an answer on file or a phone number to the ledger"; `prove.test.ts`: "refuses detail that carries a card number, anywhere in it" |
| trace-5 | R | A caller disputes what they consented to. | The wording is fingerprinted, and a call keeps the wording it started with. | covered | `prove.test.ts`: "fingerprints purpose, version and both texts"; `engine.test.ts`: "keeps the consent wordings a call started with when the config changes" |
| trace-6 | T | Two workspaces' entries mix on one shared ledger. | Entries are keyed by workspace as well as call. | covered | `session-store.test.ts`: "keeps two workspaces' entries apart on one shared ledger, even with the same call id" |
| trace-7 | R | Two overlapping retries of `endCall`, or a failed signing, publish two different receipts. | One receipt and one ledger head per call. | covered | `races.test.ts`: "publishes one receipt and keeps one ledger head when two endCall retries overlap"; `engine.test.ts`: "issues the receipt of an ended call when signing failed the first time, with the same ledger head" |
| trace-8 | R | A receipt does not say which policy and config revision judged the caller. | Policy version and config revision in grants and receipts. | open | VER-8 |
| trace-9 | S | A leaked or retired signing key keeps signing receipts that verify. | Receipt key sets and rotation. | open | PRV-1 |
| trace-10 | R | An outside party cannot check a receipt without this engine. | A stand-alone receipt verifier. | open | PRV-2 |
| trace-11 | R | A caller withdraws consent and nothing records it. | Consent revocation. | open | PRV-3 |
| trace-12 | R | An auditor cannot take the ledger out in a verifiable form. | Ledger export as signed NDJSON with a cursor. | open | PRV-4 |

### Gate

Signed, time-limited access after verification (`src/gate/`, planned). `gateModule()` throws
`NotImplementedError` today, so nothing here can run.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| gate-1 | E | Access is granted without a valid verification grant, or a grant is replayed after it expired. | The Gate module: signed, time-limited grants that need a verification grant, each in the ledger. | open | GAT-1 |
| gate-2 | S | A door controller accepts a forged or replayed grant. | The door controller webhook adapter. | open | GAT-2 |
| gate-3 | S | A one-time access code is guessed or used twice. | One-time access codes. | open | GAT-3 |
| gate-4 | E | A web sign-in step-up is completed by someone other than the verified caller. | The web sign-in step-up. | open | GAT-4 |

### Webhooks

Webhook signature checks and event mapping (`src/webhooks/`).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| webhooks-1 | S | A forged Stripe webhook settles a payment or passes a photo ID. | Stripe's published scheme: HMAC-SHA256 over `t.payload`, any configured secret, constant-time comparison. | covered | `webhooks.test.ts`: "accepts Stripe's scheme: HMAC-SHA256 of t.payload"; `webhooks.test.ts`: "refuses each failure with its reason" |
| webhooks-2 | T | An old signed Stripe webhook is replayed. | A 300-second window either way; each identity session and payment applies once. | covered | `webhooks.test.ts`: "refuses each failure with its reason"; `engine.test.ts`: "applies identity outcomes once, only while verifying, and ignores unknown sessions" |
| webhooks-3 | T | A well-signed but malformed or unexpected event is acted on. | Anything that is not a well-formed event is `null`; other types are ignored. | covered | `webhooks.test.ts`: "returns null for anything that is not a well-formed event"; `webhooks.test.ts`: "names other event types as ignored" |
| webhooks-4 | S | A forged Twilio or Telnyx webhook is trusted. | Carrier signature checks against the vendors' test vectors. Today they throw `NotImplementedError` and the routes answer 501. | open | SRV-1 |

### Reference server

`examples/reference-server/`: an example, not hardened for production.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| server-1 | S | The server parses or acts on an unsigned webhook. | The signature is checked before the body is read as an event. | covered | `reference-server.test.ts`: "verifies Stripe signatures before reading the event" |
| server-2 | T | A signed event is replayed to the server. | Each event id is applied once. | covered | `reference-server.test.ts`: "applies a signed event once and ignores events of the other kind" |
| server-3 | S | A carrier route is trusted before its signature check exists. | Carrier routes answer 501. | covered | `reference-server.test.ts`: "answers 501 on the carrier webhooks that are not built" |
| server-4 | D | A large body exhausts memory. | A body limit on every route that reads one. | covered | `reference-server.test.ts`: "refuses a body over the limit"; `reference-ui.test.ts`: "refuses a body over the limit" |
| server-5 | D | Slow or repeated requests tie the server up. | Per-route limits, request timeouts and a per-address rate limit. | open | SRV-2 |
| server-6 | I | An error answer leaks engine detail. | 500 without detail; a demo run names an engine refusal and hides anything else. | covered | `reference-server.test.ts`: "answers 500 without detail when the engine fails"; `reference-ui.test.ts`: "ends a run on a step that throws, naming an engine refusal and hiding anything else" |
| server-7 | I | Anyone who knows or guesses a call id fetches its receipt. | Receipt links by capability token. | open | SRV-3 |
| server-8 | S | A web page reaches the local demo through DNS rebinding. | The Host header must name this machine and port, on every route. | covered | `reference-ui.test.ts`: "refuses a Host header that is not this machine (DNS rebinding), and accepts the local names"; `reference-ui.test.ts`: "with the UI on, refuses a foreign Host on every route, the webhooks, receipts and key set included" |
| server-9 | I | A request reads a file outside the UI's allow-list. | A fixed allow-list; traversal, encodings and case tricks are refused. | covered | `reference-ui.test.ts`: "serves nothing outside the allow-list: traversal, encodings, case, other files" |
| server-10 | E | Script injected into the demo page runs. | A strict CSP, no inline script, style or handlers, and hardening headers. | covered | `reference-ui.test.ts`: "keeps the page free of inline script, inline style and inline handlers, so the CSP holds"; `reference-ui.test.ts`: "serves every allow-listed file with its content type, the strict CSP and the hardening headers" |
| server-11 | T | Another origin drives a demo run (cross-site request). | Demo routes refuse another origin and a non-JSON body. | covered | `reference-ui.test.ts`: "refuses an unknown flow, bad JSON, a non-JSON body and another origin" |
| server-12 | R | The server forgets its records and ledger on restart. | Optional persistent stores on `node:sqlite`. | open | SRV-4 |

### Release

What is published, and how.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| release-1 | T | A published package differs from the reviewed source, or cannot be traced to it. | A release workflow with a reproducible pack, an exports smoke test and npm provenance. Nothing is published today (`private: true`). | open | SRV-5 |
| release-2 | E | A host imports a runtime function of a module that was meant to stay internal. | The root entry point keeps the modules' runtime functions out. | covered | `entry-points.test.ts`: "keeps the runtime functions of the modules out of the root" |

### SessionStore

The shared call record, written by compare-and-set (`src/core/session-store.ts`, the host's own store).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| sessionstore-1 | T | A durable store ignores the version, so one process overwrites another's change. | `sessionStoreContract`, which the memory store passes and which catches a store that ignores the version. | covered | `session-store.test.ts`: "MemorySessionStore passes the SessionStore contract"; `session-store.test.ts`: "catches a store that ignores the version" |
| sessionstore-2 | E | Two processes both win the same attempt, or both send a link. | Compare-and-set on every change; links are reserved before they are created. | covered | `session-store.test.ts`: "runs one call across two engines, with one attempt budget between them"; `races.test.ts`: "records a payment link's delivery once when two resumes overlap" |
| sessionstore-3 | D | Contention makes a step retry forever. | Five attempts from a fresh read, then `conflict`. | covered | `session-store.test.ts`: "retries a step from a fresh read, and gives up with conflict after the last attempt" |
| sessionstore-4 | S | A new call takes the id of an existing one in a shared store. | An id that exists in the store is refused, whichever engine made it. | covered | `session-store.test.ts`: "refuses an id that exists in the store, whichever engine made it" |

### AuditLedger

The append-only ledger (`MemoryAuditLedger`, or the host's own).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| auditledger-1 | R | A retried append writes one event twice. | `append` is idempotent by event id. | covered | `session-store.test.ts`: "makes the memory ledger idempotent by event id" |
| auditledger-2 | T | A host's durable ledger is not append-only, breaks the chain or reorders concurrent appends. | `auditLedgerContract` for durable ledgers. | open | PRV-5 |
| auditledger-3 | D | An entry the ledger would refuse is saved with the step and blocks every later write. | Such an entry is refused before the step is saved. | covered | `session-store.test.ts`: "refuses an entry the ledger would refuse before it is saved, so it never blocks later writes" |

### RecordStore

Subject records and filed intake records (the host's own store).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| recordstore-1 | T | A caller of the store changes a stored record through a shared reference. | The memory store returns copies. | covered | `entry-points.test.ts`: "the record store returns copies and nothing for unknown keys" |
| recordstore-2 | T | A host's durable record store does not keep the memory store's guarantees. | `recordStoreContract` for durable record stores. | open | PRV-5 |

### PinVerifier

The host's own PIN store, in `verifier` mode.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| pinverifier-1 | S | The host's verifier says yes for a subject the records do not have. | The engine never passes an unknown subject, whatever the verifier says. | covered | `pin.test.ts`: "never passes a subject the records do not have, whatever the verifier says" |
| pinverifier-2 | I | Whether the verifier was asked tells a malformed entry or an unknown account from a wrong PIN. | The verifier is asked every time, with a stand-in for a malformed entry or a non-keypad account. | covered | `pin.test.ts`: "asks the host's PIN store every time, with a stand-in for a malformed entry or a non-keypad account (review item 11)" |
| pinverifier-3 | D | A verifier that fails gives the caller a free try. | The attempt is counted before the verifier is asked. | covered | `pin.test.ts`: "counts the attempt before asking, so a verifier that fails still uses it" |

### IdentityProvider

Photo ID plus selfie by a texted link (Stripe Identity, planned).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| identityprovider-1 | S | An identity outcome is applied to the wrong call, twice, or outside verification. | Outcomes are bound to their session, applied once and only while verifying; unknown sessions are ignored. | covered | `engine.test.ts`: "applies identity outcomes once, only while verifying, and ignores unknown sessions"; `pin.test.ts`: "drops a pending photo ID check when the subject changes, and resumes a link after a failure" |
| identityprovider-2 | E | A link reserved before a taint is created after it and still counts. | The reserved link is voided. | covered | `engine.test.ts`: "voids a photo ID link reserved before the taint and created after it"; `pin.test.ts`: "voids a reserved link when the subject changes before it was created" |
| identityprovider-3 | S | The real provider adapter mishandles sessions or outcomes. | The Stripe Identity adapter, tested against recorded responses. | open | VER-5 |

### CarrierSignals

SIM change, port and identity match on the number on file.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| carriersignals-1 | S | A carrier report checked for one subject is stored for another. | A report is stored only for the subject it checked. | covered | `pin.test.ts`: "never stores a carrier report for a subject other than the one it checked" |
| carriersignals-2 | S | No carrier answer is treated as a clean one. | Without an answer a texted code does not count unless the policy says so. | covered | `policy.test.ts`: "needs a carrier answer by default" |
| carriersignals-3 | S | The real carrier lookups mishandle answers. | Twilio Lookup and Telnyx Number Lookup adapters. | open | VER-4 |

### MessageSender

Texts to the number on file.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| messagesender-1 | S | A link is texted to the calling number or a number the model gave. | Texts go to the subject's number on file only. | covered | `engine.test.ts`: "reaches level 3 with keypad and photo ID, texting the link to the number on file only" |
| messagesender-2 | D | Repeated calls flood a customer with texts, or pump premium numbers. | Texts only after a keypad or PIN match, at most one photo ID link per call. | covered | `engine.test.ts`: "sends photo ID links only after a match, once per call, in the caller's language"; `engine.test.ts`: "has a planned texted code, refused before a match" |
| messagesender-3 | D | Texted codes are used for SMS pumping across calls. | Send limits per subject and per calling number, and a destination country allow-list. | open | VER-2 |

### PaymentLinks

Hosted payment links (Stripe Checkout, planned).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| paymentlinks-1 | T | A retry after a failure creates a second link for one request. | The request stays open and resumes with the same idempotency keys. | covered | `engine.test.ts`: "keeps a request open when creating or texting its link fails, and resumes it with the same keys"; `entry-points.test.ts`: "payment links honour idempotency keys" |
| paymentlinks-2 | I | Two workspaces' idempotency keys collide at the provider. | Keys are scoped to the workspace. | covered | `races.test.ts`: "scopes provider idempotency keys to the workspace" |
| paymentlinks-3 | S | The real provider adapter mishandles links or outcomes. | The Stripe Checkout adapter, tested against recorded responses. | open | PAY-1 |

### ReceiptSigner

The receipt signing key, in process or in a key store.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| receiptsigner-1 | T | A signer on the wrong curve or key type signs receipts. | Signers are P-256 only. | covered | `prove.test.ts`: "builds a signer from a PEM or a JWK, P-256 only" |
| receiptsigner-2 | I | The signing key and the knowledge key sit in process memory, where a process compromise reads them. | Key store contracts: a KMS signer and the knowledge key as an opaque HMAC function. | open | INT-4 |

## Left to the host

- Buffering keypad digits outside the model, never logging them, and cutting audio to
  speech-to-text and the model while `sensitive` is set.
- Keeping the knowledge key and the receipt signing key in a key store.
- Durable `SessionStore`, `RecordStore` and `AuditLedger` implementations that keep the same
  guarantees (`sessionStoreContract` today; PRV-5 for the others).
- Choosing the subject when it starts verification with a subject key (for example the owner of
  the line it was called on). That choice is not a factor: the PIN or other factors still decide.
- A `PinVerifier` that answers the same way, in the same time, for an unknown subject.
- Who may edit a workspace's FlowConfig, and keeping its revisions.
- Outside modules: their code runs inside the engine's writes and is part of the host's security
  model.
- The person path: a caller who fails or cannot use a keypad reaches someone who can help.
- Disclosure that an automated assistant answers and that the call is transcribed.
- Deciding who may switch these modules on (business verification), so the line cannot be used to
  run a phishing operation.
