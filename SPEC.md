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
| `untrusted_content {source}` | any but ended | tainted (sticky), level 0, grant dropped; a verification open when it lands is void (below) |
| `call_ended {at}` | any but ended | phase `ended`, grant dropped, sensitive cleared |

A taint during an open verification fails that verification (Sean, 2026-11-19). `finishVerification`
then grants no level and no scopes, whatever factors matched before or after the taint, and ledgers
`verification.finished` with level 0, no methods and `voidedByTaint: true`; in a flow, the
`badge.verify` step finishes below its level. The caller must start again: the next
`beginVerification` starts from no factors (the session is tainted) and counts as usual. A taint
before a verification began, or after it finished, voids nothing that comes later (it still drops
the level and the grant the call had).

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

- `create(workspaceId, callId, record)` stores it at version 1, or answers false if the id exists.
- `get` returns `{version, record}` or null.
- `compareAndSet(workspaceId, callId, expectedVersion, record)` writes only if the stored version is
  `expectedVersion`, and the new version is `expectedVersion + 1`; otherwise `{ok: false}`.
- `bindRef(workspaceId, ref, callId)` points a provider reference (`identity:<session id>`,
  `payment:<link id>`, `payment_intent:<payment intent id>`, `callback:<dialer ref>`) at a call, first
  binding wins; `resolveRef` reads it.

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
| `badge` | `badge.verify` | | `records`; `counters` with any factor the caller enters (`keypad_knowledge`, `pin`, plug-ins); `carrier` with `carrier_identity_match`; `identity`, `messages` with `photo_id`; `dialer`, `counters` with `callback`; `pinVerifier` with `pin` in verifier mode; `duressNotifier` with `pin.duress` |
| `dossier` | `dossier.collect` | `intake.file` | `records` |
| `paylink` | `paylink.request` | `payment.request` | `payments`, `messages`; `amounts` for a step with `amountRef` |
| `trace` | `trace.consent`, `trace.receipt` | | `ledger`; `signer` unless `receipts` is false |
| `gate` | `gate.grant` | `entry.open` | `access` (door controllers by name), `accessSigner` |

Gate (section 17) is off in `defaultConfig()`: it needs doors in its settings and the two access
adapters. Web sign-in step-up (section 18, module `step-up`, step `step-up.issue`, scope
`entry.sign_in`, class access, floor 2) is built in the same way and off by default too: it needs
its sites and issuer in its settings and the `stepUpSigner` adapter. Built-in modules' parts of a
call are written only by the engine's own code: no outside code reaches them (`updateModule` and
`moduleState` refuse a built-in module).

An outside module changes its part of a call with `updateModule(callId, name, fn)`: one
compare-and-set write, refused once the flow has ended and while the flow is on another module's
step. The engine holds every call to the module's scopes, so a module that never asks still fails
closed: in a flow, the scope the current step needs; outside a flow, every scope the module's
manifest names (`scope_denied`). `fn` gets a copy of the module's part and a view: the session
state, the current step (a copy, or null), the engine's clock (`now`), `newId(prefix)`,
`authorized(scope)` and `emit(event, detail)` (a `module.event` ledger entry). There is no way for
an outside module to write an outcome for work the engine holds: outcomes the engine must vouch
for (an access grant's) are the engine's own (ADR-25).

## 4. Factors, levels and scopes

Built-in factor kinds: `keypad_knowledge`, `pin`, `carrier_identity_match`, `photo_id`,
`spoken_knowledge` (section 5), `callback` (section 6) and `text_code` (planned, VER-2). A
**factor plug-in** adds a
kind the caller enters and code judges: `{kind, summary, maxAttemptsPerCall (1 to 5), adapters,
judge}`, installed with `badgeModule({ factors })`. Its kind is snake_case, 3 to 32 characters, not
a built-in kind, and never `caller_id`, `calling_number`, `ani` or `cli`. Its judge gets the
subject, the entry and `hmac(data)` under the knowledge key (asynchronous, a `Promise` of the hex
digest), never the key. Caller ID is not a kind.

A policy lists, per level 1 to 3, sets of factor kinds; a level is reached when every kind in one
of its sets has passed. `validatePolicy(policy, knownFactors)` refuses:

- a level outside 1 to 3, a level defined twice, an empty set, an unknown or repeated kind;
- at level 2 or 3, a set with fewer than two different kinds;
- at level 3, a set without `photo_id`;
- a set made only of possession of the number on file (`text_code`, `callback`): `[text_code]`,
  `[callback]` and `[text_code, callback]` are refused at every level;
- a set at level 2 or 3 made only of things the caller knows: it needs `text_code`,
  `carrier_identity_match`, `photo_id` or `callback` (keypad knowledge, the PIN, spoken answers and
  plug-ins are knowledge);
- a scope with no class, or below its class's floor. A scope's class is the strictest of what its
  name implies (`payment.`, `payout.`, `refund.`, `transfer.`, `charge.`: money; `contact.`:
  contact; `entry.`, `access.`: access; `status.`, `intake.`: none), what an installed module's
  manifest declares (`scopes.classes`), and the policy's own `scopeClasses`. Money, contact and
  access are at least level 2; none is at least 0;
- `maxKeypadAttemptsPerCall` outside 1 to 5;
- a set with `spoken_knowledge` when the policy has no `spoken`, and a `spoken` that is not
  `{fields, maxAttemptsPerCall}`: `fields` maps at least one field name to `ca_postal_code`,
  `us_zip_code` or `reference`, none of them a keypad field, and `maxAttemptsPerCall` is 1 to 5.
  So a spoken answer counts on its own only at level 1; above it, the rules above need another
  factor, and one that is not knowledge.

It checks every part in one pass: a malformed part is reported and the others are still checked.

The default policy: level 1 is keypad knowledge; level 2 is keypad plus a trusted texted code, or
keypad plus carrier identity match, or a PIN plus a texted code; level 3 is keypad plus photo ID.
Scopes: `status.read` 1, `intake.file` 1, `payment.request` 2, `contact.update` 3, `payout.update`
3. Two keypad attempts per call. A texted code or a callback counts only when the carrier answered
and reported no SIM change or port in the last 72 hours (`simSwapWindowHours`; without an answer,
only when `trustTextCodeWithoutCarrierCheck` is true); otherwise `verification.finished` lists it
in `discounted`. The default policy has no `callback` set: a host that turns the factor on adds
one, for example `[pin, callback]` at level 2.

Badge's settings turn factors on (`factors`, at least one), set the grant lifetime
(`grantTtlSeconds`, default 900, at most 3600), the lockouts across calls and the hourly limits
on flow starts (`lockout`, section 6)
and, when `pin` is on, the PIN settings (section 6).
A factor that is off is refused at every entry point. A planned factor cannot be turned on.

A **grant** carries the level, the scopes at or below it (narrowed to the verify step's `scopes`
when the step lists them), an expiry, and what judged it: `policyVersion` (the policy's `version`)
and `configRevision` (the `revision` of the FlowConfig in force when the verification finished,
newer than the call's own `revision` when the config changed during the call).
`authorize(callId, scope)` is true only for a scope the policy lists, on a call that has not
ended, whose minimum is 0 or whose grant includes it, has not expired, and has a level at or
above the scope's minimum under the config in force now.
On a
duress call (section 6) it is also false for every scope whose class is not `none` and for every
scope in the duress `refuseScopes`.

Links and callbacks go only to the subject's number on file, and only after a `keypad_knowledge`
or `pin` factor passed since verification last started from nothing. A plug-in's pass does not
unlock texts or callbacks.

## 5. Keypad knowledge and spoken answers

- The knowledge key (`EngineOptions.knowledgeKey`) is its bytes, at least 16 (a string or a
  `Uint8Array`; anything else is `invalid_input` when the engine is built), or an opaque
  `KnowledgeHmac` function, `async (data) => HMAC-SHA256(key, UTF-8 data)` as 64 lower-case hex,
  which can call a key management service so the key never enters the engine's process. It is
  asynchronous, the same shape as a plug-in's `hmac`, and the engine's own hashing (subject keys,
  field and PIN digests) goes through the same function; every keypad field is hashed before any
  is compared. An answer that is not 64 lower-case hex is refused with `invalid_input`, whose
  message never quotes it. A function that throws or rejects fails closed: no factor, the attempt
  counted, the error passed to the host (below). `subjectKeyFor`, `knowledgeDigest`, `pinDigest`
  and `judgeKeypadFactors` take either form and give the same digests for the same key: at once
  for bytes, as a `Promise` for a function.
- Subject key: `HMAC-SHA256(knowledgeKey, "subject:" + accountNumber)`, hex. A host may instead
  start verification with a subject key its own code chose (`{subjectKey}`, a string of 64 lower-case hex, read once; anything else is `invalid_input`);
  choosing the subject is not a factor.
- Field digest: `HMAC-SHA256(knowledgeKey, "field:" + field + ":" + value)`, hex.
- An entry counts only if it is 1 to 32 ASCII digits.
- `submitKeypad` compares every configured field, in constant time per field, even after a
  mismatch, and records one factor: passed only if the subject exists and every field matched.
- After `maxKeypadAttemptsPerCall` judged attempts, further submissions return `locked` without
  judging. Failures also count across calls (section 6, "Lockouts across calls").

**Spoken answers** (`spoken_knowledge`) are for values a keypad cannot enter. The host submits one
transcript per field in the policy's `spoken.fields`: `submitFactor(callId, "spoken_knowledge",
{postal_code: "K one A zero B one"})`.

- `normaliseSpokenAnswer({field, transcript, locale})` (`field` is the format) returns
  `{status: "normalised", value}` or `{status: "unusable"}`. The transcript is lower-cased and
  its accents removed; it may hold only letters, digits, spaces and `. , ; : ! ? ' " -`, and at most
  200 characters. Each token is read exactly: digits, one letter, letters and digits written
  together (`K1A`), or a word of the call's language: digit words (`zero` to `nine`, `niner`;
  `zéro` to `neuf`), letter names (`kay`, `zed`, `double u`; `ka`, `zède`, `double vé`, `i grec`),
  the NATO alphabet in both, and the traditional French alphabet in French (`Anatole` to `Zoé`).
  `as in` or `for` (English), `comme` or `comme dans` (French) after a letter must be followed by
  a word starting with that letter, which confirms it. Any other word, `oh` in a digit's place,
  number words such as `ninety`, or a result not of the format is `unusable`. Nothing is guessed.
- Formats, as normalised: `ca_postal_code` letter, digit, letter, digit, letter, digit, without
  D, F, I, O, Q, U, and without W or Z first (`K1A0B1`); `us_zip_code` five digits (ZIP+4 is
  unusable); `reference` 4 to 12 upper-case letters and digits.
- Each field is compared like a keypad field: `HMAC-SHA256(knowledgeKey, "field:" + field + ":"
  + value)` against `SubjectRecord.knowledge[field]`, in constant time, every field even after a
  mismatch. The host must store the value on file in the same normalised form (`K1A0B1`, not
  `K1A 0B1` or `k1a0b1`), or no answer ever matches; an unusable answer does the same work and fails. One factor: passed only if the
  subject exists and every field matched.
- Each attempt is counted before it is judged, an unusable one included; after
  `spoken.maxAttemptsPerCall`, submissions return `locked` without judging. Without `spoken` in
  the policy, every submission is `locked` and nothing is judged. A host can call
  `normaliseSpokenAnswer` itself first to ask again before an attempt is used.
- A spoken match does not unlock texts to the number on file (section 4).

## 6. PIN

Settings: `{mode, minDigits (4 to 12), maxDigits (minDigits to 12), maxAttemptsPerCall (1 to 5),
duress?}`. `duress` is `{refuseScopes}`, a list of scopes without duplicates (it may be empty);
the duress PIN is off unless it is set.

- An entry is well formed when it is ASCII digits with a length from `minDigits` to `maxDigits`.
  A malformed entry is still an attempt, and fails.
- `keyed_hash` mode: the stored digest is `pinDigest(knowledgeKey, subjectKey, pin)` =
  `HMAC-SHA256(knowledgeKey, "pin:" + subjectKey + ":" + pin)`, in `SubjectRecord.pinDigest`,
  read from the `RecordStore` at every attempt (not from the call's copy of the subject), so a
  reset or an enrolment since verification began counts. The entry is hashed the same way and compared in constant time; an unknown subject, a subject without
  a digest and a malformed entry do the same work and give the same answer.
- `verifier` mode: the host's `PinVerifier.verify({workspaceId, subjectKey, pin})` decides; the
  PIN is passed once and kept nowhere. It is asked for every attempt: for a malformed entry or an
  account a keypad cannot produce, with a stand-in (`minDigits` zeros, an HMAC subject key) whose
  answer is ignored. A subject the `RecordStore` does not have never passes, whatever it says.
- Each attempt is counted in its own write before it is judged. A judge that throws (the knowledge
  key store, a `PinVerifier`, a plug-in) records no factor, writes `verification.factor_error`
  (unless the call ended or the verification restarted meanwhile) and passes the error to the
  host. The attempt is not refunded, so an entry crafted to make a judge throw never gives a free
  try; a key store outage can use up the call's attempts. Every `beginVerification` starts a new
  epoch; a factor result, a carrier report or a photo ID check from an earlier epoch is never
  applied (`precondition_failed`), and a change of subject drops pending photo ID checks.
- The photo ID link is reserved, created, enrolled and texted in turn; after a failure,
  `startPhotoId` resumes with the same idempotency keys, so a call never has two links. If the
  provider answers a resume with a new session (it pruned the key), that session is enrolled before
  its link is texted, so its outcome applies; a repeated session is enrolled once. After `maxAttemptsPerCall`,
  `submitPin` returns `locked` without judging. Across calls: below.
- Enrolment: `enrolPin(callId, {pin, confirm})` lets a caller choose a PIN, keyed twice (each
  read once; a value that is not a string is `malformed`). It needs
  the `pin` factor on in `keyed_hash` mode (in `verifier` mode the host's own store enrols, and
  `enrolPin` refuses with `precondition_failed`), a call with no running or ended flow
  (`precondition_failed`), an open call (`invalid_transition`) and an unexpired grant at level 2 or
  above from this call (`scope_denied`). Each try is counted in its own write before it is judged,
  up to `maxAttemptsPerCall`; after that it answers `{enrolled: false, reason: "locked"}` without
  judging. The subject is read from the `RecordStore`; one not on file, or one that already has a
  PIN, is refused (`precondition_failed`): only the business changes a PIN on file. Both entries
  are hashed as `pinDigest` and compared in constant time. Answers: `malformed` (either entry is
  not digits of a length from `minDigits` to `maxDigits`), `mismatch`, `weak` (every digit the
  same, a run up or down with 0 following 9, as in 1234, 4321 or 7890, or a PIN equal to the
  subject's account number or any keypad knowledge on file, compared as keyed hashes; `weak` does
  not say which), or `{enrolled: true}` once `RecordStore.putPinDigest(workspaceId, subjectKey,
  digest, enrolmentId)` stored it. Then `pin.enrolled`. Each try has its own enrolment id (the call
  id and the try's number) and records its digest and id as pending on the call (one entry per try,
  so two tries at once never overwrite each other's) before the store's write; the store keeps the
  id with the digest (`SubjectRecord.pinEnrolmentId`), and a reset removes both.
  `putPinDigest` stores a digest only if the subject has none, in one atomic step, and answers
  whether it did; when it did not (another call or try enrolled first) the try takes its own entry
  back and is refused (`precondition_failed`), and nothing is replaced, so a retry of it is refused
  too. The try that stored writes `pin.enrolled` and clears every pending entry for that digest. If
  the session write after a stored digest fails, a retry on the same call with the same PIN finishes
  that enrolment only when the id on file is one of this call's own pending tries (so another
  call's enrolment of the same PIN, or one after a reset, never passes for it), checked in the write
  that records it (`{enrolled: true}`, one `pin.enrolled`), even past `maxAttemptsPerCall` (such a
  retry is not counted); any other PIN is refused as one on file, or `locked` past the limit.
- Reset: `resetPin(subjectKey)` is a host call for the business's own staff tools, never on a
  caller's request, and needs the `pin` factor on (and a string subject key: `invalid_input` otherwise). In `keyed_hash` mode it removes the digest
  (`putPinDigest` with null), so the subject has no PIN until they enrol again at level 2; in
  `verifier` mode the host's store resets its own PIN. Either way it clears the subject's PIN
  failure counters when the engine has a `counters` adapter (VER-1), its hidden one (VER-12)
  included, but not a duress flag, and appends `pin.reset` to the ledger with no call. In `keyed_hash` mode `putPinDigest` with null removes the duress PIN too, in the same atomic step, so a duress PIN the business enrols against a PIN chosen after the reset began is never removed by it.

**Lockouts across calls (VER-1).** Every factor the caller enters (keypad knowledge, the PIN,
plug-ins) is also counted across calls, in an `AttemptCounters` store every engine of the
workspace shares. A counter is keyed by workspace, factor kind, and scope: `subject` (the subject
key, whether or not the subject exists, so a lock never says which accounts are real) or `number`
(`numberKeyFor(knowledgeKey, callingNumber)` = `HMAC-SHA256(knowledgeKey, "number:" + number)`,
so the store never holds a phone number). `beginVerification(callId, {..., callingNumber})` takes
the calling number, an E.164 string, from the carrier (anything else is `invalid_input`); a
withheld number is left out, and a restart that
leaves it out keeps the one given before. The number only keys a counter: it is never a factor.
An attempt is counted under the subject's counter when there is a subject key, and the number's
when there is a number.

- `AttemptCounters`: `get(key, since)` returns the failure times at or after `since`, in the order
  recorded; `recordFailure(key, at, since)` adds one and returns the same list, this one last, in
  one atomic step; `removeFailure(key, at)` forgets one failure recorded at `at` and keeps every
  other, also in one atomic step (nothing when there is none); `reset(key)` forgets them all. `attemptCountersContract(factory)` in
  `district-assurance/testing` is the suite a store must pass; `MemoryAttemptCounters` is the
  reference. The engine refuses (`invalid_input`) a `counters` adapter missing any of the four
  methods when it is built, so a store written before `removeFailure` existed never reaches a pass.
- Badge's `lockout` setting: `{backoffSeconds, lockAfterFailures, windowHours}`, defaults
  `[5, 15, 60, 300, 900]`, `10` and `24`, which are also floors: `backoffSeconds` lists 5 to 10
  whole seconds, each at least the default at its place (900 after the fifth) and at most 86400;
  `lockAfterFailures` is 1 to 10; `windowHours` 24 to 168. `validateConfig` refuses anything else.
- With `n` failures in the window (the last `windowHours`, a failure exactly that old excluded):
  `n >= lockAfterFailures` is a hard lock until the oldest of the last `lockAfterFailures` failures
  leaves the window; otherwise, for `n >= 1`, a wait of `backoffSeconds[min(n, length) - 1]` after
  the latest failure.
- `submitFactor` (and `submitKeypad`, `submitPin`) reads the counters first. While either is
  locked, it returns `{matched: false, locked: true}` without judging and without using the call's
  attempt, and writes `verification.locked`. Otherwise it counts the call's attempt, then records a
  failure on each counter, both before judging. If the lists `recordFailure` returned show a lock
  that was not there when the counters were read (another attempt, on any call or engine, got in
  first), the attempt is refused the same way: no counter after that one is recorded, and the
  call's attempt is given back. A pass, once its result is accepted on the call, resets the
  subject's counter and takes its own failure off the number's (`forgetPass`, with `removeFailure`,
  so a failure another call records meanwhile is kept); the number's other failures stay until
  they leave the window, so a pass on the caller's own account never clears failures the line ran
  up against others. A failure stands, and
  one that starts a hard lock returns `locked: true` and writes `verification.locked`. A judge or
  verifier that throws leaves its failure counted.
- Two entries for one subject at once (two callers for one account, on any calls or engines)
  meet this rule too: the first's failure is recorded before it is judged, so it is provisional,
  but the second sees it as a failure and waits (`locked: true`, unjudged, the call's attempt
  given back, `verification.locked` with `hard: false`) for the timed wait that failure sets; the
  wait is never skipped. It is timed, not held for the whole judgment: an entry that arrives after
  it ends is judged even if the first is still being judged. There is no free guess either way,
  since every entry records its own failure before it is judged, and only a pass takes it back. If
  the first passes, its pass resets the subject's counter and the second may enter again at once;
  if it fails, both failures stand and the second waits the longer wait for two.
- The cleanup a pass owes (`forgetPass`) is saved with the pass, on the call, so a write that
  fails after the pass was saved (its ledger entry) still gets it, in the same `submitKeypad` or
  `submitPin` or before the call's next factor; a pass refused before it was saved owes none.
- **Lock notices (INT-7).** With a `notifier` adapter, after a `verification.locked` entry is
  appended (by the step's write, or later by `flushLedger`), the engine calls
  `Notifier.lockout({workspaceId, factor, scope, key, hard, until, capped})`: the counter that
  locked (`key` is the subject key, or the number's keyed hash), the factor kind, and when the lock
  ends; never a value, an account number or a phone number. The call's write reads the key from
  Badge's part of the call as the entry is saved, and keeps it beside the entry in the outbox, never
  in the ledger. A lock is told once, on whichever engine refuses it first: its counter's
  `notice:<kind>` counter in the `AttemptCounters` store records the lock's end, and a lock ending
  no later than one already told is not told again. A workspace gets at most 20 notices an hour of
  hard locks (`NOTICES_PER_HOUR`, counted under `notice:*`) and, apart, 20 of waits after a failure
  (under `notice:*wait`), so waits, which come cheap, never use up the hard locks' notices; the 20th
  of each has `capped: true`, and later locks of that kind in the hour are in the ledger only. Best effort, like the listener: the notifier is not awaited,
  and a notifier or a notice count that throws, rejects or hangs never fails the call or the ledger.
- **Unlock (INT-7).** `unlock({workspaceId, factor, scope, key, memberId})`, a host call for a
  member of the business, takes no call, so nothing on a call reaches it. It refuses
  (`invalid_input`) another workspace, a factor kind that is not installed, a scope other than
  `subject` or `number`, a key that is not 64 lower-case hex, and a `memberId` that is not an opaque
  id, 1 to 64 of letters, digits, `.`, `_`, `-` (no `@` and no space, so no email address or name
  reaches the ledger, as for `clearDuress`), or that carries a card number; an engine without
  `counters` refuses with `precondition_failed`; anything but a string key or member id is
  `invalid_input` too. It appends `verification.unlocked` (call id null, actor `member`, no event
  id, so every unlock is its own entry whatever the host's id generator repeats; the listener,
  which hears of calls, is not told), naming the counter only by `unlockedCounter(knowledgeKey,
  {factor, scope, key})` = `HMAC-SHA256(knowledgeKey, JSON.stringify(["verification.unlocked",
  factor, scope, key]))`, which the business can match and a reader of the ledger or an export
  cannot; then it clears that one counter
  and its notices, and nothing else: the other scope, other factor kinds and other subjects stay
  locked. Unlike a pass, which takes only its own failure off a number's counter, an unlock clears
  the whole counter it names, a number's failures against other accounts included: the business's
  deliberate act, in the ledger. It grants nothing: no call changes, and the
  caller verifies from no factors like anyone else. It never lifts a duress PIN's hidden lock
  (VER-12): only `clearDuress` does, as the flag stays until the business clears it.
- A counter is never keyed by flow or call, and no setting separates them: failures in one flow
  count in every other flow and call (VER-15, tested).
- Outside `unlock`, lifting a lock early is the host's: `AttemptCounters.reset` with the keys (`counterKeys`) and,
  with the duress PIN on, the subject's hidden key for the factor (`hiddenCounterKey(workspaceId,
  kind, subjectKey)`, section 6), whose hard lock otherwise holds.

**Callback (VER-9).** A built-in factor, not a plug-in: the business calls back the number on
file, which proves possession of that line whatever number the first call came from. Badge needs
the `dialer` (`CallbackDialer`) and `counters` adapters when it is on.

- `requestCallback(callId)`, while verifying, on a call where `callback` is on and, in a flow, on
  the flow's first step, a `badge.verify` step that lists `callback`; otherwise it is refused
  (`precondition_failed`, `invalid_transition`). One per call: a second request, or a request on a
  callback call, is refused (`precondition_failed`).
- The request is decided in one write that reserves it (`requested`), then refused when the call
  is tainted (untrusted content entered it, before the request or while it was decided), when no
  `keypad_knowledge` or `pin` factor passed since verification last started from nothing, when the
  subject's `phoneOnFile` is not E.164 (no number on file), when a `callback` counter is locked
  (section 6 rules, under the subject key and the first call's calling number), or when the
  subject already had `MAX_CALLBACKS_PER_DAY` (3) callbacks placed in the last 24 hours (counted
  in `AttemptCounters` under the key `callback.placed`, recorded before the dial, so of two
  requests racing for the last one only one is placed). Otherwise it is placed, and a failure is
  recorded on the `callback` counters before the line is dialed; a pass forgets the subject's
  failures and this callback's own on the number (section 6). A pass whose counters could not be
  updated keeps that work pending, and a repeated outcome retries it without recording `callback`
  again.
- The reservation keeps the subject, the verification and the time it is counted at. If
  verification restarts (another subject included) before the request is decided, it is refused,
  and nothing reserved for one subject is ever placed for another. A request that failed before
  it was decided (`requested`) is decided by the next request on the call, as of its reserved
  time: a counter that already holds its failure at that time is not counted again.
- Either way the call that asked is ended (`endCall`, a running flow abandoned; two requests at
  once end it once, and neither fails for it) and `requestCallback` returns nothing: a refused
  request looks and sounds the same as a placed one, and so does a placed one whose dial failed
  (the dialer's error is not passed on, so the answer never says whether a number is on file; the
  callback stays unpassed and the next request resumes it).
  The first call never gains a level, a factor or a grant from the callback. Asked again, it gives
  the same answer, and a placed callback whose call or dial failed is resumed with the same ids and
  idempotency key.
- A placed callback creates the callback call (an id from the id source, the first call's locale
  and revision, and its flow's steps from the first step) and, in the same write, starts
  verification on it for the subject the first call matched, with no factors; choosing the subject
  is not a factor. The dialer then rings the number on file (`dial({callId, to, locale,
  idempotencyKey})`), its reference is kept on the callback call and bound (`callback:<ref>`).
  `to` is read from the `RecordStore` when it dials, and again on every retry, never from the copy
  taken when verification began, so a number the business changed since is the one rung; with no
  E.164 number on file then, the callback fails without ringing
  (`verification.callback_finished` `refused`).
- `applyCallbackOutcome({ref, answered, confirmed})` records `callback` on the callback call:
  passed only when the number on file answered and the person keyed the confirmation. Keys, not
  speech: voicemail or an answering machine is `answered` without `confirmed`, and fails. An
  unknown reference, a second outcome, an outcome after the callback call left verification or
  ended, and one for a callback voided by untrusted content or a change of subject are ignored.
- Its level and grant belong to the callback call alone: the caller there keys the PIN (or keypad
  knowledge) again, and the policy decides as for any call.

**Limits across flows (VER-15).** A flow is *limited* when one of its steps needs a scope of class
money, contact or access, or a `badge.verify` step can grant one (its `scopes`, or without them
every scope its level reaches). Starts of limited flows are counted, whatever their outcome, in
the same `AttemptCounters` store, under the kind `flow.start` (not snake_case, so no factor shares
it), per calling number and per subject.

- `startCall({flow, callingNumber})` and `startFlow(callId, name, {callingNumber})` take the
  calling number like `beginVerification`, kept in Badge's part of the call. A limited start is
  counted on the number's counter and, when the call already named a subject, the subject's.
  `beginVerification` on a call running a limited flow counts it on the subject's counter (and on a
  number given only then), once per counter per call: a restart for the same subject counts nothing.
- Badge's `lockout.flowStartsPerHour`: `{subject, number}`, defaults `5` and `10`, which are also
  the most a config may allow (1 up to the default); `validateConfig` refuses anything else. A
  start exactly an hour old has left the hour. An engine with a limited flow in its config needs
  the `counters` adapter (`ConfigError` otherwise).
- The counters are read first: a counter already at its limit refuses the start without counting
  it. Otherwise the start is counted on each counter, and one that a concurrent start took over the
  limit refuses it too (that start stays counted). A start the call itself then refuses, because a
  concurrent `startFlow` attached a flow first or a concurrent `startCall` took the id first, is
  taken back off each counter (`removeFailure` at the time it was recorded); one whose write saved
  and then failed (the ledger down) stays counted. A `callingNumber` that is not a string is
  `invalid_input`, like one that is not E.164.
- A refused start throws `RateLimitedError` (an `EngineError` with code `rate_limited`) with one
  message, whichever limit was hit, and the `callId` of the call it was refused on, so a host that
  let `startCall` choose the id can still end the call it opened.
  The call keeps the flow, `failed` (on `startCall`, the call is still created), so no step runs and
  no other flow starts on it; the host speaks its fixed line and ends the call. It writes
  `flow.rate_limited` with the flow and the `scope` (`subject` or `number`), never a value.
- Caller ID can be spoofed, so the per-number limit can lock out the real owner of a number. The
  per-subject limit is the one that holds; the per-number one is a backstop. Lifting either early
  is the host's: `AttemptCounters.reset` with `counterKeys(workspaceId, "flow.start", keys)`.

### Duress PIN (VER-12)

A second PIN that an owner made to call under pressure enters instead of the PIN. Off unless
`pin.duress` is set; then Badge needs the `duressNotifier` adapter.

- Enrolment: `enrolDuressPin(subjectKey, pin)` is a host call for the business's own tools, never
  a caller's. It needs the `pin` factor on (`precondition_failed`), `keyed_hash` mode
  (`precondition_failed`; in `verifier` mode the host's store keeps its own duress PIN), a 64
  lower-case hex subject key (`invalid_input`), `pin.duress` set (`precondition_failed`) and a
  subject on file with a PIN (`precondition_failed`). Answers: `malformed` (not digits of a length
  from `minDigits` to `maxDigits`), `weak` (equal to the PIN on file, the account number or any
  keypad knowledge, compared as keyed hashes; every digit the same; a run; `weak` does not say
  which), or `{enrolled: true}` once `RecordStore.putDuressDigest(workspaceId, subjectKey,
  digest, ifPinDigest)` stored `duressDigest(knowledgeKey, subjectKey, pin)` = `HMAC-SHA256(knowledgeKey,
  "duress:" + subjectKey + ":" + pin)`, in `SubjectRecord.duressDigest`. The store writes it only
  while the subject's PIN digest is still the one it was checked against, atomically, and answers
  whether it did; when not (a reset and a new PIN meanwhile) `enrolDuressPin` throws `conflict` and
  nothing is stored. A second enrolment replaces it. `removeDuressPin(subjectKey)` removes it (same checks, except `pin.duress` may be
  off). Neither writes to the ledger. `enrolPin` answers `weak` for a PIN equal to a duress PIN on
  file.
- Judging: in `keyed_hash` mode every PIN entry is hashed as both a PIN and a duress PIN and
  compared with both digests (an empty one when none is on file), whatever the subject, the entry
  or the setting, so the work and the time are the same. Both digests are read from the store on
  every entry, never from the call's copy, so a duress PIN removed, or a PIN reset (which removes
  both), counts even on a call that began verification before it. In `verifier` mode `PinVerifier.verify`
  may answer `{duress: true}`, and `matched` is then ignored. A duress match counts only on a
  subject on file, with a well-formed entry, while `pin.duress` is set; otherwise it fails like a
  wrong PIN. An entry that matches both the PIN and the duress PIN (a subject imported with the two
  PINs equal), in either mode, and in `keyed_hash` mode any entry on a subject whose two digests
  are byte for byte equal, fail like a wrong PIN, with no alarm: in `verifier` mode, an answer
  `{matched: true, duress: true}` fails.
- A duress entry is a pass everywhere the caller can reach: the same `submitPin` answer, the same
  factor, level, grant, state, events and receipt as the PIN. The call record's Badge part gets
  `duress: {refuseScopes}` (the setting as it was then), which nothing clears for the rest of the
  call, and `authorize` refuses as section 4 says, with the same `false` as a scope with no grant
  (so `requestPayment` is refused with `scope_denied`). Anything sent after the call (PRV-10)
  follows the same rule as on a normal call.
- Flag until cleared: an entry of the duress PIN also flags its subject, durably and hidden, in the
  `AttemptCounters` store every engine shares (kind `duress.flag`), after the call's write and
  before the counters' visible reset, even when the entry was stale. A pass that is a duress entry
  only because the flag was set never writes the flag again, so a `clearDuress` that lands while it
  is judged stays cleared, and the pass does the same store work as a pass on a subject not flagged.
  While the flag is set, every later pass on the subject, on any call and by any entered factor, is
  a duress entry: its scopes refused, and the same to the caller as any pass. The flag is read for
  every subject, whether or not `pin.duress` is on: a subject flagged before a config turned the
  duress PIN off stays under duress, and with no `refuseScopes` left to read, its calls refuse every
  scope of the policy. Alerts are coalesced: every entry of the duress PIN alerts, and a pass that
  is a duress entry only by the flag alerts once a call (the first), so a flagged subject's call
  always raises one, and repeated passes on it do not flood the business. Delivering an owed alert
  sets the flag again first (`duress.flag`), in case the entry's own write of it was lost, unless the
  subject was cleared after the entry: each alert records the subject's count of clearings
  (`duress.clears`, one more per `clearDuress`, never reset) as it was read before the flag, and the
  flag is set again only while that count is unchanged. A failure to set it leaves the alert owed. A duress entry resets the visible
  counters as a pass does, so it looks like one; every entered factor's failures on the subject are
  also counted in a hidden counter (kind `duress.hidden.<kind>`) that only a pass not under duress
  resets (a duress entry takes off only its own failure), and that counter's hard lock (not its
  waits) refuses like any lock. So a caller who knows the duress PIN gets no more guesses at the
  real PIN than one who does not. `clearDuress(subjectKey, memberId)` is a host-privileged call,
  like `resetPin`: the business's own tools, never a caller's request, once it knows the subject is
  safe. The engine does not authenticate the member: the host must authorize them before it calls.
  `memberId` is an opaque id, 1 to 64 of letters, digits, `.`, `_`, `-` (no `@` and no space, so
  no email address or name reaches the ledger; `invalid_input` otherwise). `duress.cleared` is
  written to the ledger first, naming the subject only by `duressClearedSubject(knowledgeKey,
  subjectKey)` = `HMAC-SHA256(knowledgeKey, "duress.cleared:" + subjectKey)`, which the business can
  match and a reader of the ledger or an export cannot; then the count of clearings goes up, and the
  flag and the hidden counters of every installed factor (on or off) are cleared. A clearing that
  lands while an earlier entry's alert is being delivered may be undone by that delivery's setting of
  the flag (the counters store has no compare-and-set): the subject stays flagged, and the business
  clears it again.
- Every duress entry owes an alert: in the same write, Badge's part of the call record gets
  `duressAlerts` `{alertId, subjectKey, at, clears}` and `duress`, and the record `owesAlerts: true` until
  none is owed; `alertId` is `JSON.stringify(["duress", workspaceId, callId, n])` for the call's `n`th duress
  entry, unique across engines whatever their id generators, even when verification restarted or the
  call ended while the entry was judged (the entry is then not a factor, and `submitPin` throws the
  same error as for any other stale entry). After a write, `flushLedger` included, and even when its
  ledger append failed, the engine calls `DuressNotifier.notify({alertId, workspaceId, subjectKey,
  callId, at})` for each alert the call owes, off the response path (after the reply), and takes the
  alert off the record once `notify` resolves. An alert stays owed until then, and is sent again on
  the next write, `flushLedger` or `deliverDuressAlerts(callId)` (the host's sweep, which waits and
  answers how many were acknowledged), or `sweepAlerts()`, which finds the calls without their ids
  through the optional `SessionStore.listCallsOwingAlerts(workspaceId)` (the calls whose record has
  `owesAlerts: true`; `precondition_failed` without it) and answers `{sent, failed}`: the calls that
  owe nothing now, and those that still owe one or could not be read (a listed call the store cannot
  read, or no longer holds, is reported and the sweep goes on); one engine sends an alert once at a time, again after 30
  seconds without an answer. So `notify` may see an `alertId` more than once. A notifier that throws,
  rejects or never answers changes nothing on the call; it must not block.
- The ledger tag: every `verification.factor` entry with `kind: "pin"` carries `tag` =
  `HMAC-SHA256(knowledgeKey, JSON.stringify(["pin.tag", eventId, outcome]))`, outcome `fail`,
  `pass` or `duress`, whether or not the duress PIN is on. `readPinTag(entry)` on the engine (and
  `readPinTag(hmac, entry)`) returns the outcome, or null for another entry, a wrong key or a
  changed entry. The ledger otherwise holds the same entries; the receipt's ledger head and the
  `receipt.issued` digest differ only as the tag's bytes do.

## 7. FlowConfig

```json
{
  "version": 1,
  "revision": "2026-11-18.1",
  "policy": { "version": "...", "levels": [], "scopes": {}, "keypadFields": [], "maxKeypadAttemptsPerCall": 2,
              "simSwapWindowHours": 72, "trustTextCodeWithoutCarrierCheck": false,
              "spoken": { "fields": { "postal_code": "ca_postal_code" }, "maxAttemptsPerCall": 2 } },
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
minimum and whose `scopes`, if listed, include it, and that no flow has more `step-up.issue` steps
than step-up's `maxTokensPerCall` (each completes only on a token of its own, so such a flow could
never finish; a module's optional `validateFlow` makes such whole-flow checks). Cross-checks against a module's settings or the
policy are skipped when those did not validate (their own problems are reported). The engine
refuses a config with any problem (`ConfigError`, code `invalid_input`, with `problems`).

| Step | Fields |
|---|---|
| `badge.verify` | `level` 1 to 3; `factors`, at least one, each on in Badge's settings, together reaching `level` under the policy; optional `scopes`, each in the policy at or below `level` |
| `dossier.collect` | `form`, a form id in Dossier's settings |
| `paylink.request` | `amountMinor` and `currency`, or instead `amountRef` (1 to 64 of letters, digits, `.`, `:`, `-`, `_`; needs the `amounts` adapter), never both; `description`, `amountSource` (section 14); optional `mode` (`connect` or `platform`; connect needs Paylink's `connectedAccountId`), `linkLifeMinutes` (5 to 60), `paymentMethods` (instant methods only) |
| `trace.consent` | `purpose`, a wording in Trace's settings; `require`: `"yes"` (default) or `"answer"` |
| `trace.receipt` | none; needs the `signer` adapter |
| `gate.grant` | `target`, a target id in Gate's settings; optional `lifetimeSeconds` (10 to 900, default 60) |
| `step-up.issue` | `site`, a site id in step-up's settings; optional `lifetimeSeconds` (120 to 300, default 120) |

Settings: Badge (section 4 and 6); Dossier `{forms}` (section 13, ids unique, no sensitive field
until FIL-2); Paylink `{maxAmountMinor?, mode?, connectedAccountId?, linkLifeMinutes?, paymentMethods?}`
(`maxAmountMinor` 1 to 1,000,000; `mode` default `platform`, and `connect` needs
`connectedAccountId`, 1 to 255 letters, digits, `-` or `_`; a `connectedAccountId` needs an
explicit `mode`, so a business account never quietly defaults to the platform's; the other two are the defaults for steps
that name none and for payments outside a flow, 15 minutes and card, Apple Pay, Google Pay and
Link); Gate `{targets, maxGrantsPerCall?}` (section 17); step-up `{issuer, sites, maxTokensPerCall?}`
(section 18); Trace `{receipts?, wordings?}`
(`receipts` default true; wordings `{purpose (snake_case), version, text: {en, fr}}`, purposes
unique).

## 8. Flow execution

`startCall` refuses (`invalid_input`, nothing saved) a `callId` that is not 1 to 200 characters the
ledger can carry (no lone surrogate), a `locale` not in `SUPPORTED_LOCALES` (`en`, `fr`), and a `flow` that is not a
name; the engine refuses a `workspaceId` with a lone surrogate. These enter the ledger directly, so
no host value can block a call's ledger. `startCall({flow})` or `startFlow(callId, name)`, on an
open call that has not run a flow, copies
the flow's steps into the call record, so a later config change never moves a call. A flow that
needs a money, contact or access scope is limited per hour (section 6, "Limits across flows"). The first step
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
| `gate.grant` | an access grant issued during the step was delivered | every grant the call may have is used, none delivered and none in flight |
| `step-up.issue` | a step-up token issued during the step became valid (whatever the site does with it later) | every token the call may have is used, none valid and none being signed |

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
| `flow.rate_limited` | `flow`, `scope` (`subject` or `number`): never the subject key, the number or its hash |
| `verification.started` | `subject`: `account`, `host` or `callback` (with `requestedOn`, the call that asked) |
| `verification.factor` | `kind`, `passed` (and `status` for photo ID, `tag` for the PIN, section 6) |
| `verification.factor_error` | `kind` (the judge threw; no factor recorded, the attempt stays counted) |
| `verification.carrier_checked` | `checked`, `textCodeTrusted`, `identityMatch` |
| `verification.locked` | `kind`, `scope` (`subject` or `number`), `hard`, `until`: never the subject key, the number or its hash |
| `verification.callback_started` | `callbackCallId`, on the call that asked, when a callback is placed |
| `verification.callback_finished` | `outcome`: `refused` on the call that asked; `passed`, `no_answer` or `no_confirmation` on the callback call, with `requestedOn`. Never the number |
| `verification.unlocked` | `kind`, `scope`, `counter` (a keyed digest, `unlockedCounter`), `memberId`; call id null, actor `member`: never the key (section 6) |
| `identity.link_sent` | none |
| `verification.finished` | `level`, `methods`, `discounted`, `policyVersion`, `configRevision`; `voidedByTaint: true` when a taint landed in that verification |
| `grant.issued` | `grantId`, `level`, `scopes`, `expiresAt`, `policyVersion`, `configRevision` |
| `pin.enrolled` | none (never the digits, the digest or their length) |
| `pin.reset` | `subjectKey`; actor `member`, `callId` null |
| `duress.cleared` | `subject` (a keyed digest, never the subject key), `memberId` (an opaque id); actor `member`, `callId` null |
| `session.tainted` | `source` |
| `sensitive.opened` / `sensitive.closed` | `reason` / none |
| `intake.started` | `formId`, `version` |
| `intake.confirmed` | `recordId`, `formId`, `digest`, `confirmedBy` |
| `intake.abandoned` | none |
| `redaction.applied` | `kinds` (counts per kind) |
| `payment.amount_read_back` | `amountMinor`, `currency`, `amountSource`, `digest` (never the `amountRef`) |
| `payment.amount_confirmed` | `digest`, `confirmedBy` |
| `payment.link_sent` | `paymentId`, `linkId`, `amountMinor`, `currency`, `amountSource`, `mode`, `expiresAt` |
| `payment.link_expired` | `paymentId`, `provider` (`expired`, `not_open`, or `not_created` when no link was created), and `reason`: none when the engine's deadline came, else `not_sent_in_time`, `not_created_in_time`, `cancelled` or `call_ended` |
| `payment.outcome_ignored` | `paymentId`, `reason` (`account`): an outcome from another account |
| `payment.settled` | `paymentId`, `status`, and `late: true` for a payment made after the engine closed its link |
| `payment.settled` | `paymentId`, `status` |
| `payment.refunded` | `paymentId`, `refundId`, `providerRef`, `amountMinor`, `currency`, `reason`, `status` (`pending`, `succeeded` or `failed`) |
| `payment.disputed` | `paymentId`, `disputeId`, `status`, `amountMinor`, `currency` |
| `consent.recorded` | `consentId`, `purpose`, `wordingVersion`, `wordingDigest`, `answer`, `locale` |
| `call.ended` | none |
| `receipt.issued` | `receiptId`, `digest`, `kid` |
| `access.issued` | `grantId`, `target`, `controller`, `scope`, `level`, `verificationGrantId`, `expiresAt` (section 17) |
| `access.delivered` / `access.refused` / `access.unknown` / `access.failed` | `grantId`, `digest` and `kid` once signed, `confirmed` or `reason` (written by the engine only) |
| `access.code_spent` | `grantId`, `reason` (`wrong_guesses`), `guesses`: a one-time code spent by wrong guesses at its door, never the guess |
| `stepup.issued` | `tokenId`, `site`, `scope`, `level`, `verificationGrantId`, `expiresAt` (section 18) |
| `stepup.exchanged` / `stepup.refused` / `stepup.failed` | `tokenId`, `digest` (and `kid` when signed), `reason` when refused or failed (written by the engine only) |
| `module.event` | `module`, `event`, `detail` (written by an outside module) |

The ledger is always on: every engine needs a `ledger` adapter, and Trace cannot be turned off.
A step's entries are saved in the call record's `outbox` by the same compare-and-set write, each
with an `eventId`, then appended in order. How an event id is formed: the JSON tuple
`[workspaceId, callId, "w", n, index]`, for the `index`th entry (from 0) of the call's `n`th write
that queued entries. The workspace first makes it unique on a ledger that several workspaces
share. It is numbered by those writes, not the store's version, so a write that queues none, such
as a duress alert's acknowledgement, leaves no gap in the ids. The tag `"w"` keeps these ids apart
from the `[workspaceId, callId, version, index]` ids that builds before VER-12 form: an older and a
newer build writing one call on one store (a rolling deploy) never give two entries one id, so the
ledger never drops one as a replay; an entry the ledger would refuse (card data, or detail that is not canonical JSON, such as a lone
surrogate) is refused before it is saved, so it can never block a call's ledger; the outbox is cleared by
a further write if nobody wrote since. A failed append leaves them pending, and the next write or
`flushLedger(callId)` appends them. A ledger appends an `eventId` once (a second append returns the
first entry), so nothing is lost or doubled. The listener is told after each append, at least once
and best effort.

## 10. Audit ledger

Entry: `{seq, prevHash, eventId?, callId, actor, event, at, detail, hash}`. `seq` starts at 1; the first
`prevHash` is 64 zeros; `hash` is SHA-256 over the canonical JSON of every other field.
`verifyChain(entries, from?)` reports the first entry whose `seq`, `prevHash` or `hash` is wrong.
`chainEntry` refuses a detail in which any string (other than a 64-character hex digest) contains
a card number.

## 11. Canonical JSON

Object keys sorted by UTF-16 code units, no whitespace, strings and numbers as ECMAScript
`JSON.stringify` writes them. Refused: `undefined`, functions, symbols, bigints, non-finite
numbers, sparse array holes, objects whose prototype is not `Object.prototype` or `null`, and
strings or property names holding a lone surrogate (RFC 8785, section 3.2.2.2); a valid surrogate
pair is kept. The stand-alone verifier and the reference page refuse the same values, so a receipt
body holding a lone surrogate is invalid (the engine cannot have signed it). So that no call is
ever left with a ledger entry it cannot append, a step whose ledger detail canonical JSON refuses
is refused with `invalid_input` before it is saved; `markUntrusted` replaces a lone surrogate in
its label with U+FFFD and a card number with `[card number removed]`, so the taint always lands; and `validateConfig` refuses a config holding a
lone surrogate in any string or key.

## 12. Receipts

```json
{
  "body": {
    "v": 1, "receiptId": "...", "callId": "...", "workspaceId": "...",
    "startedAt": "...", "endedAt": "...", "issuedAt": "...",
    "verification": { "level": 3, "methods": ["keypad_knowledge", "photo_id"],
                      "policyVersion": "default-1", "configRevision": "2026-11-18.1" },
    "records":  [{ "recordId": "...", "formId": "...", "digest": "<sha256 hex>" }],
    "payments": [{ "paymentId": "...", "status": "paid", "amountMinor": 15000, "currency": "cad", "mode": "platform", "providerRef": "cs_..." }],
    "consents": [{ "purpose": "...", "wordingVersion": "1", "wordingDigest": "<sha256 hex>", "answer": "yes" }],
    "stepUp":   [{ "tokenId": "stu_...", "expiresAt": "...", "status": "issued" }],
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
part. `verification.policyVersion` and `verification.configRevision` name the policy and the
FlowConfig revision that judged the call's last finished verification (whatever level it reached);
both are absent when no verification finished on the call. They are optional, so the format stays
at `v: 1`, and a reader that does not know them still checks the signature over the whole body.
`ledger` is the head after `call.ended`, kept in the call record. If signing fails, `endCall` on
part. `ledger` is the head after `call.ended` and the expiry of the call's open payment links
(section 14), kept in the call record. If signing fails, `endCall` on
the ended call issues the receipt later with the same head, without ending the call again. `verifyReceipt(receipt, keys)` picks the key by `kid`
part. `ledger` is the head after `call.ended`, kept in the call record. If signing fails, `endCall` on
the ended call issues the receipt later with the same head, without ending the call again.
`stepUp` is step-up's part (section 18): each token record the call has, `{tokenId, expiresAt,
status}` as the end of the call left it, `failed` ones included (a reservation whose signing failed
is listed too, so the part's presence is no proof that a token became valid). It is present only
on a call with at least one record, so the format stays at `v: 1`. `verifyReceipt(receipt, keys)` picks the key by `kid`
and returns false for any change, a wrong algorithm, a malformed signature or an unknown key.

The `ReceiptSigner` contract: `sign(payload)` returns an ES256 (ECDSA P-256 with SHA-256)
signature over exactly the payload bytes, in IEEE P1363 form: `r || s`, each a 32-byte big-endian
integer, 64 bytes in all. `signReceipt` refuses any other length with `invalid_input`, and then
verifies the signature against the signer's own `publicJwk()` (with `verifyReceipt`), refusing one
that does not verify (a wrong key, a 64-byte DER signature, bytes that are not a signature), so no
receipt is issued that cannot verify. Most key management services return DER
(`SEQUENCE { r INTEGER, s INTEGER }`); `derToP1363(der)` converts it, and throws a TypeError on
anything that is not a minimal DER encoding of two positive integers of at most 32 bytes with
nothing after them. `publicJwk()` returns the public key published in the key set.

### Key sets and rotation

`receiptKeyRing({ signers, active, retired? })` is a `ReceiptSigner` that holds several signers
and signs with the one whose `keyId` is `active`; a receipt's `kid` names the key that signed it.
`retired` are public JWKs, each with its `kid` and its `retiredAt` (an ISO 8601 UTC time, as
`toISOString` writes it), of keys that signed earlier receipts and sign no more; their private
keys are not needed. `keySet()` lists the active key first, then the other signers' keys, then the
retired ones, each as `{kty: "EC", crv: "P-256", x, y, kid, alg: "ES256", use: "sig"}`, a retired
one also with `retired: true` and its `retiredAt`, and nothing else. The ring throws a TypeError,
when the host builds it, for an active kid no signer has, a key without a kid, two keys with one
kid, a signer whose public key names another kid, a key with a private part (`d`), a key that is
not a P-256 public key, or a retired key without an ISO 8601 UTC `retiredAt`.

A key with `retiredAt` verifies only a receipt whose `issuedAt` is before it. `checkReceipt(receipt,
keys)` answers `{valid: true, retiredAt: null}` under a key that is not retired, `{valid: true,
retiredAt}` under a retired key for a receipt issued before its retirement (shown as "valid,
signed with a retired key (retired <retiredAt>)"), and `{valid: false}` otherwise, including a
receipt the retired key signed at or after `retiredAt` and a `retiredAt` or `issuedAt` that is
not an ISO 8601 UTC time. `verifyReceipt` is its `valid`.

`engine.receiptKeys()` returns a key ring's whole `keySet()`, a single signer's one key, or `[]`
without a signer. The reference server serves it at `GET /.well-known/receipt-keys.json` as
`{"keys": [...]}`. To rotate without breaking old receipts:

1. Add the new signer to every process's ring, still with the old `active`, so the new key is
   published before it signs anything.
2. Make the new key `active` in every process.
3. Move the old key's public JWK to `retired`, with `retiredAt` the time the new key took over. Its
   private key can then be destroyed.

A retired key stays in the key set for as long as receipts it signed must verify. A key that
leaked is removed, not retired: every receipt it signed then fails to verify, as it should, since
anyone holding the key could have signed it.

### Checking a receipt without this package

`scripts/verify-receipt.mjs` is one file with no dependencies beyond Node 24.2 or later; it can be
copied out of the repository on its own. It takes a receipt (a file, or `-` for standard input) and
a key set (a file, or a URL), and repeats only what a verifier needs: the canonical JSON of
section 11 and ES256 over it.

```sh
node scripts/verify-receipt.mjs <receipt.json | -> <keys.json | https://host/.well-known/receipt-keys.json>
```

| Exit | Output | When |
|---|---|---|
| 0 | `valid` | the key named by `kid` verifies the signature over `canonicalJson(body)` |
| 0 | `valid, signed with a retired key (retired <retiredAt>)` | the same, under a retired key, for a receipt issued before its retirement |
| 1 | `invalid: <reason>` | `body.v` is not 1, `alg` is not `ES256`, no key has the `kid`, the key is not a public P-256 key, the key is retired and the receipt was issued at or after its `retiredAt` (or either time is not ISO 8601 UTC), the signature is not 86 base64url characters (64 bytes), or it does not match the body |
| 2 | a message on standard error | it could not check: wrong arguments, an unreadable or non-JSON file, a key set that is not `{"keys": [...]}` or a list, more than 1 MiB, or a URL it may not or cannot fetch |

A key set URL must be `https`, or `http` on `127.0.0.1`, `localhost` or `[::1]`, because a key set
fetched in the clear could be swapped for one that makes a forged receipt look valid. Redirects are
refused. A worked example, against the demo server on this machine (`npm run ui`, after the
`deposit` flow has run to its end in the page, which makes `call_1` with a payment of 15000):

```sh
$ curl -s http://127.0.0.1:8787/receipts/call_1 > receipt.json
$ node scripts/verify-receipt.mjs receipt.json http://127.0.0.1:8787/.well-known/receipt-keys.json
valid
$ curl -s http://127.0.0.1:8787/.well-known/receipt-keys.json > keys.json   # or keep a copy
$ sed 's/"amountMinor":15000/"amountMinor":1500/' receipt.json | node scripts/verify-receipt.mjs - keys.json
invalid: the signature does not match the body
$ echo $?
1
```

The key set can be fetched once and kept: since retired keys stay in it, a copy taken after a
receipt was issued verifies that receipt for as long as its key is not removed. A saved copy does
not receive revocations: if a key is later removed from the published key set (because it was
compromised), the saved `keys.json` still holds it and the verifier still accepts signatures made
with it. A saved key set therefore preserves historical verification only; it says nothing about a
key's current status. When current trust matters, verify against the key set URL, or refresh the
saved copy from it first.

Record digests are `SHA-256(canonicalJson({formId, version, values}))`; wording digests are
`SHA-256(canonicalJson({purpose, version, text: {en, fr}}))`.

## 13. Intake values

| Type | Accepted | Stored as |
|---|---|---|
| `text` | trimmed, non-empty, well-formed Unicode (no lone surrogate), at most `maxLength` (500), and no card number | string |
| `number` | `-?\d+(\.\d+)?` | number |
| `date` | `YYYY-MM-DD` naming a real day | string |
| `yes_no` | `yes`, `y`, `oui` / `no`, `n`, `non`, any case | boolean |

Forms live in Dossier's settings: a `formId` (lower case, digits, `-`, `_`), a `version` and
fields with snake_case unique keys, a known type and an English and a French label.
`validateConfig` refuses fields marked `sensitive` until field encryption exists (FIL-2).
`setIntakeField` refuses (`invalid_input`) a value with a lone surrogate, which speech-to-text or a
model can produce and a record's digest cannot hash. `startIntake(callId, formId)` names the form,
and the draft keeps the form as it was then, so a
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

`requestPayment` needs `payment.request`, a confirmed amount read-back (below), a positive integer amount in minor units up to
Paylink's `maxAmountMinor` (at most 1,000,000), a lower-case ISO 4217 currency, a 1 to 200
character description and an `amountSource` (`intake_record`, `business_endpoint` or
`price_list`). In a flow they come from the `paylink.request` step and the host passes none;
outside a flow the host's code passes them. One link at a time per call. If creating or texting the
link fails, the request stays open (a provider can create a link and still fail to answer), and
calling `requestPayment` again resumes it with the same payment id and idempotency keys; a
different amount is refused. `requestPayment` returns the status it saw last and `expiresAt`.

**Modes.** `connect` takes the money on the business's own account at the provider (a direct
charge; the business is the merchant), `platform` on the platform's own account (the platform is
the merchant). The step's `mode`, else Paylink's `mode`, else `platform`. The request to
`PaymentLinks.createLink` carries `mode`, `connectedAccountId` (exactly in connect mode, from
Paylink's settings), `paymentMethods` and `expiresAt`, and its idempotency key is the JSON tuple
`[workspaceId, callId, paymentId, "link", mode]`. A provider outcome carries `account` when it
came from a connected account; it must equal the payment's `connectedAccountId` in connect mode
and be absent in platform mode, or it is ignored (`payment.outcome_ignored`). In platform mode
the platform refunds and answers disputes (below); in connect mode both are the business's, on its
own account, and the engine handles neither.

**Link life.** A link lives `linkLifeMinutes` (step, else settings, else 15; 5 to 60) from the
moment it was texted, but never past what the provider was asked for: `expiresAt`. The provider is
asked for twice the link life from the request (so a text resumed late still gets its full life),
and at least the payments adapter's `capabilities.minLinkMinutes` plus 5 minutes (so the create
that follows is never under the minimum), at most its `maxLinkMinutes` (Stripe Checkout: 30
minutes to 24 hours). A request whose link is not known to exist and has less than the provider's
minimum left is expired before any create (`payment.link_expired`, provider `not_created`), unless
another process recorded a link for it in the meantime, which that process then decides about
(`precondition_failed` here). The adapter's `maxLinkMinutes` must be at least its `minLinkMinutes`
plus 5, or the config is refused. A link
is never texted with less than 5 minutes of the provider's life left: it is expired at the provider
(`payment.link_expired`, reason `not_sent_in_time`) and the request settles `expired` when the
provider confirms, or waits for its webhook when the provider says `not_open`. Either way
`requestPayment` throws `precondition_failed`. A process about to text a link holds a 60 second
lease on it, so a concurrent resume refuses (`precondition_failed`) rather than expiring a link
being sent; once the lease lapses, it may, and a sender stalled past it then texts a link the
provider has already closed (so it cannot be paid). A process whose request another process
settled while its create was slow never texts the link it got: it expires it at the provider and
throws `precondition_failed`. The create guard keeps a minute over the provider's minimum for its
latency; a create the provider still refuses leaves the request to the next resume, which expires
it. `expirePaymentLinks(callId)`, which the host
calls at `expiresAt` or later, asks the provider to expire each texted link still open past its
deadline (`expireLink`): on `expired` the request settles `expired` (and its flow step fails); on
`not_open` it is left for the provider's webhook, which may still say paid. A link that was never
texted never expires this way; it stays open to resume.

**Cancel and call end.** `cancelPaymentLink(callId, paymentId)` closes a payment the caller no
longer wants, through `PaymentLinks.cancel` when the adapter has it (idempotency key
`[workspaceId, callId, paymentId, "cancel", mode]`), else through `expireLink` (key `[..., "expire",
mode]`). It needs no scope, since it only closes; an unknown payment id is `invalid_input`, and a
payment no longer open is left as it is and its status returned. `endCall`, once the call has
ended, expires every payment still open through `expireLink`, so the receipt shows it `expired`.
In both cases the payment settles `expired` whatever the provider answers (`expired` or
`not_open`), the session leaves `paying`, its flow step fails, and `payment.link_expired` carries
`reason` `cancelled` or `call_ended`. A request whose link was never created, or whose create was
never answered, is settled without asking the provider (`provider: not_created`); if the create
then answers, `requestPayment` expires that link at the provider, never texts it, and throws
`precondition_failed`. The same holds for a create that answers after the call ended, even before
the end closed its request. While a process is texting a link (it holds the send lease, 60
seconds), `cancelPaymentLink` and `endCall` are refused with `precondition_failed`, so a link is
never closed under its own text and no text goes out after the call ended; once the text is
recorded, or the lease lapses (that sender stopped), they go ahead. A sender checks and renews
its lease in a write right before the text, so one that stalled past its lease (binding the
link's reference) never texts a request that was closed or a call that ended meanwhile: it expires
the link at the provider and throws `precondition_failed`; one whose lease another sender took
stops too. `endCall` appends any ledger entries still pending before it takes the receipt's head,
so the head covers every entry the end wrote. A sender that comes back after
its request was closed records nothing, so no entry follows the close or the receipt. If the
provider fails while the call ends, the call stays ended without its receipt, and `endCall` again
expires what is left and issues it.

**Late payments.** A payment the engine settled `expired` (its deadline, a cancel, the end of
the call, or a text that could not go out in time) can still be paid by a caller already on the
page. The money moved, so a `paid` outcome for it is recorded: the payment becomes `paid` and
`payment.settled` carries `late: true`. The session and the flow do not move, and a receipt
already signed is not changed: the ledger is where the late payment shows.

**Adapter capabilities.** `PaymentLinks.capabilities` declares `{modes, minLinkMinutes,
maxLinkMinutes}`. When the config is saved, a step's mode (and Paylink's default mode) must be one
the adapter takes, and the link life no longer than its maximum (`refund` is optional: no flow
step needs it, so a platform payment flow is valid without it); malformed capabilities are a
problem too, and so is an engine's payments adapter that declares no capabilities at all (a plain
JavaScript adapter). Adapters are given when the engine is built, so these checks run when the
engine is built (`createEngine`) and when a config is saved (`configure`), not at `engine.use`,
which installs modules; a refused adapter never fails mid-call. A registry built without capabilities (only adapter names) skips these checks; an engine
always has them.

**Methods.** `paymentMethods` lists only methods that settle during the call: `card` (credit, and
Visa and Mastercard debit), `apple_pay`, `google_pay`, `link`; the default is all four. Anything
else is refused when the config is saved, with the reason for `acss_debit` and `us_bank_account`
(they settle in days) and Interac (not offered for online payments). How a provider names them is
the adapter's.

Settlement:

| Provider outcome | Status |
|---|---|
| completed, `payment_status: paid` | paid |
| completed, `unpaid` | none yet (wait for the asynchronous result) |
| completed, `no_payment_required` | failed |
| async payment succeeded | paid |
| async payment failed | failed |
| expired | expired |

A payment recorded before modes existed (no `mode`) appears on its receipt as `platform`: it was
taken on the host's own account. A request settles once; later outcomes are ignored, with one exception: money that moved is
always recorded. A request the engine expired (its own deadline, a link too late to text, a race
with a slow create, a cancel or the end of the call) that the provider then reports paid becomes
`paid`, and `payment.settled` carries `late: true`.

**Refunds (platform mode).** `refundPayment({callId, paymentId, amountMinor?, reason})` is a host
call made for the business (its back office or staff): no grant reaches it, no flow step runs it,
and the model is never given it. It refunds a `paid` platform payment in full (the default: all
that is left) or in part, with `reason` one of `requested_by_customer`, `duplicate`, `fraudulent`.
Refused: `invalid_input` for a bad reason or amount, an unknown payment, or refunds that would add
up to more than was paid (a refund the provider answered `failed` does not count);
`precondition_failed` for a payment not `paid`, a connect payment, a payment refunded in full, a
payment with a dispute open or lost (the provider refuses those too), and an engine whose payments
adapter has no `refund`; `module_disabled` on a call that started with Paylink off. A refund is
reserved in one write (one in flight per payment; asking again while it is resumes it, and another
amount is refused), sent with `PaymentLinks.refund({linkId, paymentIntentId?, mode: "platform",
amountMinor, currency, reason, idempotencyKey})`, the key being `[workspaceId, callId, paymentId,
"refund", refundId]`, and committed in another write with the provider's answer and
`payment.refunded`. It returns `{refundId, status, amountMinor, refundedMinor}`. A refund still
in flight is resumed with its own key before the dispute check, which is for new refunds: a refund
the provider made whose answer was lost is learned even if a dispute opened since. An adapter
answers a refund the provider refused as `failed` and throws only when the answer was lost: a
refund that threw stays in flight and the next `refundPayment` resumes it with the same key, so
an adapter that throws for a refusal blocks the payment's refunds. An answer that is not one of the
provider's three (`pending`, `succeeded`, `failed`, with a refund id) is treated the same way, as a
lost answer (`precondition_failed`): nothing is recorded or ledgered, the refund stays in flight,
and while an adapter keeps answering that way every later refund of the payment is blocked, since
one is in flight at a time. A refund the provider made is learned once the adapter answers properly. A `pending` refund counts
toward the total; its later outcome at the provider is not tracked yet (#117), so one that fails
later still counts until the business refunds the rest by hand at the provider.

A platform payment paid late (after the engine closed its link) keeps its payment intent too, so
its disputes and refunds land like any other's.

**Disputes (platform mode).** Stripe's `charge.dispute.*` events name the charge and the payment
intent, not the Checkout Session. When a platform payment settles `paid`, the outcome's payment
intent is kept on it and bound to the call (`payment_intent:<id>`), after the write, and again on
every later outcome for the link, so a lost binding is made when the event comes again.
`applyDisputeOutcome` finds the payment by it and records the dispute's status and amount
(`payment.disputed`). A dispute that names no payment intent is not applied (`{applied: false}`);
one whose payment intent is not bound yet answers `{applied: false, unbound: true}`, since
webhooks come in any order and the payment's own event may still be on its way: the host has it
delivered again (the reference server answers 503 and does not remember the event, so Stripe
retries it within its own retry window). A connected account's dispute event is ignored
(`payment.outcome_ignored`). A later paid outcome that names the payment intent of a payment
already paid without one keeps it too. `won` and `lost` are
final; an event that changes neither status nor amount is not written again.

Refunds and disputes work after the flow and the call ended. They never change a payment's
`status`, the flow, or the receipt already issued. `PaymentLinks.refund` is optional: refunds and
disputes are host calls and webhooks, never flow steps, so no config needs it and a platform
payment flow is valid without it; `refundPayment` on an engine whose adapter has none is
refused (`precondition_failed`), and disputes are still recorded.

**Amounts from code, read back first (PAY-2).** Instead of `amountMinor` and `currency`, a step
(or, outside a flow, the host's code) can name an `amountRef`, which the host's `AmountSource`
adapter (`amounts`) resolves: `resolve({workspaceId, callId, source, reference, subjectKey,
recordIds})` returns `{amountMinor, currency}` or null. `source` is the step's `amountSource`;
`subjectKey` is the subject Badge matched; `recordIds` are the records filed on the call.
`PriceListAmounts` is the reference adapter (a fixed table, `price_list` only).

- `readBackPayment(callId, input?)` needs `payment.request`, a matched subject and an open call,
  takes its request like `requestPayment`, resolves an `amountRef` (null is `precondition_failed`;
  an answer that is not a valid amount under the limit is `invalid_input`), and returns `{text,
  digest, amountMinor, currency, description}`. `text` comes from `AMOUNT_READBACK_TEXT` in the
  call's locale: "The amount to pay is AMOUNT, for DESCRIPTION. Is that correct?" / "Le montant à
  payer est de AMOUNT, pour DESCRIPTION. Est-ce exact ?"; `digest` is `SHA-256(canonicalJson({amountMinor, currency,
  description, locale, text}))`. The call keeps the read-back (one at a time; a new one replaces
  it) until a link uses it. Untrusted content drops it. The read-back is for the subject matched
  when the amount was looked up: if another subject is matched by the time it is stored, it is
  refused (`precondition_failed`).
- `confirmPaymentAmount(callId, {digest, confirmedBy})` records that the caller said yes.
  `confirmedBy` is `voice` or `keypad` and `digest` a string, else `invalid_input`, before
  anything is written. A digest that is not the last read-back's is refused
  (`precondition_failed`); confirming twice is harmless.
- `requestPayment`: every link needs a read-back on the call that the caller confirmed, whether
  the amount is fixed (in the step or the host's code) or comes from an `amountRef`; without one
  it is `precondition_failed` and nothing is created or texted. The request must be the one read
  back (or none, outside a flow), and the link is for the amount the caller heard, checked again
  against the limit in force. A read-back for another subject than the one matched now is
  refused. A call with a link already out is refused as before (`invalid_transition`). A request
  still being sent resumes with no input, the same amount, or the same `amountRef` request it was
  made for, without a new read-back. The mode, link life and payment methods still come from the
  step and the settings when the link is reserved.

## 15. Stripe webhooks

`verifyStripeSignature` follows Stripe's published scheme: the `Stripe-Signature` header has
`t=<unix seconds>` and one or more `v1=<hex>`; each `v1` is `HMAC-SHA256(secret, t + "." + raw
body)`. The check passes if any `v1` matches any configured secret and `t` is within 300 seconds
of now, either way. A host may set `toleranceSeconds`, an integer from 0 to 86,400; any other
tolerance, or a `now` that is not a valid `Date`, throws `invalid_input` before anything is
checked, since a NaN or an Infinity would let a replay of any age pass. `parseStripeEvent` maps
`identity.verification_session.{verified,requires_input,canceled}` and
`checkout.session.{completed,async_payment_succeeded,async_payment_failed,expired}` (with the
session's `payment_intent` when it is a string) and
`charge.dispute.{created,updated,closed,funds_withdrawn,funds_reinstated}` (the dispute id, `charge`,
`payment_intent` or null, `status`, `amount` and `currency`; never its evidence); other types
are reported as ignored, and a body that is not a well-formed event is `null`, including one whose
`account` is present but not a string (never read as "no account"). The reference server
applies dispute events from the platform's payments endpoint only.

The reference server's `StripeIdentityProvider` (an example, not part of the package) is an
`IdentityProvider` that calls Stripe with `fetch`. `createDocumentCheck` sends one
`POST /v1/identity/verification_sessions`, form-encoded, with exactly `type=document`,
`options[document][require_matching_selfie]=true` and `metadata[call_id]=<call id>` (the call id
as is when it is at most 500 UTF-8 bytes, Stripe's metadata value limit, and otherwise `sha256:`
and its hex SHA-256, the same every time, so a long call id still gets a check), and the
headers `Authorization: Bearer <restricted key>`, `Idempotency-Key`, and a pinned
`Stripe-Version` (`2025-03-31.basil`). The `Idempotency-Key` is the engine's key as is when it is
1 to 255 printable ASCII characters without spaces, and otherwise `sha256:` and the hex SHA-256 of
it, so the same engine key always sends the same header and a resumed `startPhotoId` gets the same
session and link. It answers the session's `id` (which must start with `vs_`) as the session id
and its `url` (which must be `https://` and then 1 to 2,040 printable ASCII characters, no space,
line break or control character, since it goes into a text message as is) as the link. The constructor takes only a restricted key
(`rk_test_` or `rk_live_`); `npm run serve` takes only `rk_test_`. A refusal or a malformed answer
throws `StripeApiError` with the HTTP status and Stripe's error type and code when they are plain
identifiers, never Stripe's message or any value from the request or the answer. Requests time
out after 10 seconds (`timeoutMs`, a whole number from 1 to 60,000) and never follow a redirect.
An `apiBase` option must be `https:`, or `http:` on a loopback host (`127.0.0.1`, `localhost`,
`[::1]`) only, with no credentials in it; anything else, and a bad `timeoutMs`, throws in the
constructor, never quoting the value.

## 16. Texts

Code builds every text, in the call's locale, one of `SUPPORTED_LOCALES` (exported, a frozen
`["en", "fr"]` whose members are the `Locale` type; `isSupportedLocale` checks a host's value).
Each catalog of code-built words is a `Record<Locale, ...>`: `IDENTITY_TEXT`, `PAYMENT_TEXT`,
`AMOUNT_REGION` (where amounts are formatted) and `DIGIT_WORDS_BY_LOCALE` (the spoken digits the
card-number detector reads, every locale's always on). A test fails when a catalog lacks a
supported locale, when a `Record<Locale, ...>` in `src/` is not one it checks, or when code picks
words by comparing a locale instead, so a new locale grows every catalog. The destination is always the
subject's number on file. Identity link: "Your one-time identity check link: URL" / "Votre lien
de vérification d'identité, à usage unique : URL". Payment link: "Your secure payment link for
AMOUNT: URL" / "Votre lien de paiement sécurisé pour AMOUNT : URL", with the amount formatted in
the currency's own decimals. Access code (section 17): "Your one-time door code: CODE. It works
once, within N min." / "Votre code de porte, à usage unique : CODE. Valable une fois, dans les N
min.", N being the minutes left on the access grant, rounded up, at least 1.

## 17. Gate and access grants

Gate's settings: `targets`, at least one, each `{id, controller, ref}`: `id` lower-case letters,
digits and `-` (unique), `controller` the name of one of the engine's `access` adapters that has an
`unlock` function, own or from its class (checked when the engine is built and when a config is
saved), `ref` the controller's own name for the
door, 1 to 200 characters; `maxGrantsPerCall` 1 to 5, default 3. A call keeps the targets in force
when it started; a flow attached later is refused when a step names a target the call did not keep.

The engine owns every access grant (ADR-25): it reserves it, signs it, computes its digest, calls
the controller and records the controller's answer, in its own writes. Module code never writes a
grant or its outcome. `engine.grantAccess(callId, input?)`: in a flow the `gate.grant` step names
the target and the lifetime (pass no input); outside one the host's code passes `{target,
lifetimeSeconds?}` (anything else is `invalid_input`; other fields are ignored, never applied).
`engine.accessGrants(callId)` lists a call's grants as recorded; `engine.accessKeys()` is the
access signer's public key set. The access signer must be its own key: an engine whose
`accessSigner` has the receipt signer's key id or public key is refused when it is built, so a
receipt never verifies as an access grant. A host's module can never take a built-in module's name
(`engine.use` and `modules` refuse it, even after the built-in module was removed).

1. **Settle stale grants**, in a write of their own (so it holds even when the request is then
   refused): a grant still reserved past its expiry (its process stopped before recording the
   answer) becomes `unknown` (`access.unknown`, reason `no_answer_recorded`, with its digest and key
   id when it was signed). At the grant limit, that fails the step.
2. **Reserve**: refused with `precondition_failed` off the flow's current step, `scope_denied`
   without a verification grant covering `entry.open` (checked on every request, in a flow or
   not: none, expired, tainted, or below today's minimum), `invalid_input` for a missing or unknown
   target or a bad lifetime, and `precondition_failed` while another grant of the call is in flight
   or once `maxGrantsPerCall` grants were issued, and `precondition_failed` when the engine has no
   access controller by the target's name (own adapter entries with an `unlock` function only), and
   `conflict` when the id generator gives a grant id the call already used (nothing is reserved; a
   retry draws a new one). The grant's expiry is the earlier of now plus its
   lifetime and the verification grant's expiry. Ledger: `access.issued`.
3. **Sign**: ES256 over the canonical JSON of the body below, with the `accessSigner`. The engine
   computes the digest (SHA-256 of those bytes) itself. A signing failure settles the grant
   `failed` (`access.failed`, reason `not_signed`; nothing sent) and throws.
4. **Check again**, in a write: if the grant was settled meanwhile (the call ended), the call is no
   longer authorized for `entry.open`, or the grant expired while it was signed, nothing is sent
   and `scope_denied` is thrown (the last two settle it `failed`, reason `not_authorized` or
   `expired`). The digest and key id are written to the grant.
5. **Send once** to the target's controller (if it was removed from the adapters meanwhile, the
   grant is settled `failed`, reason `not_sent`, and `precondition_failed` is thrown: nothing was
   sent, so it is never recorded as `unknown`): `unlock({grant, target, idempotencyKey})`, the key
   being `[workspaceId, callId, grantId, "unlock"]`. Never retried. Right before it, with nothing in
   between, the call is checked once more against the config in force, so a config that raised
   `entry.open`'s floor after step 4 settles the grant `failed` (`not_authorized`) and nothing is
   sent. A config changed by another process is seen at its next write, not here.
6. **Record the answer**, in the engine's write: `delivered` (with `confirmed` when the controller
   reported the door moved), `refused` (the controller certainly did not act; its reason as a short
   code), or `unknown` (reason `answer_lost`) when the call threw or timed out. A grant settled
   meanwhile stays as it is. `grantAccess` returns what the call holds. A failure to write the
   answer is thrown as it is; the grant then settles as stale (step 1). Every outcome entry carries
   `grantId`, `digest` and `kid`, never the grant or its signature. A fresh request after `unknown`
   is a new grant.

**Ending a call** is refused (`precondition_failed`) while a signed grant may still be acted on: at
its door (step 4 passed, its answer not yet recorded) or sent with its answer lost (`unknown`, the
controller may still be working on it), and not yet expired. A definitive answer (`delivered`,
`refused`) lets the call end at once. The end waits for an answer still due, bounded by the
controller's timeout, or for the grant's expiry if the answer was lost or its process stopped. A grant reserved but not yet
signed is settled `unknown` (reason `call_ended`) in the same write that ends the call, and is then
never sent (step 4 finds it settled); one that expired is settled `unknown` (reason
`no_answer_recorded`). All of it happens before the receipt's ledger head is taken, so no access
outcome ever follows `receipt.issued`, and no grant reaches a door after the receipt while it can
still open it: once it expires, a relay refuses it (`verifyAccessGrant`). A controller that does not
check a grant's expiry could still act on a request delayed past it; the relay contract requires the
check.

```json
{
  "body": {
    "v": 1, "kind": "access", "grantId": "acc_...", "workspaceId": "...",
    "audience": "<controller name>", "target": "<controller's door ref>", "action": "unlock",
    "scope": "entry.open", "level": 2,
    "issuedAt": "2026-01-01T00:00:00.000Z", "expiresAt": "2026-01-01T00:01:00.000Z"
  },
  "alg": "ES256", "kid": "...", "signature": "<base64url of the 64-byte r||s signature over canonicalJson(body)>"
}
```

`verifyAccessGrant(grant, keys, {workspaceId, audience, now, clockSkewSeconds?})` returns `{ok:
true, body}` or `{ok: false, reason}`: `invalid_options` (a `clockSkewSeconds` that is not a
finite, non-negative number, or a `now` that is not a valid date: refused, so neither time check
ever turns off), `malformed` (not
this shape), `signature` (unknown `kid`,
another algorithm, any change), `workspace` (issued by another workspace, or no `workspaceId`
given: it is required, so workspaces sharing a key and a controller name never open each other's
doors), `audience`, `not_yet_valid` (with `clockSkewSeconds` of allowance, default 30, for a
grant issued a little ahead of the relay's clock), `expired` (strict: from `expiresAt` on, whatever
the skew, because the engine ends a call only once every grant at a door has answered or expired),
and `lifetime` (longer than 900 seconds, or ending before it starts). This assumes the engine's and
the relay's clocks agree (NTP): a relay whose clock runs behind by some seconds accepts a grant for
that much longer. `new SeenGrants()`: `accept(body, now)` is true once per grant id (false for an
expiry it cannot parse or a `now` that is not a valid time), and keeps the
id until the grant expires, when the verifier refuses it anyway. It keeps a forget point: ids are
forgotten only once their grant expired at or before it, and any grant expiring at or before it is
refused, so a grant accepted once is never accepted again, under any sequence of clock jumps and
rollbacks. The forget point follows the relay's clock but never passes the latest expiry it has
accepted, so a clock that jumped forward refuses no fresh grant beyond one grant lifetime (at most
15 minutes) of grants it has really seen. It knows a grant by its id alone, so grant ids must be
unique per workspace: the default generator is random (96 bits); a host's own `ids` that repeats
across calls or processes makes a relay refuse a fresh grant as a replay. `engine.accessKeys()` is the public key set.
It, and `engine.receiptKeys()`, publish only a key's public members (`kty`, `crv`, `x`, `y`, `kid`,
`alg`, `use`), whatever a signer's `publicJwk` returns, so a signer that hands back its private `d`
never has it published.
15 minutes) of grants it has really seen. `engine.accessKeys()` is the public key set.
Every key set the engine publishes (`receiptKeys()`, `accessKeys()`, `stepUpKeys()`) holds only
the public members of each key (`kty`, `crv`, `x`, `y`, `kid`, `alg`, `use`), whatever its
signer's `publicJwk` returns, so a signer that hands back its private `d` never has it published.

**The relay contract, version 1** (`webhookRelay({url, timeoutMs?})`): `POST <url>` with
`content-type: application/json`, `idempotency-key: <the key above>` (as printable ASCII: any
other character is written as a JSON `\uXXXX` escape, so the header parses to the same tuple; a
header cannot carry a character past U+00FF) and the signed grant as canonical JSON. HTTPS only, or HTTP to `127.0.0.1`, `localhost` or `[::1]`; no credentials in the
URL; redirects are not followed; the timeout is 100 to 30,000 ms (default 5,000). The relay
answers 2xx after it worked the door, optionally `{"state": "confirmed", "ref": "<its id>"}`; 4xx
when it did not act, optionally `{"error": "<code>"}` (`signature`, `workspace`, ...). A 409
(`replay`) is not a refusal: an earlier request with this grant was accepted and may have opened
the door, so it is `unknown`. Anything else, including no answer, is `unknown` too. A relay checks the grant with `verifyAccessGrant` against
`engine.accessKeys()`, its own workspace and its own audience, and refuses a grant id it has seen.

**The Seam adapter** (`seamAccessController({apiKey, baseUrl?, allowLoopbackForTests?, timeoutMs?,
confirmWithinMs?, pollIntervalMs?, fetch?, clock?})`), named in the engine's `access` adapter like
any controller: the target's `ref` is the Seam `device_id`. `baseUrl` defaults to
`https://connect.getseam.com`, and its host must be one of `SEAM_HOSTS` (`connect.getseam.com`),
over HTTPS on the default port, with no credentials, query or fragment: the API key goes nowhere
else. The loopback address, over HTTP or HTTPS, is accepted only with `allowLoopbackForTests: true`,
which is for tests and never for production; `timeoutMs` is per request, 100 to 30,000 (default 5,000); `confirmWithinMs` 0 to 30,000
(default 10,000) and `pollIntervalMs` 10 to 5,000 (default 1,000). Every request is a `POST` with
`authorization: Bearer <apiKey>` and a JSON body, redirects not followed. No idempotency key is
sent: Seam documents none on unlock.

1. `POST /devices/get {device_id}`. Unless the answer names the same device with
   `can_remotely_unlock: true` and not `properties.online: false`, the result is `refused`:
   `cannot_unlock_remotely`, `device_offline`, `device_unreadable`, Seam's error type on a 4xx
   (`device_not_found`, ...) or `http_<status>`, and `seam_unavailable` on a 5xx or no answer.
   Nothing was sent to the lock.
2. Unless the grant has at least `timeoutMs` left by `clock` (the system clock by default), the
   result is `refused` (`grant_expiring`) and nothing is sent, since the expiry is strict and the
   call may end then. This bounds when the unlock is sent and how long the client waits for it,
   not the network, and Seam's own attempt may still complete later.
   Otherwise `POST /locks/unlock_door {device_id}`, once, never retried. A 4xx is `refused` (Seam's error
   type when it is a short code, otherwise `http_<status>`); a 5xx, a timeout, a dropped connection,
   a redirect, or a 2xx without an action attempt (`action_attempt_id` 1 to 200 characters, `status`
   `pending`, `success` or `error`) throws, which Gate records as `unknown`.
4. While the attempt is `pending`: `POST /action_attempts/get {action_attempt_id}` after each
   pause of `pollIntervalMs`, the whole wait held to `confirmWithinMs` of elapsed time (each pause
   and each request is cut to what is left; 0 never asks). `success` is `delivered`, `confirmed:
   true` only when Seam reports `result.was_confirmed_by_device: true` (a `success` alone means
   Seam sent the command, not that the lock moved); `error` throws (`unknown`: a lock that timed
   out may still have moved); still `pending`, or an answer that cannot be read, is `delivered`
   with `confirmed: false`. `providerRef` is the action attempt id. Each request's path is set on
   a copy of `baseUrl`, so its host is always `baseUrl`'s.

A momentary unlock has nothing to revoke: there is no grant revocation, by design (ADR-22);
revoking an issued code belongs to one-time codes, below. Planned: web sign-in step-up as an ES256 JWT against a JWKS
(GAT-4), a Seam adapter (GAT-5), direct vendor adapters (GAT-6).

**One-time access codes** (`src/gate/codes.ts`), for a door whose controller cannot be called
live: `accessCodes({key, signer, store, ledger, messages, limits, maxWrongGuesses?, clock?, newCode?})`.
`key` is the codes' own HMAC key, at least 16 bytes (else `invalid_input`); `signer` is the
engine's `accessSigner`, so a relay checks a redeemed grant against `engine.accessKeys()`;
`ledger` is the engine's, for `access.code_spent`; `maxWrongGuesses` is 1 to 10, default 5 (else
`invalid_input`). Its `controller` is an
`AccessController` that the engine's `access` adapter names like any other
(`access: { keypad: codes.controller }`), and a target names that controller.

- `codes.issue(engine, callId, input?)` first draws its 3 candidate codes from `newCode`; any that
  is not exactly 8 digits (`ACCESS_CODE_DIGITS`) fails the issue with `invalid_input`, a host
  fault, before anything is reserved, counted, stored or texted. It then runs
  `engine.grantAccess(callId, input)` with the same
  input, steps and refusals, so the engine reserves the grant, holds it to `entry.open`, checks it
  again before it is sent, limits it per call, writes it to the ledger as above, never lets it
  outlive the verification grant, and records the controller's answer itself (ADR-25): the codes
  write no outcome. Where the controller would be asked, a code is texted instead:
  1. The call is found among the `issue` calls running in this process: one of the engine's
     workspace whose in-flight grant has this grant id and the digest the engine recorded for the
     grant it signed (a grant id alone could name another workspace's call). A grant sent to the
     code controller any other way is refused (`not_requested`) and nothing is texted.
  2. The destination is `engine.numberOnFile(callId)`: the subject Badge matched by keypad or
     PIN, its number on file and the call's locale (`precondition_failed` before a match, which
     Gate records as `unknown`). Never the calling number.
  3. `limits.take({workspaceId, key: {scope: "subject", key: subjectKey}, at, ...ACCESS_CODE_SEND_LIMITS})`
     counts the text against VER-2's `CodeStore`; false refuses it (`send_limit`) and nothing is
     texted.
  4. A drawn code is stored with `store.put` as an `AccessCodeEntry`:
     `{workspaceId, digest, grantId, callId, body, misses: 0}`, the digest being
     `HMAC-SHA256(key, JSON.stringify(["access-code", workspaceId, audience, target, code]))`
     (`accessCodeDigest`) and `body` the grant's body, unsigned. A digest already live for that
     door draws a new code, up to 3 times, then the request is refused (`no_free_code`).
  5. A grant that expired while the limiter or the store answered is not texted: its entry is
     taken back and it is `refused` (`expired`). Otherwise the code is texted (`purpose:
     "one_time_code"`, idempotency key `[workspaceId, callId, grantId, "access_code"]`), and the
     minutes in the text count from then. `delivered`, with `confirmed: false` and the message id
     as `providerRef`, once sent. A text that throws may still have arrived, so the code is taken
     back (`store.take` with its grant id, so another grant holding the same code by then is left
     alone): taken, it was never redeemed, and the grant is `refused` (`text_failed`); already
     gone (redeemed, or expired) or a store that throws, it is `unknown`.
  The ledger holds what Gate writes for any grant (`access.issued`, then `access.delivered`,
  `access.refused` with the reason above, or `access.unknown`), never the code. For a code,
  `delivered` means texted: the door acts later, when the code is redeemed. So unlike a relay
  grant, a code's grant may be acted on after the call ended and its receipt was issued, until its
  `expiresAt` (at most 15 minutes after it was issued); the redemption is in the door's own log,
  not the call's ledger, and `codes.revoke` ends it early.
- `codes.redeem({workspaceId, audience, target, code})`: `store.get` of the code's digest, the
  body signed again by `signer`, then `store.take` of the digest, so a code is redeemed once;
  only for the grant that was signed (an entry another grant holds under that digest by then stays);
  `{ok: true, grant}`, or `{ok: false}`, the same for a wrong, used, revoked, expired or malformed
  code (a code that is not a string of at most 32 characters is hashed as an empty one). A guess
  that matches no live code at that door (`audience` and `target`) is a wrong guess: it counts
  against every code live there (`store.miss`), and a code that reaches `maxWrongGuesses` is spent,
  removed, and recorded on its call as `access.code_spent` `{grantId, reason: "wrong_guesses",
  guesses}`, never with the guess or the code. Signing
  comes before the take, so a signer that throws leaves the code redeemable; a code taken, revoked
  or expired while it was signed is refused and its signature dropped. A code expires with its grant's
  `expiresAt`. The door's relay checks the grant with `verifyAccessGrant` (audience `audience`)
  and `SeenGrants`, as for any grant.
- `codes.revoke(workspaceId, grantId)` removes a grant's code; one already gone is success.
- `AccessCodeStore`: `put(entry, now)` (false when the digest is live), `get(workspaceId,
  digest)` (reads, leaving it), `take(workspaceId, digest, grantId?)` (removes and returns,
  atomically: never one entry twice; with `grantId`, only that grant's entry), `revoke(workspaceId, grantId)`,
  `miss(workspaceId, {audience, target}, limit, now)` (one wrong guess counted against every live
  entry for that door, atomically, removing and returning those at `limit`). `MemoryAccessCodeStore` is the in-memory reference, dropping expired entries on `put`.
- `limits` is VER-2's `CodeStore` (`take` counts one send atomically, or refuses and counts
  nothing; `MemoryCodeStore` in `district-assurance/testing` is the reference), the same instance
  the engine's texted codes count against, so both kinds of code share one budget per subject.
  `ACCESS_CODE_SEND_LIMITS` is VER-2's subject limit: 5 sends in 24 hours, 60 seconds apart. Until
  VER-2 (#79) lands, `CodeStore`, `CodeSendKey`, `MemoryCodeStore` and this constant are a stand-in
  copy of its shape; VER-2's per-number limit and destination allow-list are not applied to access
  codes yet.
revoking an issued code belongs to one-time codes. Planned: one-time access codes (GAT-3), a
Seam adapter (GAT-5), direct vendor adapters (GAT-6). Web sign-in step-up is section 18.

## 18. Web sign-in step-up

Digital entry (GAT-4, ADR-24): a person signing in on the host's site is shown a nonce, calls,
is verified, and keys the nonce; the call gets a step-up token, which the host's web sign-in
exchanges once to raise that sign-in's authentication level. `step-up` is a built-in module, like
Gate (ADR-25): the engine issues every token and records its one exchange itself, and no module
code can write a token or its outcome (`updateModule` and `moduleState` refuse it). Its signer is
the engine adapter `stepUpSigner`, its own ES256 key (its own `kid` and key material, not the
receipt signer's or the access signer's: the engine refuses a shared key when it is built).
`engine.stepUpKeys()` is the JWKS document `{keys: [...]}` to serve at the issuer's
`/.well-known/jwks.json`.

Settings: `issuer`, the https URL (no query, fragment or credentials) that is the tokens' `iss`;
`sites`, at least one, each `{id, audience}`: `id` lower-case letters, digits and `-` (unique),
`audience` the site's client id or origin, 1 to 200 characters without spaces, which is the
tokens' `aud`; `maxTokensPerCall` 1 to 5, default 3. A call keeps the issuer and the sites in
force when it started. `engine.stepUpTokens(callId)` lists a call's tokens as the engine keeps
them (never a token or a nonce).

`engine.issueStepUpToken(callId, {nonce, site?, lifetimeSeconds?})`: `nonce` is what the caller
keyed, 6 to 12 ASCII digits, passed by the host's code from the keypad. In a flow the
`step-up.issue` step names the site and the lifetime (pass only the nonce); outside one the
host's code passes them.

1. **Reserve**, in one engine write held to `entry.sign_in`, a token named by its id (`jti`). Refused:
   `scope_denied` without a verification grant covering `entry.sign_in` (none, expired, tainted,
   below today's minimum); `precondition_failed` while a verification runs (its subject may not be
   the grant's), while another token of the call is being signed, or once `maxTokensPerCall`
   tokens were issued; `invalid_input` for a bad nonce (the message never repeats it), a missing
   or unknown site, a bad lifetime, or a site or lifetime passed in a flow. The token lives
   `lifetimeSeconds` (2 to 5 minutes), never past the verification grant, in whole seconds.
   Ledger: `stepup.issued` (`tokenId`, `site`, `scope`, `level`, `verificationGrantId`,
   `expiresAt`).
2. **Sign** a compact JWS: header `{alg: "ES256", typ: "JWT", kid}`, payload below, the signature
   the 64-byte r||s over `base64url(header) "." base64url(payload)` (RFC 7515), each part's JSON in
   canonical form. A signing failure settles the token `failed` (`stepup.failed`, reason
   `signing`) and throws.
3. **Make it valid**, in another engine write: checked once more; if the call is no longer
   authorized, a verification started, the call's grant or its subject is no longer the token's,
   the call ended, or the token expired while it was signed, it is settled `failed`
   (`stepup.failed` with `digest`, `kid` and the reason `not_authorized` or `expired`), and
   `scope_denied` is thrown. Otherwise it is `issued`, with the SHA-256 of the compact token and
   the `kid` kept on the call, and `{token, tokenId, expiresAt}` is returned.

A token left `reserved` past its expiry (the process signing it stopped before its last write)
is failed (`stepup.failed`, reason `not_issued_in_time`) in a write of its own before the call's
next request, so it never blocks that call for good; one still within its life keeps blocking.
Ending the call fails a token still being signed (`stepup.failed`, reason `call_ended`), in the
write that ends it, so none is handed out after the end. The same write judges every `issued`
token for the last time, since the ended call holds no grant: one whose call is tainted, has a
new verification running, or no longer holds the grant the token was issued for (verified again,
for that subject or another, or the grant dropped) is refused (`stepup.refused`, reason
`tainted` or `not_authorized`), and any later exchange of it answers that reason and writes
nothing. Only a token issued for the grant the call still holds as it ends stays exchangeable
after the end, until it expires (at most 5 minutes); its `stepup.exchanged` or `stepup.refused`
entry may then land before or after `receipt.issued` (the receipt can still be signing), and never
changes the receipt. Whether tokens stay exchangeable after the end at all is a pending decision.
An exchange whose write is saved but whose ledger append then fails throws, and the token is used
up: a retry answers `unknown`, and the sign-in starts again with a new nonce (it fails closed; the
entry is appended by the call's next write or `flushLedger`). The receipt lists the call's tokens as the end left them
(`stepUp`, section 12), so a reader can tie such a later entry to it.

```json
{
  "iss": "https://verify.example.test", "aud": "<the site's audience>",
  "sub": "<stepUpSubject(subjectKey, aud)>", "iat": 1767225600, "exp": 1767225720,
  "auth_time": 1767225600, "jti": "stu_...", "acr": "urn:district-assurance:level:2",
  "nonce": "<the site's nonce>", "sid": "<the call id>", "grant": "<the verification grant id>"
}
```

`sub` is `stepUpSubject(subjectKey, audience)`, the SHA-256 of the canonical JSON of
`["step-up", audience, subjectKey]`, for the subject the call's verification grant was issued
for: a handle per site, so a `sub` alone never links one person across sites (`sid` and
`grant` are the same in every token of one call). `acr` is `stepUpAcr(level)`;
`auth_time` is when the verification grant was issued; `grant` names it.

`engine.exchangeStepUpToken(token, {audience, subjectKey, nonce})` is the host's web sign-in
exchanging a token, once, on any process of the workspace, in one engine write (so it also works
after the call ended). It returns `{ok: true, claims}` or `{ok: false, reason}` and never throws
for a bad token; a write that fails is thrown as it is.

- `malformed`: longer than 4,096 bytes (`MAX_STEP_UP_TOKEN_BYTES`, refused before it is split or
  parsed; an issued token is well under 1 KiB), or not three base64url parts with `sid`, `jti` and
  `nonce` claims.
- `unknown`: not a token waiting on that call: no such call in this workspace, no token of that
  id still `issued` (never issued, already exchanged or refused), or not the exact bytes the call
  issued (its digest). Nothing is
  written, so a forged token never uses up the real one.
- Each of these uses the token up (`refused`, `stepup.refused` with `digest` and `reason`):
  `tainted` (the call was tainted since, at any time before the exchange); `not_authorized` (a
  new verification is running on the call, or the call has not ended and its verification grant
  is no longer the token's: verified again, or dropped; or the end of the call refused it, above);
  `expired`; `mismatch` (another `audience`, a subject whose `stepUpSubject` is not the
  token's `sub`, or another nonce, compared in constant time). So anyone who holds the token can
  use it up with a wrong nonce: a refusal is final by design (a guessed nonce never gets a second
  try), at the cost of letting a token's holder deny that one sign-in, which then starts again
  with a new nonce.
- Otherwise `exchanged` (`stepup.exchanged`, with `digest` and `kid`), and the claims.

The ledger never holds the token, its signature, the nonce or `sub`. The call record holds no
nonce.

**For an OpenID Connect `acr` step-up.** A relying party asks its OpenID Provider for a higher
`acr` (`acr_values=urn:district-assurance:level:2`, or `claims` with an essential `acr`). The
provider, which is the host's web sign-in, has already authenticated the person (first factor);
it shows the nonce and the number to call, and its backend calls `exchangeStepUpToken` with the
site's audience, that person's subject key and the nonce it showed. On `ok` it may issue an ID
token with `acr` from the claims and `auth_time` from the claims; on anything else it refuses the
step-up and starts again with a new nonce. A provider that only verifies the JWS against the
JWKS (any JOSE library: ES256, `kid`, `iss`, `aud`, `exp`, `nonce`) gets authenticity but neither
the single use nor the refusal after taint: those are the exchange's, so the exchange is
required. There is no OpenID Provider in the engine (ADR-24).
revoking an issued code belongs to one-time codes. Planned: one-time access codes (GAT-3), web sign-in step-up as an ES256 JWT against a JWKS
(GAT-4), direct vendor adapters (GAT-6).
**Direct vendor adapters** (`vendorAccessController({vendor, apiKey, baseUrl?, allowLoopbackForTests?, timeoutMs?, fetch?,
clock?})`, `vendor` being `kisi` or `verkada`), named in the engine's `access` adapter like any
controller: the controller's door ref is the vendor's own id, a Kisi lock
id (digits) or a Verkada door id (a UUID). `unlock` first checks that the grant's `target` is the
target it was asked to open and has that form; otherwise it answers `refused` with
`target_mismatch` or `bad_target` and sends nothing. It also sends nothing, answering `refused`
with `grant_expiring`, for a grant with less than `timeoutMs` left by `clock` (the system clock by
default), the client's own bound on the whole unlock, since the expiry is strict and the call
may end then. This bounds when the request is sent, not the network: neither vendor's request
carries a deadline, so one delayed in transit could still arrive after the grant expired. Each
request's path is set on a copy of `baseUrl`, so its host is always `baseUrl`'s. Kisi: one `POST <baseUrl>/locks/<lock
id>/unlock` with `Authorization: KISI-LOGIN <apiKey>` and the body `{}`. Verkada: `POST
<baseUrl>/token` with `x-api-key: <apiKey>`; a token call that does not answer 200 with a
`token` string answers `refused` with `token_unavailable` and the unlock is not sent; then one
`POST <baseUrl>/access/v1/door/admin_unlock` with `x-verkada-auth: <token>` and `{"door_id":
"<door id>"}`. The token is never kept. Neither vendor checks the grant, takes an idempotency key
or reports in its answer that the door moved, so neither is sent and a 2xx is `delivered` with
`confirmed: false` and the grant id as `providerRef`. A 4xx is `refused` with `http_<status>`
(the vendor's text is never passed on); anything else throws (`unknown`). Never retried, no
redirects, one timeout for the whole unlock (100 to 30,000 ms, default 5,000). `baseUrl` defaults
to `https://api.kisi.io` or `https://api.verkada.com` (`https://api.eu.verkada.com` and
`https://api.au.verkada.com` for those regions), and its host must be one of the vendor's
(`VENDOR_HOSTS`: `api.kisi.io`; `api.verkada.com`, `api.eu.verkada.com`, `api.au.verkada.com`), over
HTTPS on the default port, with no credentials, query or fragment: the key goes nowhere else. The
loopback address, over HTTP or HTTPS, only with `allowLoopbackForTests: true`, for tests and never
for production. `apiKey` is 1 to 500 printable characters with no spaces.

A momentary unlock has nothing to revoke: there is no grant revocation, by design (ADR-22);
revoking an issued code belongs to one-time codes. Planned: one-time access codes (GAT-3), web sign-in step-up as an ES256 JWT against a JWKS
(GAT-4), a Seam adapter (GAT-5).
