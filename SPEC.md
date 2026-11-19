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

- `create(workspaceId, callId, record)` stores it at version 1, or answers false if the id exists.
- `get` returns `{version, record}` or null.
- `compareAndSet(workspaceId, callId, expectedVersion, record)` writes only if the stored version is
  `expectedVersion`, and the new version is `expectedVersion + 1`; otherwise `{ok: false}`.
- `bindRef(workspaceId, ref, callId)` points a provider reference (`identity:<session id>`,
  `payment:<link id>`) at a call, first binding wins; `resolveRef` reads it.

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
| `badge` | `badge.verify` | | `records`; `counters` with any factor the caller enters (`keypad_knowledge`, `pin`, plug-ins); `carrier` with `carrier_identity_match`; `identity`, `messages` with `photo_id`; `pinVerifier` with `pin` in verifier mode; `duressNotifier` with `pin.duress` |
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
(`grantTtlSeconds`, default 900, at most 3600), the lockouts across calls (`lockout`, section 6)
and, when `pin` is on, the PIN settings (section 6).
A factor that is off is refused at every entry point. A planned factor cannot be turned on.

A **grant** carries the level, the scopes at or below it (narrowed to the verify step's `scopes`
when the step lists them), and an expiry. `authorize(callId, scope)` is true only for a scope the
policy lists, on a call that has not ended, whose minimum is 0 or whose grant includes it, has not
expired, and has a level at or above the scope's minimum under the config in force now. On a
duress call (section 6) it is also false for every scope whose class is not `none` and for every
scope in the duress `refuseScopes`.

Links go only to the subject's number on file, and only after a `keypad_knowledge` or `pin`
factor passed since verification last started from nothing. A plug-in's pass does not unlock
texts.

## 5. Keypad knowledge

- Subject key: `HMAC-SHA256(knowledgeKey, "subject:" + accountNumber)`, hex. A host may instead
  start verification with a subject key its own code chose (`{subjectKey}`, a string of 64 lower-case hex, read once; anything else is `invalid_input`);
  choosing the subject is not a factor.
- Field digest: `HMAC-SHA256(knowledgeKey, "field:" + field + ":" + value)`, hex.
- An entry counts only if it is 1 to 32 ASCII digits.
- `submitKeypad` compares every configured field, in constant time per field, even after a
  mismatch, and records one factor: passed only if the subject exists and every field matched.
- After `maxKeypadAttemptsPerCall` judged attempts, further submissions return `locked` without
  judging. Failures also count across calls (section 6, "Lockouts across calls").

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
- Each attempt is counted in its own write before it is judged. Every `beginVerification` starts a
  new epoch; a factor result, a carrier report or a photo ID check from an earlier epoch is never
  applied (`precondition_failed`), and a change of subject drops pending photo ID checks.
- The photo ID link is reserved, created, enrolled and texted in turn; after a failure,
  `startPhotoId` resumes with the same idempotency keys, so a call never has two links. After `maxAttemptsPerCall`,
  `submitPin` returns `locked` without judging. Across calls: below.
- Enrolment: `enrolPin(callId, {pin, confirm})` lets a caller choose a PIN, keyed twice. It needs
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
  caller's request, and needs the `pin` factor on. In `keyed_hash` mode it removes the digest
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
- Lifting a lock early is the host's: `AttemptCounters.reset` with the keys (`counterKeys`) and,
  with the duress PIN on, the subject's hidden key for the factor (`hiddenCounterKey(workspaceId,
  kind, subjectKey)`, section 6), whose hard lock otherwise holds.

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
| `verification.factor` | `kind`, `passed` (and `status` for photo ID, `tag` for the PIN, section 6) |
| `verification.carrier_checked` | `checked`, `textCodeTrusted`, `identityMatch` |
| `verification.locked` | `kind`, `scope` (`subject` or `number`), `hard`, `until`: never the subject key, the number or its hash |
| `identity.link_sent` | none |
| `verification.finished` | `level`, `methods`, `discounted` |
| `grant.issued` | `grantId`, `level`, `scopes`, `expiresAt` |
| `pin.enrolled` | none (never the digits, the digest or their length) |
| `pin.reset` | `subjectKey`; actor `member`, `callId` null |
| `duress.cleared` | `subject` (a keyed digest, never the subject key), `memberId` (an opaque id); actor `member`, `callId` null |
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
with an `eventId`, then appended in order. How an event id is formed: the JSON tuple
`[workspaceId, callId, "w", n, index]`, for the `index`th entry (from 0) of the call's `n`th write
that queued entries. The workspace first makes it unique on a ledger that several workspaces
share. It is numbered by those writes, not the store's version, so a write that queues none, such
as a duress alert's acknowledgement, leaves no gap in the ids. The tag `"w"` keeps these ids apart
from the `[workspaceId, callId, version, index]` ids that builds before VER-12 form: an older and a
newer build writing one call on one store (a rolling deploy) never give two entries one id, so the
ledger never drops one as a replay; an entry the ledger would refuse (card data) is
refused before it is saved; the outbox is cleared by
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
