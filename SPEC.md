# Specification

Version 0 (pre-alpha). This document describes what the code in `src/` does today.

## 1. Session state machine

A session has a **phase** and, orthogonal to it, a **sensitive** flag, a **tainted** flag, a
**synthetic voice** band (`clear`, `spoken_off` or `level_1`, section 4), the recorded
**factors**, the current **level** and an optional **grant**.

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
| `sensitive_closed` | verifying (never paying: the payment hold ends only when the payment settles or the call ends) | sensitive cleared |
| `intake_started` | open | phase `filing` |
| `intake_confirmed {recordId}` | filing | phase `open`, record id appended |
| `intake_abandoned` | filing | phase `open` |
| `payment_requested {paymentId}` | open | phase `paying`, sensitive `payment`, payment id appended |
| `payment_settled {paymentId}` | paying | phase `open`, sensitive cleared |
| `untrusted_content {source}` | any but ended | tainted (sticky), level 0, grant dropped; a verification open when it lands is void (below) |
| `synthetic_voice_scored {band, ceiling, scopes}` | any but ended | band raised to `band` if higher (never lowered); level held to `ceiling`; a grant above `ceiling` lowered to it with only the `scopes` it reaches, or dropped at 0 |
| `call_ended {at}` | any but ended | phase `ended`, grant dropped, sensitive cleared |

A taint during an open verification fails that verification. `finishVerification`
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

`forwardingFor(state)` is the single place a host asks what it may forward. It returns
`{transcript, speechToText, model, listenIn, heldFor}`: the four are all false while `sensitive`
is set (`heldFor` is the reason, `keypad` or `payment`) and once the phase is `ended` (`heldFor`
is `ended`), and all true otherwise (`heldFor` null). With no state (null or undefined, when the
host could not read it) or a state the engine never writes (an unknown phase, a missing or unknown
`sensitive`, `paying` without the `payment` hold as a call stored before the hold could no longer be
lifted may hold, or fields that are not the state's own), all four are false and `heldFor` is
`unknown`. Each field is read once. Taint does not change forwarding. The
function is pure; the host asks again after each engine call and forwards nothing when it cannot
read the state.

## 2. The call record and the SessionStore

A call is one JSON record: `{v: 1, state, locale, revision, attestation, flow, modules}`, where
`state` is the session above, `locale` the call's language (`en`, `fr` or `es`, default `en`;
`startCall` refuses any other with `invalid_input`), `revision` the FlowConfig revision the call
started under, `attestation` its caller ID attestation (section 4, set once by `startCall`; a call
stored before it existed has none, and reads as `none` for caps and the receipt), `flow` the
cursor of the flow it runs (or null), `modules` each enabled module's own part, created by its
`initCall` when the call starts, and, once a step-up rule needs them, `signals` (the host signals
raised on the call) and `stepUps` (the rules already ledgered; section 4; a call stored before
them has neither, and reads as having none). A module turned on after a call started has no part
in it and is refused on that call (`module_disabled`).

The record lives in a `SessionStore`:

- `create(workspaceId, callId, record, hint?)` stores it at version 1, or answers false if the id
  exists.
- `get` returns `{version, record}` or null.
- `compareAndSet(workspaceId, callId, expectedVersion, record, hint?)` writes only if the stored
  version is `expectedVersion`, and the new version is `expectedVersion + 1`; otherwise `{ok:
  false}`.
- `bindRef(workspaceId, ref, callId)` points a provider reference (`identity:<session id>`,
  `payment:<link id>`, `payment_intent:<payment intent id>`, `callback:<dialer ref>`) at a call, first
  binding wins; `resolveRef` reads it.
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
must pass; `MemorySessionStore` is the reference. It also checks that every write copies its
record in, that two creates of one id or two binds of one reference at once leave exactly one
winner, and that a reference bound in one workspace never blocks the same reference in another.
Every keyed store's contract (session, ledger, record) includes keys that differ only in a lone
UTF-16 surrogate, and the replacement character U+FFFD: a store that encodes keys as UTF-8 (SQLite
with a TEXT key) collapses them, and must not.

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
installed, a factor kind that is not snake_case of 3 to 32 characters or is a name for caller ID
(section 4), a step not prefixed with the module's name, a scope need for a step it does not
provide, or a second `alwaysOn` module. A module whose manifest provides factors supplies
`factorPlugins`, the judges for them: exactly one per factor, none for a factor it does not provide,
each with `maxAttemptsPerCall` 1 to 5 and a `judge` function. A module that leaves the list out is
refused if it provides any factor; only Badge, whose own code judges its factors, is exempt.
`replace` swaps an installed module for a new build under the same name, checked against the
others the same way, in its place. `remove`
refuses Trace. `Engine.remove` also refuses a module the config has on, and a module supplying a
factor the config in force names (in the policy or Badge's `factors`).

`moduleContract(module, {settings?, steps?, policy?, installed?})` in `district-assurance/testing`
is the suite an outside module should pass (MOD-1), given sample settings and a sample of each step
it provides. It checks that the manifest passes `checkManifest` against `installed` (default: the
built-in modules) and is JSON; that the sample settings and steps validate and `requiredAdapters`
includes the manifest's adapters; that `validateSettings`, `validateStep`, `stepLevel` and
`stepGrants` never throw on garbage (every JSON type, `__proto__` and method-named keys, a long
string, lone UTF-16 surrogates, deep nesting, a sparse array, a missing value, at every path of the
samples) and answer with the right types (`stepLevel` a level from 0 to 3, or null); that `initCall`
and `enterStep` return canonical JSON, the same each time; that `stepStatus` answers the same for
the same view, in any order; that `validateFlow` and `checkAdapters`, when a module has them, answer
sentences for the sample settings and steps; and that none of these, nor `cannotRunStep` (asked for
an English call), `blocksEnd` (given a fixed `now`, as the engine passes its clock's time),
`onUntrusted` or `receiptPart`, changes a (frozen) input. Every built-in module passes it, Gate and
step-up included. `examples/modules/callback.ts` is an example outside module that passes it.

| Built-in | Steps | Needs | Adapters |
|---|---|---|---|
| `badge` | `badge.verify` | | `records`; `counters` with any factor the caller enters (`keypad_knowledge`, `pin`, `spoken_knowledge`, plug-ins); `carrier` with `carrier_identity_match`; `identity`, `messages` with `photo_id`; `messages`, `codes` with `text_code`; `dialer`, `counters` with `callback`; `pinVerifier` with `pin` in verifier mode; `duressNotifier` with `pin.duress` |
| `dossier` | `dossier.collect` | `intake.file` | `records`; `fieldCipher` once a form has a sensitive field |
| `paylink` | `paylink.request` | `payment.request` | `payments`, `messages`; `amounts` for a step with `amountRef` |
| `trace` | `trace.consent`, `trace.receipt` | | `ledger`; `signer` unless `receipts` is false; `consents` (optional) to revoke consents (section 21) |
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
`spoken_knowledge` (section 5), `callback` (section 6) and `text_code` ("Texted codes", below).
A **factor plug-in** adds a kind the caller enters and code judges: `{kind, summary,
maxAttemptsPerCall (1 to 5), adapters, judge}`, installed with `badgeModule({ factors })` when the
engine is built, or later with `engine.useFactor(plugin)`, or supplied by an outside module
installed with `engine.use(module)` whose manifest provides the factor (section 3). `adapters` is
a list of adapter names. Its kind is a string, snake_case, 3 to 32 characters, not a built-in kind
or a kind another installed module provides, and never `caller_id`, `calling_number`, `ani` or
`cli`; the registry refuses it otherwise, and nothing changes. Its judge gets the subject, the
entry and `hmac(data)` under the knowledge key (asynchronous, a `Promise` of the hex digest),
never the key. Caller ID is not a kind. Badge runs every plug-in the same way, whoever supplied it.

`useFactor` gives the engine a new build of Badge with the plug-in added (Badge never changes once
built, so engines built with the same Badge do not share factors added later) and needs Badge
installed. A factor added after a config was applied is off: the config in force does not change,
and the factor counts only once a config turns it on in Badge's `factors`. `validateConfig(config,
engine.registry)` knows it from then on, in the policy and in Badge's settings.

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
- a `timeZone` that is not an IANA time zone, and a malformed step-up rule (below);
- a `textCodeCountryCodes` that is not a list of distinct E.164 country calling codes (1 to 6
  digits, no `+`), each starting with a country code ITU-T has assigned to a country or geographic
  area (`E164_COUNTRY_CODES`; `"4"` and `"42"` are refused, `"44"` and `"4420"` accepted; spare
  and withdrawn codes are not in it). The global-service codes 800, 808, 870, 878, 881, 882, 883,
  888 and 979 (and the trial code 991) are always refused, and so is any longer prefix of one: no
  texted code goes to a global-service number.
- `attestationCaps` that is not a map, names a value that is not an attestation, or holds a cap
  outside 0 to 3.

It checks every part in one pass: a malformed part is reported and the others are still checked.

The default policy: level 1 is keypad knowledge; level 2 is keypad plus a trusted texted code, or
keypad plus carrier identity match, or a PIN plus a texted code; level 3 is keypad plus photo ID.
Scopes: `status.read` 1, `intake.file` 1, `payment.request` 2, `contact.update` 3, `payout.update`
3. Two keypad attempts per call. With a carrier answer, a texted code or a callback counts only
when the answer covered SIM changes (`simSwapChecked`) and reported no SIM change in the last 72
hours (`simSwapWindowHours`), and no port in them when it reports ports; a report without a port
age (`lastPortHoursAgo: null`, which Twilio always gives) is not checked for ports, so a port-out
with no SIM change it detects can still count. Without a carrier answer, it counts only when the
policy allows it (`trustTextCodeWithoutCarrierCheck`). Otherwise `verification.finished` lists it
in `discounted`. The default policy has no `callback` set: a host that turns the factor on adds
one, for example `[pin, callback]` at level 2.

**Caller ID attestation.** `startCall({attestation})` records, once, the STIR/SHAKEN result the
host's carrier reported for the call: `A`, `B` or `C` only when the receiving carrier's check of
the signature passed, `failed` when it failed, and `none` (the default) when there was no signature
or no result. Any other value is refused (`invalid_input`), and nothing changes it later. A
Twilio `StirVerstat` of `TN-Validation-Passed-{A,B,C}-Diverted` or
`-Passthrough` maps to `none`, because Twilio did not verify the original signer's attestation
end to end (its `-Failed-` forms map to `failed`). The attestation is never a factor, never
counts toward a factor set and never appears in `methods`. The policy's
optional `attestationCaps` gives, per value, the highest level a call with it can reach (for
example `{"C": 2, "none": 2, "failed": 1}`): `finishVerification` takes the lower of the level the
factors reached and the cap, and issues the grant and its scopes at that level, and `authorize`
applies today's cap to a grant already issued. A cap never raises a level. Without caps (the
default) the attestation is recorded in `call.started` and the receipt and changes nothing. An
attestation speaks to the calling number only, never to who is speaking; in Canada and the United
States a genuine caller often has `C` or `none` (calls from abroad, and calls whose signature was
lost on an older, non-IP network), so a cap is a business's choice (DECISIONS.md, ADR-26). A
callback call is never capped: the engine dialled the number on file itself, so an attestation
(`none` on the callback call) says nothing about it, and the callback factor already proves
possession of that line.

Badge's settings turn factors on (`factors`, at least one), set the grant lifetime
(`grantTtlSeconds`, default 900, at most 3600), the lockouts across calls and the hourly limits
on flow starts (`lockout`, section 6) and, when `pin` is on, the PIN settings (section 6), and
optionally the accessible path (`accessibility`, section 5a) and the synthetic voice thresholds
below (`syntheticVoice`). A factor that is off is refused at every entry point.

**Synthetic voice** (VER-14). `syntheticVoice` maps a vendor name (1 to 32 of `a-z`, `0-9`, `-`,
`_`, starting with a letter) to `{spokenKnowledgeAbove, levelOneAbove}`, numbers from 0 to 1 with
`levelOneAbove` not below `spokenKnowledgeAbove`; vendors' scores are not comparable, so each has
its own. `reportSyntheticVoice(callId, {score, vendor})` takes a score from 0 to 1 at any point in
a call that has not ended, in a flow or not; an input that is not an object, a vendor that is not
a string naming a vendor with thresholds, or a score that is not a number from 0 to 1, is refused
(`invalid_input`). A call stored before VER-14 has no band, and reads as `clear`. Its band is
`level_1` above `levelOneAbove`,
`spoken_off` above `spokenKnowledgeAbove`, else `clear`. The call keeps its highest band, so a
later, lower score lifts nothing, and a taint or a new verification does not reset it. Under
`spoken_off` or `level_1`, `spoken_knowledge` does not count toward a level; under `level_1`, a
verification finishes at level 1 at most. A band applies at once: in the score's own write, the
level and the grant are lowered to what the last verification's counted methods reach under the
band (re-judged under the policy only when a method stops counting), and a grant lowered to 0 is
dropped. A score never raises a level, never counts as a factor, and without a score there is no
cap. The score is not stored: the call record keeps the band, the ledger the vendor and the band.
The receipt keeps neither, and a call a band holds below what its counted methods reach shows on
its receipt the level it holds with only the methods that support it (those in a policy set at
that level or below that the call passed in full), so it reads exactly like a call that honestly
reached that level; `verification.finished` in the ledger keeps every counted method. A caller ID
attestation cap (VER-10) trims the receipt's methods the same way (decision 11). The band and the
cap are each a ceiling on the level the factors reached, so their order does not change the level.

**Step-up rules** (`stepUp`, VER-13) raise one scope's minimum for one request. A rule is `{name,
scope, level}` plus exactly one condition:

- `amountOverMinor: {<currency>: <minor units>}`: the amount the request moves is over the
  threshold for its currency. A currency the rule does not list, or an amount not known, counts as
  over. Money scopes only. A payment's amount is the one read back (PAY-2): a read-back for an
  `amountRef` is judged once the AmountSource answered.
- `localTime: {from: "HH:MM", to: "HH:MM"}`: the time of day in the policy's `timeZone` (required
  with such a rule) is in the window, `from` included and `to` excluded; when `from` is later than
  `to` the window runs past midnight (`18:00` to `08:00` is after hours).
- `signal: <name>`: the host's code raised that signal on the call with `raiseSignal(callId,
  name)`. A signal no rule uses is refused; a raised signal is never cleared for the rest of the
  call (not by a new verification, a new subject or a config change).

`validatePolicy` refuses a rule whose name is not snake_case or is repeated, whose scope the policy
does not list, whose level is outside 1 to 3 or not above the scope's minimum (rules only raise, so
no rule brings a level below a floor), with no condition or more than one, or with a malformed
condition. A scope's minimum for a request is the highest of its own and the levels of the rules
that hold (`raiseMinimum`), and a duress call (VER-12) and an attestation cap still apply under it.

A **grant** carries the level, the scopes at or below it (narrowed to the verify step's `scopes`
when the step lists them), an expiry, and what judged it: `policyVersion` (the policy's `version`)
and `configRevision` (the `revision` of the FlowConfig in force when the verification finished,
newer than the call's own `revision` when the config changed during the call).
`authorize(callId, scope, amount?)` is true only for a scope the policy lists, on a call that has
not ended, whose minimum is 0 or whose grant includes it, has not expired, and has a level at or
above the scope's minimum under the config in force now, raised by the step-up rules that hold now
(above; `amount` is `{amountMinor, currency}`, in a flow by default the current step's). The
steps' own checks (a payment, an intake, an outside module's step, Gate's door) use the same raised
minimum, for the request's own amount, so a grant already issued is held to it. The first time a
rule raises a minimum on a call, it is written to the ledger by name (`policy.step_up`), never with
the amount, the time or the signal's cause; `authorize` writes then. On a duress call (section 6)
it is also false for every scope whose class is not `none` and for every scope in the duress
`refuseScopes`.

Links and callbacks go only to the subject's number on file, and only after a `keypad_knowledge`
or `pin` factor passed since verification last started from nothing and since the session was last
tainted: `markUntrusted` voids the match, so no text, callback, carrier check or payment link goes
out on it until a fresh verification matches again. A plug-in's pass does not unlock texts or
callbacks.

**Carrier signals.** `checkCarrier` asks the `CarrierSignals` adapter about the number on file and
gets a `CarrierSignalReport`: `checked`, `simSwapChecked`, `lastSimSwapHoursAgo`, `lastPortHoursAgo`
(null when none is known) and `identityMatch` (`match`, `no_match`, `unavailable`). `simSwapChecked`
is true only when the carrier was asked about SIM changes and answered; `textCodeTrusted` never
trusts a texted code on a report without it (anything but `true`, so an adapter that leaves it out
fails closed), whatever `trustTextCodeWithoutCarrierCheck` says, since that covers no answer at all.
An `identityMatch` other than `unavailable` records the `carrier_identity_match` factor. The
reference server's adapters (`examples/reference-server/src/carrier-adapters.ts`, VER-4) map Twilio
Lookup v2 (SIM Swap, and Identity Match by `summary_score`, 80 by default) and Telnyx Number Lookup
(porting status and date; `simSwapChecked: false`, identity match `unavailable`). They round hours
down and read a change without a usable time as 0 hours ago (a Telnyx port date from the last moment
that date ends anywhere, noon UTC the next day); a Twilio answer of no SIM change within its
`swapped_period` window gives that window as a lower bound, and the window is never read as the age
of a change. A `baseUrl` override must be https (plain http only on loopback), and `timeoutMs` a
whole number from 1 to 60000; anything else throws when the adapter is built. Any failure gives
`checked: false` with nothing known, and they never throw: a number that is not E.164, a country
outside the adapter's allow-list, a timeout (3 seconds by default), a network or HTTP error, a
feature the account is not approved for, or an answer they cannot read. A Twilio report is `checked`
only when every field asked for answered.

**Texted codes** (`text_code`, needs the `messages` and `codes` adapters).
`sendTextCode(callId)` needs the factor on (and listed by the current `badge.verify` step), a
keypad or PIN match as above, and a call that is verifying. It sends only when, in order:

1. the number on file starts with `+` and one of the policy's `textCodeCountryCodes` (a country
   calling code such as `1` or `33`, or a longer prefix such as `1204`); without the list, nowhere;
2. the `CodeStore` counts the send against the subject: at most 5 in 24 hours, and none in the 60
   seconds before (`TEXT_CODE_LIMITS`);
3. when the host gave a calling number to `beginVerification` (`callingNumber`, E.164; left out
   when withheld), the `CodeStore` counts it against that number, kept as
   `HMAC-SHA256(knowledgeKey, "number:" + number)`: at most 10 in 24 hours, none in 60 seconds.

Both counts are always asked: a send the subject's limit refuses at step 2 is still counted against
the calling number's limit at step 3, and a send counted at step 2 stays counted when step 3 refuses
it, or when the text fails. A send is 6 random digits, kept in the call record only as
`HMAC-SHA256(knowledgeKey, "text_code:" + callId + ":" + code)`, valid for 10 minutes and 5 tries,
and replaces any earlier code on the call. Whether it sent or was refused, `sendTextCode` returns
`{sent: true}`: a refused send leaves the call with a code that has no digest (it never matches) and
the same expiry and tries, unless a code from an earlier send is still live, which it keeps. It
answers without waiting for the SMS adapter: a sent send and a refused one take the same store steps
up to the reply (only a country refusal, a property of the number on file, skips the `CodeStore`),
and the text goes out after it. The ledger then says which (`verification.code_sent`, or
`verification.code_refused` with `reason`: `country`, `subject_limit`, `number_limit`, or
`send_failed` when the SMS adapter failed; the send stays counted and the host hears nothing of it).
Until that entry is written, `endCall` refuses (`precondition_failed`), sent or refused alike, for
at most `TEXT_SEND_HOLD_SECONDS` (30) after the send, so a send's entry never follows
`receipt.issued`; an adapter that answers after the hold, once the call has ended, writes nothing.

`checkTextCode(callId, code)` counts and judges a try in one write and records a `text_code`
factor, passed or not. An entry that is not 6 ASCII digits is a try and fails. After the 5th try,
after 10 minutes, or once the code matched (single use), it returns `locked` without judging or
recording. Expiry is judged by the clock at the write, not when the check began. Without a code it
is refused (`precondition_failed`). A taint or a change of subject drops the code, and a taint also
refuses (`precondition_failed`) any send or factor result decided before it but not yet written.
A passed code counts toward a level only under the carrier rule above.
`codeStoreContract(factory)` in `district-assurance/testing` is the suite a durable `CodeStore`
must pass (atomic counting, no count for a refusal, the minimum interval held even when it is
longer than the window); `MemoryCodeStore` is the reference.

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
  start verification with a subject key its own code chose (`{subjectKey}`, a string of 64
  lower-case hex, read once; anything else is `invalid_input`); choosing the subject is not a
  factor.
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
  `K1A 0B1` or `k1a0b1`), or no answer ever matches; an unusable answer does the same work and
  fails. One factor: passed only if the subject exists and every field matched.
- Each attempt is counted before it is judged, an unusable one included; after
  `spoken.maxAttemptsPerCall`, submissions return `locked` without judging. Without `spoken` in
  the policy, every submission is `locked` and nothing is judged. A host can call
  `normaliseSpokenAnswer` itself first to ask again before an attempt is used.
- A spoken match does not unlock texts to the number on file (section 4).
- A spoken entry with a `pin` field is refused (`invalid_input`) before it is counted or judged:
  a PIN is only ever keyed.

## 5a. The accessible path

Badge's optional `accessibility` settings (VER-11): `{spokenKeypadFields?, keypadIdleSeconds?,
maxKeypadIdleSeconds?}`.

- `spokenKeypadFields`: keypad fields a caller may say instead of key. At least one, no
  duplicates, never `pin`, and only with the `spoken_knowledge` factor on; a `badge.verify` step
  that lists `spoken_knowledge` refuses a field that is not one of the policy's `keypadFields`.
  These fields join the policy's spoken fields in the `spoken_knowledge` factor: one answer gives
  all of them, judged together as in section 5. A keypad field is read with the same exact rules
  (`normaliseSpokenKeypadEntry({transcript, locale})`, English and French; Spanish is refused
  until a reviewed vocabulary exists), and the result must be 1 to 32 digits. It is compared as
  `HMAC-SHA256(knowledgeKey, "field:" + field + ":" + value)`. The factor recorded is
  `spoken_knowledge`, never `keypad_knowledge`: it reaches only what the policy's sets give
  `spoken_knowledge`, under `spoken.maxAttemptsPerCall`. Each such answer is also a guess at the
  keypad fields, so it uses a `keypad_knowledge` attempt too (`maxKeypadAttemptsPerCall`): the
  keypad and the voice share one budget per call, and a spoken answer is refused, even the right
  one, once either limit is used up. The cross-call counters (section 6, VER-1) count it under
  both `spoken_knowledge` and `keypad_knowledge`: a lock or wait on either refuses it, a failure
  counts toward both, and a pass forgets both.
- `keypadIdleSeconds` (5 to 60, default 10) is a call's keypad idle timeout;
  `maxKeypadIdleSeconds` (`keypadIdleSeconds` to 300, default `keypadIdleSeconds`) is the most it
  may be lengthened to. `keypadTiming(callId)` returns `{idleTimeoutMs, maxIdleTimeoutMs}` for
  the call: the idle timeout, or the maximum on a call marked relay or TTY.
- `startCall({access: "relay" | "tty"})` marks the call (read once, with the rest of the input).
  The mark is kept in the call record (`access`) and does one thing: the longer timeout above.
  Every step, factor, attempt limit and level is the same as on any call, and the mark is never in
  an event, the ledger, the session state or the receipt. Any other value is refused
  (`invalid_input`).

**The keypad collector** (`KeypadCollector`, `src/core/keypad.ts`, INT-1) takes the timing as it
comes: `new KeypadCollector({ maxDigits, ...await engine.keypadTiming(callId), onDigits, clock })`.
VER-11 adds two options. `maxIdleTimeoutMs` (`idleTimeoutMs` to 600,000, default
`idleTimeoutMs`) is the most `lengthenIdleTimeout(ms)` may make the idle timeout, for the rest of
the call; `idleTimeoutMs` reads the timeout in force. `requestKeys` maps `*` or `A` to `D` to
`repeat` or `slower`: such a key drops the unfinished entry (an overlong or rejected one too) and
`press` returns `{status: "request", request}` instead of digits. A `*` listed there is a request,
no longer "start over"; a key not listed keeps INT-1's meaning. A request is never an attempt:
nothing reaches the engine, so no attempt is used, added or given back, and the host replays its
fixed line (slower for `slower`). A caller who asks aloud to repeat or slow down is the host's too.

## 6. PIN

Settings: `{mode, minDigits (4 to 12), maxDigits (minDigits to 12), maxAttemptsPerCall (1 to 5),
duress?}`. `duress` is `{refuseScopes}`, a list of scopes without duplicates (it may be empty);
the duress PIN is off unless it is set.

- An entry is well formed when it is ASCII digits with a length from `minDigits` to `maxDigits`.
  A malformed entry is still an attempt, and fails.
- `keyed_hash` mode: the stored digest is `pinDigest(knowledgeKey, subjectKey, pin)` =
  `HMAC-SHA256(knowledgeKey, "pin:" + subjectKey + ":" + pin)`, in `SubjectRecord.pinDigest`,
  read from the `RecordStore` on every attempt; the call record's copy of the subject never holds
  it, so a reset, an enrolment, an erasure (section 26) or any other change since verification
  began counts at once. The entry is hashed the same way and compared in constant time; an
  unknown subject, a subject without a digest and a malformed entry do the same work and give the
  same answer.
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
  its link is texted, so its outcome applies; a repeated session is enrolled once.
- After `maxAttemptsPerCall`, `submitPin` returns `locked` without judging. Across calls:
  "Lockouts across calls", below.
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
  caller's request, and needs the `pin` factor on (and a string subject key: `invalid_input`
  otherwise). In `keyed_hash` mode it removes the digest (`putPinDigest` with null), so the
  subject has no PIN until they enrol again at level 2; `putPinDigest` with null removes the
  duress PIN too, in the same atomic step, so a duress PIN the business enrols against a PIN
  chosen after the reset began is never removed by it. In `verifier` mode the host's store resets
  its own PIN. Either way it clears the subject's PIN failure counters when the engine has a
  `counters` adapter (VER-1), its hidden one (VER-12) included, but not a duress flag, and appends
  `pin.reset` to the ledger with no call.

**Lockouts across calls (VER-1).** Every factor the caller enters (keypad knowledge, the PIN, spoken
answers, plug-ins) is also counted across calls, in an `AttemptCounters` store every engine of the
workspace shares. A counter is keyed by workspace, factor kind, and scope: `subject` (the subject
key, whether or not the subject exists, so a lock never says which accounts are real) or `number`
(`numberKeyFor(knowledgeKey, callingNumber)` = `HMAC-SHA256(knowledgeKey, "number:" + number)`, so
the store never holds a phone number). `beginVerification(callId, {..., callingNumber})` takes the
calling number, an E.164 string, from the carrier (anything else is `invalid_input`); a withheld
number is left out, and a restart that leaves it out keeps the one given before. The number only
keys a counter: it is never a factor. An attempt is counted under the subject's counter when there
is a subject key, and the number's when there is a number.

- `AttemptCounters`: `get(key, since)` returns the failure times at or after `since`, in the order
  recorded; `recordFailure(key, at, since)` adds one and returns the same list, this one last, in
  one atomic step; `removeFailure(key, at)` forgets one failure recorded at `at` and keeps every
  other, also in one atomic step (nothing when there is none); `reset(key)` forgets them all.
  `attemptCountersContract(factory)` in `district-assurance/testing` is the suite a store must pass;
  `MemoryAttemptCounters` is the reference. The engine refuses (`invalid_input`) a `counters`
  adapter missing any of the four methods when it is built, so a store written before
  `removeFailure` existed never reaches a pass.
- Badge's `lockout` setting: `{backoffSeconds, lockAfterFailures, windowHours}`, defaults
  `[5, 15, 60, 300, 900]`, `10` and `24`, which are also floors: `backoffSeconds` lists 5 to 10
  whole seconds, each at least the default at its place (900 after the fifth) and at most 86400;
  `lockAfterFailures` is 1 to 10; `windowHours` 24 to 168. `validateConfig` refuses anything else.
- With `n` failures in the window (the last `windowHours`, a failure exactly that old excluded):
  `n >= lockAfterFailures` is a hard lock until the oldest of the last `lockAfterFailures` failures
  leaves the window; otherwise, for `n >= 1`, a wait of `backoffSeconds[min(n, length) - 1]` after
  the latest failure.
- `submitFactor` (and `submitKeypad`, `submitPin`) reads the counters first. While either is locked,
  it returns `{matched: false, locked: true}` without judging and without using the call's attempt,
  and writes `verification.locked`. Otherwise it counts the call's attempt, then records a failure
  on each counter, both before judging. If the lists `recordFailure` returned show a lock that was
  not there when the counters were read (another attempt, on any call or engine, got in first), the
  attempt is refused the same way: no counter after that one is recorded, and the call's attempt is
  given back. A pass, once its result is accepted on the call, takes off the subject's failures
  recorded up to the pass (one by one, so a failure recorded after it, by another call, stays and a
  replayed cleanup erases nothing new) and takes its own failure off the number's (`forgetPass`,
  with `removeFailure`, so a failure another call records meanwhile is kept); the number's other
  failures stay until they leave the window, so a pass on the caller's own account never clears
  failures the line ran up against others. A failure stands, and one that starts a hard lock returns
  `locked: true` and writes `verification.locked`. A judge or verifier that throws leaves its
  failure counted.
- Two entries for one subject at once (two callers for one account, on any calls or engines) meet
  this rule too: the first's failure is recorded before it is judged, so it is provisional, but the
  second sees it as a failure and waits (`locked: true`, unjudged, the call's attempt given back,
  `verification.locked` with `hard: false`) for the timed wait that failure sets; the wait is never
  skipped. It is timed, not held for the whole judgment: an entry that arrives after it ends is
  judged even if the first is still being judged. There is no free guess either way, since every
  entry records its own failure before it is judged, and only a pass takes it back. If the first
  passes, its pass takes off the subject's failures up to the pass and the second may enter again at
  once; if it fails, both failures stand and the second waits the longer wait for two.
- The cleanup a pass owes (`forgetPass`, and with the duress PIN on its hidden counter) is saved
  with the pass, on the call, so a write that fails after the pass was saved (its ledger entry)
  still gets it, in the same `submitKeypad` or `submitPin` or before the call's next factor; a pass
  refused before it was saved owes none. The subject's part is safe to run again. The rest (the
  pass's own failure off the number, and the hidden counter's reset or, after a duress entry, its
  own failure) is claimed on the call in one more write before it runs, so it runs at most once: a
  replay never takes off another failure of the same millisecond. A claim that is not saved runs
  none of it, which stays owed; a removal that fails after its claim is not run again, and that
  failure stays until it leaves the window (fail closed). A flagged pass and an unflagged one make
  the same store round trips.
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
  of each has `capped: true`, and later locks of that kind in the hour are in the ledger only. Best
  effort, like the listener: the notifier is not awaited, and a notifier or a notice count that
  throws, rejects or hangs never fails the call or the ledger.
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
- Outside `unlock`, lifting a lock early is the host's: `AttemptCounters.reset` with the keys
  (`counterKeys`) and, with the duress PIN on, the subject's hidden key for the factor
  (`hiddenCounterKey(workspaceId, kind, subjectKey)`, "Duress PIN" below), whose hard lock
  otherwise holds.

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
  failures up to it and this callback's own on the number (section 6). A pass whose counters could
  not be updated keeps that work pending, and a repeated outcome retries it without recording
  `callback` again: the subject's part every time, and the removal off the number at most once,
  claimed on the callback call first as for any pass (section 6), so a retry never takes off
  another failure of the same millisecond.
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
  idempotency key. A resumed dial a day or more after it was counted is counted again toward the
  daily limit first (`countedAt`), and refused without ringing when the subject is at the limit.
- A placed callback creates the callback call (an id from the id source, the first call's locale
  and revision, and its flow's steps from the first step) and, in the same write, starts
  verification on it for the subject the first call matched, with no factors; choosing the subject
  is not a factor. The dialer then rings the number on file (`dial({callId, to, locale,
  idempotencyKey})`), its reference is kept on the callback call and bound (`callback:<ref>`).
  `to` is read from the `RecordStore` when it dials, and again on every retry, never from the copy
  taken when verification began, so a number the business changed since is the one rung; with no
  E.164 number on file then, the callback fails without ringing
  (`verification.callback_finished` `refused`). The dial is claimed in a write that checks the
  callback is still dialing and keeps the number dialed (`to`): a callback voided while the store
  was read never rings, and `checkCarrier` on the callback call asks about that number, never the
  copy taken when verification began (and is refused while the callback is still dialing). A retry
  to the same number reuses the idempotency key; a number changed between tries gets a key of its
  own (`redials`), and only the dial to the number kept is bound.
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

- Enrolment: `enrolDuressPin(subjectKey, pin)` is a host call for the business's own tools, never a
  caller's. It needs the `pin` factor on (`precondition_failed`), `keyed_hash` mode
  (`precondition_failed`; in `verifier` mode the host's store keeps its own duress PIN), a 64
  lower-case hex subject key (`invalid_input`), `pin.duress` set (`precondition_failed`) and a
  subject on file with a PIN (`precondition_failed`). Answers: `malformed` (not digits of a length
  from `minDigits` to `maxDigits`), `weak` (equal to the PIN on file, the account number or any
  keypad knowledge, compared as keyed hashes; every digit the same; a run; `weak` does not say
  which), or `{enrolled: true}` once `RecordStore.putDuressDigest(workspaceId, subjectKey, digest,
  ifPinDigest)` stored `duressDigest(knowledgeKey, subjectKey, pin)` = `HMAC-SHA256(knowledgeKey,
  "duress:" + subjectKey + ":" + pin)`, in `SubjectRecord.duressDigest`. The store writes it only
  while the subject's PIN digest is still the one it was checked against, atomically, and answers
  whether it did; when not (a reset and a new PIN meanwhile) `enrolDuressPin` throws `conflict` and
  nothing is stored. A second enrolment replaces it. `removeDuressPin(subjectKey)` removes it (same
  checks, except `pin.duress` may be off). Neither writes to the ledger. `enrolPin` answers `weak`
  for a PIN equal to a duress PIN on file.
- Judging: in `keyed_hash` mode every PIN entry is hashed as both a PIN and a duress PIN and
  compared with both digests (an empty one when none is on file), whatever the subject, the entry or
  the setting, so the work and the time are the same. Both digests are read from the store on every
  entry, never from the call's copy, so a duress PIN removed, or a PIN reset (which removes both),
  counts even on a call that began verification before it. In `verifier` mode `PinVerifier.verify`
  may answer `{duress: true}`, and `matched` is then ignored. A duress match counts only on a
  subject on file, with a well-formed entry, while `pin.duress` is set; otherwise it fails like a
  wrong PIN. An entry that matches both the PIN and the duress PIN (a subject imported with the two
  PINs equal), in either mode, and in `keyed_hash` mode any entry on a subject whose two digests are
  byte for byte equal, fail like a wrong PIN, with no alarm: in `verifier` mode, an answer
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
  sets the flag again first (`duress.flag`), in case the entry's own write of it was lost, unless
  the subject was cleared after the entry: each alert records the subject's count of clearings
  (`duress.clears`, one more per `clearDuress`, never reset) as it was read before the flag, and the
  flag is set again only while that count is unchanged. A failure to set it leaves the alert owed. A
  duress entry resets the visible counters as a pass does, so it looks like one; every entered
  factor's failures on the subject are also counted in a hidden counter (kind
  `duress.hidden.<kind>`) that only a pass not under duress resets (a duress entry takes off only
  its own failure), and that counter's hard lock (not its waits) refuses like any lock. So a caller
  who knows the duress PIN gets no more guesses at the real PIN than one who does not.
  `clearDuress(subjectKey, memberId)` is a host-privileged call, like `resetPin`: the business's own
  tools, never a caller's request, once it knows the subject is safe. The engine does not
  authenticate the member: the host must authorize them before it calls. `memberId` is an opaque id,
  1 to 64 of letters, digits, `.`, `_`, `-` (no `@` and no space, so no email address or name
  reaches the ledger; `invalid_input` otherwise). `duress.cleared` is written to the ledger first,
  naming the subject only by `duressClearedSubject(knowledgeKey, subjectKey)` =
  `HMAC-SHA256(knowledgeKey, "duress.cleared:" + subjectKey)`, which the business can match and a
  reader of the ledger or an export cannot; then the count of clearings goes up, and the flag and
  the hidden counters of every installed factor (on or off) are cleared. A clearing that lands while
  an earlier entry's alert is being delivered may be undone by that delivery's setting of the flag
  (the counters store has no compare-and-set): the subject stays flagged, and the business clears it
  again.
- Every duress entry owes an alert: in the same write, Badge's part of the call record gets
  `duressAlerts` `{alertId, subjectKey, at, clears}` and `duress`, and the record `owesAlerts: true`
  until none is owed; `alertId` is `JSON.stringify(["duress", workspaceId, callId, n])` for the
  call's `n`th duress entry, unique across engines whatever their id generators, even when
  verification restarted or the call ended while the entry was judged (the entry is then not a
  factor, and `submitPin` throws the same error as for any other stale entry). After a write,
  `flushLedger` included, and even when its ledger append failed, the engine calls
  `DuressNotifier.notify({alertId, workspaceId, subjectKey, callId, at})` for each alert the call
  owes, off the response path (after the reply), and takes the alert off the record once `notify`
  resolves. An alert stays owed until then, and is sent again on the next write, `flushLedger` or
  `deliverDuressAlerts(callId)` (the host's sweep, which waits and answers how many were
  acknowledged), or `sweepAlerts()`, which finds the calls without their ids through the optional
  `SessionStore.listCallsOwingAlerts(workspaceId)` (the calls whose record has `owesAlerts: true`;
  `precondition_failed` without it) and answers `{sent, failed}`: the calls that owe nothing now,
  and those that still owe one or could not be read (a listed call the store cannot read, or no
  longer holds, is reported and the sweep goes on); the sweep starts every listed call's sends at
  once. Each `notify` gets at most `notifyTimeoutMs` milliseconds (an engine option, a whole number
  from 100 to 30000, default 30000; anything else is `invalid_input` when the engine is made): one
  not settled by then counts as failed for that write, delivery or sweep (the call is in `failed`),
  its alert stays owed for the next, and its late answer, resolve or reject, records nothing. One
  engine sends an alert once at a time, again after 30 seconds without an answer. So `notify` may
  see an `alertId` more than once. A notifier that throws, rejects or never answers changes nothing
  on the call; it must not block.
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
              "simSwapWindowHours": 72, "trustTextCodeWithoutCarrierCheck": false, "textCodeCountryCodes": ["1"],
              "attestationCaps": {}, "spoken": { "fields": { "postal_code": "ca_postal_code" }, "maxAttemptsPerCall": 2 } },
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
minimum and whose `scopes`, if listed, include it, that a step whose amount is sure to trigger an
amount rule on that scope (over the threshold, a currency the rule does not list, or no amount, as
for an `amountRef`) comes after a `badge.verify` step that reaches the rule's level, and that the
engine has the `messages` adapter when a step needs a contact-class scope (its security notice,
section 16). A module's optional `validateFlow` makes whole-flow checks of its own: no flow may have
more `gate.grant` steps than Gate's `maxGrantsPerCall`, or more `step-up.issue` steps than
step-up's `maxTokensPerCall` (each completes only on a grant or token of its own, so such a flow
could never finish). Cross-checks against a module's settings or the
policy are skipped when those did not validate (their own problems are reported). The engine
refuses a config with any problem (`ConfigError`, code `invalid_input`, with `problems`).

| Step | Fields |
|---|---|
| `badge.verify` | `level` 1 to 3; `factors`, at least one, each on in Badge's settings, together reaching `level` under the policy, and `text_code` only with the policy's `textCodeCountryCodes`; optional `scopes`, each in the policy at or below `level` |
| `dossier.collect` | `form`, a form id in Dossier's settings |
| `paylink.request` | `amountMinor` and `currency`, or instead `amountRef` (1 to 64 of letters, digits, `.`, `:`, `-`, `_`; needs the `amounts` adapter), never both; `description`, `amountSource` (section 14); optional `mode` (`connect` or `platform`; connect needs Paylink's `connectedAccountId`), `linkLifeMinutes` (5 to 60), `paymentMethods` (instant methods only) |
| `trace.consent` | `purpose`, a wording in Trace's settings; `require`: `"yes"` (default) or `"answer"` |
| `trace.receipt` | optional `textLink: {consent}`, a wording purpose in Trace's settings, which also needs Trace's `businessName` and the `messages` adapter (section 16); needs the `signer` adapter |
| `gate.grant` | `target`, a target id in Gate's settings; optional `lifetimeSeconds` (10 to 900, default 60) |
| `step-up.issue` | `site`, a site id in step-up's settings; optional `lifetimeSeconds` (120 to 300, default 120) |

Settings: Badge (sections 4, 5a and 6); Dossier `{forms}` (section 13, ids unique; a sensitive
field needs the `fieldCipher` adapter; field rules as section 13 lists); Paylink `{maxAmountMinor?,
mode?, connectedAccountId?, linkLifeMinutes?, paymentMethods?}` (`maxAmountMinor` 1 to
1,000,000; `mode` default `platform`, and `connect` needs `connectedAccountId`, 1 to 255 letters,
digits, `-` or `_`; a `connectedAccountId` needs an explicit `mode`, so a business account never
quietly defaults to the platform's; the other two are the defaults for steps that name none and
for payments outside a flow, 15 minutes and card, Apple Pay, Google Pay and Link); Gate `{targets,
maxGrantsPerCall?}` (section 17); step-up `{issuer, sites, maxTokensPerCall?}` (section 18);
Trace `{receipts?, wordings?, businessName?}` (`receipts` default true; wordings `{purpose
(snake_case), version, text: {en, fr, es?}}`, purposes unique, `en` and `fr` non-empty, `es`
optional and non-empty when given, no other key in `text`, no purpose or version that reads as a
card number, since both go into the ledger; `businessName` 1 to 64 characters on one line, with
no lone surrogate and no bidirectional embedding, override or isolate, kept by a call when it
starts, like the wordings, so a flow with `textLink` cannot be attached to a call that kept none).

**Spanish is optional** (FIL-6). Forms and wordings always have English and French; Spanish only
where the workspace wrote it. A call in `es` is refused (`precondition_failed`) when its flow, at
`startCall` or `startFlow`, has a `dossier.collect` step whose form lacks a Spanish label on any
field, or a `trace.consent` step whose wording has no Spanish text. Outside a flow, the same call
is refused at `startIntake` for such a form and at `recordConsent` for such a wording, and
`buildReadBack` refuses such a form in Spanish. Spanish spoken answers are refused, since no
reviewed Spanish vocabulary exists: the engine takes no spoken "sí" and no voice confirmation on a
Spanish call, and a host recording a Spanish caller's consent (`recordConsent`, whose `answer` the
host maps) must take it on the keypad too, never from a spoken answer.

**JSON Schema.** `schema/flow-config.v1.json` (JSON Schema 2020-12, published with the package as
`district-assurance/schema/flow-config.v1.json`) describes the shape of version 1 for editors and
tools: the fields of each object, their types, ranges and patterns, the settings of the six
built-in modules, Badge, Dossier, Paylink, Trace, Gate and step-up (checked only while the module
is on), and their steps. An outside module's settings and steps are open. The schema is never
stricter than `validateConfig`: every config `validateConfig` accepts with the built-in modules
passes the schema. It cannot see the rules that need the registry, the adapters or another part
of the document (installed modules and factors, floors, the payment modes and link lives an
adapter takes, the form or wording a step names, unique ids, step order), so a config that passes
it can still be refused; `validateConfig` stays the authority. `test/config-schema.test.ts` checks
it against the TypeScript types (at type-check time) and against `validateConfig` (a corpus of
good and bad configs, both sides of the edge of every pattern and range the schema copies from a
validator, and a seeded sweep of near-miss configs), and that the package's exports resolve the
published name to the file.

## 8. Flow execution

`startCall` refuses (`invalid_input`, nothing saved) a `callId` that is not 1 to 200 characters the
ledger can carry (no lone surrogate), a `locale` not in `SUPPORTED_LOCALES` (`en`, `fr`, `es`), and
a `flow` that is not a name; the engine refuses a `workspaceId` with a lone surrogate. These enter
the ledger directly, so no host value can block a call's ledger. `startCall({flow})` or
`startFlow(callId, name)`, on an open call that has not run a flow, copies the flow's steps into the
call record, so a later config change never moves a call. A flow that needs a money, contact or
access scope is limited per hour (section 6, "Limits across flows"). The first step is entered: its
module's `enterStep` returns a mark. After every change to the call, the engine asks the current
step's module for `stepStatus(step, {state, slice, mark})`:

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
verification inputs outside a `badge.verify` step or for a factor it does not list, intake of a form
other than the step's, a payment outside its step or with an amount of its own (the step sets it), a
consent for another purpose. During a `badge.verify` step, only its factors count toward the level.
Once the flow has ended (completed, failed or abandoned), every step method is refused on that call,
an identity outcome is ignored, and an outside module's `updateModule` is refused; grants the flow
issued stand, and a payment link already sent can still settle. An outside module's step is held by
the engine to the scope its manifest needs. A flow cannot branch to ask for more (ADR-14): a step
whose scope step-up rules raise above the level the call's verification reached fails (`flow.failed`
with `rules`, the rules' names). This is checked when the step is entered, when a signal is raised,
and by the step's own work (`requestPayment`, `startIntake`, `confirmIntake`, `updateModule`), which
then also throws `scope_denied` naming the rules. A step whose module was removed while the call ran
fails. `endCall` abandons a running flow (`flow.abandoned`). `flowPosition(callId)` returns `{flow,
revision, status, index, step}`.

## 9. Engine events

Each event is one ledger entry: `name`, `callId`, `actor` (`caller`, `ai`, `code`, `member`,
`system`), `at`, and a `detail` object that never carries a value the caller keyed, a PIN, an
answer on file, a phone number, a link or card data.

| Event | Detail |
|---|---|
| `call.started` | `locale`, `revision`, `attestation` |
| `flow.started` | `flow`, `revision`, `steps` (count) |
| `flow.step_completed` / `flow.failed` | `flow`, `step` (index), `type`; `flow.failed` adds `rules` when step-up rules failed it |
| `signal.raised` | `signal` (the name the policy's rule uses) |
| `policy.step_up` | `rule`, `scope`, `level`: once per rule per call, the first time it raises a minimum |
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
| `verification.code_sent` | none |
| `verification.code_refused` | `reason`: `country`, `subject_limit`, `number_limit` or `send_failed` |
| `verification.finished` | `level` (after any attestation cap or synthetic voice band), `methods`, `discounted`, `capped` (true when an attestation cap or a synthetic voice band lowered the level), `policyVersion`, `configRevision`; `voidedByTaint: true` when a taint landed in that verification |
| `verification.synthetic_voice` | `vendor`, `band` (never the score) |
| `grant.issued` | `grantId`, `level`, `scopes`, `expiresAt`, `policyVersion`, `configRevision` |
| `pin.enrolled` | none (never the digits, the digest or their length) |
| `pin.reset` | `subjectKey`; actor `member`, `callId` null |
| `duress.cleared` | `subject` (a keyed digest, never the subject key), `memberId` (an opaque id); actor `member`, `callId` null |
| `session.tainted` | `source` |
| `sensitive.opened` / `sensitive.closed` | `reason` / none |
| `intake.started` | `formId`, `version` |
| `intake.confirmed` | `recordId`, `formId`, `digest`, `confirmedBy` |
| `intake.abandoned` | none |
| `record.filing_failed` | `recordId`, `formId`, `fields` (the form's sensitive field names), `reason` (`cipher_error` or `no_ciphertext`) |
| `delivery.attempted` | `recordId`, `destination` (the destination's id), `attempt`, `outcome` (`delivered`, `retry`, `failed`), `status` (HTTP, an integer from 100 to 599, or null for no answer, which is also what an adapter answer without such a status counts as); actor `system` |
| `redaction.applied` | `kinds` (counts per kind) |
| `payment.amount_read_back` | `amountMinor`, `currency`, `amountSource`, `digest` (never the `amountRef`) |
| `payment.amount_confirmed` | `digest`, `confirmedBy` |
| `payment.link_sent` | `paymentId`, `linkId`, `amountMinor`, `currency`, `amountSource`, `mode`, `expiresAt` |
| `payment.link_expired` | `paymentId`, `provider` (`expired`, `not_open`, or `not_created` when no link was created), and `reason`: none when the engine's deadline came, else `not_sent_in_time`, `not_created_in_time`, `cancelled` or `call_ended` |
| `payment.outcome_ignored` | `paymentId`, `reason` (`account`): an outcome from another account |
| `payment.settled` | `paymentId`, `status`, and `late: true` for a payment made after the engine closed its link |
| `payment.refunded` | `paymentId`, `refundId`, `providerRef`, `amountMinor`, `currency`, `reason`, `status` (`pending`, `succeeded` or `failed`) |
| `payment.refund_updated` | `paymentId`, `refundId`, `providerRef`, `amountMinor`, `currency`, `status` (`succeeded` or `failed`): a pending refund's later outcome at the provider |
| `payment.disputed` | `paymentId`, `disputeId`, `status`, `amountMinor`, `currency` |
| `consent.recorded` | `consentId`, `purpose`, `wordingVersion`, `wordingDigest`, `answer`, `locale` |
| `consent.revoked` | `consentId`, `purpose`, `wordingVersion`, `via` (`call`, `text` or `web`) |
| `consent.unrecorded` | `purpose` (a consent still being stored when the call ended: no consent) |
| `call.ended` | none |
| `receipt.issued` | `receiptId`, `digest`, `kid` |
| `access.issued` | `grantId`, `target`, `controller`, `scope`, `level`, `verificationGrantId`, `expiresAt` (section 17) |
| `access.delivered` / `access.refused` / `access.unknown` / `access.failed` | `grantId`, `digest` and `kid` once signed, `confirmed` or `reason` (written by the engine only) |
| `access.code_spent` | `grantId`, `reason` (`wrong_guesses`), `guesses`: a one-time code spent by wrong guesses at its door, never the guess |
| `stepup.issued` | `tokenId`, `site`, `scope`, `level`, `verificationGrantId`, `expiresAt` (section 18) |
| `stepup.exchanged` / `stepup.refused` / `stepup.failed` | `tokenId`, `digest` (and `kid` when signed), `reason` when refused or failed (written by the engine only) |
| `receipt.link_texted` | `actions` (the classes: `money`, `contact`, `access`) |
| `contact.notice_owed` | none: saved in the same write as the contact change that owes it |
| `contact.notice_sent` | none |
| `module.event` | `module`, `event`, `detail` (written by an outside module) |
| `subject.erased` | `recordIds`, `pinDigest` (whether one is deleted): the erasure's plan; `callId` null, actor `member` (section 26) |
| `subject.erasure_completed` | `erasureSeq` (the `subject.erased` entry it completes); `callId` null, actor `member` (section 26) |
| `ledger.anchored` | `seq` (the head it covers), `proof` (section 10); no call: `callId` is null |

The ledger is always on: every engine needs a `ledger` adapter, and Trace cannot be turned off.
A step's entries are saved in the call record's `outbox` by the same compare-and-set write, each
with an `eventId`, then appended in order. An event id is the JSON tuple `[workspaceId, callId,
"w", n, index]`, for the `index`th entry (from 0) of the call's `n`th write that queued entries.
The workspace first makes it unique on a ledger that several workspaces share. It is numbered by
those writes, not the store's version, so a write that queues none, such as a duress alert's
acknowledgement, leaves no gap in the ids. The tag `"w"` keeps these ids apart from the
`[workspaceId, callId, version, index]` ids that builds before VER-12 form: an older and a newer
build writing one call on one store (a rolling deploy) never give two entries one id, so the
ledger never drops one as a replay. An entry the ledger would refuse (card data, or detail that is
not canonical JSON, such as a lone surrogate) is refused before it is saved, so it can never block
a call's ledger. The outbox is cleared by a further write if nobody wrote since. A failed append
leaves the entries pending, and the next write or `flushLedger(callId)` appends them. A ledger
appends an `eventId` once (a second append returns the first entry), so nothing is lost or
doubled. A few entries are written outside a call's write. `consent.revoked` is one, since a
consent can be revoked after its call: its `eventId` is `[workspaceId, callId, "consent.revoked",
consentId]`, so a consent is revoked in the ledger once (section 21). The others (the member
actions of section 6, `access.code_spent`, `ledger.anchored`, the subject erasure entries) are
described where they are written.

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
`verifyChain(entries, from?)` reports the first entry whose `seq`, `prevHash` or `hash` is wrong;
an entry that is not an object (storage can hand back anything) is reported at the seq it holds,
as `seq`, never thrown on.
An entry that canonical JSON cannot hash (a stored number changed to `1e999` reads as Infinity) is
reported as a wrong `hash`, never thrown.
`chainEntry` refuses a detail in which any string (other than a 64-character hex digest) contains
a card number. An `AuditLedger` lists `list(fromSeq?, limit?)`: the entries with `seq` at or after
`fromSeq`, in order, at most `limit` (an integer of 1 or more) when it is given, read as one page,
so a large ledger is walked page by page; `MemoryAuditLedger` throws a TypeError for any other
`limit`.

`auditLedgerContract(factory)` in `district-assurance/testing` is the suite a ledger must pass: it
starts at seq 0 and the genesis hash, appends one seq at a time with each entry exactly as
`chainEntry` builds it, `list(fromSeq)` returns entries in order as a slice that continues the
chain, `list(fromSeq, limit)` returns at most `limit` of them as one page and refuses a `limit` that
is not an integer of 1 or more, entries are copied in and out and never change once appended, an
`eventId` is appended once (a second append, concurrent or not, returns a copy of the first entry,
and eventIds that differ only in a lone surrogate are distinct), a detail carrying a card number is
refused with nothing stored, and concurrent appends stay one valid chain.
`recordStoreContract(factory)` is the suite a `RecordStore` must pass: subjects (seeded by the
factory, since the engine only reads them) and intake records are copied in and out, workspaces
never share a key, keys that differ only in a lone surrogate stay apart, and `putIntakeRecord` is
idempotent by `recordId`, also concurrently. `MemoryAuditLedger` and `MemoryRecordStore` pass both.

The reference server has optional SQLite stores on `node:sqlite` (SRV-4,
`examples/reference-server/src/sqlite-stores.ts`; no dependency). `SqliteAuditLedger` keeps each
entry as `chainEntry` built it, as JSON, in a table whose `seq` is the primary key and whose
`eventId` is unique; triggers refuse UPDATE, DELETE, and an INSERT whose `seq` or `eventId` is
already stored (so INSERT OR REPLACE cannot swap an entry). Each append runs in a `BEGIN IMMEDIATE`
transaction (a repeated `eventId` returns the first entry; a refused entry rolls back with nothing
stored), so connections in several processes keep one chain. `SqliteRecordStore` keys subjects and
intake records by (workspace, id) as two columns; every key, the ledger's `eventId` too, is bound as
its JSON string, since `node:sqlite` binds text as UTF-8 and would turn a lone surrogate into
U+FFFD, so two ids that differ only there stay apart; `putIntakeRecord` keeps the first filing of a
`recordId`, and `putSubject` adds or replaces a subject. Entries, subjects and records are stored
as JSON with one change, since JSON writes -0 as 0: -0 is stored as the string NUL `-0`, and every
string that starts with NUL gets one more NUL in front, so -0 reads back as -0 and no stored string
reads back as anything else; the entry's hash is over canonical JSON, the same either way.
`openSqliteStores(path)` opens both on one file with a 5-second busy timeout, in WAL mode only on
a SQLite build with the fix for the WAL-reset bug (3.51.3 or later except the withdrawn 3.52.0, or
the 3.44.6 and 3.50.7 backports; https://sqlite.org/wal.html#walresetbug), and with a rollback
journal (`journal_mode = DELETE`) on an older one, such as Node 24.2's SQLite 3.50.0; it takes
a filesystem path or `:memory:`, and refuses a `file:` URI, whose file would not get the mode
below. Since the checks below read files by name before SQLite opens them, the database's
directory must be owned by the current user and not writable by group or others, and no directory
above it writable by others unless it has the sticky bit; anything else is refused before a file
is created. A new file is created exclusively with mode 0600 before SQLite opens it, in a private
directory in the directory the path resolves to, and hard-linked into place (one another process
creates in between is checked as an existing one). An existing file is checked by path (`lstat`)
and never opened outside SQLite, since closing any descriptor on a file drops every POSIX lock the
process holds on it, another connection's too. It refuses an existing database file, or a `-wal`,
`-shm` or `-journal` file beside it, that is readable or writable by group or others (SQLite keeps
an existing file's mode), a symbolic link at the path or beside it (SQLite would use the files
beside the link's target, not the ones checked), a database file with a second hard link (SQLite
names the WAL after the name it opens, so two names would keep two WALs; the brief second link
of another opener's create, its private name, is allowed), and anything that is not a regular file. The
file-backed stores are POSIX only: on Windows `openSqliteStores` refuses every database file, since
the mode sets no ACL there, so a Windows host uses another store, its own `RecordStore` and
`AuditLedger`. `:memory:` opens on every platform and keeps nothing across a restart: it is for
tests only. A file that is not a database, or a store whose schema fails, closes the
connection before the error is thrown. A write transaction that SQLite already rolled back (a full
disk, a trigger's `RAISE(ROLLBACK)`), or whose ROLLBACK fails too, rejects with the error that
caused it, and the connection stays usable. `SqliteRecordStore` also takes the PIN and
duress PIN writes, each read and written in one `BEGIN IMMEDIATE` transaction so two connections
never both pass the check, and the subject request writes: a deleted record id is kept (the id
alone) so a later `putIntakeRecord` of it stores nothing, and erasures are counted per subject in
one statement, with `putIntakeRecord(record, erasuresSeen)` checking the count and inserting in one
statement too. Both pass `auditLedgerContract`, `recordStoreContract` and
`recordStoreErasureContract` (PRV-5) and keep what they hold across a restart.

**Anchors (PRV-9).** A chain shows that no entry changed after later ones were written, but whoever
holds the ledger could rebuild all of it. `engine.anchorLedger()` takes the ledger's head
`{seq, hash}`, hands its **anchor payload** to the `anchor` adapter, and appends a
`ledger.anchored` entry `{seq, proof}` (event id `["ledger.anchored", seq]`, so engines anchoring
the same head append one entry). It refuses without the adapter or on an empty ledger
(`precondition_failed`), and refuses a malformed proof (`invalid_input`). The host schedules it
(daily, for example); the engine never calls out on its own. After the append the listener is
told, best effort, with `callId` null, and is handed a copy: what it does to the event never
reaches the entry `anchorLedger` returns. Anchoring when nothing new was appended still appends an
entry, on purpose: the previous `ledger.anchored` entry is the new head, so each run is a heartbeat
that fixes in time that the ledger was still there, unchanged, and each grows the ledger by one.

- Anchor payload: the UTF-8 bytes of `"district-assurance/ledger-anchor/v1\n" +
  canonicalJson({seq, hash})`. It is not JSON, so a signature over it never verifies as a receipt.
- `proof` is `{kind: "rfc3161", token}` or `{kind: "rekor", token, entry}`, every value base64,
  with exactly those own keys (`isAnchorProof`): a field inherited from a prototype does not count.
  `token` is an RFC 3161 TimeStampToken (DER) whose imprint is SHA-256 of the payload. `entry` is
  the Rekor v2 TransparencyLogEntry JSON for a `hashedrekord` v0.0.2 of the payload, signed by the
  host's P-256 key. Rekor v2 gives an inclusion proof and a signed checkpoint but no time, so the
  time is always the token's.
- `verifyAnchor(entry, entries, {tsa, rekor?})` checks offline and never throws. `entries` run from
  seq 1 to at least the covered seq; `tsa` is the authority's certificate chain as the host has it,
  signing certificate first (certificates in the token are ignored); `rekor` is the log's public key
  (Ed25519 or ECDSA) and origin. In order: the entry's shape, and an `entries` that is not a list,
  one holding null or anything else that is not an entry within the covered seqs, or a trust without
  a `tsa` list (`malformed`); the chain up to `seq` (`chain`); the token: one signer, signed content
  type TSTInfo, signed message digest of the TSTInfo, a signed SigningCertificate (RFC 2634, a SHA-1
  hash) or SigningCertificateV2 (RFC 5035, SHA-256 unless it names another hash) attribute,
  signature by the first certificate with RSA or ECDSA over SHA-256, 384 or 512 (`token`, also for
  an attribute this reader cannot read or a hash it does not know); the first ESSCertID of each such
  attribute names the first certificate, by its hash over the certificate's DER and, when it has an
  IssuerSerial, by its issuer and serial byte for byte (`certificate` when it names another); the
  chain: the first certificate has the time-stamping extended key usage, each is issued and signed
  by the next, every one after the first is a CA (basicConstraints cA true, keyCertSign when it has
  a keyUsage extension) whose pathLenConstraint, if any, allows the CAs below it, all are valid at
  the token's time, the last is trusted as given (`certificate`); the imprint against the head
  recomputed from `entries` (`imprint`: the chain was changed or rebuilt after the anchor); for
  Rekor, the body's digest and signature, a checkpoint signed by the log under its origin whose size
  and root lines are canonical (a decimal with no leading zero, 32 bytes of base64), and the RFC
  9162 inclusion proof of the entry's top-level `logIndex` into the tree of that checkpoint's size
  and root (`log`). The inclusion proof's own `logIndex`, `treeSize` and `rootHash` are optional
  copies and, when present, must agree with the top-level index and the checkpoint (`log`
  otherwise); as proto3 JSON writes it, a missing index is 0 and a missing list of hashes is empty.
  A log index above `Number.MAX_SAFE_INTEGER` is refused (`log`), so `logIndex` is always exact. It
  returns `{seq, hash, time, logIndex}`.
- `timestampTokenFields(token)` reads what a token says about the request it answers: `{imprintHash,
  nonce}` (the nonce as the INTEGER's contents, null when the token has none), or null when the
  token does not read. It checks nothing; a host that has just asked compares these with its
  request. An archived token has no request, so `verifyAnchor` does not read them.
- The DER reader (`readDer`) takes one-byte tags and definite lengths up to four bytes.
- The reference server has `TimestampAuthorityAnchor` (RFC 3161 over HTTP) and `RekorAnchor`
  (`POST /api/v2/log/entries`, plus the authority for the time); each checks what it got before
  the engine writes it. `timestampRequest(payload, nonce)` builds the TimeStampReq: version 1, a
  SHA-256 imprint of the payload, the nonce and `certReq` true. `TimestampAuthorityAnchor` sends a
  fresh random nonce with each request (its `nonce` option makes them, for a test that replays a
  recorded answer) and, beyond `checkTimestamp`, refuses a token whose imprint is not SHA-256 or
  that does not carry that nonce, so an earlier token for the same payload is not taken as the
  answer. `RekorAnchor` asks the authority first and Rekor after, so a refused time-stamp writes
  nothing to the public log. Both read at most `maxReplyBytes` of a reply (default
  `MAX_REPLY_BYTES`, 256 KiB), cancel the rest and refuse it, and refuse an error answer without
  reading its body.

### Export

`exportLedger({ledger, signer, clock, ledgerId, fromSeq | cursor, limit?})` is an async generator of
newline-delimited JSON lines, each ending in `\n`: one line per entry, in canonical JSON and in
order, then one signed trailer line.

```json
{
  "trailer": {
    "v": 1, "type": "ledger_export", "ledgerId": "ws_123",
    "from":    { "seq": 0,  "hash": "<64 zeros, or the hash of the entry before the first line>" },
    "through": { "seq": 17, "hash": "<hash of the last line's entry; equal to from when empty>" },
    "count": 17,
    "head":    { "seq": 17, "hash": "<the ledger head when the export was taken>" },
    "exportedAt": "...",
    "cursor": "17.<through.hash>"
  },
  "alg": "ES256",
  "kid": "...",
  "signature": "<base64url of the 64-byte r||s signature over the payload>"
}
```

The payload is the bytes of `district-assurance ledger export v1\n` followed by
`canonicalJson(trailer)`, so a trailer signature and a receipt signature can never stand in for each
other. The signer is a `ReceiptSigner`, and the receipt key set verifies trailers by `kid`. The
trailer is signed before the first line is yielded, and a signature that is not 64 bytes (P1363),
or that does not verify against the signer's own `publicJwk()`, is refused with `invalid_input`, so
a failing signer never leaves a consumer with entries and no valid trailer. Each input is read once.

A run starts at `fromSeq` (1 or more, at most the head plus one) or right after `cursor`
(`<seq>.<hash>` of a previous trailer's `through`), never both, and stops at the head read when the
export starts, or after `limit` entries; it asks the ledger for that one page (`list(from + 1,
count)`), in reads of at most `EXPORT_WALK_PAGE` entries, and again for the rest when a read hands
back fewer entries than asked. A run that stops short of the head is signed only once the chain is
walked from its end to the head, in reads of at most `EXPORT_WALK_PAGE` (1,000) entries, and
verifies there; so an export reads the ledger from the run to the head, and a run that reaches the
head reads only itself. A walk that fails is refused with `precondition_failed`, before anything is
yielded. The run is complete when `through` equals `head`; otherwise the next run takes `cursor`.
Refused with `invalid_input`: neither or both of `fromSeq` and `cursor`, a `fromSeq` or `limit` that
is not an integer of 1 or more, a `fromSeq` past the head, an empty `ledgerId`, a cursor that is
malformed or past the head. Refused with `precondition_failed`, before anything is yielded: a head
the ledger does not hold, a cursor whose entry the ledger no longer holds with that hash, a missing
entry before `fromSeq`, and a run that fails `verifyChain` from its start. `ledgerId` is the host's
name for the ledger, for example the workspace id.

`verifyLedgerExport(ndjson, keys, after?)` checks a whole run and never throws, whatever its
arguments are (a text that is not a string is `malformed`, a key set that is not a list of keys
fails `signature`, an `after` that is not a trailer fails `continuity`). It returns
`{ok: true, entries, trailer}`, or `{ok: false, reason}` with `reason`: `malformed` (a line that is
not JSON, no final newline, a trailer that is missing or inconsistent, an entry line that is not an
object), `signature` (unknown `kid`, wrong `alg`, a signature that does not verify), `continuity`
(given the previous run's trailer as `after`: a different `ledgerId`, or a start other than its
cursor) or `chain` (`verifyChain` from `from` fails, with its `seq`, or the run does not end on
`through`).

## 11. Canonical JSON

Object keys sorted by UTF-16 code units, no whitespace, strings and numbers as ECMAScript
`JSON.stringify` writes them. Refused: `undefined`, functions, symbols, bigints, non-finite numbers,
sparse array holes, objects whose prototype is not `Object.prototype` or `null`, and strings or
property names holding a lone surrogate (RFC 8785, section 3.2.2.2); a valid surrogate pair is kept.
The stand-alone verifier and the reference page refuse the same values, so a receipt body holding a
lone surrogate is invalid (the engine cannot have signed it). So that no call is ever left with a
ledger entry it cannot append, a step whose ledger detail canonical JSON refuses is refused with
`invalid_input` before it is saved; `markUntrusted` replaces a lone surrogate in its label with
U+FFFD and a card number with `[card number removed]`, so the taint always lands; and
`validateConfig` refuses a config holding a lone surrogate in any string or key.

## 12. Receipts

```json
{
  "body": {
    "v": 1, "receiptId": "...", "callId": "...", "workspaceId": "...",
    "startedAt": "...", "endedAt": "...", "issuedAt": "...",
    "verification": { "level": 3, "methods": ["keypad_knowledge", "photo_id"],
                      "policyVersion": "default-1", "configRevision": "2026-11-18.1" },
    "attestation": "A",
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
`payments` from Paylink and `consents` from Trace (`answer` is `yes`, `no`, or `not_recorded` for
a consent still being stored when the call ended, section 21); a module that is off contributes an
empty part.

- `verification.policyVersion` and `verification.configRevision` name the policy and the
  FlowConfig revision that judged the call's last finished verification (whatever level it
  reached); both are absent when no verification finished on the call. They are optional, so the
  format stays at `v: 1`, and a reader that does not know them still checks the signature over the
  whole body.
- `attestation` is the caller ID attestation the call started with (section 4); it is optional in
  the format, so a receipt without it is still version 1, and the engine always writes it.
- A receipt never carries a synthetic voice band, vendor or score, since a receipt can reach the
  caller (SRV-3).
- `stepUp` is step-up's part (section 18): each token record the call has, `{tokenId, expiresAt,
  status}` as the end of the call left it, `failed` ones included (a reservation whose signing
  failed is listed too, so the part's presence is no proof that a token became valid). It is
  present only on a call with at least one record, so the format stays at `v: 1`.
- `ledger` is the head after `call.ended`, the expiry of the call's open payment links (section
  14) and the access code entries the end wrote (section 17), kept in the call record. If signing
  fails, `endCall` on the ended call issues the receipt later with the same head, without ending
  the call again.

`verifyReceipt(receipt, keys)` picks the key by `kid` and returns false for any change, a wrong
algorithm, a malformed signature or an unknown key.

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
`deposit` flow has run to its end in the page, which shows the receipt's link `/r/<token>`, with
a payment of 15000):

```sh
$ curl -s http://127.0.0.1:8787/r/<token>.json > receipt.json
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

Record digests are `SHA-256(canonicalJson({formId, version, values}))` over the values the caller
confirmed, where each sensitive value is replaced by
`HMAC-SHA256(knowledgeKey, canonicalJson(["intake", recordId, field, value]))`, hex (section 13).
Wording digests are `SHA-256(canonicalJson({purpose, version, text: {en, fr}}))`, or `text: {en,
fr, es}` for a wording with a Spanish text, so a wording without one keeps the digest it had
before Spanish.

**Receipt links.** A call id is not a secret, so a receipt is shared by a capability link.
`newReceiptLinkToken()` returns a `token` (32 random bytes, base64url, 43 characters) and its
`hash`, `SHA-256("receipt-link:" + token)` in hex; the host sends the token once and stores only
the hash with the call id. `receiptLinkTokenHash(token)` gives the hash to look up, or null for a
string that is not a token. The reference server keeps the hashes in `ReceiptLinks` and serves:

| Route | |
|---|---|
| `GET /r/:token` | an HTML page, in English or French (`?lang=en` or `?lang=fr`, else the browser's first `Accept-Language`, else English): the signature check against the server's key set, the verification level and methods, records, payments, consents and the ledger head |
| `GET /r/:token.json` | the signed receipt |

An unknown token, a malformed one and a call without a receipt yet all answer the same `404`. The
page has no script, style or form, every value is escaped, and it is sent with `no-store`,
`Referrer-Policy: no-referrer` and `noindex`. There is no route by call id. `ReceiptLinks` keeps
every link it issues, in memory, for the life of the process, with no limit and no expiry: the
host bounds how many links it issues and how long it keeps them (a durable store with expiry in
its place).

### Monthly reports

`monthlyReport({ledger, workspaceId, month, timeZone?})` reads the whole ledger and reports one
workspace's calendar month. `month` is `YYYY-MM` read in `timeZone` (an IANA name, `UTC` by
default); an entry belongs to the month its `at` falls in, in that zone. An entry belongs to the
workspace named first in its `eventId` tuple; an entry with no `eventId`, or one that does not
name a workspace, is counted only in `unattributed` (for its month), never anywhere else. An entry
whose `at` is not a UTC time as the engine writes it (`toISOString`), or names a date that does
not exist, has no month: it is counted in `malformed.count` (across the whole ledger, whatever
workspace it names) with the first one's `seq` in `malformed.firstSeq` (null when none), never
anywhere else and never for a workspace, so one bad entry in a shared ledger never stops any
workspace's report. So is an entry of the workspace in the month whose detail does not read as the
engine writes it (a consent answer other than `yes` or `no`, a link without a non-empty string
`paymentId` or whose amount is not a whole number with a lower-case currency, a level that is not
a whole number): it is never tallied, so it can never put a non-number in the report and stop it
being signed, and a settlement without a payment id never matches a link. A bad `workspaceId`,
`month` or `timeZone` is refused with `invalid_input`. Payment totals are summed exactly: a total
that would pass `Number.MAX_SAFE_INTEGER` refuses the report (`precondition_failed`), never rounds
it.

| Field | From |
|---|---|
| `calls.started`, `calls.ended` | `call.started`, `call.ended` |
| `verifications.byLevel` | `verification.finished` by `level` (`0` to `3` always listed; 0 is a verification that reached no level) |
| `verifications.failedFactors` | `verification.factor` with `passed: false` |
| `payments.sent` | `payment.link_sent`: `count` and `totals` in minor units by currency |
| `payments.paid`, `.failed`, `.expired` | `payment.settled` by `status`, with the amount of the call's `payment.link_sent` for that payment, which may be in an earlier month |
| `payments.unmatched` | a settlement whose link the ledger does not show, or whose status is not paid, failed or expired |
| `consents` | `consent.recorded`, `{yes, no}` by `purpose` |
| `lockouts` | `verification.locked` |
| `access.issued`, `.refused`, `.revoked` | `access.issued`, `access.refused` and `access.revoked` (a controller asked to withdraw a grant after a taint, section 17, step 5), as Gate writes them |

The report also names `workspaceId`, `month`, `timeZone` and `ledger` (the seq and hash of the
last entry read). It holds counts and totals only. `reportCsv(report)` writes it as RFC 4180
`metric,value` rows with CRLF line ends (`payments.paid.total.cad,15000`); a field with a comma, a
quote or a line break is quoted, and one starting with `=`, `+`, `-`, `@`, a tab or a carriage
return gets a leading `'`. `signReportJson(signer, report)` and `signReportCsv(signer, report)`
sign with the receipt signer, over `"district-assurance signed document v1\n" + document + "\n" +
content`, where `document` is `monthly_report.json` (content: `canonicalJson(report)`) or
`monthly_report.csv` (content: the CSV). A receipt's signed bytes are canonical JSON and start
with `{`, so neither verifies as the other. `verifyReport(signed, keys)` returns false for an
unknown document type or key, a wrong algorithm, a malformed signature or any change. Both sign
functions refuse (`precondition_failed`) a report, built here or handed in, with a payment total
that is not a whole, non-negative, safe integer.

## 13. Intake values

| Type | Accepted | Stored as |
|---|---|---|
| `text` | trimmed, non-empty, Unicode text (a lone surrogate is `not_text`), at most `maxLength` (500), no card number, and matching `pattern` whole if set (`no_match`) | string |
| `number` | `-?\d+(\.\d+)?`, from `min` to `max` if set (`below_min`, `above_max`) | number |
| `date` | `YYYY-MM-DD` naming a real day, from `min` to `max` if set | string |
| `yes_no` | `yes`, `y`, `oui` / `no`, `n`, `non`, any case, in every locale (no Spanish word: a Spanish call confirms on the keypad) | boolean |

Forms live in Dossier's settings: a `formId` (lower case, digits, `-`, `_`), a `version` and
fields with snake_case unique keys, a known type and an English and a French label, plus an
optional Spanish one (`label: {en, fr, es?}`; `es` non-empty when given, no other key).

**Encrypted fields** (FIL-2). A field marked `sensitive` is stored encrypted: `validateConfig`
refuses a form with one unless the engine has the `fieldCipher` adapter (`modules.dossier: needs the
fieldCipher adapter, which the engine does not have`). `confirmIntake` computes the digest (section
12) when it reserves the record, then, on every attempt to store it, asks `FieldCipher.encrypt(text,
{workspaceId, recordId, field})` for each sensitive value given (a number or a yes/no as JSON writes
it) and stores and returns the record with the ciphertext in its place; the engine never decrypts.
The digest does not depend on the ciphertext, so it is the same when a retry encrypts again. An
engine without a cipher (another process on the same SessionStore) refuses to file such a record
(`precondition_failed`) and leaves it reserved for an engine that has one. A cipher that throws
(`cipher_error`) or answers with an empty string, a non-string or the value itself (`no_ciphertext`)
never holds the call open: the reserved filing is released as failed, the draft is dropped with its
values (phase back to `open`, nothing kept in the clear), the ledger gets `record.filing_failed
{recordId, formId, fields, reason}` (the form's sensitive field names and the reason code, never a
value), and `confirmIntake` throws `precondition_failed` with the reason code; the cipher's own
error is never passed on. Nothing was stored, since the cipher runs before the record store, so
`endCall` can go ahead and the host collects the record again if it wants it. If another process
sealed and filed the same record meanwhile, that record is returned instead. A process that sealed
the record claims the filing before it writes it (`writers`, each write by its own token, by the
same compare-and-set as every write): while any claim is live, a process whose cipher fails releases
nothing and logs nothing, and `confirmIntake` throws `conflict` ("another process is writing this
record; confirm again for its outcome"), so a retry returns the winner's record. A write whose write
fails gives up only its own claim; a claim older than two minutes (`WRITE_CLAIM_MS`) is taken as a
writer that died. A release first marks the filing `releasing` (no write claims or files it from
then on), then deletes the record by id (`RecordStore.deleteIntakeRecords`, which also makes a later
write of that id store nothing), then drops the draft and logs `record.filing_failed`: so a write
the store kept before failing, or one that outlived its claim, never leaves a stored record behind a
released filing, and a writer that finds the filing released files nothing and throws the same
`precondition_failed`. A release whose delete failed is carried on by the next confirmation, with
the reason it began with. Until the record is filed, abandoned or the call ends (`endCall` drops an
open draft, before `call.ended` and the receipt's ledger head, writing no event), the draft in the
call record holds sensitive values in the clear; afterwards the call record keeps only the encrypted
record. `setIntakeField` refuses (`invalid_input`) a value that is not a string, and refuses a value
with a lone surrogate, which speech-to-text or a model can produce and a record's digest cannot
hash, as `not_text`.

Field rules (FIL-4), each checked by `validateConfig`, which reports every bad one:

- A field has only `key`, `label`, `type`, `required`, `sensitive`, `maxLength`, `showIf`, `min`,
  `max` and `pattern`.
- No field's key or label (any language; case, accents and dots ignored) names a card, its
  number or a national identity number: the words `card`, `carte`, `tarjeta`, `cardholder`, `cvv`,
  `cvc`, `pan`, `cc`, `sin`, `nas`, `ssn`, `nss`, `social insurance`, `assurance sociale`, `social
  security`, `seguro social` or `seguridad social`, each a whole part of the name split at spaces,
  `_`, `-` and camelCase humps (`panNumber`), never a piece of a longer word (`account`, `pancake`,
  `nasal` pass), or one of them run into one word with a number or kind (`creditcard`, `cardno`,
  `numerocarte`, `numerotarjeta`, `sinnumber`, `ssnumber`, `nssnumero`, `pannumber`, `ccno`). The
  card-number check on values still applies whatever a field is called.
- `min` and `max` only on number fields (finite numbers) and date fields (`YYYY-MM-DD` dates),
  inclusive, with `min` at most `max`.
- `pattern` only on text fields: a regular expression of 1 to 200 characters, valid in Unicode
  mode, matched against the whole value. It must not use a backreference or repeat a group that
  repeats or alternates, and the product of the choices its repetitions and alternatives give
  (`?` and `|` count 2, `*` and `+` the field's `maxLength` plus 1, `{m,n}` `n - m + 1`) must be
  at most 100,000, so no pattern can stall the engine on a caller's value.
- `showIf: {field, equals}` names another field of the form, not a sensitive one, and a value that
  field can hold. A field is **shown** while that field's value equals `equals` and that field is
  shown itself; one without `showIf` always is. A chain of `showIf` that comes back to a field is
  refused.

Only shown fields are asked: `setIntakeField` on a hidden one is refused (`precondition_failed`).
Only shown fields are required, read back and filed: a value given while a field was shown stays in
the draft but out of the record, its digest and the read-back if the field is hidden again.

**Read-back** (FIL-1, FIL-6). `buildReadBack(form, values, locale)` builds, in English, French or
Spanish, what the host speaks before the caller confirms: an opening, one sentence per shown field
with a value, in form order, and the fixed confirm prompt. `text` is all three, one space apart;
`lines` and `prompt` are its parts. Another locale is refused (`invalid_input`), and Spanish is
refused (`precondition_failed`) for a form with any field that has no Spanish label.

| Type | English | French | Spanish (United States) |
|---|---|---|---|
| `text` | `Issue: Leak.` (as given; a full stop unless it ends in `.`, `!` or `?`) | `Problème : Leak.` | `Problema: Leak.` |
| `number` | `1,234.5`, `minus 2` (never in exponent form) | `1 234,5` (a non-breaking space), `moins 2` | `1,234.5`, `menos 2` |
| `date` | `Tuesday, September 1, 2026` | `le mardi 1er septembre 2026` | `el martes primero de septiembre de 2026`, `el jueves 29 de febrero de 2024` |
| `yes_no` | `yes` / `no` | `oui` / `non` | `sí` / `no` |
| sensitive | `Label: given, and not read aloud for your security.` | `Libellé : fourni, mais pas lu à voix haute, pour votre sécurité.` | `Etiqueta: se proporcionó, pero no se lee en voz alta por su seguridad.` |

Opening: "Here is what will be filed." / "Voici ce que nous allons enregistrer." / "Esto es lo que
vamos a registrar." Prompt: "Is that correct? Say yes or press 1 to confirm." / "Est-ce exact? Dites
oui ou appuyez sur le 1 pour confirmer." / "¿Es correcto? Oprima el 1 para confirmar." (the keypad
only: Spanish spoken answers are refused until a reviewed vocabulary exists, so a yes/no field takes
no "sí" and a Spanish call's read-back is confirmed with `confirmedBy: "keypad"`). Every string code
builds exists in every locale (`LOCALES`), and a parity test fails when one is missing or copies
another locale's. A sensitive field's value is never in the read-back, its text or its lines. The
`digest` is `SHA-256(canonicalJson({v: 1, locale, text, record}))`, where `record` is the record
digest of the values that would be filed (section 12), so a change to any of them, a sensitive one
included, changes it. `intakeReadBack(callId)` builds the read-back of the open draft in the call's
locale. `confirmIntake(callId, {confirmedBy, readBack})` takes the digest of the read-back the
caller heard, and refuses with `precondition_failed` unless the draft reads back to that digest now.

`startIntake(callId, formId)` names the form, and the draft keeps the form as it was then, so a
config change mid-intake never changes what is filed; a call also keeps the forms (and Trace the
wordings) in force when it started. A draft being filed refuses changes. A filing that failed
after its reservation (the store refused it, or the last write was lost) stays reserved and
resumes with the same record on the next `confirmIntake`, so `RecordStore.putIntakeRecord` must be
idempotent by `recordId`; two confirmations at once file one record. A record carries the
`subjectKey` Badge matched on the call when it was filed (a keypad or PIN match), or null when
none had. A resume needs `intake.file` again, as a first confirmation does: refused
(`scope_denied`), the filing stays reserved. `abandonIntake` releases a reserved filing: it
deletes the record by id first (`RecordStore.deleteIntakeRecords`, which also makes a later write
of that id store nothing), then drops the draft, so the call can end; a confirmation whose write
was in flight then fails (`precondition_failed`) and files nothing. A confirmation retried after
its record was filed (its ledger entry failed) returns the same record. `endCall` is refused while
a record is being filed. Provider idempotency keys are JSON tuples of the workspace, the call and the
operation, so workspaces sharing an adapter never share a key. A flow attached to a running call
is refused when a step needs a form or a wording the call did not keep.

## 14. Payments

`requestPayment` needs `payment.request` at its minimum for the amount asked (step-up rules, section
4; the amount read back, or the request being resumed), a confirmed amount read-back (below), a
positive integer amount in minor units up to Paylink's `maxAmountMinor` (at most 1,000,000), a
lower-case ISO 4217 currency, a 1 to 200 character description and an `amountSource`
(`intake_record`, `business_endpoint` or `price_list`). In a flow they come from the
`paylink.request` step and the host passes none; outside a flow the host's code passes them. One
link at a time per call. If creating or texting the link fails, the request stays open (a provider
can create a link and still fail to answer), and calling `requestPayment` again resumes it with the
same payment id and idempotency keys; a different amount is refused. `requestPayment` returns the
status it saw last and `expiresAt`.

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
and at least the payments adapter's `capabilities.minLinkMinutes` plus 5 minutes (so the create that
follows is never under the minimum), at most its `maxLinkMinutes` (Stripe Checkout: 30 minutes to 24
hours). A request whose link is not known to exist and has less than the provider's minimum left is
expired before any create (`payment.link_expired`, provider `not_created`), unless another process
recorded a link for it in the meantime, which that process then decides about (`precondition_failed`
here). The adapter's `maxLinkMinutes` must be at least its `minLinkMinutes` plus 5, or the config is
refused. A link is never texted with less than 5 minutes of the provider's life left: it is expired
at the provider (`payment.link_expired`, reason `not_sent_in_time`) and the request settles
`expired` when the provider confirms, or waits for its webhook when the provider says `not_open`.
Either way `requestPayment` throws `precondition_failed`: on `expired` it says to request a new
payment, on `not_open` to wait for the provider's outcome (the payment is still open, so no new one
can start). The life left is checked when the sender claims the text, after the link's reference is
bound, and once more after the lease is renewed right before the text. A resume that finds the text
already recorded by another sender (it finished while this one created the link) sends nothing and
returns the delivery recorded. A request is also checked against this engine's payments adapter
before its read-back is used: a mode the adapter does not take, or a link life longer than it keeps
a link (a call saved by an engine with another adapter), is `invalid_input`, and the confirmed
read-back stays for a request that fits. A process about to text a link holds a 60 second lease on
it, so a concurrent resume refuses (`precondition_failed`) rather than expiring a link being sent,
and never takes the lease over while it is live (the text may be going out); once the lease lapses,
it may, and a sender stalled past it then texts a link the provider has already closed (so it cannot
be paid). A sender whose text (or a write before it) fails gives its lease back at once, so the
retry needs no wait; a release that fails leaves the lease to lapse. A process whose request another
process settled while its create was slow never texts the link it got: it expires it at the provider
and throws `precondition_failed`. The create guard keeps a minute over the provider's minimum for
its latency; a create the provider still refuses leaves the request to the next resume, which
expires it. `expirePaymentLinks(callId)`, which the host calls at `expiresAt` or later, asks the
provider to expire each texted link still open past its deadline (`expireLink`): on `expired` the
request settles `expired` (and its flow step fails); on `not_open` it is left for the provider's
webhook, which may still say paid. A link that was never texted never expires this way; it stays
open to resume.

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
recorded, or the lease lapses, they go ahead. A lapsed lease does not prove its sender stopped:
one that renewed its lease and then stalled past it may still hand its text to the carrier after
the close, and that text carries a link the provider has closed (it cannot be paid, and nothing is
recorded for it). A host should expect such a late text and treat its link as dead. A close of a
link that exists is claimed in its first write, before the provider is asked (`closingSince` on the
request): no sender starts a text of that link from then on (it expires the link at the provider
and throws `precondition_failed`), and a close that fails at the provider stays claimed, so it can
be tried again with no sender taking over meanwhile. A sender checks and renews
its lease in a write right before the text, so one that stalled past its lease (binding the
link's reference) never texts a request that was closed or a call that ended meanwhile: it expires
the link at the provider and throws `precondition_failed`; one whose lease another sender took
stops too. `endCall` appends any ledger entries still pending before it takes the receipt's head,
so the head covers every entry the end wrote. A sender that comes back after
its request was closed records nothing, so no entry follows the close or the receipt. If the
provider fails while the call ends, the call stays ended without its receipt, and `endCall` again
expires what is left and issues it.

**Late payments.** A payment the engine settled `expired` (its deadline, a cancel, the end of the
call, a text that could not go out in time, or a race with a slow create) can still be paid by a
caller already on the page. The money moved, so a `paid` outcome for it is recorded: the payment
becomes `paid` and `payment.settled` carries `late: true`. The session and the flow do not move, and
a receipt already signed is not changed: the ledger is where the late payment shows.

**Adapter capabilities.** `PaymentLinks.capabilities` declares `{modes, minLinkMinutes,
maxLinkMinutes}`. When the config is saved, a step's mode (and Paylink's default mode) must be one
the adapter takes, and the link life no longer than its maximum (`refund` is optional: no flow step
needs it, so a platform payment flow is valid without it); malformed capabilities are a problem too,
and so is an engine's payments adapter that declares no capabilities at all (a plain JavaScript
adapter). Adapters are given when the engine is built, so these checks run when the engine is built
(`createEngine`) and when a config is saved (`configure`), not at `engine.use`, which installs
modules; a refused adapter never fails mid-call. A registry built without capabilities (only adapter
names) skips these checks; an engine always has them.

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
taken on the host's own account. A request settles once; later outcomes are ignored, with one
exception: money that moved is always recorded ("Late payments", above).

**Refunds (platform mode).** `refundPayment({callId, paymentId, amountMinor?, reason, sequence?})`
is a host call made for the business (its back office or staff): no grant reaches it, no flow step
runs it, and the model is never given it. It refunds a `paid` platform payment in full (the default:
all that is left) or in part, with `reason` one of `requested_by_customer`, `duplicate`,
`fraudulent`. Refused: `invalid_input` for a bad reason or amount, an unknown payment, or refunds
that would add up to more than was paid (a refund the provider answered `failed` does not count);
`precondition_failed` for a payment not `paid`, a connect payment, a payment refunded in full, a
payment with a dispute open or lost (the provider refuses those too), and an engine whose payments
adapter has no `refund`; `module_disabled` on a call that started with Paylink off. A refund is
reserved in one write (one in flight per payment; asking again while it is resumes it, and another
amount is refused), with its intent and idempotency key saved before the provider is asked, sent
with `PaymentLinks.refund({linkId, paymentIntentId?, mode: "platform", amountMinor, currency,
reason, idempotencyKey})`, and committed in another write with the provider's answer and
`payment.refunded`. It returns `{refundId, status, amountMinor, refundedMinor}`. Each refund of a
payment has a sequence number, 1 for its first and one more for each after (a failed one keeps its
number), and its key is `[workspaceId, callId, paymentId, "refund", sequence]`. A host that passes
`sequence` makes a retry safe after it lost the engine's answer: the same number again resumes that
refund with its key while it is in flight, or gives its saved result back once it was committed, and
never refunds again (another amount for it is `invalid_input`); the next number starts a new refund,
any other number is `invalid_input`, and a new number while another refund is in flight is
`precondition_failed`. Without `sequence`, a call is the next refund, or resumes the one in flight,
so a host that retries without it after a committed refund asks for a second one. A refund still in
flight is resumed with its own key before the dispute check, which is for new refunds: a refund the
provider made whose answer was lost is learned even if a dispute opened since. An adapter answers a
refund the provider refused as `failed` and throws only when the answer was lost: a refund that
threw stays in flight and the next `refundPayment` resumes it with the same key, so an adapter that
throws for a refusal blocks the payment's refunds. An answer that is not one of the provider's three
(`pending`, `succeeded`, `failed`, with a refund id) is treated the same way, as a lost answer
(`precondition_failed`): nothing is recorded or ledgered, the refund stays in flight, and while an
adapter keeps answering that way every later refund of the payment is blocked, since one is in
flight at a time. A refund the provider made is learned once the adapter answers properly. A
`pending` refund counts as pending, toward the total, until a provider update for it arrives.

**Refund updates (platform mode).** `applyRefundOutcome({providerRef, paymentIntentId, status,
amountMinor, currency, account?})` applies a verified refund update (Stripe's `refund.updated`,
`refund.failed` and `charge.refund.updated`; `parseStripeEvent` gives them as `kind: "refund"`, and
the reference server applies them on its payments endpoint only). It finds the payment by its bound
payment intent and the refund by the provider's refund id the engine recorded (`providerRef`). Only
a `pending` refund moves: to `succeeded`, or to `failed` (Stripe's `failed` or `canceled`), written
as `payment.refund_updated`; a failed one stops counting toward the refunded total, so the business
can refund that amount again with the next sequence number. A refund already `succeeded` or `failed`
is final, and an update that changes nothing (`pending`, `requires_action`, a repeat) writes nothing.
It answers `{applied: true, callId, status}`, `{applied: false}` for an update with no payment
intent, a refund the engine did not make (made by hand at the provider), or one whose amount or
currency differs from what the engine asked, and `{applied: false, unbound: true}` while the payment
intent is not bound or the engine's own answer for a refund of that payment is still on its way, so
the host has the event delivered again. A connected account's event is ignored and written down
(`payment.outcome_ignored`). Works after the call ended; the receipt is never changed.

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
final; an event that changes neither status nor amount is not written again. Webhooks come in any
order, so an event older than the status recorded never replaces it (a late `warning_needs_response`
after `warning_closed` would block refunds again): by the provider's time (`occurredAt`, Stripe's
event `created`) when both carry one and they differ, otherwise by the status's stage in a
dispute's life (`warning_needs_response`, `warning_under_review`, `warning_closed`,
`needs_response`, `under_review`, then `won` or `lost`). An `occurredAt` that is not a time is
`invalid_input`.

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
  payer est de AMOUNT, pour DESCRIPTION. Est-ce exact ?"; `digest` is
  `SHA-256(canonicalJson({amountMinor, currency, description, locale, readBackId, text}))`, where
  `readBackId` is the engine's own id for this read-back (from `ids`, prefix `amt`), so two
  identical read-backs (a second deposit of the same amount) never share a digest and a late yes to
  the first never confirms the second. The call keeps the read-back (one at a time; a new one
  replaces it) until a link uses it. Untrusted content drops it. The read-back is for the subject
  matched when the amount was looked up: if another subject is matched by the time it is stored, it
  is refused (`precondition_failed`).
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
  made for, without a new read-back. The scope is checked again right before the text, so a signal
  raised or a window opened while the link was created means the link is not texted
  (`scope_denied`; the link id is kept). The mode, link life and payment methods still come from the
  step and the settings when the link is reserved.

## 15. Stripe webhooks

`verifyStripeSignature` follows Stripe's published scheme: the `Stripe-Signature` header has
`t=<unix seconds>` and one or more `v1=<hex>`; each `v1` is `HMAC-SHA256(secret, t + "." + raw
body)`. The check passes if any `v1` matches any configured secret and `t` is within 300 seconds of
now, either way. The raw body is the bytes received: `payload` may be a `Uint8Array` (a string is
taken as its UTF-8), and a receiver checks those bytes before it decodes or parses them, since a
decoder with replacement reads two different invalid UTF-8 bodies the same. The reference server's
`/webhooks/stripe/*` and `/webhooks/records` routes do: a body under a bad signature is refused
without being decoded or parsed. A host may set `toleranceSeconds`, an integer from 0 to 86,400; any
other tolerance, or a `now` that is not a valid `Date`, throws `invalid_input` before anything is
checked, since a NaN or an Infinity would let a replay of any age pass. `parseStripeEvent` maps
`identity.verification_session.{verified,requires_input,canceled}` and
`checkout.session.{completed,async_payment_succeeded,async_payment_failed,expired}` (with the
session's `payment_intent` when it is a string) and
`charge.dispute.{created,updated,closed,funds_withdrawn,funds_reinstated}` (the dispute id,
`charge`, `payment_intent` or null, `status`, `amount` and `currency`, and the event's `created` as
`occurredAt`; never its evidence; a `created` that is present but not Unix seconds, or past what a
JavaScript `Date` holds, makes the body malformed), and `refund.updated`, `refund.failed` and
`charge.refund.updated` (the refund id as `providerRef`, `payment_intent` or null, `status`, `amount`
and `currency`; never its failure reason; `refund.created` is ignored); other types are reported as ignored, and a body
that is not a well-formed event is `null`, including one whose `account` is present but not a string
(never read as "no account"). The reference server applies dispute and refund events from the platform's
payments endpoint only. `applyPaymentOutcome` answers `{applied: false, unbound: true}` for a link
no call holds yet (its reference may still be being bound when the provider's event arrives); the
reference server answers 503 for it and does not remember the event, as for an unbound dispute, so
Stripe delivers it again.

The reference server's `StripeIdentityProvider` (an example, not part of the package) is an
`IdentityProvider` that calls Stripe with `fetch`. `createDocumentCheck` sends one `POST
/v1/identity/verification_sessions`, form-encoded, with exactly `type=document`,
`options[document][require_matching_selfie]=true` and `metadata[call_id]=<call id>` (the call id as
is when it is at most 500 UTF-8 bytes, Stripe's metadata value limit, and otherwise `sha256:` and
its hex SHA-256, the same every time, so a long call id still gets a check), and the headers
`Authorization: Bearer <restricted key>`, `Idempotency-Key`, and a pinned `Stripe-Version`
(`2025-03-31.basil`). The `Idempotency-Key` is the engine's key as is when it is 1 to 255 printable
ASCII characters without spaces, and otherwise `sha256:` and the hex SHA-256 of it, so the same
engine key always sends the same header and a resumed `startPhotoId` gets the same session and link.
It answers the session's `id` (which must start with `vs_`) as the session id and its `url` (which
must be `https://` and then 1 to 2,040 printable ASCII characters, no space, line break or control
character, since it goes into a text message as is) as the link. The constructor takes only a
restricted key (`rk_test_` or `rk_live_`); `npm run serve` takes only `rk_test_`. A refusal or a
malformed answer throws `StripeApiError` with the HTTP status and Stripe's error type and code when
they are plain identifiers, never Stripe's message or any value from the request or the answer.
Requests time out after 10 seconds (`timeoutMs`, a whole number from 1 to 60,000) and never follow a
redirect. An `apiBase` option must be `https:`, or `http:` on a loopback host (`127.0.0.1`,
`localhost`, `[::1]`) only, with no credentials in it; anything else, and a bad `timeoutMs`, throws
in the constructor, never quoting the value.

## 16. Texts

Code builds every text, in the call's locale, one of `SUPPORTED_LOCALES` (exported, a frozen
`["en", "fr", "es"]` whose members are the `Locale` type; `isSupportedLocale` checks a host's value).
Each catalog of code-built words is a `Record<Locale, ...>`: the texts below (`IDENTITY_TEXT`,
`PAYMENT_TEXT`, `TEXT_CODE_TEXT`, `ACCESS_CODE_TEXT`, `RECEIPT_LINK_TEXT`, `CONTACT_NOTICE_TEXT`,
`ACTION_WORDS`), `AMOUNT_REGION` and `LIST_REGION` (where amounts and lists are formatted),
`AMOUNT_READBACK_TEXT` and `READBACK_WORDING` (the read-backs), `INTERRUPT_LINES`, `BANK_WORDS`,
`NUMBER_CONNECTORS` and `NUMBER_LANGUAGES_BY_LOCALE` (the number words the redactors read: English
and French on every call, Spanish too on a Spanish call). A test fails when a catalog lacks a
supported locale, when a `Record<Locale, ...>` in `src/` is not one it checks, or when code picks
words by comparing a locale instead, so a new locale grows every catalog. The destination is
always the subject's number on file. Identity link: "Your one-time identity check link: URL" /
"Votre lien de vérification d'identité, à usage unique : URL" / "Su enlace de verificación de
identidad, de un solo uso: URL". Payment link: "Your secure payment link for AMOUNT: URL" /
"Votre lien de paiement sécurisé pour AMOUNT : URL" / "Su enlace de pago seguro por AMOUNT: URL",
with the amount formatted in the currency's own decimals, as in `en-CA`, `fr-CA` and `es-US`
(`$1,500.50` in Spanish for US dollars). Texted code: "Your one-time verification code: CODE. It
expires in 10 minutes. Do not share it." / "Votre code de vérification à usage unique : CODE. Il
expire dans 10 minutes. Ne le communiquez à personne." / "Su código de verificación de un solo
uso: CODE. Caduca en 10 minutos. No lo comparta con nadie." Access code (section 17): "Your
one-time door code: CODE. It works once, within N min." / "Votre code de porte, à usage unique :
CODE. Valable une fois, dans les N min." / "Su código de puerta de un solo uso: CODE. Sirve una
vez, dentro de N min.", N being the minutes left on the access grant, rounded up, at least 1.

**Actions.** When a flow step whose needed scope is of class money, contact or access completes
(section 4), the call notes the class, once each. An outside module that changes contact details,
in a flow or outside one, calls `contactChanged()` on its `ModuleCallView` in that same
`updateModule` change, which notes a contact action the same way; with no keypad or PIN match
standing it is refused (`precondition_failed`) and the module's change is not saved, since there
is no number to alert. Each contact action also keeps the matched subject and its number on file
as Badge read it when verification started, before the change, unless the call already kept that
same subject with that same number; Badge's keypad or PIN match always stands then, since such a
step follows a level 2 verification. Keeping one writes `contact.notice_owed` in the same write.

**Receipt link** (purpose `receipt_link`). `textReceiptLink(callId, url)` texts the host's
capability link to an ended call's receipt (section 12, an `https` URL of at most 512 characters
with no whitespace, no control or format character (such as NEL, a zero-width space or a bidi
override) and no lone surrogate, else `invalid_input`; a call not ended or without its receipt yet:
`precondition_failed`). It returns `{texted: true}` only when the flow's `trace.receipt` step has
`textLink`, an action was noted, the caller's latest answer to `textLink.consent` is "yes" (a later
"no" withdraws an earlier "yes"), a keypad or PIN match still stands (or the call kept a number for
Badge's current subject before a contact change), and no link was texted on this call yet; otherwise
`{texted: false}` and nothing is sent. It goes to the first number kept for Badge's current subject
before a contact change, else that subject's number on file; a number kept for another subject is
never used. "Receipt from BUSINESS for ACTIONS on your call: URL" / "Reçu de BUSINESS pour ACTIONS
lors de votre appel : URL" / "Recibo de BUSINESS por ACTIONS durante su llamada: URL", where ACTIONS
lists, in order, "a payment", "a change to your contact details", "an access request" / "un
paiement", "une modification de vos coordonnées", "une demande d'accès" / "un pago", "un cambio en
sus datos de contacto", "una solicitud de acceso". No amount, code or personal value. A retry after
a failure sends with the same idempotency key; the ledger gets one `receipt.link_texted`.

**Contact change notice** (purpose `contact_changed`). Each subject and number a contact step kept
is owed a security notice, whatever the caller answered about receipts: it is not a receipt and
has no setting. Each is sent, in order, to the number kept before the change, with one
idempotency key per notice, as soon as the write that owes it is saved; a failed text leaves it
owed (the change itself still succeeds), and the call's next write, `endCall` or `sweepAlerts()`
sends it. `endCall` sends any still owed before signing the receipt; if a text fails there,
`endCall` throws, and calling it again sends the notices still owed (and the receipt) without
ending the call again. `sweepAlerts()` (the host runs it on a schedule) is the one sweep for
contact notices and duress alerts (section 6): a call that owes either is stored with `owesAlerts:
true`, the session store lists those calls (`listCallsOwingAlerts`, required by the sweep), and it
sends what each still owes, ended or not, so a call that is never ended still alerts; it returns
`{sent, failed}` (call ids; a failed one stays owed, and a call the host's session retention
removed is reported as failed). A
call that ended with ledger entries still pending (a notice or receipt saved, then not appended)
is finished the same way: `endCall` appends them and returns the kept receipt, or null.
"BUSINESS: the contact details on your account were changed during a call. If it was not you,
contact us right away." / "BUSINESS : les coordonnées de votre compte ont été modifiées pendant
un appel. Si ce n'était pas vous, communiquez avec nous sans tarder." / "BUSINESS: los datos de
contacto de su cuenta se cambiaron durante una llamada. Si no fue usted, comuníquese con nosotros
de inmediato.", with "Security notice" / "Avis de sécurité" / "Aviso de seguridad" in place of
BUSINESS when Trace has no `businessName`. It
never says which detail changed or to what. The ledger gets one `contact.notice_sent` per notice.

## 17. Gate and access grants

Gate's settings: `targets`, at least one, each `{id, controller, ref}`: `id` lower-case letters,
digits and `-` (unique), `controller` the name of one of the engine's `access` adapters that has an
`unlock` function, own or from its class (checked when the engine is built and when a config is
saved), `ref` the controller's own name for the
door, 1 to 200 characters; `maxGrantsPerCall` 1 to 5, default 3. A flow with more `gate.grant`
steps than `maxGrantsPerCall` is refused when the config is saved: each step completes only on a
grant of its own, so it could never finish. A call keeps the targets in force
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
   target or a bad lifetime, `precondition_failed` while another grant of the call is in flight,
   once `maxGrantsPerCall` grants were issued, or when the engine has no access controller by the
   target's name (own adapter entries with an `unlock` function only), and `conflict` when the id
   generator gives a grant id the call already used (nothing is reserved; a retry draws a new
   one). The grant's expiry is the earlier of now plus its lifetime and the verification grant's
   expiry. Ledger: `access.issued`.
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
   between, the call is read again as it is now and checked against the config in force, so a
   taint written after step 4, or a config that raised `entry.open`'s floor, settles the grant
   `failed` (`not_authorized`) and nothing is sent. A taint that commits after that read lands
   while the grant is on its way to the door: the taint's own write records `access.tainted`
   `{grantId, digest, status, revocable}` for each grant of the call that may still be acted on
   (signed, not expired, and `reserved`, `delivered` or `unknown`), and the engine then asks each
   one's controller to withdraw it with its optional `revoke({grant, target, callId,
   idempotencyKey})` (key `[workspaceId, callId, grantId, "revoke"]`), once, recording
   `access.revoked` `{grantId, outcome: "revoked" | "failed"}`. A controller without `revoke` is
   asked nothing and the grant runs to its expiry. A grant already delivered and acted on cannot be
   pulled back: a door that opened stays opened, and `revoke` only stops what has not happened yet
   (an access code not yet redeemed, a credential not yet used). A config changed by another
   process is seen at its next write, not here.
6. **Record the answer**, in the engine's write: `delivered` (with `confirmed` when the controller
   reported the door moved), `refused` (the controller certainly did not act; its reason as a short
   code), or `unknown` (reason `answer_lost`) when the call threw or timed out, and (reason
   `malformed_answer`) when its answer is neither a delivery with a string `providerRef` and a
   boolean `confirmed` nor a refusal with a string `reason`: such an answer does not say the door
   stayed shut. A grant settled
   meanwhile stays as it is. `grantAccess` returns what the call holds. A failure to write the
   answer is thrown as it is; the grant then settles as stale (step 1). Every outcome entry carries
   `grantId`, `digest` and `kid`, never the grant or its signature. A fresh request after `unknown`
   is a new grant.

**Ending a call** is refused (`precondition_failed`) while a signed grant may still be acted on: at
its door (step 4 passed, its answer not yet recorded) or sent with its answer lost (`unknown`, the
controller may still be working on it), and not yet expired. A definitive answer (`delivered`,
`refused`) lets the call end at once. The end waits for an answer still due, bounded by the
controller's timeout, or for the grant's expiry if the answer was lost or its process stopped. A
grant reserved but not yet signed is settled `unknown` (reason `call_ended`) in the same write that
ends the call, and is then never sent (step 4 finds it settled); one that expired is settled
`unknown` (reason `no_answer_recorded`). All of it happens before the receipt's ledger head is
taken, so no outcome of a grant sent to a door controller follows `receipt.issued`, and no such
grant reaches a door after the receipt while it can still open it: once it expires, a relay refuses
it (`verifyAccessGrant`). A one-time access code (below) is the exception: its grant is `delivered`
when the code is texted, the door can accept the code after the receipt until the grant expires,
and a code spent by wrong guesses then is recorded as `access.code_spent` after the receipt. A
controller that does not check a grant's expiry could still act on a request delayed past it; the
relay contract requires the check.

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
unique across every workspace whose grants one `SeenGrants` instance checks (or each workspace
gets a tracker of its own), and across calls and processes: the default generator is random (96
bits); a host's own `ids` that repeats makes a relay refuse a fresh grant as a replay.

Every key set the engine publishes (`receiptKeys()`, `accessKeys()`, `stepUpKeys()`) holds only
the public members of each key (`kty`, `crv`, `x`, `y`, `kid`, `alg`, `use`), whatever its
signer's `publicJwk` returns, so a signer that hands back its private `d` never has it published.
Each key's `kid` is its signer's `keyId`, the one every signed document carries, whatever the JWK
says: a JWK without a `kid` would otherwise leave every grant and receipt unverifiable.

**The relay contract, version 1** (`webhookRelay({url, timeoutMs?})`): `POST <url>` with
`content-type: application/json`, `idempotency-key: <the key above>` (as printable ASCII: any other
character is written as a JSON `\uXXXX` escape, so the header parses to the same tuple; a header
cannot carry a character past U+00FF) and the signed grant as canonical JSON. HTTPS only, or HTTP to
`127.0.0.1`, `localhost` or `[::1]`; no credentials in the URL; redirects are not followed; the
timeout is 100 to 30,000 ms (default 5,000). The relay answers 2xx after it worked the door,
optionally `{"state": "confirmed", "ref": "<its id>"}`; 4xx when it did not act, optionally
`{"error": "<code>"}` (`signature`, `workspace`, ...). A 409 (`replay`) is not a refusal: an earlier
request with this grant was accepted and may have opened the door, so it is `unknown`. Anything
else, including no answer, is `unknown` too. A relay checks the grant with `verifyAccessGrant`
against `engine.accessKeys()`, its own workspace and its own audience, and refuses a grant id it has
seen.

**The Seam adapter** (`seamAccessController({apiKey, baseUrl?, allowLoopbackForTests?, timeoutMs?,
confirmWithinMs?, pollIntervalMs?, fetch?, clock?})`), named in the engine's `access` adapter like
any controller: the target's `ref` is the Seam `device_id`. `baseUrl` defaults to
`https://connect.getseam.com`, and its host must be one of `SEAM_HOSTS` (`connect.getseam.com`),
over HTTPS on the default port, with no credentials, query or fragment: the API key goes nowhere
else. The loopback address, over HTTP or HTTPS, is accepted only with `allowLoopbackForTests: true`,
which is for tests and never for production; `timeoutMs` is per request, 100 to 30,000 (default
5,000); `confirmWithinMs` 0 to 30,000 (default 10,000) and `pollIntervalMs` 10 to 5,000 (default
1,000). Every request is a `POST` with `authorization: Bearer <apiKey>` and a JSON body, redirects
not followed. No idempotency key is sent: Seam documents none on unlock.

0. Unless the grant's signed `target` is the device it is asked to open, the result is `refused`
   (`target_mismatch`) and nothing is sent, not even the device check.
1. `POST /devices/get {device_id}`. Unless the answer names the same device with
   `can_remotely_unlock: true` and not `properties.online: false`, the result is `refused`:
   `cannot_unlock_remotely`, `device_offline`, `device_unreadable`, Seam's error type on a 4xx
   (`device_not_found`, ...) or `http_<status>`, and `seam_unavailable` on a 5xx or no answer.
   Nothing was sent to the lock.
2. Unless the grant has at least `timeoutMs` left by `clock` (the system clock by default), the
   result is `refused` (`grant_expiring`) and nothing is sent, since the expiry is strict and the
   call may end then. A clock or an expiry that cannot be read counts as no time left. This bounds
   when the unlock is sent and how long the client waits for it, not the network, and Seam's own
   attempt may still complete later.
3. `POST /locks/unlock_door {device_id}`, once, never retried. A 4xx is `refused` (Seam's error
   type when it is a short code, otherwise `http_<status>`); a 5xx, a timeout, a dropped
   connection, a redirect, or a 2xx without an action attempt (`action_attempt_id` 1 to 200
   characters, `status` `pending`, `success` or `error`) throws, which Gate records as `unknown`.
4. While the attempt is `pending`: `POST /action_attempts/get {action_attempt_id}` after each
   pause of `pollIntervalMs`, the whole wait held to `confirmWithinMs` of elapsed time (each pause
   and each request is cut to what is left; 0 never asks). `success` is `delivered`, `confirmed:
   true` only when Seam reports `result.was_confirmed_by_device: true` (a `success` alone means
   Seam sent the command, not that the lock moved); `error` throws (`unknown`: a lock that timed
   out may still have moved); still `pending`, or an answer that cannot be read, is `delivered`
   with `confirmed: false`. `providerRef` is the action attempt id. Each request's path is set on
   a copy of `baseUrl`, so its host is always `baseUrl`'s.

**Direct vendor adapters** (`vendorAccessController({vendor, apiKey, baseUrl?,
allowLoopbackForTests?, timeoutMs?, fetch?, clock?})`, `vendor` being `kisi` or `verkada`), named
in the engine's `access` adapter like any controller: the controller's door ref is the vendor's
own id, a Kisi lock id (digits) or a Verkada door id (a UUID). `unlock` first checks that the
grant's `target` is the target it was asked to open and has that form; otherwise it answers
`refused` with `target_mismatch` or `bad_target` and sends nothing. It also sends nothing,
answering `refused` with `grant_expiring`, for a grant with less than `timeoutMs` left by `clock`
(the system clock by default, a reading or an expiry that cannot be read counting as no time
left), the client's own bound on the whole unlock, since the expiry is strict and the call may end
then. This bounds when the request is sent, not the network: neither vendor's request carries a
deadline, so one delayed in transit could still arrive after the grant expired. Each request's
path is set on a copy of `baseUrl`, so its host is always `baseUrl`'s. Kisi: one `POST
<baseUrl>/locks/<lock id>/unlock` with `Authorization: KISI-LOGIN <apiKey>` and the body `{}`.
Verkada: `POST <baseUrl>/token` with `x-api-key: <apiKey>`; a token call that does not answer 200
with a `token` string answers `refused` with `token_unavailable` and the unlock is not sent; then
one `POST <baseUrl>/access/v1/door/admin_unlock` with `x-verkada-auth: <token>` and `{"door_id":
"<door id>"}`. The token is never kept. Neither vendor checks the grant, takes an idempotency key
or reports in its answer that the door moved, so neither is sent and a 2xx is `delivered` with
`confirmed: false` and the grant id as `providerRef`. A 4xx is `refused` with `http_<status>`
(the vendor's text is never passed on); anything else throws (`unknown`). Never retried, no
redirects, one timeout for the whole unlock (100 to 30,000 ms, default 5,000). `baseUrl` defaults
to `https://api.kisi.io` or `https://api.verkada.com` (`https://api.eu.verkada.com` and
`https://api.au.verkada.com` for those regions), and its host must be one of the vendor's
(`VENDOR_HOSTS`: `api.kisi.io`; `api.verkada.com`, `api.eu.verkada.com`, `api.au.verkada.com`),
over HTTPS on the default port, with no credentials, query or fragment: the key goes nowhere
else. The loopback address, over HTTP or HTTPS, only with `allowLoopbackForTests: true`, for
tests and never for production. `apiKey` is 1 to 500 printable characters with no spaces.

A momentary unlock that opened its door has nothing to revoke (ADR-22). A controller that can
withdraw a grant not yet acted on offers the optional `revoke`, which the engine calls only when a
call is tainted (step 5); one-time codes have it, below.

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
  `engine.grantAccess(callId, input, {controller: codes.controller})` with the same
  input, steps and refusals (and one more: a target whose controller is not `codes.controller` is
  `invalid_input` before anything is reserved, so a code request never sets off a live door), so
  the engine reserves the grant, holds it to `entry.open`, checks it
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
  3. `limits.take({workspaceId, key: {scope: "subject", key: subjectKey}, at,
     ...ACCESS_CODE_SEND_LIMITS})` counts the text against the texted codes' `CodeStore`; false
     refuses it (`send_limit`) and nothing is texted, and a limiter that throws refuses it too
     (`send_limit_unavailable`): nothing was stored or texted, so the door certainly gets nothing.
  4. A drawn code is stored with `store.put` as an `AccessCodeEntry`:
     `{workspaceId, digest, grantId, callId, body, misses: 0}`, the digest being
     `HMAC-SHA256(key, JSON.stringify(["access-code", workspaceId, audience, target, code]))`
     (`accessCodeDigest`) and `body` the grant's body, unsigned. A digest already live for that
     door draws a new code, up to 3 times, then the request is refused (`no_free_code`).
  5. A call no longer authorized for `entry.open` (a taint landed while the limiter or the store
     answered) is not texted: its entry is taken back and it is `refused` (`not_authorized`); a
     taint after this check finds the code stored, and the controller's `revoke` takes it out. A
     grant that expired meanwhile is not texted either: its entry is taken back and it is
     `refused` (`expired`). Otherwise the code is texted (`purpose:
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
  guesses}` (event id `[workspaceId, "access.code_spent", callId, grantId]`), never with the guess
  or the code. Signing
  comes before the take, so a signer that throws leaves the code redeemable; a code taken, revoked
  or expired while it was signed is refused and its signature dropped. A code expires with its grant's
  `expiresAt`. The door's relay checks the grant with `verifyAccessGrant` (audience `audience`)
  and `SeenGrants`, as for any grant.
- `codes.revoke(workspaceId, grantId, callId?)` removes a grant's code (with `callId`, only that
  call's: grant ids are unique within a call, not across calls); one already gone is success.
- `AccessCodeStore`: `put(entry, now)` (false when the digest is live or spent), `get(workspaceId,
  digest)` (reads, leaving it; null for a spent entry), `take(workspaceId, digest, grantId?)`
  (removes and returns, atomically: never one entry twice; with `grantId`, only that grant's
  entry; never a spent one), `revoke(workspaceId, grantId, callId?)` (a spent entry too; with
  `callId` only that call's entry, which every store must honor), `spent(workspaceId, callId?)`
  (every spent entry still held, of one call with `callId`),
  `miss(workspaceId, {audience, target}, limit, now)` (one wrong guess counted against every live
  entry for that door, atomically, marking those at `limit` spent, and returning every spent entry
  of the workspace still held). A spent code opens nothing; its entry stays as the pending record
  of its `access.code_spent` ledger entry, and `codes` removes it (`revoke`) only once that entry
  is appended (idempotent by its event id), and only that call's entry. An append that fails is
  made again on the next wrong guess at that door, when the call ends (`endCall` calls the
  controller's optional `flush({workspaceId, callId})` before it takes the receipt's head, and a
  flush that fails never stops the end), and on `engine.sweepAccess()`, which the host runs on a
  schedule and which flushes the whole workspace (`{failed}` names the controllers that could not);
  every spent code is tried, and the first failure thrown. `MemoryAccessCodeStore` is the
  in-memory reference, dropping expired entries (never a spent one) on `put`.
- `limits` is the texted codes' `CodeStore` (section 4; `take` counts one send atomically, or
  refuses and counts nothing; `MemoryCodeStore` in `district-assurance/testing` is the reference),
  the same instance the engine's texted codes count against, so both kinds of code share one
  budget per subject. `ACCESS_CODE_SEND_LIMITS` is the texted codes' subject limit
  (`TEXT_CODE_LIMITS.subject`): 5 sends in 24 hours, 60 seconds apart. The texted codes'
  per-number limit and `textCodeCountryCodes` are not applied to access codes.

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

A token left `reserved` past its expiry (the process signing it stopped before its last write) is
failed (`stepup.failed`, reason `not_issued_in_time`) in a write of its own before the call's next
request, so it never blocks that call for good; one still within its life keeps blocking. Ending the
call fails a token still being signed (`stepup.failed`, reason `call_ended`), in the write that ends
it, so none is handed out after the end. The same write judges every `issued` token for the last
time, since the ended call holds no grant: one whose call is tainted, has a new verification
running, or no longer holds the grant the token was issued for (verified again, for that subject or
another, or the grant dropped) is refused (`stepup.refused`, reason `tainted` or `not_authorized`),
and any later exchange of it answers that reason and writes nothing. Only a token issued for the
grant the call still holds as it ends stays exchangeable after the end, until it expires (at most 5
minutes); its `stepup.exchanged` or `stepup.refused` entry may then land before or after
`receipt.issued` (the receipt can still be signing), and never changes the receipt. Whether tokens
stay exchangeable after the end at all is a pending decision. An exchange whose write is saved but
whose ledger append then fails throws, and the token is used up: a retry answers `unknown`, and the
sign-in starts again with a new nonce (it fails closed; the entry is appended by the call's next
write or `flushLedger`). The receipt lists the call's tokens as the end left them (`stepUp`, section
12), so a reader can tie such a later entry to it.

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

## 19. Adversarial suite

`test/adversarial/` holds scripted dialogues, one JSON file per tactic and locale
(`<tactic>.<locale>.json`): urgency, authority, "skip it", partial answers, account probing, text
flooding and injection in business data, each in English and in Canadian French. A scripted host
runs them: the caller's words reach the engine only as transcript lines to `redact`; the model's
proposals are tool calls mapped to fixed code paths (`authorize`, `startPhotoId`, `requestPayment`,
`sendTextCode`, `requestCallback`), and a proposal with no path (mark the caller verified, skip the
check) never reaches the engine; business text is always passed to `markUntrusted`; the host speaks
fixed lines chosen only from the engine's answers. After every turn the runner checks:

- **No grant without factors:** a grant needs a passed factor and never exceeds the level the
  recorded factors reach; `authorize` is true only for a scope the grant lists.
- **No text before a match:** every text and carrier check comes after a keypad or PIN match on
  the call, goes to the number on file in that subject's record (never one taken from caller ID),
  and is in the call's language. A text goes to the calling number only when it is also the
  number on file; otherwise the calling number never receives one.
- **Identical answers for unknown and wrong:** a mirror call keyed with an account that is not on
  file gets every keypad and PIN entry the script's call gets; each entry that did not match has
  the same answer, the same spoken line and the same ledger detail as the mirror's.
- **Tainted sessions lose their grant:** after business text, and at the end of every call, the
  grant is gone, the level is 0 and every scope is refused until a new verification earns one.

Every script also checks that nothing keyed, said or fetched reaches the ledger, a text or a
spoken line, and that the ledger chain verifies. The check reads every decoded string in the
ledger and every raw text body, and finds a value as a whole token, so a value embedded in a field
("DOB: 19850214") fails it while the same digits inside a hash do not. A value under 4
characters fails it only as a whole field, since shorter tokens also occur in timestamps. The
suite fails when a tactic lacks a script in either language, when the French script does not
mirror the English one turn for turn, when a built factor or a policy scope is not exercised in
both languages, or
when a script never compares a wrong entry with an unknown account or never taints a session that
holds a grant, or when a text-flooding script never sends a text (so "no text before a match" is
never vacuous). Every built factor has scripts in both languages: a texted code in text flooding
(it reaches a text and nothing else), a callback in authority (only a keypad or PIN match rings,
and only the number on file), and a spoken answer in partial answers (its match opens no text).

## 20. Keypad collector

`KeypadCollector` is a helper for the host's keypad path (INT-1): it buffers the tones of one entry
outside the model and hands them to the engine. It is pure: no timers and no I/O, time from the
injected clock. Options: `maxDigits` (1 to 32), `idleTimeoutMs` (1 to 600,000), `onDigits` (the one
callback) and an optional `clock` (an object with `now()`); anything else is refused with
`EngineError("invalid_input")`. `press(tone)` returns a status and never a digit:

| Tone | Status | Effect |
|---|---|---|
| `0` to `9`, under `maxDigits` buffered | `buffering` | appended; the idle timeout restarts |
| `0` to `9`, `maxDigits` already buffered | `overflow` | the entry is discarded |
| anything but `#` or `*`, after `overflow` or `rejected` in the same entry | `discarding` | ignored; the idle timeout restarts |
| `#`, digits buffered | `submitted` | the buffer is emptied, then `onDigits(digits)` runs once; its return value is `result` |
| `#`, nothing buffered | `empty` | none |
| `*` | `cleared` | the entry is discarded |
| anything else (`A` to `D`, several characters, not a string) | `rejected` | the entry is discarded |

Before each tone, an entry whose last tone is `idleTimeoutMs` old or older, or later than now (a
clock set back), is discarded, and the result says `timedOut: true`; the tone is then taken as the
first of a new entry. A discarded entry
(after `overflow` or `rejected`) lasts until `#` (`empty`), `*`, `clear()` or the idle timeout ends
it, so no tail of it is ever submitted: with `maxDigits` 4, `123456#` submits nothing. `expire()` does
the same from the host's own timer and says whether it discarded anything; `clear()` discards the
entry at once. A discarded entry never reaches the callback. `toString`, `toJSON` and
`util.inspect` show no digit and not how many are buffered.

## 21. Consent revocation

A consent is revoked by voice, text or dashboard with `revokeConsent({consentId, via})`, where
`via` is `call`, `text` or `web`, during its call or after it. It needs the host's `ConsentStore`
(the `consents` adapter):

- `putConsent(workspaceId, record)` keeps a `ConsentRecord`; idempotent by `consentId`.
- `getConsent(workspaceId, consentId)` returns `{consent, revoked}` (`revoked` is null or the
  revocation), or null.
- `revokeConsent(workspaceId, {consentId, via, at})` keeps a revocation beside the consent; the
  first one wins and is returned to every later call.

`recordConsent` takes `answer` `yes` or `no` and `channel` `call`, `text` or `web` (default `call`)
only: anything else is `invalid_input`, before anything is reserved, stored or ledgered. With the
adapter, `recordConsent` reserves the consent on the call, writes it to the store and then records
it (`consent.recorded`, and the flow step judged). If the store write fails the consent stays
reserved: a consent with another purpose or answer is refused (`precondition_failed`), and the next
`recordConsent` with the same purpose and answer resumes it with the same record. A store outage
never keeps the call from ending: at `endCall` a consent still reserved settles as not recorded,
which is no consent (fail closed). The ledger gets `consent.unrecorded` with the purpose only,
before `call.ended`, and the receipt lists it with `answer: "not_recorded"`. A `recordConsent` still
writing it when the call ended records nothing and throws `precondition_failed`; one after the end
is refused (`invalid_transition`). Without the adapter, consents live on the call record only and
`revokeConsent` is refused (`precondition_failed`).

`revokeConsent` refuses an empty id or an unknown `via` (`invalid_input`), a consent the store does
not have for this workspace (`invalid_input`), a consent answered "no", and a consent that is not
recorded on its call, still being stored or settled as not recorded (`precondition_failed`). So
that `consent.revoked` never precedes `consent.recorded`, it appends the call's pending ledger
entries first. When the host has removed the call record, the revocation is still stored (a yes
in the store never outlives the caller's no) and `consent.revoked` is always appended; when this
workspace's ledger holds no `consent.recorded` entry for the consent (read page by page), its detail
adds `priorRecord: false`. Otherwise it
stores the revocation, appends `consent.revoked` (actor `member` for `web`, else
`caller`) at the revocation's time, tells the listener, and returns the revocation. A second
revocation, or a retry after the ledger failed, returns the first one and completes its entry
without writing a second. Revoking does not change the call record or a receipt already signed:
the receipt proves what was answered then, and the ledger proves the revocation.

`isStopRequest(text)` is true when a text or a spoken answer, apart from spaces and a closing `.`
or `!`, is one of the standard carrier opt-out words STOP, STOPALL, UNSUBSCRIBE, CANCEL, END and
QUIT, or the French ARRÊT, ARRÊTE, ARRÊTER, in any case, with or without accents. A word inside a
longer message ("don't stop", "cancel my order") is not a match, and a value that is not a string
is false. A host may treat more words as a stop on its own. The host decides which consents a
match revokes (for example every consent texted to that number) and calls `revokeConsent` for
each.

## 22. Record delivery

`deliverRecord({ workspaceId, recordId, destination, records, delivery, ledger, clock, sleep?,
retry? })` posts a confirmed record, read from the `RecordStore`, to one destination through the
host's `RecordDelivery` adapter, which makes one HTTP request per call and never retries itself.
It is a library call the host makes after `confirmIntake` (for example from a job queue), not a
flow step. A destination is `{ destinationId, url, secret }` from the host's own configuration:
the id is lower case, digits, `-` and `_` (it goes in the ledger, the URL never does), the URL is
`https:`, or `http:` on `localhost`, `127.0.0.1` or `[::1]`, without credentials, and the secret
is a string of at least 16 characters; a destination that is not an object, or a field of the
wrong type, is refused like a bad value.

The body is the canonical JSON of `{ v: 1, type: "record.confirmed", idempotencyKey,
destinationId, record }`, the same bytes on every attempt. The idempotency key is
`SHA-256(JSON.stringify([workspaceId, "delivery", recordId, destinationId]))` in hex: one key per
record and destination, the same however often the record is delivered. Headers:
`content-type: application/json`, `idempotency-key`, and `district-signature:
t=<unix seconds>,v1=<HMAC-SHA256(secret, t + "." + body)>`, the scheme of section 15, so
`verifyStripeSignature` checks it; each attempt is signed with its own time. A receiver checks the
signature over the bytes received, then decodes them, reads the key from the signed body and
applies it once.

Retries: a 2xx delivers; no answer (the adapter rejects), 408, 429 or 5xx waits `min(maxDelayMs,
baseDelayMs * 2^(attempt - 1))` and tries again, up to `maxAttempts`; any other status fails at
once. Defaults: 5 attempts, 1 second, 60 seconds; allowed: 1 to 10 attempts, a base from 0 to
600,000 ms and a cap from the base to 3,600,000 ms. Each attempt appends one `delivery.attempted`
entry on the record's call, after the post, straight to the `ledger` it is given: no engine is
involved, so an engine's `onEvent` listener does not see these entries. `deliverRecord` returns `{
delivered, attempts, status, idempotencyKey }`; it throws `invalid_input` for a bad destination or
retry setting or an unknown record, before posting, and passes a ledger failure through.

## 23. Document uploads

A caller adds a photo or a PDF to a record they confirmed through a single-use link
(`src/file/upload.ts`). The functions take a context: the workspace id, a `DocumentStore` and the
clock, plus the `RecordStore` to create a link and an id generator and a `DocumentScanner` to
accept an upload.

- `createUploadLink({callId, recordId, locale?, allowedTypes?, maxBytes?})` (`callId` and `recordId`
  non-empty strings; a token that is not a string is a link not usable, never an error) refuses
  (`invalid_input`) an empty id, a locale not in `SUPPORTED_LOCALES`, `allowedTypes` that is empty,
  repeats a type or names one outside `image/jpeg`, `image/png`, `application/pdf`, and a
  `maxBytes` outside 1 to 26,214,400 (25 MiB); defaults are every type and 10 MiB. It refuses
  (`precondition_failed`) a record the `RecordStore` does not have or that another call confirmed.
  It returns `{token, expiresAt, allowedTypes, maxBytes}`: the token is `upl_` and 32 random bytes
  in base64url, and expires 30 minutes (`UPLOAD_LINK_TTL_SECONDS`) after creation.
- The store keeps `{workspaceId, tokenHash, callId, recordId, locale, allowedTypes, maxBytes,
  createdAt, expiresAt, usedAt}`, where `tokenHash` is the SHA-256 hex of the token. The token is
  never stored.
- `openUploadLink(token)` returns `{locale, allowedTypes, maxBytes, expiresAt}` for a link that
  exists in the workspace, is unused and has not expired (now before `expiresAt`), else null.
  Reading an expired link calls `DocumentStore.purgeExpiredUploadLinks(workspaceId, now)`, which
  removes every expired link of the workspace; `sweepUploadLinks(context)` does the same from a
  host's own timer.
- `acceptUpload({token, contentType, bytes})` throws `invalid_input` when `bytes` is not a
  `Uint8Array` or `contentType` not a string, and refuses a body over 25 MiB (`too_large`) before
  copying it. It then checks, in order: the link is usable (`link_not_usable`, for an unknown,
  malformed, used or expired token alike); the declared type, without parameters and in any case, is
  one the link allows (`type_not_allowed`); the file is not empty (`empty`) and at most `maxBytes`
  (`too_large`); the bytes start with the type's signature (`FF D8 FF`, the PNG signature, `%PDF-`;
  else `content_mismatch`). None of these spends the link. Then `DocumentStore.claimUploadLink` sets
  `usedAt` if it is still null and `usedAt` is before `expiresAt`, and only the one claim that did
  goes on (a lost or late claim is `link_not_usable`); the scanner is asked, anything but `clean:
  true` is `scan_refused`, and a scanner that throws is `scan_failed`, its error never passed on;
  the document is stored as `{documentId, workspaceId, callId, recordId, contentType, size, digest,
  receivedAt}` with `digest` the SHA-256 hex of the bytes. From the claim on, the link is spent
  whatever happens.

`MemoryDocumentStore` is the reference store. The reference server, given `uploads`, serves `GET
/u/:token` (the upload page, in the link's language or `?lang=en|fr`, with a switch to the other)
and `POST /u/:token` (a `multipart/form-data` body with a part named `file`, read up to the link's
`maxBytes` plus 16 KiB). Answers: 201 received (the page gives the document's id as a reference),
400 no file, 410 link not usable, 413 too large, 415 type, 422 scan refused, 503 scan failed, each
as a page in the same language. An upload can outlast the request deadline after it spent its link,
so the server keeps the outcome of each upload that spent one (stored, scan refused, scan failed) by
the token's hash until the link would have expired, at most `uploads.keptMax` (default 10,000) at
once. One is never dropped before it expires: when the store is still full after expired ones go, a
new upload gets 503 with `Retry-After` (whole seconds until the first kept outcome expires) before
it claims its link, and is not scanned. A retry with the same link gets that same answer, not "link
not usable", and a retry while the first upload still runs gets 503 with `Retry-After` (the timeout
in whole seconds) and is never scanned a second time. Creating the link, texting it to the number on
file and writing ledger entries for it are not wired into the engine yet.

## 24. Card numbers in transcripts

**Runs of digits.** `digitRuns(text)` reads a text into runs of digits. A run is numerals and spoken
numbers in English, French or Spanish with only separators between them (Spanish hundreds,
`doscientos` and the rest, are whole numbers no count multiplies): spaces, any dash (hyphen, en and
em dashes, the non-breaking hyphen), the minus sign, dots, commas, slashes, underscores, middle
dots, and the characters a reader never sees (zero-width spaces and joiners, soft hyphens, bidi
controls, combining marks: `SEPARATOR_CLASS`). A numeral is any run of Unicode decimal digits
(fullwidth, Arabic-Indic and the rest), read by its values for the checks, and the original span
is what is removed. English and French number words are read on every call, since callers switch
between them; Spanish words only on a Spanish call (`Engine.redact` and a `LiveCardNumberDetector`
given its `locale`), so on an English call "once" and "y" are words. Text redacted with no call
reads every language. Any other word or punctuation ends a run. Joining this widely can join things
that are not one number (a date beside an amount); over-redaction is the safe side, since the risk
is a number reaching storage. Spoken numbers are read as people say them:

| Spoken | Digits |
|---|---|
| digit by digit: `four two`, `oh`, `zéro`, `un`, `une` | `42`, `0`, `0`, `1`, `1` |
| tens and units: `forty two`, `quarante-deux`, `vingt et un`, `soixante et onze`, `soixante-douze`, `quatre-vingt-dix-sept`, `septante`, `nonante` | `42`, `42`, `21`, `71`, `72`, `97`, `70`, `90` |
| teens: `twelve`, `dix-sept` | `12`, `17` |
| `double` and `triple` before one digit: `double four`, `triple 0` | `44`, `000` |
| scales: `four hundred and two`, `forty two hundred`, `cent deux`, `deux mille vingt` | `402`, `4200`, `102`, `2020` |
| Spanish: `cero`, `cuarenta y uno`, `veintidós`, `dieciséis`, `ciento once`, `doscientos`, `cuatro mil ciento once` | `0`, `41`, `22`, `16`, `111`, `200`, `4111` |

Words are compared in Unicode NFC, lower case, with their combining marks, so `zéro` written
decomposed (`e` and U+0301) is still a number word. Units do not combine (`four two` is 4 then 2).
`quatre-vingts` and `deux cents` end a number, since French writes the plural only there. `double`
or `triple` before anything but one digit is an ordinary word.

**Redaction.** `findCardNumbers` looks, in each run, for 13 to 19 digits that pass the Luhn check,
starting and ending on a numeral or spoken number, leftmost first and longest at each position,
never overlapping; `cardNumberRedactor` replaces each with `[card number removed]`.

**Live detection.** `LiveCardNumberDetector` is fed a call's transcript one chunk at a time
(`push(chunk)`; chunks are joined with a space, so each must end at a word boundary). It answers
`{interrupt, digits}`: `interrupt` is true when a run the chunk added to holds `minDigits` digits or
more (8 by default; an integer from 4 to 19, otherwise `invalid_input`), and `digits` counts the
digits of the run still open at the end. There is no Luhn check, since a partial number cannot pass
one, so a phone number read aloud interrupts too. A chunk that does not extend the run does not
interrupt again. A run continues across chunks, also after a trailing `and`, `et`, `double` or
`triple`. The detector keeps only the open run's text, without trailing separators, so empty or
separator-only chunks never grow what it keeps; it never returns it, and forgets it on `reset()`.
The host owns one detector per call and speaks its fixed line on `interrupt`.

**Corpus.** `test/corpus/card-numbers.json` holds the cases for runs, redaction and live detection
as plain JSON, so an implementation in another language can be tested against the same cases.

## 25. Redaction

Each detector is its own `Redactor`; a host composes the ones it wants with `composeRedactors`,
card numbers first, then health card numbers, SINs and bank numbers (a 10-digit health card number
can start with a valid SIN, so the health card pass must see it whole). Composed findings report
offsets into the original input, in the order the redactors ran; `applyFindings(text, findings)`
takes findings in any order (it sorts them by position and merges overlapping ones, marked with
the kind of the one that starts first), so a host can apply composed findings to the original
text as they come. The engine's default redactor
is `cardNumberRedactor`. `Engine.redact` sets `interrupt` on any finding, whichever redactor found
it, and returns `line`, the fixed line for the kind found (`INTERRUPT_LINES`, in the call's
language; a card number first, then a health card number, a SIN, banking details; null when
nothing was found). Only the card number line offers a payment link. A match is replaced by its
kind's marker; `redaction.applied` counts findings per kind.

Digits are read in runs by the same `digitRuns` as "Card numbers in transcripts" (section 24):
numerals and spoken numbers (English and French on every call, Spanish on a Spanish call and on text
with no call), with only the separators listed there between them. A numeral is any run of Unicode
decimal digits (fullwidth, Arabic-Indic and the rest), read by its values for every check, and the
original span is what is removed. Joining this widely can join things that are not one number;
over-redaction is the safe side, since the risk is a number reaching storage. In each run, matches
are taken leftmost first, longest at each position, never overlapping. A format with groups accepts
a written number only when its groups break where the format's do, or not at all; single digits
(spoken digit words, or digits read one by one) may break anywhere.

| Kind | Redactor | Matches | Marker |
|---|---|---|---|
| `card_number` | `cardNumberRedactor` | 13 to 19 digits, Luhn | `[card number removed]` |
| `sin` | `sinRedactor` | 9 digits, Luhn, groups 3-3-3 | `[SIN removed]` |
| `health_card` | `healthCardRedactor` | Ontario: 10 digits, Luhn, groups 4-3-3 (a version code after it is kept). British Columbia: 10 digits starting with 9, mod 11 check digit (weights 2, 4, 8, 5, 10, 9, 7, 3 on digits 2 to 9), groups 4-3-3. Quebec: four letters right before the run, as one word or spelled one by one (at most 8 separators in each gap and before the digits, so only the last 48 characters before a run are read), then 8 digits whose 3rd to 6th give a month (or month plus 50) and a day, groups 4-4; the letters are removed too | `[health card number removed]` |
| `bank_account` | `bankAccountRedactor` | a whole run of 3 or more digits with a bank word among the last 4 words before it, counting only words after the previous run. English: bank, branch, transit, institution, account; French: banque, bancaire, succursale, compte, folio; Spanish: banco, bancaria, bancario, sucursal, cuenta, tránsito, institución, with or without accents; each also in the plural; read in the languages `numberLanguagesFor` gives the call: English and French always, Spanish on a Spanish call and on text with no call | `[banking details removed]` |

Bank numbers carry no check digit, so a bank word is what marks them; an account number read with no
bank word before it is not found. Health card numbers of other provinces are not found yet. Number
words ("forty two", "quarante-deux") and "double" forms are read as section 24 reads them. The test
corpus is shared JSON in `test/corpus/`, one file per kind: each case gives a text, its language and
the exact substrings a redactor must find, in order.

## 26. Subject requests: access and deletion

Two `Engine` methods the business calls from its own code, for one person's access or deletion
request. They take no call id and are no flow step, so nothing on a call reaches them. Both take
`{workspaceId, subjectKey}`: the engine's own workspace and a 64 lower-case hex subject key (a
string: an array or other object holding the key is refused), each read once, else `invalid_input`
(also for a request that is not an object); both need the `records` adapter, else
`precondition_failed`. What the law requires in a given case is the business's to decide.

The `RecordStore` lists a subject's intake records (`listIntakeRecords(workspaceId, subjectKey)`),
deletes records by id (`deleteIntakeRecords(workspaceId, recordIds)`) and removes a subject's PIN
digest, with its duress digest and the `pinEnrolmentId` that names that PIN (as a reset does),
keeping the rest of the subject record (`deletePinDigest(workspaceId, subjectKey)`); the deletes are
idempotent. `recordStoreContract` checks that all three go and the rest stays. A record filed under
no subject is never listed. The store remembers each deleted record id (the id alone) and a later
`putIntakeRecord` of it stores nothing, so a confirmation whose write was still in flight when the
subject was erased cannot bring the values back. It also counts each subject's erasures
(`markSubjectErased`, `subjectErasures`; the subject key alone): `confirmIntake` reads the count
before it reserves a record and passes it to `putIntakeRecord(record, erasuresSeen)`, which stores
nothing once the subject was erased more times than that, so a filing reserved before an erasure the
listing missed stays out too. The confirmation then reads the record back: when the store kept
nothing, the call files nothing either, drops the draft and its values (`intake.abandoned`), and the
confirmation fails with `precondition_failed`. A call whose subject changed between that read and
the reservation is refused with `conflict`, to be confirmed again.

`exportSubject({workspaceId, subjectKey, kept?})` needs the `signer` adapter and returns:

```json
{
  "body": {
    "v": 1, "type": "subject_export", "exportId": "...", "workspaceId": "...", "subjectKey": "...", "issuedAt": "...",
    "intakeRecords": [{ "recordId": "...", "subjectKey": "...", "values": {}, "...": "..." }],
    "pinDigestOnFile": true,
    "consents": [{ "consentId": "...", "callId": "...", "subjectKey": "<64 hex>", "purpose": "...", "answer": "yes", "...": "..." }],
    "revocations": [{ "consentId": "...", "via": "text", "at": "..." }],
    "calls": ["..."],
    "ledgerEntries": [{ "seq": 12, "hash": "...", "event": "intake.confirmed", "callId": "..." }],
    "receipts": [{ "receiptId": "...", "callId": "..." }],
    "heldByHost": [{ "what": "subject record", "reason": "..." }],
    "kept": [{ "what": "ledger entries", "reason": "..." }],
    "limits": ["..."]
  },
  "alg": "ES256", "kid": "...", "signature": "<base64url of the 64-byte r||s signature>"
}
```

- `intakeRecords` are the subject's, values included; `pinDigestOnFile` says whether a digest is
  on file, never the digest.
- `calls` are the calls those records name. `consents` and `receipts` are the ones those call
  records hold (a call record that is gone is skipped). A consent carries the `subjectKey` Badge
  matched on the call when it was recorded (or null), and only those recorded under this subject
  are listed: a call can match another subject later, and their consents are not this subject's. A
  consent keeps its original answer; `revocations` holds the revocation the `ConsentStore` keeps for
  each listed consent (by `consentId`), so a yes since withdrawn reads as withdrawn. Without a
  `ConsentStore` nothing can be revoked and the list is empty.
- `ledgerEntries` are this workspace's entries (by the workspace in their `eventId`) whose
  `detail.recordId`, `detail.consentId` or `detail.receiptId` names one of the above: ids only.
- `heldByHost` lists the subject record, which is the host's data, and a PIN in the host's own
  PIN store (`verifier` mode), which the engine never reads or deletes. `kept` lists, with the reason,
  what an erase keeps: ledger entries and receipts (append-only and signed; they hold ids and
  digests, kept as integrity records for the retention period; an unkeyed SHA-256 of a short value
  can be confirmed by guessing), call records and consents, then each `{what, reason}` the business
  passes in `kept` (non-empty text, else `invalid_input`). `limits` says what the export cannot
  find, including a record filed on a call with no matched subject.
- The signature is ES256 over `"district-assurance/subject-export/v1\n" + canonicalJson(body)`.
  The signed bytes name the document type, so an export never verifies as a receipt (signed over
  `canonicalJson(body)`, which starts with `{`) and a receipt never as an export.
  `verifySubjectExport(exported, keys)` checks it as `verifyReceipt` checks a receipt.

`eraseSubject({workspaceId, subjectKey})` reads the ledger once. Each erasure of a subject is
numbered from 0, and its event ids are keyed (HMAC under the knowledge key) on the subject and that
number. If the subject's last erasure has a `subject.erased` entry but no
`subject.erasure_completed`, a delete failed part way: the erase carries out that entry's plan (the
same record ids, the PIN digest if the plan says so) and appends the completion, under the same
entry, whatever was already deleted. It then lists the subject's records and whether a PIN digest is
on file, after counting the erasure (`markSubjectErased`, first, so a filing reserved before it is
guarded whether or not the listing sees it). With neither, it does nothing more and returns
`{erased: false}` (or the finished erasure). Otherwise it drops each named call record's copy of the
last confirmed record (refused with `precondition_failed` while one of the subject's records is
still being filed on a call; a call record that is gone is skipped), appends `subject.erased` under
the next number, deletes the records and the PIN digest, then appends `subject.erasure_completed`. A
later erasure (for example of a PIN digest the host put back) gets an entry of its own; two erasures
at once append one plan, and both carry it out. It never changes or removes a ledger entry or a
receipt, so `verifyChain` and every receipt still verify. The listener is not told (the entry names
no call). Attempt counts live per call in the call record and, across calls, in the
`AttemptCounters` store (section 6). Every erase request, with nothing on file too, resets the
counters kept under the subject key: each installed factor's failures and lock notices, its hidden
duress count, flow starts, callbacks placed and the duress flag (a subject under duress is first
counted as cleared, as `clearDuress` does). The calling number's counters are not the subject's and
stay until their window passes.

## 27. Carrier webhooks

`verifyTwilioSignature` follows Twilio's published scheme: the `X-Twilio-Signature` header is
`base64(HMAC-SHA1(auth token, URL + parameters))`, where URL is the full URL Twilio requested,
query included, and parameters are the form parameters of the raw body, sorted by name (then by
value for a repeated name, in code-unit order; a name and value sent twice count once) and written
as name then value with no separator.
When the URL has a `bodySHA256` query parameter, the URL alone is signed and the hex SHA-256 of
the raw body must equal it (`body_hash_mismatch` otherwise). The URL is tried as given and with the
scheme's default port (443 or 80) added or removed; a URL with another port is also tried with
that port removed (Twilio drops it for HTTPS voice callbacks), and no port but the default is ever
added. The check
passes if any configured auth token matches. Refusals: `no_secret`, `missing_header`,
`no_matching_signature`, `body_hash_mismatch`. The scheme has no timestamp.

`verifyTelnyxSignature` follows Telnyx's published scheme: the `telnyx-signature-ed25519` header is
the base64 Ed25519 signature of `telnyx-timestamp + "|" + raw body`. Public keys are the base64 of
32 raw bytes; any other value is skipped, and so is a key on one of Ed25519's eight small-order
points (in any encoding), which some platforms let verify a forged signature. The check passes if
the signature verifies under any configured key and the timestamp is within 300 seconds of now
(configurable, an integer from 0 to 86,400, else `invalid_input`), either way; an invalid `now` is
out of tolerance. It returns the same `SignatureCheck` as Stripe's: `no_secret`, `missing_header`
(either header), `malformed_header` (a signature that is not 64 bytes of base64 in its one canonical
spelling, with the unused bits of its last character zero, or a timestamp that is not 1 to 12
digits), `timestamp_out_of_tolerance`, `no_matching_signature`.

The reference server answers `POST /webhooks/twilio` and `/webhooks/telnyx` with 400 `{error:
"signature", reason}` when the check fails, 200 `{received: true}` when it passes, and does nothing
else with the body: the engine takes no carrier event yet. The body is read and checked as the raw
bytes received, never decoded first (both functions take a `string` or a `Uint8Array`): a decoder
with replacement reads two different invalid UTF-8 bodies the same, and both would verify under one
signature. Twilio's form parameters are decoded from those bytes. Twilio's URL is the configured
public origin followed by the request target. A carrier with no key configured refuses everything.

## 28. The flow simulator

`district-assurance simulate <config.json> --flow <name> --script <name or file>` (the package's
`bin`; `npm run simulate -- ...` in this repository) runs one flow of a FlowConfig with a scripted
caller and prints what happens, so a business sees a flow before a real caller meets it. The source
is `src/cli/simulate.ts`.

- The engine is `createTestEngine`'s: the fixed clock, sequential ids, the in-memory adapters and a
  throwaway signing key. No network, no key, no environment.
- The config is refused, with every problem and exit code 1, when it turns on a module that is not
  built in (`badge`, `dossier`, `paylink`, `trace`, `gate`, `step-up`: an outside module's code is not
  there to run)
  or when `validateConfig` finds a problem; an outside module listed with `enabled: false` is left
  out. A flow the config does not have, or a script that is neither built in nor a valid file, is
  refused the same way. Bad arguments print the usage and exit 2. A flow that ran exits 0, whether
  it completed or failed. Every built-in step type and factor has a scripted caller. A step the
  simulator has no caller for (a type another module adds) prints `step <type> is not simulated`,
  and a `badge.verify` step that lists a factor plug-in prints `step badge.verify factor <kind> is
  not simulated`; either way the call ends there and the run exits 3, never guessing or skipping
  part of the step.
- The caller is made up: one subject on file with a 555 number, an answer for every keypad field
  and every spoken field (a value of the field's format) and a PIN of `minDigits` digits. It acts on
  whatever step the flow is on: at `badge.verify` it keys the account number, then each factor the
  step lists (keypad answers, the PIN, spoken answers, the carrier check, a texted code it asks for
  and keys, the photo ID link), then waits for the result. With `callback`, it asks to be called
  back once it has keyed: that call ends, whoever answers on the number on file keys the
  confirmation or not, and the caller goes on on the callback call (`call: the callback call
  <id>`), keying its entered factors again, right, for the rest of the flow. At `dossier.collect` it
  answers every field of the step's form with a sample value (a text answer cut to the field's
  `maxLength`) and confirms; at `paylink.request` it asks to pay and the provider reports the
  script's outcomes; at `trace.consent` it answers; at `gate.grant` the fake door, which answers as
  every controller the config's Gate targets name, opens or refuses; at `step-up.issue` it keys a
  sign-in code and the website exchanges the token, with the site's audience. A refusal by the engine is printed and the caller goes on. After the
  last step the call ends, abandoning a flow still running, and `flow: <status>` gives the status
  once the call has ended.
- A script is `{summary, wrongKeypad, wrongPins, carrier, photoId, consent, payment, textCode,
  spoken, callback, door}`: wrong keypad
  answers and wrong PINs before the right ones (0 to 5; after each wrong entry the caller waits out
  the wait Badge's `lockout` setting gives for the failures so far, and stops once locked out), the
  carrier's `identityMatch`, the photo ID outcome, the consent answer, and the payment outcome
  (`paid`; `paid_later`, completed unpaid then the asynchronous success; `failed`; `expired`), the
texted code keyed (`right` or `wrong`), how spoken answers are heard (`right` or `wrong`), the
callback (`confirmed` or `not_confirmed`) and the door (`opens` or `refuses`). A
  script file is a JSON object with any of these fields, checked field by field; the rest come from
  `pass`. Built in:

| Script | |
|---|---|
| `pass` | every answer right, the carrier matches, the photo ID is verified, consent yes, paid |
| `wrong-pin` | one wrong PIN and one wrong keypad answer, then the right ones |
| `lockout` | wrong PINs and keypad answers until the line stops judging them |
| `consent-no` | as `pass`, consent no |
| `payment-paid` | as `pass`, paid later: completed unpaid, then the asynchronous success |
| `payment-expired` | as `pass`, the link expires |
| `text-code-wrong` | as `pass`, a wrong texted code |
| `spoken-wrong` | as `pass`, spoken answers heard as another value |
| `callback-not-confirmed` | as `pass`, the callback answered without the confirmation |
| `door-refused` | as `pass`, the door's controller refuses the unlock |

Output, one line each: the headings `simulate:`, `script:`, `call:`, `step <n>/<count>: <type>
<fields>`, `flow: <status>` and `receipt:`; `  caller:` what the caller does, then `  decision:` the
engine's answer or `  refused:` its refusal; `    event <name> (<actor>) <detail>` for every ledger
entry, as it is appended. Then the signed receipt as JSON, checked against the engine's key set, or
`receipt: none`. Nothing the caller keys or says is printed (no texted code, sign-in code or transcript either): events carry no values (section 9) and
decisions say right or wrong, never the digits. A config and a script file are someone else's
text, so every line, on standard output and standard error, writes C0 and C1 control characters
and bidi controls and marks as `\u` escapes (`terminalSafe`): a file can never move the cursor,
set the terminal's title or make one result read as another.

## 29. Reference server limits and logs

`examples/reference-server/src/app.ts`, not part of the package. Every limit below, the timeout and
each body limit is a whole number from 1 (the timeout at most 2,147,483,647 ms, what `setTimeout`
can wait); anything else throws when the server is created, since 0 or NaN would switch a limit
off. Each request is handled in this order, and every refusal is JSON `{"error": code}` (an upload
page refusal is its HTML page):

- **Rate limit**, first, before any other work: each caller, from the socket's address (an IPv6
  address counts by its /64, an IPv4-mapped one such as `::ffff:192.0.2.1` as its IPv4 address),
  gets `rateLimit.requests` requests per fixed window of `rateLimit.windowMs` (default 300 a
  minute), counted on `rateLimit.clock`, the system clock by default and never the server's
  `clock`, which the demo fixes. Every request counts, whatever its route or answer. Over the limit:
  `429 rate_limited` with `Retry-After` in whole seconds to the window's end. `X-Forwarded-For` is
  never read. At most `rateLimit.addresses` addresses are tracked (default 10,000); to make room,
  ended windows are dropped first, then the oldest.
- **Body limits** per route: `stripeIdentity`, `stripePayments`, `stripeConnect`, `records`,
  `twilio` and `telnyx` 64 KiB each, `demo` 1 KiB (`bodyLimits` overrides each). An upload
  (`POST /u/:token`) is limited by its own link's size cap plus 16 KiB of multipart overhead. A
  declared `Content-Length` over the limit is refused before a byte is read; a streamed body is cut
  off once it passes the limit. Either way: `413 body_too_large` (the upload page's "too large" for
  an upload). The other routes never read a body.
- **Timeouts**, `timeoutMs` (default 10 seconds): a request whose headers and body are not all
  received in time gets `408 request_timeout` and the connection is closed; a request not answered
  within `timeoutMs` of its headers gets `503 timeout`.
- **Requests node:http cannot read** are refused by the server's `clientError` handler, also in
  JSON and with `Connection: close`: too slow `408 request_timeout`, headers too large
  `431 headers_too_large`, chunk extensions too large `413 body_too_large`, anything else
  malformed `400 bad_request`. A reset connection, or one whose answer is already written, gets
  nothing more and is closed. A malformed request sent right behind a body drained after its
  answer is the next request, and is answered and logged as one. When earlier pipelined requests
  on the connection are still being answered, the refusal waits until each of their answers is
  sent or its socket closes, so it is never read as theirs, and it is sent once.
- **Abandoned requests**: a request whose connection closes before its answer is sent (the client
  reset it or left) is abandoned: neither its handler nor the deadline answers or logs it later.
- **Logs**: with `log`, one entry per answered request, after the answer is written, including the
  refusals above: `{time, address, method, route, status, error?, ms}`. `time` is from the
  server's clock; `address` is the caller the rate limit counts (an IPv6 /64, never the whole
  address); `method` is `unknown` when the request was refused before its headers were read;
  `route` is the matched pattern (`/r/:token`, `/r/:token.json`, `/u/:token`,
  `/webhooks/stripe/connect`, `/.well-known/security.txt`, `/demo/runs/:runId/next`) or
  `unmatched`, never the path as sent, so no call id, run id or link token reaches a log; `error`
  is a JSON answer's error code. An entry holds no header, query string or body. A `log` that
  throws, or answers a promise that rejects, loses that entry; the server and the answer are
  unaffected. `jsonLinesLog(stream)` writes each entry as one line of JSON on `stream` and never
  holds more than the stream's own buffer: while `write` answers false, each new entry is dropped
  and counted, and on `drain` one line says how many were
  (`{"warning":"log_entries_dropped","dropped":n}`); a request never waits on the log. Its `stop()`
  writes nothing more. `logJsonLines` is that log on standard output, and `npm run serve`
  (`createServe`) uses it unless given its own `log`; `main.ts` registers `guardLogStream`, an
  `error` listener on standard output that stops the log on the first error (an EPIPE when its
  reader went away), instead of the process ending on an unhandled `error` event.

## 30. The published package

The package has four entry points and no others: `district-assurance`, `district-assurance/testing`,
`district-assurance/package.json` and `district-assurance/schema/flow-config.v1.json` (the FlowConfig
JSON Schema, section 7); any other path is refused by Node. The tarball holds the compiled `dist/`
(JavaScript and declarations), the schema and the documents `files` names. It is not on npm:
`package.json` is `"private": true` until a release is decided (ADR-12). A release is a version tag
`vX.Y.Z` matching `package.json`, run by `.github/workflows/release.yml`: the CI workflow and the
supply-chain checks on the tag, two builds that must pack to the same bytes, a check of the file
list, and a smoke test that unpacks the tarball into an empty project, imports each entry point
and type-checks a strict consumer. The tagged commit must be on main. A tag push is always a dry
run. Only a manual run on the tag with `publish` ticked, in this repository and after the
`npm-publish` environment's reviewers approve, publishes that tarball with npm provenance. A
version with a pre-release part goes to the `next` dist-tag. In a fork, or a manual run without
`publish`, the same run is a dry run.
