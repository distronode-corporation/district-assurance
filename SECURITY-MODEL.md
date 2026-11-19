# Security model

What the engine protects, what it trusts, the threats it is designed against, and what it leaves
to the host. Pre-alpha: these are design intentions backed by tests where marked, not an audited
claim.

## Assets

- The organisation's reference values (account numbers, dates of birth and similar) and PINs.
- What a verified caller may do: read status, file a record, request a payment, change contact
  or payout details.
- Card data, which the engine must never receive.
- Doors and other access: what a verified caller may open, and when.
- Web sign-ins a verified call steps up, and for whom.
- Whose account a payment lands on (the business's, or the platform's).
- The record of what happened on a call: the ledger and the receipts.
- The workspace's FlowConfig: which modules run, which factors count, which scopes a flow grants.

## Trusted and untrusted

| Trusted | Untrusted |
|---|---|
| The host's code paths that call the engine | Everything the caller says |
| The adapters the host plugs in (the callback dialer's report included) | Everything the model says or proposes |
| The knowledge key, the receipt signing key, the access signing key and the step-up signing key | Caller ID and any number given on the call |
| The clock and id source | Webhook bodies until their signature verifies |
| The outside modules the host installs | Text from business endpoints, CRMs and documents |
| The door controllers and relays the host configures | A door relay's answer, beyond "took it", "refused" or "lost" |
| The SessionStore's compare-and-set | A FlowConfig until `validateConfig` passes |

## Threats and controls

### Social engineering of the AI

"I'm calling for my mother", urgency, authority, partial answers. **Control:** the model has no
path to a factor, a level or a grant. Scoped actions are refused by `authorize` until code issued
a grant (tested in `engine.test.ts`, "Engine authorize"). The host speaks fixed lines on refusals.
The adversarial suite (`test/adversarial/`, SPEC.md section 19) runs scripted dialogues in English
and Canadian French (urgency, authority, "skip it", partial answers, account probing, text
flooding, injection in business data) through a scripted host in `npm test`, and checks after
every turn that no grant comes without factors, no text goes out before a match, an unknown
account answers like a wrong answer, and a tainted session holds no grant (tested). A new tactic
or a newly built factor fails the suite until it has scripts in both languages. Texted codes get
their scripts with VER-2; until then the suite floods with photo ID and payment links.

### Account probing

Trying account numbers to learn which exist, or learning which factor failed. **Controls:** all
keypad fields are judged together and give one answer; an unknown account, a wrong value and a
non-keypad entry give the same result and the same ledger detail (tested), and the same holds for
the PIN: an unknown subject, a subject with no PIN and a malformed entry do the same keyed-hash work
and answer the same (tested), and for spoken answers: an unknown subject, a wrong answer and an
unusable transcript give the same result and the same ledger detail (tested); every field is
compared even after a mismatch; nothing reads back a value on file; links go out only after a
match, so a text never confirms an account. Failures are counted across calls per subject key, for
unknown subjects too, so a lock never tells a real account from a made-up one (tested), and per
calling number, so one line trying account after account is locked out (tested).

### Guessing

**Controls:** a per-call limit on judged attempts for every factor the caller enters (keypad
knowledge, the PIN at 1 to 5, spoken answers at 1 to 5, plug-ins at 1 to 5), after which the line
stops judging, even the right answer (tested). An unusable spoken answer is still an attempt
(tested). Each attempt is counted in its own write before it is judged, so a crash, a
failing PIN verifier or knowledge key store, an entry crafted to make a judge throw, or a second
process never gives a free try (tested, two engines on one
store). PINs are at least 4 digits, and keypad attempts are capped at 5 per call like the PIN's.
Across calls (VER-1), every entered factor is counted per subject and per calling number in an
`AttemptCounters` store all engines share: a wait after each failure (5, 15, 60, 300, then 900
seconds) and a hard lock after 10 failures in 24 hours; a config can make these stricter, never
looser (tested). The failure is recorded before the entry is judged, like the call's attempt, so a
crash, a failing verifier or a second process never gives a free try; the counters are read before
the attempt, and an attempt that finds a lock another engine just set is refused unjudged (tested,
two engines racing). A locked line answers `locked` even to the right PIN, on any call and either
engine, until the window passes or a member of the business lifts the lock with `unlock`
(INT-7, below), which clears that one counter entirely (tested). A pass resets the subject's
counter but takes only its own failure off the number's: a line's failures against other accounts
stay through a pass on its own account, so alternating with that pass does not escape the lock per
calling number (tested). Taking it off is one atomic step of the store
(`removeFailure`), so a failure another call records on the same number meanwhile is never lost
(tested, two engines). Only a member's `unlock`
clears a number's counter outright, failures against other accounts included, so that is the
business's deliberate act, recorded in the ledger.

Lockout alerts (INT-7): after a `verification.locked` entry is written, the host's `Notifier` is
told the counter (the subject key, or the keyed hash of the calling number), the factor kind and
when the lock ends, never a value or a phone number (tested). A notice is told once per lock,
across engines, and a workspace gets at most 20 an hour of hard locks and, apart, 20 of waits
after a failure, the last of each marked `capped`, so an attack locking subject after subject cannot
flood the owner, and waits, which come cheap, cannot use up the hard locks' notices to hide one
(tested); every lock stays in the ledger (tested). The
notifier is best effort and never awaited: one that throws, rejects or hangs never blocks the call
or the ledger (tested). `unlock` is a host call with no call id, so no call path reaches it; it
clears one counter (one factor kind, one scope, one key) and nothing else, writes
`verification.unlocked` with the member's opaque id and the counter as a keyed digest (never the
key) before clearing, and grants nothing: the caller still
verifies from no factors (tested). An unlock gives whoever is calling a fresh set of tries on
that counter, so who may make it is the host's. Without this, a
4-digit PIN with 3 attempts per call fell within about 3,300 calls; now an attacker gets at most
10 guesses per subject per 24 hours, about 3,650 a year against 10,000 PINs, so a 4-digit PIN
still needs watching (`verification.locked` in the ledger) and a longer PIN where the risk is
high. In `verifier` mode the host's PIN store is asked for every attempt, with a stand-in for a
malformed entry, so timing does not tell them apart. A PIN a caller chooses (`enrolPin`) is refused when every digit is the same, when it is
a run (1234, 4321, 7890), or when it equals the account number or any keypad knowledge on file,
with one answer (`weak`) for all three, so a try never says which value is on file (tested).

### PIN enrolment and reset

A caller who passed weaker checks choosing or replacing a PIN, which would then stand for them on
every later call. **Controls:** `enrolPin` needs a grant at level 2 or above from the same call,
which always includes a factor that is not knowledge, on an open call outside any flow; tries are
counted before they are judged and limited to the PIN's attempts per call; the PIN is keyed twice
and the two digests compared in constant time; only a subject with no PIN on file can enrol, so a
caller can never replace a PIN: changing one is `resetPin`, a host call from the business's own
tools (tested). The store writes a digest only if none is on file, in one atomic step, so of two
enrolments at once one wins and the other is refused without replacing it, and a retry of the loser
is refused too, even when its take-back write failed, because a retry finishes only an enrolment
whose id, stored with the digest, is the retrying call's own; whichever try stored the PIN writes
`pin.enrolled`, once, even when two tries on one
call race or the session write after the store's fails on the call's last try (tested). The PIN factor
reads both digests (the PIN's and the duress PIN's) from the store on every attempt, so after a
reset or a removed duress PIN the old one fails even on a call that began verification before it
(tested). In `verifier` mode the engine never enrols. `pin.enrolled` and `pin.reset` carry no
digits (tested). Who may call `resetPin`, and how the business confirms the request first, is the
host's (left to the host).

### Spoken answers

A postal code or a reference said aloud is heard by speech-to-text, can reach the model and the
transcript, and is known to more people than a keypad value. A misrecognised transcript must never
be read loosely into a pass. **Controls:** `normaliseSpokenAnswer` is exact: a fixed vocabulary per
language, a fixed format per field, and anything else is `unusable`, never a near match (a corpus of
English and French transcripts, misrecognitions included, is tested). **Limit:** the engine sees
only the transcript, not what the caller said. At level 1 a spoken answer is accepted when its
transcript is the stored value in the field's format; if speech-to-text turns a wrong answer into
the stored value, the engine cannot tell and the factor passes. Speech-to-text accuracy is outside
this engine and belongs to the host's speech handling. The engine offers no host control for such
a substitution; a host that needs one must provide it (for example, reading the value back for the
caller to confirm, or requiring another factor), or keep spoken answers off. The value is compared
like a keypad field, as a keyed digest in constant time, and never stored or logged. A spoken answer counts on
its own only at level 1; above it, the policy needs another factor that is not knowledge
(tested). A spoken match does not unlock texts to the number on file (tested). A policy without
spoken fields never judges one (tested). Left to the host: passing the caller's answer from its
speech pipeline in a code path, never through the model, and keeping it out of stored transcripts.

### Moving between flows

Limits that reset between flows could be dodged by moving between them: an owner command, then a
payment, then a door. **Controls (VER-15):** the counters are keyed by subject or calling-number
hash and factor kind, never by flow or call, and no setting separates them, so failures in one
flow count in every other (tested). Flows that need a money, contact or access scope are also
limited per hour, whatever their outcome: 10 starts per calling number and, once verification
names a subject, 5 per subject, as defaults a config can only lower (tested, a changed or withheld
calling number does not lift the subject limit, and separate subjects stay separate). A refused
start gives the host one answer, `rate_limited`, whichever limit was hit, and writes
`flow.rate_limited` with the scope of the limit, never a value. Caller ID can be spoofed, so the
per-number limit can lock out the real owner of a number for up to an hour: an attacker who
spoofs a victim's number can spend its starts. The per-subject limit is the one that holds; the
per-number one is a backstop against one line trying subject after subject. The subject's limit
is counted for any account number keyed, real or not, so a caller who keys numbers at random learns
nothing from it; one who keys a real account soon after that account's own five limited flows in
the hour is refused, which says only that the account was busy, never its details. Lifting either
early is the host's (`AttemptCounters.reset` on the `flow.start` counter); a pass never lifts a
start limit, since it forgets only the failures of its own factor kind (`forgetPass`, tested).

### Coercion (duress PIN)

An owner made to call under pressure, with the person forcing them listening beside them.
**Controls (VER-12, off unless Badge's `pin.duress` is set):** the business enrols a second,
duress PIN for the subject with a host call, never a caller one, stored as its own keyed digest
and refused when it equals the PIN, the account number or any keypad knowledge (tested). Every PIN
entry is compared with both digests, whether or not a duress PIN is on file, so the work, the time
and the answer are the same (tested). A duress entry gets the same answer, level, grant, events
and receipt as the PIN (tested); the duress state is kept only in the call record. On that call
`authorize` refuses every money, contact and access scope and the scopes the business lists in
`refuseScopes` (for example `owner.command`), with the same `false` as a scope with no grant
(tested). Every duress entry owes an alert, written in the same write as the entry, and recorded
against the call even if verification restarted or the call ended while it was judged (tested).
The engine sends it to the host's `DuressNotifier` after that write, off the caller's response path
(so a slow notifier delays nothing the caller hears), even when the ledger append fails (tested),
and keeps it owed until `notify` resolves: the call's next write, `flushLedger` and the host's sweep
`deliverDuressAlerts` retry it, at least once by `alertId`, which the call's id and entry number
make unique across engines (tested); after a crash `sweepAlerts` finds every call that still owes
one without knowing its id (tested). A notifier that fails changes
nothing on the call (tested). `putDuressDigest` stores only while the PIN checked against is still on
file, so a reset and a new PIN meanwhile can never make the duress PIN equal the PIN (tested); a
reset removes the PIN and the duress PIN in one store step, so it never removes a duress PIN
enrolled against a newer PIN (tested); and an entry that matches both, on an imported subject or in
the host's verifier's answer, or any entry on a subject whose two digests are equal, is refused like
a wrong PIN, neither a login nor an alarm (tested). A duress entry flags its subject until the
business clears it (`clearDuress`, written to the ledger with an opaque member id and a keyed
digest of the subject, so neither the ledger nor an export shows who was under duress): every
later pass on the subject, on any call, is a duress entry, refused the same scopes, and alerted
once a call (tested). The flag holds after a config turns the duress PIN off, refusing every scope
(tested); a lost write of the flag is made good when the entry's alert is delivered, never over a
clearing that came after the entry (tested), though a clearing that lands during that delivery may
need repeating; a duress PIN entry whose own write fails still flags its subject (tested); a clearing that lands while a pass is judged stays
cleared (tested). A duress
entry resets the visible counters as any pass does, but the subject's failures are also counted
where only a pass not under duress resets them, and their hard lock holds: an attacker who knows
the duress PIN gets no more guesses at the real PIN than one who does not, and the real PIN, when
it passes, alerts (tested, 20 wrong guesses between duress entries over 10 calls). Every PIN ledger entry carries a
`tag` keyed to its event id and outcome, and the event ids of a duress call run as a normal call's
(an alert's acknowledgement is not counted), so only the holder of the knowledge key can tell a
duress pass from a normal one (tested); enrolling or removing a duress PIN writes nothing to the ledger.
A PIN reset removes the duress PIN too.

**Limits.** It does not stop someone who knows both PINs, or who makes the owner say which is
which. The code is public, so an attacker can learn exactly how a duress call behaves. A refused
action can itself be noticed by someone watching: the host speaks the same fixed line it uses for
any scope without a grant, but a payment that never happens is still visible. The notifier is best
effort; who it alerts, and how fast, is the host's. Anything the host sends after the call (PRV-10)
must follow the same rule as on a normal call, or it gives the duress away.

### SIM swap and port-out

An attacker who took over the number on file receives the texted code or link. **Controls:** a
carrier answer makes a texted code count only when it covered SIM changes (`simSwapChecked`) and
reported no SIM change inside the policy window (72 hours by default), and no port inside it when
it reports ports; an answer that did not cover SIM changes never makes one count, whatever the
policy says (tested). Without a carrier answer, a texted code counts only when the policy allows
it (`trustTextCodeWithoutCarrierCheck`, off by default). Gap: a report with no port age (Twilio
gives none) is not checked for ports, so a port-out that the carrier does not show as a SIM change
is not caught by this rule. A texted code is never a factor alone, and level 3 requires a photo ID plus
selfie, which a stolen SIM alone does not pass. Contact and payout scopes default to level 3.
A callback (VER-9) has the same weaknesses and the same controls: the policy refuses it alone or
with only a texted code, the carrier rule discounts it, and level 3 still needs photo ID (tested).

### Spoofed caller ID and the callback

Caller ID can be spoofed, so it is never a factor. A callback rings the number on file, whatever
number the first call came from. **Controls:** the first call is ended, never held, and never
gains a level, a factor or a grant from the callback (tested). The callback is its own call, for
the subject the first call matched (not a factor), and `callback` is recorded there only when the
dialer reports that the number on file answered and the person keyed the confirmation: keys, not
speech, so voicemail or an answering machine never passes (tested). It is possession of the line
only, so the callback call needs a PIN or keypad match too, under the policy. The number rung is
read from the store when it is dialed and on every retry, so a number the business changed (after
a SIM swap is reported, say) is never bypassed by a copy taken earlier (tested). A request is
refused without a keypad or PIN match or a number on file, or on a call untrusted content entered,
and a refused request returns the same and ends the first call the same way as a placed one, as
does a placed one whose dial failed, so neither a caller nor the code asking can tell them apart;
only the ledger says which (tested). Left to the host: call forwarding and someone else answering the line on file, which
the carrier rule does not see.

The reference carrier adapters (Twilio Lookup, Telnyx Number Lookup) fail closed: a timeout, an
error, a country outside their allow-list, a feature the account is not approved for or an answer
they cannot read gives `checked: false`, never an exception into the call; a SIM change or port
without a usable time counts as just now, Twilio's `swapped_period` (the window it looked at) is
only a lower bound when it reports no change inside it, and hours are rounded down (tested against
replayed responses). They refuse a plain-http `baseUrl` other than loopback, so credentials never
cross a network in clear text (plain http to a loopback host, for a local fake, stays on the host
but is still unencrypted). Their failure reports carry the vendor's status and error code, never the number or
the identity on file. Telnyx reports no SIM change, so its report says `simSwapChecked: false` and a
texted code never counts on it (tested); a host that turns texted codes on (VER-2) takes the SIM
swap signal from Twilio. Twilio Identity Match sends the identity on file to Twilio, in the
request's query string. Twilio Lookup reports no port age, so on Twilio a texted
code or a callback counts without a port check: a port-out with no SIM change Twilio detects is not
seen (Sean, 2026-11-19). A host that needs ports checked for high levels uses a port-aware lookup
(Telnyx's port date beside Twilio's SIM swap, for example) or requires another factor there.

### Text flooding and SMS pumping

Repeated calls triggering texts to a real customer, or to premium numbers. **Controls:** texts go
only to the number on file, only after a keypad or PIN match, and at most one photo ID link per
call (tested). Texted codes go only to the country calling codes the policy lists, none without a
list (tested); at most 5 per subject and 10 per calling number in 24 hours, 60 seconds apart,
counted across calls and engines in the shared `CodeStore` before the text goes out (tested). A
refused send answers exactly like a sent one, with a code that never matches and the same tries
and expiry, and in the same steps: the answer never waits for the SMS adapter, which runs after the
reply, so its time cannot tell a sent code from a refused one (tested). The line never tells a
caller that a limit was hit or which one (tested); the ledger says why. A withheld calling number
is held to the per-subject limit only. One-time access codes count against the same per-subject
limit in the same `CodeStore`, so the two share a budget; a limited request texts nothing
(tested). Callbacks ring a real customer's line, so they are limited too: one per call, only after
a keypad or PIN match, at most 3 placed per subject in 24 hours on any call or engine, and each
counted as a failure before it is dialed, under the subject and the first call's calling number, so
failed callbacks bring the same waits and hard lock as wrong PINs (tested, including two requests
racing for the last one).

### Guessing a texted code

**Controls:** 6 digits, 5 tries per code (a malformed entry is one), 10 minutes, used once, bound
to the call by its HMAC (the same digits on another call fail) and dropped on a taint or a change
of subject (tested). With the send limit, a subject faces at most 25 tries a day, a chance of
about 1 in 40,000.

### Replay

Replayed webhooks, reused links, replayed tones. **Controls:** Stripe signatures are checked with a
300-second window and constant-time comparison (tested); the reference server applies each event
id once while it remembers it, 4 days and 10,000 ids at most so a flood of events cannot exhaust
its memory (tested); the engine applies each identity session and each payment settlement once (tested).
Identity links are single-use by the provider. The reference server's Stripe Identity adapter
sends the engine's idempotency key with every create, so a retried `startPhotoId` gets the same
session and link, never a second one (tested against a local fake). It never logs the link, and its
errors carry a status and Stripe's error type and code only, never the link, the key or Stripe's
message (tested). It takes a restricted key only, never a secret key, and `npm run serve` takes a
test-mode one only (tested); the key comes from the environment. It refuses an API base
that is not `https:`, except `http:` on a loopback host for a local fake, so the key never crosses a
network in cleartext (tested). Left to the host: whether keypad tones arrive as
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
problem, Trace (the ledger) cannot be turned off, the floors cannot be lowered (`entry.open` is
an access scope, never below level 2), planned factors cannot be turned on, a payment link can
offer only instant methods and live 5 to 60 minutes, connect mode cannot run without a connected
account, and every call's ledger entries carry the config revision
it ran under. Every grant, its `verification.finished` and `grant.issued` entries and the signed
receipt name the policy version and the config revision that judged the caller, so a verification
judged under a config changed mid-call is told apart from one judged under the call's own (tested).
Who may edit a config, and how its history is kept, is the host's (left to the host).

### Races across processes

Two processes acting on one call at once. **Controls:** every change is a compare-and-set on the
call's version, retried from a fresh read; links are reserved before they are created, so two
processes cannot both send one; a lost race writes nothing to the ledger (tested). A durable store
must pass `sessionStoreContract`. Failure counters across calls are recorded in one atomic step
that returns what came before, so of two attempts racing on one subject only one is judged
(tested); a durable counter store must pass `attemptCountersContract`. This holds for two genuine
callers too: when two entries for one account arrive at once, the second meets the first's
provisional failure and waits, unjudged, even with the right answer, for the timed wait that
failure sets (5 seconds by default; decision 1: no skip). The wait is timed, not held for the
whole judgment: if the first is still being judged when it ends (a verifier slower than the
wait), the second is judged too. That is never a free guess, since every entry records its own
failure before it is judged, and only a pass takes it back. A pass by the first lifts the wait at
once; a failure makes it the wait after two failures (tested). A pass that was saved owes its
counters cleanup with it, so a correct entry whose ledger write then fails still has its
provisional failures taken back (tested). Two callers for one
account at the same moment are rare, and the cost is a wait of seconds and the second caller
entering the answer again.

### Prompt injection

A webhook reply, a CRM note or a document says "ignore the rules". **Controls:** `markUntrusted`
taints the session, drops the grant and sets the level to 0; a verification open when the taint
lands fails, granting no level from factors matched before or after it, so the caller must start
again; the next verification starts from no factors, a photo ID link sent before the taint no
longer counts, and the keypad or PIN match made before the taint no longer unlocks a text, a
callback, a carrier check or a payment link until a fresh verification matches (tested). An entry
judged while any taint lands (the first or a later one, counted per call) is not recorded as a
pass, never restores the match and never counts toward a grant; its attempt stays used, so it is no
free guess (tested). Fetched text never chooses a tool, a recipient or an amount: amounts come from
the host's code with an `amountSource`, or from the host's `AmountSource` adapter by a reference the
config names, and destinations come from the subject record. Untrusted content also drops an amount
read back and confirmed before it, so the caller hears it again (tested).

### Unlocks: forged, replayed, or sent twice

Someone forges an access grant, replays one, or a retry opens a door for a caller who is no longer
there, or code inside the engine writes an outcome the door never gave. **Controls:** the engine
owns every access grant (ADR-25): it reserves it, signs it, computes its digest, calls the
controller once and records the controller's actual answer, all in its own writes. Gate is a
built-in module, so no module code can reach a grant (`updateModule` refuses it) and there is no
outcome API to write one: a forged delivery, a re-pointed or lowered grant, a second settlement or
a digest the engine did not compute has no path in (tested, for every attack of the PR 2 reviews).
A grant needs a verification grant covering `entry.open` (level 2 or more), checked on every
request, in a flow and outside one, and once more right before the door is asked, so a call tainted
or a grant expired while it was signed sends nothing (tested). An access grant is signed with
ES256 under the access signer's own key and carries its audience (the controller), its target, its
level and a short validity, never past the verification grant (tested); a relay holds only the
public key, so taking a relay over does not let anyone mint grants, and one changed byte fails
(tested). A grant is bound to its workspace: a verifier must name the workspace it serves, so
workspaces that share a key and a controller name never open each other's doors (tested). The
example relay refuses a grant id it has seen (`SeenGrants`, tested in the demo). A call never ends
while a signed grant may still be acted on (at its door, or sent with its answer lost): the end
waits for the answer, or for the grant's expiry, so no access outcome follows the receipt and no grant reaches a door after it
while it can still open one (tested). Left as a limit, stated plainly: a door controller that does
not check a grant's expiry could act on a request delayed past it, after the call ended; the relay
contract requires the check, and the record would then say `unknown`, never `delivered`. The access
signer must be its own key (refused when it is the receipt signer's), and a host's module can never
take Gate's name, even after Gate was removed (tested). Outside modules' `updateModule` is held by the engine to their manifest's
scopes on every call, outside a flow too (tested).
**An unlock is never retried:** one grant in flight per call, sent once, no redirects followed;
a lost answer (a timeout, a dropped connection, a 5xx) is recorded as `unknown`, and opening again
is a fresh request with a new grant, up to `maxGrantsPerCall` (tested). The answer is recorded
even if the caller's grant expired while the door answered (tested); one that arrives after the
call ended is not (the grant was settled `unknown` at the end). The ledger
holds each grant's digest and outcome, never the grant. The Seam adapter (`seamAccessController`)
keeps the same rule: Seam documents no idempotency key on unlock, so it sends the unlock once and
never again, only after Seam says the device can unlock remotely, and only while the grant has at
least the request timeout left (which bounds the send and the client's wait, not the network);
every request stays on the configured host (tested); any failure
before the unlock is `refused` (nothing was sent), a lost or unreadable answer to the unlock, or an
attempt Seam reports failed, is `unknown`, and `confirmed` only when Seam reports that the device
confirmed the unlock (tested against a local server replaying Seam's answers). Its API key goes only in the
authorization header, never into a result, an error or the ledger (tested). Seam itself is
trusted to unlock only the device it was asked to, as any controller is, and to act on an attempt
promptly: an attempt still pending at Seam when its grant expires may move the lock later. Left to
the host: a relay that keeps seen
grant ids across restarts (or refuses every grant for 15 minutes plus the verifier's clock skew
after one), a relay clock kept in sync with the engine's (a grant's expiry is strict, so a relay
running behind accepts it that much longer), and the door's own safety
holds each grant's digest and outcome, never the grant.
**Direct vendor adapters** (Kisi, Verkada) are weaker on one point: the vendor cannot check the
signed grant, so the vendor's API key opens the door on its own, and whoever holds it can open
every door it reaches. The adapter sends nothing for a target its grant does not name or that is
not the vendor's id format, nor for a grant with less than its timeout left (so the client never
sends, or waits on, an unlock past the grant's expiry; a request delayed in the network could
still arrive later, since neither vendor's request carries a deadline), keeps every request on
the configured host (a base path starting with `//` cannot redirect the key, tested), keeps the API
key out of errors, sends the unlock once (never retried, no redirects; a lost answer is
`unknown`), and passes on only the HTTP status of a refusal, never the vendor's text (tested
against a local fake server). Verkada's short-lived token is fetched for each unlock and never
kept; a failed token call refuses, since no unlock was sent (tested). Left to the host: a relay
that keeps seen grant ids across restarts (or refuses every grant for 15 minutes plus the
verifier's clock skew after one), a relay clock kept in sync with the engine's (a grant's expiry
is strict, so a relay running behind accepts it that much longer), keeping a vendor API key in its
key store, scoped to as few doors as the vendor allows (a Kisi user or a Verkada key with door
access to those doors only), and the door's own safety
(an unlock pulse, not a latch).

### One-time access codes: stolen, guessed or reused

Someone reads a code store, guesses a code at the keypad, uses a code twice or at another door, or
has a code sent to a number they hold. **Controls:** a code is issued only through Gate's grant
path, so every control above holds (`entry.open` at level 2 or more, checked again before the
text, one in flight, the per-call limit, the ledger) and it lives no longer than its access grant
(at most 15 minutes, never past the verification grant) (tested). It is texted only to the number
on file of the subject Badge matched by keypad or PIN, never the calling number (tested). The
engine stores only an HMAC of the code under the codes' own key, bound to the workspace, the
controller and the door, with the unsigned grant body: a stolen store yields neither a code nor a
grant a relay accepts (tested). Redeeming removes the code in the same step (single use), refuses
it at another door, in another workspace, or after the grant's expiry, and answers the same for
every refusal (tested); `revoke` removes a code early. The code is never in the ledger, an event,
an error or the store (tested). A text that fails takes its code back, and its grant is `refused` only when that proves the
code unused, else `unknown`, since the text may have arrived (tested). A signer that fails at
redemption leaves the code redeemable, and a code is taken only after it is signed (tested). 8 digits give one
chance in 100 million per live code per guess, and 5 wrong guesses at a door (configurable, 1 to
10) spend every code live there, recorded as `access.code_spent` without the guess (tested). The
trade-off: someone at the keypad can spend the codes of a door with a few wrong guesses, and the
caller then asks for a new one. A `newCode` that is not exactly 8 digits fails the issue before
anything is stored (tested). Left to the host: a keypad that slows after wrong entries, a durable
`AccessCodeStore` whose `take` and `miss` are atomic across processes, and
keeping the codes' key in a key store. A code's grant is `delivered` once texted, so the call can
end and its receipt be issued while the code is still live: unlike a relay grant, it may open the
door after the receipt, until its expiry, and that redemption is not in the call's ledger (the
host revokes a code it no longer wants, and logs redemptions at the door). A code is texted only
to the call whose in-flight grant has the digest the engine recorded, never one matched on its
grant id alone (tested).
### Web sign-in step-up: stolen, replayed or misdirected tokens

Someone replays a step-up token, uses one meant for another person or site, or keeps using one
after the call turned untrusted. **Controls:** a token is issued only with a verification grant
covering `entry.sign_in` (level 2 or more), checked by the engine on every request and once more
after signing, so a call tainted, verified again, ended or expired while it was signed gets
nothing (tested). Step-up is built in (ADR-25): the engine issues every token and records its
exchange, and no module code can write a token or its outcome (tested). It is an ES256 JWT under
its own key (`stepUpSigner`), which the engine refuses to share with the receipt or access signer,
by key id or key material (tested); it lives 2 to 5 minutes and never past the verification grant
(tested). It is bound to the site's audience, to
the subject the verification grant was issued for (never one the host or the model names, and
none while a new verification runs), to the grant itself and to the nonce the site showed
(tested). The web sign-in exchanges it through the engine, which accepts only the exact bytes the
call issued, once: the exchange settles the token in the engine's own write, so a second one is
refused, on any process (tested). An exchange after the call was tainted, while a new verification runs on it, after the call was verified again,
after expiry, or for another site, subject or nonce is refused and uses the token up; a forged or
altered token is refused without using up the real one (tested). The ledger holds the token's
digest and outcome, never the token, the nonce or the subject handle, and the call record keeps
no nonce (tested). `sub` is a handle per site, so a `sub` alone cannot link one person across sites (tested); `sid` (the call) and `grant` are the same in every token of one call, so two sites given tokens from the same call can link those tokens.
Hanging up never revives a token: the write that ends the call refuses every issued token whose
call is tainted, has a new verification running or no longer holds the token's grant (verified
again, as that subject or another), since the ended call holds no grant to judge it by later
(tested). Only a token for the grant the call still holds as it ends stays exchangeable, until it
expires (at most 5 minutes; whether it should is a pending decision), its exchange written before
or after `receipt.issued` and never changing the receipt; the receipt lists the call's tokens as the end left them
(tested). A refused exchange is final, so anyone holding a token can use it up with a wrong nonce
and deny that one sign-in (it starts again with a new nonce); a guessed nonce never gets a second
try (tested). Published key sets carry only public key members, whatever a signer returns
(tested).
Left to the host: exchanging every token through the engine (checking the JWS against the JWKS
alone gives neither the single use nor the refusal after taint), handing the token only to the
browser session that showed the nonce, a nonce of at least 6 digits that lives no longer than
the token, and the words the caller hears before keying it ("you are signing in to ... on the
web"), since a person can be talked into keying someone else's nonce.

### Wrong or surprise amounts

A link for an amount the caller never agreed to: a mistyped price, a business endpoint that
answers wrong, or a request changed between what was said and what was sent. **Controls:** no
link is texted, for a fixed amount or one from the `AmountSource` adapter, until code has read the
amount back in the caller's language and the caller confirmed that exact read-back, bound by its
digest (tested). An amount from the adapter is checked like any amount (a positive integer, a
lower-case currency, under the limit). The link must be for the request read back and is for the
amount the caller heard; a different request, a stale digest or an unconfirmed read-back is
refused (tested). A read-back is bound to the subject the lookup was for: a lookup that finishes
after another subject was matched is refused, and so is a link for a read-back made for another
subject (tested). The ledger records the read-back and the confirmation, with the amount and the
digest but never the reference. Left to the host: speaking the read-back as built, and taking the
caller's yes by keypad or voice outside the model.

### Money on the wrong account

A webhook from one account settles a payment taken on another, or a config sends money to the
wrong merchant. **Controls:** each step names its mode; connect mode needs a connected account in
the settings, checked when the config is saved and again when the link is requested, and a
business account with no explicit mode is refused rather than defaulting to the platform (tested).
A mode the payments adapter does not declare is refused when the config is saved (tested). Money
that moved is never dropped: a payment the engine had expired that the provider then reports paid
is recorded as paid and flagged late in the ledger (tested), so no race between processes can take
a caller's money without a record. An
outcome from a connected account other than the payment's, or a connected account's outcome for a
platform payment, is ignored and written to the ledger (tested). The reference server takes
connect-mode events on their own endpoint with their own signing secret. The idempotency key of a
link includes the mode.

### Refunds and disputes in platform mode

Money sent back twice or to no one, a refund started from a call, a refund on a disputed payment,
or a dispute lost without the business hearing of it. **Controls:** in platform mode the platform
is the merchant, so it refunds through `refundPayment`; an adapter without `refund` keeps platform
payment flows valid (no flow step needs a refund) and `refundPayment` is refused at run time,
while disputes are still recorded (tested). `refundPayment` is a host
call made for the business: no grant reaches it and no flow step runs it, so neither the caller nor
the model has a path to it; the host keeps it off every tool the model can call (left to the host).
It refunds only a paid platform payment, never more in total than was paid, one refund in flight
per payment, each with its own idempotency key; a refund whose answer was lost resumes with the
same key, so the provider refunds once (tested). A refund is refused while a dispute is open or
after it was lost (tested). Dispute events come only through the signed payments webhook, are found
by the payment intent bound when the payment was paid, and a connected account's is ignored and
written down (tested). Refunds and disputes are ledger entries with amounts and statuses, never
card data or dispute evidence, the listener hears both, and the receipt issued at the end of the
call never changes (tested). Connect payments are the business's, refunded and disputed on its own
account: the engine refuses to refund one and never binds its disputes (tested). Left to the host:
who in the business may ask for a refund, and answering a dispute with evidence at the provider.

### Card data and PCI DSS scope

**Controls:** Pay is by a hosted payment page; the engine sees a link id and a status, never a card
number. A link offers only methods that settle during the call (cards, Apple Pay, Google Pay,
Link) and lives 15 minutes from the text by default (5 to 60); the engine expires it itself at
that deadline, at the provider first, because a provider's shortest link life can be longer
(tested). A link never outlives its call: `endCall` expires every open link at the provider
before the receipt is signed, and the caller can cancel one (`cancelPaymentLink`); a link
created while its request was being closed, or after its call ended, is expired, never texted,
and neither a cancel nor the end of the call closes a link while it is being texted (tested). Money that moves
after the engine closed a link is still recorded as paid and flagged `late` in the ledger, so a
late payment is never lost (tested). Card numbers in transcripts are detected (Luhn, digits and English or French digit words)
and replaced, and the host is told to interrupt (tested). Intake refuses a value carrying a card
number, and the ledger refuses detail carrying one (tested). Keypad card capture is planned only
through a PCI-certified carrier service on a call path where tones never reach this engine
(PAY-6), after an assessor's scoping. Nothing here is a PCI DSS attestation; a host's scope
depends on its whole call path.

### Tampering with the record

**Controls:** the ledger is hash-chained, and any changed, removed or reordered entry is detected
(tested). Receipts are signed with ES256 over canonical JSON and carry the ledger head; one changed
byte fails verification (tested). Signing keys rotate with a key ring: one key signs, and the
published key set keeps the public keys that signed before, so a receipt signed before a rotation
still verifies after it (tested). The ring publishes only public P-256 members and refuses a key
with a private part, two keys with one kid, or a kid that matches no signer (tested). Anyone can
check a receipt without this package with `scripts/verify-receipt.mjs`, which has no dependencies,
refuses a key set fetched over plain http from another machine, and reports a tampered receipt as
invalid (tested).
A step's ledger entries are saved with the step itself (an outbox in the call record) and
appended by event id, once each; a ledger that fails leaves them pending, and the next write or
`flushLedger` appends them, so no saved step is ever missing from the ledger for good (tested).

### Breach of stored data

**Controls:** reference values are HMACs under a per-workspace key, because a plain hash of a date
of birth is reversed by trying every date; the caller's entries are never stored. Sensitive intake
fields are refused by `validateConfig` until field encryption exists (FIL-2). PINs on file are
HMACs bound to their subject, or stay in the host's own PIN store (`verifier` mode). A texted code
is kept only as an HMAC bound to its call, and a calling number only as an HMAC.

### Theft of the keys

**Controls:** neither key has to be in the engine's process. The knowledge key can be an opaque,
asynchronous HMAC function that calls the host's key management service; the engine, the built-in
factors and plug-ins all hash through that one function, an answer that is not a 64-character
lower-case hex digest is refused without being quoted, and a key store that rejects fails closed:
no factor, the attempt counted, nothing it was asked written to the ledger (tested). The receipt
key stays behind `ReceiptSigner`; a signer that returns anything but a 64-byte P1363 signature is
refused, and `derToP1363` converts a key store's DER answer, checked
against `node:crypto` (tested). An HMAC function does not stop a process that can call it from
computing digests, so who may call the key store remains the host's control. A receipt key that
leaked is removed from the key set, not retired, so the receipts it signed stop verifying. A
retired key is published with its `retiredAt`, and a receipt it says it issued at or after that
time is invalid (tested), but `issuedAt` is written by whoever holds the key, so retiring a key
does not limit what a thief can sign with it. A key set saved to a file does not see that removal: verifying against a
saved copy keeps accepting the leaked key, so a holder who needs current trust verifies against
the key set URL or refreshes the copy.

## Open questions

- **Who carries refunds and disputes in platform mode.** The engine now refunds platform payments
  and records their disputes (above), but who bears a lost dispute, and on what terms between the
  platform and the business, is a legal and payment provider question that is not decided.
  Refund status changes after the provider's first answer (`charge.refund.updated`) are not
  followed yet.
- **Seam in the door path.** The adapter is built (GAT-5), but putting a paid third party between
  the engine and a door in production still waits on its pricing and its handling of Canadian data
  being checked, and on one unlock proven by hand in Seam's sandbox.

## Left to the host

- Authorizing the member behind `clearDuress` and `resetPin`: the engine takes the member id as
  given, so only the host's staff tools, after their own sign-in, may call them.
- Repeating a `clearDuress` that raced an alert's delivery: the counters store has no
  compare-and-set, so a clearing that lands while an earlier entry's alert is delivered may be
  undone, leaving the subject flagged (fail closed) until the business clears it again (tested).
- Accepting that the hidden counter shows in the hard lock: because a duress entry never clears
  earlier wrong guesses, a caller who counts guesses can see the hard lock come sooner after a
  duress entry than after a real pass; waits and answers are unchanged (a kept trade-off).
- Buffering keypad digits outside the model, never logging them, and cutting audio to
  speech-to-text and the model while `sensitive` is set.
- Keeping the knowledge key, the receipt signing key, the access signing key, the access code key
  and the step-up signing key in a key store, each apart from the others, behind a `KnowledgeHmac`
  function and `ReceiptSigner`s, and limiting who may call them.
- A door keypad that slows after wrong access codes, and a durable `AccessCodeStore` whose
  `take` and `miss` are atomic across processes.
- Exchanging each step-up token through the engine (`exchangeStepUpToken`), and only for the
  browser session that showed its nonce.
- Calling `expirePaymentLinks` at each link's `expiresAt` (a timer or a sweep); until it does, or
  the call ends, a link lives as long as the provider keeps it. Calling `endCall` again when it
  failed at the provider, so the call's open links are expired and its receipt issued.
- Refunding a late payment (one flagged `late` in the ledger) when the business does not want it.
- Rotating receipt keys (publish the next key, then switch, then retire), keeping retired public
  keys as long as their receipts matter, and removing a key that leaked.
- Durable `SessionStore`, `RecordStore` and `AuditLedger` implementations that keep the same
  guarantees (`sessionStoreContract` today; PRV-5 for the others), one durable `AttemptCounters`
  store shared by every process of a workspace (`attemptCountersContract`), and a durable
  `CodeStore` shared by every engine of a workspace that passes `codeStoreContract`.
- Passing the calling number from the carrier to `beginVerification`, never one the caller or the
  model gives, so the per-number limits apply. Caller ID can be spoofed, so the number's counter is
  a brake on one line, not a control; the subject's counter is what bounds guessing, and a withheld
  number skips the number's counter.
- Speaking the same line, at the same moment, whether a code was sent or not.
- A lockout is also a way to lock someone out: anyone who knows a subject (the owner of a line)
  can spend its 10 failures. The engine tells a `Notifier` of each lock (INT-7, below); acting on
  notices, the person path for a locked caller, who among the business's members may call
  `unlock`, and checking that the caller is real before doing so are the host's. `unlock` must be
  reachable only from the business's own tools, never from a call's tool paths.
- A `CallbackDialer` that dials only the number the engine gives, honours the idempotency key,
  plays a fixed prompt, and reports `confirmed` only for the confirmation key, never for speech or
  a machine. Speaking the same "we will call you back" line and hanging up whatever
  `requestCallback` decides, without waiting on it, so its timing tells the caller nothing.
- Choosing the subject when it starts verification with a subject key (for example the owner of
  the line it was called on). That choice is not a factor: the PIN or other factors still decide.
- A `PinVerifier` that answers the same way, in the same time, for an unknown subject.
- Calling `resetPin` only from the business's own staff tools, after the business has confirmed
  the request, never from a path a caller or the model can reach; and a `RecordStore.putPinDigest`
  that stores only the digest it is given, and only if the subject has none, atomically. The same
  for `enrolDuressPin`, `removeDuressPin` and `putDuressDigest`, which stores only the duress
  digest it is given, replaces one on file (only the business sets it), and only while the PIN
  digest on file is the one given, atomically.
- A `DuressNotifier` that alerts someone the business named, away from the call, and never
  through anything the caller or the person beside them can see; that never blocks (it queues the
  alert and returns); that drops repeats by `alertId`; and a sweep calling `sweepAlerts` (with a
  session store that lists the calls owing alerts) or `deliverDuressAlerts` for recent calls, in
  case a process stopped with an alert owed; a `RecordStore` whose `putPinDigest(null)` also
  removes the duress digest in the same step; and, in `verifier` mode, a
  `PinVerifier` that answers a duress PIN in the same time as any other entry.
- Who may edit a workspace's FlowConfig, and keeping its revisions.
- Keeping `refundPayment` on the business's side (a back office, staff tools), never on a tool the
  model can call, and deciding who in the business may ask for a refund.
- Outside modules: their code runs inside the engine's writes and is part of the host's security
  model.
- The person path: a caller who fails or cannot use a keypad reaches someone who can help.
- Disclosure that an automated assistant answers and that the call is transcribed.
- Deciding who may switch these modules on (business verification), so the line cannot be used to
  run a phishing operation.
