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
(INT-7, below), which clears that one counter entirely (tested). A pass takes off the subject's
failures recorded up to it (a later one, by another call, stays) but takes only its own failure off the number's: a line's failures against other accounts
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

### The accessible path

Callers who cannot use a keypad, or need more time, must be able to verify without the bar being
lowered for anyone, and a mark that says a caller uses a relay or a TTY can reveal a disability.
**Controls:** a keypad field said instead of keyed (Badge's `spokenKeypadFields`) is judged in
the `spoken_knowledge` factor, so it reaches only what the policy gives a spoken answer, under the
spoken attempt limit, and never unlocks texts; without spoken fields in the policy it is never
judged (tested). It also uses a keypad attempt, so saying a field never adds guesses at it: the
keypad and the voice share one budget per call, and across calls it counts as a keypad failure too, so alternating keyed and spoken guesses reach the same lock (tested). The PIN is never taken by speech: the
setting refuses it and a spoken entry carrying one is refused before it is counted (tested). A
keypad `repeat` or `slower` request hands the host no digits, so it never uses, adds or gives back
an attempt (tested). A call marked relay or TTY gets a longer keypad timeout, up to Badge's limit,
and nothing else: the same steps, factors, attempt limits and level, the same ledger entries and
the same receipt, with no trace of the mark (tested).

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

### Caller ID spoofing

A caller presents the number on file as their caller ID. **Controls:** caller ID is never a
factor, and no plug-in may take a name that means it. The STIR/SHAKEN attestation the host's
carrier reports is recorded once when the call starts (`call.started`, the receipt) and can only
lower a level, by the policy's `attestationCaps`: no value raises a level, stands in for a factor or
appears in `methods`, and a cap applies to a grant already issued too (tested,
`verify-attestation.test.ts`). By default there are no caps, because in Canada and the United
States genuine callers often have `C` or no attestation (calls from abroad, signatures lost on an
older, non-IP network), and an attestation speaks to the calling number only, never to who is
speaking. Left to the host: mapping its carrier's value faithfully (the reference server README),
and reporting `none` when it has no result.

### Account takeover by a contact change

Someone who passed verification changes the phone number on file, so the real customer hears
nothing from then on. **Controls:** each flow step that needs a contact-class scope, and each
change an outside module marks with `contactChanged()` (in a flow or outside one), makes the call
owe a security notice, saved in the same write as the change and sent right after it to the
changed subject's number on file as Badge read it before the change, whatever the caller answered
about receipt texts. A notice whose text failed stays owed and is retried by the call's next write,
by `endCall`, and by `sweepAlerts()`, which the host runs on a schedule, so an attacker who changes
the number and never lets the call end still triggers it (tested); a call that changes two
subjects, or the same subject under two numbers, sends one to each, and never two to the same
subject's same number. Nobody on the call can turn it off. The receipt link of that call goes to
the earlier number only when it was kept for the subject the receipt link is for; a number kept
for another subject is never used (tested in `prove-receipt-text.test.ts`). A notice texted but not
yet logged (a ledger outage) is logged by the next `endCall`, which neither texts nor ends again. A config with such a step is refused without a `messages` adapter.
The notice carries no values, not even which detail changed. Left to the host: an outside module
must call `contactChanged()` in the change that changes contact details (the engine cannot see a
change made in the host's own systems otherwise); running `sweepAlerts()` on a schedule; and
keeping call records at least until their alerts are sent.

### Text flooding and SMS pumping

Repeated calls triggering texts to a real customer, or to premium numbers. **Controls:** texts go
only to the number on file, only after a keypad or PIN match, and at most one photo ID link per
call (tested). A receipt link goes at most once per call, only after a money, contact or access step,
with the caller's consent (the latest answer for the purpose: a later "no" withdraws a "yes") and
a standing keypad or PIN match; a contact change notice at most once per subject and number
(tested). Texted codes go only to the country calling codes the policy lists, none without a
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
Record deliveries are signed in the same scheme, each attempt with its own time, and carry one
idempotency key per record and destination inside the signed body; the reference server's sample
receiver checks the signature first and applies each key once (tested).
Telnyx signatures (Ed25519) cover the timestamp and are refused outside a 300-second window
(tested). Twilio signatures (HMAC-SHA1, compared in constant time) cover the URL and the body but
no timestamp, so a captured Twilio request verifies again when replayed; the reference server only
acknowledges carrier webhooks today, and a host that acts on one must apply each event once itself
(left to the host). The identity is the event, not the call or message: one call sends several
callbacks with the same call id, so a host keys on the carrier's event id where there is one, and
on `CallSid` plus `SequenceNumber` for Twilio call-progress callbacks. An unsigned or wrongly
signed carrier request is refused, and a carrier with no key configured refuses everything
(tested).
Identity links are single-use by the provider. The reference server's Stripe Identity adapter
sends the engine's idempotency key with every create, so a retried `startPhotoId` gets the same
session and link, never a second one (tested against a local fake). It never logs the link, and its
errors carry a status and Stripe's error type and code only, never the link, the key or Stripe's
message (tested). It takes a restricted key only, never a secret key, and `npm run serve` takes a
test-mode one only (tested); the key comes from the environment. It refuses an API base
that is not `https:`, except `http:` on a loopback host for a local fake, so the key never crosses a
network in cleartext (tested). A document upload link is single use by an atomic
claim in the `DocumentStore`: of two uploads at once, one is stored (tested); it expires after 30
minutes and is bound to one call and one confirmed record of that call (tested). Left to the
host: whether keypad tones arrive as out-of-band events or as in-band audio on each carrier
bridge, since in-band tones can be replayed acoustically and can reach speech-to-text.

### Flooding the reference server

Large or slow requests, many requests from one address, and logs that leak what a request carried.
**Controls (reference server, SPEC.md, "Reference server limits and logs"):** a body limit per route, refused on the declared
length before reading and cut off while streaming; deadlines to receive a request (408) and to
answer it (503); a fixed-window rate limit per socket address, an IPv6 address counted by its /64
so one subscriber cannot rotate through it, that ignores `X-Forwarded-For` and tracks a bounded
number of addresses; and one structured log entry per request that names the route pattern, never
the path, and holds no header, query string or body, so signatures, call ids, receipt link tokens
and upload link tokens stay out of the logs (tested). Left to the host: limits in front of the
server (a proxy shares one address for all its callers here), and limits across replicas.

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

### Filing what the caller did not hear

A model that paraphrases a value, or a host path that changes the draft after the caller agreed,
so the record filed is not the one confirmed. **Controls:** the read-back is built by code from the
draft, in the call's language (`buildReadBack`, SPEC.md section 13), never by the model.
`confirmIntake` takes the digest of the read-back the caller heard, which covers the spoken text
and the record digest of every value, and refuses a draft that no longer reads back to it, so a
value changed since, a sensitive one included, is never filed on an old yes (tested). A sensitive
value is never read back: its line says only that it was given, so it does not reach the
transcript, the model or anyone listening in (tested). The digest says no more about the values
than the record digest the ledger and the receipt already carry. Spanish is optional per form and
per consent wording: a call in Spanish whose flow needs a form or a wording with no Spanish text is
refused when the flow starts, and outside a flow at `startIntake` and `recordConsent`, so a caller
is never asked to confirm, or to consent to, words they were not read in their language (tested).

### Config tampering

Someone who can edit a workspace's FlowConfig. **Controls:** the engine refuses any config with a
problem, Trace (the ledger) cannot be turned off, the floors cannot be lowered (`entry.open` is
an access scope, never below level 2), planned factors cannot be turned on, a payment link can
offer only instant methods and live 5 to 60 minutes, connect mode cannot run without a connected
account, and every call's ledger entries carry the config revision
it ran under. Every grant, its `verification.finished` and `grant.issued` entries and the signed
receipt name the policy version and the config revision that judged the caller, so a verification
judged under a config changed mid-call is told apart from one judged under the call's own (tested).
A form's text `pattern` cannot stall the engine on a caller's value: a
backreference, a repeated group that repeats or alternates, and a pattern with more than 100,000
ways to try a value are refused (tested). A `showIf` cycle is refused, and a `showIf` cannot
depend on a sensitive field, whose value the questions asked would otherwise tell (tested); a
hidden field's value is never read back or filed (tested).
Who may edit a config, and how its history is kept, is the host's (left to the host).
A factor added after the engine was built (`engine.useFactor`, or an outside module's factor and
judge with `engine.use`) is off until a config turns it on in Badge's settings; adding one never
changes the config in force (tested). The registry refuses a factor whose kind another module
provides or is a name for caller ID, from a plug-in and from any module's manifest alike (tested).
A module cannot be removed while the config in force names a factor it supplies (tested).

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
provisional failures taken back (tested). The removals that are not safe to repeat (its own
failure off the number, the hidden counter's) are claimed on the call before they run, so a
cleanup run again after a lost write never takes off another failure of the same millisecond
(tested); one that fails after its claim leaves that failure to the window. Two callers for one
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

### A risky request on a verification made for a small one

A caller verified for a small deposit asks for a large one, or the call runs after hours when no
one would notice, or the host's own code sees something wrong mid-call. **Controls:** the policy's
step-up rules raise a scope's minimum for the amount asked (a currency a rule does not list, or an
amount not known, counts as over), the time of day in the business's time zone, or a signal the
host's code raised (tested). `authorize` and every step's own check use the raised minimum, for a
grant already issued too, so the grant does not carry over to the larger request (tested). A raised
signal is never cleared on the call, by any API (tested). Rules only raise: `validatePolicy` refuses
one whose level is not above its scope's minimum, so no rule lowers a floor (tested). A flow cannot
branch, so a flow step whose raised minimum its verification did not reach fails, naming the rule,
and `validateConfig` refuses a flow whose step amount is sure to trigger an amount rule above its
verification (tested). The rule that applied is on the ledger by name, without the amount or the
time (tested). Left to the host: when to raise a signal, and keeping its own cause of the signal
out of the ledger (the engine writes the signal's name only).

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
per payment, each with its own idempotency key, saved with the refund's intent before the provider
is asked and made of the payment and the refund's sequence number; a refund whose answer was lost
resumes with the same key, so the provider refunds once. The sequence number is required: a host
that lost the engine's answer must ask again with the same number to get the committed refund's
saved result back, never a second refund (tested); a new number is a new refund, limited to the
amount not yet refunded. A refund is refused while a dispute is open or
after it was lost (tested). Dispute events come only through the signed payments webhook, are found
by the payment intent bound when the payment was paid, and a connected account's is ignored and
written down (tested). Refunds and disputes are ledger entries with amounts and statuses, never
card data or dispute evidence, the listener hears both, and the receipt issued at the end of the
call never changes (tested). Connect payments are the business's, refunded and disputed on its own
account: the engine refuses to refund one and never binds its disputes (tested). Left to the host:
who in the business may ask for a refund, and answering a dispute with evidence at the provider.

### Card data and PCI DSS scope

**Controls:** Pay is by a hosted payment page; the engine sees a link id and a status, never a card
number. Card numbers in transcripts are detected (Luhn, digits, and English or French number words
read digit by digit, as numbers such as "forty two" or "quarante-deux", or with "double") and
replaced, and the host is told to interrupt (tested over a shared JSON corpus). While the caller
is still reading, the live detector tells the host to interrupt once a run reaches 8 digits, before
a whole number has been spoken (tested over the same corpus); it keeps only the open run in memory
and never returns it. Over-redaction and over-interrupting (a phone number read aloud) are
accepted. Speech-to-text that renders a number in a way the corpus does not cover can still slip
past both; the host's sensitive pause around payment stays the main control. Intake refuses a value carrying a card
number, and the ledger refuses detail carrying one (tested). Keypad card capture is planned only
through a PCI-certified carrier service on a call path where tones never reach this engine
(PAY-6), after an assessor's scoping. Nothing here is a PCI DSS attestation; a host's scope
depends on its whole call path.

### Hostile documents

A caller, or whoever holds an upload link, sends malware, a script dressed as a photo, or a file
large enough to hurt. **Controls:** an upload link takes only the types it was made for (JPEG, PNG,
PDF), a declared type is checked against the file's leading bytes, and the size is capped per link
(10 MiB by default, 25 MiB at most) before anything is stored (tested). Every document goes to the
host's `DocumentScanner` before it is stored, and one it does not pass is refused and spends the
link (tested). The reference server's upload page has no script, a CSP that allows nothing but a
form posted back to itself, and no referrer, so the token in its address never leaves in a header.
Left to the host: a real scanner, and serving stored documents only as downloads, never inline.

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
A call nobody writes again is caught up by `flushPending`, a background flush the host schedules,
over the calls its session store lists as pending (tested). The ledger is the record, never the
`onEvent` listener: the listener hears of an entry only after the ledger has it, may hear of it
twice (same `eventId`) or not at all, and its failures go to `onListenerError` without stopping
the call or the ledger (tested). A listener gets the same detail as the ledger, never a value.
A durable ledger must pass `auditLedgerContract`: append-only, one valid chain under concurrent
appends, each `eventId` once, copies in and out, and card data refused (tested on
`MemoryAuditLedger`).
The reference server's optional SQLite ledger (SRV-4) adds triggers that refuse any UPDATE or
DELETE of an entry, and any INSERT (such as INSERT OR REPLACE) over a stored `seq` or `eventId`,
from any connection, and takes the database's write lock for each append, so
two processes on one file keep one chain (tested). The triggers stop mistakes, not an attacker: any
connection can drop them, and anyone who can write the file can rewrite it; the hash chain and
signed receipts are what detect that.
Monthly reports are signed with the receipt key under domain separation: the signed bytes start
with a line naming the document type, so a signed report never verifies as a receipt, a receipt
never as a report, and a JSON report never as a CSV one (tested). A report carries counts and
totals only, and counts an entry for a workspace only when its `eventId` names that workspace;
an entry without one is reported as unattributed, so one business never sees another's calls
(tested). An entry whose time does not read is counted as malformed, by its `seq` only, for no
workspace: one tenant's bad entry never stops another tenant's report (tested).

### Reading someone else's receipt

Call ids are not secrets, and a receipt says how a caller was verified, what they filed and paid.
**Controls:** the reference server serves a receipt only at `/r/<token>`, where the token is 256
random bits issued for that call; it keeps only the token's SHA-256, so its store never holds a
working link (the demo UI's in-memory run state does hold its own run's token, to show the
link; a host would send it and drop it); an unknown, malformed or not yet usable token gives the same `404`; there is no
route by call id (tested). The page carries no script, is never cached or indexed, and sends no
Referer, so the token does not leak to another site (tested). `textReceiptLink` sends the host's
link only to the number on file and never writes the link to the ledger (tested). Left to the
host: issuing the token and building the link, rate limits on `/r/` (SRV-2), a durable store for the hashes (SRV-4),
and expiry or revocation of a link, which are not built.

### Consent that outlives its withdrawal

A caller who said yes to texts later says STOP, or asks staff to remove it, and the business
keeps relying on the old yes. **Controls:** `revokeConsent` takes a revocation by voice, text or
dashboard, during the call or after it, keeps it in the host's `ConsentStore` and writes
`consent.revoked` to the ledger, once per consent however often it is retried, with the channel
and time of the first revocation, never before the consent's own `consent.recorded` (tested). The
standard opt-out words (STOP, STOPALL, UNSUBSCRIBE, CANCEL, END, QUIT) and the French ARRÊT, ARRÊTE
and ARRÊTER map to revocation; a longer message that only contains one does not (tested). With a
store, a consent is written to it before it is recorded on the call, so no recorded consent is
missing from the store; one still being written when the call ends counts as no consent, is noted
as `consent.unrecorded` and shows as `not_recorded` on the receipt, so a store outage never keeps
a call from ending and never leaves a yes behind (tested). The ledger
detail names the consent and the channel, never a phone number or the message. Left to the host:
plugging in a `ConsentStore` wherever consents are recorded (without one, consents cannot be
revoked through the engine), deciding which consents an inbound STOP revokes, checking the store
before every text it sends on a consent, and who may revoke from a dashboard.

Whoever holds the ledger could rebuild the whole chain. **Control (PRV-9):** `anchorLedger` fixes
the head in time with a third party, and `verifyAnchor` checks it offline against the host's copy
of the authority's certificate chain and Rekor's key: an entry an anchor covers cannot change
afterwards without the change showing, and a rebuilt chain fails as `imprint` (tested; both
adapters are tested on answers built locally in the services' formats with throwaway keys, not yet
on an answer recorded from a real authority or log). Every certificate above the authority's own
must be a CA allowed to issue (cA true, keyCertSign, pathLen), so a leaf under the trusted root
cannot stand in as an issuer (tested). The token must name the authority's signing certificate in a
signed SigningCertificate or SigningCertificateV2 attribute, so a token cannot be passed off under
another certificate (tested). The reference authority adapter asks with a fresh nonce for a SHA-256
imprint and refuses an answer that does not echo the nonce, so a recorded token is not taken as a
new answer, and both reference adapters cap a reply's size (tested). It does not prove the chain was honest before it was
anchored, nor anything after the last anchor. With a time-stamp authority alone, the authority
sees only a hash and only the proofs the operator keeps exist, so an operator could drop an
inconvenient one. With Rekor, everyone can see every head the operator anchored, so a missing
anchor shows too. A public log shows each anchored head (a hash), the key that signed it and the
signature, and nothing else: no entry, no call and no workspace. The time is not in the log; it
is in the authority's token, which the operator keeps. The anchor payload is domain-separated,
so a head signed for the log can never verify as a receipt, even under the receipt key (tested).
The time always comes from the authority, since Rekor v2 keeps none.

### Breach of stored data

**Controls:** reference values are HMACs under a per-workspace key, because a plain hash of a date
of birth is reversed by trying every date; the caller's entries are never stored. Sensitive intake
fields are encrypted by the host's `FieldCipher` before the record reaches the `RecordStore`, and
a config with one is refused without a cipher; an engine without one refuses to file such a
record (tested). The record's digest, which receipts and the ledger carry, covers a sensitive
value only as an HMAC under the knowledge key, so a receipt cannot be used to test guesses at a
short value such as a policy number (tested, ADR-27). A cipher that throws, or answers with nothing or with
the value itself, is refused and never holds a call open: the filing is released as failed, the
draft and its values are dropped, `record.filing_failed` names only the fields and a reason code,
and the cipher's own error, which may quote the value, is never passed on (tested). Left open: while a draft is open or being filed, its sensitive values
sit in the clear in the call record, so a durable `SessionStore` holds them until the record is
filed or abandoned, or the call ends, which drops an open draft (tested). PINs on file are
HMACs bound to their subject, or stay in the host's own PIN store (`verifier` mode). A delivered
record goes only to a destination in the host's configuration, over `https:` (or `http:` to a
loopback host) and never to a URL with credentials in it; its `delivery.attempted` ledger entries
carry the record id, the destination's id, the attempt, the outcome and the status, never a field
value, the URL or the secret (tested). A texted code
is kept only as an HMAC bound to its call, and a calling number only as an HMAC. Upload link
tokens are 256 random bits and only their SHA-256 is stored, so a copy of the `DocumentStore`
yields no working link (tested).
The reference server's optional SQLite stores (SRV-4) keep subjects (HMACs and the number on
file), confirmed intake values and the ledger in one file, unencrypted, created readable and
writable by its owner only (created exclusively with mode 0600), with SQLite's WAL and
shared-memory files created alike (tested); a file that already exists, or a `-wal`, `-shm` or
`-journal` file beside it, readable or writable by others is refused, as are a symbolic link (at
the path or beside it), anything that is not a regular file, a database file on Windows (where the
mode sets no ACL), and a `file:` URI, which would open a file other than the one given that mode
(tested). Protecting that file, its backups and the disk under it is
left to the host.

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

### Other identity and banking numbers in transcripts

A caller reads a social insurance number, a health card number or bank details aloud, and the
transcript is stored or sent on. **Controls:** `sinRedactor` (9 digits, Luhn),
`healthCardRedactor` (Ontario, British Columbia and Quebec formats with their checks) and
`bankAccountRedactor` (3 or more digits after a bank word) find these in digits and in English or
French digit words, and replace them (tested over the shared corpus in `test/corpus/`). They are
off unless the host composes them in. Limits: bank numbers have no check digit, so one read with
no bank word before it is missed; other provinces' health card numbers are missed; intake values
and ledger detail are checked for card numbers only.

### Access and deletion requests

A person asks the business what it holds about them, or asks it to delete that (PIPEDA, and
Quebec's private-sector law as amended by Law 25). **Controls:** `exportSubject` and `eraseSubject`
are host calls the business makes with a subject key; they take no call id and no flow step names
them, so nothing a caller or the model says reaches them. An intake record carries the subject the
call matched by keypad or PIN, never a subject only claimed, so one caller cannot file records into
another person's export. A consent likewise carries the subject matched when it was recorded, and
an export lists only that subject's consents, so a call that later matches another subject never
discloses that person's consents in the first one's export (tested). The export says whether a PIN digest is on file and never carries the
digest; it is signed with the receipt key under its own domain (the signed bytes name the document
type), so an export never verifies as a receipt and a receipt never as an export (tested). The
erase deletes the subject's records, the call's copy of their values and the PIN digest through the
stores, appends `subject.erased` (record ids and whether a PIN digest goes; no subject key) and
`subject.erasure_completed`, and a deleted record id is never stored again, so a confirmation still
writing when the erase ran cannot bring the values back (tested). It
never changes a ledger entry or a receipt, so the chain and every signature still verify (tested).

**What stays, plainly:** the ledger entries and receipts keep each record's SHA-256 digest, as
integrity records for the retention period: changing them would break the chain and the
signatures. They hold no value, but the digest is unkeyed, so a short or guessable record (a
yes/no answer, a date, a short phrase) can be confirmed by anyone who holds the ledger or a
receipt, guesses the values and hashes them. Treat the ledger and receipts as personal
information for retention and access control. The export lists these as kept, with that reason.
Records filed on a call with no matched subject cannot be found by subject; the export says so.
Consents stay in their call records until PRV-3's `ConsentStore`; the erase resets the failure counters kept under the subject's key (VER-1).

## Open questions

- **Seam in the door path.** The adapter is built (GAT-5), but putting a paid third party between
  the engine and a door in production still waits on its pricing and its handling of Canadian data
  being checked, and on one unlock proven by hand in Seam's sandbox.
- **Who carries refunds and disputes in platform mode.** The engine now refunds platform payments
  and records their disputes (above), but who bears a lost dispute, and on what terms between the
  platform and the business, is a legal and payment provider question that is not decided.
  Refund status changes after the provider's first answer (`charge.refund.updated`,
  `refund.updated`) are not followed yet: a `pending` refund counts as pending until a provider
  update arrives, and the engine has no path for one, so a pending refund that later fails still
  counts against the payment until the business refunds the rest by hand at the provider (#117).

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
| core-18 | R | A host's listener misses an event and nobody is told. | Defined delivery semantics: the ledger is the record, and the listener is told best effort, after each append, and may be told again of the same entry, with the entry's `eventId` and `seq`; a throw or rejection goes to `onListenerError`; `flushPending` appends and re-delivers what a failed append left pending. A notice lost when the process stops right after an append is not re-sent; the ledger still holds the event. | covered | `engine.test.ts`: "tells the listener after each append, with the entry's event id and seq"; `engine.test.ts`: "reports a listener's throw and rejection to onListenerError, and the call and the ledger go on"; `engine.test.ts`: "tells the listener again, with the same event id and seq, of an entry a lost clear left pending"; `engine.test.ts`: "flushes in the background the calls whose ledger entries are pending, and only those"; `event-delivery-hostile.test.ts`: "A4: a write that lands between flushPending's read and its unmark keeps the call marked" |
| core-19 | E | The model is talked into acting for someone else (urgency, authority, "calling for my mother"). | An adversarial evaluation set in English and French gating each release. The model already has no path to a factor, a level or a grant (core-1). | open | VER-7 |
| core-20 | I | A host keeps forwarding audio or transcript to the model while keypad digits or a payment are in progress. | `forwardingFor(state)`, the one helper that says what a host may forward for the current session: nothing while `sensitive` is set or after the call, and nothing for a state it cannot read. The host must still ask it and obey (Left to the host). | covered | `session.test.ts`: "holds the transcript, both audio paths and listen-in through keypad entry and payment, and after the call"; `session.test.ts`: "fails closed with no state, or one the engine never writes"; `forwarding-hostile.test.ts`: "W4: nothing the host can call while paying lifts the hold before the payment settles" |
| core-21 | T | An outside module's validators throw on garbage, or its step status is not pure, and a bad config passes. | A contract suite for outside modules. | open | MOD-1 |

### Badge

Who is calling, in levels (`src/verify/`).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| badge-1 | S | A caller guesses keypad knowledge or a PIN within one call. | A per-call limit on judged attempts for every entered factor; after it, even the right answer is not judged. | covered | `engine.test.ts`: "locks keypad judging after the policy's attempts"; `pin.test.ts`: "counts malformed, wrong and unknown-subject entries the same way, and locks after the limit"; `policy.test.ts`: "caps keypad attempts like the PIN" |
| badge-2 | S | A caller guesses a PIN across many calls (a 4-digit PIN with 3 attempts per call falls within about 3,300 calls). | Durable failure counters per subject and per calling number, shared by every engine: waits after each failure and a hard lock after 10 failures in 24 hours, checked before a factor is judged. | covered | `verify-counters.test.ts`: "refuses during the wait without judging or using the call's attempt, then locks hard after 10 failures in 24 hours"; `pin.test.ts`: "carries a PIN lock across two calls and two engines, and lifts it only when the window passes or the business resets it"; `verify-counters.test.ts`: "counts an unknown subject by its key too, so a lock never tells which accounts exist" |
| badge-3 | S | A crash, a failing PIN verifier or a second process gives a caller a free try. | Each attempt is counted in its own write before it is judged. | covered | `pin.test.ts`: "counts the attempt before asking, so a verifier that fails still uses it"; `session-store.test.ts`: "gives concurrent attempts on one call no more than the limit, and judges only one of them at once" |
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
| dossier-4 | I | A sensitive field (a social insurance number) is stored in the clear. | A sensitive value is encrypted by the host's `fieldCipher` before the record is stored, and once filed is kept in the clear nowhere else; while a draft is open or being filed, its values sit in the clear in the call record (the session store) until it is filed or abandoned, or the call ends; without the cipher the config is refused and nothing is filed. | covered | `engine.test.ts`: "sensitive fields"; `field-cipher-hostile.test.ts`: "G3: the plaintext is in no ledger entry, receipt, stored record or session after filing"; `field-cipher-hostile.test.ts`: "G5: an engine without the cipher on the same stores refuses to file, and the engine with it files the same record" |
| dossier-5 | T | A form edited in the middle of a draft changes what the caller is confirming. | A draft keeps the form it started with. | covered | `flows.test.ts`: "keeps the form a draft started with when the config changes the form" |
| dossier-6 | R | A caller disputes a value because it was never read back to them. | Read-backs in English and French before confirmation. | open | FIL-1 |
| dossier-7 | T | A record delivered to the business is forged, changed or replayed on the way. | Signed delivery webhooks with retries and idempotency. | open | FIL-3 |
| dossier-8 | S | A document upload link is guessed or reused. | Single-use upload links. | open | FIL-5 |

### Paylink

Payment by a link texted to the number on file (`src/pay/`).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| paylink-1 | E | A payment is requested without the `payment.request` scope, or with a bad amount. | The scope is required; amounts and descriptions are checked. | covered | `engine.test.ts`: "refuses without the scope, without an amount, and refuses bad amounts and descriptions at the read-back"; `modules.test.ts`: "validates amounts and currencies" |
| paylink-2 | T | The model or the caller chooses the amount. | In a flow, the step sets the amount. | covered | `flows.test.ts`: "runs deposit end to end, with the amount from the flow and a receipt" |
| paylink-3 | R | The caller disputes an amount that was never read back before the link was sent. | Amounts come from the step, the host or an `AmountSource`, never the model, and the link is texted only after the caller heard and confirmed the amount read back. | covered | `paylink-amounts.test.ts`: "never texts a link the caller has not heard and confirmed, whether the amount is fixed or not"; `paylink-amounts.test.ts`: "reads a fixed amount back and sends the link only for the amount the caller confirmed" |
| paylink-4 | S | A payment link goes to the calling number or one the model supplied. | The link goes to the number on file only. | covered | `engine.test.ts`: "texts a link to the number on file and settles only on paid" |
| paylink-5 | T | A failed, expired or forged outcome settles a payment. | A payment settles only on `paid`, and once. | covered | `modules.test.ts`: "settles as paid only when the provider says paid"; `flows.test.ts`: "refuses the wrong form or consent purpose for the step, and fails on an unpaid link" |
| paylink-6 | E | A caller who refused consent is still taken to a payment. | A consent of no fails its step before any money step. | covered | `flows.test.ts`: "fails the flow on a consent of no, before any money step (review blocker 2)" |
| paylink-7 | E | A link stays payable after the call or after it should have been withdrawn. | Cancel and expire open links. | open | PAY-3 |
| paylink-8 | E | A payment lands in the wrong Stripe account (the business's or the platform's). | `connect` and `platform` modes: a connect payment is made on the business's account and settles only on an outcome from that account. | covered | `paylink-modes.test.ts`: "takes a connect payment on the business's account, and its receipt says so"; `paylink-modes.test.ts`: "never lets an outcome from another account settle a payment, and writes down one that reaches it"; `paylink-modes.test.ts`: "keeps two connected accounts' payments apart even when their providers give the same link id" |
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
| trace-11 | R | A caller withdraws consent and nothing records it. | `revokeConsent` records a revocation by voice, text or dashboard in the `ConsentStore` and the ledger, once, even after the call is gone. | covered | `engine.test.ts`: "stores each consent, and revokes one by text after the call ended, once, in the ledger"; `engine.test.ts`: "never writes consent.revoked before its consent.recorded, even with the recorded entry still pending" |
| trace-12 | R | An auditor cannot take the ledger out in a verifiable form. | Ledger export as signed NDJSON with a cursor. | open | PRV-4 |

### Gate

Signed, time-limited access to a door after verification, and one-time access codes
(`src/gate/`). Grants are signed with the access key, never the receipt key.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| gate-1 | E | Access is granted without a valid verification grant, or a grant outlives the verification it rests on. | A grant needs a verification grant covering `entry.open` at level 2, and never outlives it; a tainted, expired or ended call sends nothing. | covered | `gate.test.ts`: "refuses without a verification grant covering entry.open, in a flow and outside one"; `gate.test.ts`: "never outlives the verification grant"; `gate.test.ts`: "sends nothing when the call was tainted, the grant expired or the call ended while it was signed" |
| gate-2 | S | A door controller accepts a forged, replayed or misdirected grant. | Grants are ES256-signed with the access key; the relay's verifier checks the workspace, the audience and the window, and refuses a grant id it has seen until the grant expires. | covered | `gate.test.ts`: "runs an entry flow: a signed grant to the door, verified with the access key only"; `gate.test.ts`: "refuses the wrong audience, a long or inverted lifetime, and anything malformed"; `gate.test.ts`: "refuses a grant id it has seen until the grant expired"; `gate.test.ts`: "refuses a grant another workspace issued, even on a shared key and controller name (review R1)" |
| gate-3 | S | A one-time access code is guessed or used twice. | Codes are single use, stored only as a keyed hash, bound to their door and workspace, and five wrong guesses at the door spend the code. | covered | `gate.test.ts`: "texts a code to the number on file and redeems it once, for the grant it stands for"; `gate-codes-hostile.test.ts`: "two keypads offering one code at once: one grant between them, however their signing interleaves"; `gate-codes-hostile.test.ts`: "five wrong guesses at its door spend the code, recorded without the guess; four do not" |
| gate-4 | E | A web sign-in step-up is completed by someone other than the verified caller. | The step-up token is bound to the nonce the person keyed, the verified subject and the call's grant (see Step-up). | covered | `gate-step-up.test.ts`: "refuses an expired token, and one for another site, subject or nonce, each using it up" |

### Step-up

Web sign-in step-up (`src/gate/step-up.ts`): a verified caller keys the nonce shown on the host's
site, and the call gets a short-lived ES256 token the site exchanges once, through the engine, to
raise its sign-in level.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| stepup-1 | E | A token is issued without a verification at level 2, or outlives it. | Issue needs a grant covering `entry.sign_in`, never during a running verification, and a token never outlives the grant. | covered | `gate-step-up.test.ts`: "refuses without a verification grant covering entry.sign_in, or while a verification runs"; `gate-step-up.test.ts`: "never outlives the verification grant" |
| stepup-2 | S | A stolen or replayed token signs someone in, or is used in another site or workspace. | Each token exchanges once, for its own site, subject and nonce; a mismatch uses it up, and another workspace never finds it. | covered | `gate-step-up-hostile.test.ts`: "two exchanges of one token at once: one succeeds, the other is refused, and one entry each"; `gate-step-up.test.ts`: "refuses an expired token, and one for another site, subject or nonce, each using it up"; `gate-step-up-hostile.test.ts`: "a token from one workspace never exchanges in another with the same call and token ids" |
| stepup-3 | T | A forged or tampered token is accepted, or one signed with another key. | Tampered bytes answer unknown; the step-up signer must not share a key with the receipt or access signer. | covered | `gate-step-up-hostile.test.ts`: "never throws on hostile tokens, and a tampered byte is unknown"; `gate-step-up.test.ts`: "refuses a step-up signer that shares a key with the receipt or the access signer" |
| stepup-4 | E | A token issued before the call was tainted, or verified again for someone else, is still exchanged. | Taint and re-verification refuse the exchange and use the token up. | covered | `gate-step-up.test.ts`: "refuses an exchange after the call is tainted, and that uses the token up"; `gate-step-up.test.ts`: "refuses a token whose call was verified again since" |

### Webhooks

Webhook signature checks and event mapping (`src/webhooks/`).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| webhooks-1 | S | A forged Stripe webhook settles a payment or passes a photo ID. | Stripe's published scheme: HMAC-SHA256 over `t.payload`, any configured secret, constant-time comparison. | covered | `webhooks.test.ts`: "accepts Stripe's scheme: HMAC-SHA256 of t.payload"; `webhooks.test.ts`: "refuses each failure with its reason" |
| webhooks-2 | T | An old signed Stripe webhook is replayed. | A 300-second window either way; each identity session and payment applies once. | covered | `webhooks.test.ts`: "refuses each failure with its reason"; `engine.test.ts`: "applies identity outcomes once, only while verifying, and ignores unknown sessions" |
| webhooks-3 | T | A well-signed but malformed or unexpected event is acted on. | Anything that is not a well-formed event is `null`; other types are ignored. | covered | `webhooks.test.ts`: "returns null for anything that is not a well-formed event"; `webhooks.test.ts`: "names other event types as ignored" |
| webhooks-4 | S | A forged Twilio or Telnyx webhook is trusted. | Twilio's HMAC-SHA1 over the URL and sorted parameters, and Telnyx's Ed25519 over the timestamp and payload with a timestamp window; Twilio's check is tested against Twilio's published examples, and Telnyx's against RFC 8032's first Ed25519 test vector, since Telnyx publishes no signed example; any configured secret or key. | covered | `webhooks.test.ts`: "accepts Twilio's published examples, form and JSON bodies"; `webhooks.test.ts`: "accepts any configured public key, skipping ones that are not 32 bytes of base64"; `carrier-signature-hostile.test.ts`: "P4: a timestamp far in the future or the past, is refused; leading zeros are the same second"; `carrier-signature-hostile.test.ts`: "P8: a body that adds an unsigned pair, or swaps two values between names, is refused"; `carrier-signature-hostile.test.ts`: "P1: a small-order public key (a placeholder of zeros, the identity) never verifies a forged signature" |

### Reference server

`examples/reference-server/`: an example, not hardened for production.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| server-1 | S | The server parses or acts on an unsigned webhook. | The signature is checked before the body is read as an event. | covered | `reference-server.test.ts`: "verifies Stripe signatures before reading the event" |
| server-2 | T | A signed event is replayed to the server. | Each event id is applied once. | covered | `reference-server.test.ts`: "applies a signed event once and ignores events of the other kind" |
| server-3 | S | A forged or replayed Twilio or Telnyx webhook is trusted. | Carrier routes check the vendor's signature (Twilio against the public URL, Telnyx with its timestamp window) before acting. | covered | `reference-server.test.ts`: "checks Twilio signatures against the public URL, query included"; `reference-server.test.ts`: "checks Telnyx signatures and their timestamp" |
| server-4 | D | A large body exhausts memory. | A body limit on every route that reads one. | covered | `reference-server.test.ts`: "refuses a body over its route's limit, declared or streamed"; `reference-server.test.ts`: "gives every route that reads a body its own limit"; `reference-ui.test.ts`: "refuses a body over the limit" |
| server-5 | D | Slow or repeated requests tie the server up. | Per-route limits, request timeouts and a per-address rate limit. | covered | `reference-server.test.ts`: "limits each address to a number of requests per window, on the rate limit's clock"; `reference-server.test.ts`: "answers 503 when a request takes longer than its deadline"; `reference-server.test.ts`: "disconnects a client that sends its headers too slowly with a 408, in JSON, and logs it" |
| server-6 | I | An error answer leaks engine detail. | 500 without detail; a demo run names an engine refusal and hides anything else. | covered | `reference-server.test.ts`: "answers 500 without detail when the engine fails"; `reference-ui.test.ts`: "ends a run on a step that throws, naming an engine refusal and hiding anything else" |
| server-7 | I | Anyone who knows or guesses a call id fetches its receipt. | Receipt links by capability token. | open | SRV-3 |
| server-8 | S | A web page reaches the local demo through DNS rebinding. | The Host header must name this machine and port, on every route. | covered | `reference-ui.test.ts`: "refuses a Host header that is not this machine (DNS rebinding), and accepts the local names"; `reference-ui.test.ts`: "with the UI on, refuses a foreign Host on every route, the webhooks, receipts and key set included" |
| server-9 | I | A request reads a file outside the UI's allow-list. | A fixed allow-list; traversal, encodings and case tricks are refused. | covered | `reference-ui.test.ts`: "serves nothing outside the allow-list: traversal, encodings, case, other files" |
| server-10 | E | Script injected into the demo page runs. | A strict CSP, no inline script, style or handlers, and hardening headers. | covered | `reference-ui.test.ts`: "keeps the page free of inline script, inline style and inline handlers, so the CSP holds"; `reference-ui.test.ts`: "serves every allow-listed file with its content type, the strict CSP and the hardening headers" |
| server-11 | T | Another origin drives a demo run (cross-site request). | Demo routes refuse another origin and a non-JSON body. | covered | `reference-ui.test.ts`: "refuses an unknown flow, bad JSON, a non-JSON body and another origin" |
| server-12 | R | The server forgets its records and ledger on restart. | Optional persistent stores on `node:sqlite` (`SqliteAuditLedger`, `SqliteRecordStore`), passing the ledger and record store contracts. They are opt-in: a host wires them in, and the server as `npm run serve` starts it stays in memory. | covered | `sqlite-stores.test.ts`: "keep the ledger, subjects and records across a restart, and the chain goes on"; `sqlite-stores.test.ts`: "SqliteAuditLedger on a file passes the AuditLedger contract"; `sqlite-stores.test.ts`: "SqliteRecordStore on a file passes the RecordStore contract" |

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
| auditledger-2 | T | A host's durable ledger is not append-only, breaks the chain or reorders concurrent appends. | `auditLedgerContract` for durable ledgers, which the memory and SQLite ledgers pass and which catches a ledger that rewrites an entry or whose appends interleave. | covered | `contracts.test.ts`: "MemoryAuditLedger passes the AuditLedger contract"; `contracts.test.ts`: "catches a ledger that rewrites an entry, or skips the card number check"; `contracts.test.ts`: "catches a ledger whose appends interleave, forking the chain"; `sqlite-stores.test.ts`: "SqliteAuditLedger passes the AuditLedger contract" |
| auditledger-3 | D | An entry the ledger would refuse is saved with the step and blocks every later write. | Such an entry is refused before the step is saved. | covered | `session-store.test.ts`: "refuses an entry the ledger would refuse before it is saved, so it never blocks later writes" |

### RecordStore

Subject records and filed intake records (the host's own store).

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| recordstore-1 | T | A caller of the store changes a stored record through a shared reference. | The memory store returns copies. | covered | `entry-points.test.ts`: "the record store returns copies and nothing for unknown keys" |
| recordstore-2 | T | A host's durable record store does not keep the memory store's guarantees. | `recordStoreContract` for durable record stores, which the memory and SQLite stores pass and which catches a store whose keys collide across workspaces or that hands out what it stores. | covered | `contracts.test.ts`: "MemoryRecordStore passes the RecordStore contract"; `contracts.test.ts`: "catches a store whose keys collide across workspaces"; `contracts.test.ts`: "catches a store that hands out what it stores"; `sqlite-stores.test.ts`: "SqliteRecordStore passes the RecordStore contract" |

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
| messagesender-2 | D | Repeated calls flood a customer with texts, or pump premium numbers. | Photo ID links only after a keypad or PIN match, at most one per call; texted codes are limited per subject and per calling number across calls. | covered | `engine.test.ts`: "sends photo ID links only after a match, once per call, in the caller's language"; `verify-text-code.test.ts`: "allows 5 codes per subject per 24 hours, across calls"; `verify-text-code.test.ts`: "limits sends per calling number, across subjects" |
| messagesender-3 | D | Texted codes are used for SMS pumping across calls. | Send limits per subject and per calling number, held in the shared `CodeStore`, and a destination country allow-list in the policy. | covered | `verify-text-code.test.ts`: "allows 5 codes per subject per 24 hours, across calls"; `verify-text-code.test.ts`: "limits sends per calling number, across subjects"; `verify-text-code.test.ts`: "texts only to countries the policy allows, and counts nothing it refuses for that" |

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

### AmountSource

The host's lookup of a payment amount from a reference (a record, an endpoint or a price list).
Code asks it, never the model.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| amountsource-1 | T | A source answers a bad amount or currency (negative, fractional, too large, a string). | The answer is checked like any other amount; a bad one is refused and nothing is read back or texted. | covered | `paylink-amounts-hostile.test.ts`: "refuses every bad amount a source can answer, and writes nothing"; `paylink-amounts.test.ts`: "refuses an amountRef nobody can resolve, a bad answer, and a link without a read-back" |
| amountsource-2 | T | A source's answer changes after it was checked, so the link is for another amount. | The answer is read once; the link is for the amount the caller confirmed. | covered | `paylink-amounts-hostile.test.ts`: "reads a source's answer once, so a getter cannot pass the check and then change the amount"; `paylink-amounts.test.ts`: "resolves a flow step's amountRef, reads it back and texts the link only after the caller confirmed" |
| amountsource-3 | D | A source answers nothing at all and the call crashes. | No answer is no amount, refused cleanly. | covered | `paylink-amounts.test.ts`: "reads an AmountSource that answers nothing at all as no amount, not as a crash" |

### Anchor

A time-stamp authority, or a public log plus one, that fixes the ledger head in time. It is given
the head and its anchor payload, never the ledger.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| anchor-1 | T | A ledger is rebuilt after it was anchored and still looks anchored. | `verifyAnchor` checks the proof against the entries, offline, and catches a rebuilt chain or a proof for an earlier head. | covered | `prove-anchor.test.ts`: "catches a chain rebuilt after it was anchored"; `anchor-hostile.test.ts`: "Y2: an adapter that answers a proof for an earlier head is caught when the anchor is checked" |
| anchor-2 | S | A proof from one ledger, or a token for another payload, is passed off as this one's. | The token's imprint must match this head's payload; a proof from another ledger never verifies. | covered | `anchor-hostile.test.ts`: "Y3: two ledgers: an anchor from one never verifies against the other"; `prove-anchor.test.ts`: "refuses a token for another payload as imprint" |
| anchor-3 | S | An anchor payload is reused as a receipt signature. | The payload is domain-separated, so a head signed with the receipt key never verifies as a receipt. | covered | `prove-anchor.test.ts`: "is domain-separated: a context line, then the head as canonical JSON"; `prove-anchor.test.ts`: "a head signed with the receipt key never verifies as a receipt" |
| anchor-4 | T | A malformed proof or a hostile entry is accepted, or throws. | Anything malformed is refused without throwing: a proof counts only its own keys (an inherited `kind` or `token` is not a field), and an export holding null or a non-entry where an entry should be is `malformed`. | covered | `prove-anchor.test.ts`: "refuses without an anchor adapter, on an empty ledger, and on a malformed proof"; `anchor-hostile.test.ts`: "Y5: a proof with another kind, an extra field, or a Rekor kind without a log in the trust is refused"; `anchor-review.test.ts`: "an inherited token or kind is refused, and the engine refuses such a proof"; `anchor-review.test.ts`: "a covered prefix holding null or a non-entry is a failed check, never a throw" |
| anchor-5 | S | A token signed with the authority's key is passed off under another certificate, or names none. | The token's signed SigningCertificate or SigningCertificateV2 must name the authority's signing certificate as the host has it (its hash and, when given, its issuer and serial); a token with neither attribute, or one this reader cannot read, is refused (`certificate`, or `token` when it does not read). Version 1's SHA-1 hash only binds a certificate the verifier already holds, so a collision gains an attacker nothing; it is accepted because many authorities still issue it, and SigningCertificateV2 (SHA-256 by default) is preferred. | covered | `anchor-review.test.ts`: "refuses a token that names another certificate"; `anchor-review.test.ts`: "refuses a token with neither attribute"; `anchor-review.test.ts`: "refuses a hash it does not know and an ESSCertID that does not read (fail closed)" |
| anchor-6 | S | An earlier token for the same payload, or one over another hash, is taken as the authority's answer to a new request. | The reference authority adapter sends a fresh nonce and asks for a SHA-256 imprint, and refuses a token that does not echo the nonce or has another imprint hash. An archived token has no request, so `verifyAnchor` checks it without either. | covered | `anchor-review.test.ts`: "sends a nonce in the request and accepts the token that echoes it"; `anchor-review.test.ts`: "refuses a recorded token answered to a new request (another nonce, or none)"; `anchor-review.test.ts`: "refuses a token with no nonce" |
| anchor-7 | D | An authority or a log answers an endless or huge body and the host runs out of memory. | Both reference adapters read at most `maxReplyBytes` (default `MAX_REPLY_BYTES`, 256 KiB), cancel the rest and refuse; an error answer's body is never read. | covered | `anchor-review.test.ts`: "reads at most maxReplyBytes, cancels the rest and refuses"; `anchor-review.test.ts`: "refuses an error answer without reading its body, and a reply with no body" |
| anchor-8 | T | A Rekor entry reports an index, tree size or root the log never signed. | The index is the entry's top-level `logIndex`; the size and root come from the signed checkpoint; the inclusion proof's own copies, when present, must agree, or the entry is refused (`log`). | covered | `anchor-review.test.ts`: "reads the top-level logIndex and the checkpoint's size and root: the inner copies may be left out"; `anchor-review.test.ts`: "refuses inner copies that disagree with the top-level index or the checkpoint"; `anchor-review.test.ts`: "refuses a checkpoint whose size or root line is not canonical" |
| anchor-9 | I | A head reaches the public log for an anchor that then fails, or a retry logs it twice. | The Rekor adapter asks the authority first: a refused time-stamp writes nothing to the log. | covered | `anchor-review.test.ts`: "a refused time-stamp writes nothing to the public log"; `anchor-review.test.ts`: "asks the authority, then Rekor, and the proof verifies offline" |

### AttemptCounters

Failed attempts across calls, per subject and per calling number, shared by every engine of a
workspace, for lockouts that outlive a call.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| attemptcounters-1 | S | A durable store loses or reorders failures, so a guesser gets more tries than the lock allows. | `attemptCountersContract`, which the memory store passes and which catches a store whose removal is wrong or a no-op. | covered | `verify-counters.test.ts`: "MemoryAttemptCounters passes the AttemptCounters contract"; `verify-counters-hostile.test.ts`: "contract suite vs a store whose removeFailure is a no-op"; `verify-counters-hostile.test.ts`: "contract suite vs a store whose removeFailure removes the OLDEST failure whatever `at`" |
| attemptcounters-2 | S | A caller guesses across calls and engines. | Waits after each failure and a hard lock after 10 in 24 hours; two attempts racing on two engines judge only one. | covered | `verify-counters.test.ts`: "refuses during the wait without judging or using the call's attempt, then locks hard after 10 failures in 24 hours"; `verify-counters.test.ts`: "lets one of two attempts racing on two engines be judged, and refuses the other as locked" |
| attemptcounters-3 | I | A lock tells which accounts exist, or the store keeps a phone number. | An unknown subject is counted by its key too; a calling number is kept only as a keyed hash. | covered | `verify-counters.test.ts`: "counts an unknown subject by its key too, so a lock never tells which accounts exist"; `verify-counters.test.ts`: "keys a subject and a calling number apart, and never keeps the number" |
| attemptcounters-4 | E | A store missing a method, or one that throws, opens the lock. | The adapter's shape is checked when the engine is built, and a failing removal fails closed. | covered | `verify-counters-hostile.test.ts`: "each method missing, or a non-function value, is refused at construction"; `verify-counters-hostile.test.ts`: "removeFailure throws: the pass is already on the call, submit rejects, the failure stays (fail closed)" |

### CallbackDialer

Places a callback to the number on file as a new outbound call; the person confirms with keys.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| callbackdialer-1 | S | The caller steers the callback to a number they hold. | The engine dials the number on file, read from the store when it dials, never the calling number. | covered | `verify-callback-attack.test.ts`: "the caller cannot steer the number: calling number is never dialed"; `verify-callback-attack.test.ts`: "dials the number on file in the store when it dials, not the copy taken when verification began" |
| callbackdialer-2 | S | Voicemail, a replayed outcome or a forged reference passes the callback. | Only keys confirm; unknown, repeated and late outcomes are ignored, and a reference passes only its own callback. | covered | `verify-callback-attack.test.ts`: "voicemail-shaped outcomes never pass; replays and late outcomes are ignored"; `verify-callback-attack.test.ts`: "a ref from one callback cannot pass another call's callback" |
| callbackdialer-3 | D | Retries or concurrent requests ring the line many times. | One callback per call, a retried dial keeps its idempotency key, and a daily limit per subject. | covered | `verify-callback-attack.test.ts`: "two concurrent requests on one call: one ring, counted once, and both resolve"; `verify-callback.test.ts`: "dials again with the same key after a dialer that placed the call and failed to answer: one ring"; `verify-callback.test.ts`: "locks after a failed callback, and holds a daily limit per subject" |
| callbackdialer-4 | I | A dialer error tells the caller whether a number is on file. | A telephony error answers as a refusal does. | covered | `verify-callback-attack.test.ts`: "a telephony error answers as a refusal does, so the result never says whether a number is on file" |

### CodeStore

Send limits for texted codes, per subject and per calling number, shared by every engine of a
workspace. The codes themselves live in the call record.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| codestore-1 | D | A durable store ignores its limits, so codes are sent for SMS pumping. | `codeStoreContract`, which the memory store passes and which catches a store that ignores its limits. | covered | `verify-text-code.test.ts`: "MemoryCodeStore passes the CodeStore contract"; `verify-text-code.test.ts`: "fails a store that ignores its limits" |
| codestore-2 | D | Repeated calls send many codes to one subject or from one calling number. | 5 sends per subject per 24 hours, 60 seconds apart, and a limit per calling number across subjects. | covered | `verify-text-code.test.ts`: "allows 5 codes per subject per 24 hours, across calls"; `verify-text-code.test.ts`: "waits 60 seconds between sends, and a refused send keeps the live code"; `verify-text-code.test.ts`: "limits sends per calling number, across subjects" |
| codestore-3 | I | A refused send tells the caller they hit a limit. | Refused and sent sends look the same to the caller, with the same store calls before the reply. | covered | `verify-text-code.test.ts`: "refused and sent sends look the same to the caller"; `verify-text-code-hostile.test.ts`: "C1 with a calling number, a send refused by the subject's limit makes the same store calls before the reply as a sent one" |

### ConsentStore

The host's consent records, so a consent given on a call can be revoked after the call is gone.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| consentstore-1 | R | A revocation is lost, or a retry moves its time or channel. | Revoked once, the first revocation wins and the ledger has one entry; revocation works after the call record is gone. | covered | `consent-hostile.test.ts`: "V2 a consent revoked twice by different channels keeps the first, and the ledger has one entry"; `engine.test.ts`: "revokes from the store alone once the host removed the call record, and passes a session store failure through" |
| consentstore-2 | E | One workspace revokes or reads another's consent on a shared store. | Consents are keyed by workspace; another workspace's id is unknown. | covered | `consent-hostile.test.ts`: "V3 another workspace's consent id on a shared store is unknown here"; `prove.test.ts`: "keeps workspace and consent apart, whatever slashes they hold" |
| consentstore-3 | T | A store that is down records a consent that was never kept, or two processes record it twice. | A consent whose store is down settles as not recorded, which is no consent; two resumes record one. | covered | `engine.test.ts`: "ends a call whose consent store is down: the consent settles as not recorded, which is no consent"; `engine.test.ts`: "records one consent when two processes resume it at once" |

### DuressNotifier

Told when a caller enters a duress PIN, so the business can alert someone away from the call.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| duressnotifier-1 | I | The caller, or someone listening, can tell the alarm went off. | The caller gets the same answer, level, events and receipt as for the normal PIN, and the reply never waits for the notifier. | covered | `verify-duress.test.ts`: "gives the same answer, level, grant, events and receipt as the normal PIN"; `verify-duress-hostile.test.ts`: "answers the caller before the notifier runs at all" |
| duressnotifier-2 | D | A failing or slow notifier, or a failed ledger write, loses the alert. | The alert is owed in the same write as the entry and retried until the notifier answers, with the same alert id. | covered | `verify-duress.test.ts`: "keeps an alert owed until the notifier answers, and retries it on the next write, on flushLedger and on the host's sweep"; `verify-duress-hostile.test.ts`: "1. ledger append fails on the factor write: alert still goes out" |
| duressnotifier-3 | I | The alert carries the PIN. | The alert names the workspace, subject, call and time, never the PIN. | covered | `verify-duress.test.ts`: "is told of every duress entry, after the write and off the response path, with an alert id, the workspace, the subject, the call and the time, never the PIN" |

### FieldCipher

Encrypts a sensitive intake value with the host's key before the record is stored. The engine
never decrypts.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| fieldcipher-1 | I | A sensitive value reaches the ledger, the receipt, the stored record or the session in the clear. | The value is sealed before the record is stored; after filing, or once a draft is abandoned or dropped at the end of the call, the plaintext is kept nowhere. Until then, an open or filing draft holds it in the clear in the call record. | covered | `field-cipher-hostile.test.ts`: "G3: the plaintext is in no ledger entry, receipt, stored record or session after filing"; `field-cipher-hostile.test.ts`: "G4: an open draft dropped at endCall leaves no plaintext in the session store" |
| fieldcipher-2 | I | A cipher that fails or answers garbage gets the value stored in the clear, or in an error. | Such an answer is refused, nothing is stored, and the plaintext is in no error; an engine without the cipher refuses to file. | covered | `field-cipher-hostile.test.ts`: "G2: a cipher answering nothing usable is refused, nothing is stored, and the plaintext is in no error"; `field-cipher-hostile.test.ts`: "G5: an engine without the cipher on the same stores refuses to file, and the engine with it files the same record" |
| fieldcipher-3 | T | A ciphertext is moved to another record or field. | The cipher is given the workspace, record and field as context, to bind as additional authenticated data. | covered | `field-cipher-hostile.test.ts`: "G6: the context the cipher is given names this workspace, record and field, and cannot change the record" |

### Notifier

Tells the business that someone is locked out, best effort; the ledger stays the record.

| Id | STRIDE | Threat | Control | Status | Proof |
|---|---|---|---|---|---|
| notifier-1 | D | A notifier that throws, rejects or hangs blocks the call or the ledger. | Notices go out after the ledger entry, and a failing notifier never blocks either. | covered | `verify-lockout-alerts.test.ts`: "go out only after the ledger entry is written"; `verify-lockout-alerts.test.ts`: "never block the call or the ledger when the notifier throws, rejects or hangs, or the bookkeeping fails" |
| notifier-2 | I | A notice carries an account number, a phone number or what the caller keyed. | A notice names the counter and its keyed hash, never a value. | covered | `verify-lockout-alerts.test.ts`: "tell the business once per lock, however many attempts and engines it refuses, with the counter and never a value"; `verify-lockout-alerts.test.ts`: "name the calling number by its keyed hash, and tell a wait after a failure as well as a hard lock" |
| notifier-3 | D | An attacker runs up waits so a hard lock's notice is lost in the noise. | Hard locks' notices are kept apart from waits'. | covered | `verify-lockout-alerts.test.ts`: "keep the hard locks' notices apart from the waits', so waits an attacker runs up never hide a hard lock (review)" |

## Left to the host

- Routing keypad tones to a buffer outside the model, never logging them or the string its
  callback receives, and cutting audio to speech-to-text and the model while `sensitive` is set.
  `KeypadCollector` is that buffer (SPEC.md, section 20): it shows no digit, nor how many, through
  `toString`, JSON or `util.inspect`, discards an entry that is too long, idle or ends in an
  unexpected tone (ignoring the rest of it until `#` or `*`, so no tail is submitted), and gives
  the digits only to its one callback (tested). JavaScript cannot wipe a string, so the buffer is
  dropped, not overwritten.
- Authorizing the member behind `clearDuress` and `resetPin`: the engine takes the member id as
  given, so only the host's staff tools, after their own sign-in, may call them.
- Repeating a `clearDuress` only when a flag write's take-back fails: the counters store has no
  compare-and-set, so a flag written for an earlier entry (its own write, or its alert's) reads the
  count of clearings again afterwards and takes itself back over a clearing that landed meanwhile
  (tested); if that removal fails, the subject stays flagged (fail closed) until the business
  clears it again.
- Accepting that the hidden counter shows in the hard lock: because a duress entry never clears
  earlier wrong guesses, a caller who counts guesses can see the hard lock come sooner after a
  duress entry than after a real pass; waits and answers are unchanged (a kept trade-off).
- Buffering keypad digits outside the model, never logging them, and cutting audio to
  speech-to-text and the model while `sensitive` is set. The engine answers what may be forwarded
  in one place, `forwardingFor(state)`, which holds the transcript, both audio paths and listen-in
  together while `sensitive` is set and after the call ends (tested); acting on that answer on
  every path, and forwarding nothing when the state cannot be read, is the host's.
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
- A `FieldCipher` with authenticated encryption under a key the host keeps in a key store, binding
  the context (workspace, record, field) so a ciphertext moved elsewhere fails to decrypt; and
  protecting a durable `SessionStore` as it would the records, since an open draft is in the clear.
- Scheduling `anchorLedger` (daily, for example), keeping the authority's certificate chain and
  Rekor's key from a source it trusts, and choosing the authority and the log.
- Durable `SessionStore`, `RecordStore` and `AuditLedger` implementations that keep the same
  guarantees: they must pass `sessionStoreContract`, `recordStoreContract` and
  `auditLedgerContract` from `district-assurance/testing`, as the memory adapters do (tested); one
  durable `AttemptCounters` store shared by every process of a workspace
  (`attemptCountersContract`), and a durable `CodeStore` shared by every engine of a workspace that passes `codeStoreContract`. The reference server's
  `SqliteRecordStore` and `SqliteAuditLedger` (SRV-4) are an example that passes the record and
  ledger suites, not a production store. Scheduling `flushPending` on a session store with
  `pendingCalls`.
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
- Record delivery: keeping each destination's signing secret in a key store, a `RecordDelivery`
  adapter with a timeout that does not follow redirects, calling `deliverRecord` again (from a
  durable queue) for a record that was not delivered, and a receiver that checks the signature and
  applies each idempotency key once.
- Until the engine sends upload links itself: texting an upload link only to the number on file,
  never logging its token, and a `DocumentStore` whose `claimUploadLink` is atomic.
- Outside modules: their code runs inside the engine's writes and is part of the host's security
  model. So do factor judges, the host's plug-ins and those an outside module supplies: the
  engine counts and limits their attempts, but whether a judge answers the same way for an unknown
  subject and a wrong entry is the judge's.
- The person path: a caller who fails or cannot use a keypad reaches someone who can help.
- Relay and TTY callers: a flow they use offers a factor set they can complete at the step's
  level (a spoken answer alone reaches level 1 at most, and the carrier check and texted links
  still need a keypad or PIN match), or the host takes the call to the person path. Marking the
  call (`startCall({access})`) only from what the host knows of the call path, never from the
  model, and keeping the mark out of its own logs and transcripts.
- Spoken requests to repeat or slow down: the host replays its fixed line, and they never reach
  the engine.
- Disclosure that an automated assistant answers and that the call is transcribed.
- A security.txt (RFC 9116) for its own domain: its own contacts and policy, served over HTTPS by
  its TLS front end, signed if it wants (an OpenPGP cleartext signature), and renewed before it
  expires. The reference server can serve one from the host's settings; it never serves this
  project's address.
- Deciding who may switch these modules on (business verification), so the line cannot be used to
  run a phishing operation.
- Access and deletion requests: confirming who is asking before calling `exportSubject` or
  `eraseSubject`, deciding what the law requires in each case (and passing what it must keep, with
  the reason, as `kept`), the subject record itself, session and ledger retention, and a
  `RecordStore` whose deletes really delete (backups included).
