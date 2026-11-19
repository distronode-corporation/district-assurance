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
text never confirms an account. Failures are counted across calls per subject key, for unknown
subjects too, so a lock never tells a real account from a made-up one (tested), and per calling
number, so one line trying account after account is locked out (tested).

### Guessing

**Controls:** a per-call limit on judged attempts for every factor the caller enters (keypad
knowledge, the PIN at 1 to 5, plug-ins at 1 to 5), after which the line stops judging, even the
right answer (tested). Each attempt is counted in its own write before it is judged, so a crash, a
failing PIN verifier or a second process never gives a free try (tested, two engines on one
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
calling number (tested). Taking it off is a reset and a rewrite, not one atomic step, so a failure
another call records on the same number in that instant may be lost. Only a member's `unlock`
clears a number's counter outright, failures against other accounts included, so that is the
business's deliberate act, recorded in the ledger.

Lockout alerts (INT-7): after a `verification.locked` entry is written, the host's `Notifier` is
told the counter (the subject key, or the keyed hash of the calling number), the factor kind and
when the lock ends, never a value or a phone number (tested). A notice is told once per lock,
across engines, and a workspace gets at most 20 an hour, the last marked `capped`, so an attack
locking subject after subject cannot flood the owner; every lock stays in the ledger (tested). The
notifier is best effort and never awaited: one that throws, rejects or hangs never blocks the call
or the ledger (tested). `unlock` is a host call with no call id, so no call path reaches it; it
clears one counter (one factor kind, one scope, one key) and nothing else, writes
`verification.unlocked` with the member's id before clearing, and grants nothing: the caller still
verifies from no factors (tested). An unlock gives whoever is calling a fresh set of tries on
that counter, so who may make it is the host's. Without this, a
4-digit PIN with 3 attempts per call fell within about 3,300 calls; now an attacker gets at most
10 guesses per subject per 24 hours, about 3,650 a year against 10,000 PINs, so a 4-digit PIN
still needs watching (`verification.locked` in the ledger) and a longer PIN where the risk is
high. In `verifier` mode the host's PIN store is asked for every attempt, with a stand-in for a
malformed entry, so timing does not tell them apart.

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
must pass `sessionStoreContract`. Failure counters across calls are recorded in one atomic step
that returns what came before, so of two attempts racing on one subject only one is judged
(tested); a durable counter store must pass `attemptCountersContract`.

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

## Left to the host

- Buffering keypad digits outside the model, never logging them, and cutting audio to
  speech-to-text and the model while `sensitive` is set.
- Keeping the knowledge key and the receipt signing key in a key store.
- Durable `SessionStore`, `RecordStore` and `AuditLedger` implementations that keep the same
  guarantees (`sessionStoreContract` today; PRV-5 for the others), and one durable
  `AttemptCounters` store shared by every process of a workspace (`attemptCountersContract`).
- Passing the calling number from the carrier to `beginVerification`, never one the caller or the
  model gives. Caller ID can be spoofed, so the number's counter is a brake on one line, not a
  control; the subject's counter is what bounds guessing, and a withheld number skips the
  number's counter.
- A lockout is also a way to lock someone out: anyone who knows a subject (the owner of a line)
  can spend its 10 failures. The engine tells a `Notifier` of each lock (INT-7, below); acting on
  notices, the person path for a locked caller, who among the business's members may call
  `unlock`, and checking that the caller is real before doing so are the host's. `unlock` must be
  reachable only from the business's own tools, never from a call's tool paths.
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
