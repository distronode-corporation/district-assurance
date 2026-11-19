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
them apart. A PIN a caller chooses (`enrolPin`) is refused when every digit is the same, when it is
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
a wrong PIN, neither a login nor an alarm (tested). Every PIN ledger entry carries a
`tag` keyed to its event id and outcome, so only the holder of the knowledge key can tell a duress
pass from a normal one (tested); enrolling or removing a duress PIN writes nothing to the ledger.
A PIN reset removes the duress PIN too.

**Limits.** It does not stop someone who knows both PINs, or who makes the owner say which is
which. The code is public, so an attacker can learn exactly how a duress call behaves. A refused
action can itself be noticed by someone watching: the host speaks the same fixed line it uses for
any scope without a grant, but a payment that never happens is still visible. The notifier is best
effort; who it alerts, and how fast, is the host's. Anything the host sends after the call (PRV-10)
must follow the same rule as on a normal call, or it gives the duress away.

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

## Left to the host

- Buffering keypad digits outside the model, never logging them, and cutting audio to
  speech-to-text and the model while `sensitive` is set.
- Keeping the knowledge key and the receipt signing key in a key store.
- Durable `SessionStore`, `RecordStore` and `AuditLedger` implementations that keep the same
  guarantees (`sessionStoreContract` today; PRV-5 for the others).
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
- Outside modules: their code runs inside the engine's writes and is part of the host's security
  model.
- The person path: a caller who fails or cannot use a keypad reaches someone who can help.
- Disclosure that an automated assistant answers and that the call is transcribed.
- Deciding who may switch these modules on (business verification), so the line cannot be used to
  run a phishing operation.
