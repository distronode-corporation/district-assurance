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
Identity links are single-use by the provider. A document upload link is single use by an atomic
claim in the `DocumentStore`: of two uploads at once, one is stored (tested); it expires after 30
minutes and is bound to one call and one confirmed record of that call (tested). Left to the
host: whether keypad tones arrive as out-of-band events or as in-band audio on each carrier
bridge, since in-band tones can be replayed acoustically and can reach speech-to-text.

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
byte fails verification (tested). Planned: key rotation and a published key set history (PRV-1).
A step's ledger entries are saved with the step itself (an outbox in the call record) and
appended by event id, once each; a ledger that fails leaves them pending, and the next write or
`flushLedger` appends them, so no saved step is ever missing from the ledger for good (tested).

### Breach of stored data

**Controls:** reference values are HMACs under a per-workspace key, because a plain hash of a date
of birth is reversed by trying every date; the caller's entries are never stored. Sensitive intake
fields are refused by `validateConfig` until field encryption exists (FIL-2). PINs on file are
HMACs bound to their subject, or stay in the host's own PIN store (`verifier` mode). Upload link
tokens are 256 random bits and only their SHA-256 is stored, so a copy of the `DocumentStore`
yields no working link (tested).

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
- Until the engine sends upload links itself: texting an upload link only to the number on file,
  never logging its token, and a `DocumentStore` whose `claimUploadLink` is atomic.
- Outside modules: their code runs inside the engine's writes and is part of the host's security
  model.
- The person path: a caller who fails or cannot use a keypad reaches someone who can help.
- Disclosure that an automated assistant answers and that the call is transcribed.
- Deciding who may switch these modules on (business verification), so the line cannot be used to
  run a phishing operation.
