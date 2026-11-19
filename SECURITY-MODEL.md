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
- Whose account a payment lands on (the business's, or the platform's).
- The record of what happened on a call: the ledger and the receipts.
- The workspace's FlowConfig: which modules run, which factors count, which scopes a flow grants.

## Trusted and untrusted

| Trusted | Untrusted |
|---|---|
| The host's code paths that call the engine | Everything the caller says |
| The adapters the host plugs in | Everything the model says or proposes |
| The knowledge key, the receipt signing key and the access signing key | Caller ID and any number given on the call |
| The clock and id source | Webhook bodies until their signature verifies |
| The outside modules the host installs | Text from business endpoints, CRMs and documents |
| The door controllers and relays the host configures | A door relay's answer, beyond "took it", "refused" or "lost" |
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
problem, Trace (the ledger) cannot be turned off, the floors cannot be lowered (`entry.open` is
an access scope, never below level 2), planned factors cannot be turned on, a payment link can
offer only instant methods and live 5 to 60 minutes, connect mode cannot run without a connected
account, and every call's ledger entries carry the config revision
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
holds each grant's digest and outcome, never the grant. Left to the host: a relay that keeps seen
grant ids across restarts (or refuses every grant for 15 minutes plus the verifier's clock skew
after one), a relay clock kept in sync with the engine's (a grant's expiry is strict, so a relay
running behind accepts it that much longer), and the door's own safety
(an unlock pulse, not a latch).

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

### Card data and PCI DSS scope

**Controls:** Pay is by a hosted payment page; the engine sees a link id and a status, never a card
number. A link offers only methods that settle during the call (cards, Apple Pay, Google Pay,
Link) and lives 15 minutes from the text by default (5 to 60); the engine expires it itself at
that deadline, at the provider first, because a provider's shortest link life can be longer
(tested). Card numbers in transcripts are detected (Luhn, digits and English or French digit words)
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

## Open questions

- **Refunds and disputes in platform mode.** In `platform` mode the platform is the merchant of
  record, so a refund or a dispute lands on the platform's account, not the business's. Who
  carries them, and on what terms, is a legal and payment provider question that is not decided.
  The engine has no refund or dispute code in either mode; a host handles both at the provider.
- **Seam in the door path.** A paid third party between the engine and a door (GAT-5) waits on its
  pricing and its handling of Canadian data being checked.

## Left to the host

- Buffering keypad digits outside the model, never logging them, and cutting audio to
  speech-to-text and the model while `sensitive` is set.
- Keeping the knowledge key, the receipt signing key and the access signing key in a key store, the access key
  apart from the receipts'.
- Calling `expirePaymentLinks` at each link's `expiresAt` (a timer or a sweep); until it does, a
  link lives as long as the provider keeps it.
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
