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
| The adapters the host plugs in | Everything the model says or proposes |
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
(tested). One-time access codes count against VER-2's per-subject send limit (5 texts in 24
hours, 60 seconds apart) in VER-2's `CodeStore`, the one texted codes use, so the two share a
budget; a limited request texts nothing (tested). Planned: VER-2's full limits (per calling
number, and a destination country allow-list) with texted codes; until VER-2 lands, the store's
interface here is a stand-in copy of its shape, and access codes do not yet apply the per-number
limit or the allow-list.

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
must pass `sessionStoreContract`.

### Prompt injection

A webhook reply, a CRM note or a document says "ignore the rules". **Controls:** `markUntrusted`
taints the session, drops the grant and sets the level to 0; a verification open when the taint
lands fails, granting no level from factors matched before or after it, so the caller must start
again; the next verification starts from no factors, and a photo ID link sent before the taint no
longer counts (tested). Fetched text never chooses a tool, a recipient or an amount: amounts come from
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
per payment, each with its own idempotency key, saved with the refund's intent before the provider
is asked and made of the payment and the refund's sequence number; a refund whose answer was lost
resumes with the same key, so the provider refunds once; the sequence number is required, so a
host that lost the engine's answer and asks again gets the committed refund's saved result back,
never a second refund (tested). A refund is refused while a dispute is open or
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

## Left to the host

- Buffering keypad digits outside the model, never logging them, and cutting audio to
  speech-to-text and the model while `sensitive` is set.
- Keeping the knowledge key, the receipt signing key, the access signing key and the access code
  key in a key store, the access key apart from the receipts'.
- A door keypad that slows after wrong access codes, and a durable `AccessCodeStore` whose
  `take` and `miss` are atomic across processes.
- Keeping the knowledge key, the receipt signing key, the access signing key and the step-up
  signing key in a key store, each apart from the others.
- Exchanging each step-up token through the engine (`exchangeStepUpToken`), and only for the
  browser session that showed its nonce.
- Calling `expirePaymentLinks` at each link's `expiresAt` (a timer or a sweep); until it does, a
  link lives as long as the provider keeps it.
- Keeping the knowledge key, the receipt signing key and the access signing key in a key store, the access key
  apart from the receipts'.
- Calling `expirePaymentLinks` at each link's `expiresAt` (a timer or a sweep); until it does, or
  the call ends, a link lives as long as the provider keeps it. Calling `endCall` again when it
  failed at the provider, so the call's open links are expired and its receipt issued.
- Refunding a late payment (one flagged `late` in the ledger) when the business does not want it.
- Durable `SessionStore`, `RecordStore` and `AuditLedger` implementations that keep the same
  guarantees (`sessionStoreContract` today; PRV-5 for the others).
- Choosing the subject when it starts verification with a subject key (for example the owner of
  the line it was called on). That choice is not a factor: the PIN or other factors still decide.
- A `PinVerifier` that answers the same way, in the same time, for an unknown subject.
- Who may edit a workspace's FlowConfig, and keeping its revisions.
- Keeping `refundPayment` on the business's side (a back office, staff tools), never on a tool the
  model can call, and deciding who in the business may ask for a refund.
- Outside modules: their code runs inside the engine's writes and is part of the host's security
  model.
- The person path: a caller who fails or cannot use a keypad reaches someone who can help.
- Disclosure that an automated assistant answers and that the call is transcribed.
- Deciding who may switch these modules on (business verification), so the line cannot be used to
  run a phishing operation.
