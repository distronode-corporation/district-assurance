# Decisions

Architecture decision records, newest last. Each says what was decided, why, and what would
change it.

## ADR-1. An engine plus a reference server, nothing else public

**Decided.** This repository holds a TypeScript library (the engine) and a small runnable reference
server with a demo. Call handling, carrier routing, regional deployment, key management and
anything specific to one host's infrastructure stay out of it.
**Why.** The engine's rules (how factors combine, what a receipt proves, what a webhook may
change) are what outsiders need to read and trust. Hosting details are not, and publishing them
would only widen the attack surface. **Revisit** if a second host needs a shared piece that is
not engine logic.
**Amended by ADR-30:** the Stripe adapters and the carrier Lookup parsers are now public entry points.

## ADR-2. One package, not a workspace

**Decided.** One npm package with folders per module (`core`, `verify`, `file`, `pay`, `prove`,
`webhooks`) and two entry points (`.` and `./testing`). The reference server lives in
`examples/reference-server/` and imports the sources directly; it has no `package.json` of its
own.
**Why.** The modules share one session, one policy and one ledger: splitting them into packages
would version together anyway, and a workspace adds a lockfile per package, cross-package builds
and a second install for the example. One package keeps `npm ci` to one install, and folder
boundaries are enough to keep modules apart (`verify`, `file`, `pay` and `prove` import only
`core`; `webhooks` imports one type from `pay`; `engine.ts` composes them). **Revisit** when a host wants one module without the others, for
example the ledger alone, which would become `district-assurance-prove`.
**Amended by ADR-13:** modules are now switched by config inside the one package. Paylink imports
Badge's `matchedSubject` (a link goes to the number Badge matched); the other boundaries hold.

## ADR-3. No runtime dependencies

**Decided.** `node:crypto` provides SHA-256, HMAC, constant-time comparison and ES256. No `jose`,
no Stripe SDK, no schema library. Development tools only, pinned exactly: `typescript`,
`@types/node`, `oxlint`, `c8` (with the same `test-exclude` overrides as our other public
repositories), `fast-check` for the property and fuzz suites (SRV-7), and `stripe` for the
`StripeClientLike` type test and the byte comparison (ADR-30), none of which `files` ships.
**Why.** Every dependency of a security library is part of its security. The receipt format
(canonical JSON plus a raw P1363 signature) is simple enough that a JWS library buys nothing; the
Stripe calls the reference server will make are a few `fetch` requests. **Revisit** if JWS
interoperability is needed (a receipt as a compact JWS is a small change), or SAML or similar
arrives.

## ADR-4. Node 24.19 or later

**Decided.** `engines: >=24.19`; CI runs 24.19 and the latest 24 on Linux, macOS and Windows.
**Why.** Node 24 is the current LTS line and runs the TypeScript sources directly (type
stripping). `crypto.argon2`, which PIN records use (ADR-29), arrived in 24.7.0 as a release
candidate (stability 1.2) and is stable from 24.19.0, so 24.19 is the first release whose API
for it is no longer experimental. The floor was 24.2 (the first with `import.meta.main`); the
entry points still do not rely on it. A host on an older line would be on an unsupported Node by
the time this reaches 1.0.

## ADR-5. Internal segment names in code

**Decided.** `verify`, `file`, `pay`, `prove` in code, types and documents until the product names
are chosen. Marketing names will be applied to documentation and product surfaces, not to module
paths, so the API does not change when a name does.
**Amended by ADR-13:** the product names are chosen (Badge, Dossier, Paylink, Trace, Gate) and are
the module names in the registry, in FlowConfig and in step types (`badge.verify`), because a
config is read by people. Folders and the pure helpers keep `verify`, `file`, `pay`, `prove`.

## ADR-6. Planned work throws `NotImplementedError` with an issue id

**Decided.** Every planned entry point exists now with its intended signature and throws
`NotImplementedError(feature, issue)`. A test checks that each one throws and that its issue id is
in ROADMAP.md.
**Why.** Hosts can wire against the final shape now; a call into unbuilt work fails closed and
says where the work is tracked; the roadmap and the code cannot drift apart silently.

## ADR-7. 100% coverage on every file in `src/`

**Decided.** c8 holds lines, statements, functions and branches to 100% per file, a file no test
loads included. Stubs are covered by the test that proves they throw.
**Why.** This is security code; an untested branch is an unknown branch. The reference server is
tested but not held to the bar, since it is an example.

## ADR-8. All keypad fields judged together

**Decided.** `submitKeypad` takes every configured field at once and returns one `matched`
boolean. An unknown subject gives the same answer, the same ledger detail and the same work.
**Why.** Judging fields one at a time tells a caller which one was wrong, and judging the account
number first tells them which accounts exist.

## ADR-9. Levels have floors the business cannot lower

**Decided.** `payment.*`, `payout.*` and `contact.*` scopes need at least level 2 (two different
factors). Level 3 always includes `photo_id`. A texted code is never a factor alone, and it does
not count without a clean carrier answer unless the policy opts in.
**Why.** A weakly verified caller who can change the phone number on file owns the account from
then on. These floors are the minimum that stops that, whatever a business configures.
**Amended (modular core review):** floors follow a scope's class, not only its name. Every scope
has a class (money, contact, access or none), from its name, a module's manifest or the policy's
`scopeClasses`, the strictest winning; a scope with no class is refused, so `refund.issue` or
`transfer.funds` cannot slip under level 2. Level 2 and above also need a factor that is not
knowledge (texted code, carrier identity match or photo ID), so keypad plus PIN is not level 2.

## ADR-10. Hash-chained ledger and ES256 receipts over canonical JSON

**Decided.** The ledger is a SHA-256 chain over RFC 8785 style canonical JSON; receipts are ES256
(P-256) signatures over the canonical body, with the key chosen by `kid` and the ledger head
inside.
**Why.** Canonical JSON makes the hash and the signature independent of key order and
whitespace, so any language can verify. ES256 is supported by every platform's crypto library and
by common key management services, so a host can keep the private key in a KMS behind
`ReceiptSigner`.

## ADR-11. Stripe webhook signatures are real, carrier ones are stubs

**Decided.** `verifyStripeSignature` is implemented and tested now; Twilio and Telnyx
signature checks throw `NotImplementedError` and the reference server answers 501 on their routes.
**Why.** The demo needs signed identity and payment outcomes end to end, and Stripe's scheme is
small, public and testable without Stripe. Each carrier scheme differs (Twilio signs the URL and
form parameters, Telnyx uses Ed25519), and each will be built against the carrier's own test
vectors (SRV-1). Until then a carrier route can never be trusted by accident.
**Amended (modular core):** the carriers are Twilio and Telnyx. Sinch is out of scope for now; its
stub and route are removed, and `CarrierSignals` stays vendor-neutral so it can be added later.
**Amended (SRV-1):** both carrier checks are built and tested (SPEC.md, section 27); the stubs
and the 501 answers are gone.

## ADR-12. The package is private until a release is decided

**Decided.** `package.json` has `"private": true`, so `npm publish` refuses. The name
`district-assurance` is not reserved on npm by this repository.
**Why.** Pre-alpha code should not be installable by accident. Publishing is a separate decision
with its own release workflow (provenance, reproducible packs), modelled on our other public
packages.
**Amended (SRV-5):** the release workflow is built (`.github/workflows/release.yml`); the package
stays private until the pull request that decides the first release removes `"private": true`.
**Amended (first release, Sean, 2026-11):** the first release is 0.1.0. Its release pull request
removes `"private": true`, and from 0.1.0 on every version is published by `release.yml` from its
tag through npm trusted publishing, with provenance. The name is reserved on npm by the
package's owner with a hand-published placeholder version below 0.1.0, since npm sets a trusted
publisher only on a package that exists; the placeholder is not a release. The fork dry run
SRV-5 asked for is replaced by the dry run a tag push runs in this repository before anything is
published.

## ADR-13. A small core plus modules, switched by config

**Decided.** The core holds the session state machine, the policy and its levels, redaction, the
module registry and the audit ledger. Badge, Dossier, Paylink and Trace are modules, Gate is the
fifth, step-up the sixth (ADR-18, ADR-24, ADR-25), and a host adds its own with `engine.use(module)`. A module declares, in code, what it
provides (factors, flow steps, outcomes), the scopes it grants or needs, the adapters it requires,
and a validator for its settings. Installing and removing is code (`use`, `remove`); turning an
installed module on or off is the workspace's FlowConfig. A module turned on after a call started
is refused on that call.
**Why.** The same engine has to serve a PIN check before an owner's command and full verification
with a payment during the call, or secure entry, and an open-source user has to be able to take
only what they need. A fixed four-step engine could do one of those. Declarations in code let the
registry and the validator refuse a clash or a missing adapter before any call runs. **Revisit**
if modules need their own release cycle (ADR-2).

## ADR-14. Flows are versioned config, validated whole, run step by step

**Decided.** A workspace's FlowConfig (format version 1, plus the host's own `revision`) holds the
policy, the module switches and settings, and named flows, each an ordered list of steps.
`validateConfig(config, registry)` returns every problem at once, each with its path, and never
throws; the engine refuses a config with any problem. A call copies its flow's steps when the flow
starts and runs them one at a time: work that is not the current step's is refused, only the
step's factors count toward its level, the step's own amount is the payment's amount, and a
`badge.verify` step can name the scopes its grant covers. No UI: config and API first.
**Why.** A host must be able to refuse a bad config when an operator saves it, not discover it in
the middle of a call, so the validator lists everything and is exercised on garbage. Copying the
steps means a config change never moves a call. Refusing off-step work means a flow cannot be
skipped by calling the API in another order. Scopes are granted by level, so without a step's
`scopes` a keypad-verified caller would also hold any other scope at that level, `owner.command`
included; listing them keeps each grant to its purpose. **Revisit** when a flow needs branching
(a step chosen by an earlier outcome): that would be format version 2.

## ADR-15. Badge factors are plug-ins; the PIN is one

**Decided.** Each factor kind says how it reaches the engine, its attempt limit and its adapters;
Badge's settings turn factors on, and a host adds a factor the caller enters with
`badgeModule({ factors })`. The new `pin` factor compares against a keyed hash bound to the
subject (`HMAC(key, "pin:" + subjectKey + ":" + pin)`), or asks the host's own `PinVerifier` (for
example a scrypt store). 4 to 12 digits, 1 to 5 attempts per call. Every entered factor's attempt
is counted in its own write before it is judged. Plug-ins get `hmac(data)` (asynchronous since
INT-4, so the key can stay in a key management service), never the key. No factor may be named for
caller ID. A PIN or keypad match unlocks texts to the number on file; a plug-in's match does not. `returning_pin` is replaced by `pin`; enrolment is VER-6.
**Why.** The first live use is a PIN check (ADR-20), and hosts already keep PINs in their own
stores, so both a keyed hash and a verifier are needed. Counting before judging means a crash or a
second process never yields a free try. Binding the digest to the subject stops two equal PINs
from having equal digests. **Revisit** with VER-1 (lockouts across calls), which a short PIN needs
before a live line.

## ADR-16. Sessions in a shared store, with compare-and-set (INT-3)

**Decided.** A call is one JSON record in a `SessionStore`, written only by compare-and-set on a
version per session. Every engine step reads, applies one pure change and writes; a lost write is
retried from a fresh read, five attempts, then `conflict`. Ledger entries follow a successful
write. Steps with side effects reserve first (an attempt, a link) and commit after. Provider
references are bound in the store. `MemorySessionStore` is the reference, and
`sessionStoreContract` is a runner-agnostic suite (cases as plain async functions) any durable
store must pass. The engine's reads (`state`, `authorize`, `receipt`) became asynchronous.
**Why.** A host runs the engine in more than one process (a voice agent and a web backend, several
replicas), so a call's state cannot live in one process's memory, and two processes must never
both win the same attempt or both send a link. Compare-and-set is the simplest primitive every
database offers (a version column). The contract suite does not import a test runner, so a host
on vitest or jest can run it. **Revisit** if a host needs transactions across calls (counters,
VER-1, are a separate adapter).

## ADR-17. The ledger is always on; receipts and consent are optional

**Decided.** Trace is the one `alwaysOn` module: it cannot be turned off or removed, the engine
refuses to start without a `ledger` adapter, and every module's events go to the same chain.
Receipts are per flow (a `trace.receipt` step) or, for calls without a flow, Trace's `receipts`
setting (default on); consent wordings live in Trace's settings. A workspace without receipts
needs no signer.
**Why.** The ledger is what makes every other module's claims checkable after the fact, so a
config must not be able to switch it off, even by mistake. A receipt is a product choice (an
owner's own command needs none; a deposit does), and a signer is real key management a small host
may not want for every flow.

## ADR-18. Gate is the fifth module

**Decided.** Secure entry, physical and digital, is a module of its own (GAT-1): after
verification it produces a signed, time-limited access grant (ES256 over canonical JSON, as
receipts), delivered through an `AccessController` adapter (a door controller webhook, a one-time
access code, a web sign-in step-up). It refuses without a valid verification grant, and every
grant goes to the ledger. The real adapters stay `NotImplementedError` with their ids; a fake
ships first. Badge stays identity only. Built in the second pull request of the modular core
(ADR-21, ADR-22).
**Why.** Access is an outcome, like a record or a payment, with its own format, adapter and
failure modes; folding it into Badge would make identity code decide about doors.
**Amended:** the real adapters are built: the signed-webhook relay, Seam, Kisi and Verkada
controllers, one-time access codes and web sign-in step-up (ADR-22, ADR-24, ADR-25).

## ADR-19. Paylink takes payments in one of two modes

**Decided.** Per flow step, `connect` (the business's own Stripe account, direct charges; the
business is the merchant) or `platform` (the platform's account; the platform is the merchant).
One `PaymentLinks` adapter shape, with the mode and an optional connected account on the request.
The engine still never sees card data. Built with PAY-7 in the second pull request (ADR-23).
**Why.** Both kinds of host exist: a business that takes its own money, and a platform that sells
on its own account. One adapter shape keeps the engine's payment rules the same for both.

## ADR-20. Owner command is the first live use

**Decided.** The first flow a host runs live is `owner-command`: Badge with a PIN only, plus Trace
(the ledger; no receipt step), granting `owner.command` at level 1 and nothing else. It replaces a
host's own owner PIN check on its phone line, before Dossier or Paylink go live. The PIN factor
and the shared session store are on its critical path, and so were built first. VER-1 (lockouts
across calls) was the hard gate for a live line, and is built.
**Why.** It is the smallest flow that proves the engine on a real line: one factor, one scope, no
money and no customer data, run across the host's processes. Its scopes stay below the floors, so
an owner command can never move money or change contact details at level 1.

## ADR-21. Access grants are signed like receipts

**Decided.** An access grant is a small body (grant id, workspace, audience, target, action, scope,
level, issued and expiry times) signed with ES256 over its canonical JSON (`signDocument`, the
receipt code generalised), under the access signer's own `kid`. It never outlives the call's
verification grant and lives 10 to 900 seconds, 60 by default. The ledger gets `access.issued` and
the outcome with the grant's digest, never the grant. A verifier must name the workspace it serves:
grants are bound to their workspace as well as their audience. Outside modules see the current
step, the engine's clock and an id source.
**Why.** One signing format for receipts and grants means one verifier in every language.
**Superseded in part by ADR-25:** Gate first ran on the outside module path, with its answers
written through `recordModuleOutcome` and judged by the module's own `checkOutcome`. Four rounds of
hostile review broke that design, and Gate is now built in (ADR-25).
**Revisit** when Gate needs a receipt part (access on the call's receipt).

## ADR-22. The signed-webhook relay first; an unlock is never retried

**Decided.** The first real `AccessController` is `webhookRelay`: it POSTs the signed grant to a
small relay on the site's network, which verifies it with the public key (`verifyAccessGrant`),
refuses a grant id it has seen (`SeenGrants`) and works the door. The grant's ES256 signature is
the webhook's signature; there is no shared HMAC secret, so a relay that is taken over cannot
mint grants. HTTPS only (HTTP to the loopback for tests and the demo), no redirects, a 5 second
timeout, one request. A 2xx is delivered, a 4xx refused, anything else unknown. Gate never retries
an unlock: one grant in flight per call, a lost answer recorded as `unknown`, and opening again is
a fresh request with a new grant, up to `maxGrantsPerCall` (default 3). Seam (GAT-5) and direct
vendor adapters (GAT-6) came after the relay, as did one-time codes (GAT-3) and web step-up
(GAT-4); all four are built now, under the same never-retry rule.
**Why.** The maintainers' decisions of 2026-11-18: the relay first (no vendor account, testable in CI, the
escape hatch for any door system), Seam after its pricing and Canadian data handling are
checked, and a lost unlock never retried, because a retry can open a door twice for a caller who
is no longer there. GAT-2's original text asked for an HMAC header and one retry; both are
superseded by this record. GAT-1's original `revoke` and `gate.revoked` are dropped by design: a
momentary unlock that lives at most 15 minutes has nothing to revoke once sent, and revoking an
issued code is part of one-time codes (GAT-3). **Revisit** if a relay needs to refuse junk before parsing (an
optional HMAC header could be added without changing the grant).

## ADR-23. Two payment modes, a link life the engine enforces, instant methods only

**Decided.** Each `paylink.request` step chooses `connect` (the business's own account at the
provider, a direct charge, the business is the merchant) or `platform` (the platform's account,
the platform is the merchant); Paylink's settings give the default (`platform`) and the
`connectedAccountId` that connect mode needs, and the validator refuses connect without it. The
request to the one `PaymentLinks` adapter carries the mode, the account in connect mode, the
payment methods and the engine's deadline; the idempotency key includes the mode. A link lives
`linkLifeMinutes` (5 to 60, default 15) from when it was texted, and the engine expires it itself
at that deadline (`expirePaymentLinks`, through the new `PaymentLinks.expireLink`), because
Stripe Checkout's shortest `expires_at` is 30 minutes. Two times are kept apart: the provider
expiry (`providerExpiresAt`, set when the request is reserved, from twice the link life within the
adapter's declared range, plus a margin over its minimum) is what `createLink` receives as
`expiresAt`; the engine's deadline (the text plus the link life, never past the provider expiry) is
what `requestPayment` returns and `expirePaymentLinks` enforces. The engine has no timer: the host
must call `expirePaymentLinks` at `expiresAt` (a timer or a sweep), or the link stays payable until
the provider expiry, and a payment in that window is still recorded. A link may offer only methods that settle
during the call: card (credit, and Visa and Mastercard debit), Apple Pay, Google Pay and Link, the
default; the validator refuses anything else, pre-authorized debit and Interac by name. A
provider outcome whose connected account is not the payment's is ignored and written to the
ledger. Receipts and `payment.link_sent` carry the mode. **Amended (hostile review of PR 2):** the
payments adapter declares its capabilities (modes, shortest and longest link life), the validator
holds steps and settings to them, and the provider is asked for a life inside them; a link with
less than 5 minutes of the provider's life left is expired, never texted; a `connectedAccountId`
needs an explicit mode.
**Why.** The maintainers' decisions of 2026-11-18: both modes, chosen per flow; the engine expires links at 15
minutes by default, configurable from 5 to 60; any popular method that settles while the person
is on the call. Stripe documents Interac only in person and pre-authorized debit settles in days.
Checking the account stops an event from one business settling another's payment. **Revisit**
when Stripe offers Interac in online Checkout, or a provider's methods need mapping the validator
cannot see. PAY-1 proved the Checkout mapping in Stripe test mode: Apple Pay and Google Pay go
as `card`, and Link only beside `card`.

## ADR-24. Web step-up is an ES256 JWT checked against a JWKS

**Decided.** GAT-4 issues a compact JWS (`alg: ES256`) bound to a nonce the site
showed and the caller keyed, checked by the site with any JOSE library against a published JWKS.
Receipts and access grants keep canonical JSON. No OpenID Provider (CIBA) for now.
**Why.** Sites already verify JWTs against a JWKS (sign-in with large identity providers works the
same way); running a full OpenID Provider is too heavy for a small business. node:crypto signs
ES256 in the JWS format already, so this needs no runtime dependency (ADR-3). **Revisit** for
enterprise hosts that want CIBA.

## ADR-25. The engine owns access outcomes; Gate is built in

**Decided.** Gate is a built-in module, like Paylink. Its door controllers (`access`, by name) and
its grant signer (`accessSigner`) are engine adapters, and the config turns it on. The engine
itself reserves each grant, signs it, computes its digest from the frozen grant it signed, calls the
controller once, and records the controller's actual answer (`delivered`, `refused` or `unknown`)
with its ledger entry, all in its own writes. The module only proposes the intent: the targets
(door, controller) in its settings, and the step's lifetime; level, workspace and expiry come from
the call. No module code can write a grant or its outcome: `updateModule` and `moduleState`
refuse every built-in module, and the outside-module outcome API of earlier drafts
(`recordModuleOutcome`, reservations, `outcomeRecord`, `checkOutcome`) is removed. An outside
module's `updateModule` is held by the engine to its manifest's scopes on every call: in a flow,
the current step's; outside a flow, all of them. Ending a call settles a grant still in flight as
`unknown` if it was not yet signed, and is refused while a signed grant is at its door (until its
answer is recorded or it expires, after which a relay refuses it), so no access outcome ever
follows `receipt.issued` (re-issuing a receipt is not supported, so nothing is ever appended under
one). No door acts on a grant after the receipt only while the relay keeps accurate time: the
relay judges the expiry by its own clock, so a relay whose clock runs behind the engine's accepts
a grant for that much longer (SPEC.md, section 17). Holding the end, rather than a lock across
the unlock, keeps the engine free of locks: the wait is bounded by the controller's timeout, or by
the grant's lifetime (at most 15 minutes) if its process stopped. Built-in module names are the
engine's for good, and the access signer must be a key of its own.
**Why.** Four rounds of hostile review on PR 2 each found a new way for a module's own code to
write an outcome the controller never gave: a forged grant beside a pending one, a reserved grant
re-pointed or lowered, the same reservation settled again, a digest the engine never signed, a
write through `updateModule` that skipped the outcome checks entirely, and a late answer landing
after the receipt. Each patch closed one path while the root cause stayed: the module could write
outcome state, and the engine trusted the module's judgement of it, while the controller's real
answer lived only in the module's memory. Moving the outcome into the engine removes that trust
instead of policing it: there is no write path left to attack. A late door answer recorded as
`unknown` when the call ends is honest (the engine does not know), and keeps the receipt final.
**Revisit** if a host needs its own access module with engine-held outcomes: that would be a
generic "held work" contract in the core (the engine calls an adapter the module names and records
its answer), designed once, not per module.
**Amended (GAT-3):** a one-time access code's grant is `delivered` when the code is texted, and
the door acts on it later, when the code is redeemed, which may follow `receipt.issued` (until the
grant expires, at most 15 minutes). The ledger still gets no access entry after the receipt: the
redemption is the door's to log, and the host revokes a code it no longer wants.
**Amended (GAT-4):** web sign-in step-up is built in on the same terms: the engine reserves,
signs and validates each step-up token and records its one exchange, under the `stepUpSigner`
adapter (a key of its own, apart from the receipt and access signers). The write that ends a
call fails a token still being signed and refuses every issued token its call no longer vouches
for (tainted, a new verification running, or another grant). Whether a token issued for the grant
the call still holds at its end stays exchangeable until it expires (at most 5 minutes), with its
exchange entry then written before or after `receipt.issued`, is a pending decision; the code does so for now,
and the receipt lists the call's tokens.

## ADR-26. Caller ID attestation is a cap, off by default (VER-10)

**Decided.** A call records, once when it starts, the STIR/SHAKEN attestation its host's carrier
reported (`A`, `B`, `C`, `failed` or `none`). It is never a factor. The policy's optional
`attestationCaps` sets, per value, the highest level a call with it can reach; a cap only lowers a
level. By default there are no caps: the attestation is written to `call.started` and the receipt
and changes nothing. A business turns caps on in its policy.
**Why.** An attestation says how much the signing carrier knew about the calling number, never
who is speaking, so it can make a call count for less but never for more. In Canada and the United
States, `C` or no attestation is common for genuine callers (calls from abroad, and calls whose
signature was lost on an older, non-IP network), so caps on by default would turn genuine callers
away. **Revisit** if carriers' coverage makes a missing or `C` attestation rare for genuine callers.

## ADR-27. A record's digest covers the plaintext, with sensitive values keyed (FIL-2)

**Decided.** A sensitive intake value is encrypted by the host's `FieldCipher` before the record
is stored; the engine never decrypts. The record's digest, which the ledger and the receipt
carry, covers the values the caller confirmed, not the ciphertext, and each sensitive value
enters it as `HMAC-SHA256(knowledgeKey, canonicalJson(["intake", recordId, field, value]))`.
**Why.** A digest over the ciphertext would change whenever the cipher does: a fresh nonce on a
retried filing, a host re-encrypting its records under a new key. Receipts already issued would
then point at nothing, and the digest would vouch for bytes rather than for what the caller
heard and confirmed. A digest over the bare plaintext would be stable, but a receipt is handed to
the caller and may travel further, and a short value (a nine-digit SIN with a check digit, a date
of birth) could be found by hashing every candidate with the other values. Keying it under the
workspace's knowledge key removes that, as it does for reference values (SPEC.md, section 5).
Binding it to the record and the field keeps two records with the same value apart, and the JSON
tuple keeps it apart from the `subject:`, `field:` and `pin:` digests, so it never equals a value
on file. A host checks a record against its receipt by decrypting it and computing the same HMAC.
Rotating the knowledge key makes old receipts uncheckable against their records, since the old
key is needed to recompute each sensitive value's HMAC; a host that rotates it keeps the old key
for checking.
**Revisit** if a third party without the knowledge key must check a record against its receipt:
that needs a per-record salt published with the record instead.

## ADR-28. Subject erasure deletes values and keeps digests (PRV-7)

**Decided.** `eraseSubject` deletes a subject's intake records, the copy of their values a call
record keeps, and their PIN digest, through the stores, and appends `subject.erased`. It never
changes or removes a ledger entry or a receipt. The record digests already in the ledger and in
receipts stay, as integrity records kept for the retention period, and `exportSubject` lists them
as kept, with that reason. The export is signed with the receipt key under its own domain (the
signed bytes start with `district-assurance/subject-export/v1`), so it never verifies as a receipt.
**Why.** The ledger is append-only and hash-chained and receipts are signed: removing an entry or
editing a digest would break every hash after it and every signature that covers it, and the
record of what happened is what the business needs to show later. Neither holds a value, only ids
and digests (SPEC.md sections 9 and 12). But a digest is not anonymous: apart from sensitive values,
which it covers keyed (ADR-27), it is an unkeyed SHA-256,
and a short or guessable value (a yes/no answer, a date, a short phrase) can be confirmed by
anyone who guesses it and hashes it. So the ledger and receipts stay personal information for
retention and access control, and the business decides, case by case, what the law lets it keep.
**Would change it.** Keyed or salted record digests whose key can be destroyed per subject (a
change to the receipt format, so a new version), or a regulator's guidance that the digests must go.

## ADR-29. PINs are Argon2id over the keyed HMAC

**Decided.** In `keyed_hash` mode a PIN or duress PIN on file is
`$pin1$argon2id$v=19$m=19456,t=2,p=1$<salt>$<tag>`: Argon2id (`node:crypto`, RFC 9106) whose
message is the 32 bytes of the keyed HMAC the engine already computed,
`HMAC-SHA256(knowledgeKey, "pin:" + subjectKey + ":" + pin)` (or `"duress:"`), with a random 16-byte
salt and a 32-byte tag. `pin1` names the construction, and the algorithm, version and cost are in the
string. A record is read strictly: any cost but today's, below it (a downgrade) or above it
(refused before any run: a dearer record would take longer to check than the stand-in an unknown
subject gets), another algorithm, version or spelling, never matches.
Every check is one Argon2id run (on a stand-in at today's cost when no usable record is on file)
and a constant-time compare of the tag. A record of the earlier format, the bare 64-hex HMAC, still
verifies, and on a match the PIN factor replaces it with an Argon2id record through
`RecordStore.upgradePinDigest`, a compare-and-set on the old value (rehash on login), best effort:
a failed hash or write keeps the outcome, and the next match verifies whichever record it left. Lockouts,
counters and answers are unchanged. Keypad knowledge stays a keyed HMAC.
**Why.** The keyed HMAC alone kept records useless without the knowledge key, but anyone holding
both the store and the key could try every PIN at HMAC speed; OpenSSF's `crypto_password_storage`
asks for an iterated, salted, key-stretched hash. Argon2id over the HMAC, rather than the HMAC as
Argon2's secret, keeps what the HMAC gave: the key can stay in a key store behind an HMAC function
(the engine never needs its bytes), each guess still needs the key, and the input to Argon2id is
already domain-separated (`pin:` and `duress:`) and bound to the subject. An earlier record is
exactly the Argon2id message, so it upgrades in place on the next match with no new key call. ADR-3
forbids runtime dependencies, so it is `node:crypto`'s Argon2, which sets the Node floor (ADR-4).
The cost is OWASP's minimum for Argon2id (19 MiB, 2 passes, 1 lane), chosen for a phone call: the
PIN factor runs two at once per entry (the PIN's and the duress PIN's, so the time never says
whether a duress PIN is on file), off the main thread on libuv's pool. The `PIN record check`
benchmark measures one run: about 21 ms on CI's `ubuntu-24.04` runner (4 cores, Node 24.19)
and about 30 ms on a 2018 laptop core (BENCHMARKS.md), and the two runs of an entry overlap, so
the whole owner-command flow, one PIN entry included, takes about 26 ms on the runner. The bar for a verify step is the pause a
caller hears after the last digit; that sits well inside the hundreds of milliseconds a carrier
and a speech engine already take, and an enrolment pays three runs. Records are not deterministic, so
the stores compare them as opaque strings and never look one up by value.
**Limits.** Stretching cannot make a 4-digit PIN strong: with the store and the key, 10,000 runs
find it. Custody of the knowledge key and the lockouts remain the main controls. A subject who never
calls again keeps an earlier record until a reset.
**Revisit** when the cost should rise (a new floor in `PIN_HASH_PARAMETERS`, with the old floor kept
as the lowest accepted and records below the new target rehashed on login, as the earlier format
is), or when Node changes the API.

## ADR-30. The Stripe adapters and the carrier parsers are public entry points

**Decided.** `district-assurance/stripe` publishes what a host needs to take payments by link in
test or live mode: `StripeCheckoutLinks`, Connect onboarding on Accounts v2, the Connect webhook
verifier and the key, mode and error types around them. `district-assurance/carrier` publishes the
Twilio and Telnyx Lookup field parsers. The adapters take a structural `StripeClientLike`, which a
stripe-node instance satisfies as it is and `fetchStripeClient` implements over `fetch`, so ADR-3
holds: no runtime dependency (stripe-node is a development dependency, for the type test and the
byte comparison only). The reference server uses these exports and keeps no copy of its own.
**Hosts own storage, credentials, rate limits and country policy.** Nothing in either entry point
stores a connected account, reads the environment, holds a key beyond the client a host builds, limits
how often a host calls Stripe or a carrier, or decides which countries a lookup covers. Each mode is
explicit: a key, a session id and every answer must be the mode's, and the verifying webhook secret
fixes an event's mode.
**Why.** A second host (ours) needed the same adapters, with live mode beside test, and porting
them by hand had already produced two copies that drifted (Checkout on endive takes
`allowed_payment_method_types`; the reference copy still sent basil's `payment_method_types`). The
rules in them (which mode a key, an id and an event are in; that an event names the stored account;
that an expire tells a close from a payment that won the race; that Stripe's message never leaves)
are what an outsider needs to read and trust, as ADR-1 says of the engine's rules.
**Revisit** if a host needs a provider other than Stripe for links, or the SDK's shapes move far
enough that a structural type no longer fits it.

## ADR-31. The owner PIN is the package's, over the engine's own stores

**Decided.** The owner PIN (ADR-20) is `createOwnerPin` in the package: the owner's subject key
(`subject:owner:<workspaceId>`), its PIN counters (the subject's and the line's), the lock facts a
business's tools show, and set, clear and lift, with a change resetting before it stores. It runs
over the adapters the engine already has (`Engine`, `KnowledgeHmac`, `RecordStore`,
`AttemptCounters`), plus one minimal interface, `SubjectWriter.createSubject` (create if absent,
atomic, never a rewrite), because the engine never creates a subject and the owner's must exist
before `putPinDigest` stores anything; a rewrite could drop a PIN another change just stored. Who may call
it, the owner's verified number, binding a phone call to an engine call, the key store and lock
notices stay the host's (ADR-1).
**Why.** These are rules every host of the owner command needs the same way, and a wrong order is a
security bug (a reset after the store, or a counter left out, would leave a line unguarded or a
lock unlifted); in the package they are tested to 100% with the engine they depend on. Reading the
PIN length and the lockout from the engine's config, rather than taking copies, keeps the facts
the business sees equal to what the engine enforces. **Revisit** if `RecordStore` gains an atomic
reset-and-replace (then a change never passes through no PIN), or a host needs the owner subject
under a key of its own.
