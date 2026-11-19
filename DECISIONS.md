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
repositories).
**Why.** Every dependency of a security library is part of its security. The receipt format
(canonical JSON plus a raw P1363 signature) is simple enough that a JWS library buys nothing; the
Stripe calls the reference server will make are a few `fetch` requests. **Revisit** if JWS
interoperability is needed (a receipt as a compact JWS is a small change), or SAML or similar
arrives.

## ADR-4. Node 24.2 or later

**Decided.** `engines: >=24.2`; CI runs 24.2 and the latest 24 on Linux, macOS and Windows.
**Why.** Node 24 is the current LTS line, runs the TypeScript sources directly (type stripping),
and 24.2 adds `import.meta.main`, which the demo uses. A host on an older line would be on an
unsupported Node by the time this reaches 1.0.

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

## ADR-12. The package is private until a release is decided

**Decided.** `package.json` has `"private": true`, so `npm publish` refuses. The name
`district-assurance` is not reserved on npm by this repository.
**Why.** Pre-alpha code should not be installable by accident. Publishing is a separate decision
with its own release workflow (provenance, reproducible packs), modelled on our other public
packages.

## ADR-13. A small core plus modules, switched by config

**Decided.** The core holds the session state machine, the policy and its levels, redaction, the
module registry and the audit ledger. Badge, Dossier, Paylink and Trace are modules, Gate will be
the fifth, and a host adds its own with `engine.use(module)`. A module declares, in code, what it
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
is counted in its own write before it is judged. Plug-ins get `hmac(data)`, never the key. No
factor may be named for caller ID. A PIN or keypad match unlocks texts to the number on file; a
plug-in's match does not. `returning_pin` is replaced by `pin`; enrolment is VER-6.
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
ships first. Badge stays identity only. It is built in the second pull request of the modular
core; `gateModule()` throws `NotImplementedError` until then.
**Why.** Access is an outcome, like a record or a payment, with its own format, adapter and
failure modes; folding it into Badge would make identity code decide about doors.

## ADR-19. Paylink takes payments in one of two modes

**Decided.** Per flow step, `connect` (the business's own Stripe account, direct charges; the
business is the merchant) or `platform` (the platform's account; the platform is the merchant).
One `PaymentLinks` adapter shape, with the mode and an optional connected account on the request.
The engine still never sees card data. Built with PAY-7 in the second pull request; until then
`validateConfig` refuses a step with a `mode`, citing PAY-7, so no config can reach it mid-call.
**Why.** Both kinds of host exist: a business that takes its own money, and a platform that sells
on its own account. One adapter shape keeps the engine's payment rules the same for both.

## ADR-20. Owner command is the first live use

**Decided.** The first flow a host runs live is `owner-command`: Badge with a PIN only, plus Trace
(the ledger; no receipt step), granting `owner.command` at level 1 and nothing else. It replaces a
host's own owner PIN check on its phone line, before Dossier or Paylink go live. The PIN factor
and the shared session store are on its critical path, and so were built first. VER-1 (lockouts across
calls) is a hard gate: no host runs it on a live line before VER-1 is merged.
**Why.** It is the smallest flow that proves the engine on a real line: one factor, one scope, no
money and no customer data, run across the host's processes. Its scopes stay below the floors, so
an owner command can never move money or change contact details at level 1.

## ADR-21. Caller ID attestation is a cap, off by default (VER-10)

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
