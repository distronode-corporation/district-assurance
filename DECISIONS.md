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

## ADR-10. Hash-chained ledger and ES256 receipts over canonical JSON

**Decided.** The ledger is a SHA-256 chain over RFC 8785 style canonical JSON; receipts are ES256
(P-256) signatures over the canonical body, with the key chosen by `kid` and the ledger head
inside.
**Why.** Canonical JSON makes the hash and the signature independent of key order and
whitespace, so any language can verify. ES256 is supported by every platform's crypto library and
by common key management services, so a host can keep the private key in a KMS behind
`ReceiptSigner`.

## ADR-11. Stripe webhook signatures are real, carrier ones are stubs

**Decided.** `verifyStripeSignature` is implemented and tested now; Twilio, Telnyx and Sinch
signature checks throw `NotImplementedError` and the reference server answers 501 on their routes.
**Why.** The demo needs signed identity and payment outcomes end to end, and Stripe's scheme is
small, public and testable without Stripe. Each carrier scheme differs (Twilio signs the URL and
form parameters, Telnyx uses Ed25519), and each will be built against the carrier's own test
vectors (SRV-1). Until then a carrier route can never be trusted by accident.

## ADR-12. The package is private until a release is decided

**Decided.** `package.json` has `"private": true`, so `npm publish` refuses. The name
`district-assurance` is not reserved on npm by this repository.
**Why.** Pre-alpha code should not be installable by accident. Publishing is a separate decision
with its own release workflow (provenance, reproducible packs), modelled on our other public
packages.
