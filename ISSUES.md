# Issues

Every open issue of [ROADMAP.md](ROADMAP.md) that has an id, 4 of them, written out: the heading is the title, the fenced block is the body. Each is already open on GitHub under the same id ([PAY-1](https://github.com/distronode-corporation/district-assurance/issues/25), [PAY-4](https://github.com/distronode-corporation/district-assurance/issues/28), [PAY-6](https://github.com/distronode-corporation/district-assurance/issues/30), [SRV-5](https://github.com/distronode-corporation/district-assurance/issues/40)); this file keeps their text with the code. ROADMAP.md has the order and the dependencies, and `test/stubs.test.ts` fails if an id here is missing there.

One more open issue has no id and is not written out here: [#134](https://github.com/distronode-corporation/district-assurance/issues/134) (simulator callers for the remaining steps).

### PAY-1: Stripe Checkout adapter: connect mode and wallet methods

**Labels:** `paylink`, `m6`  
**Milestone:** M6 Paylink  
**Depends on:** none

```markdown
## Why

`StripeCheckoutLinks` (in the reference server) runs in platform mode, proven in Stripe test mode by `npm run demo:e2e`. In connect mode it sends the `Stripe-Account` header, but that has not been proven against Stripe.

## Acceptance criteria

- [ ] In `connect` mode, a direct charge on the connected account, proven in Stripe test mode, and `expireLink` on the connected account.
- [ ] How Apple Pay, Google Pay and Link map to Checkout's parameters is proven in test mode, not assumed.
- [ ] Connect-mode events come from the Connect endpoint, with its own signing secret, carry the connected account, and settle the payment end to end with a real test-mode event.

## Files

- examples/reference-server/src/stripe-adapters.ts
- examples/reference-server/src/main.ts

## Tests

- test/stripe-adapters.test.ts against a local fake
- A recorded manual run in Stripe test mode in the pull request

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-4: Saved-card charges for level 2 callers (gated)

**Labels:** `paylink`, `m6`  
**Milestone:** M6 Paylink  
**Depends on:** PAY-2

```markdown
## Why

Charging a card the business already holds. Off by default, its own switch.

## Acceptance criteria

- [ ] `chargeSavedCard` through an adapter, only with a level 2 grant and a confirmed amount read-back; never enabled by default.

## Files

- src/pay/later.ts
- src/pay/paylink.ts

## Tests

- test/engine.test.ts

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### PAY-6: Keypad card capture through a certified carrier service (gated)

**Labels:** `paylink`, `m6`  
**Milestone:** M6 Paylink  
**Depends on:** PAY-1

```markdown
## Why

Some buyers will need it; it must never route tones through this engine.

## Acceptance criteria

- [ ] Starts only after an assessor's scoping. The engine calls a `CarrierPayments` adapter to start and end capture and receives only a token and a result.
- [ ] An architecture note in SECURITY-MODEL.md shows that no tone reaches the engine during capture.

## Files

- src/pay/later.ts
- src/core/adapters.ts
- SECURITY-MODEL.md

## Tests

- test/engine.test.ts: the engine never receives digits

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```

### SRV-5: Release workflow: the dry run in a fork and the first release

**Labels:** `reference-server`, `m8`  
**Milestone:** M8 Reference server hardening  
**Depends on:** none

```markdown
## Why

The release workflow is built (`.github/workflows/release.yml`, with `supply-chain.yml`), and nothing is published yet, by decision: `package.json` keeps `"private": true`.

## Acceptance criteria

- [ ] The workflow's dry run on a tag in a fork, recorded in the pull request (also asked for by signed releases, SRV-6).
- [ ] `private: true` is removed only in the pull request that decides the first release, and that release is checked against the reviewed source.

## Files

- .github/workflows/release.yml
- package.json

## Tests

- A dry run on a tag in a fork

## Done when

All boxes are ticked, `npm run test:coverage` keeps every `src/` file at 100%, SPEC.md and SECURITY-MODEL.md match the change, and CHANGELOG.md has a line under Unreleased.
```
