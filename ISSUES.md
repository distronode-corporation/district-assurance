# Issues

Every open issue of [ROADMAP.md](ROADMAP.md) that has an id, 2 of them, written out: the heading is the title, the fenced block is the body. Each is already open on GitHub under the same id ([PAY-4](https://github.com/distronode-corporation/district-assurance/issues/28), [PAY-6](https://github.com/distronode-corporation/district-assurance/issues/30)); this file keeps their text with the code. ROADMAP.md has the order and the dependencies, and `test/stubs.test.ts` fails if an id here is missing there.

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
