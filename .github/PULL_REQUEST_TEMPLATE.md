<!-- Thanks for the contribution. Delete any section that genuinely does not apply. -->

## What changed

<!-- One or two sentences. The diff says what; this says it in words. -->

## Why

<!-- The problem, not the patch. If it fixes an issue, link it (Fixes #123). If you hit
     it in practice rather than reading the code, say what you saw. -->

## How it was tested

<!-- Commands you actually ran, and what they said. "Should work" is not a test.
     This list is what CI's test job runs (CONTRIBUTING.md, "The whole local gate"). -->

- [ ] `npm run lint`
- [ ] `npm run typecheck`
- [ ] `npm run test:coverage` (100% lines, statements, functions and branches in every `src/` file)
- [ ] `npm run build`
- [ ] `npm run demo`
- [ ] No em dash added anywhere

## Spec, security model and changelog

<!-- CONTRIBUTING.md, "Commits and pull requests". -->

- [ ] A change to the state machine, the factor rules, the ledger or the receipt format updates
      SPEC.md; a change to a control updates SECURITY-MODEL.md
- [ ] A new module setting or flow step has `validateConfig` tests for every problem it can have
- [ ] A line under "Unreleased" in CHANGELOG.md
- [ ] No real customer data, phone numbers, keys or secrets in code, tests or this description

## Anything a reviewer should know

<!-- A decision you were unsure about, something you deliberately left out, a follow-up
     you think is needed. Saying "I could not test X" here is useful, not a problem. -->
