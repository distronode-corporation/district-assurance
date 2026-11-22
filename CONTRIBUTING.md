# Contributing

Thank you for helping. A few ground rules keep the engine small and trustworthy.

## Principles

- **The model proposes, code decides.** Nothing a model says may become a factor, a level, a
  grant, an amount or a destination.
- **Fail closed.** When a check cannot be completed, refuse. Planned work throws
  `NotImplementedError` with its ROADMAP.md issue id, never a placeholder that succeeds.
- **No oracle.** Refusals do not say which check failed or whether an account exists.
- **No values in logs.** Ledger detail and events say what happened and how, never what was keyed,
  what is on file, a phone number or a link.
- **No test-mode bypasses.** Tests inject what they need: a clock, ids, adapters.
- **No runtime dependencies.** Adding one needs a very good reason, written in DECISIONS.md.
- **TypeScript with erasable syntax only**, so Node runs the sources directly in tests.
- **Plain writing.** No em dashes; a colon, a comma or two sentences instead. CI checks.

## Setup

Node.js 24.19 or later.

```sh
npm ci
npm run lint
npm run typecheck
npm run test:coverage   # 100% lines, statements, functions and branches in every src/ file
npm run demo
```

## Style

Code follows oxlint's `correctness` rules (`.oxlintrc.json`) and TypeScript's `strict` mode with
the extra checks in `tsconfig.json`. Formatting follows `.editorconfig`, checked in CI with
editorconfig-checker. Tests use `node:test` and `node:assert`, one file per area under `test/`.

## Pull requests

- One change per pull request, with tests. New code in `src/` keeps every file at 100%.
- A change to the state machine, the factor rules, the ledger or the receipt format updates
  SPEC.md in the same pull request; a change to a control updates SECURITY-MODEL.md.
- A new module setting or flow step comes with `validateConfig` tests for every problem it can
  have (`test/config.test.ts`), so a bad config is refused when it is saved.
- A new `NotImplementedError` names a ROADMAP.md issue and is added to `test/stubs.test.ts`, which
  fails otherwise.
- A decision with alternatives gets an ADR in DECISIONS.md.
- Add a line under "Unreleased" in CHANGELOG.md. From 0.4.0 on, write it for the people who use
  the package, not as an API list: a version's section opens with a short plain paragraph, then
  `### Added`, `### Changed` or `### Fixed` bullets that each start with a **bold plain phrase**
  followed by readable sentences, as in
  [bridgewatch's CHANGELOG](https://github.com/distronode-corporation/bridgewatch/blob/main/CHANGELOG.md).
  The release workflow copies the section as it is into the GitHub release's notes
  (`scripts/release-notes.mjs`).
- Never put real customer data, real phone numbers, keys or secrets in code, tests or issues. Use
  555 numbers, `example.test` hosts and values marked "not a secret".

## Reporting bugs and asking for features

Open a [GitHub issue](https://github.com/distronode-corporation/district-assurance/issues). For a
bug, say what you ran (the commit, the Node.js version and the flow config or a test that shows
it), what happened and what you expected. For a feature, say what you need and why; check
ROADMAP.md first, since planned work already has an issue id there. Issues and their answers stay
public. The same rule as for code applies: no real customer data, phone numbers, keys or secrets.

## Reporting security issues

Not in a public issue: see [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
