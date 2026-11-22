# Contributing to district-assurance

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

## Layout

```
src/core/                  The call session and its state machine, the session store, the policy
                           and its levels, redaction, the module registry and the config.
src/verify/, src/file/,    The modules: Badge (verify), Dossier (file), Paylink (pay) and Trace
src/pay/, src/prove/       (prove). Trace's ledger is always on.
src/gate/                  Gate (entry): access grants, door controller adapters, one-time access
                           codes, and Step-up.
src/stripe/, src/carrier/  The `district-assurance/stripe` and `district-assurance/carrier` entry
                           points.
src/webhooks/              Stripe and carrier webhook signature checks, and the mapping from
                           Stripe's events to the engine's outcomes.
src/testing/               `district-assurance/testing`: the fakes, the contract suites and
                           `createTestEngine()`.
src/cli/                   `district-assurance simulate`.
schema/                    The JSON schema for FlowConfig.
examples/reference-server/ The small reference server, the demo and the browser demo.
examples/modules/          Callback, an example outside module.
test/                      `node:test` suites, one file per area, with the property and fuzz suites.
bench/                     The benchmarks (BENCHMARKS.md).
scripts/                   The build's clean step, the audit pack, the release notes and the
                           standalone receipt verifier.
```

## Setup

Node.js 24.19 or later.

```sh
npm ci
npm run lint
npm run typecheck
npm run test:coverage   # 100% lines, statements, functions and branches in every src/ file
npm run demo
```

## The inner loop

```sh
npm test                                     # every suite, on the TypeScript sources
node --test test/config.test.ts              # one file
```

Node runs the sources directly (erasable TypeScript only), so there is no build step in the loop.
The suites need no network, no account and no key: tests inject a clock, ids and fake adapters.

## The whole local gate

This is what CI's `test` job runs, on Ubuntu, macOS and Windows, on Node.js 24 and 24.19:

```sh
npm ci --ignore-scripts
npm run lint             # oxlint's correctness rules, warnings included
npm run typecheck
npm run test:coverage    # 100% in every src/ file, each on its own (.c8rc.json)
npm run build
npm run demo
node scripts/audit-pack.mjs                  # Linux and the latest Node 24 only
npm run bench -- --budget-ms 25 --out bench.json
```

On Linux, CI also checks every tracked file against `.editorconfig` with editorconfig-checker,
and fails on an em dash anywhere (`git grep -nI $'\xe2\x80\x94' -- . ':!package-lock.json'`).

## Style

Code follows oxlint's `correctness` rules (`.oxlintrc.json`) and TypeScript's `strict` mode with
the extra checks in `tsconfig.json`. Formatting follows `.editorconfig`, checked in CI with
editorconfig-checker. Tests use `node:test` and `node:assert`, one file per area under `test/`.

## Commits and pull requests

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

Pull requests run `.github/workflows/ci.yml`, and every job of it that runs must be green. How a change
is reviewed and accepted, which checks the `main` ruleset requires, who holds which role, and how a
release is made is in [GOVERNANCE.md](GOVERNANCE.md).

By contributing you agree that your contribution is licensed under the Apache License 2.0, as
section 5 of the licence provides. There is no CLA and no sign-off requirement.

## Docs

If you change behaviour the README, SPEC.md or SECURITY-MODEL.md describe (a default, a rule, an
event, a format, an exit code), change the page that describes it in the same pull request.

## Questions and bugs

Open a [GitHub issue](https://github.com/distronode-corporation/district-assurance/issues), through
the bug report, feature request or question form; see [.github/SUPPORT.md](.github/SUPPORT.md). For a bug, say
what you ran (the commit, the Node.js version and the flow config or a test that shows it), what
happened and what you expected. For a feature, say what you need and why; check ROADMAP.md first,
since planned work already has an issue id there. Issues and their answers stay public. The same
rule as for code applies: no real customer data, phone numbers, keys or secrets.

For anything security-relevant, do not open an issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
