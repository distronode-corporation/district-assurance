# Governance

district-assurance is owned by Distronode Corporation and published from the
`distronode-corporation` organization on GitHub. This file says who decides what, how a change
gets in, how a release goes out, how a vulnerability report is handled, and what happens if the
maintainer is no longer available. It is the district-assurance version of the organization's
[GOVERNANCE.md](https://github.com/distronode-corporation/.github/blob/main/GOVERNANCE.md); where
the two differ, this file is the one that applies here.

## How decisions are made

district-assurance is maintained by a company, not a foundation: there is no elected committee
and no vote. The maintainer decides, on behalf of Distronode Corporation.

A change to the code or the documentation is proposed as a pull request against `main`, discussed
there, and merged only once the code owner approves it. Larger questions (a new module, a change
to the state machine, the factor rules, the ledger or the receipt format, a breaking change to the
API or to FlowConfig, a change of scope) are raised as an issue first, and the decision and its
reason are written on that issue or pull request, so they are public with the change. A decision
with alternatives also gets an ADR in [DECISIONS.md](DECISIONS.md).

A disagreement is settled in the thread where it comes up, by the evidence: a failing test, a
recorded run, a line of a provider's API documentation or of [SPEC.md](SPEC.md). If it is not
settled there, the code owner decides and says why in public. district-assurance is Apache-2.0,
so a disagreement that cannot be settled never leaves anyone stuck: you are free to fork.

What the repository enforces today:

- **Every path has a code owner.** `.github/CODEOWNERS` assigns every path to the `approvers`
  team, so every pull request requests its review.
- **`main` takes changes only through a pull request.** The default branch ruleset requires an
  approving review from a code owner, given after the most recent push (a new push dismisses an
  earlier approval); every review thread resolved; and the required checks passing on a branch
  that is up to date with `main`. The required checks are the six `test` legs (Ubuntu, macOS and
  Windows, each on Node.js 24 and 24.19), CodeQL's `analyze (javascript-typescript)` and
  `review-threads`. Changes merge through a merge queue, as squash or rebase merges only. The
  ruleset refuses force pushes and deletion of `main`. The `approvers` team, whose only member
  is the maintainer, can bypass it, and GitHub records each bypass in the ruleset's history.
- **Review threads must be resolved.** The `review-threads` check is red while any thread on a
  pull request is open, whether a person or a review bot started it.
- **Dependabot gets one narrow exception.** Its patch and minor updates to development
  dependencies alone are queued to merge themselves, but the merge happens only once the same
  ruleset is satisfied, the code owner's approval included; everything else waits for a person
  (`.github/workflows/dependabot-auto-merge.yml` lists what).

What makes a pull request acceptable (the principles, the style rules, the test and coverage
rules, and how to run what CI runs) is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Roles and responsibilities

| Role | Who | Responsibilities |
| --- | --- | --- |
| Contributor | Anyone who opens an issue or a pull request | Follow [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Say why a change is needed, with its tests and docs in the same pull request. |
| Reviewer | Anyone may review a pull request in public; a review counts toward merging only from a code owner | Read the change against CONTRIBUTING.md and, for anything that touches verification, payment, the ledger, receipts or access, against [SECURITY-MODEL.md](SECURITY-MODEL.md). Ask for changes in a review thread, so it has to be resolved before the merge. |
| Maintainer and code owner | The `approvers` team named in `.github/CODEOWNERS`, acting for Distronode Corporation | Approve every change to `main`, triage issues, keep CI green and dependencies current, keep the docs consistent with the code, and decide on the project's direction ([ROADMAP.md](ROADMAP.md)). |
| Release manager | The code owner, for the release in hand | Approve the release pull request, as described under [How a release is made](#how-a-release-is-made). |
| Security contact | Distronode Corporation, through private vulnerability reporting and opensource@distronode.com | Handle reports as described in [SECURITY.md](SECURITY.md#reporting-a-vulnerability). |

One account can hold several roles. CODEOWNERS is the public record of who holds the code owner
role. If you would like to take on more, say so in an
[issue](https://github.com/distronode-corporation/district-assurance/issues).

## How a release is made

There is one human gate: a release pull request, approved by the code owner, that sets
`package.json`'s version and dates its `## [X.Y.Z] - YYYY-MM-DD` section in
[CHANGELOG.md](CHANGELOG.md). When it merges,
[`.github/workflows/release.yml`](.github/workflows/release.yml) does the rest on its own, on that
merge commit of `main`: it creates and signs the tag `vX.Y.Z` with gitsign (keyless Sigstore
signing under the workflow's own identity), verifies it, builds, checks and publishes to npm with
provenance, signs an SBOM attestation, and makes the tag's GitHub release. The steps, and how to
check a release, are in the README under
[How releases work](README.md#how-releases-work) and [Verify a release](README.md#verify-a-release).

The repository's tag rules forbid moving or deleting a `v*` tag (an admin can bypass them).

## Vulnerability response

Report a vulnerability privately, never in a public issue: through
[GitHub's private vulnerability reporting](https://github.com/distronode-corporation/district-assurance/security/advisories/new),
or by email to opensource@distronode.com. The supported versions, what is in scope and how
reporters are credited are in [SECURITY.md](SECURITY.md).

## Continuity

The project does not depend on one person's account. The `distronode-corporation` GitHub
organization has more than one owner: besides the maintainer and the organization's own account,
a second owner account, `distronode-legal`, is held by Distronode Corporation's legal function (as
the organization's
[GOVERNANCE.md](https://github.com/distronode-corporation/.github/blob/main/GOVERNANCE.md#continuity)
also records). An owner can give write access, change CODEOWNERS and the rulesets, and run the
workflows, so if the maintainer is lost or unavailable, Distronode Corporation commits to being
able, within one week, to create and close issues, name a new code owner, accept changes and make
a release.

Making a release needs a code owner's approval of the release pull request, and otherwise only
what the release workflow is given; no one's personal device is involved:

- The tag is signed through Sigstore with a short-lived certificate issued to the workflow, and
  the SBOM attestation the same way, so there is no long-lived signing key for anyone to hold.
- The npm package is published through npm trusted publishing: npm exchanges the workflow's OIDC
  token for a one-time publish credential, so no npm token is stored. The `npm-publish` environment it
  runs in admits `main` only.
- The GitHub release and its files use the workflow's own repository token.

## Changing this document

A change to this file is a pull request, under the same rules as any other change.
