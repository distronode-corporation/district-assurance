# Security policy

## Reporting a vulnerability

Please report privately, not in a public issue, discussion or pull request.

- **Preferred:** GitHub's private vulnerability reporting. Open the repository's **Security** tab
  and choose **Report a vulnerability**, or go straight to
  <https://github.com/distronode-corporation/district-assurance/security/advisories/new>.
- **Fallback:** email **opensource@distronode.com** if you cannot use GitHub.

Include what you did, what happened, and what you expected. A proof of concept is welcome but not
required. Never include a real card number, a real person's details, a signing key or a webhook
secret; if one is part of the problem, say where it appeared, not what it was.

Expect an acknowledgement within a few working days. This is a small project with no paid bug
bounty; what you get is credit in the changelog entry for the fix, if you want it.

### How a report is handled

The process is the one every repository in the organization follows (its
[GOVERNANCE.md](https://github.com/distronode-corporation/.github/blob/main/GOVERNANCE.md#vulnerability-response)):

1. **Acknowledgement** within a few working days.
2. **Assessment** against this file and [SECURITY-MODEL.md](SECURITY-MODEL.md): whether it is in
   [scope](#scope), how bad it is, and which versions it affects. You are kept informed in the
   private advisory or by email.
3. **Fix**, developed privately where the report is still undisclosed, with a test that fails
   without it, and released as a new version. Fixes land in the latest release (see
   [Supported versions](#supported-versions)) rather than being backported.
4. **Disclosure**: a GitHub security advisory for this repository once the fix is released, and an
   entry in [CHANGELOG.md](CHANGELOG.md).
5. **Credit**: only with your agreement, the reporter is named in the advisory and in the changelog
   entry (see [Thanks](#thanks)). Say in the report whether, and how, you would like to be named.

A vulnerability in a dependency is found by the dependency checks in
`.github/workflows/supply-chain.yml` (dependency review on pull requests, npm audit and
osv-scanner on the lockfile) and handled by updating the dependency.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | Yes |
| 0.x | No: upgrade to 1.x, which breaks nothing that 0.4.2 offered |

From 0.1.0 on, releases are published to npm as `district-assurance` with npm provenance. Fixes
land in the latest 1.x release; reports against `main` are welcome too.

## Security model

The threat model is in [SECURITY-MODEL.md](SECURITY-MODEL.md): what is trusted, what each control
guarantees, and what is left to the host.

## Scope

In scope: this repository's code, which is the library (`src/`, published as
`district-assurance` and `district-assurance/testing`) and the reference server
(`examples/reference-server/`), as code.

Out of scope: any host's deployment, even one built on this code. Its operator answers for it, so
report a problem with a running service to that operator, through the contact in its own
`/.well-known/security.txt` if it has one. If the cause is in this code, report that here too.

## Checking a release

A release is made by the release workflow alone, once the code owner has approved the release
pull request and it has merged ([How releases work](README.md#how-releases-work)). From 0.2.0 on,
its tag is signed by that workflow with gitsign; each release is published to npm with
provenance and carries a CycloneDX SBOM with a signed attestation, all signed through Sigstore by
the release workflow. Check the tag with

```sh
gitsign verify-tag vX.Y.Z \
  --certificate-identity https://github.com/distronode-corporation/district-assurance/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

and the package with `npm audit signatures` and `gh attestation verify`, as README.md shows under
[Verify a release](README.md#verify-a-release). If a check fails for a version we published,
report it as a vulnerability, below.

## Thanks

People who reported a problem and agreed to be named, newest first. Nobody is listed without
asking, and you may ask to be removed at any time.

None yet.
