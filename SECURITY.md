# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.0.x (pre-alpha, unreleased) | Best effort |

Nothing is released yet. Reports against `main` are welcome.

## Scope

In scope: this repository's code, which is the library (`src/`, published as
`district-assurance` and `district-assurance/testing`) and the reference server
(`examples/reference-server/`), as code.

Out of scope: any host's deployment, even one built on this code. Its operator answers for it, so
report a problem with a running service to that operator, through the contact in its own
`/.well-known/security.txt` if it has one. If the cause is in this code, report that here too.

## Reporting a vulnerability

Please report privately, not in a public issue, discussion or pull request.

- **Preferred:** GitHub's private vulnerability reporting. Open the repository's **Security** tab
  and choose **Report a vulnerability**.
- **Fallback:** email **opensource@distronode.com** if you cannot use GitHub.

Include what you did, what happened, and what you expected. A proof of concept is welcome but not
required. Never include a real card number, a real person's details, a signing key or a webhook
secret; if one is part of the problem, say where it appeared, not what it was.

Expect an acknowledgement within a few working days. This is a small project with no paid bug
bounty; what you get is credit in the changelog entry for the fix, if you want it.

## Thanks

People who reported a problem and agreed to be named, newest first. Nobody is listed without
asking, and you may ask to be removed at any time.

None yet.

The threat model is in [SECURITY-MODEL.md](SECURITY-MODEL.md): what is trusted, what each control
guarantees, and what is left to the host.
