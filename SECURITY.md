# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately**, not in a public issue or pull
request.

Use GitHub's private vulnerability reporting:
<https://github.com/kc9wwh/symbiont-sso/security/advisories/new>

Helpful details: the symbiont version or image tag, how it is deployed, the
service provider it fronts, and steps or a proof of concept to reproduce.
Please do not include real credentials, assertions or session cookies.

This is a small, individually maintained project, so reports are handled on a
best-effort basis. A confirmed issue is fixed in a new release and published
as a GitHub security advisory, crediting the reporter unless they prefer not
to be named.

## Supported versions

Only the latest release receives security fixes. Releases are the `v*` tags
and the matching `ghcr.io/kc9wwh/symbiont` images.

## Scope

symbiont is a SAML identity provider that authenticates users through an OIDC
provider. In scope: authentication bypass, forged or replayed assertions,
open redirects, session handling, parsing of untrusted input (SAML requests,
RelayState, forwarded-IP headers), and secrets leaking into logs. The
README's *Security notes* section lists known limits that are by design, such
as offboarding and the replay window for IdP-initiated logins.

Out of scope: weaknesses in the OIDC provider or the service provider
themselves, and misconfiguration that the README warns against.

## Verifying what you run

Release images carry an SBOM and signed build provenance. See *Verifying the
image* in the README.
