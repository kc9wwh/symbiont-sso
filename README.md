# symbiont

> **Pre-release:** per-SP access policy (`access` blocks) is parsed and validated but **not yet enforced**. Any user the upstream IdP authenticates receives an assertion for any configured SP. Do not use with Fleet JIT provisioning enabled until this is resolved. Tracked in [TODO](#todo) below.

> **Status: under construction.** This README is a stub that collects
> decisions as they are made; the full guide (quick start, Fleet and
> Pocket ID setup, troubleshooting) lands with the packaging phase.

symbiont is a small SAML identity provider that authenticates users against
an upstream OpenID Connect provider. It lets SAML-only service providers
(primarily [Fleet](https://fleetdm.com)) sign users in through OIDC-only
identity providers (such as [Pocket ID](https://pocket-id.org)).

## Security notes

### Assertion validity and replay

Assertions are valid for **90 seconds** after issue (`NotOnOrAfter`), and
`NotBefore` is backdated **180 seconds** to tolerate clock skew. These are
the defaults of the crewjam/saml library, which Fleet also uses to validate
responses; Fleet additionally allows 180 seconds of skew on its side.

**IdP-initiated logins** (`/login/{sp_id}`) produce unsolicited responses
that have no `InResponseTo` to bind them to a request. Replay protection for
those therefore relies on the assertion validity window (90 s plus the SP's
clock-skew allowance) and on the SP rejecting reuse of an assertion ID.
Fleet does track consumed assertion IDs; other SPs may not. Only enable
`idp_initiated` where you need it.

## TODO

- [ ] Enforce per-SP `access` policy at `/sso` (Phase 4). Deny from existing session; no IdP redirect loop.
- [ ] Per-SP attribute mapping + Fleet role validation, `/login/{sp_id}`, `check-mapping` (Phase 4).
- [ ] Document two-layer access: upstream OIDC client restricted to the union of SP groups (e.g., Pocket ID "Allowed user groups"), Symbiont per-SP `access` as the authoritative per-SP control.

## License

MIT, see [LICENSE](LICENSE).
