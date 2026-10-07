# symbiont

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

## Future work

- **Encrypted assertions:** per-SP `encrypt_assertions: true` plus the SP's
  encryption certificate. Assertions are encrypted to the *SP's* public
  key, so symbiont's metadata intentionally publishes no `encryption` key.
  Fleet does not currently configure an SP key.

## License

MIT, see [LICENSE](LICENSE).
