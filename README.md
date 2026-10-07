# symbiont

> **Status:** feature-complete for the MVP; packaging (container image, CI)
> and the full quick start / troubleshooting guide land in the next phase.

symbiont is a small SAML identity provider that authenticates users against
an upstream OpenID Connect provider. It lets SAML-only service providers
(primarily [Fleet](https://fleetdm.com)) sign users in through OIDC-only
identity providers (such as [Pocket ID](https://pocket-id.org)).

```
 browser ──► Fleet (SAML SP) ──AuthnRequest──► symbiont ──OIDC──► Pocket ID
                ▲                                │   ▲                │
                └──── signed SAML Response ◄─────┘   └── code + ID token
```

## Sessions and re-authentication

`SESSION_TTL` (default `60s`) governs **only symbiont's own session**: how
long a sign-in at the upstream IdP can be reused for further SAML
assertions without another round-trip. When it expires, symbiont sends the
browser back to the IdP, which may **sign the user in silently** using its
own session. To force users to authenticate at the IdP every time:

- set `OIDC_PROMPT=login`, or
- enable the IdP client's own setting (Pocket ID: **Requires
  reauthentication** on the OIDC client).

There is no Single Logout: Fleet does not implement SAML SLO, so logging out
of Fleet ends neither the symbiont nor the IdP session. Keep `SESSION_TTL`
short.

## Access policy

Every service provider in `SYMBIONT_SP_CONFIG_FILE` must have an `access`
block (default deny; a missing block is a startup error):

```yaml
access:
  allow_groups: [fleet-admins, fleet-maintainers]   # any of these groups
  allow_emails: [break-glass@example.com]           # or any of these emails
  # allow_all: true                                 # explicit opt-in; exclusive
```

The policy is evaluated **every time an assertion is issued**, for the SP
that asked, using the identity stored in the bridge session. The session
holds identity only (email, name, groups, claims), never decisions, so one
sign-in can be reused across SPs without leaking access: an employee who
signed in for device enrollment still gets **403 "You don't have access to
Fleet"** at the Fleet admin console. Denials are logged at WARN with
`sp_id`, `email` and `reason` (`no_matching_group`, `email_not_allowed`).
The session is kept and the user is not sent back to the IdP.

### Two layers of access control

1. **Upstream (coarse):** restrict the OIDC client at the IdP to the union
   of every group any SP allows. In Pocket ID, set **Allowed user groups**
   on the symbiont client. Users outside those groups never get a session.
2. **symbiont (authoritative, per SP):** each SP's `access` block decides
   which of those users get an assertion for that SP.

## Attribute mapping

Each SP has its own mapping; attributes are only ever sent to the SP they
are configured for. Every assertion carries `email` and `name`, plus:

- `passthrough_prefixes`: claims whose names start with a prefix are copied
  verbatim (strings, numbers, booleans; arrays and objects are skipped).
- `attributes`: rule-based values, evaluated top-down; **first match
  wins**. `group: <name>` matches membership in the groups claim (exact,
  case-sensitive); `claim: {name: <claim>, equals: <value>}` matches a
  scalar claim or membership in an array claim. `default` is sent when no
  rule matches; omit it to send nothing. Rule and default values override a
  passthrough claim of the same name.

### Fleet roles (`fleet_role_validation: true`, the default)

Applies to `FLEET_JIT_USER_ROLE_GLOBAL`, `FLEET_JIT_USER_ROLE_FLEET_<id>`
and the legacy `FLEET_JIT_USER_ROLE_TEAM_<id>`:

- Values must be `admin`, `maintainer`, `observer`, `observer_plus`,
  `technician` or `null`, checked at startup. `gitops` is rejected because
  it is for API-only users. Values arriving via `passthrough_prefixes` are
  checked at sign-in; an invalid one rejects the login and is logged by
  attribute/claim name only.
- **A default is only applied when no rule for the other scope matched.**
  Defaults therefore never cause conflicts, and a `default` may be set on
  the GLOBAL role or on fleet-level roles, not both (startup error).
- A user who matches **both** a GLOBAL rule and a fleet-level rule is
  rejected with *"conflicting Fleet roles: user matched both global and
  fleet-level role rules"*, because Fleet cannot hold both.
- `FLEET_<id>` and `TEAM_<id>` for the same id is a startup error.
- Each role attribute is single-valued.

Fleet semantics: JIT provisioning and role sync are Fleet Premium features
and require `enable_jit_provisioning: true`. Fleet only changes a user's
role when role attributes are present; with no matching rule and no
`default`, Fleet **keeps the existing role**, so set a `default` to demote
users who leave all groups. Fleet IDs come from the Fleet UI or
`fleetctl get teams`.

See [`examples/mapping.fleet.yaml`](examples/mapping.fleet.yaml).

### Testing a mapping: `check-mapping`

```
symbiont check-mapping --file symbiont.yaml --claims claims.json [--sp fleet-admin]
```

Evaluates each SP's access policy and mapping against sample claims (ID
token and userinfo merged, as JSON) using the same code path as real
logins, and prints the attributes each SP would receive, or the denial or
rejection reason. Exit code 0 means every evaluated SP would issue an
assertion. Example claims files are in [`examples/`](examples).

## Fleet setup

Admin console SSO (Settings → Integrations → Single sign-on, or GitOps
`org_settings.sso_settings`):

```yaml
enable_sso: true
enable_sso_idp_login: true        # UI: "Allow SSO login initiated by identity provider"
enable_jit_provisioning: true     # Premium; required for role mapping
idp_name: Pocket ID
entity_id: fleet.example.com      # = entity_id of the fleet-admin SP
metadata_url: https://saml.example.com/metadata
```

End-user authentication for MDM enrollment (Settings → Integrations →
Single sign-on → End users, or GitOps `mdm.end_user_authentication`):

```yaml
idp_name: Pocket ID
entity_id: fleet.example.com/mdm  # = entity_id of the fleet-enduser SP
metadata_url: https://saml.example.com/metadata
```

Keep a non-SSO break-glass admin account.

### IdP-initiated login (`/login/{sp_id}`)

With `idp_initiated.enabled: true` on an SP (off by default),
`https://<bridge>/login/<sp_id>` signs the user in (through the IdP if there
is no bridge session) and posts an unsolicited SAML Response to that SP's
`idp_initiated.acs_url`. It goes through exactly the same access policy and
mapping as SP-initiated login. Unknown or disabled SPs return 404.

- Fleet **rejects** unsolicited responses unless `enable_sso_idp_login:
  true` ("Allow SSO login initiated by identity provider") is set.
- An optional `?RelayState=` (at most 80 bytes) is passed through, but
  **Fleet ignores RelayState for IdP-initiated logins and always lands on
  `/`**.
- Fleet's MDM end-user authentication is SP-initiated only; symbiont warns
  at startup if IdP-initiated login targets that ACS.

## Pocket ID setup

- Create an OIDC client for symbiont: callback URL
  `https://<bridge>/oidc/callback` (logged at startup as
  `oidc_redirect_uri`); confidential client with PKCE enabled.
- **Allowed user groups:** the union of all groups your SPs allow (see
  [Two layers of access control](#two-layers-of-access-control)).
- **Launch URL:** `https://<bridge>/login/fleet-admin` puts a Fleet tile on
  the Pocket ID dashboard (requires IdP-initiated login, above).
- **Requires reauthentication:** forces a passkey prompt on every sign-in
  (equivalent to `OIDC_PROMPT=login`).
- Create groups matching your `access` and `attributes` rules and assign
  users; confirm `groups` appears in the ID token or userinfo.
- If users lack `email_verified=true`, set `OIDC_REQUIRE_EMAIL_VERIFIED=false`
  and use `ALLOWED_EMAIL_DOMAINS`.


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

Phase 5 (packaging + docs):

- [ ] Dockerfile (distroless, non-root), `docker-compose.example.yml`,
  `.env.example`, CI (vet, race tests, image build).
- [ ] CI: pin golangci-lint to a Go 1.27-compatible release (v2.14.0 or
  later; v2.11.x built with Go 1.26 cannot read Go 1.27 export data).
- [ ] `SYMBIONT_TRUSTED_PROXIES` (CIDR list). When the socket peer is
  trusted, log the real client IP as `client_ip`, from `CF-Connecting-IP` or
  the right-most untrusted `X-Forwarded-For` hop; never trust these headers
  otherwise. `remote_addr` stays the socket peer.
- [ ] Full README: quick start, configuration reference, troubleshooting,
  manual verification checklist.

## License

MIT, see [LICENSE](LICENSE).
