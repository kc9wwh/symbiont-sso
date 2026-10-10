# symbiont

symbiont is a small SAML identity provider that authenticates users against
an upstream OpenID Connect provider. It lets SAML-only service providers
(primarily [Fleet](https://fleetdm.com)) sign users in through OIDC-only
identity providers (such as [Pocket ID](https://pocket-id.org)).

```
 browser ──► Fleet (SAML SP) ──AuthnRequest──► symbiont ──OIDC──► Pocket ID
                ▲                                │   ▲                │
                └──── signed SAML Response ◄─────┘   └── code + ID token
```

**What it is:** a single stateless-ish container (in-memory sessions), one
IdP identity serving several SAML service providers, each with its own
access policy and attribute mapping (including Fleet JIT roles).

**What it is not:** a user directory, an admin UI, or a SAML Single Logout
endpoint. Fleet does not implement SAML SLO, so there is nothing to log out
of; see [Sessions and re-authentication](#sessions-and-re-authentication).
It runs as a single instance (sessions are in memory).

## Quick start (Docker)

You need: a public HTTPS hostname for the bridge (e.g. through Cloudflare
Tunnel), an OIDC client at your IdP, and Fleet admin access.

1. **Get the files**

   ```sh
   mkdir symbiont && cd symbiont
   base=https://raw.githubusercontent.com/kc9wwh/symbiont-sso/main
   curl -fsSLO $base/docker-compose.example.yml
   curl -fsSL  $base/.env.example -o symbiont.env
   curl -fsSL  $base/examples/symbiont.yaml -o symbiont.yaml
   mv docker-compose.example.yml docker-compose.yml
   ```

2. **Create secrets** (the container runs as uid 65532 and must be able
   to read them)

   ```sh
   mkdir secrets
   docker run --rm -v "$PWD/secrets:/out" -u "$(id -u):$(id -g)" \
     ghcr.io/kc9wwh/symbiont gencert --cn saml.example.com \
     --out-cert /out/saml_cert.pem --out-key /out/saml_key.pem
   openssl rand -base64 32 > secrets/session_secret
   printf '%s' 'YOUR-OIDC-CLIENT-SECRET' > secrets/oidc_client_secret
   chmod 0444 secrets/*
   ```

   With Docker Compose file-based secrets the files are bind-mounted with
   host permissions, hence world-readable here; keep the `secrets/`
   directory itself private (`chmod 0700 secrets`, owned by the deploying
   user). On Swarm/Kubernetes use their native secret mechanisms instead.

3. **Configure** `symbiont.env` (`SYMBIONT_BASE_URL`, `OIDC_ISSUER`,
   `OIDC_CLIENT_ID`) and `symbiont.yaml` (your Fleet `entity_id` and ACS
   URLs, groups). Check your mapping offline:

   ```sh
   docker run --rm -v "$PWD:/w:ro" ghcr.io/kc9wwh/symbiont check-mapping \
     --file /w/symbiont.yaml --claims /w/sample-claims.json
   ```

4. **Register the callback** `https://<bridge>/oidc/callback` at your IdP
   ([Pocket ID setup](#pocket-id-setup)).

5. **Start** and watch the logs; symbiont refuses to start with a clear
   list of problems if anything is misconfigured.

   ```sh
   docker compose up -d && docker compose logs -f symbiont
   ```

   Startup logs `oidc_redirect_uri` and `metadata_url`; there should be no
   `WARN` lines (a placeholder-domain warning means `symbiont.yaml` still
   has example values).

6. **Point Fleet at** `https://<bridge>/metadata` ([Fleet
   setup](#fleet-setup)) and sign in. Keep a non-SSO break-glass admin.

## Configuration

All settings are environment variables. Variables marked † also accept a
`<NAME>_FILE` variant holding the value in a file (setting both is an
error). Invalid configuration stops startup with every problem listed.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SYMBIONT_BASE_URL` | yes | | Public URL, no path. `https` (plain `http` only for localhost). Users must reach the bridge only at this hostname. |
| `SYMBIONT_LISTEN_ADDR` | no | `:8080` | |
| `SYMBIONT_SP_CONFIG_FILE` | yes | | Service provider YAML ([example](examples/symbiont.yaml)). |
| `SYMBIONT_TRUSTED_PROXIES` | no | (none) | Comma-separated CIDRs/IPs. See [Client IPs behind a proxy](#client-ips-behind-a-proxy). |
| `SYMBIONT_RATE_LIMIT_PER_MINUTE` | no | `60` | Per-client cap on requests to `/sso` and `/login/*`; `0` disables. Behind a proxy, also set `SYMBIONT_TRUSTED_PROXIES` or every user shares one budget. |
| `SYMBIONT_TRUST_CF_CONNECTING_IP` | no | `false` | Prefer `CF-Connecting-IP` from a trusted proxy. Set only when every trusted proxy is Cloudflare. |
| `OIDC_ISSUER` | yes | | Must equal the discovery document's `issuer` exactly (trailing slash matters). Discovery runs at startup. |
| `OIDC_CLIENT_ID` | yes | | |
| `OIDC_CLIENT_SECRET` † | yes | | |
| `OIDC_SCOPES` | no | `openid email profile groups` | Space-separated; must include `openid`. |
| `OIDC_EMAIL_CLAIM` | no | `email` | |
| `OIDC_NAME_CLAIM` | no | `name` | |
| `OIDC_GROUPS_CLAIM` | no | `groups` | String array (or single string). |
| `OIDC_FETCH_USERINFO` | no | `true` | Merge userinfo claims; ID token wins; userinfo `sub` must match. |
| `OIDC_PROMPT` | no | (unset) | `login`, `consent`, `select_account`. `login` forces IdP re-auth. |
| `OIDC_REQUIRE_EMAIL_VERIFIED` | no | `true` | |
| `ALLOWED_EMAIL_DOMAINS` | no | (any) | Comma-separated; global gate before any per-SP policy. |
| `SAML_CERT_FILE` | yes | | PEM certificate (`symbiont gencert`). |
| `SAML_KEY_FILE` | yes | | PEM RSA key, ≥ 2048 bits, unencrypted. |
| `SESSION_SECRET` † | yes | | Base64, ≥ 32 bytes decoded (`openssl rand -base64 32`). |
| `SESSION_TTL` | no | `60s` | Bridge session only. |
| `PENDING_REQUEST_TTL` | no | `10m` | Max time for an upstream login. |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error`. JSON logs on stdout. |

Endpoints: `GET /metadata`, `GET|POST /sso`, `GET /login/{sp_id}`,
`GET /oidc/callback`, `GET /healthz`.

Subcommands: `symbiont gencert`, `symbiont check-mapping`,
`symbiont version`.

## Deployment

The image is `ghcr.io/kc9wwh/symbiont` (linux/amd64 and linux/arm64),
built from `gcr.io/distroless/static`: no shell, runs as uid/gid 65532,
works with a read-only root filesystem and all capabilities dropped (see
[`docker-compose.example.yml`](docker-compose.example.yml)). It serves
plain HTTP on 8080; terminate TLS in front of it.

**Health checks:** the image has no shell or curl, so a Docker
`HEALTHCHECK` cannot run inside it. Use your orchestrator's HTTP probe
against `GET /healthz` (returns `200 {"status":"ok"}`, makes no upstream
calls), e.g. a Kubernetes `livenessProbe.httpGet` on port 8080, or your
reverse proxy's / uptime monitor's health check.

### Cloudflare Tunnel

- Route the public hostname to the container over **plain HTTP**
  (`http://symbiont:8080` from a `cloudflared` sidecar on the same network;
  a commented example is in the compose file). Set `SYMBIONT_BASE_URL` to
  the public `https://` hostname.
- On the bridge hostname, **disable Rocket Loader and Email Obfuscation**
  (e.g. with a Configuration Rule). Both rewrite HTML: Rocket Loader
  replaces the auto-submit script, which the page's Content-Security-Policy
  then blocks, and Email Obfuscation can alter form contents. Users would
  be stuck on a "Continue" button or the login would fail.
- **Do not put Cloudflare Access in front of `/metadata`**: Fleet fetches
  it server-side and cannot authenticate. If you protect the hostname with
  Access, add a bypass for `/metadata` and `/healthz` at minimum;
  `/sso`, `/login/*` and `/oidc/callback` must also be reachable by
  browsers without an extra interactive Access login.
- Set `SYMBIONT_TRUSTED_PROXIES` to the network `cloudflared` connects
  from to log real client IPs.

### Client IPs behind a proxy

`remote_addr` in logs is always the TCP peer (behind a tunnel, that is the
tunnel). With `SYMBIONT_TRUSTED_PROXIES` set, requests whose peer falls in
one of those ranges also log `client_ip`: the right-most `X-Forwarded-For`
entry that is not itself a trusted proxy. With
`SYMBIONT_TRUST_CF_CONNECTING_IP=true` a valid `CF-Connecting-IP` wins
instead; enable that only when every trusted proxy is Cloudflare, because
any other proxy lets a client set the header. Requests from any other peer never use these
headers, since a client could set them to anything. Ranges larger than /8
(IPv4) or /16 (IPv6) produce a startup warning. Besides logging,
`client_ip` (or the TCP peer when it is absent) keys the per-client login
rate limit, with IPv6 clients grouped by /64. A wrong
`SYMBIONT_TRUSTED_PROXIES` therefore affects throttling too: too narrow and
every user shares the proxy's budget, too wide and a client can pick its
own bucket. It is never used for access decisions.

## Sessions and re-authentication

`SESSION_TTL` (default `60s`) governs **only symbiont's own session**: how
long a sign-in at the upstream IdP can be reused for further SAML
assertions without another round-trip. When it expires, symbiont sends the
browser back to the IdP, which may **sign the user in silently** using its
own session. To force users to authenticate at the IdP every time:

- set `OIDC_PROMPT=login`, or
- enable the IdP client's own setting (Pocket ID: **Requires
  reauthentication** on the OIDC client).

If a service provider sends `ForceAuthn="true"`, symbiont ignores its own
session and asks the IdP to re-authenticate (`prompt=login&max_age=0`). It
then requires the ID token's `auth_time` to prove that happened, and refuses
the login (`reauthentication_not_performed` in the logs) if `auth_time` is
missing or older than the request. The IdP must therefore return `auth_time`
(Pocket ID does). Fleet does not send `ForceAuthn`.

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

The shipped examples use reserved example domains (RFC 2606:
`example.com`, `example.net`, `example.org`, `*.example`). symbiont logs a
startup WARN for any service provider whose `entity_id` or ACS URL host is
under one of them, to catch `SYMBIONT_SP_CONFIG_FILE` pointing at an
example file by mistake.

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

### Offboarding

symbiont only decides whether to issue the **next** assertion. A denial at
the bridge (user removed from the IdP, from an allowed group, or blocked by
`ALLOWED_EMAIL_DOMAINS`) stops new SSO logins, but it **does not change an
existing Fleet account's role, and does not end that user's existing Fleet
sessions**. Fleet only updates roles when it receives an assertion, and the
bridge sends none to a denied user. To offboard, disable or delete the user
in Fleet (UI, API, or SCIM provisioning from your directory), and remove
them at the IdP.

### Other notes

- Assertions and responses are both signed (RSA-SHA256). NameID is the
  email (`emailAddress` format); the audience is only the requesting SP.
- The bridge session cookie carries only a signed random ID; identity is
  kept in memory, never authorization decisions. Restarting the container
  ends all bridge sessions (users sign in at the IdP again).
- Logs never contain tokens, codes, cookies, assertions, secrets, claim
  sets or role values; they contain email, `sp_id`, outcome and error
  category.
- Requests to `/sso` are limited to 64 KB (including after decompression);
  RelayState is opaque, at most 80 bytes, and never used as a redirect.

## Limitations

- Single instance: sessions and pending logins are in memory (bounded to
  10,000 sessions and 5,000 pending logins). Running replicas requires sticky sessions and still loses
  state on restart.
- No SAML Single Logout, no encrypted assertions, no signed AuthnRequest
  verification (requests are bound to configured SPs and ACS URLs instead).
- HTTP-POST is the only response binding; AuthnRequests may use
  HTTP-Redirect or HTTP-POST.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Startup: `OIDC_ISSUER is "…" but the provider reports issuer "…"` | `OIDC_ISSUER` must match the provider's `issuer` exactly, including any trailing slash. |
| Startup: `placeholder domain` WARN | `SYMBIONT_SP_CONFIG_FILE` still points at, or was copied unchanged from, an example file. |
| Fleet: "invalid audience" / entity ID errors | Fleet `entity_id` must equal the SP's `entity_id` in `symbiont.yaml` exactly. Admin SSO and end-user auth are separate SPs. |
| Bridge page "address that is not configured" | Fleet's ACS URL (from its server URL) is not listed in `acs_urls`. Check Fleet's server URL and the exact path. |
| IdP error "redirect URI mismatch" | Register exactly the `oidc_redirect_uri` from the startup log. |
| "Sign-in failed" page; `"error_category":"state_cookie_mismatch"` in logs | The login started on a different hostname than `SYMBIONT_BASE_URL` (cookies are host-only), or the browser blocks cookies. The log includes a hint when hosts differ. |
| Stuck on a "Continue" button | JavaScript blocked or rewritten. Disable Cloudflare Rocket Loader on the bridge hostname. |
| "Your account has no email address" / "not been verified" | Check `email` scope and claim; Pocket ID users need verified emails, or set `OIDC_REQUIRE_EMAIL_VERIFIED=false` with `ALLOWED_EMAIL_DOMAINS`. |
| 403 "You don't have access to …" | Expected when the user's groups don't match the SP's `access`. Check the `groups` claim (`check-mapping`, `LOG_LEVEL=debug`) and that the `groups` scope is requested. |
| "conflicting Fleet roles" | The user matched both a GLOBAL and a fleet-level rule. Fix group membership or rules. |
| IdP-initiated login (dashboard tile) rejected by Fleet | Enable `enable_sso_idp_login` ("Allow SSO login initiated by identity provider"). |
| Fleet rejects responses as expired / not yet valid | Clock skew. Assertions are valid 90 s with 180 s skew allowance; run NTP on both hosts. |
| Role didn't change after a group change | Fleet only changes roles when role attributes are sent, and only with JIT provisioning (Premium). Without a `default`, users who match no rule keep their role. |

## Manual verification checklist

Run against a real Fleet Premium instance and IdP after deploying:

1. SP-initiated: Fleet login → IdP (passkey) → lands in Fleet as the right user.
2. IdP-initiated: `/login/fleet-admin` (or the IdP dashboard tile) → lands in Fleet.
3. JIT: a new user in `fleet-admins` is created as global admin; moving
   them to `fleet-observers` demotes them on next login.
4. Fleet-level role: a user in a fleet-level group gets that role on that fleet only.
5. Conflict: a user in both global and fleet-level groups sees the bridge's
   conflict error.
6. Logout: after Fleet logout, the next login re-prompts at the IdP when
   `OIDC_PROMPT=login` (or the IdP's re-authentication setting) is on.
7. (Optional) MDM end-user authentication during ADE on a test Mac.
8. An employee-only user completes ADE end-user auth but gets the bridge's
   403 page at Fleet admin login.
9. An admin can do both; the Fleet admin role matches the mapping, and the
   enrollment login causes no role change.
10. With JIT on, an IdP user in no allowed group is not created in Fleet.
11. Logs show `client_ip` (when `SYMBIONT_TRUSTED_PROXIES` is set) and no
    secrets, codes or assertions.

## Development

```sh
go vet ./... && go test -race ./...
golangci-lint run          # v2.14.0+ (built with Go 1.27)
docker build -t symbiont --build-arg VERSION=dev .
```

CI (`.github/workflows/ci.yml`) runs tidy/gofmt checks, vet, race tests and
golangci-lint, builds the multi-arch image on every push and PR, and
publishes to `ghcr.io/kc9wwh/symbiont` on `v*` tags (`X.Y.Z`, `X.Y`, `X`
for X ≥ 1, plus a short-SHA tag).

## License

MIT, see [LICENSE](LICENSE).
