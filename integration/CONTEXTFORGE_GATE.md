# XID-10 gate against ContextForge (setup recipe)

Drives the delegation probe through a real IBM ContextForge gateway doing
RFC 8693 token exchange against the local AS (`local_as.py`). ContextForge is
the deputy under test; `local_as` is the IdP; a recording MCP server is the
upstream. This is the "real third-party gateway" evidence for XID-10.

Verified against **ContextForge 1.1.1** on macOS, Python 3.13.

## Prerequisites

A venv with both ContextForge and pyjwt (ContextForge needs Python ≥3.12):

```
uv venv --python 3.13 <venv>
uv pip install --python <venv>/bin/python "mcp-contextforge-gateway==1.1.1" "pyjwt[crypto]" cryptography
```

Everything below runs on localhost only (loopback); nothing binds all
interfaces.

## 1. Persistent local AS (IdP) on a fixed port

```
<venv>/bin/python integration/local_as.py serve --port 4190 --key-path cf/as_key.pem
# issuer_unregistered only: add --lax-subject-issuer (see below)
```

`key_path` makes the signing keys stable across restarts — ContextForge caches
the JWKS. The AS serves `/jwks` (its own key, signs exchanged tokens),
`/jwks/provx` and `/jwks/provy` (one key PER test login provider),
`/token` (RFC 8693 exchange + client credentials), `/exchanges` (the log of
exchange requests: requested scope/audience, actor present, issued scope,
outcome — `sha256:` fingerprints only, never tokens) and
`/issue?sub=&aud=&scope=&iss=&email=&key=` (mint a user token; `key` names the
signing key).

The exchange validates a subject token with the key that belongs to **its**
issuer and refuses an unregistered issuer. It never grants a scope the subject
token lacks: issued scope = requested ∩ subject scope (the subject's own scope
if none is requested). `--lax-subject-issuer` (opt-in) accepts any issuer whose
signature verifies under one of the AS's keys; the issuer-binding mode needs it
so the AS cannot be what refuses an unregistered issuer (the gate checks).

## 2. ContextForge

```
cd <cfhome>
<venv>/bin/python -m mcpgateway.scripts.init_secrets          # -> .env.secrets
# build .env from .env.secrets plus:
#   DATABASE_URL=sqlite:///./mcp.db  HOST=127.0.0.1  PORT=4144
#   PLATFORM_ADMIN_EMAIL=admin@example.com
#   SSO_ENABLED=true                     # mounts the SSO router (provider admin API)
#   SSO_API_TOKEN_AUTH_ENABLED=true      # accept external IdP access tokens
#   SSRF_ALLOW_LOCALHOST=true            # allow the 127.0.0.1 token_url/upstream
#   MCP_CLIENT_CONNECT_MODE=auto
<venv>/bin/python -m mcpgateway.bootstrap_db
<venv>/bin/python -m mcpgateway                               # serves :4144
```

The gate configures ContextForge through its supported admin APIs (admin
bearer from `mcpgateway.utils.create_jwt_token -u admin@example.com --admin`):

| What | ContextForge 1.1.1 API |
|---|---|
| SSO providers `local-as`, `provx`, `provy` (issuer, `jwks_uri` → the AS, `trusted_for_api_auth=true`, `api_audience=mcpgateway-api`, placeholder `client_secret: "unused"`) | `POST /auth/sso/admin/providers` to create; `PUT /auth/sso/admin/providers/{id}` on repeat runs (the update repeats `api_audience`, which 1.1.1 requires whenever `trusted_for_api_auth` is true); read back with `GET` and checked |
| Team `xid10-team` | `GET /teams/?search_query=…`, `POST /teams/` |
| `developer` role, team scope, per external user | `GET /rbac/roles`, `GET`/`POST /rbac/users/{email}/roles` |
| Clear `is_admin` (only if set) | `PATCH /auth/email/admin/users/{email}` |
| Which provider an email is bound to (`issuer_email_crossprovider`) | `GET /auth/email/admin/users/{email}` → `auth_provider` |

The provider API lives in the SSO router, which 1.1.1 mounts only with
`SSO_ENABLED=true`; without it (or on an older ContextForge) the gate stops
with an error that says so. The SSO admin endpoints are rate-limited (10
requests a minute); the gate waits out an HTTP 429 and retries.

**One step still writes the database: team membership.** Every 1.1.1 API that
adds a user to a team (`POST /teams/{id}/members`, the `members` seed of
`POST /teams/`, invitations) types the address as `EmailStr`, which rejects
reserved domains such as `.test`, and the gate's users are
`alice@local-as.test`, `alice@provx.test` and so on. The gate tries the API
first and, only on that exact rejection, inserts the `EmailTeamMember` row
directly. Everything else goes through the API.

A role granted right after a user's first sign-in is not visible for up to
60 s (ContextForge's role cache), so every mode waits 65 s
(`CF_ROLE_CACHE_WAIT`) after granting a new role.

## 3. Run the gate

The gate refuses to start unless `AS_BASE` and `CF_URL` are set explicitly, and
refuses the ports 8790 and 4444 (reserved for other processes on the
reference machine; there is no override). Each saved run
records the endpoints it used. `UPSTREAM_PORT` pins the recording upstream
(both loopback families); `FIXTURE_PORT` pins the in-run thin-deputy fixture
(upstream on N, deputy on N+1).

The standalone thin-deputy gate (`integration/xid10_thin_deputy_gate.py`) does
not use `FIXTURE_PORT`: it needs `THIN_PORT_BASE=N` (AS on N, lax AS on N+1,
upstream on N+2, deputy on N+3) and refuses to start without it. See the
README.

```
cd <cfhome> && set -a && . ./.env && set +a
export AS_BASE=http://127.0.0.1:4190 CF_URL=http://127.0.0.1:4144 UPSTREAM_PORT=4180 FIXTURE_PORT=4170
XID10_MODE=delegation    <venv>/bin/python integration/xid10_contextforge_gate.py
XID10_MODE=impersonation <venv>/bin/python integration/xid10_contextforge_gate.py
XID10_MODE=two_issuers   <venv>/bin/python integration/xid10_contextforge_gate.py
# resource reads instead of tool calls (any mode):
XID10_MODE=delegation XID10_TRIGGER=resource <venv>/bin/python integration/xid10_contextforge_gate.py
```

`XID10_TRIGGER` is `tool` (default) or `resource` — the latter drives the probe
via `resources/read` instead of `tools/call`.

New checks (each writes `runs/contextforge-<name>-<ts>.json` with top-level
`probe`, `grade`, `cosai`, controls, observations, endpoints):

```
XID10_MODE=scope_narrowing                        <venv>/bin/python integration/xid10_contextforge_gate.py
XID10_MODE=scope_narrowing XID10_GW_SCOPES=NONE   <venv>/bin/python integration/xid10_contextforge_gate.py
# with the AS started --lax-subject-issuer:
XID10_MODE=issuer_unregistered                    <venv>/bin/python integration/xid10_contextforge_gate.py
XID10_MODE=issuer_email_crossprovider             <venv>/bin/python integration/xid10_contextforge_gate.py
```

- `scope_narrowing` (CoSAI MCP Security v2.0 §3.3.2): users hold
  `read:notes write:notes admin`; the gateway's `oauthConfig.scopes` is
  `["read:notes"]` (`XID10_GW_SCOPES=NONE` -> `[]`). Where ContextForge sets the
  exchange scope: `mcpgateway/services/tool_service.py` (1.1.1, ~line 4566) reads
  `scopes = oauth_config.get("scopes") or []` and passes
  `scope=" ".join(scopes) if scopes else None` to
  `OAuthManager.token_exchange`, which adds `scope` to the request only
  `if scope:` (`mcpgateway/services/oauth_manager.py`). Grades: FAIL
  `scope_exceeded` (anything the user lacked), OK `narrowed` (narrower than the
  user AND equal to the request), OBSERVATION `not_narrowed` (gateway requested
  nothing, the user's full scope arrived), else INCONCLUSIVE. Each per-call
  record says who narrowed (requested / issued / arrived).
- `issuer_unregistered` (§3.2.2/§3.3.2): a token signed with provX's (trusted)
  key but `iss=https://unregistered.test`. Every request (control before,
  probe, control after) carries its own nonce in the tool arguments, and the
  upstream records it, so each upstream call is tied to the request that
  caused it. FAIL if the probe request returns a successful result, or if any
  upstream call carries the probe's nonce, whatever identity it carries. OK
  only if it is refused, nothing with its nonce reaches the upstream, no
  exchange is attempted for it, and an otherwise identical provX token
  reaches the upstream with its own nonce before and after. An upstream call
  with no known nonce is INCONCLUSIVE, never blamed on the probe.
- `issuer_email_crossprovider`: provX token claiming `carol@provy.test`, an email
  first provisioned via provY. Recorded as an observation (which identity, if
  any, reached the upstream; which provider the email is bound to in CF's DB,
  read-only). `SSO_ALLOW_PROVIDER_LINKING` defaults to `false`
  (`mcpgateway/config.py`, `sso_allow_provider_linking`).
- Both new checks first run a deliberately broken thin-deputy fixture against
  the same AS (`scope_escalation`, `issuer_any`); OK is allowed only if that
  fixture FAILed in the same run.
- External users get their `developer` team role right after first sign-in
  (see the setup table above for the APIs).

Expected (ContextForge 1.1.1):
- `delegation` → not vulnerable (all checks pass).
- `impersonation` → vulnerable, `failures=['actor_present']` (the exchanged
  token has no `act` claim — the acting agent is invisible).
- `two_issuers` → not vulnerable: two users both named `alice` from different
  providers (provX/provY, each with its own signing key, SSOProvider
  `jwks_uri` → `/jwks/provx`, `/jwks/provy`) stay distinct through the exchange (distinct tokens,
  no cross-identity reuse). ContextForge also enforces one-email-to-one-provider
  binding, refusing a second provider's claim on the same email unless
  `SSO_ALLOW_PROVIDER_LINKING` — a built-in guard against the cross-provider
  confusion class (two users with the same username from different issuers).

Each run writes `integration/runs/contextforge-<mode>-<ts>.json` with the
checks, the three recorded upstream calls, and the gateway version.

## Notes / gotchas (all encoded in the driver)

- **Inbound identity:** the external user's RS256 token must carry an `email`
  claim (ContextForge provisions the user from it) and `aud=mcpgateway-api`.
- **Authorization:** the external users are granted `tools.execute` via a
  team-scoped **`developer` role** (an ordinary, non-admin path), not admin.
  ContextForge's tool-execution RBAC is orthogonal to the delegation behavior
  under test.
- **Upstream reachability:** ContextForge rewrites `127.0.0.1`→`localhost` and
  may connect over IPv6, so the upstream listens on **both** loopback families
  (127.0.0.1 and ::1) — never all-interfaces.
- **Discovery:** list results must carry `resultType`/`cacheScope`/`ttlMs`, and
  a token-exchange gateway skips registration-time discovery unless its
  `oauthConfig` has a `discovery` client-credentials sub-config.
- **Scope:** only localhost / servers you run. The AS, the gateway and the
  upstream are all local and disposable.
