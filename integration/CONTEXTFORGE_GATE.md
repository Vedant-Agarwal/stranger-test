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
<venv>/bin/python -c "import sys;sys.path.insert(0,'integration');from local_as import LocalAS;s=LocalAS(issuer='https://local-as.test',key_path='cf/as_key.pem').serve(port=8790);s.serve_forever()"
```

`key_path` makes the signing key stable across restarts — ContextForge caches
the JWKS. The AS serves `/jwks`, `/token` (RFC 8693 exchange + client
credentials) and `/issue?sub=&aud=&scope=` (mint a user token).

## 2. ContextForge

```
cd <cfhome>
<venv>/bin/python -m mcpgateway.scripts.init_secrets          # -> .env.secrets
# build .env from .env.secrets plus:
#   DATABASE_URL=sqlite:///./mcp.db  HOST=127.0.0.1  PORT=4444
#   PLATFORM_ADMIN_EMAIL=admin@example.com
#   SSO_API_TOKEN_AUTH_ENABLED=true      # accept external IdP access tokens
#   SSRF_ALLOW_LOCALHOST=true            # allow the 127.0.0.1 token_url/upstream
#   MCP_CLIENT_CONNECT_MODE=auto
<venv>/bin/python -m mcpgateway.bootstrap_db
<venv>/bin/python -m mcpgateway                               # serves :4444
```

The gate inserts the SSOProvider row itself (issuer `https://local-as.test`,
`trusted_for_api_auth=true`, `api_audience=mcpgateway-api`, `jwks_uri` → the
AS). An admin bearer for the REST API comes from
`mcpgateway.utils.create_jwt_token -u admin@example.com --admin`.

## 3. Run the gate

```
cd <cfhome> && set -a && . ./.env && set +a
XID10_MODE=delegation    <venv>/bin/python integration/xid10_contextforge_gate.py
XID10_MODE=impersonation <venv>/bin/python integration/xid10_contextforge_gate.py
XID10_MODE=two_issuers   <venv>/bin/python integration/xid10_contextforge_gate.py
# resource reads instead of tool calls (any mode):
XID10_MODE=delegation XID10_TRIGGER=resource <venv>/bin/python integration/xid10_contextforge_gate.py
```

`XID10_TRIGGER` is `tool` (default) or `resource` — the latter drives the probe
via `resources/read` instead of `tools/call`.

Expected (ContextForge 1.1.1):
- `delegation` → not vulnerable (all checks pass).
- `impersonation` → vulnerable, `failures=['actor_present']` (the exchanged
  token has no `act` claim — the acting agent is invisible).
- `two_issuers` → not vulnerable: two users both named `alice` from different
  providers (provX/provY) stay distinct through the exchange (distinct tokens,
  no cross-identity reuse). ContextForge also enforces one-email-to-one-provider
  binding, refusing a second provider's claim on the same email unless
  `SSO_ALLOW_PROVIDER_LINKING` — a built-in guard against the cross-provider
  confusion (TrustGate) class.

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
