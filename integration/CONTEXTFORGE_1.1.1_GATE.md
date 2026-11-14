# ContextForge 1.1.1 — fails closed on token-exchange failure (setup recipe)

Validation against a known, fixed bug, the **1.1.1 side**. ContextForge
**1.0.6** forwards a federated `resources/read` to the upstream with **no
`Authorization` header** when the RFC 8693 token exchange fails (see
`CONTEXTFORGE_1.0.6_GATE.md`). This gate runs the **same method** on
ContextForge **1.1.1** and confirms, from a live run, that 1.1.1 **fails
closed**: when the exchange fails, no `resources/read` reaches the upstream and
the caller gets an error. "1.1.1 fixes it" then rests on a run, not on reading
source.

Everything runs on **localhost / loopback only**. Bearer tokens are redacted to
`sha256:` fingerprints in the saved run — full JWTs are never written.

Verified against **ContextForge 1.1.1** on macOS, Python 3.13. The inbound
caller is the CF **admin** JWT; **untested with an ordinary, non-admin user**
(the fail-closed behavior is in the resource-federation path, orthogonal to
RBAC — a non-admin run would need the full SSO-provider / team / role setup of
`CONTEXTFORGE_GATE.md`).

## Why pip, not a container

Unlike 1.0.6, 1.1.1 **is** cleanly pip-installable, so it runs from a venv on
the host. The gate therefore reaches the AS and the recording upstream at
`127.0.0.1` directly (no `host.docker.internal`), mints the admin token with
the local `mcpgateway.utils.create_jwt_token` (no `docker exec`), and reads the
resource-template ids from the sqlite DB file read-only (no `docker exec`).
1.1.1's REST routes are `/v1/...`.

## 1. Install and run ContextForge 1.1.1 (loopback only)

```
uv venv --python 3.13 <venv>
uv pip install --python <venv>/bin/python "mcp-contextforge-gateway==1.1.1" "pyjwt[crypto]" cryptography

cd <cfhome>
<venv>/bin/python -m mcpgateway.scripts.init_secrets          # -> .env.secrets
# build .env from .env.secrets plus:
#   DATABASE_URL=sqlite:///./mcp.db  HOST=127.0.0.1  PORT=4145
#   PLATFORM_ADMIN_EMAIL=admin@example.com
#   SSRF_ALLOW_LOCALHOST=true           # allow the 127.0.0.1 token_url/upstream
#   MCP_CLIENT_CONNECT_MODE=auto
<venv>/bin/python -m mcpgateway.bootstrap_db
cd <cfhome> && set -a && . ./.env && set +a && <venv>/bin/python -m mcpgateway   # serves :4145
```

(No SSO provider is needed: the inbound caller is the CF admin JWT, minted from
the same `JWT_SECRET`, so `SSO_ENABLED` is irrelevant to this test.)

## 2. Run the gate

With the CF venv and the CF `.env` loaded (so `create_jwt_token` matches the
running server), from the repository root:

```
cd <repo> && set -a && . <cfhome>/.env && set +a
export CF_URL=http://127.0.0.1:4145 CF_DB=<cfhome>/mcp.db CF_UP_PORT=8797 CF_AS_PORT=8795
<venv>/bin/python integration/xid10_cf111_resource_exchange_fail.py
```

The gate (all loopback):

1. Starts a **recording upstream** (both loopback families — ContextForge may
   connect over IPv6) that logs every POST — method, whether `Authorization`
   was present, header names, token fingerprint — and echoes the client's
   requested `protocolVersion`. It advertises a resource **template**
   `note://{id}`.
2. Starts a **toggleable AS**: `POST /token` returns a signed RS256 token for a
   token-exchange grant in `ok` mode and HTTP 400 `invalid_grant` in `fail`
   mode. `client_credentials` (the gateway's discovery sub-config) **always**
   succeeds — only the token-exchange grant is toggled.
3. Registers a fresh oauth **token-exchange** gateway via `POST /v1/gateways`
   (`token_url` → the AS `/token`, `target_audience` → the upstream, plus a
   `discovery` client-credentials sub-config so 1.1.1 runs registration-time
   discovery), refreshes to discover the template, and exposes it on a virtual
   server (`POST /v1/servers`).
4. Reads **uncached template-instance** URIs over MCP at
   `POST /servers/{id}/mcp`, as the admin JWT:
   - **control**, AS=`ok`: the exchange succeeds; the upstream `resources/read`
     carries `Authorization: Bearer <exchanged>`.
   - **test x3**, AS=`fail`: the exchange returns HTTP 400; **no**
     `resources/read` reaches the upstream and the caller gets
     `Token exchange failed … Contact your administrator`.

The control proves the read path works, so the test's absence of an upstream
read is the behavior, not a harness artifact. The three test reads use distinct
uncached instances (`note://live-fail-1..3`) to confirm determinism.

## Gotchas (all encoded in the gate)

- **Cache vs federate.** A catalogued resource with stored content is served
  locally and never federates. The live RFC 8693 exchange path is reached only
  for **uncached** resources, i.e. resource **templates** — the gate reads a
  template instance to force it.
- **Discovery needs a credential.** A 1.1.1 token-exchange gateway skips
  registration-time discovery unless its `oauthConfig` has a `discovery`
  client-credentials sub-config; without it the template is never discovered.
- **Templates are filtered out of `GET /v1/resources`;** the gate reads their
  ids from the sqlite DB (`CF_DB`), read-only, to associate them with the
  virtual server.
- **Inbound caller** is the CF admin JWT (3-part, so CF's `looks_like_jwt()`
  guard passes and a real exchange is attempted).
- **Upstream reachability:** ContextForge rewrites `127.0.0.1`→`localhost` and
  may connect over IPv6, so the upstream listens on **both** loopback families.

## What it shows

| Exchange | `resources/read` upstream | `Authorization` | caller |
|---|---|---|---|
| succeeds (control) | yes | present (`Bearer`) | content |
| **fails (HTTP 400)** | **no** | — | **error (fails closed)** |

Root cause (source): in 1.0.6 the `resource_service` token-exchange branch only
logs on failure and falls through with no auth header; **1.1.1 raises
`ResourceError(...)`** and fails closed. Reproduced live: 1.0.6 forwards an
unauthenticated request upstream; 1.1.1 fails closed. **1.1.0 not tested.**
