# ContextForge 1.0.6 — missing-auth-on-exchange-failure (setup recipe)

Validation against a known, fixed bug: ContextForge **1.0.6** forwards a
federated `resources/read` to the upstream with **no `Authorization` header**
when the RFC 8693 token exchange fails, instead of failing closed — i.e. the
gateway sends an unauthenticated upstream request. Reproduced live on the
official 1.0.6 container image; fixed by 1.1.1 (its source raises on exchange
failure). 1.1.0 not tested. The inbound caller here is the CF admin JWT;
untested with an ordinary, non-admin user.

Everything runs on **localhost / loopback only**. Bearer tokens are redacted to
`sha256:` fingerprints in the saved run — full JWTs are never written.

## Why a container

1.0.6 is **not cleanly pip-installable** (a dependency conflict with `cpex`/`mcp`
in this era), so it must run from the official image, not a venv. 1.0.6's REST
routes are un-prefixed (`/gateways`, `/resources`, `/servers`), unlike the
`/v1/...` paths of the 1.1.1 recipe.

## 1. Run ContextForge 1.0.6 (loopback only)

```
docker run -d --name cf106-xid10 \
  --add-host=host.docker.internal:host-gateway \
  -p 127.0.0.1:4446:4444 \
  -e HOST=0.0.0.0 -e PORT=4444 \
  -e DATABASE_URL=sqlite:////tmp/mcp.db \
  -e PLATFORM_ADMIN_EMAIL=admin@example.com \
  -e EMAIL_AUTH_ENABLED=true \
  -e SSRF_ALLOW_LOCALHOST=true -e SSRF_ALLOW_PRIVATE_NETWORKS=true \
  -e MCP_CLIENT_CONNECT_MODE=auto -e LOG_LEVEL=DEBUG \
  ghcr.io/ibm/mcp-context-forge:v1.0.6
```

`HOST=0.0.0.0` is the bind **inside** the container; the host only exposes it on
`127.0.0.1:4446` via the `-p 127.0.0.1:4446:4444` mapping (never all interfaces).
`--add-host=host.docker.internal:host-gateway` lets the container reach host
services (the AS and the recording upstream) at `host.docker.internal`, which on
Docker Desktop for Mac forwards to the host's loopback.

Admin bearer for the REST API (generated inside the container):

```
docker exec cf106-xid10 sh -lc \
  'python -m mcpgateway.utils.create_jwt_token -u admin@example.com --admin -e 1800'
```

## 2. Run the gate

With a Python that has `pyjwt[crypto]` + `cryptography`:

```
CF_URL=http://127.0.0.1:4446 CF_CONTAINER=cf106-xid10 \
  python integration/xid10_cf106_resource_exchange_fail.py
```

The gate (all loopback; container reaches these via `host.docker.internal`):

1. Starts a **recording upstream** (both loopback families) that logs every POST
   — method, whether `Authorization` was present, header names, token
   fingerprint — and echoes the client's requested `protocolVersion` so the MCP
   SDK client never aborts `initialize` on a version mismatch. It advertises a
   resource **template** `note://{id}`.
2. Starts a **toggleable AS**: `/token-ex` returns a signed RS256 token in `ok`
   mode and HTTP 400 `invalid_grant` in `fail` mode.
3. Registers a fresh oauth **token-exchange** gateway (`grant_type:
   token-exchange`, `token_url` → the AS `/token-ex`, `target_audience` → the
   upstream), refreshes to discover the template, and exposes it on a virtual
   server.
4. Reads an **uncached template-instance** URI (`note://live-...`) over MCP at
   `POST /servers/{id}/mcp`, as the admin JWT, twice:
   - **control**, AS=`ok`: the exchange succeeds; the upstream `resources/read`
     carries `Authorization: Bearer <exchanged>`.
   - **test**, AS=`fail`: the exchange returns HTTP 400; the upstream still gets
     `initialize` + `notifications/initialized` + `resources/read` with the
     **same header names minus** `Authorization` — the gateway sends the request
     unauthenticated. (This test upstream answers without checking the token, so
     CF returns content; a real upstream that requires a token would refuse.)

The control proves the read path works, so the test's missing header is the
behavior, not a harness artifact.

## Gotchas (all encoded in the gate)

- **Cache vs federate.** A catalogued resource with stored content is served
  locally and never federates — so a read of a normal cached resource reaches no
  upstream at all (looks "fail-closed" for the wrong reason). The live RFC 8693
  exchange path (`resource_service.invoke_resource`) is reached only for
  **uncached** resources, i.e. resource **templates**. The gate reads a template
  instance to force it.
- **Discovery needs a manual refresh:** `POST
  /gateways/{id}/tools/refresh?include_resources=true`.
- **Templates are filtered out of `GET /resources`;** the gate reads their ids
  straight from the container DB to associate them with the virtual server.
- **Inbound caller** is the CF admin JWT (3-part, so CF's `looks_like_jwt()`
  guard passes and a real exchange is attempted). This isolates the
  exchange-failure forwarding behavior from identity/RBAC, which 1.1.1 already
  covers.

## What it shows

| Exchange | `resources/read` upstream | `Authorization` |
|---|---|---|
| succeeds | yes | present (`Bearer`) |
| **fails (HTTP 400)** | yes | **absent** |

The finding is that the gateway sends an **unauthenticated** request upstream;
the harm depends on whether the upstream trusts it.

Root cause (source): in 1.0.6 the `resource_service` token-exchange branch only
`logger.error`s on failure and falls through with no auth header; **1.1.1's
source raises `ResourceError(...)`** and fails closed. Reproduced on 1.0.6;
fixed by 1.1.1; **1.1.0 not tested**.
