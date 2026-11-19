# ContextForge — same-user-credentials token-exchange cache (CVE-2026-110195)

Validation against a **known, fixed CVE**. [CVE-2026-110195](https://www.cve.org/CVERecord?id=CVE-2026-110195)
(IBM ContextForge MCP Gateway; [advisory](https://www.ibm.com/support/pages/node/7296695);
affected **1.0.0–1.0.11**, fixed in **1.1.0**; reported by **Nick Simpson**): the
RFC 8693 token-exchange cache keyed only on `(gateway, user, audience)` and
omitted the inbound credential, so the upstream token minted for one credential
of a user was served to **another credential of the same user**.

This gate drives the `same-user-credentials` probe
(`strangertest/credcache.py`) against a running ContextForge gateway and
**reproduces the cache-key collision described in the CVE** — it is **not a new
discovery**. Everything runs on **localhost / loopback only**; bearer tokens are
reduced to `sha256:` fingerprints in the saved run.

Verified against **1.0.11** (expect FLAGGED/FAIL), **1.1.1** (expect OK), and
**1.1.0** (the first fixed release; expect OK), macOS, Python 3.13.

## The method

- **Two credentials, one user.** Two distinct login JWTs for the same
  bootstrapped account (`admin@example.com`) — a "session" and an "api-token"
  credential. Both authenticate as the same user, so a `(gateway, user,
  audience)` cache key collides; the inbound credential is the only
  distinguishing factor, which is exactly what the fix added to the key.
- **Deterministic AS.** `POST /token` answers `client_credentials` (the
  gateway's discovery sub-config) with an opaque token, and a token-exchange
  grant with an `access_token` that is a deterministic function of the inbound
  `subject_token` and audience — so a **distinct inbound credential always
  yields a distinct upstream token**, and a cache hit (no fresh exchange)
  reuses a byte-identical one.
- **Recording upstream** (both loopback families): advertises one tool
  `read_note(nonce)`; records every federated `tools/call` with the bearer
  fingerprint and the nonce, so each call is tied to the leg that caused it.
  (A tool, not a resource: 1.0.x registration-time discovery reliably finds
  tools, and the token-exchange cache is consulted for a federated tool call
  just as for a resource read.)
- **`fresh_cache`** registers a **fresh** token-exchange gateway + virtual
  server (new gateway id ⇒ cold cache). The probe uses it between the two cold
  controls and before the warm run.
- The probe then runs:
  - **cold control** — each credential alone, on its own fresh gateway, must
    mint a **distinct** upstream token (else the result is INCONCLUSIVE, never
    a leak);
  - **warm test** — credential 1 populates the cache, credential 2 hits it:
    **FAIL** if credential 2's upstream call carried credential 1's token.

## 1. Install and run ContextForge (loopback only)

```
uv venv --python 3.13 <venv>
uv pip install --python <venv>/bin/python "mcp-contextforge-gateway==<version>" "pyjwt[crypto]" cryptography

cd <cfhome>
<venv>/bin/python -m mcpgateway.scripts.init_secrets          # -> .env.secrets
# build .env from .env.secrets plus:
#   DATABASE_URL=sqlite:///./mcp.db  HOST=127.0.0.1  PORT=<46xx>
#   PLATFORM_ADMIN_EMAIL=admin@example.com
#   SSRF_ALLOW_LOCALHOST=true           # allow the 127.0.0.1 token_url/upstream
#   MCP_CLIENT_CONNECT_MODE=auto
<venv>/bin/python -m mcpgateway.bootstrap_db
cd <cfhome> && set -a && . ./.env && set +a && <venv>/bin/python -m mcpgateway   # serves :<46xx>
```

## 2. Run the gate

With the CF venv and the CF `.env` loaded (so `create_jwt_token` matches the
running server), from the repository root:

```
cd <repo> && set -a && . <cfhome>/.env && set +a
export CF_URL=http://127.0.0.1:<46xx> CF_DB=<cfhome>/mcp.db CF_VERSION=<version> \
       CF_REST_PREFIX=/v1 CF_UP_PORT=4622 CF_AS_PORT=4621
<venv>/bin/python integration/xid10_cf_samecred_cache.py
```

Run it once per version (1.0.11, then 1.1.1, then optionally 1.1.0). The saved
run lands under `integration/runs/`; a redacted copy belongs in
`integration/sample-runs/contextforge-<version>-samecred-cache.json`, which
`integration/gen_results.py` reads for the "Validation against CVE-2026-110195"
section of `RESULTS.md`.

## Gotchas (all encoded in the gate)

- **The caller must exist in CF's user DB.** Both credentials are JWTs for the
  bootstrapped `admin@example.com`; a JWT for an unknown email is rejected
  (`User not found in database`). Two credentials of one *existing* user is all
  the collision needs.
- **Modern envelope.** 1.0.x validates discovery results against the
  `2026-07-28` schema, so the upstream's `tools/list` / `tools/call` results
  carry `resultType` (and `cacheScope` / `ttlMs` on lists).
- **Fresh gateway per cold run.** The exchange cache key includes the gateway
  id, so a new registration gives a cold cache without restarting CF.
- **Live expiry is not exercised here.** The cache TTL tracks the token's
  `expires_in` and CF serves within a skew window, so the expired-cache case is
  covered by the in-process practice unit test
  (`tests/test_credcache.py::ObservationAndHygieneTests::test_expired_cache_observation_recorded`)
  rather than a flaky live wait.

## What it shows

| Version | cold control | warm: credential 2's upstream token | verdict |
|---|---|---|---|
| **1.0.11** | distinct per credential | **credential 1's token (reused)** | FLAGGED (vulnerable) |
| **1.1.0** | distinct per credential | its own distinct token | OK |
| **1.1.1** | distinct per credential | its own distinct token | OK |

Root cause (source): `services/token_exchange_cache.py` keyed on
`(gateway_id, user_email, audience)`; the fix adds the inbound `subject_token`
to the key and bumps the namespace to `token_exchange:v2:`. Confirmed from both
the version diff and the live runs.

## Applicability to the other gateways

The probe only applies to a gateway that (a) does RFC 8693 token exchange, (b)
**caches** the exchanged token, and (c) could key that cache in a way that
collides across two credentials of one user.

- **agentgateway 1.7.0 — run, OK (not this class).** The same probe, driven
  through the v1.7.0 release binary (sha256-verified against the published
  checksum; cold cache = process restart), grades **OK**: credential 2 triggers
  its own fresh exchange and carries its own distinct token, so agentgateway
  re-exchanges per credential rather than reusing a cached per-user token. See
  `integration/xid10_agw_samecred_cache.py` and
  `integration/sample-runs/agentgateway-1.7.0-samecred-cache.json`.
- **LiteLLM 1.109.1 — expected OK from its cache key, not run.** LiteLLM caches
  exchanged tokens keyed on the **subject token** (plus tenant and exchange
  config, per `LITELLM_GATE.md`), so two credentials of one user already get
  distinct entries. LiteLLM is not installed on this machine, so the probe was
  not run against it; this is an expectation from its documented key, not a
  result.
