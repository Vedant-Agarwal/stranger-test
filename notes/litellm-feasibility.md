# LiteLLM as a third XID-10 gateway: feasibility check (2026-11-13)

Exploration, one evening. Not a gate: nothing here was saved under
`integration/runs/`, nothing feeds `gen_results.py`, and no existing probe,
gate, grade or sample run was changed. Driver: `integration/litellm_feasibility.py`
(exploration script, loopback 44xx only, tokens as `sha256:` fingerprints only).

## Version, install, licence

- **LiteLLM 1.109.1**, `uv pip install "litellm[proxy]"` into its own Python 3.12
  venv in a scratch folder outside the repo. That pulled `mcp` 2.3.0,
  `litellm_enterprise` 0.1.82 and `litellm_proxy_extras` 0.4.113.
- Licence: `litellm` dist-info says `License-Expression: MIT`.
  `litellm_enterprise` is `LicenseRef-Proprietary`, but it is only installed as
  a dependency. The outbound MCP exchange path (`proxy/mcp_server/outbound_credentials/token_exchanger.py`,
  the resolver, `mcp_server_manager.py`) has no `premium_user` or licence check.
  The `premium_user` gates in `mcp_server/` are on other features: LiteLLM's own
  inbound IdP-token exchange on `POST /token` (`idp_token_exchange.py`), ID-JAG
  and the bridge token flow.
- **Live confirmation:** the exchange ran with no licence key, no database and
  only a throwaway master key (below). **MCP token exchange works without an
  Enterprise licence.**

## Setup used

Loopback only: local_as `:4490`, LiteLLM `:4400`, recording upstream `:4480`,
plus a scratch switchable token endpoint `:4491` used only for 5a (it forwards
to local_as `/token` until it is switched to always fail; it lives outside the
repo). Started by hand:

```
python integration/local_as.py serve --port 4490 --key-path <scratch>/as_key.pem
LITELLM_MASTER_KEY=sk-throwaway-<random> LITELLM_LOCAL_MODEL_COST_MAP=True LITELLM_TELEMETRY=False \
  <venv>/bin/litellm --config ll-delegation.yaml --host 127.0.0.1 --port 4400
```

```yaml
model_list: []
litellm_settings:
  telemetry: false
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
mcp_servers:
  notes:
    url: http://127.0.0.1:4480/mcp
    transport: http
    auth_type: oauth2_token_exchange
    token_exchange_endpoint: http://127.0.0.1:4490/token
    client_id: litellm-gw
    client_secret: throwaway-client-secret
    audience: https://upstream.test/mcp
    scopes: ["read:notes"]
    subject_token_type: urn:ietf:params:oauth:token-type:jwt
    token_exchange_profile: rfc8693
```

LiteLLM binds only `127.0.0.1:4400` (checked with `lsof`). No model-provider keys.
The caller sends `x-litellm-api-key: <master key>` and `Authorization: Bearer <user JWT from local_as /issue>`.

## MCP protocol versions

- **Caller side:** by default LiteLLM advertises only the legacy versions
  `2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25` (`capabilities.configured_versions()`,
  `MCP_LEGACY_VERSIONS`). `2026-07-28` is opt-in through
  `general_settings.mcp_advertised_versions` and is refused on `/sse`. The repo's
  `MCPClient` asks for `2026-07-28` and LiteLLM answered `2025-11-25`. The
  client then ran legacy Streamable HTTP (`HTTPTransport(modern=False)`).
- **Upstream side:** a server's `protocol_version` defaults to `auto`. Against
  the recorder, LiteLLM sent `initialize` with `2025-11-25`, then
  `MCP-Protocol-Version: 2025-11-25` on each request. It never sent
  `server/discover`.
- The recorder answers `initialize` with the version requested when that version is
  legacy, otherwise with `2025-11-25`. The agentgateway gate's upstream answers
  `2026-07-28` regardless, so it was not reused.
- Not tried: LiteLLM in `2026-07-28` mode on either side.

## Step 3: one tool call as user A — **got through**

Tool exposed as `notes-read_note` (server-name prefix). Caller got `ok`. The upstream
saw, for `tools/list`, `tools/call`, `tools/list`, one bearer `sha256:e98bfdcf1596`
= `{sub: alice, aud: https://upstream.test/mcp, scope: read:notes, iss: local-as, act: none}`.
local_as recorded one exchange: subject `sha256:dbf626d252f4` (alice's user
JWT), `requested_audience=https://upstream.test/mcp`, `requested_scope=read:notes`,
`actor_present=false`, issued `sha256:e98bfdcf1596`. The user JWT's fingerprint
never appeared upstream. Header names reaching the upstream: accept,
accept-encoding, authorization, connection, content-length, content-type, host,
mcp-protocol-version, mcp-session-id, user-agent. No `x-litellm-api-key`.

Two side observations: LiteLLM opens a fresh upstream session
(`initialize`, GET, DELETE) per gateway request, and it sends a `tools/list`
after each `tools/call`.

## Step 4: delegation probe A, B, A (grading unchanged)

| Check | Result | Observed |
|---|---|---|
| subject_preserved | **OK** | alice, bob, alice (iss local-as) |
| actor_present | **FAIL** | `act` absent on all three: LiteLLM sends no `actor_token` (`_rfc8693_form` has no actor field), so this is impersonation |
| audience_correct | **OK** | `aud=https://upstream.test/mcp` on all three |
| scope_narrowed | **OK** | `read:notes` |
| no_token_reuse | **OK** | A `sha256:f7393c192ba6` ≠ B `sha256:84b76d099d54` |
| no_cross_identity_bleed | **OK** | A's 3rd call is alice on A's own token |

Probe summary: `LEAK ... (actor_present) — impersonation`. This is the expected
outcome of a gateway that impersonates by design, the same shape as the
agentgateway `impersonation` row. LiteLLM has no delegation configuration to
compare it against.

## Step 5 observations

**a. Exchange failure.** Control first, through the switchable token endpoint
while it forwarded: tools/list and tools/call reached the upstream with the exchanged
token (`sha256:c3765397d825`). Then the endpoint was switched to always 400:

- new user token for alice (cache miss): **nothing reached the upstream**. The
  token endpoint got 2 failing exchange attempts. The caller got HTTP 200 with a
  tool result `isError: true`, "Missing or invalid subject token. Authenticate
  with your identity provider…", which misleads because the subject token was
  valid and the AS refused it.
- no `Authorization` at all: **nothing reached the upstream**, and **no exchange was
  attempted** (the fail counter did not move). Same `isError` text.
- on the aggregate `/mcp` the failure is HTTP 200 + `isError`. On the per-server
  endpoint `/mcp/notesflip` a call with no user token is **HTTP 401** with
  `WWW-Authenticate: Bearer resource_metadata="/.well-known/oauth-protected-resource/mcp/notesflip", error="invalid_token"`.
- side, not a failure-path result: the control's own token still worked after
  the switch, because its exchanged token was cached and no exchange was needed.
- First attempt, with a second server pointed straight at local_as `/token-fail`:
  listing that server failed, so its tool was never registered. The call came
  back as "Tool 'read_note' not found" with nothing upstream. That shows the
  routing refusing the call, not the exchange-failure path, which is why the
  switchable endpoint was added.

So LiteLLM **fails closed** on exchange failure, with or without Authorization.

**b. Same username, two issuers** (alice@provx vs alice@provy, A, B, A): the
two exchanges were separate (subject fps `abfb5e08668c` vs `352e5526a10a`),
the tokens were distinct (`b839436d8659` vs `e61acbe43fb1`), and the upstream saw
`orig_iss` provx, provy, provx. All checks OK except `actor_present` FAIL (as in step 4).
This depends on local_as's `orig_iss` claim, the same known limit as the other gates.

**c. Issuer the login server does not know** (`iss=https://unregistered.test`,
signed with the provx key): **the login server refuses it, not the gateway.**
LiteLLM, with JWT auth off, does not validate the user token at all and passed it
to the exchange twice (local_as seq 11, 12: `refused: invalid_grant: unregistered issuer`).
Nothing reached the upstream, and the caller got the same `isError` text. Control
(provx mallory) went through. Consequence, predicted and NOT run: against the
lax AS used for `issuer_unregistered`, the token would probably reach the
upstream, because nothing in LiteLLM checks the issuer. Validating inbound
JWTs (`enable_jwt_auth`) is Enterprise-licensed and needs a database.

**d. One LiteLLM key, A's token then B's.** The A, B, A probe already does
this: every connection used the same master key. The upstream saw alice, then bob,
then alice, on three separate exchanges (two distinct tokens). The LiteLLM key is
not tied to a user: whoever holds a key can present any user token, and only the
user token decides who the upstream sees. That is ordinary bearer semantics,
not a finding. Also: a user JWT with no LiteLLM key was refused with HTTP 400
`{"detail":"No connected db."}`, because LiteLLM tried to read it as a key.

**e. Caching.** A's 1st and 3rd calls carried the **same** exchanged token
(`a_first_eq_a_third_token: True`). local_as logged one exchange for A and one for
B. Per source, the cache key is sha256 of (subject token, tenant, profile,
endpoint, audience, subject_token_type, client_id, client_secret, auth method,
scopes), held in process, with a TTL of expiry − 60 s (default 3600 s, at least 10 s). A fresh
user token is a new key. The MCP server id is **not** in the key; only the
exchange config is. Not tested: two servers with identical exchange config.

## How LiteLLM differs

| | LiteLLM 1.109.1 | ContextForge 1.1.1 | agentgateway 1.7.0 |
|---|---|---|---|
| Who authenticates the caller | LiteLLM key (`x-litellm-api-key`). The user JWT is **not validated by the gateway** without Enterprise JWT auth; the AS validates it at exchange time | ContextForge validates the user JWT (external IdP) and provisions the user from `email` | `jwtAuth` validates the user JWT against the AS JWKS |
| Who supplies the actor | **Nobody.** No `actor_token`, so impersonation only (`actor_present` FAIL) | The gateway, from its own client credentials (`forge`) | The caller, in `x-actor-token` |
| Exchange failure | Fails closed. Nothing upstream. Caller gets HTTP 200 `isError` on `/mcp`, 401 + `WWW-Authenticate` on `/mcp/<server>` with no token | Fails closed (error), per RESULTS.md resource-read test | Not in RESULTS.md (only missing actor → HTTP 400, nothing upstream) |
| Caching | Per subject token + exchange config, in process. A1 = A3 | Per user. A1 = A3 | Per user. A1 = A3 |
| Setup | pip `litellm[proxy]`, one `config.yaml`, master key, no DB | pip, env + admin API, team role for external users | One release binary + config file (it writes to the config) |
| MCP versions | Legacy (≤ 2025-11-25) by default on both sides; 2026-07-28 opt-in | — | 2026-07-28 on both sides |

## Doc claims

| Claim | Status |
|---|---|
| `mcp_servers:` with `auth_type: oauth2_token_exchange`, `token_exchange_endpoint`, `client_id`, `client_secret`, `audience`, `scopes`, `subject_token_type`, `token_exchange_profile: rfc8693` | **Confirmed.** All parsed by `mcp_server_manager.py` and used live. `profile` also accepts `entra_obo` |
| LiteLLM key in `x-litellm-api-key`, user token in `Authorization` becomes the subject_token | **Confirmed** live. A bearer starting with the virtual-key prefix is never used as a subject |
| Only the exchanged token goes upstream | **Confirmed** for this config. The user JWT fingerprint never reached the upstream, and neither did `x-litellm-api-key` |
| Exchanged tokens cached, keyed on subject token + MCP server | **Partly wrong.** Cached and keyed on the subject token, but on the *exchange config*, not the server id (source). Live: A1 = A3 |
| No user token → 401, nothing upstream | **Partly.** Nothing upstream and no exchange attempted: confirmed. The 401 (with `WWW-Authenticate`) is only on `/mcp/<server>`. Aggregate `/mcp` returns HTTP 200 with an `isError` tool result |
| No actor_token support documented | **Confirmed in source:** the RFC 8693 form has no actor fields |
| Not labelled Enterprise-only | **Confirmed in practice:** no licence check on this path, and it ran without a licence. LiteLLM's *inbound* `/token` exchange and JWT auth are licensed |
| Not checked | Whether `client_id`/`client_secret` reach the token endpoint, and as Basic or post (local_as ignores client auth); `entra_obo`; 2026-07-28 mode; Redis or multi-replica cache |

## Estimate for a proper third gate

About **1.5–2 days**:

- `integration/xid10_litellm_gate.py` modelled on the agentgateway driver:
  start LiteLLM on a temp copy of a repo config with port substitution; record
  version, wheel hash and config sha256; keep the log in memory and redact it;
  use a legacy-protocol recording upstream. About half a day.
- Modes: `impersonation` (the only shape LiteLLM has), `two_issuers`,
  `scope_narrowing` (+ no `scopes`), `issuer_unregistered` (lax AS),
  `issuer_email_crossprovider`, exchange-fail (fail closed), plus a broken
  passthrough fixture if LiteLLM has a passthrough auth type
  (`oauth_passthrough` exists, not tried). About a day with debugging.
- `gen_results.py` column + `LITELLM_GATE.md`. About half a day.
- A decision for you, not for me: LiteLLM can only impersonate, so the
  "distinct actor and subject" cell will always be FAIL. Showing it as FAIL, or
  as NOT SUPPORTED like other cells, is a presentation choice. The grading
  itself stays as it is.

## Processes

Started and stopped: local_as (`:4490`), three LiteLLM runs on `:4400` (delegation,
two-server fail, switchable-endpoint configs; each killed before the next),
the scratch switchable token endpoint (`:4491`), and the driver's in-process
upstream (`:4480`, stopped by each run). After cleanup no process from this
work was running and nothing was listening on 4400–4499. An unrelated local
service was already running and was not touched.
No JWT-shaped string is in any LiteLLM log.
