# XID-10 gate against LiteLLM (setup recipe)

Drives the delegation probe through **LiteLLM**, an LLM gateway with MCP
features, doing RFC 8693 token exchange against the local AS (`local_as.py`).
LiteLLM is the deputy under test; `local_as` is the IdP; a recording MCP server
(started by the driver) is the upstream. Same six checks as the ContextForge
and agentgateway gates, plus scope narrowing, issuer binding, an
exchange-failure check, a cache trial and a task-handle trial.

Pinned to **LiteLLM 1.109.1** (`litellm[proxy]` from pip, open-source build, MIT;
MCP SDK 2.3.0). The driver refuses any other installed version and records the
version, the MCP SDK version, the licence field and the sha256 of the installed
dist-info `RECORD` in every run. Configured by its config file only; no source
changes. No licence key, no database, no model-provider keys.

Driver: `integration/xid10_litellm_gate.py`. Configs: `integration/litellm/`.
Sample runs: `integration/sample-runs/litellm-*.json`.

## Prerequisites

```
uv venv --python 3.12 <llvenv>
uv pip install --python <llvenv>/bin/python "litellm[proxy]==1.109.1"
uv venv --python 3.13 <venv>            # the driver's Python
uv pip install --python <venv>/bin/python "pyjwt[crypto]" cryptography
```

## Ports

All required, all on 127.0.0.1, all in **4500-4699** (45xx for these modes; 46xx for the deeper scenarios), never 4000, 4444 or
8790 (the driver refuses to start otherwise):

| Variable | What |
|---|---|
| `AS_BASE` | `http://127.0.0.1:<port>` of the local AS you started |
| `LL_PORT` | LiteLLM (`--host 127.0.0.1`) |
| `UPSTREAM_PORT` | the recording upstream |
| `FIXTURE_BASE=N` | in-run fixtures: fixture AS N, thin upstream N+2, thin deputy N+3, switchable token endpoint N+4, fall-through deputy N+5 |

## 1. Local AS, in the mode the scenario needs

```
# default (every scenario except b and e-lax)
<venv>/bin/python integration/local_as.py serve --port 4590 --key-path <dir>/as_key.pem
# b: the actor comes from the gateway's client authentication
<venv>/bin/python integration/local_as.py serve --port 4590 --key-path <dir>/as_key.pem \
    --client litellm-gw:$LL_CLIENT_SECRET --act-from-client
# e: issuer_unregistered (lax; issuer_unregistered_strict uses the default AS above)
<venv>/bin/python integration/local_as.py serve --port 4590 --key-path <dir>/as_key.pem --lax-subject-issuer
```

**Client authentication (new in local_as).** `--client ID:SECRET` (repeatable)
registers a client for the token-exchange grant. Every exchange record says
whether client credentials arrived (`client_auth_method`:
`client_secret_basic`, `client_secret_post`, `client_id_only`, `multiple` or
none), the `client_id`, and whether they were valid (`client_valid`, or `null`
when no clients are registered). The secret is never logged.
`--client-auth none|optional|strict` decides what is refused (default `none`:
nothing, the old behaviour; refusal is HTTP 401 `invalid_client`).
`--act-from-client`: valid client credentials and no `actor_token` give
`act: {"sub": <client_id>}`. Off by default, so existing runs are unchanged.
Each run records the AS mode (`login_server`) and, per exchange, the client
authentication it saw (`exchanges_client_auth`); `act_from_client` runs get
`-act_from_client` in the file name and are kept out of the scenario tables.

## 2. Run

```
export AS_BASE=http://127.0.0.1:4590 LL_PORT=4500 UPSTREAM_PORT=4580 FIXTURE_BASE=4560
export LL_BIN=<llvenv>/bin/litellm LL_CLIENT_SECRET=<throwaway>
LL_MODE=delegation                     <venv>/bin/python integration/xid10_litellm_gate.py   # a (and b, with the act_from_client AS)
LL_MODE=two_issuers                    <venv>/bin/python integration/xid10_litellm_gate.py   # c
LL_MODE=scope_narrowing                <venv>/bin/python integration/xid10_litellm_gate.py   # d
LL_MODE=scope_narrowing LL_GW_SCOPES=NONE <venv>/bin/python integration/xid10_litellm_gate.py
LL_MODE=issuer_unregistered            <venv>/bin/python integration/xid10_litellm_gate.py   # e (lax AS)
LL_MODE=issuer_unregistered_strict     <venv>/bin/python integration/xid10_litellm_gate.py   # e (default AS)
LL_MODE=issuer_email_crossprovider     <venv>/bin/python integration/xid10_litellm_gate.py   # f
LL_MODE=exchange_fail                  <venv>/bin/python integration/xid10_litellm_gate.py   # g
LL_MODE=cache                          <venv>/bin/python integration/xid10_litellm_gate.py   # i
LL_MODE=passthrough                    <venv>/bin/python integration/xid10_litellm_gate.py   # broken config, must be flagged
LL_MODE=shared_credential              <venv>/bin/python integration/xid10_litellm_gate.py   # broken config, must be flagged
```

h (task handles) runs in the handle gate:

```
for v in token-exchange passthrough shared-credential; do
  HANDLE_GATEWAY=litellm HANDLE_LL_CONFIG=$v HANDLE_STAGE=trial HANDLE_PORT_BLOCK=4500-4599 \
  HANDLE_AS_PORT=4591 HANDLE_GW_PORT=4501 HANDLE_UPSTREAM_PORT=4581 HANDLE_SCRATCH=<dir> \
  LL_BIN=<llvenv>/bin/litellm <venv>/bin/python integration/handle_gateway_gate.py
done
```

The driver starts LiteLLM itself on a temp copy of the config with the
upstream URL, token endpoint, client secret and (shared credential only) a
static token substituted, and a throwaway master key generated per run. The
saved config has the secret and the token as `sha256:` fingerprints; the
master key is stored only as a fingerprint. LiteLLM's log is kept in memory
and printed only redacted, on failure.

## How it is wired

```
client --(x-litellm-api-key: master key; Authorization: Bearer <user JWT>)--> LiteLLM :4500/mcp
LiteLLM --(RFC 8693: subject_token = the user JWT; client_secret_post)--> local_as /token
LiteLLM --(exchanged token, aud https://upstream.test/mcp)--> upstream :4580/mcp
```

**Protocol version.** LiteLLM 1.109.1 advertises 2024-11-05..2025-11-25 by
default (`general_settings.mcp_advertised_versions` opts in 2026-07-28). The
client asks for 2026-07-28 and gets 2025-11-25; LiteLLM opens the upstream
with `initialize` at 2025-11-25. The recording upstream answers `initialize`
with the legacy version requested (2025-11-25 otherwise) and
`server/discover` with method-not-found. Each run records the client's
negotiated version, the upstream `initialize` versions and the
`MCP-Protocol-Version` headers. Only the task-handle trial opts in to
2026-07-28 on both sides, because the practice task server speaks only that.

**Every OK is shown able to fail in the same run.** `delegation` and
`two_issuers` run the thin-deputy fixtures (`static_credential`,
`token_passthrough`, `cached_token_reuse`, `scope_escalation`, and for
two_issuers `conflated_issuer`) in the same run; a check that passed is graded
OK only if one of them failed it (`check_grades`), else INCONCLUSIVE.
Scope and issuer runs carry the thin `scope_escalation` / `issuer_any`
fixture (the strict-login-server issuer run is an observation, marked
`observation_only`, and carries none: against a login server that refuses the
token no fixture could fail); the exchange-failure run carries a fall-through deputy that forwards
with no `Authorization` when the exchange fails.

## Scenarios, results (1.109.1) and LiteLLM's documentation

Docs pages cited: [MCP overview](https://docs.litellm.ai/docs/mcp),
[MCP OBO auth (token exchange)](https://docs.litellm.ai/docs/mcp_obo_auth),
[MCP OAuth passthrough](https://docs.litellm.ai/docs/mcp_oauth_passthrough).

| | Scenario | Result | What the docs say |
|---|---|---|---|
| a | delegation A, B, A | `actor_present` FAIL; the other five OK (each failed by an in-run fixture) | OBO page: config keys as used here; "keep the LiteLLM key in `x-litellm-api-key`" and leave `Authorization` for the user token; LiteLLM "forwards only the exchanged scoped token". No `actor_token` is documented. |
| b | delegation, AS `act_from_client` | all six OK; actor at the upstream `litellm-gw` (act source: client auth). LiteLLM sent `client_secret_post` in both modes | OBO page: `client_id`/`client_secret` are the credentials LiteLLM uses at the exchange endpoint. |
| c | two issuers, same username | all OK except `actor_present` FAIL | not documented |
| d | scope narrowing | `scopes: [read:notes]` → OK narrowed; no `scopes` → NOT NARROWED | OBO page: `scopes` optional, joined into the OAuth `scope` parameter. |
| e | issuer unregistered, two runs of the same probe | **DELEGATED TO LOGIN SERVER**: in both runs LiteLLM passed the token to the exchange. Strict (default) login server: refused, nothing reached the upstream (controls before and after reached it). Lax login server: granted, the call reached the upstream (in-run `issuer_any` fixture FAIL). The probe's own grades are kept in the runs (strict INCONCLUSIVE, "stopped later, not by the gateway"; lax FAIL); the label is mapped in `gen_results.py`, as the other observation labels are | not documented; the OBO page describes the bearer as the `subject_token` the IdP exchanges. Open-source LiteLLM does no inbound JWT validation in this config (JWT auth is a licensed feature). Whether issuer validation happens at the gateway or at the login server is a deployment choice; on LiteLLM's open-source build it happens only at the login server. |
| f | email claimed across providers | ACCEPTED AS X (no user store) | not documented |
| g | exchange failure, control first | OK, fails closed: nothing reached the upstream with or without `Authorization`; caller gets HTTP 200 + tool error "Missing or invalid subject token…" on `/mcp`, 401 + `WWW-Authenticate` on `/mcp/notes` with no token; fall-through fixture FAIL | OBO page: a request with no user token gets `401 Unauthorized` and is not forwarded (true on `/mcp/<server>`; the aggregate `/mcp` returns a tool error). Exchange failure: no status documented. |
| h | task handles: token exchange, passthrough, shared credential | NOT SUPPORTED in all three: LiteLLM answers `tasks/get`, `tasks/update`, `tasks/cancel` itself with -32601 and does not forward the tasks capability; the probe is not run | MCP overview: tasks are not mentioned. Passthrough page: `true_passthrough` forwards "the client's `Authorization`" unchanged. Overview: `bearer_token` sends a configured static bearer. |
| i | caching of `resources/read` | DOES NOT CACHE (1 origin read per gateway read, twice); the cachescope probe is not run | MCP overview: token caching is documented for client credentials; no result cache is documented. |
| — | broken configs through LiteLLM | `passthrough` flagged (actor, audience); `shared_credential` flagged (subject, actor, reuse, bleed) | see h |

Exchanged tokens are cached per subject token (A's first and third calls
carried the same token). The OBO page says the cache is keyed by subject token
and MCP server ID; in the 1.109.1 source (`outbound_credentials/token_exchanger.py`
`_cache_key`) the key is the subject token, tenant and the exchange config
(endpoint, audience, scopes, client id and secret, ...), not the server id.
Two servers with identical exchange config were not tested.

## Notes / gotchas (encoded in the driver)

- Tools are prefixed with the server name (`notes-read_note`).
- LiteLLM opens a fresh upstream session per gateway request and sends a
  `tools/list` after each `tools/call`; only tools/call and resources/read are
  graded.
- With the user token but no LiteLLM key the proxy answers HTTP 400
  `No connected db.` (it tries to read the JWT as a key).
- Client authentication: LiteLLM sends `client_id` + `client_secret` as form
  parameters (`client_secret_post`).
- Scope: localhost only. The AS, LiteLLM, the upstream and the fixtures are all
  local and disposable.
