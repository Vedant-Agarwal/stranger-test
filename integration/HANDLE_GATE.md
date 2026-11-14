# TASK-HANDLE gate: the task-handle probe through real gateways

Runs the saved-reference probe (`strangertest/handle.py`) through two real,
third-party MCP gateways, with the practice task server
(`strangertest/practice_handle_http.py`) as the upstream. Driver:
`integration/handle_gateway_gate.py`. CoSAI MCP Security v2.0 sections 3.2.7 /
3.2.12. Run on 2026-11-11, macOS, Python 3.13.

| Gateway | Forwards the tasks extension? | Grade | Sample runs |
|---|---|---|---|
| IBM ContextForge **1.1.1** | **No** | **INCONCLUSIVE** (cannot be tested: no tasks) | `sample-runs/contextforge-handle-trial.json` |
| agentgateway **1.7.0**, token exchange (`handle-token-exchange.yaml`, the compliant config) | **Yes** | **OK**, enforced by the **upstream**, not the gateway | `sample-runs/agentgateway-handle-token-exchange-{safe,leaky,trial}.json` |
| agentgateway 1.7.0, per-user passthrough (`handle-per-user.yaml`) | Yes | **OK**, but the config forwards the user's own token (breaks the no-token-passthrough rule) | `sample-runs/agentgateway-handle-safe.json`, `-leaky.json`, `-trial.json` |
| agentgateway 1.7.0, ONE shared upstream credential (`handle-shared-credential.yaml`) | Yes | **LEAK** (configuration risk: `backendAuth.key` is a documented option) | `sample-runs/agentgateway-handle-shared-credential-{safe,leaky}.json` |

MCP version: **2026-07-28 on both sides** for both gateways (client to gateway:
`MCP-Protocol-Version: 2026-07-28` plus the `_meta` envelope; gateway to
upstream: every request the upstream saw carried `2026-07-28` in both the header
and `_meta`, recorded as `upstream_protocol_versions_seen`). The practice server
speaks only 2026-07-28, so a version mismatch would have shown up as a failed
discovery, and none did.

## Step 1: does each gateway forward tasks?

### ContextForge 1.1.1: NO, so INCONCLUSIVE

- **Source** (pip package `mcp-contextforge-gateway==1.1.1`, read only):
  - `mcpgateway/transports/streamablehttp_transport.py:4030-4040` registers MCP
    handlers for `server/discover`, `tools/list`, `tools/call`, `prompts/*`,
    `resources/*`, `completion/complete` and `logging/setLevel` only. There is
    no `tasks/get`, `tasks/update` or `tasks/cancel` handler.
  - `streamablehttp_transport.py:2104-2130`: `tools/call` always returns a
    `types.CallToolResult`. There is no `CreateTaskResult` path.
  - `grep` finds no `io.modelcontextprotocol/tasks`, MCP `tasks/get` or
    `CreateTaskResult` anywhere under `mcpgateway/`. The only `tasks/get` and
    `tasks/cancel` strings are the A2A routes (`main.py:10455-10530`,
    `services/a2a_protocol.py:40-42`), which are not MCP.
- **Trial** (`HANDLE_STAGE=trial`, one user, the CF platform admin JWT inbound):
  - CF registered the practice server and stored its advertised capability
    `extensions: {"io.modelcontextprotocol/tasks": {}}`, but did not use it.
  - The client's `tools/call` declared the tasks extension in `_meta`. The
    `tools/call` that CF sent upstream **did not carry the capability**
    (`tasks_ext_declared: false`), so the upstream correctly answered with a
    plain result. The client received `{"content":[{"text":"done"}],
    "resultType":"complete"}`, not a task.
  - `tasks/get`, `tasks/update` and `tasks/cancel` got HTTP 404 from CF with
    `{"code":-32601,"message":"Method not found","data":"tasks/get"}` (and the
    same for the other two). None of them reached the upstream.
- The finding stops there. Nothing was built around it (no translating proxy,
  no patch, no plugin).

### agentgateway 1.7.0: YES

- **Source** (tag `v1.7.0`, git `26f5aebe99a3`, read only):
  - `crates/agentgateway/src/mcp/session.rs:736-756`: `GetTask`, `UpdateTask`
    and `CancelTask` are parsed, checked against the configured static
    `mcpAuthorization` CEL policy (`authorize_task_request`,
    `session.rs:256-280`, resource type `Task(target, taskId)`), and sent to the
    upstream. **Nothing binds a taskId to the user who created it.**
  - `handler.rs:205-237`: taskIds are namespaced as `<target>+<id>` only when
    several targets are multiplexed. With one target they pass through
    unchanged.
  - `streamablehttp.rs:428-441`: `tasks/*` are name-bearing, so the `Mcp-Name`
    header must equal `params.taskId`.
  - `schema/cel.md:191-193`: `mcp.task.target` and `mcp.task.name` are
    available to authorization rules (a static allow/deny per task id, not
    per-owner).
- **Trial:** the CreateTaskResult passed through unchanged, and `tasks/get`,
  `tasks/update` and `tasks/cancel` all reached the upstream. The client's tasks
  capability arrived in the upstream's `_meta`.
- **First trial attempt: a client bug, not a gateway result.** The repo's
  `HTTPTransport` sends `Mcp-Name` only for `tools/call`, `prompts/get` and
  `resources/read`. agentgateway therefore refused every `tasks/*` with HTTP 400
  `-32020 "invalid MCP routing header: Mcp-Name"`. The tasks extension SEP
  requires the header. SEP-2663, `seps/2663-tasks-extension.md` line 515, says
  for `tasks/get`, `tasks/update` and `tasks/cancel` over Streamable HTTP that
  "the client **MUST** set the `Mcp-Name` header ... to the value of
  `params.taskId`"
  (<https://github.com/modelcontextprotocol/modelcontextprotocol/blob/200d5339bbc7649ee92d6445dc17368e2b5b11ba/seps/2663-tasks-extension.md>,
  fetched 2026-11-11). Read alongside: the official Python SDK
  (`mcp_types/_types.py:139` in mcp 2.3.0) and agentgateway
  (`streamablehttp.rs:428-441`). The core 2026-07-28 transport table lists only
  `tools/call`, `resources/read` and `prompts/get` as name-bearing; the tasks
  requirement comes from the extension. Fixed in `handle.py` (`TasksHTTPTransport`;
  `transports.py` itself is untouched). Without the fix, the probe would have
  been INCONCLUSIVE because its own controls fail, not OK.

## Step 2: the probe through agentgateway

### Token exchange (the compliant config)

`handle-token-exchange.yaml`: inbound `jwtAuth` (strict), then
`backendAuth.oauthTokenExchange` at the driver's own local AS. The user's
validated JWT is the subject token and the client's `x-actor-token` (a
client-credentials token for `handle-agent`) is the actor token, so the
upstream gets a token with `aud=https://upstream.test/mcp` and
`act.sub=handle-agent`. The practice server runs with `identity_from="jwt"`:
it keys the caller on the token's `(orig_iss or iss, sub)`, since a gateway may
exchange a fresh token per request.

Each run checks, at the upstream, that the exchange really happened
(`token_exchange_at_upstream`): the user's own token never arrived, every
token's `aud` is the upstream, and every token's `act.sub` is the agent. A run
where any of these fails is invalid. Observed (2026-11-11): all three held, on
32 upstream calls in the safe run. agentgateway reused one exchanged token per
user (two distinct tokens at the upstream).

| Upstream | get | update | cancel | Overall |
|---|---|---|---|---|
| `leaky` (broken fixture, must fail) | LEAK | LEAK | LEAK | **LEAK** (detected) |
| `safe` | OK | OK | OK | **OK** |

As with passthrough, B's request on A's task reached the upstream as B and the
upstream refused it: the gateway adds no task-owner check.

### Per-user passthrough

Setup (`handle-per-user.yaml`): inbound `jwtAuth` (strict) against the driver's
own local AS. Users A (`alice`) and B (`bob`) have distinct RS256 tokens
(audience `agentgateway-api`). `backendAuth.passthrough` forwards each user's
validated JWT, so the practice server, which keys identity on `Authorization`,
sees two distinct users. No `mcpAuthorization` rules are configured.

Both upstream modes run behind **the same agentgateway process** (same pid):
the broken fixture (`leaky`) first, then `safe`. The practice server's mode is
switched in place between them. **OK is allowed only if the fixture is LEAK.**

| Upstream | get | update | cancel | Overall |
|---|---|---|---|---|
| `leaky` (broken fixture, must fail) | LEAK (B received A's marker) | LEAK (`input_required` to `completed`) | LEAK (`working` to `cancelled`) | **LEAK** (detected) |
| `safe` | OK (refused, -32602) | OK (refused, -32602; A's task unchanged) | OK (refused, -32602; A's task unchanged) | **OK** |

**Who enforced what:** in the safe run, B's request naming A's task **reached
the upstream as B** for every method (`b_request_on_a_task_reached_upstream_as_b:
true`), and the upstream refused it. agentgateway added no task-owner check,
which matches the source: its only task gate is a static CEL policy. So the OK
reflects the upstream's owner check, which works through the gateway because
the gateway preserves per-user identity. **agentgateway itself neither adds nor
removes protection here.** Behind a leaky upstream, B gets A's task through
agentgateway unhindered.

This config forwards the user's own token to the upstream, which breaks the
CoSAI no-token-passthrough rule. So its runs carry
`violates_no_token_passthrough: true` and `counts_toward_gateway_verdict:
false`; the gateway's task-handle verdict comes from the token-exchange runs.

### Configuration risk: one shared upstream credential

`handle-shared-credential.yaml` is the same config, except that
`backendAuth.key` sends one static credential for every user. `backendAuth.key`
is a **documented** agentgateway option: the docs page "Static keys and
passthrough"
(<https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/backend-authn/key/>)
says a static key "sends a value that you configure, either inline or from a
file on disk"; the v1.7.0 generated config reference (`schema/config.md`) lists
`backendAuth.key`; and the v1.7.0 example `examples/llm-telemetry/tracing/phoenix.yaml`
uses it. Each shared-credential run records these citations under
`backendauth_key_documented`. Through it the
upstream saw **one** identity for A and B (`upstream_distinguishes_users:
false`). Even the **safe** upstream returned A's marker to B and let B update
and cancel A's tasks: **LEAK on all three methods**. The gateway still
authenticated A and B as distinct users at its edge. The leak comes from that
deployment choice: the upstream cannot tell users apart, and the gateway binds
no task to its creator. This is a configuration hazard of the gateway, not a
bug in agentgateway's code, and it was observed on a config we wrote.

## How to run

Prerequisites: the agentgateway v1.7.0 release binary, checked against GitHub's
digest (see `AGENTGATEWAY_GATE.md`), and a venv with
`mcp-contextforge-gateway==1.1.1` and `pyjwt[crypto]`. For ContextForge, a
`CF_HOME` holding a bootstrapped `.env` (from `init_secrets`, plus
`DATABASE_URL=sqlite:///./mcp.db`, `HOST=127.0.0.1`, `SSRF_ALLOW_LOCALHOST=true`,
`SSO_API_TOKEN_AUTH_ENABLED=true`, `PLATFORM_ADMIN_EMAIL=admin@example.com`) and
`python -m mcpgateway.bootstrap_db`.

**Ports are required and explicit.** The driver refuses to start if any port is
unset, outside `HANDLE_PORT_BLOCK` (default `4200-4299`), equal to 8790 or 4444,
or already listening. It runs its own local AS, its own practice upstream and
the gateway, all on 127.0.0.1, and records every URL and port in the run.

```
export HANDLE_SCRATCH=<scratch> HANDLE_AS_PORT=4290 HANDLE_UPSTREAM_PORT=4280
# agentgateway
export AGW_BIN=<dir>/agentgateway-darwin-arm64 HANDLE_GW_PORT=4230 HANDLE_AGW_ADMIN_PORT=4231
HANDLE_GATEWAY=agentgateway HANDLE_STAGE=trial <venv>/bin/python integration/handle_gateway_gate.py
HANDLE_GATEWAY=agentgateway HANDLE_STAGE=probe HANDLE_AGW_CONFIG=token-exchange <venv>/bin/python integration/handle_gateway_gate.py
HANDLE_GATEWAY=agentgateway HANDLE_STAGE=probe <venv>/bin/python integration/handle_gateway_gate.py
HANDLE_GATEWAY=agentgateway HANDLE_STAGE=probe HANDLE_AGW_CONFIG=shared-credential <venv>/bin/python integration/handle_gateway_gate.py
# ContextForge (trial only: it does not forward tasks)
CF_HOME=<cfhome> HANDLE_GATEWAY=contextforge HANDLE_GW_PORT=4244 HANDLE_STAGE=trial <venv>/bin/python integration/handle_gateway_gate.py
```

`HANDLE_SCRATCH` is required too (an existing directory for the AS key and the
gateway's config copy); there is no temp-dir fallback.

**Exit codes.** `2` if the driver cannot run at all (pyjwt or `local_as`
missing), with an `ERROR:` line on stderr. `1` for a refusal (unset or bad
port, unset `HANDLE_SCRATCH`, A and B with the same credential) or an invalid
run. A run is invalid when, in the probe stage, the leaky fixture was not LEAK
through the same gateway; when any mode's upstream received no `tools/call`
(so nothing could be observed); or when the trial could not complete (a call
got no server answer, or the gateway never reached the upstream). Run files
are still saved and carry `run_valid: false` and `run_problems`, and one
`ERROR:` line is printed per problem. `0` otherwise. That includes a completed
trial whose honest outcome is "the gateway does not forward tasks"
(ContextForge): grade INCONCLUSIVE, with the reason.

**What a grade is about.** Every run carries `agw_config` (`token-exchange`,
`per-user`, `shared-credential`, or `null` for ContextForge), `grade_subject`,
and `counts_toward_gateway_verdict` (true only for token exchange and
ContextForge). Per-user passthrough runs also carry
`violates_no_token_passthrough: true`. The shared-credential runs keep their LEAK,
but `grade_subject` says they grade a deployment we configured
(`backendAuth.key`, one static upstream credential for all users), and
`counts_toward_gateway_verdict` is `false`. Do not read them as "agentgateway:
LEAK".

Runs land in `integration/runs/` (git-ignored). Copies are kept in
`integration/sample-runs/`. Bearer tokens appear only as `sha256:`
fingerprints; this includes the static `backendAuth.key` value in the stored
config text.

## Where a false LEAK or a false OK could come from, and what catches it

| Risk | Kind | Caught by |
|---|---|---|
| A's task changes with nobody acting (self-progressing) | false LEAK | drift check; `test_self_progressing_task_is_inconclusive_not_leak`, `test_stable_task_passes_drift_check` |
| Cosmetic change (statusMessage, lastUpdatedAt) counted as a leak | false LEAK | leak rule per method; `test_cosmetic_change_is_observation_not_leak`, `test_cancel_leaks_only_when_cancelled`, `test_update_leaks_when_*` |
| Marker found as a substring | false LEAK | exact leaf equality; `test_exact_leaf_only` |
| Existence oracle (different error for a foreign id) counted as a leak | false LEAK | recorded as an observation; `test_existence_oracle_is_observation_not_leak` |
| Answers served by something other than the target (**seen here**: restarting the upstream on the same port left the gateway's keep-alive connections on the old leaky server, so a "safe" run read LEAK while the new server saw 0 requests) | false LEAK/OK | mode switched in place (`TasksState.reset`), `test_mode_switch_in_place_takes_effect`; the gate grades INCONCLUSIVE if the upstream saw no `tools/call` in that mode |
| A and B are really one user (the same inbound credential) | false LEAK | the gate refuses to run if A's and B's inbound tokens are equal (gate check, not a unit test) |
| Refusal of a malformed request, not an authorization decision (**seen here**: missing `Mcp-Name` gave -32020) | false OK | B's own get/update/cancel controls through the same path; `test_malformed_request_refusal_is_inconclusive_never_ok`, `test_tasks_requests_carry_mcp_name`, `test_update_rejected_for_own_task_is_inconclusive_never_ok`, `test_own_cancel_failure_is_inconclusive_never_ok` |
| Target or gateway does not support tasks (**seen here**: ContextForge) | false OK | `test_no_tasks_extension`, `test_client_without_capability_is_inconclusive` |
| Broken observer (A cannot read its own marker) | false OK | positive control; `test_broken_observer_is_inconclusive_not_ok` |
| Mutation acknowledged but its effect not visible in time | false OK | `test_ack_without_observable_change_is_inconclusive` |
| Unreachable target | false OK | `test_unreachable_server_is_inconclusive` |
| Broken fixture not detected through the same gateway | false OK | the gate downgrades OK to INCONCLUSIVE unless the leaky run was LEAK |

## Limits and assumptions

- ContextForge's verdict covers 1.1.1 only, with default settings and a
  `STREAMABLEHTTP` gateway. Its trial used the platform admin JWT as the inbound
  caller, which is enough to show that tasks are not forwarded but is not
  per-user auth. The `direct_proxy` gateway mode was not tried; the source shows
  it still returns `CallToolResult` and registers no `tasks/*` handler.
- agentgateway's verdict covers 1.7.0 with a single MCP target (no taskId
  namespacing), `statefulMode: stateful`, and no `mcpAuthorization` rules. A
  per-task CEL rule could restrict tasks, but it is static and cannot express
  "only the creator".
- The upstream is the repo's practice server. Its owner check keys on the raw
  `Authorization` value. A real upstream would key on a validated subject.
- Task IDs were handed to B; guessing them is out of scope.
