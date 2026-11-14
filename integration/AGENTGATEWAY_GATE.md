# XID-10 gate against agentgateway (setup recipe)

Drives the delegation probe through a real **agentgateway** doing RFC 8693
token exchange against the local AS (`local_as.py`). agentgateway is the
deputy under test; `local_as` is the IdP; a recording MCP server (started by
the driver) is the upstream. Same six checks and same scenarios as the
ContextForge gate.

Verified against **agentgateway v1.7.0** (git `26f5aebe99a3`), the official
`agentgateway-darwin-arm64` release binary, on macOS. No Docker. The gateway is
configured by its config file only; no source or binary changes.

## Prerequisites

1. The agentgateway binary. Download the release asset and check it against the
   digest GitHub records for it:

   ```
   gh release download v1.7.0 -R agentgateway/agentgateway -p agentgateway-darwin-arm64 -D <dir>
   gh api repos/agentgateway/agentgateway/releases/tags/v1.7.0 \
     --jq '.assets[]|select(.name=="agentgateway-darwin-arm64")|.digest'
   shasum -a 256 <dir>/agentgateway-darwin-arm64     # must match the digest
   chmod +x <dir>/agentgateway-darwin-arm64
   <dir>/agentgateway-darwin-arm64 --version         # "version": "1.7.0"
   ```

   v1.7.0 darwin-arm64 digest: `sha256:34bfc961d0e459d0f89103100e61730d4b5d8e2151c851d33cd034a126eb2bfe`.

2. A Python with pyjwt (the driver itself is otherwise standard library):

   ```
   uv venv --python 3.13 <venv>
   uv pip install --python <venv>/bin/python "pyjwt[crypto]" cryptography
   ```

Everything runs on loopback. **agentgateway binds all interfaces by default**
(gateway, stats `:15020`, readiness `:15021`), so every config here pins the
gateway to `127.0.0.1`, the admin port to `127.0.0.1` (port substituted at run time), and turns stats
and readiness off.

## 1. Local AS (IdP)

The same AS as the ContextForge gate (one signing key per test provider at
`/jwks/<name>`, scope capped at requested ∩ subject, exchange log at
`/exchanges`; see `CONTEXTFORGE_GATE.md`):

```
<venv>/bin/python integration/local_as.py serve --port 4190 --key-path <dir>/as_key.pem
# issuer_unregistered only: add --lax-subject-issuer
```

**Ports.** The configs in `integration/agentgateway/` name fixed ports (AS
8790, gateway 3790, admin 15790, upstream 18790). The driver writes a
port-substituted copy for each run from `AS_BASE`, `AGW_URL`, `AGW_ADMIN_PORT`
and `UPSTREAM_PORT`, refuses to start unless `AS_BASE` and `AGW_URL` are set
explicitly, and refuses ports 8790/4444 (no override). Each run records the endpoints and the sha256 of the substituted
config (`gateway_run_config_sha256`) next to the repo config's hash.

## 2. Run the gate

The driver starts agentgateway itself (on a temp copy of the config, see
gotchas), starts the recording upstream on `127.0.0.1:$UPSTREAM_PORT`, runs the probe,
and stops both. `FIXTURE_PORT` pins the in-run thin-deputy fixture (upstream
on N, deputy on N+1).

The standalone thin-deputy gate (`integration/xid10_thin_deputy_gate.py`) does
not use `FIXTURE_PORT`: it needs `THIN_PORT_BASE=N` (AS on N, lax AS on N+1,
upstream on N+2, deputy on N+3) and refuses to start without it. See the
README.

```
export AGW_BIN=<dir>/agentgateway-darwin-arm64
export AS_BASE=http://127.0.0.1:4190 AGW_URL=http://127.0.0.1:4130/mcp AGW_ADMIN_PORT=4131 UPSTREAM_PORT=4180 FIXTURE_PORT=4170
XID10_MODE=delegation                          <venv>/bin/python integration/xid10_agentgateway_gate.py
XID10_MODE=impersonation                       <venv>/bin/python integration/xid10_agentgateway_gate.py
XID10_MODE=two_issuers                         <venv>/bin/python integration/xid10_agentgateway_gate.py
XID10_MODE=delegation XID10_TRIGGER=resource   <venv>/bin/python integration/xid10_agentgateway_gate.py
```

Side checks (not scenario rows):

```
XID10_MODE=broken_passthrough        <venv>/bin/python integration/xid10_agentgateway_gate.py
XID10_MODE=delegation_missing_actor  <venv>/bin/python integration/xid10_agentgateway_gate.py
```

New checks (same meaning and grades as in `CONTEXTFORGE_GATE.md`):

```
XID10_MODE=scope_narrowing                        <venv>/bin/python integration/xid10_agentgateway_gate.py
XID10_MODE=scope_narrowing XID10_GW_SCOPES=NONE   <venv>/bin/python integration/xid10_agentgateway_gate.py
# with the AS started --lax-subject-issuer:
XID10_MODE=issuer_unregistered                    <venv>/bin/python integration/xid10_agentgateway_gate.py
XID10_MODE=issuer_email_crossprovider             <venv>/bin/python integration/xid10_agentgateway_gate.py
```

Where agentgateway sets the exchange scope: `backendAuth.oauthTokenExchange.scopes`;
in v1.7.0 `crates/agentgateway/src/http/auth/oauth/transport.rs` appends
`scope=<scopes joined by space>` only `if !spec.scopes.is_empty()`. So
`xid10-delegation.yaml` (`scopes: [read:notes]`) requests read:notes and
`xid10-scope-none.yaml` (no `scopes`) requests nothing. agentgateway keeps no
user store, so `issuer_email_crossprovider` only records which identity the
upstream saw.

Configs, one per mode, in `integration/agentgateway/`:

| Mode | Config | Client sends |
|---|---|---|
| `delegation` | `xid10-delegation.yaml` | user JWT + `x-actor-token` |
| `impersonation` | `xid10-impersonation.yaml` (no `actorToken`) | user JWT |
| `two_issuers` | `xid10-two-issuers.yaml` (trusts provX + provY, each via its own `/jwks/<name>`) | user JWT + `x-actor-token` |
| `scope_narrowing` | `xid10-delegation.yaml` (`XID10_GW_SCOPES=NONE`: `xid10-scope-none.yaml`) | user JWT + `x-actor-token` |
| `issuer_unregistered`, `issuer_email_crossprovider` | `xid10-two-issuers.yaml` | user JWT + `x-actor-token` |
| `broken_passthrough` | `xid10-broken-passthrough.yaml` (no exchange) | user JWT + `x-actor-token` |
| `delegation_missing_actor` | `xid10-delegation.yaml` | user JWT only |

Expected (agentgateway 1.7.0):
- `delegation` (tools/call and resources/read) → not vulnerable.
- `impersonation` → vulnerable, `failures=['actor_present']`.
- `two_issuers` → not vulnerable (the two alices stay distinct).
- `broken_passthrough` → vulnerable, `['actor_present', 'audience_correct']`.
- `delegation_missing_actor` → agentgateway refuses discovery with HTTP 400;
  nothing reaches the upstream; no run is saved.

Each run writes `integration/runs/agentgateway-<mode>[-resource]-<ts>.json`
with the checks, the three recorded upstream calls (tokens as `sha256:`
fingerprints only), the full `--version` JSON, and the exact config text and
its sha256. Then regenerate the results page (it folds in the latest run per
scenario):

```
<venv>/bin/python integration/gen_results.py
```

## How it is wired

```
client --(user JWT [+ x-actor-token])--> agentgateway 127.0.0.1:4130/mcp
          jwtAuth: issuer + audience agentgateway-api, JWKS from the AS
agentgateway --(RFC 8693: subject_token [+ actor_token])--> local_as /token
agentgateway --(exchanged token, aud https://upstream.test/mcp)--> upstream :4180/mcp
```

`backendAuth.oauthTokenExchange` sits on the MCP target. The subject token is
the validated inbound JWT (`subjectToken.source.expression:
jwt.rawToken.unredacted()`); `audiences` and `scopes` narrow the exchange.

## Notes / gotchas (all encoded in the driver or configs)

- **Actor token comes from the caller.** agentgateway cannot fetch its own
  actor token (there is no client-credentials actor source, unlike
  ContextForge's `actor_token_source=client_credentials`). `actorToken.source`
  must be a request location, so the calling agent sends a client-credentials
  token for `agent-client` in `x-actor-token`. agentgateway strips that header
  before forwarding upstream (the run records `actor_header_reached_upstream`).
  The `act` claim therefore names the calling agent, not the gateway.
- **Open question (not a finding): who vouches for the actor token?** Because
  the actor token is supplied by the caller, agentgateway validates the user's
  (subject) token but nothing in this config checks that the caller actually
  *is* the agent named in the actor token. A caller holding a user's token and
  any valid `agent-client` token can present itself as that agent. This is
  most likely intended — the authorization server issuing the actor token is
  expected to bind it to the real caller — so it is a question to put to the
  agentgateway maintainers, **not** a bug we report. We have not run a
  "lying caller" test against it for that reason.
- **The gateway writes to its config file.** On startup agentgateway adds a
  generated `config.session.key` to the file it was given. The driver copies
  the config to a temp dir and runs it from there, so the repo file stays clean
  and no generated secret is committed.
- **Protocol version.** agentgateway 1.7.0 requires an `MCP-Protocol-Version`
  header on every request; at `2026-07-28` there is no `initialize`. The driver
  uses the repo's `HTTPTransport(modern=True)`. agentgateway speaks
  `2026-07-28` to the upstream too (no `initialize` upstream either).
- **jwtAuth strips the Authorization header** after validating it (unless
  `preserveToken: true`), which is why the subject token is read with the CEL
  expression rather than the default header source.
- **Fixed ports.** The config names the upstream port, so the upstream listens
  on a fixed port (`UPSTREAM_PORT`); the driver substitutes it into the run
  copy of the config.
- **Logs.** agentgateway's log is kept in memory and printed only on failure,
  with every JWT-shaped string replaced by its fingerprint.
- **Scope:** localhost / servers you run only. The AS, the gateway and the
  upstream are all local and disposable.
