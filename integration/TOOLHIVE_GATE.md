# ToolHive XID-10 gate — reproduction recipe

Stacklok ToolHive **v0.65.0** as a real RFC 8693 token-exchange MCP gateway,
driven with the existing XID-10 probes. Loopback only; ports 46xx; tokens stored
as `sha256:` fingerprints only. ToolHive is the deputy under test; `local_as` is
the IdP; a recording MCP server (started by the driver) is the upstream.

Two modes:
- **standalone** — `thv run <remote-url>` (a transparent proxy to a remote MCP
  server). Driver: `integration/xid10_toolhive_gate.py`.
- **vMCP** — `thv vmcp serve` (a Virtual MCP server aggregating a group).
  Driver: `integration/xid10_toolhive_vmcp_gate.py`.

Why `thv run` and not `thv proxy` for standalone: only `thv run` exposes
`--jwks-allow-private-ip` and `--oidc-insecure-allow-http`, which the loopback
`local_as` needs. **Dev flags disclosure:** those two flags are set **only**
because `local_as` is on `http://127.0.0.1`; they change only *where keys are
fetched from*, not the token-exchange or token-validation logic being tested.
They are recorded in every run file (`gateway_cli`, `dev_flags`).

## Install (operator)

Download the release binary and verify its sha256 against the published
checksums (do not skip this):

```
gh release download v0.65.0 --repo stacklok/toolhive \
  --pattern 'toolhive_0.65.0_darwin_arm64.tar.gz' \
  --pattern 'toolhive_0.65.0_checksums.txt' -D <scratch>
cd <scratch>
shasum -a 256 -c <(grep 'darwin_arm64.tar.gz$' toolhive_0.65.0_checksums.txt)
tar xzf toolhive_0.65.0_darwin_arm64.tar.gz
./thv version   # must print v0.65.0, commit 2cf07aa23a97...
```

License: Apache-2.0. The gate refuses to run against any version other than the
pinned `0.65.0`. ToolHive uses `$HOME`/XDG for state; each driver run uses an
**isolated temporary HOME**, and ToolHive persists no tokens/secrets on these
paths (no secrets provider configured).

## Driver Python

Any Python with `pyjwt[crypto]`:

```
python3 -m venv <scratch>/driver-venv
<scratch>/driver-venv/bin/pip install "pyjwt[crypto]==2.15.1"
```

## local_as (operator starts it, so its mode is explicit and recorded)

```
# strict (delegation, scope, exchange_fail, cache, same_user_credentials, vMCP)
python integration/local_as.py serve --port 4610 --key-path <scratch>/strict.pem

# act_from_client (the actor-via-client-auth delegation variant)
python integration/local_as.py serve --port 4640 --key-path <scratch>/afc.pem \
  --client "toolhive-gw:<secret>" --client-auth optional --act-from-client

# lax (issuer_unregistered: the broken fixture needs the AS to accept any issuer)
python integration/local_as.py serve --port 4650 --key-path <scratch>/lax.pem \
  --lax-subject-issuer
```

## Standalone modes

Common env: `THV_BIN=<scratch>/thv`, `TH_PROXY_PORT=4613`, `UPSTREAM_PORT=4612`,
`FIXTURE_BASE=4620`. `TH_MODE` picks the mode; `AS_BASE` picks the login server.

```
# delegation (strict AS): actor_present FAIL (impersonation, no actor_token)
AS_BASE=http://127.0.0.1:4610 TH_MODE=delegation python integration/xid10_toolhive_gate.py

# delegation via act_from_client (actor appears from client_secret_basic)
AS_BASE=http://127.0.0.1:4640 TH_MODE=delegation TH_CLIENT_SECRET=<secret> \
  python integration/xid10_toolhive_gate.py

# scope narrowing (and the no-scopes variant)
AS_BASE=http://127.0.0.1:4610 TH_MODE=scope_narrowing python integration/xid10_toolhive_gate.py
AS_BASE=http://127.0.0.1:4610 TH_MODE=scope_narrowing TH_GW_SCOPES=NONE \
  python integration/xid10_toolhive_gate.py

# unregistered issuer (lax AS so the broken fixture can fail)
AS_BASE=http://127.0.0.1:4650 TH_MODE=issuer_unregistered python integration/xid10_toolhive_gate.py

# two issuers; cross-provider email; exchange failure; cache; inbound validation
AS_BASE=http://127.0.0.1:4610 TH_MODE=two_issuers              python integration/xid10_toolhive_gate.py
AS_BASE=http://127.0.0.1:4610 TH_MODE=issuer_email_crossprovider python integration/xid10_toolhive_gate.py
AS_BASE=http://127.0.0.1:4610 TH_MODE=exchange_fail           python integration/xid10_toolhive_gate.py
AS_BASE=http://127.0.0.1:4610 TH_MODE=cache                   python integration/xid10_toolhive_gate.py
AS_BASE=http://127.0.0.1:4610 TH_MODE=inbound_validation      python integration/xid10_toolhive_gate.py

# same-user-credentials (CVE-2026-110195 class)
AS_BASE=http://127.0.0.1:4610 TH_MODE=same_user_credentials   python integration/xid10_toolhive_gate.py
```

### ToolHive validates the inbound issuer itself (one configured issuer)

ToolHive validates the inbound token (issuer + signature + audience) against the
single configured OIDC issuer + JWKS, and refuses a mismatch at the gateway with
HTTP 401 before any exchange (the `inbound_validation` observation shows provy,
an unregistered issuer and a wrong audience all refused). Because it binds to one
issuer, the `two_issuers` / `issuer_email_crossprovider` probes are driven with
ToolHive configured for issuer `provx` (so the control token validates):

- `issuer_unregistered` → **OK** (rejected at the gateway), like CF/agentgateway.
- `two_issuers` → **INCONCLUSIVE** (the second issuer is refused at the gateway;
  the A/B conflation cannot be exercised). Results-layer label:
  "NOT APPLICABLE: second issuer refused at gateway".
- `issuer_email_crossprovider` → **OBSERVATION / accepted-as-x**, `run_valid=False`
  (the Y-via-provy positive control cannot be established).

## vMCP mode (`thv vmcp serve`)

```
AS_BASE=http://127.0.0.1:4610 UPSTREAM_PORT=4612 BACKEND_PORT=4615 VMCP_PORT=4614 \
  THV_BIN=<scratch>/thv python integration/xid10_toolhive_vmcp_gate.py
```

The driver creates a ToolHive group, registers the recording upstream as a remote
backend workload in it (`thv run <url> --group`), writes an inline config with
`incomingAuth: oidc` (loopback AS allowed via `jwksAllowPrivateIp` +
`insecureAllowHttp`) and `outgoingAuth` inline `tokenExchange`, and runs
`thv vmcp serve`. `incomingAuth: anonymous` does **not** work — vMCP has no
identity to exchange ("identity has no token"); an authenticated OIDC identity is
required.

**Observation:** on `thv vmcp serve`, each request re-exchanges (a fresh backend
session per request; ~7 exchanges per tool call, a distinct upstream token each
time), so the source-level token cache (`pkg/vmcp/cache/cache.go`:
`{backend}:{hash(subject_token)}:{audience}`) is **not exercised** in this mode.
same-user-credentials therefore grades OK with **cache hit observed = False**
("caching not observed in this run") — the same as standalone, and we do **not**
claim "caches per credential". This is an observation of this deployment mode,
**not a bug**. The **Kubernetes operator deployment** (where backend sessions may
persist and the cache may apply) was **not tested**. **`subjectProviderName`**
(exchange a stored upstream token) was **not run** — it requires ToolHive's
embedded authorization server.

## Results

Each driver writes a redacted run to `integration/runs/` (gitignored); the
committed, fingerprints-only copies are in `integration/sample-runs/toolhive-*.json`,
and the ToolHive section of `integration/RESULTS.md` is generated from them by
`integration/gen_results.py` (regenerate; a second regeneration is byte-identical).
Full suite: `python -m unittest discover` (gen_results tests need the driver venv).

## Cleanup

Each driver stops its own workloads (`thv stop`/`thv rm`), kills the proxy and
removes its temporary HOME. After a run confirm nothing is left: no listeners on
46xx, no `thv` processes, and no `~/Library/Application Support/toolhive` /
`~/.config/toolhive` written by any non-isolated invocation (delete it if a bare
`thv` call created one). Stop the `local_as` instances when done.
