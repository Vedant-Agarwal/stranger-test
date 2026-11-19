# LiteLLM CVE-2026-59822 regression gate — recipe

A regression check that the fix for **CVE-2026-59822** holds on the **FIXED**
versions of LiteLLM. Results label: **"validated against the fix for
CVE-2026-59822 (fixed versions 1.84.0, 1.109.1; invalid/forged tokens
rejected)"**.

- Advisory: <https://github.com/BerriAI/litellm/security/advisories/GHSA-7488-6r32-c95q>
- Fix: <https://github.com/BerriAI/litellm/pull/26463> (first fixed: **1.84.0**)

**Scope (hard rules).** This tests **patched behaviour only**. It installs and
runs **only fixed versions** (1.84.0 and 1.109.1), never anything `< 1.84.0`; the
driver refuses to run against a version below 1.84.0. It records no exploit or
bypass steps — only what a patched server rejects. Loopback only; the master key
and the forged JWT are stored as `sha256:` fingerprints.

## What the fix does

PR #26463 tightened `MCPRequestHandler.process_mcp_request`. Before the fix, an
`Authorization` bearer that failed LiteLLM key validation (401/403) fell back to
an anonymous `UserAPIKeyAuth()` for **any** MCP server. After the fix the
anonymous fallback runs **only if every** target server is operator-configured
`auth_type=oauth2`; for a non-oauth2 server (or an unresolved/empty target list)
the original auth error is re-raised and the request is **rejected**.

So on a fixed version, against a **non-oauth2** MCP server, a request whose
bearer cannot be validated must not establish an authenticated session.

## What the gate asserts (expected PASS on both fixed versions)

Against `integration/litellm/cve59822-default-auth.yaml` (one server,
`auth_type: none`, non-oauth2), it POSTs MCP `initialize` to the per-server
endpoint `/mcp/notes` with four bearers:

| case | bearer | expected |
|---|---|---|
| `no_bearer` | *(none)* | rejected — no session |
| `garbage_bearer` | a non-key string | rejected — no session |
| `forged_bearer` | a well-formed RS256 JWT signed by a key the server does not trust | rejected — no session |
| `valid_bearer` | the run's LiteLLM master key | accepted — session established |

"Session established" = HTTP 200 with an `initialize` JSON-RPC result
(`protocolVersion`). The status code of a rejection differs by version (1.84.0
surfaces the re-raised auth error as **500**; 1.109.1 as **401** for no bearer /
**400** for an unvalidatable bearer) — the gate grades on whether a session was
established, not on the exact code, and records both.

Each conclusion is gated by an **in-run broken fixture**: a fail-open deputy
(`FailOpenDeputy`) that grants a session to any/no bearer. The same check, run
against the fixture, must **catch** it (the fixture establishes sessions for the
invalid bearers) — so the check is shown able to fail before the real gateway's
PASS is trusted.

**STOP rule.** If a fixed version ever establishes a session for an
invalid/forged bearer, the gate records `status: STOP`, does not grade PASS, and
exits non-zero. Nothing is published; inspect the saved run first.

## Install the fixed versions (throwaway venvs, loopback only)

LiteLLM needs Python ≥ 3.10. Build a venv per fixed version with `python3.11`:

```
mkdir -p ~/st-scratch/litellm-59822 && cd ~/st-scratch/litellm-59822
for v in 1.84.0 1.109.1; do
  python3.11 -m venv venv-$v
  ./venv-$v/bin/pip install -q "litellm[proxy]==$v" "pyjwt[crypto]"
done
```

## Run (per version)

Ports must be 4500–4699 (never 4000/4444/8790); the driver is a Python with
`pyjwt[crypto]` (the fixed venv itself works):

```
cd integration
V=1.84.0   # then 1.109.1
PY=~/st-scratch/litellm-59822/venv-$V/bin/python
LL_BIN=~/st-scratch/litellm-59822/venv-$V/bin/litellm \
LL_PORT=4551 UPSTREAM_PORT=4553 FIXTURE_PORT=4555 \
  $PY -I xid10_litellm_cve59822_gate.py
```

Expected: `[PASS] invalid/forged/absent bearer rejected (no session); valid
bearer accepted; the fail-open fixture was caught by the same check`.

Runs are saved to `integration/runs/` (gitignored); committed fingerprint-only
copies are `integration/sample-runs/litellm-cve59822-1_84_0.json` and
`…-1_109_1.json`, and the "Validation against CVE-2026-59822" section of
`RESULTS.md` is generated from them by `gen_results.py` (regenerate twice —
byte-identical). Full suite: `python -m unittest discover`.

## Teardown

```
rm -rf ~/st-scratch/litellm-59822
```

Confirm nothing is left listening on the 45xx ports and no LiteLLM process
remains.
