# Results at a glance

A short view of what has been run against real gateways. The full record, with
a saved run behind every cell, is [`integration/RESULTS.md`](../integration/RESULTS.md);
that file is generated from the runs and is the source of truth. If the two
disagree, this page is the one that is out of date.

Each cell is the result of one named check on one version. It is not a verdict
on the product: checks that were not run say nothing, and a later version may
behave differently.

## Delegation and isolation checks

| Check | ContextForge 1.1.1 | agentgateway 1.7.0 | LiteLLM 1.109.1 | ToolHive 0.65.0 (standalone) | Kuadrant 1.6.0 |
|---|---|---|---|---|---|
| Distinct actor and subject through token exchange | OK | OK (actor is caller-supplied) | NOT SUPPORTED | NOT SUPPORTED | NOT SUPPORTED |
| Scope narrows on delegation | OK | OK | OK | OK | not run |
| Unregistered issuer refused | OK | OK | left to the login server | OK | not run |
| No token passthrough | OK | OK | OK | OK | not run |
| Upstream token is audience-restricted | OK | OK | OK | OK | OK |
| Own token per user, no cross-user reuse | OK | OK | OK | OK | OK |
| Task handles scoped to the caller | NOT SUPPORTED | OK with token exchange | NOT SUPPORTED | not run | not run |
| Private results not cached across users | does not cache | does not cache | does not cache | does not cache | not run |
| No identity crossing under 50 concurrent sessions | OK | OK | OK | not run | not run |
| Fails closed when the token exchange fails | OK | OK | OK (one observation, slow login server) | OK | OK |

Notes that change how a cell should be read:

- **NOT SUPPORTED** means the gateway does not offer the feature the check
  needs (no actor token on the exchange; the tasks extension is not forwarded).
  It is neither a pass nor a leak.
- **agentgateway, task handles.** With a shared upstream credential
  (`backendAuth.key`, a documented option) the same check grades LEAK. That is a
  configuration risk, not a gateway defect.
- **LiteLLM, unregistered issuer.** The open-source build does not inspect the
  user's token, so issuer binding is whatever the login server enforces.

## Two-identity `confirm` tests

| Test | Recorded runs against a real gateway |
|---|---|
| `state-handle` | none recorded here yet |
| `tasks-idor` | none recorded here yet |
| `elicitation` | none recorded here yet |
| `confused-deputy` | lab test; see the thin-deputy fixtures in the full results |
| `subscriptions` | lab test; see the XID-13 gate in the full results |
| `agent-memory` | **LangGraph dev server (1.2.24) on its SQLite store, sample app with handlers on: `LEAK` on `langgraph-checkpoint-sqlite` 3.1.0, `OK` on 3.1.1**, with prefix-sibling users (`integration/langgraph/real_server_store_gate.py`). Reproduces the fixed, public CVE-2026-71433. |

Each catches its bundled leaky server and clears its safe one
(`stranger-test confirm <test> --demo`).

## Detection proof

A clean cell only means something if the check can fail. Every check above is
also run against a deliberately broken fixture in the same harness, and each
fixture is flagged for the right reason. See "Detection proof" in the full
results.

## Add your gateway

Run the checks in your own CI ([`docs/CI.md`](CI.md)) and open a pull request
adding a row or a column, with the version and the saved run.
