# Stranger Test

**The MCP scanner that _confirms_ cross-user auth leaks — not just flags them.**

An MCP (Model Context Protocol) server is a trusted middleman: it holds many
users' credentials, tokens and data behind one endpoint. Stranger Test asks the
one question that matters: **can one user's data, events, or authority reach
another user through the server?** Then — unlike a static scanner — it *proves
the answer* by driving the server as two real identities and watching whether
the line between them held.

```bash
# scan any MCP server you run, in ~30s — no third-party dependencies:
pip install stranger-test
stranger-test scan http://localhost:4600/mcp
# (or, zero-install with pipx: pipx run stranger-test scan http://localhost:4600/mcp)
```

Free, Apache-2.0, standard-library-only Python (3.9+).

---

## Why it's different

Most MCP security tools are **static**: they read config or source and flag
*risk signals*. That's useful — Stranger Test does it too (`scan`) — but a signal
is a thing to look at, not a proven leak. And a single-identity scanner
**structurally cannot** tell you whether identity B can actually reach identity
A's data, because it only ever connects as one identity.

Stranger Test adds the axis nobody else covers: a **dynamic, two-identity
confirmation lab** (`confirm`). It connects as A *and* B, performs the real
protocol dance, and grades the result **LEAK / OK / INCONCLUSIVE** — with a
built-in positive control so "no leak" can never be a silently broken test.

|                         | Static scanners / guardrails | **Stranger Test** |
|-------------------------|:---:|:---:|
| Flags config/source risk signals | ✓ | ✓ (`scan`) |
| Connects as **two** identities    | — | ✓ |
| **Confirms** a cross-user leak dynamically | — | ✓ (`confirm`) |
| Positive control (catches a broken test)   | — | ✓ |
| Explicit `INCONCLUSIVE` (never a false "clean") | — | ✓ |

Guardrails and prompt-firewalls sit in one user's session, so cross-user
authority is a permanent blind spot for them. That blind spot is the whole point
of this tool.

---

## 1. Scan (Tier 1) — one command, read-only

```bash
pipx run stranger-test scan http://localhost:4600/mcp          # or: pip install stranger-test
stranger-test scan http://localhost:4600/mcp --bearer "$TOKEN" # scan as an authenticated caller
stranger-test scan http://localhost:4600/mcp --sarif > out.sarif
```

A single read-only pass. It fingerprints the server — transport, protocol
version, auth posture, session handling, cache scope, advertised delegation —
and flags authorization **risk signals** by severity. Tokens are fingerprinted
(sha256), never printed. It **never writes** to the target.

- `--json` → a `{profile, findings}` document · `--sarif` → SARIF 2.1.0 for CI
  code-scanning.
- **Exit codes drop straight into a CI gate:** `0` no signal · `1` ≥1 signal ·
  `2` unreachable.
- **Safe by default:** refuses any non-loopback target unless you pass
  `--allow-nonloopback` for a server you're authorized to test.

A finding whose class has a confirmer prints the exact `confirm` command to run
next.

## 2. Confirm (Tier 2) — prove it with two identities

`scan` flags a signal; `confirm` **runs a two-identity lab test** that proves it
`LEAK`, clears it `OK`, or returns `INCONCLUSIVE`. Every test ships a bundled
leaky + safe practice server, so `--demo` proves the test works with no target:

```bash
stranger-test confirm --list
stranger-test confirm state-handle --demo          # leaky -> LEAK, safe -> OK
stranger-test confirm state-handle http://127.0.0.1:4600/mcp --token-a <A> --token-b <B>
```

The dynamic cross-user tests (two identities, loopback, fingerprints only):

| Test | What it proves |
|---|---|
| `state-handle`    | B replays A's server-minted state handle and reaches A's state (the 2026-07-28 stateless core: a handle **MUST NOT** be treated as authentication) |
| `confused-deputy` | the server forwards the caller's token to a wrong-audience upstream, or acts with its own authority on an under-scoped request (RFC 8693) |
| `tasks-idor`      | B reads / updates / cancels A's task by id, and whether task ids are enumerable (tasks extension, SEP-2663) |
| `elicitation`     | A starts an elicitation, B completes the authorization — does the grant bind to A? (account takeover); plus secrets requested in form mode |
| `subscriptions`   | B's `subscriptions/listen` stream receives notifications scoped to A |
| `agent-memory`    | B reads what A saved in an agent server's memory — threads, long-term Store, or by asking the agent. Speaks the **LangGraph Server** API; give the server's base URL. With prefix-sibling ids it also catches the store namespace-boundary bugs (CVE-2026-71433 / -115883). |

`agent-memory` needs only a running LangGraph server and two test users' tokens;
nothing about your agent:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a <A> --token-b <B>
```

Guide, with a copy-paste test-user auth snippet: [docs/AGENT-MEMORY.md](docs/AGENT-MEMORY.md).
Background and results on affected and fixed store versions:
[docs/LANGGRAPH-MEMORY-ISOLATION.md](docs/LANGGRAPH-MEMORY-ISOLATION.md).

Every `confirm` grade requires **provably distinct principals** before it will
call anything a LEAK — on a server that collapses both callers to one identity
it reports `OBSERVATION`, not a false positive.

---

## Install

Python 3.9+. Standard library only — **no third-party dependencies.**

```bash
pip install stranger-test             # the CLI + library
pipx run stranger-test scan <url>     # or zero-install, one-off (needs pipx)
```

## Try it (no target needed)

See a leak caught in under a minute. This starts the bundled practice MCP
subscription server on a loopback port and runs the XID-13 subscription probe
against it — first in `leaky` mode, then in `safe` mode:

```
python3 -m strangertest.demo
```

```
Subscription-leak probe (XID-13) against the bundled practice server.
B subscribes to A's resource; A changes it; did B hear about it?

[leaky] LEAK: identity 'B' received update notifications for 'note://alice/secret', a resource owned by identity 'A' — cross-identity subscription/notification leak.
[safe] OK: identity 'B' received no notifications for 'A''s resource 'note://alice/secret'.
```

The `leaky` line is the detection; the `safe` line is the same probe reporting a
correctly-scoped server clean. `demo` exits **0** when the contrast holds (leaky
leaks **and** safe does not) — so a printed `LEAK` with exit `0` is the demo
working, not a finding against you. Other probes: `python3 -m strangertest demo
--probe {cache,handle,cachescope}`.

## How it works

Every probe is an **A/B probe**: act as identity **A**, observe as identity
**B**, and check whether the line between them held.

- **Positive controls.** A probe first proves its observer actually works, so
  that "no leak" cannot be a false negative caused by a broken observer.
- **An explicit `inconclusive` grade.** When the probe cannot observe what it
  needs — an undecodable delegated token, a stream that will not open, a server
  too old to carry the channel — it reports *inconclusive*, distinct from *no
  leak*. It never reports a leak it could not actually see, and never calls an
  unobservable server clean.
- **Authorized-first.** Every probe passes the target through an authorization
  guard before any connection is made (see *Scope and safety*).
- **Fingerprints only.** Tokens and session ids are recorded as sha256
  fingerprints, never in the clear.

**Transports** (`strangertest.transports`), standard library only: **stdio**
(subprocess, newline-delimited JSON-RPC) and **Streamable HTTP** (JSON or SSE),
including the 2026-07-28 "modern" per-request envelope.

Identity is `(issuer, subject)`, so two users named the same from different
providers are never conflated.

## Integration gates

The gates in `integration/` exercise the probes end-to-end against real servers.
They need extra dependencies (`pyjwt[crypto]`, plus the target server itself),
are **not** run by `python3 -m unittest discover`, and skip cleanly when their
dependencies are absent. Everything in the gates runs on localhost only.

- **XID-13 subscription gate** — drives the subscription probe against the
  official MCP SDK subscriptions example server.
- **XID-10 thin-deputy gate** (`integration/xid10_thin_deputy_gate.py`) — runs
  the delegation probe over a real RFC 8693 token exchange against
  deliberately-broken deputy fixtures (`static_credential`, `token_passthrough`,
  `cached_token_reuse`, a conflated-issuer case), plus the scope-narrowing and
  issuer-binding fixtures. Each is a known leak the probe must flag, for the
  right reason. Ports via `THIN_PORT_BASE=N` (local AS on N, lax AS N+1,
  recording upstream N+2, deputy N+3, all 127.0.0.1); it refuses 8790 and 4444.
- **XID-10 ContextForge gate** (`integration/xid10_contextforge_gate.py`) —
  drives the delegation probe through a real IBM ContextForge gateway doing
  RFC 8693 token exchange.
- **XID-10 agentgateway gate** — the same probe/checks through a second,
  unrelated gateway: **agentgateway v1.7.0** (official release binary).
- **XID-10 LiteLLM gate** — the same probe/checks through **LiteLLM 1.109.1**,
  plus exchange-failure and cache checks.

Setup recipes: [`integration/CONTEXTFORGE_GATE.md`](integration/CONTEXTFORGE_GATE.md),
[`integration/AGENTGATEWAY_GATE.md`](integration/AGENTGATEWAY_GATE.md),
[`integration/LITELLM_GATE.md`](integration/LITELLM_GATE.md).

## Findings

Stranger Test is built to find real cross-user leaks and disclose them
responsibly. Confirmed advisories are listed here as they are published.

The detection engine is validated end-to-end against real third-party gateways
on loopback — **agentgateway v1.7.0, LiteLLM 1.109.1, IBM ContextForge** — plus
the deliberately-broken fixtures above, each of which the probe flags for the
right reason. In the delegation scenarios run so far, the checks passed on those
versions: faithful delegation grades clean, impersonation (no `act` claim) is
flagged, and two users named `alice` from different providers are kept distinct.
A passing check covers only that check on that version; it is not a verdict on
the product. The probe's ability to *detect* is demonstrated by the broken
fixtures. See the [results at a glance](docs/RESULTS-SUMMARY.md) and the full
[`integration/RESULTS.md`](integration/RESULTS.md). To run it in your own CI,
see [`docs/CI.md`](docs/CI.md).

## Scope and safety

Point Stranger Test only at **localhost, servers you run, or targets you are
explicitly authorized to test.** The authorization guard allows local
development hosts (loopback, `.localhost`, `.test`) automatically and refuses
every other target unless you pass explicit authorization recording who
permitted the test. There is deliberately no "scan everything" mode: one target,
one authorization. Any real finding is for **private, responsible disclosure**
to the server's owner. Do not name-and-shame.

## What's new in 0.3.0

- **`confirm agent-memory`** — a sixth deep test, for **agent servers** rather
  than MCP servers: can identity B read what A saved in the agent's memory
  (LangGraph threads, long-term Store, or via the agent)? Bundled `--demo`, and
  a real-LangGraph gate in `integration/langgraph/`. Two tokens are enough to
  run it on your own app: see [docs/AGENT-MEMORY.md](docs/AGENT-MEMORY.md).
- **Store namespace-boundary catch.** With two prefix-sibling identities
  (`--namespace-b`), `agent-memory` catches the LangGraph store bugs fixed in
  2026 (CVE-2026-71433, CVE-2026-115883): it grades `LEAK` against the real
  `langgraph-checkpoint-sqlite` 3.1.0 and `OK` against 3.1.1.

### 0.2.0

- **`scan`** (Tier 1) one-command read-only scanner, SARIF/JSON, CI exit codes.
- **`confirm`** (Tier 2) five dynamic cross-user tests, each with a `--demo`.
- **Precision:** a `LEAK` needs provably distinct principals, else `OBSERVATION`.
- **One exit-code scheme:** `0` OK, `1` LEAK/FAIL, `2` INCONCLUSIVE, `3` usage.

Unit tests, from a clone of the repository root:

```
python3 -m unittest discover
```

(The tests in `tests/test_gen_results.py`, `tests/test_cf_provider_api.py` and
most of `tests/test_local_as_client_auth.py` are skipped unless `pyjwt[crypto]`
is installed.)

## License

Apache-2.0 (see [`LICENSE`](LICENSE)).
