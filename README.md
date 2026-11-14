# Stranger Test

Stranger Test is a free, standard-library-only Python tool and library for
testing **MCP (Model Context Protocol) servers** for cross-identity and
delegated-authority authorization leaks.

An MCP server is a trusted middleman that usually holds many users' credentials
and data. The question Stranger Test asks is simple: can one identity's data,
events, or authority reach another identity through the server? We organise
these failures into a taxonomy of 14 **XID** leak classes, and build detection
ahead of a class becoming common rather than after. Two of the earliest-built
detectors are:

- **XID-13** — cross-identity subscription/notification leak.
- **XID-10** — delegation dropped or forged: the on-behalf-of / token-exchange
  confused-deputy problem.

## Try it

See a leak caught in under a minute, with no third-party dependencies. This
starts the bundled practice MCP subscription server on a loopback port and runs
the XID-13 subscription probe against it — first in `leaky` mode, then in `safe`
mode. From the repository root, with plain system Python:

```
python3 -m strangertest.demo
```

In `leaky` mode, identity B hears identity A's resource update — a leak:

```
Subscription-leak probe (XID-13) against the bundled practice server.
B subscribes to A's resource; A changes it; did B hear about it?

[leaky] LEAK: identity 'B' received update notifications for 'note://alice/secret', a resource owned by identity 'A' — cross-identity subscription/notification leak.
[safe] OK: identity 'B' received no notifications for 'A''s resource 'note://alice/secret'.
```

The `leaky` line is the detection; the `safe` line is the same probe reporting a
correctly-scoped server clean.

### On the command line

The `strangertest` CLI demonstrates a probe against the bundled practice servers
(leaky then safe) with `demo`, and probes a server you are authorized to test
with `scan` (read/marker probe) and `handle` (task-handle probe).

```
python3 -m strangertest demo --probe handle
```

```
[leaky]
LEAK: identity 'B' could use identity 'A''s task handle via tasks/get, tasks/update, tasks/cancel - cross-identity saved-reference (task handle) leak.
[safe]
OK: identity 'B' could not get, update or cancel identity 'A''s task.
```

```
python3 -m strangertest demo --probe cachescope
```

```
[leaky]
labelling: OK - content differs per identity and is labelled private
honouring: LEAK - B received A's private content for the identical request
[safe]
labelling: OK - content differs per identity and is labelled private
honouring: OK - caching observed, and B received B's own content, not A's
```

`demo` exits **0** when the demonstration holds — the leaky server leaks **and**
the safe one does not — and **1** otherwise. So a printed `LEAK` line with exit
`0` is expected: it is the demo working, not a finding against you.

To probe a server you run, point `handle` at it as two identities (non-local
targets require `--authorized`):

```
python3 -m strangertest handle https://your-gateway.example/mcp \
  --token-a "$TOKEN_A" --token-b "$TOKEN_B" \
  --authorized --authorization-note "you@example, staging"
```

Every command shares one exit-code scheme — **0** OK, **1** LEAK or FAIL,
**2** INCONCLUSIVE, **3** usage error or authorization refusal — so any of them
works as a CI gate.

**Not every check is a one-URL scan.** The delegation, scope and issuer checks
need a login server and a recording upstream; the private-cache check needs a
recording upstream. They run from the [integration gates](#integration-gates),
not the command line. `demo --probe cachescope` shows the cache check locally
against a bundled practice upstream.

## How it works

Every probe is an **A/B probe**: act as identity **A**, observe as identity
**B**, and check whether the line between them held.

- **Positive controls.** A probe first proves its observer actually works, so
  that "no leak" cannot be a false negative caused by a broken observer.
- **An explicit `inconclusive` grade.** When the probe cannot observe what it
  needs — an undecodable delegated token, a stream that will not open, a server
  too old to carry the channel — it reports *inconclusive*, which is distinct
  from *no leak*. It never reports a leak it could not actually see, and never
  calls an unobservable server clean.
- **Authorized-first.** Every probe passes the target through an authorization
  guard before any connection is made (see *Scope and safety* below).

The three probes:

1. **Read probe** (`strangertest.probe`) — A plants a uniquely-marked record;
   B tries to read it back. If B sees A's marker, authority crossed identities.
2. **Subscription probe / XID-13** (`strangertest.subscribe`) — B opens a
   subscription stream on a resource owned by A; A then changes it. If B
   receives an update notification for A's resource, one identity's events
   reached another. Detection is exact-URI, exact-method — not a substring
   search — and the stream is opened and acknowledged *before* A acts, because
   the channel does not replay.
3. **Delegation probe / XID-10** (`strangertest.delegate`) — the server acts
   on behalf of a user against an upstream you control. The probe drives it as
   A, then B, then A again (the second A call catches a deputy that cached or
   bled B's token into A's request) and inspects what reached the upstream:
   subject preserved, acting agent present, audience correct, scope narrowed,
   a distinct token per principal, and no cross-identity bleed. Identity is
   `(issuer, subject)`, so two users named the same from different providers
   are not conflated.

**Transports** (`strangertest.transports`), standard library only: **stdio**
(subprocess, newline-delimited JSON-RPC) and **Streamable HTTP** (JSON or SSE),
including the 2026-07-28 "modern" per-request envelope.

## What's new in 0.1.0

- New CLI commands: `handle` (task-handle probe as two identities) and
  `demo --probe {cache,handle,cachescope}` (run a probe against the bundled
  practice servers in leaky then safe mode).
- **Behaviour change — exit codes.** Every command now shares one scheme:
  `0` = OK, `1` = LEAK or FAIL, `2` = INCONCLUSIVE (including transport errors
  where nothing could be observed), `3` = usage error or authorization refusal.
  An **authorization refusal now exits 3, not 2**; a usage error also exits 3.
  Inconclusive and transport errors stay 2.

## Install and run

Requires Python 3.9+. The core library and unit tests use the standard library
only — no third-party dependencies.

Install from PyPI:

```
pip install stranger-test
```

Then run the bundled demo (same as [Try it](#try-it) above):

```
python3 -m strangertest.demo
```

Unit tests, from a clone of the repository root:

```
python3 -m unittest discover
```

(270 tests; the 10 in `tests/test_gen_results.py` and the 11 in `tests/test_cf_provider_api.py` are skipped unless pyjwt[crypto] is installed.)

## Integration gates

The integration "gates" in `integration/` exercise the probes end-to-end
against real servers. They need extra dependencies (`pyjwt[crypto]`, plus the
target server itself), are **not** run by `python3 -m unittest discover`, and
skip cleanly when their dependencies are absent.

- **XID-13 subscription gate** — drives the subscription probe against the
  official MCP SDK subscriptions example server.
- **XID-10 thin-deputy gate** (`integration/xid10_thin_deputy_gate.py`) — runs
  the delegation probe over a real RFC 8693 token exchange against a set of
  deliberately-broken deputy fixtures: `static_credential`, `token_passthrough`,
  `cached_token_reuse`, and a conflated-issuer case. Each is a known leak the
  probe must flag, for the right reason. It also runs the scope-narrowing and
  issuer-binding fixtures. Its ports are **required**: `THIN_PORT_BASE=N` pins
  the local AS on N, the lax AS on N+1, the recording upstream on N+2 and the
  deputy on N+3, all on 127.0.0.1. The gate refuses to start without it, and
  refuses any of those ports if it is 8790 or 4444:

  ```
  THIN_PORT_BASE=4500 <venv>/bin/python integration/xid10_thin_deputy_gate.py
  ```

  (`THIN_NEW_CHECKS_OUT=<file>` also saves the scope and issuer fixture
  results.) Used as a library, e.g. by `integration/gen_results.py`, the
  fixtures take ephemeral ports when `THIN_PORT_BASE` is unset.
- **XID-10 ContextForge gate** (`integration/xid10_contextforge_gate.py`) —
  drives the delegation probe through a real IBM ContextForge gateway doing
  RFC 8693 token exchange. Configured by `XID10_MODE`
  (`delegation` | `impersonation` | `two_issuers`) and `XID10_TRIGGER`
  (`tool` | `resource`).
- **XID-10 agentgateway gate** (`integration/xid10_agentgateway_gate.py`) —
  drives the same delegation probe, same six checks and scenarios, through a
  second, unrelated third-party gateway: **agentgateway v1.7.0** (the official
  release binary, configured by its config file only). A second gateway so the
  probe's behaviour is not tied to any one implementation.

The setup recipes are in
[`integration/CONTEXTFORGE_GATE.md`](integration/CONTEXTFORGE_GATE.md) and
[`integration/AGENTGATEWAY_GATE.md`](integration/AGENTGATEWAY_GATE.md).
Everything in the gates runs on localhost only.

## A sample result

Run against a real **IBM ContextForge 1.1.1** gateway (macOS, Python 3.13); the
same scenarios run against **agentgateway v1.7.0** with the same results:

- **Faithful delegation** grades clean — all checks pass.
- **Impersonation** (no actor token) is flagged, because the exchanged token
  carries no acting-agent `act` claim, so the agent acting for the user is
  invisible.
- **Two issuers** — two users both named `alice` from different providers are
  kept distinct through the exchange (distinct tokens, no cross-identity reuse);
  no conflation.

To be clear about what this does and does not show: **no vulnerability was found
in either gateway.** The probe's ability to *detect* leaks is demonstrated by the
deliberately-broken thin-deputy fixtures above, each of which the probe flags.
A comparison against the older **1.0.6** release (to check a since-fixed
historical behaviour) is noted as **future work** and has not yet been run.

## Scope and safety

Point Stranger Test only at **localhost, servers you run, or targets you are
explicitly authorized to test.** The authorization guard allows local
development hosts (loopback, `.localhost`, `.test`) automatically and refuses
every other target unless you pass explicit authorization recording who
permitted the test. There is deliberately no "scan everything" mode: one target,
one authorization.

Any real finding is for **private, responsible disclosure** to the server's
owner. Do not name-and-shame.

## License

Apache-2.0 (see `LICENSE`).
