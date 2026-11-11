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

## Install and run

Requires Python 3.9+. The core library and unit tests use the standard library
only — no third-party dependencies.

Unit tests, from the repository root:

```
python3 -m unittest discover
```

(106 tests.)

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
  probe must flag, for the right reason.
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
