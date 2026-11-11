# Static study — methodology and first count

Date: 2026-11-09. Status: first pass, static only. **No leak is confirmed.**

Project names, per-project results and the disclosure shortlist are kept out of
this file on purpose. They live in `study/private/` (gitignored) and are for
private, responsible disclosure only.

## The pattern, precisely

`strangertest survey` flags a **tool handler** that **touches stored or shared
state** and in which **no caller identity is referenced**. The exact rules
(what counts as a handler, as state, and as an identity word) are in the
docstring and constants of `strangertest/source_audit.py`. It parses Python with
`ast`; nothing is imported, executed or connected to.

A flag is a low-confidence triage hit. It says "read this", not "this leaks".

## Corpus

18 public GitHub repositories containing Python MCP servers, shallow-cloned at
their default-branch head on 2026-11-09 (commit SHAs in
`study/private/corpus-manifest.txt`). It is a convenience sample chosen for
servers that hold data (memory, vector, SQL, key/value, document stores) plus
two SDK repositories with example servers. It is not random and not
representative of MCP servers in general. TypeScript servers, the majority of
the ecosystem, are not covered.

Run with Python 3.13 (`python3.13 -I study/run_corpus.py corpus <out.json>`).
Under the system Python 3.9, 48 files using newer syntax failed to parse and
whole servers were silently missed; under 3.13 there were no parse errors.

## Raw detector output

| | count |
|---|---|
| Python files read | 2,604 |
| Tool handlers found | 901 |
| ...that touch stored/shared state | 185 |
| ...and reference no caller identity (flagged) | **127** |
| ...state-touching but cleared by an identity word | 58 |

## Hand verification

All 127 flagged handlers were classified, but at the level of the server they
belong to: for each server I read the transport options, any auth or
middleware, how the store is keyed, and what the README promises. Handlers in
one server share one design, so they were not each read line by line. Treat
the table as a careful first read by one reviewer, not an audit.

| Verdict | handlers | servers |
|---|---|---|
| Not applicable: stdio only, one user, no second identity exists | 70 | 5 |
| Example / tutorial code, not a deployed server | 28 | 2 repos |
| Detector false positive (no shared state actually touched) | 4 | 3 |
| **Candidate: network transport available, one shared store, no per-caller identity in the server** | **25** | **5** |
| Confirmed leak | 0 | 0 |

So 25 of 127 flags (20%) survive a first read as worth a dynamic test.

The 58 cleared handlers were also checked, at the same level:

- 37 were cleared for a real reason: the server resolves a caller identity
  (middleware, a session-bound account, a workspace). Whether that binding is
  *correct* was not assessed.
- 21 were cleared for the wrong reason: the matched word was backend
  configuration (a database username, a tenant setting of the upstream
  client), or unrelated (`token_limit`, a set `member`). 5 of those 21 are in
  network-capable servers and have the same shape as the candidates above,
  adding one more server.

## First candidate count

**6 servers (30 handlers) out of 18 repositories** have the shape "reachable
over a network transport, handlers reach one shared store, no caller identity
in the server": 5 servers / 25 handlers found by the detector, 1 server / 5
handlers found only by hand.

What that number does and does not mean:

- It is a count of servers with the *shape*, not of vulnerabilities. Every one
  of the six is a single-tenant server by design: one database or one
  collection for whoever connects. A cross-identity leak only exists if an
  operator puts more than one user, or an untrusted network, in front of it.
- Default bind addresses were localhost where checked. One of the six states
  in its README that it has no authentication by design and must not be
  exposed; that one is documented behaviour, not a finding.
- One has documentation that could be read as offering tenant separation where
  the code separates tool names only. That is the one worth confirming and, if
  confirmed, raising privately with the maintainers.
- Confidence that these six have the shape: medium-high (read by hand).
  Confidence that any is a real-world leak: low until tested dynamically.

## What the detector is bad at (measured here)

- Precision against "worth a dynamic test": 25/127 = 20%. Most noise is
  single-user stdio servers (55%) and example code (22%).
- It cannot tell a server's own backend credential from a caller's identity:
  36% of clears were for the wrong reason.
- A caller-chosen partition key (`user_id`, `group_id` passed as a tool
  argument with nothing binding it to the caller) clears a handler if the word
  matches, though it is arguably the most interesting shape. Two servers in the
  corpus have it.
- Registration styles it does not follow (dict-based dispatch, tools built in
  another module) are missed; two servers reported far fewer handlers than
  they define. Recall was not measured.
- The detector was adjusted after the first corpus run (function aliases,
  `tool(fn)` call form, `execute_*` methods, more store names), so these
  numbers are from the corpus it was tuned on, not a held-out set.

## Dynamic confirmation so far (2026-11-10)

One of the six was tested, against copies started by us on loopback only (our
own throwaway database, two server processes configured as two tenants on it).
A marker planted through tenant A's tools was read, and then deleted, through
tenant B's tools. That confirms the behaviour the static read predicted: the
option the documentation offers for multi-tenant use separates tool names, not
data.

It does not show that any real deployment is affected: the two tenants shared a
database because the test set them up that way, and an operator who gives each
tenant its own database is isolated by the database. It is a
documentation/expectation issue to raise privately, not a broken control.

The shortlist is **eight**, not the **six** candidates counted above, and both
numbers are intended. The six are the servers whose *code* matched the leak
shape in the static pass. The shortlist adds the servers that warranted a
hands-on look for another reason — a documented multi-tenant claim, or a
service that needs a third party to exercise — so eight were worked through in
total.

All eight shortlisted servers have now been worked through (2026-11-10):

- **a graph-database memory server** — confirmed a documentation/expectation
  gap (namespacing separates tool names, not data). Worth a private note to the
  maintainers.
- **a vector-database server, a graph-database query server, and an
  SQL-database server** — behaviourally confirmed as
  single-tenant-by-design: no per-caller identity exists, so two clients share
  one store. Expected, not a disclosure.
- **a second SQL-database server** — not run; one of its pinned dependencies is
  not available on the public package index and I would not edit the target to
  force it. Same class as the two databases above.
- **a hosted memory service, a temporal knowledge-graph framework, and a
  productivity-suite server** — out of local scope: each needs a
  third-party service (the hosted memory service's API, an LLM/embedder, a
  third-party OAuth provider), which the local-only rule forbids. Static reads
  showed no leak evidence for the last two.

Count: **1 of 8 is a finding (a docs/expectation gap, lab-confirmed); 4 of 8 are
by-design single-tenant (confirmed); 3 of 8 out of local scope; 0 confirmed in
any real deployment.** The per-server detail (names, plant/read pairs, results)
is in study/private/shortlist.md.

## Next: dynamic confirmation

Only against copies we start ourselves on localhost, through the existing
guard. The shortlist with the plant/read tool pair for each case is in
`study/private/shortlist.md`.
