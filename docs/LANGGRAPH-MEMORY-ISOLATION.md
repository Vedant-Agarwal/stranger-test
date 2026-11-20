# Does your LangGraph app keep users' memory apart? A check you can run

An agent app that serves many users keeps memory for each of them: saved
conversations (threads) and long-term memory (the Store). This page describes a
free check that acts as two users against a LangGraph server you run and reports
whether one can read the other's memory. To run it, see
[AGENT-MEMORY.md](AGENT-MEMORY.md).

This page uses the term **agent memory spill** for that failure: one user of an
agent app can read memory the app stored for another user, through the server's
ordinary read paths, because a per-user access check is missing or wrong. It is
a different problem from leaks through similarity search, where no access check
fails and another user's memory is retrieved because it is semantically close.

## Why check at all

In LangGraph, the server authenticates callers with the auth handler your app
provides, and it limits access to threads and Store items through the
`@auth.on` handlers your app adds. The official guides show the pattern
([resource authorization](https://docs.langchain.com/langsmith/resource-auth),
[Store authorization](https://docs.langchain.com/langsmith/store-auth)). That is
a reasonable design, and it means isolation depends on handlers each team
writes. The store layer underneath has also had namespace-matching bugs, all
fixed, including:

- [CVE-2026-71433](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-47pj-3jcm-6whg):
  namespace prefix matching crossed segment boundaries in the Postgres and
  SQLite stores. Fixed in `langgraph-checkpoint-postgres` and
  `langgraph-checkpoint-sqlite` 3.1.1.
- [CVE-2026-115883](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-6hmw-9432-67qq):
  namespace labels containing `.` reached other namespaces. Fixed in
  `langgraph-checkpoint-sqlite` 3.1.2 and `langgraph-checkpoint-postgres` 3.1.3.

Both were reported by other researchers and are public. They are listed here
because they show what to test for, and so that you can confirm you are on a
fixed version.

## What the check does

`stranger-test confirm agent-memory` needs two test users' tokens:

1. User A saves a unique marker in a thread and in the Store.
2. User A reads it back on every path. A path A cannot read herself is reported
   as not exercised and can never count as a pass.
3. User B tries each path: A's thread by id, thread search, the Store item by
   namespace and key, Store search, and (if you supply your agent's inputs)
   asking the agent.

It grades `LEAK`, `OK` or `INCONCLUSIVE`. A server with no authentication is
reported as an `OBSERVATION`, because the two callers are then the same user.

## What it found on a sample app

A small sample app with no model (`integration/langgraph/app/`), on a local
LangGraph dev server (LangGraph 1.2.23), with two fixed test users:

| Sample app | Result |
|---|---|
| Authenticates users, adds no `@auth.on` handlers | `LEAK` on 8 of 8 paths |
| Adds an owner filter for threads and an own-namespace check for the Store | `OK` |

## What it found on the affected and fixed store

The same check, through a real LangGraph dev server (LangGraph 1.2.24,
langgraph-api 0.18.3) running the sample app with its handlers on, and with the
server's Store set to LangGraph's own SQLite store, and then to its Postgres
store (PostgreSQL 16, local). Only the store and its version change. The two
test users' ids are string-prefix siblings, `ali` and `alice`; `alice` saves an
item, and `ali` searches his own namespace.

| Store package | 3.1.0 (affected by CVE-2026-71433) | 3.1.1 (fixed) |
|---|---|---|
| `langgraph-checkpoint-sqlite` | `LEAK`: `ali`'s own-namespace search returned `alice`'s item | `OK` |
| `langgraph-checkpoint-postgres` | `LEAK`: same | `OK` |

Every other exercised path was `OK` on every run, because the app's own
checks blocked them. Reproduce with
`integration/langgraph/real_server_store_gate.py` (through the server),
`integration/langgraph/real_store_gate.py` (the store behind a minimal app), and
`integration/langgraph/cve_2026_71433_store.py` (the library alone).

## If you run LangGraph for more than one user

- Upgrade the store packages to the fixed versions above.
- Add `@auth.on` handlers for threads and the Store, then check that they hold.
- Do not treat a thread id or a namespace as proof of who is asking.

## Limits

- The check covers what it can reach over the server's HTTP API. A clean result
  is not a proof of isolation.
- The store-boundary path needs two test accounts whose ids are prefix siblings.
- It does not test leaks through semantic (similarity) search.
- It was run against LangGraph's local dev server with the SQLite and Postgres
  stores, not against LangGraph's hosted or self-hosted platform.
- Run it only against servers you run or are authorized to test.
