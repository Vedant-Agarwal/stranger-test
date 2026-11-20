# Test your own LangGraph app for cross-user memory leaks

## What the test checks

An agent server that serves many users keeps memory for them: saved
conversations (threads) and long-term memory (the Store). `confirm agent-memory`
signs in as two users, has user A save a unique marker, and then checks whether
user B can read it back. In LangGraph, threads and Store items are only
protected per user if the app adds its own authorization handlers, so a `LEAK`
here normally means the app is missing them, not that the framework is broken.

## 1. Try the demo (no setup)

```bash
pip install stranger-test
stranger-test confirm agent-memory --demo
```

This starts two small practice servers on your own machine, one leaky and one
safe, and runs the test against both. You should see `LEAK` for the first, `OK`
for the second, and `VERDICT: the test WORKS`.

## 2. Run it against your own app with two tokens

You need:

- a running LangGraph server that you own, on localhost (for example
  `langgraph dev`, which listens on `http://127.0.0.1:2024` by default);
- bearer tokens for two different test users.

That is all. You do not have to tell the test anything about your agent:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a <A's token> --token-b <B's token>
```

Give the server's base URL, not a path under it.

In this mode the test runs the paths it can drive through the server's HTTP API
alone:

| Path | What B tries |
|---|---|
| `thread_get` | read A's thread by its id |
| `thread_search` | list threads and find A's |
| `store_get` | read A's Store item by namespace and key |
| `store_search_namespace` | search A's Store namespace |
| `store_search_all` | search the whole Store with no namespace |

These are reported `NOT_RUN`, because they need more input from you (section 4):
`thread_state`, `thread_history`, `agent_recall` and `store_search_own_prefix`.
The last line of the output names the flags that would turn them on.

If your app limits each user to their own part of the Store, also pass a
namespace user A is allowed to write to, with dots between the parts:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a <A's token> --token-b <B's token> \
  --namespace-a alice.notes
```

Without it the test writes to a throwaway namespace. A well-scoped app refuses
that, and the Store paths then show `NOT_EXERCISED` instead of `OK`.

## 3. No auth in your dev app yet? Add two test users

**This snippet is for local testing only.** The tokens are fixed strings in the
source. Never deploy it.

Save this as `auth.py` next to your graph:

```python
"""Test-user auth for LOCAL TESTING ONLY: two fixed tokens, two users."""
from langgraph_sdk import Auth

TOKENS = {"tok-alice": "alice", "tok-bob": "bob"}

auth = Auth()


@auth.authenticate
async def authenticate(authorization: str | None) -> Auth.types.MinimalUserDict:
    """Who is calling? Unknown or missing tokens are refused."""
    token = (authorization or "").removeprefix("Bearer ").strip()
    user = TOKENS.get(token)
    if user is None:
        raise Auth.exceptions.HTTPException(status_code=401, detail="unknown token")
    return {"identity": user}


@auth.on
async def owner_only(ctx: Auth.types.AuthContext, value: dict):
    """Threads and runs: stamp the owner on create, filter by owner on read."""
    owner = {"owner": ctx.user.identity}
    value.setdefault("metadata", {}).update(owner)
    return owner


@auth.on.store()
async def own_namespace_only(ctx: Auth.types.AuthContext, value: dict):
    """Store: a caller may only touch namespaces that start with their own id."""
    namespace = tuple(value.get("namespace") or ())
    if not namespace or namespace[0] != ctx.user.identity:
        raise Auth.exceptions.HTTPException(status_code=403, detail="not your namespace")
```

Then point `langgraph.json` at it by adding this line:

```json
"auth": {"path": "./auth.py:auth"}
```

Restart the server and run:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a tok-alice --token-b tok-bob \
  --namespace-a alice.notes
```

The snippet has two parts, and they do different jobs. `authenticate` only
decides who the caller is. The `@auth.on` and `@auth.on.store()` handlers are
what keep one user out of another user's data. To see the difference, delete
those two handlers and run the test again: the grade changes from `OK` to
`LEAK`. An app that authenticates callers but has no such handlers is the most
common way to get a `LEAK`.

Note that the Store handler only checks the HTTP API. Inside your graph, your
own code chooses the namespace, so make sure it includes the user there too.

## 4. Optional: deeper paths

- `--namespace-a alice.notes` is a Store namespace A may write to (see
  section 2).
- `--assistant`, `--save-input` and `--recall-input` together test through the
  agent itself. `--assistant` is the graph id from your `langgraph.json`.
  `--save-input` is a JSON run input that makes your agent save something; the
  test replaces `{marker}` in it with its own unique marker. `--recall-input` is
  a JSON run input that makes your agent recall it, and must not contain
  `{marker}`. This turns on `thread_state`, `thread_history` and `agent_recall`.
- `--whoami-field` names a field in your agent's run output that carries the
  caller's identity, if your app has one. The test uses it to make sure the two
  tokens really are two different users.

For the sample app in `integration/langgraph/app/` the full command is:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a tok-alice --token-b tok-bob \
  --namespace-a alice.notes \
  --assistant memory \
  --save-input '{"action": "save", "key": "st-probe", "value": "{marker}"}' \
  --recall-input '{"action": "recall", "key": "st-probe"}' \
  --whoami-field whoami
```

- `--namespace-b` is B's own Store namespace, and it only does something when
  the two users' ids are *prefix siblings*: B's id is the beginning of A's id,
  such as `ali` and `alice` (`--namespace-a alice.notes --namespace-b ali`).

That last path, `store_search_own_prefix`, catches a store that compares
namespaces as plain text rather than part by part, so that B's search of `ali`
also returns items under `alice`. This is the shape of the store
namespace-boundary bugs that were fixed in `langgraph-checkpoint-sqlite` and
`langgraph-checkpoint-postgres` 3.1.1 to 3.1.3 (CVE-2026-71433 and
CVE-2026-115883); they were found by other researchers and are fixed and
public.

## 5. Reading the result

The first line is the overall grade:

| Grade | Meaning | Exit code |
|---|---|---|
| `OK` | B could not read A's memory on any path that was exercised. | 0 |
| `LEAK` | B read A's marker on at least one path. | 1 |
| `INCONCLUSIVE` | Nothing could be tested: the server was unreachable, A could not create a thread, or A could not read her own marker anywhere. | 2 |
| `OBSERVATION` | Worth knowing, but not a cross-user leak: the server accepts callers with no token or a made-up token, both tokens are the same user, or B can see that A's namespace exists but not what is in it. | 2 |

Exit code 3 means a usage error or a refused target; no test was run.

Then one line per path:

| Outcome | Meaning |
|---|---|
| `LEAK` | B got A's marker this way. |
| `OK` | A could read her own marker this way and B could not. |
| `NOT_EXERCISED` | A could not read her own marker this way, so the path proves nothing. It never counts as `OK`. |
| `NOT_RUN` | The path was skipped because it needs an option you did not give. |

An `OK` grade only covers the paths marked `OK`. Check how many there were.

Add `--json` for the full report. Tokens and markers appear only as short
`sha256:` fingerprints, never in clear.

## 6. Limits

- The test covers only what it can drive over the server's HTTP API. It does
  not read your code, and it cannot see data paths that never go through that
  API.
- There is no semantic-search leak test yet.
- Only test servers you run or are authorized to test. Anything that is not on
  localhost is refused unless you pass `--allow-nonloopback`.
- The test creates a few threads and Store items tagged `st-probe-...` and does
  not delete them. Use a development server.
