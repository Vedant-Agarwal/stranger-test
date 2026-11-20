# Run Stranger Test in CI

Two ways to gate a build on it. Both test a server that your own CI job starts,
on the runner's loopback, with test accounts. Nothing leaves the runner.

## 1. Scan (one identity, read-only)

Start your MCP server in the job, then:

```yaml
- uses: strangertest-labs/stranger-test@v0.3
  with:
    url: http://127.0.0.1:8080/mcp
```

The step fails when the scan finds a risk signal, and also when the server
cannot be reached (nothing was scanned, so it is not a pass).

To see the signals in the repository's code-scanning tab:

```yaml
- uses: strangertest-labs/stranger-test@v0.3
  with:
    url: http://127.0.0.1:8080/mcp
    sarif-file: stranger-test.sarif
    fail-on: never            # report only; let code scanning show it
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: stranger-test.sarif
```

## 2. Confirm (two identities)

This is the cross-user check. It needs two test accounts on the server under
test, each with its own bearer token:

```yaml
- uses: strangertest-labs/stranger-test@v0.3
  with:
    mode: confirm
    test: state-handle        # or tasks-idor, elicitation
    url: http://127.0.0.1:8080/mcp
    token-a: ${{ secrets.MCP_TEST_TOKEN_A }}
    token-b: ${{ secrets.MCP_TEST_TOKEN_B }}
```

Run one step per test. The two tokens must belong to two different users. If
the server maps both to the same user, the test reports `OBSERVATION` instead of
a leak, because reaching your own data is not a cross-user leak.

## 3. Agent memory (LangGraph servers)

`agent-memory` checks an agent server instead of an MCP server: can one user
read memory stored for another (an agent memory spill)? Give the server's base
URL, not an MCP path. Two tokens are enough to test the thread and Store paths:

```yaml
- uses: strangertest-labs/stranger-test@v0.3
  with:
    mode: confirm
    test: agent-memory
    url: http://127.0.0.1:2024
    token-a: ${{ secrets.AGENT_TEST_TOKEN_A }}
    token-b: ${{ secrets.AGENT_TEST_TOKEN_B }}
    namespace-a: alice.notes      # a Store namespace user A may write to
```

To also test through the agent, add your graph's id and inputs:

```yaml
    assistant: my_graph
    save-input: '{"messages": [{"role": "user", "content": "remember {marker}"}]}'
    recall-input: '{"messages": [{"role": "user", "content": "what did I ask you to remember?"}]}'
```

`{marker}` is replaced by the test's own marker. See
[AGENT-MEMORY.md](AGENT-MEMORY.md) for every option and how to read the result.

## What fails the step

| Result | `fail-on: leak` (default) | `fail-on: inconclusive` | `fail-on: never` |
|---|---|---|---|
| scan: no signal / confirm: `OK` | pass | pass | pass |
| scan: risk signal / confirm: `LEAK` | **fail** | **fail** | pass |
| confirm: `INCONCLUSIVE` or `OBSERVATION` | pass, with a warning | **fail** | pass |
| scan: target unreachable | **fail** | **fail** | pass |
| bad input, or a non-loopback target without `allow-nonloopback` | **fail** | **fail** | **fail** |

Use `fail-on: inconclusive` once the test runs cleanly against your server, so
that a later change which stops the test from observing anything also fails the
build.

The tool's own exit code is available as the step output `exit-code`.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `url` | (required) | The MCP endpoint to test. For `agent-memory`, the agent server's base URL. |
| `mode` | `scan` | `scan` or `confirm`. |
| `test` | | `confirm` only: `state-handle`, `tasks-idor`, `elicitation` or `agent-memory`. |
| `token-a`, `token-b` | | `confirm` only: the two users' bearer tokens. |
| `namespace-a`, `namespace-b` | | `agent-memory` only: Store namespaces, dotted. `namespace-b` with prefix-sibling ids also checks the namespace boundary. |
| `assistant`, `save-input`, `recall-input` | | `agent-memory` only: graph id and JSON run inputs for the through-the-agent paths. |
| `whoami-field` | | `agent-memory` only: run-output field that carries the caller's identity. |
| `bearer` | | `scan` only: scan as an authenticated caller. |
| `sarif-file` | | `scan` only: also write SARIF 2.1.0 here. |
| `allow-nonloopback` | `false` | Permit a target that is not on loopback. Only for a server you are authorized to test. |
| `fail-on` | `leak` | `leak`, `inconclusive` or `never`. |
| `python-version` | `3.12` | Python used to run the tool. |

Tokens are passed to the tool through environment variables and appear in
reports only as `sha256:` fingerprints.

## Without the action

Any CI system can run the same thing directly:

```bash
pip install stranger-test
stranger-test scan http://127.0.0.1:8080/mcp
stranger-test confirm state-handle http://127.0.0.1:8080/mcp --token-a "$A" --token-b "$B"
```

Exit codes: `0` OK, `1` leak or risk signal, `2` inconclusive or unreachable,
`3` usage error or refused target.

## Not available as a one-step test

`confused-deputy` and `subscriptions` need a recording upstream or a login
server that the test controls, so they run as `--demo` and from the
[integration gates](../integration/RESULTS.md), not against a bare URL.
