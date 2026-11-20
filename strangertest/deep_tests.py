"""Registry of the Tier-2 "deep" cross-user tests, and the glue that lets the CLI
run them and the Tier-1 scanner point at them.

Tier 1 (``strangertest scan``) is a single-identity, read-only risk scan of any
MCP server. Tier 2 (``strangertest confirm``) is the dynamic, two-identity lab
test that *confirms* a cross-user leak (LEAK), clears it (OK), or can't tell
(INCONCLUSIVE) — the thing a static scanner structurally cannot do.

Each registered test exposes:
  - ``demo()``  — stand up the bundled leaky + safe practice servers on loopback
                  and run the probe against each; proves the test catches a real
                  leak and clears a safe server. Needs no target or credentials.
  - ``run_target(url, token_a, token_b, **opts)`` — run against a real server you
                  are authorized to test, with two identities' bearer tokens.
                  ``None`` for the lab-only tests (they need a controlled upstream
                  or a target-specific mutation; use ``demo`` as the reference).

Everything here is loopback-only for demos, fingerprints-only, and starts nothing
on a forbidden port.
"""

from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

PORT_LO, PORT_HI = 4600, 4699
FORBIDDEN_PORTS = {4000, 4444, 8790}

# A leak verdict may be spelled "LEAK" or (confused-deputy) "FAIL".
_LEAK_GRADES = {"LEAK", "FAIL"}


def _free_port() -> int:
    for port in range(PORT_LO, PORT_HI + 1):
        if port in FORBIDDEN_PORTS:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("no free loopback port in 4600-4699")


@contextmanager
def _serve(server):
    """Serve a ThreadingHTTPServer in a background thread; url in, shut down after."""
    addr = server.server_address
    assert PORT_LO <= addr[1] <= PORT_HI and addr[1] not in FORBIDDEN_PORTS, addr
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{addr[1]}/mcp"
    finally:
        server.shutdown()
        server.server_close()


def _grade_of(report: Any) -> str:
    return str(getattr(report, "grade", "INCONCLUSIVE"))


def leaked(report: Any) -> bool:
    return _grade_of(report) in _LEAK_GRADES


# --------------------------------------------------------------------------- #
# Per-test demo + real-target runners (mirror each probe's own test harness).  #
# --------------------------------------------------------------------------- #

def _demo_statehandle() -> Dict[str, Any]:
    from .statehandle import run_statehandle_probe, statehandle_identity, statehandle_canary
    from .practice_statehandle_http import build_server

    def canary_against(leaky_url):
        return lambda: statehandle_canary(
            statehandle_identity(leaky_url, "canary-a", "CA"),
            statehandle_identity(leaky_url, "canary-b", "CB"),
        )

    with _serve(build_server("leaky", port=_free_port())) as leaky_url:
        leaky = run_statehandle_probe(
            leaky_url, statehandle_identity(leaky_url, "alice", "A"),
            statehandle_identity(leaky_url, "bob", "B"), authorized=True)
        with _serve(build_server("safe", port=_free_port())) as safe_url:
            safe = run_statehandle_probe(
                safe_url, statehandle_identity(safe_url, "alice", "A"),
                statehandle_identity(safe_url, "bob", "B"),
                canary=canary_against(leaky_url), authorized=True)
    return {"leaky": leaky, "safe": safe}


def _target_statehandle(url: str, token_a: str, token_b: str, **_) -> Any:
    from .statehandle import run_statehandle_probe, statehandle_identity, statehandle_canary
    from .practice_statehandle_http import build_server
    # A local known-leaky canary so an OK can't be vacuous.
    with _serve(build_server("leaky", port=_free_port())) as leaky_url:
        canary = lambda: statehandle_canary(  # noqa: E731
            statehandle_identity(leaky_url, "canary-a", "CA"),
            statehandle_identity(leaky_url, "canary-b", "CB"))
        return run_statehandle_probe(
            url, statehandle_identity(url, token_a, "A"),
            statehandle_identity(url, token_b, "B"), canary=canary,
            authorized=True, authorization_note="operator-confirmed target")


def _demo_tasks() -> Dict[str, Any]:
    from .tasks_idor import run_tasks_idor_probe, tasks_identity
    from .practice_tasks_http import build_server
    with _serve(build_server("leaky", host="127.0.0.1", port=_free_port())) as leaky_url:
        leaky = run_tasks_idor_probe(
            leaky_url, tasks_identity(leaky_url, "alice", "A"),
            tasks_identity(leaky_url, "bob", "B"), authorized=True)
    with _serve(build_server("safe", host="127.0.0.1", port=_free_port())) as safe_url:
        safe = run_tasks_idor_probe(
            safe_url, tasks_identity(safe_url, "alice", "A"),
            tasks_identity(safe_url, "bob", "B"), authorized=True)
    return {"leaky": leaky, "safe": safe}


def _target_tasks(url: str, token_a: str, token_b: str, **_) -> Any:
    from .tasks_idor import run_tasks_idor_probe, tasks_identity
    return run_tasks_idor_probe(
        url, tasks_identity(url, token_a, "A"), tasks_identity(url, token_b, "B"),
        authorized=True, authorization_note="operator-confirmed target")


def _elicit_identity(url: str, token: str, label: str):
    from .probe import Identity
    from .mcp_client import MCPClient
    from .transports import HTTPTransport
    return Identity(label=label, connect=lambda: MCPClient(
        HTTPTransport(url, headers={"Authorization": f"Bearer {token}"}, modern=True)))


def _demo_elicitation() -> Dict[str, Any]:
    from .elicitation_takeover import run_elicitation_takeover_probe
    from .practice_elicitation_http import build_server, make_test_jwt
    a, b = make_test_jwt("alice"), make_test_jwt("bob")
    with _serve(build_server("leaky", port=_free_port())) as leaky_url:
        leaky = run_elicitation_takeover_probe(
            leaky_url, _elicit_identity(leaky_url, a, "A"),
            _elicit_identity(leaky_url, b, "B"), authorized=True)
    with _serve(build_server("safe", port=_free_port())) as safe_url:
        safe = run_elicitation_takeover_probe(
            safe_url, _elicit_identity(safe_url, a, "A"),
            _elicit_identity(safe_url, b, "B"), authorized=True)
    return {"leaky": leaky, "safe": safe}


def _target_elicitation(url: str, token_a: str, token_b: str, **_) -> Any:
    from .elicitation_takeover import run_elicitation_takeover_probe
    return run_elicitation_takeover_probe(
        url, _elicit_identity(url, token_a, "A"), _elicit_identity(url, token_b, "B"),
        authorized=True, authorization_note="operator-confirmed target")


def _demo_subscriptions() -> Dict[str, Any]:
    from .probe import Identity
    from .mcp_client import MCPClient
    from .transports import HTTPTransport
    from .subscriptions_leak import run_subscriptions_leak_probe
    from .practice_subscriptions_http import build_server
    a_uri, b_uri = "note://alice/private-secret", "note://bob/own-note"

    def ident(url, token, label):
        return Identity(label=label, connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {token}"})))

    def change(uri, value):
        return lambda client: client.call_tool("set_resource", {"uri": uri, "value": value})

    def run(url):
        return run_subscriptions_leak_probe(
            url, ident(url, "alice", "A"), ident(url, "bob", "B"),
            resource_uri=a_uri, change=change(a_uri, "a-value"),
            b_own_uri=b_uri, b_change=change(b_uri, "b-value"),
            idle_timeout=2.0, authorized=True)

    with _serve(build_server("leaky", host="127.0.0.1", port=_free_port())) as leaky_url:
        leaky = run(leaky_url)
    with _serve(build_server("safe", host="127.0.0.1", port=_free_port())) as safe_url:
        safe = run(safe_url)
    return {"leaky": leaky, "safe": safe}


def _demo_confused_deputy() -> Dict[str, Any]:
    from .confused_deputy import run_confused_deputy_probe, CallerSpec, token_fingerprint
    from .probe import Identity
    from .mcp_client import MCPClient
    from .transports import HTTPTransport
    from .practice_confused_deputy_http import (
        HTTPMockUpstream, build_confused_deputy_server, make_caller_token)
    aud = "https://api.myserver.example/mcp"

    def caller(url, subject):
        token = make_caller_token(subject)
        return CallerSpec(
            identity=Identity(label=subject, connect=lambda: MCPClient(
                HTTPTransport(url, headers={"Authorization": f"Bearer {token}"}))),
            subject=subject, inbound_token_fp=token_fingerprint(token))

    def sensitive(client):
        client.call_tool("call_upstream", {})

    def benign(client):
        client.call_tool("benign_upstream", {})

    @contextmanager
    def harness(mode):
        upstream = HTTPMockUpstream(aud, port=_free_port()).start()
        server = build_confused_deputy_server(mode, upstream.url, upstream.expected_audience,
                                              port=_free_port())
        with _serve(server) as url:
            yield url, upstream
        upstream.stop()

    def broken_fixture():
        with harness("leaky") as (burl, bup):
            return run_confused_deputy_probe(
                burl, caller(burl, "alice"), caller(burl, "bob"), upstream=bup,
                sensitive_trigger=sensitive, benign_trigger=benign,
                expected_audience=aud, broken_fixture=None, authorized=True)

    with harness("leaky") as (url, up):
        leaky = run_confused_deputy_probe(
            url, caller(url, "alice"), caller(url, "bob"), upstream=up,
            sensitive_trigger=sensitive, benign_trigger=benign,
            expected_audience=aud, broken_fixture=None, authorized=True)
    with harness("safe") as (url, up):
        safe = run_confused_deputy_probe(
            url, caller(url, "alice"), caller(url, "bob"), upstream=up,
            sensitive_trigger=sensitive, benign_trigger=benign,
            expected_audience=aud, broken_fixture=broken_fixture, authorized=True)
    return {"leaky": leaky, "safe": safe}


# The bundled practice agent's run inputs ({marker} is filled in by the probe).
_PRACTICE_AGENT = {
    "assistant_id": "memory",
    "save_input": {"action": "save", "key": "st-probe", "value": "{marker}"},
    "recall_input": {"action": "recall", "key": "st-probe"},
    "whoami_field": "whoami",
}


def _demo_agent_memory() -> Dict[str, Any]:
    from .agent_memory import run_agent_memory_probe
    from .practice_agent_memory_http import build_server

    out = {}
    for mode in ("leaky", "safe"):
        with _serve(build_server(mode, port=_free_port())) as mcp_url:
            base = mcp_url[: -len("/mcp")]      # this API lives at the server root
            out[mode] = run_agent_memory_probe(
                base, "tok-alice", "tok-bob", namespace_a=["alice", "notes"],
                authorized=True, **_PRACTICE_AGENT)
    # The namespace-boundary shape needs prefix-sibling ids: B is "ali", A is "alice".
    with _serve(build_server("prefixbug", port=_free_port())) as mcp_url:
        out["prefixbug"] = run_agent_memory_probe(
            mcp_url[: -len("/mcp")], "tok-alice", "tok-ali",
            namespace_a=["alice", "notes"], namespace_b=["ali"], authorized=True)
    return out


def _json_opt(value: Any, name: str) -> Any:
    """A CLI option that carries JSON (a run input); None stays None."""
    if value is None or isinstance(value, (dict, list)):
        return value
    import json
    try:
        return json.loads(value)
    except ValueError as exc:
        raise ValueError(f"--{name} is not valid JSON: {exc}")


def _target_agent_memory(url: str, token_a: str, token_b: str, **opts) -> Any:
    from .agent_memory import run_agent_memory_probe
    def split(value):
        return [p for p in value.split(".") if p] if isinstance(value, str) else value
    return run_agent_memory_probe(
        url, token_a, token_b, namespace_a=split(opts.get("namespace_a")),
        namespace_b=split(opts.get("namespace_b")),
        assistant_id=opts.get("assistant_id"),
        save_input=_json_opt(opts.get("save_input"), "save-input"),
        recall_input=_json_opt(opts.get("recall_input"), "recall-input"),
        whoami_field=opts.get("whoami_field"),
        authorized=True, authorization_note="operator-confirmed target")


# --------------------------------------------------------------------------- #
# The registry.                                                               #
# --------------------------------------------------------------------------- #

@dataclass
class DeepTest:
    id: str
    title: str
    summary: str
    tier1_check: Optional[str]            # scanner check_id this confirms (or None)
    demo: Callable[[], Dict[str, Any]]
    run_target: Optional[Callable[..., Any]] = None   # None = lab-only (use demo)
    target_note: str = ""


DEEP_TESTS: Dict[str, DeepTest] = {
    "state-handle": DeepTest(
        "state-handle", "State-handle hijacking",
        "Replay identity A's server-minted state handle as identity B; a server that "
        "treats the handle as authentication lets B reach A's state.",
        tier1_check="session-id-as-bearer", demo=_demo_statehandle,
        run_target=_target_statehandle),
    "confused-deputy": DeepTest(
        "confused-deputy", "Confused deputy / token passthrough",
        "Does the server forward the caller's token to a wrong-audience upstream, or act "
        "with its own authority on an under-scoped request?",
        tier1_check="token-exchange-present", demo=_demo_confused_deputy,
        run_target=None,
        target_note="Lab test: point the deputy's upstream at the bundled recorder "
                    "(run with --demo for the reference run)."),
    "tasks-idor": DeepTest(
        "tasks-idor", "Tasks-extension cross-tenant IDOR",
        "As identity B, read/update/cancel identity A's task by its id, and test whether "
        "task ids are guessable/enumerable.",
        tier1_check=None, demo=_demo_tasks, run_target=_target_tasks),
    "elicitation": DeepTest(
        "elicitation", "Elicitation cross-user binding / account takeover",
        "Identity A starts an elicitation, identity B completes the authorization — does "
        "the grant bind to A? Also flags secrets requested in form mode.",
        tier1_check=None, demo=_demo_elicitation, run_target=_target_elicitation),
    "subscriptions": DeepTest(
        "subscriptions", "Subscriptions/listen notification leakage",
        "Does identity B's listen stream receive notifications scoped to identity A?",
        tier1_check="cachescope-mislabel-signal", demo=_demo_subscriptions,
        run_target=None,
        target_note="Lab/target test needs a resource A can mutate; run with --demo for "
                    "the reference run."),
    "agent-memory": DeepTest(
        "agent-memory", "Agent memory isolation (threads and long-term Store)",
        "Identity A saves a marker in an agent server's memory; can identity B read it "
        "back from A's thread, from the Store, or by asking the agent? Speaks the "
        "LangGraph Server API; give the server's base URL, not an MCP endpoint.",
        tier1_check=None, demo=_demo_agent_memory, run_target=_target_agent_memory),
}

# Scanner Tier-1 check_id -> the Tier-2 test that confirms it.
CONFIRM_FOR_CHECK: Dict[str, str] = {
    t.tier1_check: t.id for t in DEEP_TESTS.values() if t.tier1_check
}


def get(test_id: str) -> Optional[DeepTest]:
    return DEEP_TESTS.get(test_id)


def confirm_hint(check_id: str) -> Optional[str]:
    """For a scanner finding's check_id, the `confirm` command that proves it, if any."""
    tid = CONFIRM_FOR_CHECK.get(check_id)
    return f"stranger-test confirm {tid} <url> --token-a <A> --token-b <B>" if tid else None


__all__ = ["DEEP_TESTS", "DeepTest", "get", "confirm_hint", "CONFIRM_FOR_CHECK", "leaked"]
