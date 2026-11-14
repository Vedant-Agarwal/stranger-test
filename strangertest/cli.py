"""Command-line interface for Stranger Test.

For now the CLI runs the bundled local practice server end-to-end:

    python3 -m strangertest practice          # the leaky server: should find a leak
    python3 -m strangertest practice --safe    # the isolated server: should be clean
    python3 -m strangertest practice --json     # full JSON report

``scan`` runs the same probe against an authorized HTTP server.

Every command shares one exit-code scheme, so any of them works as a CI check:
0 = OK, 1 = LEAK or FAIL, 2 = INCONCLUSIVE (including transport errors where
nothing could be observed), 3 = usage error or authorization refusal.

``survey <path>`` is the static side: it reads MCP server source code and lists
low-confidence candidates. It exits 0 even with candidates (they are not
confirmed leaks); a missing path is a usage error (3).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import List, Optional

from . import __version__
from .guard import AuthorizationError
from .handle import (
    CLIENT_CAPABILITIES_WITH_TASKS,
    TasksHTTPTransport,
    run_handle_probe,
)
from .mcp_client import MCPClient
from .probe import Identity, ProbeError, ProbePlan, run_probe
from .source_audit import survey
from .transports import HTTPTransport, HTTPTransportError, StdioTransport

# One exit-code scheme for every command:
#   0 OK, 1 LEAK or FAIL, 2 INCONCLUSIVE (including transport errors where
#   nothing could be observed), 3 usage error or authorization refusal.
EXIT_OK = 0
EXIT_FINDING = 1
EXIT_INCONCLUSIVE = 2
EXIT_USAGE = 3


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors exit 3, not argparse's default 2."""

    def error(self, message: str):  # noqa: D401
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _grade_exit(grade: str) -> int:
    """Map a probe grade to the shared exit-code scheme."""
    if grade in ("LEAK", "FAIL"):
        return EXIT_FINDING
    if grade == "OK":
        return EXIT_OK
    return EXIT_INCONCLUSIVE  # INCONCLUSIVE or anything not observed


def _refuse(exc: "AuthorizationError") -> int:
    """Print an authorization refusal and return the usage exit code.

    ``exc`` carries the library wording (which names the Python ``authorized=True``
    argument); the command line adds how to do the same from the shell.
    """
    print(f"refused: {exc}", file=sys.stderr)
    print("re-run with --authorized if you are permitted to test this target "
          "(and --authorization-note to record who authorized it).",
          file=sys.stderr)
    return EXIT_USAGE


def _practice_identity(label: str, identity_id: str, mode: str, store_path: str) -> Identity:
    command = [sys.executable, "-m", "strangertest.practice_server"]
    env = {
        "STRANGERTEST_MODE": mode,
        "STRANGERTEST_IDENTITY": identity_id,
        "STRANGERTEST_STORE": store_path,
    }
    return Identity(label=label, connect=lambda: MCPClient(StdioTransport(command, env=env)))


def cmd_practice(args: argparse.Namespace) -> int:
    mode = "safe" if args.safe else "leaky"
    plan = ProbePlan.key_value("kv_set", "kv_get", "secret")
    with tempfile.TemporaryDirectory() as tmp:
        store = os.path.join(tmp, "store.json")
        report = run_probe(
            "http://localhost/practice",
            _practice_identity("A", "alice", mode, store),
            _practice_identity("B", "bob", mode, store),
            plan,
        )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return 1 if report.leaked else 0


def cmd_scan(args: argparse.Namespace) -> int:
    def http_identity(label: str, token) -> Identity:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return Identity(
            label=label,
            connect=lambda: MCPClient(HTTPTransport(args.url, headers=headers)),
        )

    plan = ProbePlan.key_value(args.plant_tool, args.read_tool, args.key)
    try:
        report = run_probe(
            args.url,
            http_identity("A", args.token_a),
            http_identity("B", args.token_b),
            plan,
            authorized=args.authorized,
            authorization_note=args.authorization_note,
        )
    except AuthorizationError as exc:
        return _refuse(exc)
    except ProbeError as exc:
        print(f"inconclusive: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    except HTTPTransportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return EXIT_FINDING if report.leaked else EXIT_OK


def _tasks_identity(url: str, token, label: str) -> Identity:
    """A task-capable (modern, tasks extension) identity, like scan's but for
    the task-handle probe. ``token`` None means an anonymous caller."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            TasksHTTPTransport(
                url,
                headers=headers,
                modern=True,
                client_capabilities=CLIENT_CAPABILITIES_WITH_TASKS,
            )
        ),
    )


def cmd_handle(args: argparse.Namespace) -> int:
    try:
        report = run_handle_probe(
            args.url,
            _tasks_identity(args.url, args.token_a, "A"),
            _tasks_identity(args.url, args.token_b, "B"),
            authorized=args.authorized,
            authorization_note=args.authorization_note,
        )
    except AuthorizationError as exc:
        return _refuse(exc)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return _grade_exit(report.grade)


def cmd_survey(args: argparse.Namespace) -> int:
    # Static only: reads source files, never connects to anything, so there is
    # no target to authorize. Exit code is 0 even with candidates, because a
    # candidate is a low-confidence hit to read by hand, not a confirmed leak.
    try:
        report = survey(args.path, include_tests=args.include_tests)
    except FileNotFoundError:
        print(f"error: no such path: {args.path}", file=sys.stderr)
        return EXIT_USAGE
    if args.json:
        print(json.dumps(report.to_dict(include_all=args.all), indent=2))
    else:
        print(report.summary())
    return 0


def _http_identity(url: str, token, label: str) -> Identity:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return Identity(
        label=label,
        connect=lambda: MCPClient(HTTPTransport(url, headers=headers, modern=True)),
    )


def _demo_exit(reports) -> int:
    # The demo is a self-check: the leaky server must leak and the safe one
    # must not. 0 when that contrast holds, 1 (FAIL) when it does not.
    return EXIT_OK if (reports["leaky"].leaked and not reports["safe"].leaked) else EXIT_FINDING


def _print_demo(probe: str, reports, as_json: bool) -> None:
    if as_json:
        payload = {"demo": probe}
        payload.update({mode: reports[mode].to_dict() for mode in ("leaky", "safe")})
        print(json.dumps(payload, indent=2))
    else:
        for mode in ("leaky", "safe"):
            print(f"[{mode}]")
            print(reports[mode].summary())


def _demo_cache(as_json: bool) -> int:
    plan = ProbePlan.key_value("kv_set", "kv_get", "secret")
    reports = {}
    for mode in ("leaky", "safe"):
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "store.json")
            reports[mode] = run_probe(
                "http://localhost/practice",
                _practice_identity("A", "alice", mode, store),
                _practice_identity("B", "bob", mode, store),
                plan,
            )
    _print_demo("cache", reports, as_json)
    return _demo_exit(reports)


def _demo_handle(as_json: bool) -> int:
    import threading

    from .practice_handle_http import build_server

    reports = {}
    for mode in ("leaky", "safe"):
        server = build_server(mode)
        thread = threading.Thread(
            target=lambda s=server: s.serve_forever(poll_interval=0.01), daemon=True
        )
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            reports[mode] = run_handle_probe(
                url,
                _tasks_identity(url, "alice", "A"),
                _tasks_identity(url, "bob", "B"),
            )
        finally:
            server.shutdown()
            server.server_close()
    _print_demo("handle", reports, as_json)
    return _demo_exit(reports)


def _demo_cachescope(as_json: bool) -> int:
    from .cachescope import run_cachescope_probe
    from .practice_cache_http import CacheStack, UpstreamConfig

    uri = "note://shared/inbox"
    reports = {}
    for mode in ("leaky", "safe"):
        with CacheStack(UpstreamConfig(), mode) as stack:
            reports[mode] = run_cachescope_probe(
                stack.proxy_url,
                stack.upstream_url,
                _http_identity(stack.proxy_url, "alice", "A"),
                _http_identity(stack.proxy_url, "bob", "B"),
                direct_a=_http_identity(stack.upstream_url, "alice", "A-direct"),
                direct_b=_http_identity(stack.upstream_url, "bob", "B-direct"),
                uri=uri,
                upstream_calls=stack.upstream_calls,
            )
    _print_demo("cachescope", reports, as_json)
    return _demo_exit(reports)


_DEMO_PROBES = {
    "cache": _demo_cache,
    "handle": _demo_handle,
    "cachescope": _demo_cachescope,
}


def cmd_demo(args: argparse.Namespace) -> int:
    return _DEMO_PROBES[args.probe](args.json)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="strangertest",
        description="Tests MCP servers for cross-identity and delegated-authority (RFC 8693) authorization leaks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The delegation, scope and issuer checks need a login server and a\n"
            "recording upstream; the private-cache check needs a recording upstream.\n"
            "They are run from the integration gates, not from this command line.\n"
            "See integration/RESULTS.md and the gate guides (integration/*_GATE.md).\n"
            "`demo --probe cachescope` shows the cache check locally against a\n"
            "bundled practice upstream.\n\n"
            "Exit codes: 0 OK, 1 LEAK or FAIL, 2 INCONCLUSIVE, 3 usage or "
            "authorization refusal."
        ),
    )
    parser.add_argument("--version", action="version", version=f"stranger-test {__version__}")
    sub = parser.add_subparsers(dest="command")

    practice = sub.add_parser(
        "practice", help="Run the probe against the bundled local practice server."
    )
    practice.add_argument(
        "--safe",
        action="store_true",
        help="Use the correctly-isolated server instead of the leaky one.",
    )
    practice.add_argument(
        "--json", action="store_true", help="Print the full JSON report."
    )
    practice.set_defaults(func=cmd_practice)

    scan = sub.add_parser(
        "scan",
        help="Probe an authorized MCP server over HTTP as two identities.",
        description=(
            "Plants a marker as identity A (via --token-a) and checks whether "
            "identity B (--token-b, or anonymous if omitted) can read it back. "
            "Non-local targets require --authorized and are your responsibility "
            "to be permitted to test."
        ),
    )
    scan.add_argument("url", help="MCP server endpoint, e.g. https://mcp.example.com/mcp")
    scan.add_argument("--token-a", dest="token_a", default=None, help="Bearer token for identity A (the planter).")
    scan.add_argument("--token-b", dest="token_b", default=None, help="Bearer token for identity B (the reader); omit for an anonymous B.")
    scan.add_argument("--plant-tool", dest="plant_tool", required=True, help="Tool name A calls to store the marker.")
    scan.add_argument("--read-tool", dest="read_tool", required=True, help="Tool name B calls to read it back.")
    scan.add_argument("--key", default="secret", help="Key the marker is stored under (default: secret).")
    scan.add_argument("--authorized", action="store_true", help="Confirm you are authorized to test this target (required for non-local hosts).")
    scan.add_argument("--authorization-note", dest="authorization_note", default=None, help="Who authorized this test; recorded in the report.")
    scan.add_argument("--json", action="store_true", help="Print the full JSON report.")
    scan.set_defaults(func=cmd_scan)

    handle = sub.add_parser(
        "handle",
        help="Probe an authorized MCP server's task handles as two identities.",
        description=(
            "Identity A (--token-a) starts tasks (tasks extension, SEP-2663); "
            "identity B (--token-b, or anonymous if omitted) is given their "
            "taskIds and tries tasks/get, tasks/update and tasks/cancel on "
            "them. Non-local targets require --authorized."
        ),
    )
    handle.add_argument("url", help="MCP server endpoint, e.g. https://mcp.example.com/mcp")
    handle.add_argument("--token-a", dest="token_a", default=None, help="Bearer token for identity A (the task owner).")
    handle.add_argument("--token-b", dest="token_b", default=None, help="Bearer token for identity B (the other caller); omit for an anonymous B.")
    handle.add_argument("--authorized", action="store_true", help="Confirm you are authorized to test this target (required for non-local hosts).")
    handle.add_argument("--authorization-note", dest="authorization_note", default=None, help="Who authorized this test; recorded in the report.")
    handle.add_argument("--json", action="store_true", help="Print the full JSON report.")
    handle.set_defaults(func=cmd_handle)

    demo = sub.add_parser(
        "demo",
        help="Demonstrate a probe locally in both leaky and safe mode.",
        description=(
            "Starts the matching bundled practice server in leaky and then safe "
            "mode and prints both results. No network target is needed. Exits 0 "
            "when the leaky server leaks and the safe one does not."
        ),
    )
    demo.add_argument(
        "--probe",
        choices=["cache", "handle", "cachescope"],
        default="cache",
        help="Which probe to demonstrate (default: cache).",
    )
    demo.add_argument("--json", action="store_true", help="Print both reports as JSON.")
    demo.set_defaults(func=cmd_demo)

    surv = sub.add_parser(
        "survey",
        help="Statically triage MCP server source code (reads files only).",
        description=(
            "Parses Python source under PATH and lists tool handlers that touch "
            "stored/shared state but reference no caller identity. This is "
            "coarse, low-confidence triage: every hit needs reading by hand. "
            "Nothing is executed and nothing is connected to."
        ),
    )
    surv.add_argument("path", help="A source file or a directory of MCP server source.")
    surv.add_argument("--json", action="store_true", help="Print the full JSON report.")
    surv.add_argument("--all", action="store_true", help="With --json, include every handler found, not only the candidates.")
    surv.add_argument("--include-tests", dest="include_tests", action="store_true", help="Also scan test files and tests/ directories.")
    surv.set_defaults(func=cmd_survey)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    return func(args)


if __name__ == "__main__":
    raise SystemExit(main())
