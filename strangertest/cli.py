"""Command-line interface for Stranger Test.

For now the CLI runs the bundled local practice server end-to-end:

    python3 -m strangertest practice          # the leaky server: should find a leak
    python3 -m strangertest practice --safe    # the isolated server: should be clean
    python3 -m strangertest practice --json     # full JSON report

``scan`` runs the same probe against an authorized HTTP server. For both, exit
code is 1 when a leak is found and 0 when none is, so the same command works as
a CI check.

``survey <path>`` is the static side: it reads MCP server source code and lists
low-confidence candidates. It always exits 0 unless the path is missing.
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
from .mcp_client import MCPClient
from .probe import Identity, ProbeError, ProbePlan, run_probe
from .source_audit import survey
from .transports import HTTPTransport, HTTPTransportError, StdioTransport


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
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except ProbeError as exc:
        print(f"inconclusive: {exc}", file=sys.stderr)
        return 2
    except HTTPTransportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return 1 if report.leaked else 0


def cmd_survey(args: argparse.Namespace) -> int:
    # Static only: reads source files, never connects to anything, so there is
    # no target to authorize. Exit code is 0 even with candidates, because a
    # candidate is a low-confidence hit to read by hand, not a confirmed leak.
    try:
        report = survey(args.path, include_tests=args.include_tests)
    except FileNotFoundError:
        print(f"error: no such path: {args.path}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.to_dict(include_all=args.all), indent=2))
    else:
        print(report.summary())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strangertest",
        description="Tests MCP servers for cross-identity and delegated-authority (RFC 8693) authorization leaks.",
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
        parser.print_help()
        return 2
    return func(args)


if __name__ == "__main__":
    raise SystemExit(main())
