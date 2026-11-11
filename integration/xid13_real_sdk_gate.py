"""XID-13 real-server gate: drive the OFFICIAL MCP SDK example over real HTTP.

This is the "prove it against a server you didn't write" check for the
subscription-leak probe. It boots the reference SDK's subscriptions example
server (``stories.subscriptions.server``) over genuine Streamable HTTP and
drives it with the stdlib Stranger Test probe, asserting the probe speaks the
real 2026-07-28 ``subscriptions/listen`` wire: the modern per-request envelope,
the server's acknowledgment, real pushed ``notifications/resources/updated``
frames, and exact-URI filtering (an unsubscribed resource stays silent) — the
same behavior the SDK's own ``client.py`` asserts.

It is NOT part of ``unittest discover``: it needs the SDK, uvicorn and the
``stories`` examples package, which live only in the SDK's own environment.

Run it from a checkout of the SDK (here, under corpus/), inside that env::

    cd corpus/modelcontextprotocol_python-sdk
    UV_DYNAMIC_VERSIONING_BYPASS=0.0.0 uv sync --frozen --python 3.11   # once
    UV_DYNAMIC_VERSIONING_BYPASS=0.0.0 uv run --frozen python \
        ../../integration/xid13_real_sdk_gate.py

Exit status 0 means the gate passed; non-zero names the failing checks.

NOTE on the A/B leg: the SDK example has no identities and its notes are
global, so a second connection legitimately sees the first's edits. That is
correct behavior there and exercises the probe end to end; it is NOT a
vulnerability finding. Leak-vs-safe *detection* is proven by the leaky/
owner-only practice fixtures in tests/, not here.
"""

import os
import sys
import threading
import time

# Make the stdlib strangertest package importable from inside the SDK's env.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

try:
    import uvicorn
    from stories._hosting import asgi_from
    from stories.subscriptions.server import build_server
except Exception as exc:  # pragma: no cover - environment gate
    print(f"SKIP: SDK example environment not available ({exc}).")
    print("Run this under the SDK's env; see the module docstring.")
    sys.exit(0)

from strangertest.mcp_client import MCPClient
from strangertest.probe import Identity
from strangertest.subscribe import run_subscription_probe
from strangertest.transports import HTTPTransport

PORT = int(os.environ.get("STRANGERTEST_GATE_PORT", "8791"))
URL = f"http://127.0.0.1:{PORT}/mcp"
TODO = "note://todo"
JOURNAL = "note://journal"

failures = []


def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def connect():
    # 2026-07-28 is the modern per-request-envelope era: no initialize
    # handshake, version declared per request.
    return MCPClient(
        HTTPTransport(
            URL,
            modern=True,
            declared_version="2026-07-28",
            client_info={"name": "stranger-test", "version": "0"},
            client_capabilities={},
        )
    )


def main():
    app = asgi_from(build_server(), path="/mcp")
    config = uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if getattr(server, "started", False):
            break
        time.sleep(0.1)
    time.sleep(0.3)

    try:
        c = connect()
        c.initialize()
        check("handshake negotiates 2026-07-28", c.protocol_version == "2026-07-28",
              f"got {c.protocol_version!r}")

        stream = c.listen(resource_subscriptions=[TODO])
        check("server acknowledges the subscription",
              stream.honored.get("resourceSubscriptions") == [TODO],
              f"honored={stream.honored!r}")

        c.call_tool("edit_note", {"name": "journal", "text": "day two"})
        c.call_tool("edit_note", {"name": "todo", "text": "water plants"})
        events = stream.drain_events(idle_timeout=2.0)
        uris = [e.get("params", {}).get("uri") for e in events]
        check("pushed update for the subscribed URI", TODO in uris, f"uris={uris!r}")
        check("unsubscribed URI not delivered (exact-URI filter)",
              JOURNAL not in uris, f"uris={uris!r}")
        metas = [e.get("params", {}).get("_meta", {}) for e in events]
        check("frames carry a subscription-id _meta",
              any("io.modelcontextprotocol/subscriptionId" in m for m in metas),
              f"metas={metas!r}")
        stream.close()
        c.close()

        report = run_subscription_probe(
            URL,
            Identity(label="A", connect=connect),
            Identity(label="B", connect=connect),
            resource_uri=TODO,
            change=lambda cl: cl.call_tool("edit_note", {"name": "todo", "text": "x"}),
        )
        check("A/B probe runs end to end and returns a report",
              report.resource_uri == TODO, report.summary())
    finally:
        server.should_exit = True
        thread.join(timeout=5)

    print()
    if failures:
        print(f"GATE FAILED: {failures}")
        sys.exit(1)
    print("GATE PASSED: probe speaks the real subscriptions/listen wire.")


if __name__ == "__main__":
    main()
