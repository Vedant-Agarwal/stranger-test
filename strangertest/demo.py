"""A zero-dependency, in-process demo of the subscription-leak probe (XID-13).

Run it with the plain system interpreter, from the repo root::

    python3 -m strangertest.demo

It starts the bundled practice MCP subscription server on a loopback port in a
background thread — first in ``leaky`` mode, then in ``safe`` mode — and runs the
subscription-leak probe against each. In leaky mode identity B hears identity
A's resource update (a cross-identity leak); in safe mode it does not.

Nothing listens on a public interface and no third-party packages are used; this
is a demo, not a test. The wiring mirrors ``tests/test_subscribe_http.py``.
"""

from __future__ import annotations

import threading

from strangertest.mcp_client import MCPClient
from strangertest.practice_http import build_server
from strangertest.probe import Identity
from strangertest.subscribe import run_subscription_probe
from strangertest.transports import HTTPTransport

A_URI = "note://alice/secret"


def _identity(url: str, token: str, label: str) -> Identity:
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {token}"})
        ),
    )


def _change(uri: str):
    return lambda client: client.call_tool("set_resource", {"uri": uri, "value": "x"})


def _probe_mode(mode: str) -> None:
    server = build_server(mode)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
        report = run_subscription_probe(
            url,
            _identity(url, "alice", "A"),
            _identity(url, "bob", "B"),
            resource_uri=A_URI,
            change=_change(A_URI),
        )
    finally:
        server.shutdown()
        server.server_close()

    print(f"[{mode}] {report.summary()}")


def main() -> None:
    print("Subscription-leak probe (XID-13) against the bundled practice server.")
    print("B subscribes to A's resource; A changes it; did B hear about it?\n")
    _probe_mode("leaky")
    _probe_mode("safe")


if __name__ == "__main__":
    main()
