"""LOCAL practice MCP server for the subscriptions/listen notification-leak probe.

A thin layer over :mod:`strangertest.practice_http`, which already serves genuine
2026-07-28 ``subscriptions/listen`` SSE streams keyed by the ``Authorization``
header. This module adds the modes the
:mod:`strangertest.subscriptions_leak` probe needs and exposes one
``build_server(mode, ...)`` entry point:

* ``"leaky"`` -- fans a resource update out to **every** listen stream
  subscribed to that URI, regardless of who owns the resource. B, listening on
  A's URI, receives A's notification: the cross-identity delivery leak.
  (Delegated to :func:`strangertest.practice_http.build_server` unchanged.)
* ``"safe"`` -- delivers each resource update **only to the owner's** stream, so
  A's notification never reaches B. (Also delegated unchanged.)
* ``"mute"`` -- the BROKEN fixture: streams open and acknowledge normally, but
  the server fans nothing out, so no notification ever fires. The probe's
  positive control (A's own stream must receive A's own notification) fails,
  and the probe must grade INCONCLUSIVE, never OK. This is what proves an OK
  from the ``safe`` server means something.

``practice_http.py`` is reused by import and is **not modified**: ``"mute"`` is a
``SubscriptionState`` subclass whose ``_fanout`` is a no-op, wired into the same
request handler.

NEVER expose this on a network. It stores unauthenticated data by design.

    STRANGERTEST_MODE=leaky python3 -m strangertest.practice_subscriptions_http
"""

from __future__ import annotations

import os
from http.server import ThreadingHTTPServer

from .practice_http import SubscriptionState, _make_handler
from .practice_http import build_server as _base_build_server

__all__ = ["MutedSubscriptionState", "build_server", "main"]


class MutedSubscriptionState(SubscriptionState):
    """Like the leaky state, but never pushes a notification to any stream.

    Streams still open, acknowledge and stay alive; the server simply never
    fans an update out. Used as the broken fixture that makes the probe's
    "notifications fire at all" control fail -> INCONCLUSIVE.
    """

    def __init__(self) -> None:
        super().__init__(leaky=True, fail_listen=False)

    def _fanout(self, uri: str) -> None:  # noqa: D401 - deliberately does nothing
        return


class CollapsedSubscriptionState(SubscriptionState):
    """Leaky fan-out, but reports ONE shared principal for every caller.

    The identity-collapse / shared-session shape: A's notification reaches B's
    stream, yet the server maps A and B to the same principal, so the delivery
    is not a cross-user access gain. The probe must grade OBSERVATION, not LEAK.
    """

    def __init__(self) -> None:
        super().__init__(leaky=True, fail_listen=False)

    def _principal(self, identity: str) -> str:
        return "shared-principal"


def build_server(
    mode: str,
    host: str = "127.0.0.1",
    port: int = 0,
    fail_listen: bool = False,
) -> ThreadingHTTPServer:
    """A practice subscriptions server in ``leaky``, ``safe`` or ``mute`` mode.

    ``leaky``/``safe`` (and ``fail_listen``) are delegated to
    :func:`strangertest.practice_http.build_server` untouched; ``mute`` wires
    the no-op-fanout state into that module's handler.
    """
    if mode in ("mute", "collapse"):
        if fail_listen:
            raise ValueError(f"{mode!r} mode does not combine with fail_listen")
        state = MutedSubscriptionState() if mode == "mute" else CollapsedSubscriptionState()
        server = ThreadingHTTPServer((host, port), _make_handler(state))
        server.daemon_threads = True
        return server
    return _base_build_server(mode, host=host, port=port, fail_listen=fail_listen)


def main() -> None:
    mode = os.environ.get("STRANGERTEST_MODE", "leaky")
    port = int(os.environ.get("STRANGERTEST_PORT", "0"))
    server = build_server(mode, port=port)
    host, bound = server.server_address[0], server.server_address[1]
    print(f"practice-subscriptions [{mode}] on http://{host}:{bound}/mcp")
    server.serve_forever()


if __name__ == "__main__":
    main()
