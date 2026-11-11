"""A LOCAL single-process HTTP practice MCP server with real subscription streams.

For exercising the XID-13 subscription-leak probe over genuine HTTP using the
2026-07-28 ``subscriptions/listen`` wire format (SEP-2575): a client opens one
``subscriptions/listen`` POST whose response *is* a ``text/event-stream``; the
first frame is ``notifications/subscriptions/acknowledged`` (echoing the honored
filter), and every later frame is a change notification pushed as it happens.
There is no poll and no replay — this matches how the reference SDK behaves.

One process serves multiple identities, keyed by the ``Authorization`` header,
so one identity's change can — in ``leaky`` mode — be delivered to another
identity that subscribed to the same URI. In ``safe`` mode a resource update is
delivered only to the identity that owns the resource. ``fail_listen`` mode
makes ``subscriptions/listen`` reply with a plain JSON error instead of a
stream, so the probe can prove it reports *inconclusive* rather than "no leak".

NEVER expose this on a network. Run it:

    STRANGERTEST_MODE=leaky python3 -m strangertest.practice_http
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Set

PROTOCOL_VERSION = "2026-07-28"
SUBSCRIPTION_ID_META_KEY = "io.modelcontextprotocol/subscriptionId"
ACK_METHOD = "notifications/subscriptions/acknowledged"
UPDATED_METHOD = "notifications/resources/updated"
# How long a listen handler blocks for an event before writing a keepalive
# comment (which also lets it notice a client that has gone away).
_KEEPALIVE_SECONDS = 1.0
# A listen stream is torn down after this long regardless, so a test that
# forgets to close one cannot wedge a server thread forever.
_MAX_STREAM_SECONDS = 120.0


def _result(mid: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


class _Subscription:
    """One open listen stream's server-side state."""

    def __init__(self, identity: str, uris: Set[str]):
        self.identity = identity
        self.uris = uris
        self.queue: "queue.Queue[str]" = queue.Queue()


class SubscriptionState:
    def __init__(self, leaky: bool, fail_listen: bool = False):
        self.leaky = leaky
        self.fail_listen = fail_listen
        self.values: Dict[str, Any] = {}
        self.owner: Dict[str, str] = {}
        self.subs: List[_Subscription] = []
        self._lock = threading.Lock()

    # -- request/response (JSON) methods --------------------------------

    def handle(self, identity: str, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            return _result(mid, {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {"name": "practice-http"},
                "capabilities": {"resources": {}},
            })
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            return _result(mid, {"tools": [
                {"name": "set_resource"}, {"name": "get_resource"},
            ]})
        if method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            if name == "set_resource":
                uri = args.get("uri")
                with self._lock:
                    self.owner.setdefault(uri, identity)
                    self.values[uri] = args.get("value")
                    self._fanout(uri)
                return _result(mid, {"content": [{"type": "text", "text": "ok"}]})
            if name == "get_resource":
                value = self.values.get(args.get("uri"), "")
                return _result(mid, {"content": [{"type": "text", "text": value}]})
            return _err(mid, -32601, f"unknown tool {name}")
        if mid is None:
            return None
        return _err(mid, -32601, f"unknown method {method}")

    def _fanout(self, uri: str) -> None:
        """Queue a resource-update for every subscriber that should see it.

        Called under ``self._lock``. Leaky mode delivers to any subscriber of
        the URI; safe mode delivers only to the resource's owner.
        """
        owner = self.owner.get(uri)
        for sub in self.subs:
            if uri not in sub.uris:
                continue
            if self.leaky or sub.identity == owner:
                sub.queue.put(uri)

    # -- subscription lifecycle -----------------------------------------

    def register(self, identity: str, uris: Set[str]) -> _Subscription:
        sub = _Subscription(identity, uris)
        with self._lock:
            self.subs.append(sub)
        return sub

    def unregister(self, sub: _Subscription) -> None:
        with self._lock:
            try:
                self.subs.remove(sub)
            except ValueError:
                pass


def _sse_frame(message: Dict[str, Any]) -> bytes:
    return b"data: " + json.dumps(message).encode("utf-8") + b"\n\n"


def _make_handler(state: SubscriptionState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep output quiet
            pass

        def _identity(self) -> str:
            return self.headers.get("Authorization", "anonymous")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            identity = self._identity()
            try:
                msg = json.loads(raw)
            except ValueError:
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                return

            if msg.get("method") == "subscriptions/listen":
                self._serve_listen(identity, msg)
                return

            resp = state.handle(identity, msg)
            if resp is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _serve_listen(self, identity: str, msg: Dict[str, Any]) -> None:
            mid = msg.get("id")
            # fail_listen fixture: reply with a plain JSON error, not a stream,
            # so the probe reports the subscription inconclusive.
            if state.fail_listen:
                body = json.dumps(_err(mid, -32000, "listen unavailable")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            filters = (msg.get("params") or {}).get("notifications") or {}
            uris = set(filters.get("resourceSubscriptions") or [])
            honored: Dict[str, Any] = {}
            if filters.get("toolsListChanged"):
                honored["toolsListChanged"] = True
            if filters.get("resourcesListChanged"):
                honored["resourcesListChanged"] = True
            if filters.get("promptsListChanged"):
                honored["promptsListChanged"] = True
            if uris:
                honored["resourceSubscriptions"] = sorted(uris)
            meta = {SUBSCRIPTION_ID_META_KEY: mid}

            sub = state.register(identity, uris)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            try:
                # The ack is always the first frame on the stream.
                self._write_frame({
                    "jsonrpc": "2.0",
                    "method": ACK_METHOD,
                    "params": {"notifications": honored, "_meta": meta},
                })
                deadline = time.monotonic() + _MAX_STREAM_SECONDS
                while time.monotonic() < deadline:
                    try:
                        uri = sub.queue.get(timeout=_KEEPALIVE_SECONDS)
                    except queue.Empty:
                        if not self._write(b": keepalive\n\n"):
                            break
                        continue
                    ok = self._write_frame({
                        "jsonrpc": "2.0",
                        "method": UPDATED_METHOD,
                        "params": {"uri": uri, "_meta": meta},
                    })
                    if not ok:
                        break
            finally:
                state.unregister(sub)

        def _write_frame(self, message: Dict[str, Any]) -> bool:
            return self._write(_sse_frame(message))

        def _write(self, data: bytes) -> bool:
            try:
                self.wfile.write(data)
                self.wfile.flush()
                return True
            except (BrokenPipeError, ConnectionError, OSError):
                return False

    return Handler


def build_server(
    mode: str,
    host: str = "127.0.0.1",
    port: int = 0,
    fail_listen: bool = False,
) -> ThreadingHTTPServer:
    state = SubscriptionState(leaky=(mode != "safe"), fail_listen=fail_listen)
    server = ThreadingHTTPServer((host, port), _make_handler(state))
    server.daemon_threads = True
    return server


def main() -> None:
    mode = os.environ.get("STRANGERTEST_MODE", "leaky")
    port = int(os.environ.get("STRANGERTEST_PORT", "0"))
    server = build_server(mode, port=port)
    host, bound = server.server_address[0], server.server_address[1]
    print(f"practice-http [{mode}] on http://{host}:{bound}/mcp")
    server.serve_forever()


if __name__ == "__main__":
    main()
