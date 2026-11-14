"""LOCAL practice setup for the private-cached-results probe (CoSAI 3.2.7).

Two single-process HTTP servers that speak just enough 2026-07-28 MCP
(``resources/read``) over plain JSON:

* an **upstream** that returns per-user content (a marker that differs for each
  bearer token) with ``cacheScope`` / ``ttlMs`` result fields, and counts the
  ``resources/read`` calls it serves;
* a **caching proxy** in front of it that keeps responses for ``ttlMs``.

Upstream labelling is configurable (``public`` / ``private`` / missing) and so is
whether the content really is per-user, so a mislabelled upstream is expressible.
Proxy modes:

* ``leaky``        cache keyed on the request only (shares private results)
* ``safe``         private results keyed per authorization context; public
                   results keyed on the request only (sharing is allowed there)
* ``skip_private`` never stores a ``private`` result
* ``nocache``      never stores anything
* ``stale_shared`` always forwards upstream (the origin count rises, so caching
                   is never observed) but answers every caller with the first
                   result it saw for the URI (a leak the control cannot see)

NEVER expose these on a network. Both bind loopback by default.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

PROTOCOL_VERSION = "2026-07-28"
PROXY_MODES = ("leaky", "safe", "skip_private", "nocache", "stale_shared")


@dataclass
class UpstreamConfig:
    """How the practice upstream labels and shapes its ``resources/read`` result.

    ``cache_scope`` is ``"public"``, ``"private"`` or ``None`` (field omitted).
    ``per_user`` False makes the content identical for every caller.
    ``unstable`` appends the read counter, so content changes on every read.
    """

    cache_scope: Optional[str] = "private"
    per_user: bool = True
    ttl_ms: int = 60000
    unstable: bool = False  # content changes on every read (clock-style)


def _result(mid: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def user_marker(auth: str) -> str:
    """The per-user marker the upstream puts in that caller's content."""
    return "private-note-for:" + (auth or "anonymous")


class UpstreamState:
    def __init__(self, config: UpstreamConfig):
        self.config = config
        self.read_calls = 0
        self._lock = threading.Lock()

    def handle(self, auth: str, msg: Dict[str, Any]) -> Dict[str, Any]:
        mid = msg.get("id")
        if msg.get("method") != "resources/read":
            return _err(mid, -32601, f"unknown method {msg.get('method')}")
        uri = (msg.get("params") or {}).get("uri")
        with self._lock:
            self.read_calls += 1
            n = self.read_calls
        text = user_marker(auth) if self.config.per_user else "shared-content"
        if self.config.unstable:
            text = f"{text}@{n}"
        result: Dict[str, Any] = {
            "resultType": "complete",
            "contents": [{"uri": uri, "mimeType": "text/plain", "text": text}],
            "ttlMs": self.config.ttl_ms,
        }
        if self.config.cache_scope is not None:
            result["cacheScope"] = self.config.cache_scope
        return _result(mid, result)


class ProxyState:
    def __init__(
        self,
        upstream_url: str,
        mode: str,
        rewrite_hints: Optional[Dict[str, Any]] = None,
    ):
        if mode not in PROXY_MODES:
            raise ValueError(f"unknown proxy mode {mode!r}")
        self.upstream_url = upstream_url
        self.mode = mode
        self.rewrite_hints = rewrite_hints or {}
        self._cache: Dict[Tuple, Tuple[float, Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def _key(self, auth: str, uri: Any, scope: Any) -> Tuple:
        if self.mode == "leaky":
            return ("resources/read", uri)
        if scope == "public":
            return ("resources/read", uri)
        return ("resources/read", uri, auth)

    def _lookup(self, auth: str, uri: Any) -> Optional[Dict[str, Any]]:
        if self.mode == "nocache":
            return None
        now = time.monotonic()
        with self._lock:
            # Public/leaky entries sit under (method, uri); safe-mode private
            # entries sit under (method, uri, auth), so a hit is never another
            # caller's private entry.
            for key in (("resources/read", uri), ("resources/read", uri, auth)):
                hit = self._cache.get(key)
                if hit and hit[0] > now:
                    return hit[1]
        return None

    def _store(self, auth: str, uri: Any, result: Dict[str, Any]) -> None:
        if self.mode == "nocache":
            return
        scope = result.get("cacheScope")
        if self.mode == "skip_private" and scope != "public":
            return
        ttl = result.get("ttlMs")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
            return
        if self.mode == "safe" and scope not in ("public", "private"):
            return  # unlabelled: not safe to cache
        with self._lock:
            self._cache[self._key(auth, uri, scope)] = (
                time.monotonic() + ttl / 1000.0,
                result,
            )

    def _handle_stale_shared(self, auth: str, raw: bytes, mid: Any, uri: Any):
        fresh = self._forward(auth, raw, mid)
        if "result" not in fresh:
            return fresh
        with self._lock:
            first = self._cache.setdefault(("stale", uri), (0.0, fresh["result"]))
        return _result(mid, json.loads(json.dumps(first[1])))

    def _forward(self, auth: str, raw: bytes, mid: Any) -> Dict[str, Any]:
        req = urllib.request.Request(
            self.upstream_url,
            data=raw,
            headers={"Content-Type": "application/json", "Authorization": auth},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, ValueError) as exc:
            return _err(mid, -32000, f"upstream failure: {exc}")

    def handle(self, auth: str, raw: bytes, msg: Dict[str, Any]) -> Dict[str, Any]:
        mid = msg.get("id")
        if msg.get("method") != "resources/read":
            return _err(mid, -32601, "proxy only handles resources/read")
        uri = (msg.get("params") or {}).get("uri")
        if self.mode == "stale_shared":
            return self._handle_stale_shared(auth, raw, mid, uri)
        cached = self._lookup(auth, uri)
        if cached is not None:
            return _result(mid, json.loads(json.dumps(cached)))
        upstream = self._forward(auth, raw, mid)
        if "result" not in upstream:
            return upstream
        result = dict(upstream["result"])
        self._store(auth, uri, result)
        for k, v in self.rewrite_hints.items():
            result[k] = v
        return _result(mid, result)


def _make_handler(handle):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            auth = self.headers.get("Authorization", "")
            try:
                msg = json.loads(raw)
            except ValueError:
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps(handle(auth, raw, msg)).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


class CacheStack:
    """An upstream plus a caching proxy in front of it, both on loopback."""

    def __init__(
        self,
        upstream: Optional[UpstreamConfig] = None,
        proxy_mode: str = "leaky",
        rewrite_hints: Optional[Dict[str, Any]] = None,
        host: str = "127.0.0.1",
    ):
        self.upstream_state = UpstreamState(upstream or UpstreamConfig())
        self.upstream_server = ThreadingHTTPServer(
            (host, 0),
            _make_handler(lambda auth, raw, msg: self.upstream_state.handle(auth, msg)),
        )
        self.upstream_url = f"http://{host}:{self.upstream_server.server_address[1]}/mcp"
        self.proxy_state = ProxyState(self.upstream_url, proxy_mode, rewrite_hints)
        self.proxy_server = ThreadingHTTPServer(
            (host, 0),
            _make_handler(self.proxy_state.handle),
        )
        self.proxy_url = f"http://{host}:{self.proxy_server.server_address[1]}/mcp"
        for s in (self.upstream_server, self.proxy_server):
            s.daemon_threads = True
        self._threads = []

    def upstream_calls(self) -> int:
        return self.upstream_state.read_calls

    def start(self) -> "CacheStack":
        for s in (self.upstream_server, self.proxy_server):
            t = threading.Thread(
                target=s.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
            )
            t.start()
            self._threads.append(t)
        return self

    def stop(self) -> None:
        for s in (self.proxy_server, self.upstream_server):
            s.shutdown()
            s.server_close()

    def __enter__(self) -> "CacheStack":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


def main() -> None:
    import os

    mode = os.environ.get("STRANGERTEST_MODE", "leaky")
    stack = CacheStack(UpstreamConfig(), mode).start()
    print(f"practice-cache [{mode}] proxy {stack.proxy_url} upstream {stack.upstream_url}")
    threading.Event().wait()


if __name__ == "__main__":
    main()
