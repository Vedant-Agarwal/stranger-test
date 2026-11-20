"""LOCAL practice server for the agent-memory isolation probe.

A standard-library stand-in for the part of an agent server's HTTP API that
holds per-user memory: threads (saved conversation state) and a key-value Store
(long-term memory). The endpoint shapes follow the LangGraph Server API closely
enough for :mod:`strangertest.agent_memory` to drive both this and a real
LangGraph server with the same code:

    GET  /ok
    POST /threads                         {"metadata": {...}}
    GET  /threads/{id}
    GET  /threads/{id}/state
    GET  /threads/{id}/history
    POST /threads/search                  {"limit": n}
    POST /threads/{id}/runs/wait          {"assistant_id": ..., "input": {...}}
    PUT  /store/items                     {"namespace": [...], "key": k, "value": {...}}
    GET  /store/items?namespace=a.b&key=k
    POST /store/items/search              {"namespace_prefix": [...]}
    POST /store/namespaces                {}

The one bundled "agent" (assistant id ``memory``) takes
``{"action": "save", "key": k, "value": v}`` or ``{"action": "recall", "key": k}``.

Callers authenticate with ``Authorization: Bearer tok-<name>``; the identity is
``<name>``. Modes:

* ``leaky``  -- authenticates callers but authorizes nothing: any user can read
  any thread or Store item, and the agent keeps one shared memory namespace.
* ``safe``   -- threads belong to their creator; Store access is limited to
  namespaces whose first label is the caller's identity.
* ``meta``   -- like ``safe``, but ``/store/namespaces`` lists every user's
  namespaces (existence is visible, contents are not).
* ``open``   -- no authentication at all: every caller is ``anonymous``.
* ``broken`` -- like ``safe``, but nothing can be read back even by its owner,
  so the probe's positive controls fail and it must grade INCONCLUSIVE.
* ``prefixbug`` -- like ``safe`` (the app checks namespace ownership), but the
  Store matches a namespace prefix as a *string*, not segment by segment (the
  shape of CVE-2026-71433). A user whose id is a string prefix of another user's
  id sees that user's items in their own-namespace search.

NEVER expose this on a network. It stores unauthenticated data by design.

    STRANGERTEST_MODE=leaky STRANGERTEST_PORT=4650 python3 -m strangertest.practice_agent_memory_http
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

MODES = ("leaky", "safe", "meta", "open", "broken", "prefixbug")
FORBIDDEN_PORTS = {4000, 4444, 8790}
ASSISTANT_ID = "memory"

__all__ = ["MODES", "ASSISTANT_ID", "AgentMemoryState", "build_server", "main"]


class _HTTPError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class AgentMemoryState:
    """Threads and Store items for every user of one practice server."""

    def __init__(self, mode: str):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
        self.mode = mode
        self.threads: Dict[str, Dict[str, Any]] = {}
        self.items: Dict[Tuple[Tuple[str, ...], str], Dict[str, Any]] = {}
        self._lock = threading.Lock()

    # -- who is calling ---------------------------------------------------

    def identify(self, authorization: Optional[str]) -> str:
        if self.mode == "open":
            return "anonymous"
        token = (authorization or "")
        token = token[len("Bearer "):] if token.startswith("Bearer ") else ""
        if not token.startswith("tok-") or len(token) <= 4:
            raise _HTTPError(401, "unknown token")
        return token[4:]

    @property
    def _owner_scoped(self) -> bool:
        return self.mode in ("safe", "meta", "broken", "prefixbug")

    # -- threads ----------------------------------------------------------

    def create_thread(self, user: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        thread = {"thread_id": str(uuid.uuid4()), "owner": user,
                  "metadata": dict(metadata), "values": {}, "history": []}
        with self._lock:
            self.threads[thread["thread_id"]] = thread
        return self._thread_view(thread)

    def _thread_view(self, thread: Dict[str, Any]) -> Dict[str, Any]:
        metadata = {} if self.mode == "broken" else dict(thread["metadata"])
        return {"thread_id": thread["thread_id"], "metadata": metadata, "status": "idle"}

    def _thread_for(self, user: str, thread_id: str) -> Dict[str, Any]:
        thread = self.threads.get(thread_id)
        if thread is None or (self._owner_scoped and thread["owner"] != user):
            raise _HTTPError(404, f"Thread with ID {thread_id} not found")
        return thread

    def get_thread(self, user: str, thread_id: str) -> Dict[str, Any]:
        return self._thread_view(self._thread_for(user, thread_id))

    def get_state(self, user: str, thread_id: str) -> Dict[str, Any]:
        thread = self._thread_for(user, thread_id)
        values = {} if self.mode == "broken" else dict(thread["values"])
        return {"values": values, "next": [], "tasks": []}

    def get_history(self, user: str, thread_id: str) -> List[Dict[str, Any]]:
        thread = self._thread_for(user, thread_id)
        if self.mode == "broken":
            return []
        return [{"values": dict(v), "next": [], "tasks": []} for v in reversed(thread["history"])]

    def search_threads(self, user: str) -> List[Dict[str, Any]]:
        with self._lock:
            threads = list(self.threads.values())
        return [self._thread_view(t) for t in threads
                if not self._owner_scoped or t["owner"] == user]

    # -- the agent --------------------------------------------------------

    def run(self, user: str, thread_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        thread = self._thread_for(user, thread_id)
        if body.get("assistant_id") != ASSISTANT_ID:
            raise _HTTPError(404, "Thread or assistant not found.")
        state = dict(body.get("input") or {})
        namespace = ("memories",) if self.mode in ("leaky", "open") else (user, "memories")
        key = str(state.get("key"))
        if state.get("action") == "save":
            with self._lock:
                self.items[(namespace, key)] = {"text": state.get("value")}
            state["result"] = "saved"
        else:
            item = self.items.get((namespace, key))
            state["result"] = item.get("text") if item else None
        state["whoami"] = user
        with self._lock:
            thread["values"] = state
            thread["history"].append(state)
        return {"result": None, "whoami": user} if self.mode == "broken" else dict(state)

    # -- the Store --------------------------------------------------------

    def _check_namespace(self, user: str, namespace: Tuple[str, ...]) -> None:
        if self._owner_scoped and (not namespace or namespace[0] != user):
            raise _HTTPError(403, "not your namespace")

    def put_item(self, user: str, namespace: Tuple[str, ...], key: str, value: Dict[str, Any]) -> None:
        self._check_namespace(user, namespace)
        with self._lock:
            self.items[(namespace, key)] = dict(value)

    def get_item(self, user: str, namespace: Tuple[str, ...], key: str) -> Dict[str, Any]:
        self._check_namespace(user, namespace)
        item = self.items.get((namespace, key))
        if item is None or self.mode == "broken":
            raise _HTTPError(404, "Item not found")
        return {"namespace": list(namespace), "key": key, "value": dict(item)}

    def search_items(self, user: str, prefix: Tuple[str, ...]) -> Dict[str, Any]:
        self._check_namespace(user, prefix)
        if self.mode == "broken":
            return {"items": []}
        if self.mode == "prefixbug":
            def matches(ns):  # string match on the dotted form: crosses segment boundaries
                return ".".join(ns).startswith(".".join(prefix))
        else:
            def matches(ns):  # segment-by-segment match
                return ns[:len(prefix)] == prefix
        with self._lock:
            found = [{"namespace": list(ns), "key": key, "value": dict(value)}
                     for (ns, key), value in self.items.items() if matches(ns)]
        return {"items": found}

    def list_namespaces(self, user: str) -> Dict[str, Any]:
        with self._lock:
            names = sorted({ns for ns, _ in self.items})
        if self.mode in ("safe", "broken", "prefixbug"):
            names = [ns for ns in names if ns and ns[0] == user]
        return {"namespaces": [list(ns) for ns in names]}


def _make_handler(state: AgentMemoryState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep output quiet
            pass

        def _send(self, status: int, payload: Any = None) -> None:
            body = b"" if payload is None else json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            try:
                parsed = json.loads(raw)
            except ValueError:
                raise _HTTPError(422, "body is not JSON")
            if not isinstance(parsed, dict):
                raise _HTTPError(422, "body must be an object")
            return parsed

        def _dispatch(self, method: str) -> None:
            url = urlparse(self.path)
            parts = [p for p in url.path.split("/") if p]
            try:
                body = self._body() if method in ("POST", "PUT") else {}
                if method == "GET" and parts == ["ok"]:
                    return self._send(200, {"ok": True})
                user = state.identify(self.headers.get("Authorization"))
                if parts and parts[0] == "threads":
                    return self._threads(method, parts[1:], user, body)
                if parts and parts[0] == "store":
                    return self._store(method, parts[1:], user, body, parse_qs(url.query))
                raise _HTTPError(404, "Not Found")
            except _HTTPError as exc:
                self._send(exc.status, {"detail": exc.detail})

        def _threads(self, method, rest, user, body) -> None:
            if method == "POST" and not rest:
                return self._send(200, state.create_thread(user, body.get("metadata") or {}))
            if method == "POST" and rest == ["search"]:
                return self._send(200, state.search_threads(user))
            if method == "GET" and len(rest) == 1:
                return self._send(200, state.get_thread(user, rest[0]))
            if method == "GET" and len(rest) == 2 and rest[1] == "state":
                return self._send(200, state.get_state(user, rest[0]))
            if method == "GET" and len(rest) == 2 and rest[1] == "history":
                return self._send(200, state.get_history(user, rest[0]))
            if method == "POST" and len(rest) == 3 and rest[1:] == ["runs", "wait"]:
                return self._send(200, state.run(user, rest[0], body))
            raise _HTTPError(404, "Not Found")

        def _store(self, method, rest, user, body, query) -> None:
            if method == "PUT" and rest == ["items"]:
                state.put_item(user, tuple(body.get("namespace") or ()), str(body.get("key")),
                               body.get("value") or {})
                return self._send(204)
            if method == "GET" and rest == ["items"]:
                namespace = tuple(p for p in (query.get("namespace") or [""])[0].split(".") if p)
                return self._send(200, state.get_item(user, namespace, (query.get("key") or [""])[0]))
            if method == "POST" and rest == ["items", "search"]:
                return self._send(200, state.search_items(user, tuple(body.get("namespace_prefix") or ())))
            if method == "POST" and rest == ["namespaces"]:
                return self._send(200, state.list_namespaces(user))
            raise _HTTPError(404, "Not Found")

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_PUT(self):
            self._dispatch("PUT")

    return Handler


def build_server(mode: str, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    state = AgentMemoryState(mode)
    server = ThreadingHTTPServer((host, port), _make_handler(state))
    server.daemon_threads = True
    server.state = state  # type: ignore[attr-defined]
    return server


def main() -> None:
    mode = os.environ.get("STRANGERTEST_MODE", "leaky")
    port = int(os.environ.get("STRANGERTEST_PORT", "0"))
    if port in FORBIDDEN_PORTS:
        raise SystemExit(f"ERROR: refusing reserved port {port}")
    server = build_server(mode, port=port)
    host, bound = server.server_address[0], server.server_address[1]
    print(f"practice-agent-memory-http [{mode}] on http://{host}:{bound}")
    server.serve_forever()


if __name__ == "__main__":
    main()
