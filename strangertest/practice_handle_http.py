"""A LOCAL single-process HTTP practice MCP server with tasks (saved references).

For exercising the saved-reference probe (:mod:`strangertest.handle`) over real
HTTP. It speaks just enough of the 2026-07-28 tasks extension
(``io.modelcontextprotocol/tasks``): ``tools/call`` on ``start_job`` returns a
``CreateTaskResult`` (``resultType: "task"``) when the request declares the
extension in ``_meta`` clientCapabilities, and ``tasks/get``, ``tasks/update``
and ``tasks/cancel`` act on it.

``start_job`` takes ``marker`` and ``kind``:

* ``complete``: finishes shortly after creation; ``result`` holds the marker.
* ``input``: held in ``input_required`` (with ``inputRequests``) until a
  ``tasks/update`` supplies ``inputResponses``, then completes.
* ``hold``: held in ``working`` until ``tasks/cancel``.

Identity is the ``Authorization`` header, or with ``identity_from="jwt"`` the
bearer token's ``(orig_iss or iss, sub)`` claims (read, NOT verified: this
server sits behind the gateway under test, which validated the caller), so a
token a gateway exchanges afresh on every request still names the same user.
``leaky`` mode skips the owner check
on the methods in ``leaky_methods`` (default: all three). ``safe`` mode answers
a foreign taskId exactly like a nonexistent one (-32602). ``oracle`` mode is
safe but words the foreign-id error differently (an existence oracle, which is
an observation, not a leak). ``no_tasks`` never returns a task.

NEVER expose this on a network. Run it:

    STRANGERTEST_MODE=leaky python3 -m strangertest.practice_handle_http
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, Optional

PROTOCOL_VERSION = "2026-07-28"
TASKS_EXTENSION = "io.modelcontextprotocol/tasks"
CLIENT_CAPS_KEY = "io.modelcontextprotocol/clientCapabilities"
ALL_METHODS = ("get", "update", "cancel")
_COMPLETE_AFTER = 0.05  # seconds before a "complete" task finishes


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _result(mid: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _b64json(part: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def token_claims(authorization: str) -> Optional[Dict[str, Any]]:
    """The claims of a ``Bearer <JWT>`` header, unverified; None if not a JWT."""
    token = authorization[7:] if authorization.startswith("Bearer ") else authorization
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        claims = _b64json(parts[1])
    except Exception:
        return None
    return claims if isinstance(claims, dict) else None


def identity_from_jwt(authorization: str) -> str:
    """``jwt:<orig_iss or iss>|<sub>`` from the bearer's claims; the raw header
    when there is no JWT with a ``sub`` (so two unparseable tokens stay two
    identities instead of collapsing into one)."""
    claims = token_claims(authorization)
    if not claims or not claims.get("sub"):
        return authorization
    return f"jwt:{claims.get('orig_iss') or claims.get('iss')}|{claims['sub']}"


def _claims_record(authorization: str) -> Optional[Dict[str, Any]]:
    claims = token_claims(authorization)
    if claims is None:
        return None
    act = claims.get("act")
    return {"iss": claims.get("iss"), "orig_iss": claims.get("orig_iss"),
            "sub": claims.get("sub"), "aud": claims.get("aud"),
            "scope": claims.get("scope"),
            "act_sub": act.get("sub") if isinstance(act, dict) else None}


class _Task:
    def __init__(self, owner: str, marker: str, kind: str):
        self.id = "task-" + secrets.token_hex(16)
        self.owner = owner
        self.marker = marker
        self.kind = kind
        self.created_at = _now()
        self.updated_at = self.created_at
        self.created_mono = time.monotonic()
        self.status = {"complete": "working", "input": "input_required", "hold": "working"}[kind]
        self.result: Optional[Dict[str, Any]] = None
        self.input_applied: Any = None

    def settle(self) -> None:
        if (
            self.kind == "complete"
            and self.status == "working"
            and time.monotonic() - self.created_mono >= _COMPLETE_AFTER
        ):
            self.status = "completed"
            self.result = {"content": [{"type": "text", "text": self.marker}]}
            self.updated_at = _now()

    def view(self) -> Dict[str, Any]:
        self.settle()
        out: Dict[str, Any] = {
            "taskId": self.id,
            "status": self.status,
            "createdAt": self.created_at,
            "lastUpdatedAt": self.updated_at,
            "ttlMs": 60000,
            "pollIntervalMs": 20,
        }
        if self.status == "input_required":
            out["inputRequests"] = {"q1": {"method": "elicitation/create"}}
        if self.status == "completed":
            out["result"] = self.result
        return out


class TasksState:
    def __init__(
        self,
        mode: str = "leaky",
        leaky_methods: Optional[Iterable[str]] = None,
        no_tasks: bool = False,
        reject_updates: bool = False,
        drift: bool = False,
        require_name_header: bool = False,
        identity_from: str = "header",
    ):
        if identity_from not in ("header", "jwt"):
            raise ValueError(f"identity_from must be 'header' or 'jwt', not {identity_from!r}")
        self.identity_from = identity_from
        self.mode = mode
        # Strict routing-header check (SEP-2663: Mcp-Name mirrors taskId on
        # tasks/*), answered with -32020 like a strict gateway would.
        self.require_name_header = require_name_header
        self.drift = drift
        self.views = 0
        self.reject_updates = reject_updates
        if mode == "leaky":
            self.leaky_methods = set(leaky_methods if leaky_methods is not None else ALL_METHODS)
        else:
            self.leaky_methods = set()
        self.no_tasks = no_tasks
        self.tasks: Dict[str, _Task] = {}
        self._lock = threading.Lock()
        # What reached this server, for gateway gates: one entry per message
        # (method, whether the tasks extension was declared in _meta, the
        # caller identity as a sha256 fingerprint, the MCP-Protocol-Version
        # header). Never the raw identity: it may be a bearer token.
        self.seen: list = []

    def reset(self, mode: str, **kwargs: Any) -> None:
        """Switch mode in place, dropping all tasks and the request record.

        Use this, not a server restart on the same port, to change mode behind
        a gateway: a gateway's pooled keep-alive connections would otherwise
        keep reaching the OLD server's handler threads (and its old mode).
        """
        kwargs.setdefault("identity_from", self.identity_from)
        with self._lock:
            self.__init__(mode, **kwargs)  # type: ignore[misc]

    def _lookup(self, identity: str, method: str, task_id: Any):
        """Return (task, None) or (None, error_response_args)."""
        task = self.tasks.get(task_id) if isinstance(task_id, str) else None
        if task is None:
            return None, "Invalid or nonexistent taskId"
        if task.owner != identity and method not in self.leaky_methods:
            if self.mode == "oracle":
                return None, "Task belongs to another identity"
            return None, "Invalid or nonexistent taskId"
        return task, None

    def handle(
        self, identity: str, msg: Dict[str, Any], name_header: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        method = msg.get("method")
        mid = msg.get("id")
        params = msg.get("params") or {}
        caps = (params.get("_meta") or {}).get(CLIENT_CAPS_KEY) or {}
        has_ext = TASKS_EXTENSION in (caps.get("extensions") or {})

        if method in ("initialize", "server/discover"):
            # Discovery, so a gateway can front this server. Advertises the
            # tasks extension; speaks 2026-07-28 (and answers a 2025-11-25
            # initialize with the same version list so a mismatch is visible).
            return _result(mid, {
                "resultType": "complete",
                "protocolVersion": PROTOCOL_VERSION,
                "supportedVersions": [PROTOCOL_VERSION],
                "capabilities": {"tools": {"listChanged": False},
                                 "extensions": {TASKS_EXTENSION: {}}},
                "serverInfo": {"name": "practice-handle", "version": "1"},
            })
        if method == "tools/list":
            return _result(mid, {
                "resultType": "complete", "cacheScope": "private", "ttlMs": 0,
                "tools": [{
                    "name": "start_job",
                    "description": "Start a task (tasks extension).",
                    "inputSchema": {"type": "object", "properties": {
                        "marker": {"type": "string"},
                        "kind": {"type": "string"}}},
                }],
            })
        if isinstance(method, str) and method.startswith("notifications/"):
            return None

        if method == "tools/call":
            args = params.get("arguments") or {}
            if params.get("name") != "start_job":
                return _err(mid, -32601, f"unknown tool {params.get('name')}")
            if self.no_tasks or not has_ext:
                return _result(mid, {
                    "resultType": "complete",
                    "content": [{"type": "text", "text": "done"}],
                })
            kind = args.get("kind", "complete")
            if kind not in ("complete", "input", "hold"):
                return _err(mid, -32602, "bad kind")
            task = _Task(identity, str(args.get("marker", "")), kind)
            with self._lock:
                self.tasks[task.id] = task
            created = task.view()
            created["status"] = "working" if kind != "input" else "input_required"
            created.pop("result", None)
            created["resultType"] = "task"
            return _result(mid, created)

        if method in ("tasks/get", "tasks/update", "tasks/cancel"):
            if self.no_tasks or not has_ext:
                return _err(mid, -32021, "Missing required client capability: tasks")
            short = method.split("/", 1)[1]
            if self.require_name_header and name_header != params.get("taskId"):
                return _err(mid, -32020, "invalid MCP routing header: Mcp-Name")
            if short == "update" and self.reject_updates:
                return _err(mid, -32602, "Malformed inputResponses")
            with self._lock:
                task, message = self._lookup(identity, short, params.get("taskId"))
                if task is None:
                    return _err(mid, -32602, message)
                if short == "get":
                    out = task.view()
                    if self.drift and task.kind != "complete":
                        # A self-progressing task: it changes with nobody acting.
                        self.views += 1
                        out["statusMessage"] = f"progress tick {self.views}"
                    out["resultType"] = "complete"
                    return _result(mid, out)
                task.settle()
                if short == "update":
                    if task.status == "input_required" and params.get("inputResponses"):
                        task.input_applied = params["inputResponses"]
                        task.status = "completed"
                        task.result = {"content": [{"type": "text", "text": "input applied"}]}
                        task.updated_at = _now()
                elif task.status in ("working", "input_required"):
                    task.status = "cancelled"
                    task.updated_at = _now()
                return _result(mid, {"resultType": "complete"})

        if mid is None:
            return None
        return _err(mid, -32601, f"unknown method {method}")


def _owner_fp(state: TasksState, task_id: Any) -> Optional[str]:
    task = state.tasks.get(task_id) if isinstance(task_id, str) else None
    if task is None:
        return None
    return "sha256:" + hashlib.sha256(task.owner.encode()).hexdigest()[:12]


def _make_handler(state: TasksState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            # No standalone SSE stream.
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_DELETE(self):
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            header = self.headers.get("Authorization", "anonymous")
            identity = (identity_from_jwt(header) if state.identity_from == "jwt"
                        else header)
            try:
                msg = json.loads(raw)
            except ValueError:
                msg = None
            if isinstance(msg, dict):
                params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                caps = (params.get("_meta") or {}).get(CLIENT_CAPS_KEY) or {}
                state.seen.append({
                    "method": msg.get("method"),
                    "tasks_ext_declared": TASKS_EXTENSION in (caps.get("extensions") or {}),
                    "identity": "sha256:" + hashlib.sha256(identity.encode()).hexdigest()[:12],
                    # The bearer itself (fingerprint) and its claims, so a gate
                    # can show the token at the upstream is not the user's own.
                    "token": "sha256:" + hashlib.sha256(header.encode()).hexdigest()[:12],
                    "claims": _claims_record(header),
                    "protocol_header": self.headers.get("MCP-Protocol-Version"),
                    "meta_protocol": (params.get("_meta") or {}).get(
                        "io.modelcontextprotocol/protocolVersion"),
                    # Owner of the task this request names (fingerprint), so a
                    # gate can tell "B's request on A's task reached the upstream".
                    "task_owner": _owner_fp(state, params.get("taskId")),
                })
            if not isinstance(msg, dict):
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            resp = state.handle(identity, msg, self.headers.get("Mcp-Name"))
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

    return Handler


def build_server(
    mode: str,
    host: str = "127.0.0.1",
    port: int = 0,
    leaky_methods: Optional[Iterable[str]] = None,
    no_tasks: bool = False,
    reject_updates: bool = False,
    drift: bool = False,
    require_name_header: bool = False,
    identity_from: str = "header",
) -> ThreadingHTTPServer:
    state = TasksState(mode, leaky_methods, no_tasks, reject_updates, drift,
                       require_name_header, identity_from)
    server = ThreadingHTTPServer((host, port), _make_handler(state))
    server.daemon_threads = True
    server.state = state  # type: ignore[attr-defined]
    return server


def main() -> None:
    mode = os.environ.get("STRANGERTEST_MODE", "leaky")
    port = int(os.environ.get("STRANGERTEST_PORT", "0"))
    server = build_server(mode, port=port)
    host, bound = server.server_address[0], server.server_address[1]
    print(f"practice-handle-http [{mode}] on http://{host}:{bound}/mcp")
    server.serve_forever()


if __name__ == "__main__":
    main()
