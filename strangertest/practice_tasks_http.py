"""A LOCAL single-process HTTP practice MCP server for the tasks-extension
cross-tenant IDOR probe (:mod:`strangertest.tasks_idor`).

It speaks just enough of the 2026-07-28 tasks extension
(``io.modelcontextprotocol/tasks``) to be attacked: ``tools/call`` on
``start_job`` returns a ``CreateTaskResult`` (``resultType: "task"``) when the
request declares the extension in ``_meta`` clientCapabilities, and
``tasks/get``, ``tasks/update`` and ``tasks/cancel`` act on a task addressed by
``taskId``.

It exists so the probe can be exercised against both a vulnerable and a correct
server over real loopback HTTP. Two primary modes:

* ``leaky`` - the spec violated two ways at once:
    1. No per-request authorization. The owner check on ``tasks/get`` /
       ``tasks/update`` / ``tasks/cancel`` is skipped, so identity B can read,
       update and cancel identity A's task given its id (cross-tenant IDOR).
    2. Low-entropy, sequential task ids (``task-1``, ``task-2``, ...): a third
       party can guess and enumerate them. The spec's "generate task IDs with
       enough entropy that a third party cannot guess" is broken.
* ``safe`` - per-request authorization keyed on the caller identity (a foreign
  or forged ``taskId`` is answered exactly like a nonexistent one, ``-32602``),
  and high-entropy random ids (``task-<32 hex>``, 128 bits).

Identity is the ``Authorization`` header (so ``Bearer alice`` and ``Bearer
bob`` are two users).

Broken-fixture knobs (NOT real modes - used only to prove the probe's controls
fail a broken observer rather than silently grading OK):

* ``break_own_read=True`` - a completed task returns the WRONG marker, so even
  the owner cannot read its own task result (positive control fails).
* ``accept_forged=True`` - a nonexistent ``taskId`` returns a fabricated task
  instead of ``-32602`` (the forged-id negative control fails).

NEVER expose this on a network. Run it:

    STRANGERTEST_MODE=leaky python3 -m strangertest.practice_tasks_http
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

PROTOCOL_VERSION = "2026-07-28"
TASKS_EXTENSION = "io.modelcontextprotocol/tasks"
CLIENT_CAPS_KEY = "io.modelcontextprotocol/clientCapabilities"
_COMPLETE_AFTER = 0.05  # seconds before a "complete" task finishes

ERR_INVALID_PARAMS = -32602
ERR_MISSING_CAPABILITY = -32021


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _result(mid: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


class _Task:
    def __init__(self, task_id: str, owner: str, marker: str, kind: str):
        self.id = task_id
        self.owner = owner
        self.marker = marker
        self.kind = kind
        self.created_at = _now()
        self.updated_at = self.created_at
        self.created_mono = time.monotonic()
        self.status = "input_required" if kind == "input" else "working"
        self.result: Optional[Dict[str, Any]] = None

    def settle(self) -> None:
        if (
            self.kind == "complete"
            and self.status == "working"
            and time.monotonic() - self.created_mono >= _COMPLETE_AFTER
        ):
            self.status = "completed"
            self.result = {"content": [{"type": "text", "text": self.marker}]}
            self.updated_at = _now()

    def view(self, marker_override: Optional[str] = None) -> Dict[str, Any]:
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
            if marker_override is not None:
                out["result"] = {"content": [{"type": "text", "text": marker_override}]}
            else:
                out["result"] = self.result
        return out


class TasksState:
    """The practice server's behaviour for one mode.

    ``mode`` is ``"leaky"`` or ``"safe"``. ``id_style`` defaults to the mode's
    natural style (sequential for leaky, random for safe) but can be overridden
    to build a server with, e.g., per-request authz AND guessable ids.
    """

    def __init__(
        self,
        mode: str = "leaky",
        *,
        id_style: Optional[str] = None,
        no_tasks: bool = False,
        reject_updates: bool = False,
        break_own_read: bool = False,
        accept_forged: bool = False,
    ):
        if mode not in ("leaky", "safe", "collapse"):
            raise ValueError(f"mode must be 'leaky', 'safe' or 'collapse', not {mode!r}")
        self.mode = mode
        self.authorize = mode == "safe"
        # "collapse": no per-request authz (like leaky), but whoami reports one
        # shared principal for every caller — the identity-collapse shape where a
        # cross-identity task reach is NOT a cross-user access gain.
        self.collapse = mode == "collapse"
        self.id_style = id_style or ("sequential" if mode in ("leaky", "collapse") else "random")
        if self.id_style not in ("sequential", "random"):
            raise ValueError(f"id_style must be 'sequential' or 'random', not {self.id_style!r}")
        self.no_tasks = no_tasks
        self.reject_updates = reject_updates
        self.break_own_read = break_own_read
        self.accept_forged = accept_forged
        self.tasks: Dict[str, _Task] = {}
        self._seq = 0
        self._lock = threading.Lock()
        # One record per message, fingerprints only (never a raw token).
        self.seen: list = []

    def reset(self, mode: str, **kwargs: Any) -> None:
        with self._lock:
            self.__init__(mode, **kwargs)  # type: ignore[misc]

    def _new_id(self) -> str:
        if self.id_style == "sequential":
            self._seq += 1
            return f"task-{self._seq}"
        return "task-" + secrets.token_hex(16)

    def _lookup(self, identity: str, task_id: Any):
        """Return (task, None) or (None, error_message)."""
        task = self.tasks.get(task_id) if isinstance(task_id, str) else None
        if task is None:
            if self.accept_forged and isinstance(task_id, str) and task_id:
                # A broken server that invents a task for any id: the probe's
                # forged-id negative control must catch this and refuse to say OK.
                ghost = _Task(task_id, identity, "forged-" + secrets.token_hex(4), "complete")
                ghost.created_mono -= _COMPLETE_AFTER  # already "completed"
                return ghost, None
            return None, "Invalid or nonexistent taskId"
        if self.authorize and task.owner != identity:
            # Safe: a foreign id is indistinguishable from a nonexistent one.
            return None, "Invalid or nonexistent taskId"
        return task, None

    def handle(self, identity: str, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = msg.get("method")
        mid = msg.get("id")
        params = msg.get("params") or {}
        caps = (params.get("_meta") or {}).get(CLIENT_CAPS_KEY) or {}
        has_ext = TASKS_EXTENSION in (caps.get("extensions") or {})

        if method in ("initialize", "server/discover"):
            return _result(mid, {
                "resultType": "complete",
                "protocolVersion": PROTOCOL_VERSION,
                "supportedVersions": [PROTOCOL_VERSION],
                "capabilities": {"tools": {"listChanged": False},
                                 "extensions": {TASKS_EXTENSION: {}}},
                "serverInfo": {"name": "practice-tasks", "version": "1"},
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
                }, {
                    "name": "whoami",
                    "description": "Report the caller's principal (distinctness signal).",
                    "inputSchema": {"type": "object", "properties": {}},
                }],
            })
        if isinstance(method, str) and method.startswith("notifications/"):
            return None

        if method == "tools/call":
            args = params.get("arguments") or {}
            if params.get("name") == "whoami":
                principal = ("shared-principal" if self.collapse
                             else "sha256:" + hashlib.sha256(identity.encode()).hexdigest()[:12])
                return _result(mid, {
                    "content": [{"type": "text", "text": principal}],
                    "structuredContent": {"principal": principal},
                })
            if params.get("name") != "start_job":
                return _err(mid, -32601, f"unknown tool {params.get('name')}")
            if self.no_tasks or not has_ext:
                return _result(mid, {
                    "resultType": "complete",
                    "content": [{"type": "text", "text": "done"}],
                })
            kind = args.get("kind", "complete")
            if kind not in ("complete", "input", "hold"):
                return _err(mid, ERR_INVALID_PARAMS, "bad kind")
            with self._lock:
                task = _Task(self._new_id(), identity, str(args.get("marker", "")), kind)
                self.tasks[task.id] = task
            created = task.view()
            created["status"] = "working" if kind != "input" else "input_required"
            created.pop("result", None)
            created["resultType"] = "task"
            return _result(mid, created)

        if method in ("tasks/get", "tasks/update", "tasks/cancel"):
            if self.no_tasks or not has_ext:
                return _err(mid, ERR_MISSING_CAPABILITY,
                            "Missing required client capability: tasks")
            short = method.split("/", 1)[1]
            if short == "update" and self.reject_updates:
                return _err(mid, ERR_INVALID_PARAMS, "Malformed inputResponses")
            with self._lock:
                task, message = self._lookup(identity, params.get("taskId"))
                if task is None:
                    return _err(mid, ERR_INVALID_PARAMS, message)
                if short == "get":
                    override = ("wrong-" + secrets.token_hex(4)) if self.break_own_read else None
                    out = task.view(marker_override=override)
                    out["resultType"] = "complete"
                    return _result(mid, out)
                task.settle()
                if short == "update":
                    if task.status == "input_required" and params.get("inputResponses"):
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


def _make_handler(state: TasksState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
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
            identity = self.headers.get("Authorization", "anonymous")
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
                })
            if not isinstance(msg, dict):
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
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

    return Handler


def build_server(
    mode: str,
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    id_style: Optional[str] = None,
    no_tasks: bool = False,
    reject_updates: bool = False,
    break_own_read: bool = False,
    accept_forged: bool = False,
) -> ThreadingHTTPServer:
    state = TasksState(
        mode,
        id_style=id_style,
        no_tasks=no_tasks,
        reject_updates=reject_updates,
        break_own_read=break_own_read,
        accept_forged=accept_forged,
    )
    server = ThreadingHTTPServer((host, port), _make_handler(state))
    server.daemon_threads = True
    server.state = state  # type: ignore[attr-defined]
    return server


def main() -> None:
    mode = os.environ.get("STRANGERTEST_MODE", "leaky")
    port = int(os.environ.get("STRANGERTEST_PORT", "0"))
    server = build_server(mode, port=port)
    host, bound = server.server_address[0], server.server_address[1]
    print(f"practice-tasks-http [{mode}] on http://{host}:{bound}/mcp")
    server.serve_forever()


if __name__ == "__main__":
    main()
