"""The saved-reference probe: another identity's task handle (tasks extension).

A starts a long-running task (``tools/call`` returning ``resultType: "task"``)
and holds its ``taskId``. Identity B, authenticated as B and given that taskId,
calls ``tasks/get``, ``tasks/update`` and ``tasks/cancel`` on it. The tasks
extension (``io.modelcontextprotocol/tasks``) says servers MUST authenticate
and authorize each task request; CoSAI MCP Security v2.0 sections 3.2.7 and
3.2.12 cover the same failure. Guessing taskIds is out of scope: B is given the
ID.

Three tasks are started by A, one per attacked method, so a leak is attributed
to the method that caused it and one attack cannot disturb another:

* ``get``: a task that completes with a unique marker in its result.
* ``update``: a task held in ``input_required``.
* ``cancel``: a task held in ``working``.

Grading (never OK for something not observed):

* Positive controls first. A reads each of its own tasks through ``tasks/get``
  and must see the expected state (and the marker for the ``get`` task); B
  starts and reads one of its own. If any control fails, INCONCLUSIVE.
* ``get`` leaks if B's response carries A's marker (exact leaf equality, not a
  substring search) or a recognised task status.
* B's own update and cancel are also controls: B starts its own input/hold
  task and updates/cancels it. If that fails, the method is INCONCLUSIVE.
* Drift control: A reads the target task twice over ``drift_window`` before B
  acts. If it changed with nobody acting, the method is INCONCLUSIVE.
* ``cancel`` leaks only if, after B's attempt, A's task is "cancelled".
  ``update`` leaks only if A's task leaves "input_required" or its
  inputRequests change. Other changes (statusMessage, lastUpdatedAt, ...) are
  recorded as observations. If B got an acknowledgement but no leak-relevant
  change is observable within the settle window, that method is INCONCLUSIVE;
  if B got an error and nothing changed, it is OK.
* No tasks extension (the server never returns ``resultType: "task"`` or
  returns -32021): INCONCLUSIVE.
* If B's reply to A's taskId differs in shape from its reply to a NONEXISTENT
  taskId, that is recorded as an observation ("existence oracle"), not a leak.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .guard import authorize
from .mcp_client import MCP_NAME_HEADER, JSONRPCError, MCPClient
from .probe import Identity, new_marker
from .transports import TASK_NAME_BEARING_METHODS, HTTPTransport

__all__ = [
    "TASKS_EXTENSION",
    "TaskPlan",
    "MethodResult",
    "HandleReport",
    "tasks_identity",
    "TasksHTTPTransport",
    "run_handle_probe",
]

TASKS_EXTENSION = "io.modelcontextprotocol/tasks"
CLIENT_CAPABILITIES_WITH_TASKS = {"extensions": {TASKS_EXTENSION: {}}}
TASK_STATUSES = frozenset(
    {"working", "input_required", "completed", "failed", "cancelled"}
)
ERR_INVALID_PARAMS = -32602
ERR_MISSING_CAPABILITY = -32021

LEAK = "LEAK"
OK = "OK"
INCONCLUSIVE = "INCONCLUSIVE"

FAILURE_CLASS = "cross-identity saved-reference (task handle) leak"

# The attacked method, the kind of task A starts for it, and the state A's
# positive control must see.
_KINDS = {
    "get": ("complete", "completed"),
    "update": ("input", "input_required"),
    "cancel": ("hold", "working"),
}


class TasksHTTPTransport(HTTPTransport):
    """Modern HTTP transport that mirrors ``taskId`` into ``Mcp-Name`` on tasks/*.

    Kept for existing callers: it is ``HTTPTransport`` with
    ``name_bearing_methods=TASK_NAME_BEARING_METHODS`` (the default here)."""

    def __init__(self, url, **kwargs):
        kwargs.setdefault("name_bearing_methods", TASK_NAME_BEARING_METHODS)
        super().__init__(url, **kwargs)


def tasks_identity(url: str, token: str, label: str) -> Identity:
    """An Identity that talks modern (2026-07-28) HTTP and declares the tasks extension."""
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            TasksHTTPTransport(
                url,
                headers={"Authorization": f"Bearer {token}"},
                modern=True,
                client_capabilities=CLIENT_CAPABILITIES_WITH_TASKS,
            )
        ),
    )


def _default_input_responses(task: Dict[str, Any]) -> Dict[str, Any]:
    requests = task.get("inputRequests")
    if isinstance(requests, dict) and requests:
        return {key: {"value": "st-b-input"} for key in requests}
    return {"answer": "st-b-input"}


@dataclass
class TaskPlan:
    """How to make A's server start each kind of task, and how B answers input.

    ``arguments(marker, kind)`` builds the ``tools/call`` arguments; ``kind`` is
    ``"complete"`` (finishes with the marker in its result), ``"input"`` (waits
    in input_required) or ``"hold"`` (stays working). ``input_responses`` builds
    the ``inputResponses`` B sends, from A's view of the task.
    """

    tool: str = "start_job"
    arguments: Callable[[str, str], Dict[str, Any]] = lambda marker, kind: {
        "marker": marker,
        "kind": kind,
    }
    input_responses: Callable[[Dict[str, Any]], Dict[str, Any]] = (
        _default_input_responses
    )


@dataclass
class MethodResult:
    method: str
    grade: str
    detail: str


@dataclass
class HandleReport:
    target: str
    authorization: str
    identity_a: str
    identity_b: str
    grade: str
    detail: str
    methods: Dict[str, MethodResult] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)

    @property
    def leaked(self) -> bool:
        return self.grade == LEAK

    @property
    def leaked_methods(self) -> List[str]:
        return [m for m, r in self.methods.items() if r.grade == LEAK]

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "probe": "handle",
            "target": self.target,
            "authorization": self.authorization,
            "identity_a": self.identity_a,
            "identity_b": self.identity_b,
            "grade": self.grade,
            "detail": self.detail,
            "methods": {
                m: {"grade": r.grade, "detail": r.detail}
                for m, r in self.methods.items()
            },
            "observations": list(self.observations),
        }
        if self.leaked:
            data["failure_class"] = FAILURE_CLASS
            data["leaked_methods"] = self.leaked_methods
        return data

    def summary(self) -> str:
        if self.grade == LEAK:
            return (
                f"LEAK: identity {self.identity_b!r} could use identity "
                f"{self.identity_a!r}'s task handle via "
                f"{', '.join('tasks/' + m for m in self.leaked_methods)} "
                f"- {FAILURE_CLASS}."
            )
        if self.grade == OK:
            return (
                f"OK: identity {self.identity_b!r} could not get, update or "
                f"cancel identity {self.identity_a!r}'s task."
            )
        return f"INCONCLUSIVE: {self.detail}"


class _Inconclusive(Exception):
    pass


def _rpc(client: MCPClient, method: str, params: Dict[str, Any]) -> Any:
    # MCPClient has no generic request method; _call is its single request path.
    # This is the ONLY place handle.py touches it.
    call = getattr(client, "_call", None)
    if call is None:
        raise RuntimeError(
            "MCPClient._call is missing: strangertest/handle.py _rpc() needs "
            "a generic request method on the client; update _rpc()"
        )
    return call(method, params)


def _contains_exact(obj: Any, marker: str) -> bool:
    """True if any string leaf of ``obj`` equals ``marker`` exactly."""
    if isinstance(obj, str):
        return obj == marker
    if isinstance(obj, dict):
        return any(_contains_exact(v, marker) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_exact(v, marker) for v in obj)
    return False


def _is_task_result(result: Any) -> bool:
    return (
        isinstance(result, dict)
        and result.get("resultType") == "task"
        and isinstance(result.get("taskId"), str)
        and bool(result["taskId"])
    )


_CHANGE_KEYS = ("status", "statusMessage", "inputRequests", "result", "error")
# Drift is judged on everything a task shows, including its timestamp.
_DRIFT_KEYS = _CHANGE_KEYS + ("lastUpdatedAt",)


def _snapshot(task: Dict[str, Any], keys: tuple = _CHANGE_KEYS) -> str:
    import json

    return json.dumps({k: task.get(k) for k in keys}, sort_keys=True, default=str)


_LEAK_RULE = {
    "cancel": "cancel leaks only if A's task becomes 'cancelled'",
    "update": "update leaks only if A's task leaves 'input_required' "
    "or its inputRequests change",
}


def _is_leak_change(method: str, before: Dict[str, Any], now: Dict[str, Any]) -> bool:
    if method == "cancel":
        return now.get("status") == "cancelled"
    return now.get("status") != "input_required" or _snapshot(
        before, ("inputRequests",)
    ) != _snapshot(now, ("inputRequests",))


def _start(client: MCPClient, plan: TaskPlan, marker: str, kind: str) -> Dict[str, Any]:
    try:
        result = client.call_tool(plan.tool, plan.arguments(marker, kind))
    except JSONRPCError as exc:
        if exc.code == ERR_MISSING_CAPABILITY:
            raise _Inconclusive(
                f"the server returned {ERR_MISSING_CAPABILITY} (missing client "
                f"capability): no tasks extension for this client"
            )
        raise _Inconclusive(f"starting a task failed: {exc}")
    if not _is_task_result(result):
        raise _Inconclusive(
            "the server did not return resultType 'task' from tools/call "
            f"{plan.tool!r}: no tasks extension (or the plan's tool is wrong)"
        )
    return result


def _wait_for(
    client: MCPClient,
    task_id: str,
    pred: Callable[[Dict[str, Any]], bool],
    what: str,
    timeout: float,
) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: Any = None
    while True:
        try:
            last = _rpc(client, "tasks/get", {"taskId": task_id})
        except Exception as exc:
            raise _Inconclusive(f"tasks/get on own task failed: {exc}")
        if isinstance(last, dict) and pred(last):
            return last
        if time.monotonic() >= deadline:
            got = last.get("status") if isinstance(last, dict) else last
            raise _Inconclusive(f"own task never {what} (last status {got!r})")
        time.sleep(0.02)


def _wait_status(
    client: MCPClient, task_id: str, want: str, timeout: float
) -> Dict[str, Any]:
    return _wait_for(
        client, task_id, lambda t: t.get("status") == want, f"reached {want!r}", timeout
    )


def _own_control(
    method: str, client: MCPClient, plan: TaskPlan, timeout: float
) -> Optional[str]:
    """B drives its OWN task through ``method``; return None or why it failed.

    Without this a server that rejects every update (or cancel) would look
    safe: B's refusal on A's task would prove nothing.
    """
    kind, expected = _KINDS[method]
    try:
        created = _start(client, plan, new_marker(), kind)
        task_id = created["taskId"]
        seen = _wait_status(client, task_id, expected, timeout)
        if method == "update":
            _rpc(
                client,
                "tasks/update",
                {"taskId": task_id, "inputResponses": plan.input_responses(seen)},
            )
            _wait_for(
                client,
                task_id,
                lambda t: t.get("status") != "input_required",
                "left 'input_required' after B's own update",
                timeout,
            )
        else:
            _rpc(client, "tasks/cancel", {"taskId": task_id})
            _wait_status(client, task_id, "cancelled", timeout)
    except Exception as exc:
        return f"B's own tasks/{method} control failed: {exc}"
    return None


def _outcome(call: Callable[[], Any]) -> Dict[str, Any]:
    """Run an RPC and return ``{"ok": result}`` or ``{"error": (code, message)}``."""
    try:
        return {"ok": call()}
    except JSONRPCError as exc:
        return {"error": (exc.code, exc.message)}
    except Exception as exc:  # transport trouble: not a server answer
        return {"failed": str(exc)}


def _shape(outcome: Dict[str, Any], task_id: str) -> Any:
    if "error" in outcome:
        code, message = outcome["error"]
        return ("error", code, str(message).replace(task_id, "<id>"))
    if "ok" in outcome:
        result = outcome["ok"]
        keys = sorted(result) if isinstance(result, dict) else type(result).__name__
        return ("ok", tuple(keys) if isinstance(keys, list) else keys)
    return ("failed",)


def run_handle_probe(
    target: str,
    identity_a: Identity,
    identity_b: Identity,
    *,
    plan: Optional[TaskPlan] = None,
    ready_timeout: float = 5.0,
    settle_timeout: float = 1.0,
    drift_window: float = 0.25,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> HandleReport:
    """A starts tasks; B, given the taskIds, tries get/update/cancel on them."""
    decision = authorize(
        target, authorized=authorized, authorization_note=authorization_note
    )
    plan = plan or TaskPlan()

    def report(grade, detail, methods=None, observations=None) -> HandleReport:
        return HandleReport(
            target=decision.target,
            authorization=decision.reason,
            identity_a=identity_a.label,
            identity_b=identity_b.label,
            grade=grade,
            detail=detail,
            methods=methods or {},
            observations=observations or [],
        )

    client_a = identity_a.connect()
    client_b: Optional[MCPClient] = None
    try:
        try:
            client_a.initialize()
            client_b = identity_b.connect()
            client_b.initialize()

            # --- A starts one task per attacked method, and A's own control. ---
            tasks: Dict[str, Dict[str, Any]] = {}
            markers: Dict[str, str] = {}
            for method, (kind, expected) in _KINDS.items():
                markers[method] = new_marker()
                created = _start(client_a, plan, markers[method], kind)
                task_id = created["taskId"]
                seen = _wait_status(client_a, task_id, expected, ready_timeout)
                if method == "get" and not _contains_exact(seen, markers["get"]):
                    raise _Inconclusive(
                        "positive control failed: A's completed task did not "
                        "return A's marker through tasks/get"
                    )
                tasks[method] = {"id": task_id, "seen": seen}

            # --- B's own control: B can start and read a task of its own. ---
            b_marker = new_marker()
            b_created = _start(client_b, plan, b_marker, "complete")
            b_seen = _wait_status(client_b, b_created["taskId"], "completed", ready_timeout)
            if not _contains_exact(b_seen, b_marker):
                raise _Inconclusive(
                    "positive control failed: B could not read its own task result"
                )

            # --- B's own update and cancel controls (per method). ---
            control_failed: Dict[str, str] = {}
            for method in ("update", "cancel"):
                why = _own_control(method, client_b, plan, ready_timeout)
                if why is not None:
                    control_failed[method] = why
        except _Inconclusive as exc:
            return report(INCONCLUSIVE, str(exc))
        except Exception as exc:
            return report(INCONCLUSIVE, f"could not set up the probe: {exc}")

        methods: Dict[str, MethodResult] = {}
        foreign: Dict[str, Dict[str, Any]] = {}
        observations: List[str] = []

        # --- Attack 1: tasks/get with A's completed task. ---
        g_id = tasks["get"]["id"]
        out = _outcome(lambda: _rpc(client_b, "tasks/get", {"taskId": g_id}))
        foreign["get"] = out
        if "failed" in out:
            methods["get"] = MethodResult("get", INCONCLUSIVE, f"transport failure: {out['failed']}")
        elif "error" in out:
            methods["get"] = MethodResult("get", OK, f"B was refused ({out['error'][0]})")
        else:
            res = out["ok"]
            if _contains_exact(res, markers["get"]):
                methods["get"] = MethodResult("get", LEAK, "B received A's marker")
            elif isinstance(res, dict) and res.get("status") in TASK_STATUSES:
                methods["get"] = MethodResult(
                    "get", LEAK, f"B received A's task status {res['status']!r}"
                )
            else:
                methods["get"] = MethodResult(
                    "get", INCONCLUSIVE, "B got an unrecognised success reply"
                )

        # --- Attacks 2 and 3: B mutates; A re-reads. ---
        for method in ("update", "cancel"):
            t_id = tasks[method]["id"]
            before = tasks[method]["seen"]
            if method in control_failed:
                methods[method] = MethodResult(
                    method, INCONCLUSIVE, control_failed[method]
                )
                continue
            # Drift control: with nobody acting, A's task must hold still.
            try:
                first = _rpc(client_a, "tasks/get", {"taskId": t_id})
                time.sleep(drift_window)
                second = _rpc(client_a, "tasks/get", {"taskId": t_id})
            except Exception as exc:
                methods[method] = MethodResult(
                    method, INCONCLUSIVE, f"A could not re-read its task: {exc}"
                )
                continue
            if _snapshot(first, _DRIFT_KEYS) != _snapshot(second, _DRIFT_KEYS):
                methods[method] = MethodResult(
                    method,
                    INCONCLUSIVE,
                    f"A's task is unstable: it changed within {drift_window}s "
                    f"with nobody acting, so a change after B's attempt "
                    f"could not be attributed to B",
                )
                continue
            before = second
            if method == "update":
                params = {
                    "taskId": t_id,
                    "inputResponses": plan.input_responses(before),
                }
            else:
                params = {"taskId": t_id}
            out = _outcome(lambda: _rpc(client_b, f"tasks/{method}", params))
            foreign[method] = out
            if "failed" in out:
                methods[method] = MethodResult(
                    method, INCONCLUSIVE, f"transport failure: {out['failed']}"
                )
                continue
            deadline = time.monotonic() + (settle_timeout if "ok" in out else 0.0)
            leaked_now: Optional[Dict[str, Any]] = None
            last_now: Optional[Dict[str, Any]] = None
            reread_error: Optional[str] = None
            while True:
                try:
                    now = _rpc(client_a, "tasks/get", {"taskId": t_id})
                except Exception as exc:
                    reread_error = str(exc)
                    break
                if isinstance(now, dict):
                    last_now = now
                    if _is_leak_change(method, before, now):
                        leaked_now = now
                        break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
            if leaked_now is None and last_now is not None:
                other = [
                    k
                    for k in _DRIFT_KEYS
                    if _snapshot(before, (k,)) != _snapshot(last_now, (k,))
                ]
                if other:
                    observations.append(
                        f"after B's tasks/{method}, A's task changed in "
                        f"{', '.join(other)} (not counted as a leak: "
                        f"{_LEAK_RULE[method]})"
                    )
            if leaked_now is not None:
                methods[method] = MethodResult(
                    method,
                    LEAK,
                    f"after B's tasks/{method}, A's task changed "
                    f"({before.get('status')!r} -> {leaked_now.get('status')!r})",
                )
            elif reread_error is not None:
                methods[method] = MethodResult(
                    method, INCONCLUSIVE, f"A could not re-read its task: {reread_error}"
                )
            elif "error" in out:
                methods[method] = MethodResult(
                    method, OK, f"B was refused ({out['error'][0]}); A's task unchanged"
                )
            else:
                observations.append(
                    f"tasks/{method} by another identity on A's task was "
                    f"acknowledged (no error) but no change to A's task was "
                    f"visible: possibly a silent no-op, possibly a delayed effect"
                )
                methods[method] = MethodResult(
                    method,
                    INCONCLUSIVE,
                    f"B's tasks/{method} was acknowledged but no leak-relevant "
                    f"change to A's task was observed within {settle_timeout}s",
                )

        # --- Existence oracle: foreign id versus nonexistent id. ---
        for method in ("get", "update", "cancel"):
            out = foreign.get(method)
            if out is None or "error" not in out:
                continue
            ghost = "st-nonexistent-" + secrets.token_hex(8)
            if method == "update":
                params = {"taskId": ghost, "inputResponses": plan.input_responses({})}
            else:
                params = {"taskId": ghost}
            ghost_out = _outcome(lambda: _rpc(client_b, f"tasks/{method}", params))
            if "failed" in ghost_out:
                continue
            if "error" not in ghost_out or ghost_out["error"][0] != ERR_INVALID_PARAMS:
                observations.append(
                    f"tasks/{method} on a nonexistent taskId did not return "
                    f"{ERR_INVALID_PARAMS} (got {_shape(ghost_out, ghost)!r})"
                )
            real_id = tasks[method]["id"]
            if _shape(out, real_id) != _shape(ghost_out, ghost):
                observations.append(
                    f"existence oracle on tasks/{method}: reply for another "
                    f"identity's taskId {_shape(out, real_id)!r} differs from "
                    f"reply for a nonexistent taskId {_shape(ghost_out, ghost)!r}"
                )
    finally:
        _safe_close(client_a)
        if client_b is not None:
            _safe_close(client_b)

    grades = {r.grade for r in methods.values()}
    if LEAK in grades:
        overall = LEAK
        detail = "B used A's task handle: " + ", ".join(
            f"{m} ({r.detail})" for m, r in methods.items() if r.grade == LEAK
        )
    elif grades == {OK}:
        overall = OK
        detail = "B was refused on get, update and cancel and A's tasks were unchanged"
    else:
        overall = INCONCLUSIVE
        detail = "; ".join(
            f"{m}: {r.detail}" for m, r in methods.items() if r.grade != OK
        )
    return report(overall, detail, methods, observations)


def _safe_close(client: MCPClient) -> None:
    try:
        client.close()
    except Exception:
        pass
