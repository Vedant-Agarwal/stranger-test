"""Tasks-extension cross-tenant IDOR probe (+ task-id enumerability).

The MCP tasks extension (``io.modelcontextprotocol/tasks``) returns a task
handle from ``tools/call`` and exposes ``tasks/get``, ``tasks/update`` and
``tasks/cancel`` addressed by ``taskId``. The spec says a server MUST authorize
each task-related request (a task is NOT a higher-trust channel), and MUST
generate task ids with enough entropy that a third party cannot guess or
enumerate them. This probe checks both duties at once:

1. **Cross-tenant IDOR (given the id).** Identity A starts one task per attacked
   method; identity B, authenticated as B and handed A's ``taskId``, calls
   ``tasks/get`` / ``tasks/update`` / ``tasks/cancel`` on it. If B can read,
   change or cancel A's task, that method LEAKs (confirmed cross-tenant IDOR).
   This is the sibling of :mod:`strangertest.handle`; the grading of the three
   mutating/reading methods follows it (exact-leaf marker match for get; a task
   actually leaving its held state for update/cancel; a cosmetic-only change is
   an observation, not a leak).

2. **Id enumerability (not given the id).** The probe samples several ids the
   server minted and estimates their entropy. If the ids are sequential or
   otherwise low-entropy, a third party can guess them: a weakness short of a
   confirmed read, recorded as an OBSERVATION. When the ids are numerically
   sequential the probe goes further and has B actively *guess* a neighbouring
   id it was never given; if B can then read a stranger's task that way, the
   enumeration is confirmed and graded a LEAK (method ``enumerate``).

Grades:

* ``LEAK`` (a.k.a. FAIL) - B read/changed/cancelled A's task (cross-tenant
  IDOR), or B reached a stranger's task via a guessed id. Attributed to the
  method.
* ``OBSERVATION`` - task ids look guessable / low-entropy, but no cross-user
  read was confirmed. A weakness, not a confirmed leak.
* ``OK`` - every cross-identity task op was refused AND the ids are
  high-entropy. Only reached when the controls held (see below).
* ``INCONCLUSIVE`` - the server does not implement tasks, or the probe could
  not observe it (a control failed).

Controls, which must hold before any OK (a broken observer must never grade OK):

* positive: A operating ``tasks/get`` on A's OWN completed task must succeed and
  return A's marker; B must be able to drive its own update/cancel. If not,
  INCONCLUSIVE.
* negative: a forged, never-minted ``taskId`` must be refused. A server that
  answers a forged id with a task cannot be trusted to have refused B, so the
  run is INCONCLUSIVE rather than OK.

Only fingerprints of task ids and identities are ever stored or reported.
"""

from __future__ import annotations

import math
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .delegate import token_fingerprint
from .guard import authorize
from .handle import (
    CLIENT_CAPABILITIES_WITH_TASKS,
    TASKS_EXTENSION,
    TaskPlan,
    TasksHTTPTransport,
    _contains_exact,
    _rpc,
    tasks_identity,
)
from .mcp_client import JSONRPCError, MCPClient
from .probe import Identity, new_marker

__all__ = [
    "LEAK",
    "FAIL",
    "OK",
    "INCONCLUSIVE",
    "OBSERVATION",
    "TASKS_EXTENSION",
    "GUESSABLE_BITS",
    "MethodResult",
    "EntropyFinding",
    "ControlResult",
    "TasksIdorReport",
    "assess_entropy",
    "tasks_identity",
    "run_tasks_idor_probe",
]

LEAK = "LEAK"
FAIL = LEAK  # the task brief writes the confirmed-IDOR grade as "LEAK/FAIL"
OK = "OK"
INCONCLUSIVE = "INCONCLUSIVE"
OBSERVATION = "OBSERVATION"

FAILURE_CLASS = "tasks-extension cross-tenant IDOR (unauthorized task handle / guessable task id)"

ERR_INVALID_PARAMS = -32602
ERR_MISSING_CAPABILITY = -32021
TASK_STATUSES = frozenset(
    {"working", "input_required", "completed", "failed", "cancelled"}
)

# Below this estimated entropy a task id is treated as guessable. The spec wants
# ids "a third party cannot guess/enumerate"; 64 bits is the usual floor for an
# unguessable token. (A random 16-hex-char id is 64 bits; the safe practice
# server mints 32 hex chars = 128 bits.)
GUESSABLE_BITS = 64

# The attacked method, the task kind A starts for it, and the state A's own task
# must reach for the method to be testable.
_KINDS = {
    "get": ("complete", "completed"),
    "update": ("input", "input_required"),
    "cancel": ("hold", "working"),
}

_CHANGE_KEYS = ("status", "statusMessage", "inputRequests", "result", "error")
_DRIFT_KEYS = _CHANGE_KEYS + ("lastUpdatedAt",)
_LEAK_RULE = {
    "cancel": "cancel leaks only if A's task becomes 'cancelled'",
    "update": "update leaks only if A's task leaves 'input_required' "
    "or its inputRequests change",
}


# ---------------------------------------------------------------- result types


@dataclass
class MethodResult:
    method: str
    grade: str
    detail: str


@dataclass
class EntropyFinding:
    grade: str  # OBSERVATION (guessable), OK (high-entropy) or INCONCLUSIVE
    detail: str
    est_bits: Optional[float] = None
    sequential: bool = False
    enumerated: bool = False  # B reached a stranger's task via a guessed id
    sample_fingerprints: List[str] = field(default_factory=list)


@dataclass
class ControlResult:
    name: str
    passed: bool
    detail: str


@dataclass
class TasksIdorReport:
    target: str
    authorization: str
    identity_a: str
    identity_b: str
    grade: str
    detail: str
    methods: Dict[str, MethodResult] = field(default_factory=dict)
    entropy: Optional[EntropyFinding] = None
    controls: Dict[str, ControlResult] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)

    @property
    def leaked(self) -> bool:
        return self.grade == LEAK

    @property
    def leaked_methods(self) -> List[str]:
        return [m for m, r in self.methods.items() if r.grade == LEAK]

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "probe": "tasks_idor",
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
            "controls": {
                c: {"passed": r.passed, "detail": r.detail}
                for c, r in self.controls.items()
            },
            "observations": list(self.observations),
        }
        if self.entropy is not None:
            data["entropy"] = {
                "grade": self.entropy.grade,
                "detail": self.entropy.detail,
                "est_bits": self.entropy.est_bits,
                "sequential": self.entropy.sequential,
                "enumerated": self.entropy.enumerated,
                "sample_fingerprints": list(self.entropy.sample_fingerprints),
            }
        if self.leaked:
            data["failure_class"] = FAILURE_CLASS
            data["leaked_methods"] = self.leaked_methods
        return data

    def summary(self) -> str:
        if self.grade == LEAK:
            return (
                f"LEAK: identity {self.identity_b!r} reached identity "
                f"{self.identity_a!r}'s task via "
                f"{', '.join('tasks/' + m if m != 'enumerate' else 'id enumeration' for m in self.leaked_methods)} "
                f"- {FAILURE_CLASS}."
            )
        if self.grade == OBSERVATION:
            return (
                f"OBSERVATION: cross-identity task ops were refused, but task "
                f"ids look guessable ({self.entropy.detail if self.entropy else ''})."
            )
        if self.grade == OK:
            return (
                f"OK: identity {self.identity_b!r} could not reach identity "
                f"{self.identity_a!r}'s task, and task ids are high-entropy."
            )
        return f"INCONCLUSIVE: {self.detail}"


# ----------------------------------------------------------- entropy assessment


def assess_entropy(ids: List[str]) -> EntropyFinding:
    """Estimate whether a sample of minted task ids is guessable.

    Strips the common prefix/suffix the server puts on every id, then judges the
    varying core. All-decimal, small, closely-spaced cores are flagged
    ``sequential`` (trivially enumerable). Otherwise entropy is estimated as
    ``len(shortest core) * log2(alphabet size)`` and compared to
    :data:`GUESSABLE_BITS`.
    """
    fps = [token_fingerprint(i) or "sha256:?" for i in ids]
    uniq = [i for i in dict.fromkeys(ids)]  # preserve order, drop dups
    if len(uniq) < 2:
        return EntropyFinding(
            INCONCLUSIVE,
            "too few distinct task ids to assess entropy",
            sample_fingerprints=fps,
        )

    prefix = _common_prefix(uniq)
    suffix = _common_suffix([i[len(prefix):] for i in uniq])
    cores = [i[len(prefix): len(i) - len(suffix) if suffix else len(i)] for i in uniq]
    cores = [c for c in cores if c]
    if not cores:
        return EntropyFinding(
            OBSERVATION,
            "every task id is identical once the shared prefix/suffix is removed",
            est_bits=0.0,
            sequential=True,
            sample_fingerprints=fps,
        )

    # Sequential: cores are all decimal and span a tiny, closely-spaced range.
    if all(c.isdigit() for c in cores):
        nums = sorted(int(c) for c in cores)
        span = nums[-1] - nums[0]
        if span <= max(len(nums) * 4, 32):
            return EntropyFinding(
                OBSERVATION,
                f"task ids are sequential integers (sample spans {nums[0]}..{nums[-1]} "
                f"after a shared prefix); a third party can enumerate them",
                est_bits=math.log2(span + 1) if span > 0 else 0.0,
                sequential=True,
                sample_fingerprints=fps,
            )

    core_len = min(len(c) for c in cores)
    bits = core_len * math.log2(_alphabet_size(cores))
    if bits < GUESSABLE_BITS:
        return EntropyFinding(
            OBSERVATION,
            f"task ids carry only ~{bits:.0f} bits of entropy in their variable "
            f"part (< {GUESSABLE_BITS}); a third party may be able to guess them",
            est_bits=bits,
            sample_fingerprints=fps,
        )
    return EntropyFinding(
        OK,
        f"task ids carry ~{bits:.0f} bits of entropy in their variable part "
        f"(>= {GUESSABLE_BITS}): not practically guessable",
        est_bits=bits,
        sample_fingerprints=fps,
    )


def _common_prefix(strings: List[str]) -> str:
    if not strings:
        return ""
    s1, s2 = min(strings), max(strings)
    i = 0
    while i < len(s1) and i < len(s2) and s1[i] == s2[i]:
        i += 1
    return s1[:i]


def _common_suffix(strings: List[str]) -> str:
    return _common_prefix([s[::-1] for s in strings])[::-1]


def _alphabet_size(cores: List[str]) -> int:
    chars = set("".join(cores))
    if chars <= set("0123456789"):
        return 10
    if chars <= set("0123456789abcdefABCDEF"):
        return 16
    if all(c.isalnum() for c in chars):
        return 62
    return 94


def _sequential_guesses(known_id: str, count: int = 4) -> List[str]:
    """Candidate neighbour ids around ``known_id`` if its tail is an integer."""
    m = re.search(r"(\d+)(\D*)$", known_id)
    if not m:
        return []
    num, tail = int(m.group(1)), m.group(2)
    head = known_id[: m.start(1)]
    guesses: List[str] = []
    for delta in range(1, count + 1):
        for cand in (num - delta, num + delta):
            if cand >= 0:
                guesses.append(f"{head}{cand}{tail}")
    return guesses


# ------------------------------------------------------------- task primitives


class _Inconclusive(Exception):
    pass


def _is_task_result(result: Any) -> bool:
    return (
        isinstance(result, dict)
        and result.get("resultType") == "task"
        and isinstance(result.get("taskId"), str)
        and bool(result["taskId"])
    )


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


def _wait_status(client: MCPClient, task_id: str, want: str, timeout: float) -> Dict[str, Any]:
    return _wait_for(
        client, task_id, lambda t: t.get("status") == want, f"reached {want!r}", timeout
    )


def _snapshot(task: Dict[str, Any], keys: tuple = _CHANGE_KEYS) -> str:
    import json

    return json.dumps({k: task.get(k) for k in keys}, sort_keys=True, default=str)


def _is_leak_change(method: str, before: Dict[str, Any], now: Dict[str, Any]) -> bool:
    if method == "cancel":
        return now.get("status") == "cancelled"
    return now.get("status") != "input_required" or _snapshot(
        before, ("inputRequests",)
    ) != _snapshot(now, ("inputRequests",))


def _outcome(call: Callable[[], Any]) -> Dict[str, Any]:
    try:
        return {"ok": call()}
    except JSONRPCError as exc:
        return {"error": (exc.code, exc.message)}
    except Exception as exc:
        return {"failed": str(exc)}


def _own_control(method: str, client: MCPClient, plan: TaskPlan, timeout: float) -> Optional[str]:
    """B drives its OWN task through ``method``; return None or why it failed."""
    kind, expected = _KINDS[method]
    try:
        created = _start(client, plan, new_marker(), kind)
        task_id = created["taskId"]
        seen = _wait_status(client, task_id, expected, timeout)
        if method == "update":
            _rpc(client, "tasks/update",
                 {"taskId": task_id, "inputResponses": plan.input_responses(seen)})
            _wait_for(client, task_id, lambda t: t.get("status") != "input_required",
                      "left 'input_required' after B's own update", timeout)
        else:
            _rpc(client, "tasks/cancel", {"taskId": task_id})
            _wait_status(client, task_id, "cancelled", timeout)
    except Exception as exc:
        return f"B's own tasks/{method} control failed: {exc}"
    return None


# ------------------------------------------------------------------- the probe


def _principal_of(client) -> Optional[str]:
    """Ask the server who it thinks the caller is, via a ``whoami`` tool, so the
    probe can confirm A and B are DISTINCT principals before calling a reach a
    cross-user LEAK. Returns None when there is no such signal (then a reach is
    graded OBSERVATION, not LEAK — it can't be told from an identity-collapse /
    shared-session design)."""
    try:
        res = client.call_tool("whoami", {})
    except Exception:
        return None
    if not isinstance(res, dict) or res.get("isError"):
        return None
    sc = res.get("structuredContent")
    if isinstance(sc, dict) and isinstance(sc.get("principal"), str):
        return sc["principal"]
    content = res.get("content")
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                return part["text"]
    return None


def run_tasks_idor_probe(
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
) -> TasksIdorReport:
    """A starts tasks; B (as B) tries get/update/cancel on A's ids and tests
    whether A's ids are guessable/enumerable."""
    decision = authorize(target, authorized=authorized, authorization_note=authorization_note)
    plan = plan or TaskPlan()

    def report(grade, detail, **kw) -> TasksIdorReport:
        return TasksIdorReport(
            target=decision.target,
            authorization=decision.reason,
            identity_a=identity_a.label,
            identity_b=identity_b.label,
            grade=grade,
            detail=detail,
            **kw,
        )

    client_a = identity_a.connect()
    client_b: Optional[MCPClient] = None
    controls: Dict[str, ControlResult] = {}
    observations: List[str] = []
    principal_a: Optional[str] = None
    principal_b: Optional[str] = None
    try:
        try:
            client_a.initialize()
            client_b = identity_b.connect()
            client_b.initialize()

            # Distinctness: a reach of A's task is a cross-user LEAK only if A and
            # B are genuinely different principals. A server that collapses them
            # (shared session/credential) reaches here without a real access gain.
            principal_a = _principal_of(client_a)
            principal_b = _principal_of(client_b)

            # --- A starts one task per attacked method. ---
            tasks: Dict[str, Dict[str, Any]] = {}
            markers: Dict[str, str] = {}
            minted_ids: List[str] = []
            for method, (kind, expected) in _KINDS.items():
                markers[method] = new_marker()
                created = _start(client_a, plan, markers[method], kind)
                task_id = created["taskId"]
                minted_ids.append(task_id)
                seen = _wait_status(client_a, task_id, expected, ready_timeout)
                tasks[method] = {"id": task_id, "seen": seen}

            # --- Positive control: A reads its OWN completed task + marker. ---
            own = tasks["get"]
            if _contains_exact(own["seen"], markers["get"]):
                controls["own_read"] = ControlResult(
                    "own_read", True, "A read its own completed task and saw its marker"
                )
            else:
                controls["own_read"] = ControlResult(
                    "own_read", False,
                    "A could not read its own task result (broken observer)",
                )
                raise _Inconclusive(
                    "positive control failed: A's completed task did not return "
                    "A's marker through tasks/get"
                )

            # Extra A-minted samples, so entropy/sequence is judged on >2 ids.
            for _ in range(2):
                created = _start(client_a, plan, new_marker(), "complete")
                minted_ids.append(created["taskId"])

            # --- B's own controls: B can start+read, update and cancel its own. ---
            b_marker = new_marker()
            b_created = _start(client_b, plan, b_marker, "complete")
            b_ids = {b_created["taskId"]}
            b_seen = _wait_status(client_b, b_created["taskId"], "completed", ready_timeout)
            if not _contains_exact(b_seen, b_marker):
                controls["b_own_read"] = ControlResult(
                    "b_own_read", False, "B could not read its own task result"
                )
                raise _Inconclusive(
                    "positive control failed: B could not read its own task result"
                )
            controls["b_own_read"] = ControlResult(
                "b_own_read", True, "B read its own task"
            )

            control_failed: Dict[str, str] = {}
            for method in ("update", "cancel"):
                why = _own_control(method, client_b, plan, ready_timeout)
                if why is None:
                    controls[f"b_own_{method}"] = ControlResult(
                        f"b_own_{method}", True, f"B drove its own tasks/{method}"
                    )
                else:
                    control_failed[method] = why
                    controls[f"b_own_{method}"] = ControlResult(
                        f"b_own_{method}", False, why
                    )

            # --- Negative control: a forged, never-minted id must be refused. ---
            forged = "task-forged-" + secrets.token_hex(16)
            fout = _outcome(lambda: _rpc(client_b, "tasks/get", {"taskId": forged}))
            if "error" in fout:
                controls["forged_refused"] = ControlResult(
                    "forged_refused", True, f"a forged taskId was refused ({fout['error'][0]})"
                )
            elif "ok" in fout and isinstance(fout["ok"], dict) and (
                _contains_exact(fout["ok"], forged) is False
                and fout["ok"].get("status") in TASK_STATUSES
            ):
                controls["forged_refused"] = ControlResult(
                    "forged_refused", False,
                    "the server answered a forged, never-minted taskId with a task "
                    "(cannot trust its refusals)",
                )
            elif "failed" in fout:
                raise _Inconclusive(f"transport failure on the forged-id control: {fout['failed']}")
            else:
                controls["forged_refused"] = ControlResult(
                    "forged_refused", False,
                    "the server did not refuse a forged, never-minted taskId",
                )
        except _Inconclusive as exc:
            return report(INCONCLUSIVE, str(exc), controls=controls, observations=observations)
        except Exception as exc:
            return report(INCONCLUSIVE, f"could not set up the probe: {exc}",
                          controls=controls, observations=observations)

        methods: Dict[str, MethodResult] = {}
        foreign: Dict[str, Dict[str, Any]] = {}

        # --- Attack 1: tasks/get with A's completed task id. ---
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

        # --- Attacks 2 and 3: B mutates A's task; A re-reads. ---
        for method in ("update", "cancel"):
            t_id = tasks[method]["id"]
            if method in control_failed:
                methods[method] = MethodResult(method, INCONCLUSIVE, control_failed[method])
                continue
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
                    method, INCONCLUSIVE,
                    f"A's task is unstable: it changed within {drift_window}s with "
                    f"nobody acting, so a change after B's attempt is unattributable",
                )
                continue
            before = second
            if method == "update":
                params = {"taskId": t_id, "inputResponses": plan.input_responses(before)}
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
                other = [k for k in _DRIFT_KEYS
                         if _snapshot(before, (k,)) != _snapshot(last_now, (k,))]
                if other:
                    observations.append(
                        f"after B's tasks/{method}, A's task changed in "
                        f"{', '.join(other)} (not counted as a leak: {_LEAK_RULE[method]})"
                    )
            if leaked_now is not None:
                methods[method] = MethodResult(
                    method, LEAK,
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
                    f"B's tasks/{method} on A's task was acknowledged (no error) but "
                    f"no leak-relevant change to A's task was visible within "
                    f"{settle_timeout}s"
                )
                methods[method] = MethodResult(
                    method, INCONCLUSIVE,
                    f"B's tasks/{method} was acknowledged but no leak-relevant change "
                    f"to A's task was observed within {settle_timeout}s",
                )

        # --- Entropy / enumerability assessment on the sampled ids. ---
        entropy = assess_entropy(minted_ids)

        # Active enumeration: if ids are numerically sequential, B GUESSES a
        # neighbouring id it was never given and tries to read it. A stranger's
        # task reached this way is a confirmed enumeration leak.
        if entropy.sequential:
            reached: List[str] = []
            for guess in _sequential_guesses(g_id):
                if guess in b_ids:
                    continue  # never count B's own task as a stranger read
                gout = _outcome(lambda: _rpc(client_b, "tasks/get", {"taskId": guess}))
                if "ok" in gout and isinstance(gout["ok"], dict) and (
                    gout["ok"].get("status") in TASK_STATUSES
                    or any(_contains_exact(gout["ok"], mk) for mk in markers.values())
                ):
                    reached.append(token_fingerprint(guess) or "sha256:?")
            if reached:
                entropy.enumerated = True
                entropy.detail += (
                    "; B reached a stranger's task via a GUESSED id "
                    "(confirmed enumeration)"
                )
                methods["enumerate"] = MethodResult(
                    "enumerate", LEAK,
                    f"B read a task it was never given by guessing a sequential id "
                    f"({len(reached)} guessed id(s) reached a stranger's task)",
                )
                observations.append(
                    "task ids are enumerable: a guessed id reached another "
                    f"identity's task (fingerprints: {', '.join(reached)})"
                )
    finally:
        _safe_close(client_a)
        if client_b is not None:
            _safe_close(client_b)

    # --- Overall grade. ---
    method_grades = {r.grade for r in methods.values()}
    controls_ok = all(c.passed for c in controls.values())

    distinct = (
        principal_a is not None and principal_b is not None and principal_a != principal_b
    )
    if LEAK in method_grades and not distinct:
        # B reached A's task, but A and B are not provably distinct principals
        # (identity collapse / shared session, or no principal signal). Not a
        # confirmed cross-user access gain — grade OBSERVATION, not LEAK.
        reached = ", ".join(
            f"{m} ({r.detail})" for m, r in methods.items() if r.grade == LEAK
        )
        if principal_a is not None and principal_b is not None:
            cause = ("the server maps A and B to one principal (identity collapse / "
                     "shared session or credential)")
        else:
            cause = ("A and B could not be shown to be distinct principals (no "
                     "principal signal); verify they are different users")
        overall = OBSERVATION
        detail = f"B reached A's task ({reached}), but {cause}: not a cross-user access gain"
        observations.append(detail)
    elif LEAK in method_grades:
        overall = LEAK
        detail = "B reached A's task: " + ", ".join(
            f"{m} ({r.detail})" for m, r in methods.items() if r.grade == LEAK
        )
    elif INCONCLUSIVE in method_grades or not controls_ok:
        overall = INCONCLUSIVE
        bad = [f"{m}: {r.detail}" for m, r in methods.items() if r.grade == INCONCLUSIVE]
        bad += [f"control {c.name}: {c.detail}" for c in controls.values() if not c.passed]
        detail = "; ".join(bad) or "could not reach a verdict"
    elif entropy.grade == OBSERVATION:
        overall = OBSERVATION
        detail = (
            "every cross-identity task op was refused and A's tasks were "
            f"unchanged, but the task ids are guessable: {entropy.detail}"
        )
    elif entropy.grade == INCONCLUSIVE:
        overall = INCONCLUSIVE
        detail = f"cross-identity ops refused, but entropy inconclusive: {entropy.detail}"
    else:
        overall = OK
        detail = (
            "B was refused on get, update and cancel, A's tasks were unchanged, "
            "and the task ids are high-entropy"
        )

    return report(
        overall,
        detail,
        methods=methods,
        entropy=entropy,
        controls=controls,
        observations=observations,
    )


def _safe_close(client: MCPClient) -> None:
    try:
        client.close()
    except Exception:
        pass
