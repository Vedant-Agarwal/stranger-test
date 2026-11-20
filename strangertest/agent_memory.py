"""Cross-user agent-memory isolation probe.

An agent server that serves many users keeps memory for them: saved
conversation state (threads) and long-term memory (a key-value Store). This
probe asks one question: **can user B read what user A stored?**

It speaks the LangGraph Server HTTP API (threads, runs, Store) with the standard
library only. In that framework, access to threads and Store items is authorized
only if the application adds its own handlers, so a LEAK here is normally an
application misconfiguration, not a framework defect.

Steps:

1. **Auth posture.** Call with no token and with a made-up token. If either is
   accepted, every caller is one principal: OBSERVATION, never LEAK.
2. **A plants** a unique marker in a thread's metadata, in the Store, and (when
   the operator supplies ``save_input``) through the agent itself.
3. **Positive control per path.** A reads the marker back through each path. A
   path A cannot read herself is *not exercised*: it can never count as OK.
4. **B reads** every path with A's identifiers, and lists/searches without them.

Grades: ``LEAK`` (B obtained A's marker on a path whose control held, and auth
is enforced), ``OK`` (no path leaked and at least one was exercised),
``INCONCLUSIVE`` (nothing could be exercised or the server was unreachable),
``OBSERVATION`` (no authentication, the two callers map to one principal, or
only the existence of A's data is visible to B).

Tokens and markers appear in reports only as ``sha256:`` fingerprints.

Design record: amem-adr/471cead694a97fc9dc67746963f0f872 (path list and grading rules).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .guard import authorize

LEAK = "LEAK"
OBSERVATION = "OBSERVATION"
OK = "OK"
INCONCLUSIVE = "INCONCLUSIVE"

# Per-path outcomes.
P_LEAK = "LEAK"
P_OK = "OK"
P_NOT_EXERCISED = "NOT_EXERCISED"
P_NOT_RUN = "NOT_RUN"

__all__ = [
    "LEAK", "OBSERVATION", "OK", "INCONCLUSIVE",
    "AgentMemoryReport", "run_agent_memory_probe",
]


def _fp(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _fill(template: Any, marker: str) -> Any:
    """Copy ``template`` with every ``{marker}`` in a string replaced."""
    if isinstance(template, str):
        return template.replace("{marker}", marker)
    if isinstance(template, dict):
        return {k: _fill(v, marker) for k, v in template.items()}
    if isinstance(template, list):
        return [_fill(v, marker) for v in template]
    return template


@dataclass
class _Response:
    status: int            # 0 = no HTTP answer at all
    body: str
    error: Optional[str] = None

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except ValueError:
            return None


class _Caller:
    """One identity's HTTP access to the agent server."""

    def __init__(self, base: str, token: Optional[str], timeout: float):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout

    def call(self, method: str, path: str, body: Any = None) -> _Response:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token is not None:
            headers["Authorization"] = f"Bearer {self.token}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return _Response(response.status, response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            return _Response(exc.code, exc.read().decode("utf-8", "replace"))
        except Exception as exc:  # connection refused, timeout, bad URL
            return _Response(0, "", f"{type(exc).__name__}: {exc}")


@dataclass
class AgentMemoryReport:
    target: str
    grade: str
    detail: str
    paths: List[Dict[str, Any]] = field(default_factory=list)
    controls: Dict[str, Any] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)
    fingerprints: Dict[str, Any] = field(default_factory=dict)
    # Flags the operator left out that would turn NOT_RUN paths on. Text output
    # only: this is deliberately not part of to_dict().
    missing_inputs: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def leaked(self) -> bool:
        return self.grade == LEAK

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probe": "agent-memory",
            "target": self.target,
            "grade": self.grade,
            "detail": self.detail,
            "paths": self.paths,
            "controls": self.controls,
            "observations": self.observations,
            "fingerprints": self.fingerprints,
        }

    def summary(self) -> str:
        lines = [f"{self.grade}: {self.detail}"]
        for path in self.paths:
            note = f" ({path['note']})" if path.get("note") else ""
            lines.append(f"  {path['outcome']:<14} {path['name']}: {path['what']}{note}")
        for observation in self.observations:
            lines.append(f"  note: {observation}")
        return "\n".join(lines)

    def hint(self) -> str:
        """One closing line naming the flags that would run the NOT_RUN paths.

        Empty when no path was left out for want of an optional input.
        """
        parts = []
        agent = self.missing_inputs.get("agent")
        if agent:
            parts.append("to also test through the agent: " + ", ".join(agent))
        if self.missing_inputs.get("namespace_b"):
            parts.append("to also test the Store namespace boundary: --namespace-b "
                         "(with prefix-sibling ids)")
        if not parts:
            return ""
        return "hint: " + "; ".join(parts) + "; see docs/AGENT-MEMORY.md"


def run_agent_memory_probe(
    url: str,
    token_a: Optional[str],
    token_b: Optional[str],
    *,
    namespace_a: Optional[Sequence[str]] = None,
    namespace_b: Optional[Sequence[str]] = None,
    assistant_id: Optional[str] = None,
    save_input: Optional[Dict[str, Any]] = None,
    recall_input: Optional[Dict[str, Any]] = None,
    whoami_field: Optional[str] = None,
    timeout: float = 20.0,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> AgentMemoryReport:
    """Run the probe against the agent server at ``url`` (its base URL).

    ``namespace_a`` is a Store namespace user A is allowed to write to (an app
    that scopes the Store per user will refuse any other); when omitted a
    throwaway namespace is used. ``namespace_b`` is B's own namespace; when it
    is given and its dotted form is a *string* prefix of A's but not a
    segment-by-segment prefix (``ali`` vs ``alice.notes``), the probe also
    checks that B's own-namespace search does not return A's item. That is the
    shape of the namespace-boundary bugs fixed in LangGraph's SQLite/Postgres
    stores in 2026; it needs two accounts whose ids are prefix siblings.
    ``save_input`` / ``recall_input`` are run
    inputs for the operator's own agent, with ``{marker}`` replaced by the
    probe's marker; without them the through-the-agent paths are not run.
    ``whoami_field`` names a field of the run output that carries the caller's
    identity, if the app has one.
    """
    authorize(url, authorized=authorized, authorization_note=authorization_note)

    marker = "st-mem-" + secrets.token_hex(8)
    tag = "st-probe-" + secrets.token_hex(4)          # distinctive, carries no secret
    namespace = list(namespace_a) if namespace_a else [tag]
    if namespace_a:
        namespace = namespace + [tag]
    item_key = "st-item"
    fingerprints = {"token_a": _fp(token_a), "token_b": _fp(token_b), "marker": _fp(marker)}
    controls: Dict[str, Any] = {}
    observations: List[str] = []
    paths: List[Dict[str, Any]] = []

    missing_inputs: Dict[str, List[str]] = {}

    def report(grade: str, detail: str) -> AgentMemoryReport:
        # Only name a flag when a path it would enable was actually left NOT_RUN.
        not_run = {p["name"] for p in paths if p["outcome"] == P_NOT_RUN}
        relevant = {}
        if missing_inputs.get("agent") and not_run & {"thread_state", "thread_history", "agent_recall"}:
            relevant["agent"] = missing_inputs["agent"]
        if missing_inputs.get("namespace_b") and "store_search_own_prefix" in not_run:
            relevant["namespace_b"] = missing_inputs["namespace_b"]
        return AgentMemoryReport(url, grade, detail, paths, controls, observations, fingerprints,
                                 relevant)

    if token_a is None or token_b is None or token_a == token_b:
        return report(INCONCLUSIVE, "two different bearer tokens are needed (one per identity).")

    agent_flags = [flag for flag, given in (("--assistant", bool(assistant_id)),
                                            ("--save-input", save_input is not None),
                                            ("--recall-input", recall_input is not None))
                   if not given]
    if agent_flags:
        missing_inputs["agent"] = agent_flags
    if not namespace_b:
        missing_inputs["namespace_b"] = ["--namespace-b"]

    a = _Caller(url, token_a, timeout)
    b = _Caller(url, token_b, timeout)

    # -- 1. auth posture ----------------------------------------------------
    anonymous = _Caller(url, None, timeout).call("POST", "/threads/search", {"limit": 1})
    made_up = _Caller(url, "st-unknown-" + secrets.token_hex(8), timeout).call(
        "POST", "/threads/search", {"limit": 1})
    controls["no_token_status"] = anonymous.status
    controls["made_up_token_status"] = made_up.status
    if anonymous.status == 0 and made_up.status == 0:
        return report(INCONCLUSIVE, f"the server could not be reached ({anonymous.error}).")
    auth_enforced = anonymous.status in (401, 403) and made_up.status in (401, 403)
    controls["auth_enforced"] = auth_enforced

    # -- 2. A plants --------------------------------------------------------
    created = a.call("POST", "/threads", {"metadata": {"st_probe": tag, "st_marker": marker}})
    thread_a = (created.json() or {}).get("thread_id") if created.status == 200 else None
    controls["a_create_thread_status"] = created.status
    if not thread_a:
        return report(INCONCLUSIVE, f"identity A could not create a thread (HTTP {created.status}).")

    run_planted = False
    whoami: Dict[str, Optional[str]] = {"a": None, "b": None}
    if assistant_id and save_input is not None:
        saved = a.call("POST", f"/threads/{thread_a}/runs/wait",
                       {"assistant_id": assistant_id, "input": _fill(save_input, marker)})
        controls["a_agent_save_status"] = saved.status
        run_planted = saved.status == 200
        if whoami_field and isinstance(saved.json(), dict):
            whoami["a"] = saved.json().get(whoami_field)

    put = a.call("PUT", "/store/items",
                 {"namespace": namespace, "key": item_key, "value": {"text": marker}})
    controls["a_store_put_status"] = put.status
    dotted = ".".join(namespace)

    # -- 3 + 4. each path: A's control, then B ------------------------------
    def path(name: str, what: str, method: str, route: str, body: Any = None,
             *, enabled: bool = True, why_not: str = "") -> None:
        if not enabled:
            paths.append({"name": name, "what": what, "outcome": P_NOT_RUN, "note": why_not})
            return
        control = a.call(method, route, body)
        if marker not in control.body:
            paths.append({"name": name, "what": what, "outcome": P_NOT_EXERCISED,
                          "control_status": control.status,
                          "note": f"A could not read her own marker this way (HTTP {control.status})"})
            return
        attempt = b.call(method, route, body)
        seen = marker in attempt.body
        paths.append({"name": name, "what": what, "outcome": P_LEAK if seen else P_OK,
                      "control_status": control.status, "b_status": attempt.status,
                      "note": f"B got HTTP {attempt.status}"})

    path("thread_get", "B reads A's thread by id", "GET", f"/threads/{thread_a}")
    path("thread_state", "B reads A's saved conversation state", "GET", f"/threads/{thread_a}/state",
         enabled=run_planted, why_not="no save_input given, so nothing was saved through the agent")
    path("thread_history", "B reads A's conversation history", "GET", f"/threads/{thread_a}/history",
         enabled=run_planted, why_not="no save_input given, so nothing was saved through the agent")
    path("thread_search", "B lists threads and finds A's", "POST", "/threads/search", {"limit": 100})
    path("store_get", "B reads A's memory item by namespace and key", "GET",
         f"/store/items?namespace={dotted}&key={item_key}")
    path("store_search_namespace", "B searches A's memory namespace", "POST",
         "/store/items/search", {"namespace_prefix": namespace, "limit": 100})
    path("store_search_all", "B searches all memory with no namespace", "POST",
         "/store/items/search", {"namespace_prefix": [], "limit": 100})

    # B's OWN namespace search: with prefix-sibling ids, a store that matches
    # namespace prefixes as strings rather than segments returns A's item.
    own_name, own_what = "store_search_own_prefix", "B searches B's own namespace and gets A's item"
    if namespace_b:
        ns_b = list(namespace_b)
        dotted_b = ".".join(ns_b)
        is_string_prefix = dotted.startswith(dotted_b)
        is_segment_prefix = namespace[:len(ns_b)] == ns_b
        if is_string_prefix and not is_segment_prefix:
            b_put = b.call("PUT", "/store/items",
                           {"namespace": ns_b + [tag], "key": item_key, "value": {"text": "own-" + tag}})
            own_search = b.call("POST", "/store/items/search",
                                {"namespace_prefix": ns_b, "limit": 100})
            controls["b_store_put_status"] = b_put.status
            if ("own-" + tag) not in own_search.body:
                paths.append({"name": own_name, "what": own_what, "outcome": P_NOT_EXERCISED,
                              "control_status": own_search.status,
                              "note": f"B could not read B's own item this way (HTTP {own_search.status})"})
            else:
                seen = marker in own_search.body
                paths.append({"name": own_name, "what": own_what,
                              "outcome": P_LEAK if seen else P_OK, "b_status": own_search.status,
                              "note": f"namespaces are prefix siblings ({dotted_b!r} vs {dotted!r})"})
        else:
            paths.append({"name": own_name, "what": own_what, "outcome": P_NOT_RUN,
                          "note": "namespace_b is not a string-but-not-segment prefix of A's "
                                  "namespace; give prefix-sibling ids (e.g. ali / alice) to run this"})
    else:
        paths.append({"name": own_name, "what": own_what, "outcome": P_NOT_RUN,
                      "note": "needs namespace_b (B's own namespace) with a prefix-sibling id"})

    # Through the agent: B asks, in B's own thread, for what A saved.
    recall_name, recall_what = "agent_recall", "B asks the agent for A's memory"
    if assistant_id and recall_input is not None and run_planted:
        # Positive control: A, in a fresh thread of her own, must get the marker
        # back from the agent. Otherwise "B got nothing" would prove nothing.
        a_own = a.call("POST", "/threads", {"metadata": {"st_probe": tag}})
        a_thread2 = (a_own.json() or {}).get("thread_id") if a_own.status == 200 else None
        a_recall = (a.call("POST", f"/threads/{a_thread2}/runs/wait",
                           {"assistant_id": assistant_id, "input": _fill(recall_input, marker)})
                    if a_thread2 else _Response(a_own.status, ""))
        controls["a_agent_recall_sees_marker"] = marker in a_recall.body
        own = b.call("POST", "/threads", {"metadata": {"st_probe": tag}})
        thread_b = (own.json() or {}).get("thread_id") if own.status == 200 else None
        if marker in json.dumps(_fill(recall_input, marker)):
            paths.append({"name": recall_name, "what": recall_what,
                          "outcome": P_NOT_RUN, "note": "recall_input must not contain {marker}"})
        elif not controls["a_agent_recall_sees_marker"]:
            paths.append({"name": recall_name, "what": recall_what, "outcome": P_NOT_EXERCISED,
                          "control_status": a_recall.status,
                          "note": f"the agent did not return A's own marker to A (HTTP {a_recall.status})"})
        elif thread_b:
            recalled = b.call("POST", f"/threads/{thread_b}/runs/wait",
                              {"assistant_id": assistant_id, "input": _fill(recall_input, marker)})
            if whoami_field and isinstance(recalled.json(), dict):
                whoami["b"] = recalled.json().get(whoami_field)
            seen = marker in recalled.body
            paths.append({"name": recall_name, "what": recall_what,
                          "outcome": P_LEAK if seen else P_OK, "b_status": recalled.status,
                          "note": f"B got HTTP {recalled.status}"})
        else:
            paths.append({"name": recall_name, "what": recall_what, "outcome": P_NOT_EXERCISED,
                          "note": f"B could not create a thread (HTTP {own.status})"})
    else:
        paths.append({"name": recall_name, "what": recall_what,
                      "outcome": P_NOT_RUN, "note": "needs assistant_id, save_input and recall_input"})

    # Existence only: can B see that A's namespace exists?
    listing = b.call("POST", "/store/namespaces", {"limit": 100})
    listed = listing.json() if isinstance(listing.json(), dict) else {}
    listed_namespaces = [list(ns) for ns in (listed.get("namespaces") or []) if isinstance(ns, list)]
    namespace_visible = put.status in (200, 204) and list(namespace) in listed_namespaces
    controls["b_sees_a_namespace_name"] = namespace_visible

    controls["whoami_a"] = _fp(whoami["a"]) if whoami["a"] else None
    controls["whoami_b"] = _fp(whoami["b"]) if whoami["b"] else None

    # -- grade --------------------------------------------------------------
    leaked = [p["name"] for p in paths if p["outcome"] == P_LEAK]
    exercised = [p["name"] for p in paths if p["outcome"] in (P_LEAK, P_OK)]
    skipped = [p["name"] for p in paths if p["outcome"] == P_NOT_EXERCISED]
    if skipped:
        observations.append("not exercised (A could not read her own marker): " + ", ".join(skipped))

    if not auth_enforced:
        observations.append(
            f"a request with no token got HTTP {anonymous.status} and one with a made-up token got "
            f"HTTP {made_up.status}")
        return report(OBSERVATION,
                      "the server does not authenticate callers, so A and B are the same principal; "
                      "nothing here can be called a cross-user leak. Add authentication first.")

    same_principal = whoami["a"] is not None and whoami["a"] == whoami["b"]
    if leaked and same_principal:
        return report(OBSERVATION,
                      "B read A's marker, but the app reports the same identity for both tokens, "
                      "so this is one principal reading its own data.")
    if leaked:
        return report(LEAK,
                      f"identity B read identity A's memory on {len(leaked)} of {len(exercised)} "
                      f"paths: {', '.join(leaked)}.")
    if not exercised:
        return report(INCONCLUSIVE,
                      "no path could be exercised: A could not read her own marker back anywhere.")
    if namespace_visible:
        return report(OBSERVATION,
                      "B could not read A's memory, but B can see that A's memory namespace exists.")
    return report(OK, f"identity B could not read identity A's memory on any of the "
                      f"{len(exercised)} exercised paths.")
