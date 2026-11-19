"""The state-handle hijacking probe (the flagship cross-user replay).

In the stateless MCP model (2026-07-28), a server often hands a caller a **state
handle** — an opaque id returned from one call that the caller passes back on
later calls to reach the state that call created (an opened document, a staged
transaction, a cursor, an upload slot...). The spec is explicit: a server MUST
NOT treat *possession* of a state handle as authentication, and MUST bind each
handle to the authenticated user, so that only that user can act through it.

This probe tests that binding directly. It drives the target with **two
identities, A and B, each with its own token**:

1. **A mints a handle.** A calls the ``open`` tool with a unique marker; the
   server returns a server-minted handle that references A's freshly created
   state (which holds A's marker).
2. **B replays A's handle.** B, authenticated as B, calls the ``read`` tool
   passing *A's* handle and sees whether it reaches A's state.

Grades (three only; never ``OK`` for something not observed):

* ``LEAK`` — B reached A's state through A's handle (B received A's marker). The
  server treated possession of the handle as authentication.
* ``OK`` — B was refused: the server verified the *user*, not the handle.
* ``INCONCLUSIVE`` — the leak could not be observed (no handle was issued, a
  control failed, a transport error, an unrecognised reply, ...).

False-pass controls, enforced in grading (``OK`` is withheld unless *all* hold):

* **A's own read (positive control).** A reading A's own handle must return A's
  marker, or the observer is blind and nothing can be graded.
* **B's own handle must succeed.** B opens its own state and reads it back with
  its own handle; if that fails, a happy path does not work here and B's refusal
  on A's handle proves nothing — so ``OK`` would be vacuous.
* **A forged handle must be refused.** B presents a made-up handle; if the server
  does not refuse it, refusal is not evidence of user-binding.
* **A broken fixture must be caught in the same run** (the ``canary``). A
  known-leaky reference server, driven by the *same* replay logic, must be
  detected as a leak; if the detector cannot even catch a server that is wide
  open, a refusal from the target is not trustworthy. ``OK`` is never returned
  without a canary that fired.

Only handle/token *fingerprints* (``sha256:``) are ever recorded.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .guard import authorize
from .mcp_client import JSONRPCError, MCPClient
from .probe import Identity, new_marker, _tool_error_text
from .transports import HTTPTransport

__all__ = [
    "LEAK",
    "OBSERVATION",
    "OK",
    "INCONCLUSIVE",
    "StateHandlePlan",
    "StateHandleReport",
    "statehandle_identity",
    "statehandle_canary",
    "run_statehandle_probe",
]

LEAK = "LEAK"
OBSERVATION = "OBSERVATION"
OK = "OK"
INCONCLUSIVE = "INCONCLUSIVE"

FAILURE_CLASS = (
    "state-handle hijacking: possession of another identity's state handle "
    "reached that identity's state (handle treated as authentication)"
)


def _fp(value: Optional[str]) -> Optional[str]:
    """``sha256:<12 hex>`` for a handle/token; never the raw value."""
    if value is None:
        return None
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:12]


def _contains_exact(obj: Any, marker: str) -> bool:
    """True if any string leaf of ``obj`` equals ``marker`` exactly.

    Exact-leaf (not substring) so a marker echoed inside a larger error string
    is not mistaken for the planted state being returned.
    """
    if isinstance(obj, str):
        return obj == marker
    if isinstance(obj, dict):
        return any(_contains_exact(v, marker) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_exact(v, marker) for v in obj)
    return False


def _default_extract_handle(result: Any) -> Optional[str]:
    """Pull a server-minted handle out of an ``open`` tool result.

    Reads ``structuredContent.handle`` (the 2026 structured-output field), or a
    top-level ``handle`` key. Returns ``None`` when no handle is present, which
    the probe grades INCONCLUSIVE rather than guessing. It deliberately does NOT
    treat an arbitrary acknowledgement text as a handle: a server with no
    state-handle feature typically returns a plain ack, and mistaking that for a
    handle would turn "no feature" into a confusing control failure. A server
    that returns its handle in some other shape is given a custom
    :attr:`StateHandlePlan.extract_handle`.
    """
    if not isinstance(result, dict):
        return None
    sc = result.get("structuredContent")
    if isinstance(sc, dict) and isinstance(sc.get("handle"), str) and sc["handle"]:
        return sc["handle"]
    if isinstance(result.get("handle"), str) and result["handle"]:
        return result["handle"]
    return None


@dataclass
class StateHandlePlan:
    """How to mint a handle and how to read state back through it.

    The engine stays independent of a particular server's tool names.
    ``open_arguments(marker)`` builds the arguments for the call that mints the
    handle (and stores ``marker`` in the created state); ``read_arguments(handle)``
    builds the arguments for the call that reads state back through a handle.
    ``extract_handle(result)`` pulls the minted handle id out of the open result;
    ``detect_marker(marker, result)`` is True when a read result carries the
    marker (so the state behind the handle was reached). ``forged_handle()``
    mints a handle-shaped value that was never issued by the server.
    """

    open_tool: str = "open_state"
    read_tool: str = "read_state"
    open_arguments: Callable[[str], Dict[str, Any]] = lambda marker: {"marker": marker}
    read_arguments: Callable[[str], Dict[str, Any]] = lambda handle: {"handle": handle}
    extract_handle: Callable[[Any], Optional[str]] = _default_extract_handle
    detect_marker: Callable[[str, Any], bool] = lambda marker, result: _contains_exact(
        result, marker
    )
    forged_handle: Callable[[], str] = lambda: "sh-forged-" + secrets.token_hex(16)
    # Observe the principal the server thinks a caller is, as an opaque string, so
    # the probe can check A and B are DISTINCT principals before calling a handle
    # replay a cross-user LEAK. Returns None when the server exposes no such signal
    # (then the reach is graded OBSERVATION, not LEAK — it cannot be told apart
    # from an identity-collapse / shared-session design). Default: a ``whoami`` tool.
    principal_of: Callable[["MCPClient"], Optional[str]] = None  # type: ignore[assignment]


@dataclass
class StateHandleReport:
    target: str
    authorization: str
    identity_a: str
    identity_b: str
    grade: str
    detail: str
    controls: Dict[str, str] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)

    @property
    def leaked(self) -> bool:
        return self.grade == LEAK

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "probe": "statehandle",
            "target": self.target,
            "authorization": self.authorization,
            "identity_a": self.identity_a,
            "identity_b": self.identity_b,
            "grade": self.grade,
            "detail": self.detail,
            "controls": dict(self.controls),
            "observations": list(self.observations),
        }
        if self.leaked:
            data["failure_class"] = FAILURE_CLASS
        return data

    def summary(self) -> str:
        if self.grade == LEAK:
            return (
                f"LEAK: identity {self.identity_b!r} reached identity "
                f"{self.identity_a!r}'s state by replaying A's state handle "
                f"- {FAILURE_CLASS}."
            )
        if self.grade == OBSERVATION:
            return f"OBSERVATION: {self.detail}"
        if self.grade == OK:
            return (
                f"OK: identity {self.identity_b!r} was refused when replaying "
                f"identity {self.identity_a!r}'s state handle; the server verified "
                f"the user, not the handle."
            )
        return f"INCONCLUSIVE: {self.detail}"


class _Inconclusive(Exception):
    pass


def statehandle_identity(url: str, token: str, label: str) -> Identity:
    """An Identity that talks to ``url`` carrying ``Bearer <token>``.

    Two identities must carry different tokens for the probe to mean anything.
    """
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {token}"})
        ),
    )


def _read_outcome(client: MCPClient, plan: StateHandlePlan, handle: str) -> Dict[str, Any]:
    """Read state through ``handle`` and classify the reply.

    Returns exactly one of:
    ``{"ok": result}``        a non-error tool result,
    ``{"refused": (where, msg)}`` a refusal (JSON-RPC error or tool ``isError``),
    ``{"failed": msg}``       a transport failure (not a server answer).
    """
    try:
        result = client.call_tool(plan.read_tool, plan.read_arguments(handle))
    except JSONRPCError as exc:
        return {"refused": ("jsonrpc", f"[{exc.code}] {exc.message}")}
    except Exception as exc:  # transport trouble: not a server decision
        return {"failed": str(exc)}
    tool_error = _tool_error_text(result)
    if tool_error is not None:
        return {"refused": ("tool", tool_error)}
    return {"ok": result}


def _open_handle(client: MCPClient, plan: StateHandlePlan, marker: str) -> str:
    """Mint a handle as this client; raise ``_Inconclusive`` if none is issued."""
    try:
        opened = client.call_tool(plan.open_tool, plan.open_arguments(marker))
    except Exception as exc:
        raise _Inconclusive(f"the {plan.open_tool!r} call failed: {exc}")
    tool_error = _tool_error_text(opened)
    if tool_error is not None:
        raise _Inconclusive(f"the {plan.open_tool!r} call reported an error: {tool_error}")
    handle = plan.extract_handle(opened)
    if not handle:
        raise _Inconclusive(
            f"the {plan.open_tool!r} call returned no state handle: this target "
            f"has no state-handle feature to attack (or the plan is wrong)"
        )
    return handle


def statehandle_canary(
    identity_a: Identity,
    identity_b: Identity,
    plan: Optional[StateHandlePlan] = None,
) -> bool:
    """Run the raw replay attack against a KNOWN-LEAKY fixture.

    Returns True iff the detector caught the leak: ``identity_b`` read
    ``identity_a``'s marker by replaying A's handle. This is the broken-fixture
    self-check that gates ``OK`` in :func:`run_statehandle_probe` — if even a
    wide-open server is not caught, a refusal from the real target is not
    trustworthy. Any error returns False (the canary did not fire).
    """
    plan = plan or StateHandlePlan()
    marker = new_marker()
    client_a = identity_a.connect()
    client_b: Optional[MCPClient] = None
    try:
        client_a.initialize()
        handle_a = _open_handle(client_a, plan, marker)
        client_b = identity_b.connect()
        client_b.initialize()
        out = _read_outcome(client_b, plan, handle_a)
        return "ok" in out and bool(plan.detect_marker(marker, out["ok"]))
    except Exception:
        return False
    finally:
        _safe_close(client_a)
        if client_b is not None:
            _safe_close(client_b)


def _default_principal(client: "MCPClient") -> Optional[str]:
    """Ask the server who it thinks the caller is, via a ``whoami`` tool.

    Returns the reported principal as a string, or None if the server has no such
    tool / did not answer (distinctness then can't be observed)."""
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


def run_statehandle_probe(
    target: str,
    identity_a: Identity,
    identity_b: Identity,
    *,
    plan: Optional[StateHandlePlan] = None,
    canary: Optional[Callable[[], bool]] = None,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> StateHandleReport:
    """A mints a state handle; B, given A's handle, tries to reach A's state.

    ``canary`` is a zero-argument callable that runs the detector against a
    known-leaky fixture and returns True iff it caught the leak (see
    :func:`statehandle_canary`). ``OK`` is returned only when the canary fired
    in the same run; without a canary the probe cannot prove it can detect the
    leak, so a refusal grades INCONCLUSIVE, never OK.

    The target is authorized first (see :mod:`strangertest.guard`).
    """
    decision = authorize(
        target, authorized=authorized, authorization_note=authorization_note
    )
    plan = plan or StateHandlePlan()

    def report(grade: str, detail: str, controls=None, observations=None) -> StateHandleReport:
        return StateHandleReport(
            target=decision.target,
            authorization=decision.reason,
            identity_a=identity_a.label,
            identity_b=identity_b.label,
            grade=grade,
            detail=detail,
            controls=controls or {},
            observations=observations or [],
        )

    marker_a = new_marker()
    marker_b = new_marker()
    controls: Dict[str, str] = {}
    observations: List[str] = []

    client_a = identity_a.connect()
    client_b: Optional[MCPClient] = None
    principal_a: Optional[str] = None
    principal_b: Optional[str] = None
    try:
        try:
            client_a.initialize()
            handle_a = _open_handle(client_a, plan, marker_a)
            controls["handle_a"] = _fp(handle_a)

            # Positive control: A must be able to read its OWN state back.
            own_a = _read_outcome(client_a, plan, handle_a)
            if "ok" not in own_a or not plan.detect_marker(marker_a, own_a["ok"]):
                raise _Inconclusive(
                    "positive control failed: A could not read its own state back "
                    "through its own handle, so the observer is blind"
                )
            controls["a_own_read"] = "passed"

            client_b = identity_b.connect()
            client_b.initialize()
            handle_b = _open_handle(client_b, plan, marker_b)
            controls["handle_b"] = _fp(handle_b)

            # Distinctness: are A and B DISTINCT principals from the server's view?
            # A handle replay that reaches another caller's state is only a
            # cross-user LEAK when the two are genuinely different principals; if
            # the server collapses them (shared session / shared credential) the
            # reach grants no authority beyond a shared identity.
            principal_fn = plan.principal_of or _default_principal
            principal_a = principal_fn(client_a)
            principal_b = principal_fn(client_b)
            if principal_a is None or principal_b is None:
                controls["identities"] = "UNVERIFIED: the server exposes no principal signal"
            elif principal_a == principal_b:
                controls["identities"] = "COLLAPSED: A and B resolve to one principal"
            else:
                controls["identities"] = "distinct"
        except _Inconclusive as exc:
            return report(INCONCLUSIVE, str(exc), controls, observations)
        except Exception as exc:
            return report(INCONCLUSIVE, f"could not set up the probe: {exc}", controls)

        # Control: B using its OWN handle must succeed (proves the happy path).
        own_b = _read_outcome(client_b, plan, handle_b)
        b_own_ok = "ok" in own_b and bool(plan.detect_marker(marker_b, own_b["ok"]))
        controls["b_own_read"] = (
            "passed"
            if b_own_ok
            else f"FAILED: B could not read its own state ({_describe(own_b)})"
        )

        # Control: a forged handle must be refused (refusal is not universal).
        forged = _read_outcome(client_b, plan, plan.forged_handle())
        forged_refused = "refused" in forged
        controls["forged_handle"] = (
            "refused"
            if forged_refused
            else f"FAILED: a forged handle was not refused ({_describe(forged)})"
        )

        # The attack: B replays A's handle.
        attack = _read_outcome(client_b, plan, handle_a)
    finally:
        _safe_close(client_a)
        if client_b is not None:
            _safe_close(client_b)

    # --- grade ---
    if "ok" in attack and plan.detect_marker(marker_a, attack["ok"]):
        # B reached A's state. Only a cross-user LEAK if A and B are distinct
        # principals; a collapsed/unverifiable identity is an OBSERVATION, not a
        # confirmed cross-user access gain (rules out the shared-session / shared-
        # credential false positive seen on identity-collapsing gateways).
        distinct = principal_a is not None and principal_b is not None and principal_a != principal_b
        if distinct:
            return report(
                LEAK,
                f"identity {identity_b.label!r} replayed identity {identity_a.label!r}'s "
                f"state handle and received A's marker: the handle was treated as "
                f"authentication (A and B are distinct principals)",
                controls,
                observations,
            )
        if principal_a is not None and principal_b is not None and principal_a == principal_b:
            observations.append(
                "the server resolves A and B to the SAME principal (identity "
                "collapse / shared session or credential), so reaching A's state "
                "grants B nothing beyond a shared identity"
            )
            return report(
                OBSERVATION,
                f"identity {identity_b.label!r} reached identity {identity_a.label!r}'s "
                f"state, but the server maps both to one principal: this is identity "
                f"collapse, not a cross-user access gain",
                controls,
                observations,
            )
        observations.append(
            "could not confirm A and B are distinct principals (no principal "
            "signal); if this is a shared-session / shared-credential design the "
            "reach is not a cross-user access gain"
        )
        return report(
            OBSERVATION,
            f"identity {identity_b.label!r} reached identity {identity_a.label!r}'s "
            f"state by replaying A's handle, but A and B could not be shown to be "
            f"distinct principals: verify they are different users before treating "
            f"this as a cross-user leak",
            controls,
            observations,
        )
    if "failed" in attack:
        return report(
            INCONCLUSIVE,
            f"B's replay of A's handle hit a transport failure: {attack['failed']}",
            controls,
            observations,
        )
    if "ok" in attack:
        # A non-error reply that does not carry A's marker: not observed as a
        # leak, and not a refusal either, so it cannot be graded OK.
        observations.append(
            "B's replay of A's handle returned a non-error reply that did not "
            "carry A's marker; neither a confirmed leak nor a refusal"
        )
        return report(
            INCONCLUSIVE,
            "B's replay of A's handle got an unrecognised success reply "
            "(no marker, no refusal); not reported as OK",
            controls,
            observations,
        )

    # B was refused. OK only when every control behaved AND the canary fired.
    if not b_own_ok:
        return report(
            INCONCLUSIVE,
            "B was refused on A's handle, but B's own-handle control failed, so "
            "the refusal proves nothing (a happy path does not work here)",
            controls,
            observations,
        )
    if not forged_refused:
        return report(
            INCONCLUSIVE,
            "B was refused on A's handle, but a forged handle was NOT refused, so "
            "refusal is not evidence of user-binding",
            controls,
            observations,
        )
    if canary is None:
        return report(
            INCONCLUSIVE,
            "B was refused on A's handle and the controls behaved, but no "
            "broken-fixture self-check (canary) was supplied, so the probe cannot "
            "prove it can detect this leak; not reported as OK",
            controls,
            observations,
        )
    try:
        canary_fired = bool(canary())
    except Exception as exc:  # a broken canary must not silently pass as OK
        return report(
            INCONCLUSIVE,
            f"the broken-fixture self-check (canary) raised {exc!r}; cannot confirm "
            f"the probe detects the leak, so not reported as OK",
            controls,
            observations,
        )
    controls["canary"] = "fired (known leak detected)" if canary_fired else "DID NOT fire"
    if not canary_fired:
        return report(
            INCONCLUSIVE,
            "B was refused on A's handle, but the broken-fixture self-check did "
            "NOT detect a known leak, so the detector is unreliable here; not "
            "reported as OK",
            controls,
            observations,
        )
    return report(
        OK,
        f"identity {identity_b.label!r} was refused when replaying identity "
        f"{identity_a.label!r}'s handle; B's own handle worked, a forged handle "
        f"was refused, and a known-leaky fixture was caught in the same run",
        controls,
        observations,
    )


def _describe(outcome: Dict[str, Any]) -> str:
    if "refused" in outcome:
        where, msg = outcome["refused"]
        return f"{where} refusal: {msg}"
    if "failed" in outcome:
        return f"transport failure: {outcome['failed']}"
    return "non-error reply without the expected marker"


def _safe_close(client: MCPClient) -> None:
    try:
        client.close()
    except Exception:
        pass
