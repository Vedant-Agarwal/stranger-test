"""Subscriptions/listen cross-user notification-delivery probe + grader.

At MCP 2026-07-28 (SEP-2575) a client opens one long-lived ``subscriptions/listen``
stream and the server pushes it server->client notifications as they happen:
``notifications/resources/updated`` for a subscribed URI,
``notifications/resources/list_changed``, ``notifications/tools/list_changed``,
the tasks-extension events, and so on. Delivery must be scoped to the authorized
caller. This probe asks the one question that matters for that scoping:

    identity B opens a listen stream; identity A changes a resource that only A
    is authorized to see; does B's stream receive A's notification?

If it does, one identity's server-pushed events reached another connection -- a
**cross-identity subscription/notification delivery leak**. This is distinct
from :mod:`strangertest.subscribe` (which asks only "did B hear A's update"):
here the positive controls are built into the probe, so the grade is one of
three and an unverifiable observation can never masquerade as "no leak".

The grade is existence-based (did A's event reach B's stream at all), matching
how these leaks present -- the content may or may not be included.

Grades
------
* ``LEAK``         -- B's stream received a notification scoped to A. (==FAIL)
* ``OK``           -- B's stream received only its own notifications; A's did
                      not cross. Reported only when the controls below held.
* ``INCONCLUSIVE`` -- the server has no listen stream, a stream would not open,
                      or the controls did not hold (nothing was observed), so
                      no claim can be made.

Controls (an OK is worthless without them; a failed control is INCONCLUSIVE,
never OK)
    * **A's own stream fires.** A opens its OWN listen stream on the same
      resource; after A acts, A's stream must receive A's notification. This
      proves notifications fire at all. A server that pushes nothing (the
      ``mute`` practice fixture) fails here and is graded INCONCLUSIVE before
      any OK can be reached.
    * **B's own stream is alive** (only when ``b_own_uri`` is given). B changes
      its own resource and must receive that on its own stream, proving B's
      stream is not simply dead -- so "B got only its own" is a real finding.

The resource A acts on is A's marker: it is reported only as a ``sha256:``
fingerprint, and the probe matches A's notification by exact method+URI, never
by scanning frames for a value. Fingerprints only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .delegate import token_fingerprint
from .guard import authorize
from .mcp_client import ListenNotSupportedError, ListenStream, MCPClient
from .probe import Identity, ProbeError

__all__ = [
    "LEAK",
    "OBSERVATION",
    "OK",
    "INCONCLUSIVE",
    "FAILURE_CLASS",
    "SubscriptionsLeakReport",
    "updated_matcher",
    "run_subscriptions_leak_probe",
]

LEAK = "LEAK"
OBSERVATION = "OBSERVATION"
OK = "OK"
INCONCLUSIVE = "INCONCLUSIVE"


def _principal_of(client: Any) -> Optional[str]:
    """Ask the server who it thinks the caller is, via a ``whoami`` tool, so a
    cross-stream delivery is graded LEAK only when A and B are DISTINCT
    principals. Returns None when no such signal exists (then the delivery is
    graded OBSERVATION, not LEAK — it can't be told from identity collapse)."""
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

FAILURE_CLASS = "cross-identity subscription/notification delivery leak"


def updated_matcher(uri: str) -> Callable[[Dict[str, Any]], bool]:
    """A predicate: is ``frame`` a ``resources/updated`` notification for ``uri``?

    Exact method and exact URI -- not a substring search over the frame -- so a
    frame that merely echoes the URI inside an unrelated field, or a
    list-changed notification, is not mistaken for a delivered scoped update.
    Pass a different predicate to ``run_subscriptions_leak_probe`` to score a
    tasks-extension or list-changed notification instead.
    """

    def _match(frame: Dict[str, Any]) -> bool:
        if frame.get("method") != "notifications/resources/updated":
            return False
        params = frame.get("params") or {}
        return params.get("uri") == uri

    return _match


@dataclass
class SubscriptionsLeakReport:
    target: str
    authorization: str
    identity_a: str
    identity_b: str
    grade: str
    detail: str
    marker_fingerprint: Optional[str] = None
    controls: Dict[str, bool] = field(default_factory=dict)
    # B's observed frames, kept off repr/to_dict; for the caller to inspect.
    b_notifications: Any = field(default=None, repr=False)
    a_notifications: Any = field(default=None, repr=False)

    @property
    def leaked(self) -> bool:
        return self.grade == LEAK

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "probe": "subscriptions_leak",
            "target": self.target,
            "authorization": self.authorization,
            "identity_a": self.identity_a,
            "identity_b": self.identity_b,
            "grade": self.grade,
            "detail": self.detail,
            "marker_fingerprint": self.marker_fingerprint,
            "controls": dict(self.controls),
        }
        if self.leaked:
            data["failure_class"] = FAILURE_CLASS
        return data

    def summary(self) -> str:
        if self.grade == LEAK:
            return (
                f"LEAK: identity {self.identity_b!r} received on its listen stream "
                f"a notification scoped to identity {self.identity_a!r}'s resource "
                f"(marker {self.marker_fingerprint}) -- {FAILURE_CLASS}."
            )
        if self.grade == OBSERVATION:
            return f"OBSERVATION: {self.detail}"
        if self.grade == OK:
            return (
                f"OK: identity {self.identity_b!r} received only its own "
                f"notifications; identity {self.identity_a!r}'s did not cross "
                f"(marker {self.marker_fingerprint})."
            )
        return f"INCONCLUSIVE: {self.detail}"


def _grade(**kw: Any) -> SubscriptionsLeakReport:
    return SubscriptionsLeakReport(**kw)


def run_subscriptions_leak_probe(
    target: str,
    identity_a: Identity,
    identity_b: Identity,
    *,
    resource_uri: str,
    change: Callable[[MCPClient], Any],
    is_a_notification: Optional[Callable[[Dict[str, Any]], bool]] = None,
    b_own_uri: Optional[str] = None,
    b_change: Optional[Callable[[MCPClient], Any]] = None,
    is_b_own_notification: Optional[Callable[[Dict[str, Any]], bool]] = None,
    idle_timeout: float = 2.0,
    ack_timeout: float = 10.0,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> SubscriptionsLeakReport:
    """B listens on A's resource; A acts; did A's notification reach B's stream?

    The 2026-07-28 listen stream has no replay, so order is load-bearing: every
    stream is opened and acknowledged *before* anyone acts, otherwise an event
    that predates a subscription is simply never delivered and the probe would
    mis-grade.

    1. B opens a listen stream subscribed to A's ``resource_uri`` (and to
       ``b_own_uri`` if given) -- the eavesdrop attempt.
    2. A opens its OWN listen stream on ``resource_uri`` -- the positive control
       that proves notifications fire at all.
    3. A applies ``change`` (fires a notification about ``resource_uri``).
    4. If ``b_own_uri`` is given, B applies ``b_change`` (fires a notification
       about ``b_own_uri``) -- proves B's stream is alive.
    5. Both streams are drained.

    Grading: if A's own stream never saw A's notification, nothing fired that
    the probe could trust -> INCONCLUSIVE. If ``b_own_uri`` was given and B's
    own notification never reached B's stream, B's stream is not demonstrably
    alive -> INCONCLUSIVE. Only once those hold: A's notification on B's stream
    -> LEAK; otherwise OK.

    Anything that stops the probe observing the channel -- a pre-2026 server, a
    stream that will not open or acknowledge, a read that fails -- is
    INCONCLUSIVE, never "no leak". Authorized first, like every probe.
    """
    decision = authorize(
        target, authorized=authorized, authorization_note=authorization_note
    )
    match_a = is_a_notification or updated_matcher(resource_uri)
    match_b_own = (
        is_b_own_notification
        if is_b_own_notification is not None
        else (updated_matcher(b_own_uri) if b_own_uri else None)
    )
    marker_fp = token_fingerprint(resource_uri)

    client_a = identity_a.connect()
    client_b: Optional[MCPClient] = None
    stream_a: Optional[ListenStream] = None
    stream_b: Optional[ListenStream] = None

    def inconclusive(detail: str, **extra: Any) -> SubscriptionsLeakReport:
        return _grade(
            target=decision.target,
            authorization=decision.reason,
            identity_a=identity_a.label,
            identity_b=identity_b.label,
            grade=INCONCLUSIVE,
            detail=detail,
            marker_fingerprint=marker_fp,
            **extra,
        )

    principal_a: Optional[str] = None
    principal_b: Optional[str] = None
    try:
        client_a.initialize()
        client_b = identity_b.connect()
        client_b.initialize()

        # Distinctness: a cross-stream delivery is a cross-user LEAK only if A and
        # B are genuinely different principals; a server that collapses them
        # (shared session/credential) delivers across without a real access gain.
        principal_a = _principal_of(client_a)
        principal_b = _principal_of(client_b)

        b_subs = [resource_uri] + ([b_own_uri] if b_own_uri else [])
        try:
            stream_b = client_b.listen(
                resource_subscriptions=b_subs, ack_timeout=ack_timeout
            )
            stream_a = client_a.listen(
                resource_subscriptions=[resource_uri], ack_timeout=ack_timeout
            )
        except ListenNotSupportedError as exc:
            return inconclusive(
                f"{exc} The probe cannot observe this server's subscription "
                f"channel (not 'no leak')."
            )
        except Exception as exc:
            return inconclusive(
                f"could not open a subscriptions/listen stream: {exc} "
                f"(not 'no leak')."
            )

        # Streams are open and acknowledged; only now may anyone act.
        change(client_a)
        if b_own_uri and b_change is not None:
            b_change(client_b)

        try:
            a_events = stream_a.drain_events(idle_timeout)
            b_events = stream_b.drain_events(idle_timeout)
        except Exception as exc:
            return inconclusive(
                f"could not read a subscriptions/listen stream: {exc} "
                f"(not 'no leak')."
            )
    finally:
        for closeable in (stream_a, stream_b, client_a, client_b):
            if closeable is not None:
                _safe_close(closeable)

    control_a = any(match_a(e) for e in a_events)
    controls: Dict[str, bool] = {"a_own_stream_fires": control_a}
    if not control_a:
        return inconclusive(
            f"control failed: identity {identity_a.label!r}'s own listen stream "
            f"did not receive its own notification, so no notification fired that "
            f"the probe could trust -- nothing observed.",
            controls=controls,
            a_notifications=a_events,
            b_notifications=b_events,
        )

    if match_b_own is not None:
        control_b = any(match_b_own(e) for e in b_events)
        controls["b_own_stream_alive"] = control_b
        if not control_b:
            return inconclusive(
                f"control failed: identity {identity_b.label!r}'s own listen "
                f"stream did not receive its own notification, so its stream is "
                f"not demonstrably alive -- 'no leak' cannot be trusted.",
                controls=controls,
                a_notifications=a_events,
                b_notifications=b_events,
            )

    crossed = any(match_a(e) for e in b_events)
    distinct = (
        principal_a is not None and principal_b is not None and principal_a != principal_b
    )
    controls["identities"] = (
        "distinct" if distinct
        else "COLLAPSED (one principal)" if (principal_a is not None and principal_b is not None)
        else "UNVERIFIED (no principal signal)"
    )
    if crossed and distinct:
        grade = LEAK
        detail = "B's listen stream received a notification scoped to A"
    elif crossed:
        # Delivered across, but A and B are not provably distinct principals:
        # identity collapse / shared session, not a cross-user access gain.
        grade = OBSERVATION
        cause = ("the server maps A and B to one principal (identity collapse / "
                 "shared session)" if (principal_a is not None and principal_b is not None)
                 else "A and B could not be shown to be distinct principals")
        detail = (f"B's stream received A's notification, but {cause}: verify they are "
                  f"distinct users before treating this as a cross-user leak")
    else:
        grade = OK
        detail = "B's listen stream received only its own notifications; A's did not cross"
    return _grade(
        target=decision.target,
        authorization=decision.reason,
        identity_a=identity_a.label,
        identity_b=identity_b.label,
        grade=grade,
        detail=detail,
        marker_fingerprint=marker_fp,
        controls=controls,
        a_notifications=a_events,
        b_notifications=b_events,
    )


def _safe_close(closeable: Any) -> None:
    try:
        closeable.close()
    except Exception:
        pass
