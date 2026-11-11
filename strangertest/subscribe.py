"""The subscription-leak probe (XID-13).

Identity B subscribes to a resource owned by identity A; A then changes it. If B
receives an update notification for A's resource, the server has delivered one
identity's events to another — a **cross-identity subscription/notification
leak**.

Same "A acts, B observes" shape as the read probe: connections come from
:class:`~strangertest.probe.Identity` objects and the server-specific "how A
changes the resource" step is injected, so the engine stays server-agnostic and
is testable in-process. Detection is existence-based (did B hear about A's
resource at all), matching how these leaks present — the content may or may not
be included.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .guard import authorize
from .mcp_client import ListenNotSupportedError, ListenStream, MCPClient
from .probe import Identity, ProbeError

__all__ = ["SubscriptionReport", "run_subscription_probe"]

FAILURE_CLASS = "cross-identity subscription/notification leak"


def _is_update_for(frame: Dict[str, Any], uri: str) -> bool:
    """True if ``frame`` is a resource-update notification for exactly ``uri``.

    Exact-URI, exact-method matching — not a substring search over the frame —
    so a notification that merely echoes the URI inside an unrelated field, or
    a list-changed notification, is not mistaken for a delivered update.
    """
    if frame.get("method") != "notifications/resources/updated":
        return False
    params = frame.get("params") or {}
    return params.get("uri") == uri


@dataclass
class SubscriptionReport:
    target: str
    authorization: str
    identity_a: str
    identity_b: str
    resource_uri: str
    leaked: bool
    detail: str
    notifications: Any = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "probe": "subscription",
            "target": self.target,
            "authorization": self.authorization,
            "identity_a": self.identity_a,
            "identity_b": self.identity_b,
            "resource_uri": self.resource_uri,
            "leaked": self.leaked,
            "detail": self.detail,
        }
        if self.leaked:
            data["failure_class"] = FAILURE_CLASS
        return data

    def summary(self) -> str:
        if self.leaked:
            return (
                f"LEAK: identity {self.identity_b!r} received update notifications "
                f"for {self.resource_uri!r}, a resource owned by identity "
                f"{self.identity_a!r} — {FAILURE_CLASS}."
            )
        return (
            f"OK: identity {self.identity_b!r} received no notifications for "
            f"{self.identity_a!r}'s resource {self.resource_uri!r}."
        )


def run_subscription_probe(
    target: str,
    identity_a: Identity,
    identity_b: Identity,
    *,
    resource_uri: str,
    change: Callable[[MCPClient], Any],
    idle_timeout: float = 2.0,
    ack_timeout: float = 10.0,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> SubscriptionReport:
    """B opens a listen stream on A's ``resource_uri``; A changes it; did B hear it?

    The real 2026-07-28 subscription channel is a stream with no replay, so the
    order is load-bearing: B opens ``subscriptions/listen`` and waits for the
    server's acknowledgment *first*, and only then does A apply ``change`` (a
    tool call that mutates the resource). B then drains whatever the server
    pushed. If B receives a resource-update notification for A's resource, one
    identity's events reached another — the leak.

    Anything that stops the probe from observing B's stream — a server that
    predates 2026-07-28, a stream that will not open or acknowledge, a read that
    fails — is raised as :class:`ProbeError` (inconclusive), never reported as
    "no leak". Authorized first, like every probe.
    """
    decision = authorize(
        target, authorized=authorized, authorization_note=authorization_note
    )

    client_a = identity_a.connect()
    client_b: Optional[MCPClient] = None
    stream: Optional[ListenStream] = None
    try:
        client_a.initialize()
        client_b = identity_b.connect()
        client_b.initialize()
        try:
            stream = client_b.listen(
                resource_subscriptions=[resource_uri], ack_timeout=ack_timeout
            )
        except ListenNotSupportedError as exc:
            raise ProbeError(
                f"{exc} The probe is inconclusive for {identity_b.label!r} "
                f"(not 'no leak')."
            )
        except Exception as exc:
            raise ProbeError(
                f"could not open a subscription stream for {identity_b.label!r}: "
                f"{exc}. The probe is inconclusive (not 'no leak')."
            )
        # The stream is open and acknowledged; only now may A act, because the
        # channel does not replay events that predate the subscription.
        change(client_a)
        try:
            events = stream.drain_events(idle_timeout)
        except Exception as exc:
            raise ProbeError(
                f"could not read the subscription stream for {identity_b.label!r}: "
                f"{exc}. The probe is inconclusive (not 'no leak')."
            )
    finally:
        if stream is not None:
            _safe_close(stream)
        _safe_close(client_a)
        if client_b is not None:
            _safe_close(client_b)

    leaked = any(_is_update_for(e, resource_uri) for e in events)
    return SubscriptionReport(
        target=decision.target,
        authorization=decision.reason,
        identity_a=identity_a.label,
        identity_b=identity_b.label,
        resource_uri=resource_uri,
        leaked=leaked,
        detail="B received update notifications for A's resource" if leaked
        else "B received no notifications for A's resource",
        notifications=events,
    )


def _safe_close(closeable: Any) -> None:
    try:
        closeable.close()
    except Exception:
        pass
