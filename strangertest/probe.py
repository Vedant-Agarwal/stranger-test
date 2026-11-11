"""The A/B probe engine.

This is the heart of Stranger Test. Given a target MCP server and two
identities (A and B, or B as an anonymous client), it:

1. passes the target through :func:`strangertest.guard.authorize` first;
2. connects as identity A and plants a uniquely-marked record;
3. connects as identity B and tries to read that record back;
4. reports whether B could reach A's marker.

If B can read what A planted, the server has let one identity's authority reach
another: a **cross-identity / delegated-authority confused-deputy leak**.

How to plant and how to read are supplied by a :class:`ProbePlan`, so the
engine stays independent of any particular server's tool names. Connections are
supplied by :class:`Identity` objects, so a test can hand the engine an
in-memory server and no network is touched.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from .guard import authorize
from .mcp_client import MCPClient

__all__ = [
    "Identity",
    "ProbePlan",
    "ProbeReport",
    "ProbeError",
    "run_probe",
    "new_marker",
]


class ProbeError(RuntimeError):
    """A probe could not be carried out (as opposed to finding/​not finding a leak).

    Raised when the plant step itself fails — e.g. the plant tool returns a
    tool-level error. Without this, a failed plant would make B's read come up
    empty and the probe would wrongly report "no leak".
    """


def _tool_error_text(result: Any) -> Optional[str]:
    """Return the error text if ``result`` is an MCP tool-error result, else None.

    A tool-level failure comes back as a normal result with ``isError: true``
    (not a JSON-RPC error), so it has to be checked for explicitly.
    """
    if not isinstance(result, dict) or not result.get("isError"):
        return None
    for block in result.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            return str(block.get("text", "")).strip() or "tool reported isError"
    return "tool reported isError"

FAILURE_CLASS = "cross-identity / delegated-authority confused-deputy leak"


def new_marker() -> str:
    """A unique, recognisable marker to plant as identity A."""
    return "st-marker-" + secrets.token_hex(8)


@dataclass
class Identity:
    """A labelled way to open a fresh connection as one identity.

    ``connect`` returns a new, unconnected :class:`MCPClient`; the engine calls
    ``initialize`` on it. Identity A and identity B must connect with different
    credentials for the probe to mean anything.
    """

    label: str
    connect: Callable[[], MCPClient]


@dataclass
class ProbePlan:
    """How to plant a marker and how to try to read it back."""

    plant_tool: str
    read_tool: str
    plant_arguments: Callable[[str], Dict[str, Any]]
    read_arguments: Callable[[], Dict[str, Any]]
    detect: Callable[[str, Dict[str, Any]], bool]

    @classmethod
    def key_value(cls, plant_tool: str, read_tool: str, key: str) -> "ProbePlan":
        """A plan for a simple key/value style server.

        A stores ``marker`` at ``key``; B reads ``key``; a leak is the marker
        turning up anywhere in B's response.
        """
        return cls(
            plant_tool=plant_tool,
            read_tool=read_tool,
            plant_arguments=lambda marker: {"key": key, "value": marker},
            read_arguments=lambda: {"key": key},
            detect=lambda marker, result: marker in json.dumps(result),
        )


@dataclass
class ProbeReport:
    target: str
    authorization: str
    identity_a: str
    identity_b: str
    plant_tool: str
    read_tool: str
    marker: str
    leaked: bool
    detail: str
    read_result: Any = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "target": self.target,
            "authorization": self.authorization,
            "identity_a": self.identity_a,
            "identity_b": self.identity_b,
            "plant_tool": self.plant_tool,
            "read_tool": self.read_tool,
            "marker": self.marker,
            "leaked": self.leaked,
            "detail": self.detail,
        }
        if self.leaked:
            data["failure_class"] = FAILURE_CLASS
        return data

    def summary(self) -> str:
        if self.leaked:
            return (
                f"LEAK: identity {self.identity_b!r} could read a marker that "
                f"identity {self.identity_a!r} planted via {self.plant_tool!r} "
                f"(read back through {self.read_tool!r}) — {FAILURE_CLASS}."
            )
        return (
            f"OK: identity {self.identity_b!r} could not read the marker that "
            f"identity {self.identity_a!r} planted."
        )


def run_probe(
    target: str,
    identity_a: Identity,
    identity_b: Identity,
    plan: ProbePlan,
    *,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> ProbeReport:
    """Run one A-plants / B-reads probe against ``target``.

    The target is authorized first (see :mod:`strangertest.guard`); if it is not
    allowed, this raises before any connection is made.
    """
    decision = authorize(
        target, authorized=authorized, authorization_note=authorization_note
    )

    marker = new_marker()
    client_a = identity_a.connect()
    client_b: Optional[MCPClient] = None
    try:
        client_a.initialize()
        plant_result = client_a.call_tool(plan.plant_tool, plan.plant_arguments(marker))
        plant_error = _tool_error_text(plant_result)
        if plant_error is not None:
            raise ProbeError(
                f"could not plant as {identity_a.label!r}: tool {plan.plant_tool!r} "
                f"failed ({plant_error}). The probe is inconclusive."
            )

        client_b = identity_b.connect()
        client_b.initialize()
        read_result = client_b.call_tool(plan.read_tool, plan.read_arguments())
    finally:
        _safe_close(client_a)
        if client_b is not None:
            _safe_close(client_b)

    leaked = bool(plan.detect(marker, read_result))
    report = ProbeReport(
        target=decision.target,
        authorization=decision.reason,
        identity_a=identity_a.label,
        identity_b=identity_b.label,
        plant_tool=plan.plant_tool,
        read_tool=plan.read_tool,
        marker=marker,
        leaked=leaked,
        detail="marker planted by A was visible to B" if leaked
        else "marker planted by A was not visible to B",
        read_result=read_result,
    )
    return report


def _safe_close(client: MCPClient) -> None:
    try:
        client.close()
    except Exception:
        pass
