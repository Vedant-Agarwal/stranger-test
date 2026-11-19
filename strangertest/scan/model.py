"""Shared data contract for the one-command scanner.

The *adapter* agent owns the canonical copy of this module; reconcile on merge.
This placeholder exists so the CLI and the renderers can be built and tested
against a mock before the adapter and check-catalog agents land. The field
names and grade/severity vocabularies here are the contract — keep them exact.

Design notes for whoever reconciles:

* ``auth`` / ``session`` / ``cache`` are small nested records. They are modelled
  here as dataclasses, but the renderers read them through ``field_of()`` so a
  plain ``dict`` from the adapter works too. Keep the field names identical.
* Nothing in a profile is a secret. ``fingerprints`` holds short, non-reversible
  identifiers (hashes / truncations) — never a raw token, key or session id.
"""

from __future__ import annotations

from dataclasses import dataclass, field, is_dataclass, asdict
from typing import Any, Dict, List, Optional

# The only grades a finding may carry, worst-first for display.
GRADES = ("RISK", "OBSERVATION", "OK", "INCONCLUSIVE")
# The only severity hints a finding may carry, worst-first.
SEVERITIES = ("high", "medium", "low", "info")

__all__ = [
    "GRADES",
    "SEVERITIES",
    "AuthInfo",
    "SessionInfo",
    "CacheInfo",
    "TargetProfile",
    "ScanFinding",
    "field_of",
    "to_plain",
]


@dataclass
class AuthInfo:
    """What the server advertises about authentication."""

    required: Optional[bool] = None
    scheme: Optional[str] = None
    oauth_metadata: Optional[Dict[str, Any]] = None
    token_exchange_hint: Optional[str] = None
    www_authenticate: Optional[str] = None


@dataclass
class SessionInfo:
    """How the server handles MCP session ids (``Mcp-Session-Id``)."""

    issues_session_id: Optional[bool] = None
    echoes_inbound_session_id: Optional[bool] = None
    accepts_forged_session_id: Optional[bool] = None


@dataclass
class CacheInfo:
    """What the server advertises about response caching (cache-scope)."""

    advertises_cachescope: Optional[bool] = None
    forces_private: Optional[bool] = None
    ttl_ms: Optional[int] = None


@dataclass
class TargetProfile:
    """A read-only fingerprint of one MCP server, produced by the adapter."""

    url: str
    reachable: bool = False
    transport: Optional[str] = None
    protocol_version: Optional[str] = None
    server_info: Dict[str, Any] = field(default_factory=dict)
    auth: Dict[str, Any] = field(default_factory=dict)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    session: Dict[str, Any] = field(default_factory=dict)
    cache: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    fingerprints: Dict[str, Any] = field(default_factory=dict)



@dataclass
class ScanFinding:
    """One graded observation from the check catalog."""

    check_id: str
    title: str
    grade: str  # one of GRADES
    severity_hint: str  # one of SEVERITIES
    rationale: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


def field_of(obj: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` off ``obj`` whether it is a dataclass/object or a dict.

    The adapter agent may hand back dataclasses or plain dicts; the renderers
    read every field through this so either shape renders identically.
    """
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def to_plain(obj: Any) -> Any:
    """Recursively convert dataclasses to plain JSON-ready structures.

    Leaves dicts/lists/scalars untouched, so a dict-shaped profile from the
    adapter passes through unchanged.
    """
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_plain(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_plain(v) for v in obj]
    return obj
