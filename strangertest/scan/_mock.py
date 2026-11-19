"""Fabricated profile + findings so the renderers and CLI can be built and
tested before the adapter and check-catalog agents land.

Nothing here touches the network. ``mock_profile_target`` and ``mock_run_checks``
match the signatures the real ``strangertest.scan.adapter.profile_target`` and
``strangertest.scan.checks.run_checks`` will expose, so the CLI can be wired to
these today and flipped to the real modules on merge with a one-line import
change (see ``strangertest/cli.py``).
"""

from __future__ import annotations

from typing import Any, List, Optional

from .model import (
    AuthInfo,
    CacheInfo,
    ScanFinding,
    SessionInfo,
    TargetProfile,
)


def mock_profile(url: str = "http://localhost:4600/mcp") -> TargetProfile:
    """A rich, reachable sample profile that exercises every renderer branch."""
    return TargetProfile(
        url=url,
        reachable=True,
        transport="streamable-http",
        protocol_version="2026-07-28",
        server_info={"name": "practice-mcp", "version": "0.3.1"},
        auth=AuthInfo(
            required=True,
            scheme="oauth2",
            oauth_metadata={
                "issuer": "https://auth.example.test",
                "token_endpoint": "https://auth.example.test/token",
            },
            token_exchange_hint="urn:ietf:params:oauth:grant-type:token-exchange",
            www_authenticate='Bearer realm="mcp", error="invalid_token"',
        ),
        capabilities={"tools": {}, "resources": {"subscribe": True}, "tasks": {}},
        session=SessionInfo(
            issues_session_id=True,
            echoes_inbound_session_id=True,
            accepts_forged_session_id=True,
        ),
        cache=CacheInfo(
            advertises_cachescope=True,
            forces_private=False,
            ttl_ms=30000,
        ),
        headers={
            "content-type": "text/event-stream",
            "mcp-session-id": "<fingerprint:sess:9f3a…>",
            "cache-control": "public, max-age=30",
        },
        errors=[],
        fingerprints={
            "server": "sha256:3b1f…c2",
            "session_id": "sha256:9f3a…7d",
            "oauth_issuer": "sha256:a41e…0b",
        },
    )


def mock_findings() -> List[ScanFinding]:
    """One finding of every grade/severity, so renderers and exit codes can be
    exercised without the real check catalog."""
    return [
        ScanFinding(
            check_id="XID-SESSION-FORGE",
            title="Server accepts a forged inbound session id",
            grade="RISK",
            severity_hint="high",
            rationale=(
                "The server adopted a client-supplied Mcp-Session-Id it never "
                "issued. A caller who guesses or replays another identity's "
                "session id may be treated as that identity."
            ),
            evidence={
                "echoes_inbound_session_id": True,
                "accepts_forged_session_id": True,
                "forged_id_fingerprint": "sha256:deadbe…",
            },
            recommendation=(
                "Issue session ids server-side only; reject inbound session ids "
                "that the server did not mint."
            ),
        ),
        ScanFinding(
            check_id="XID-CACHE-SHARED",
            title="Cacheable responses are not forced private",
            grade="RISK",
            severity_hint="medium",
            rationale=(
                "Responses advertise a shared (public) cache scope with a TTL. "
                "A shared cache in front of the server could serve one "
                "identity's response to another."
            ),
            evidence={"advertises_cachescope": True, "forces_private": False, "ttl_ms": 30000},
            recommendation="Mark per-identity responses Cache-Control: private.",
        ),
        ScanFinding(
            check_id="XID-TOKEN-EXCHANGE",
            title="Token-exchange (RFC 8693) delegation advertised",
            grade="OBSERVATION",
            severity_hint="low",
            rationale=(
                "The server hints at on-behalf-of token exchange. Delegation "
                "itself is not a leak, but dropped or forged delegation is the "
                "XID-10 class — worth a deep-check."
            ),
            evidence={"token_exchange_hint": "urn:ietf:params:oauth:grant-type:token-exchange"},
            recommendation="Run the lab deep-check for XID-10 (delegation).",
        ),
        ScanFinding(
            check_id="AUTH-REQUIRED",
            title="Authentication is required",
            grade="OK",
            severity_hint="info",
            rationale="The server challenges unauthenticated callers (WWW-Authenticate present).",
            evidence={"required": True, "scheme": "oauth2"},
            recommendation="",
        ),
        ScanFinding(
            check_id="XID-SUBSCRIPTION",
            title="Subscription isolation could not be determined from a single pass",
            grade="INCONCLUSIVE",
            severity_hint="info",
            rationale=(
                "The server advertises resource subscriptions, but a read-only "
                "single pass cannot tell whether one identity's updates reach "
                "another."
            ),
            evidence={"capabilities.resources.subscribe": True},
            recommendation="Run the lab deep-check for XID-13 (subscription leak).",
        ),
    ]


def clean_profile(url: str = "http://localhost:4601/mcp") -> TargetProfile:
    """A reachable, well-behaved server (used to exercise the exit-0 path)."""
    p = mock_profile(url)
    p.session = SessionInfo(issues_session_id=True, echoes_inbound_session_id=False,
                            accepts_forged_session_id=False)
    p.cache = CacheInfo(advertises_cachescope=True, forces_private=True, ttl_ms=0)
    return p


def clean_findings() -> List[ScanFinding]:
    """Findings with no RISK grade (used to exercise the exit-0 path)."""
    return [
        ScanFinding(
            check_id="XID-SESSION-FORGE",
            title="Server rejects forged inbound session ids",
            grade="OK",
            severity_hint="info",
            rationale="The server minted its own session id and ignored the forged one.",
            evidence={"accepts_forged_session_id": False},
        ),
        ScanFinding(
            check_id="AUTH-REQUIRED",
            title="Authentication is required",
            grade="OK",
            severity_hint="info",
            rationale="Unauthenticated callers are challenged.",
            evidence={"required": True},
        ),
    ]


def unreachable_profile(url: str = "http://localhost:4699/mcp") -> TargetProfile:
    """An unreachable target (used to exercise the exit-2 path)."""
    return TargetProfile(
        url=url,
        reachable=False,
        errors=["connection refused"],
    )


# --- stand-ins for the sibling modules, matching their signatures -----------

def mock_profile_target(
    url: str,
    *,
    bearer: Optional[str] = None,
    timeout: float = 10.0,
    allow_nonloopback: bool = False,
    **_: Any,
) -> TargetProfile:
    """Mock of ``strangertest.scan.adapter.profile_target``.

    Fabricates a profile; never connects. ``bearer`` is accepted and ignored
    (and never echoed) so the CLI wiring matches the real adapter exactly.
    """
    return mock_profile(url)


def mock_run_checks(profile: TargetProfile, *, live: Any = None) -> List[ScanFinding]:
    """Mock of ``strangertest.scan.checks.run_checks``."""
    if not getattr(profile, "reachable", False):
        return []
    return mock_findings()
