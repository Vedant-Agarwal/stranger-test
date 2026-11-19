"""The safe scan check catalog.

:func:`run_checks` turns a single-identity :class:`~strangertest.scan.model.TargetProfile`
into a list of graded :class:`~strangertest.scan.model.ScanFinding` records. Every
check here is **non-destructive, read-only and single-identity**: it reads the
profile (and, where noted, may make a few extra *safe* read-only calls through an
optional ``live`` callable). None of them writes, guesses credentials, drives two
identities, or loads the target.

Grading discipline (inherited from the lab probes — see ``strangertest/cachescope.py``,
``delegate.py``, ``concurrency.py``, ``handle.py``):

* ``RISK``          — a dangerous misconfiguration was *observed* with one credential.
* ``OBSERVATION``   — a noteworthy signal that is not, on its own, a confirmed fault.
* ``OK``            — the safe behaviour was positively observed (a false-pass control).
* ``INCONCLUSIVE``  — the profile lacks the data to grade; never guessed as OK or RISK.

A single-identity scan can detect *signals* of the cross-identity / delegated-authority
leak classes but can **never confirm them**. Where a signal implies such a class, the
recommendation says to run the lab deep-check (two identities, a controlled upstream).
Tokens and secrets appear only as ``sha256:`` fingerprints, never raw.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .model import ScanFinding, TargetProfile, field_of

try:  # reuse the canonical fingerprint helper; fall back if layout shifts
    from ..delegate import token_fingerprint as _token_fingerprint
except Exception:  # pragma: no cover - defensive
    import hashlib as _hashlib

    def _token_fingerprint(token: Optional[str]) -> Optional[str]:
        if not token:
            return None
        return "sha256:" + _hashlib.sha256(str(token).encode()).hexdigest()[:12]


__all__ = ["run_checks", "CHECKS"]

# Hosts for which cleartext transport is acceptable (a dev loopback target).
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}

# Response-header names that must never carry a credential back to the client.
# If any of these appears in the *response*, the gateway is handing an inbound /
# upstream credential to whoever is on the other side.
_CREDENTIAL_PASSTHROUGH_HEADERS = {
    "authorization",
    "proxy-authorization",
    "x-forwarded-access-token",
    "x-forwarded-authorization",
    "x-forwarded-client-cert",
    "x-amzn-oidc-accesstoken",
    "x-amzn-oidc-data",
    "x-amzn-oidc-identity",
    "x-api-key",
    "x-auth-request-access-token",
    "x-access-token",
}


def _lower_keys(headers: Any) -> Dict[str, Any]:
    if not isinstance(headers, dict):
        return {}
    return {str(k).lower(): v for k, v in headers.items()}


def _host_of(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    rest = url.split("://", 1)[-1]
    authority = rest.split("/", 1)[0].split("?", 1)[0]
    # strip userinfo, then split host:port (leave bracketed IPv6 intact)
    authority = authority.rsplit("@", 1)[-1]
    if authority.startswith("["):
        return authority.split("]", 1)[0] + "]"
    return authority.split(":", 1)[0] or None


def _has_capability(profile: TargetProfile, name: str) -> bool:
    caps = profile.capabilities
    return isinstance(caps, dict) and name in caps and caps.get(name) is not None


# --------------------------------------------------------------------------- #
# Individual checks. Each takes (profile, live) and returns one ScanFinding.
# --------------------------------------------------------------------------- #


def check_auth_not_required(profile: TargetProfile, live: Optional[Callable]) -> ScanFinding:
    """RISK when the server served initialize/list with no credential."""
    cid, title = "auth-not-required", "Authentication not required"
    required = field_of(profile.auth, "required")

    # Optional safe fallback: if the adapter did not settle `required`, a single
    # unauthenticated read-only probe can. Guarded so a signature mismatch with
    # the adapter's `live` contract can never crash the scan.
    probed_unauth = None
    if required is None and callable(live):
        try:
            res = live("initialize", authenticated=False)
            if isinstance(res, dict) and "ok" in res:
                probed_unauth = bool(res["ok"])
        except Exception:
            probed_unauth = None
        if probed_unauth is not None:
            required = not probed_unauth

    if profile.reachable is False:
        return ScanFinding(
            cid, title, "INCONCLUSIVE", "info",
            "Target was not reachable, so authentication could not be exercised.",
            {"reachable": False},
            "Confirm the URL and transport, then re-run the scan.",
        )
    if required is None:
        return ScanFinding(
            cid, title, "INCONCLUSIVE", "info",
            "The profile does not record whether an unauthenticated request was served.",
            {"auth_required": None, "live_probe_used": probed_unauth is not None},
            "Have the adapter attempt one unauthenticated initialize/list, or pass a live probe.",
        )
    if required is False:
        served = sorted(k for k in (profile.capabilities or {})) if isinstance(profile.capabilities, dict) else []
        return ScanFinding(
            cid, title, "RISK", "high",
            "The server answered an unauthenticated initialize/list — no credential was demanded.",
            {
                "auth_required": False,
                "served_capabilities": served,
                "protocol_version": profile.protocol_version,
                "source": "live_probe" if probed_unauth is not None else "profile",
            },
            "Require a credential on every MCP request; if this exposure is intended, "
            "document it. Then run authenticated checks to see what an anonymous caller can reach.",
        )
    return ScanFinding(
        cid, title, "OK", "info",
        "The server refused an unauthenticated request (a credential is required).",
        {"auth_required": True, "scheme": field_of(profile.auth, "scheme"),
         "www_authenticate": _present(field_of(profile.auth, "www_authenticate"))},
        "No action; authentication is enforced at the door.",
    )


def check_session_id_as_bearer(profile: TargetProfile, live: Optional[Callable]) -> ScanFinding:
    """RISK when a session id unbound to the caller is accepted as authority."""
    cid, title = "session-id-as-bearer", "Session id accepted as bearer authority"
    s = profile.session
    if field_of(s, "accepts_forged_session_id") is True:
        return ScanFinding(
            cid, title, "RISK", "high",
            "The server honoured a session id that was never bound to this caller — "
            "a session id is being treated as a bearer token.",
            {
                "accepts_forged_session_id": True,
                "echoes_inbound_session_id": field_of(s, "echoes_inbound_session_id"),
                "issues_session_id": field_of(s, "issues_session_id"),
            },
            "Bind every session id to the authenticated principal that created it and "
            "reject ids presented by a different caller. This is a session-hijack / IDOR "
            "signal only: run the lab deep-check (two identities, controlled upstream) to "
            "confirm one caller can reach another's session.",
        )
    if field_of(s, "echoes_inbound_session_id") is True and field_of(s, "accepts_forged_session_id") is None:
        return ScanFinding(
            cid, title, "OBSERVATION", "medium",
            "The server reused a client-supplied session id but it was not probed with a "
            "forged, unbound id.",
            {"echoes_inbound_session_id": True, "accepts_forged_session_id": None},
            "Probe with a forged session id unbound to the caller, then run the lab "
            "deep-check to confirm whether sessions are isolated.",
        )
    if field_of(s, "accepts_forged_session_id") is False or field_of(s, "issues_session_id") is True:
        return ScanFinding(
            cid, title, "OK", "info",
            "Session handling looks bound to the caller (a forged id was rejected or the "
            "server mints its own ids).",
            {"accepts_forged_session_id": field_of(s, "accepts_forged_session_id"),
             "issues_session_id": field_of(s, "issues_session_id")},
            "No action; keep session ids bound to the authenticated principal.",
        )
    return ScanFinding(
        cid, title, "INCONCLUSIVE", "info",
        "The profile records nothing about session-id handling.",
        {"session": vars(s) if s else {}},
        "Have the adapter note whether a session id is issued and whether a forged id is accepted.",
    )


def check_cachescope_mislabel_signal(profile: TargetProfile, live: Optional[Callable]) -> ScanFinding:
    """OBSERVATION/RISK around resources/read cacheScope labelling."""
    cid, title = "cachescope-mislabel-signal", "resources/read cache-scope labelling"
    c = profile.cache
    has_resources = _has_capability(profile, "resources")

    # No resources capability at all -> nothing cacheable to mislabel.
    if not has_resources and field_of(c, "advertises_cachescope") is None:
        return ScanFinding(
            cid, title, "INCONCLUSIVE", "info",
            "No resources capability and no cache labelling were observed.",
            {"resources_capability": has_resources, "advertises_cachescope": None},
            "If the target serves resources/read, capture a sample result's cacheScope.",
        )
    if field_of(c, "advertises_cachescope") is False:
        # Per the lab probe: a missing cacheScope is only an OBSERVATION; the spec
        # states no default, so it is never graded a confirmed leak from a scan.
        return ScanFinding(
            cid, title, "OBSERVATION", "medium",
            "resources/read results carry no cacheScope label; a shared cache has no "
            "instruction not to share a per-user result.",
            {"advertises_cachescope": False, "resources_capability": has_resources},
            "Label per-user results cacheScope=private. Run the lab cachescope probe (two "
            "identities) to confirm whether a private result is actually shared.",
        )
    if field_of(c, "advertises_cachescope") is True and field_of(c, "forces_private") is False:
        return ScanFinding(
            cid, title, "OBSERVATION", "medium",
            "resources/read results are labelled cacheScope=public while the server also "
            "serves resources that are plausibly per-user.",
            {"advertises_cachescope": True, "forces_private": False,
             "ttl_ms": field_of(c, "ttl_ms"), "resources_capability": has_resources},
            "Confirm no public-labelled result is user-specific. A single identity cannot "
            "see another user's content, so run the lab cachescope probe to confirm.",
        )
    if field_of(c, "advertises_cachescope") is True and field_of(c, "forces_private") is True:
        return ScanFinding(
            cid, title, "OK", "info",
            "resources/read results are labelled cacheScope=private (not shareable across "
            "authorization contexts).",
            {"advertises_cachescope": True, "forces_private": True, "ttl_ms": field_of(c, "ttl_ms")},
            "No action; honour the private label in any cache in front of this server.",
        )
    return ScanFinding(
        cid, title, "INCONCLUSIVE", "info",
        "Cache labelling was only partially observed.",
        {"advertises_cachescope": field_of(c, "advertises_cachescope"), "forces_private": field_of(c, "forces_private")},
        "Capture a sample resources/read result and record its cacheScope and ttlMs.",
    )


def check_token_exchange_present(profile: TargetProfile, live: Optional[Callable]) -> ScanFinding:
    """OBSERVATION when the target advertises RFC 8693 token exchange."""
    cid, title = "token-exchange-present", "RFC 8693 token exchange advertised"
    meta = field_of(profile.auth, "oauth_metadata") if isinstance(field_of(profile.auth, "oauth_metadata"), dict) else {}
    grant_types = meta.get("grant_types_supported") or []
    advertises_exchange = (
        field_of(profile.auth, "token_exchange_hint") is True
        or "urn:ietf:params:oauth:grant-type:token-exchange" in (grant_types or [])
    )
    if advertises_exchange:
        return ScanFinding(
            cid, title, "OBSERVATION", "info",
            "The target advertises RFC 8693 token exchange — it acts as a deputy, minting "
            "upstream tokens on a caller's behalf.",
            {
                "token_exchange_hint": field_of(profile.auth, "token_exchange_hint"),
                "grant_types_supported": grant_types or None,
                "oauth_issuer": meta.get("issuer"),
            },
            "Delegation is where confused-deputy leaks live (cf. CVE-2026-110195). Run the "
            "lab same-user-credentials and delegation deep-checks (two identities, a "
            "controlled upstream) to confirm the exchange binds to the inbound credential.",
        )
    if field_of(profile.auth, "token_exchange_hint") is False or (field_of(profile.auth, "oauth_metadata") is not None):
        return ScanFinding(
            cid, title, "OK", "info",
            "No RFC 8693 token exchange is advertised; the target is not acting as a "
            "token-minting deputy in what was observed.",
            {"token_exchange_hint": field_of(profile.auth, "token_exchange_hint"),
             "grant_types_supported": grant_types or None},
            "No action from the scan; delegation leaks are out of scope without an exchange.",
        )
    return ScanFinding(
        cid, title, "INCONCLUSIVE", "info",
        "No OAuth metadata was captured, so token-exchange support is unknown.",
        {"oauth_metadata": None},
        "Fetch the target's OAuth / protected-resource metadata and record grant_types_supported.",
    )


def check_header_leakage(profile: TargetProfile, live: Optional[Callable]) -> ScanFinding:
    """RISK when a credential-bearing header is handed back in the response."""
    cid, title = "header-leakage", "Credential header passthrough / leakage"
    headers = _lower_keys(profile.headers)
    if not headers:
        return ScanFinding(
            cid, title, "INCONCLUSIVE", "info",
            "No response headers were captured.",
            {"response_headers_seen": 0},
            "Have the adapter record the target's response headers.",
        )
    leaked = sorted(h for h in _CREDENTIAL_PASSTHROUGH_HEADERS if h in headers)
    if leaked:
        evidence: Dict[str, Any] = {"leaked_headers": leaked}
        # fingerprint any value so nothing raw is ever stored
        evidence["fingerprints"] = {h: _token_fingerprint(str(headers.get(h))) for h in leaked}
        return ScanFinding(
            cid, title, "RISK", "high",
            "The server returned a credential-bearing header in its response, handing an "
            "inbound/upstream credential back to the client.",
            evidence,
            "Strip credential headers (Authorization, X-Forwarded-Access-Token, OIDC "
            "headers, API keys) from responses and never reflect inbound auth. Then run the "
            "lab delegation deep-check to confirm whose credential is being exposed.",
        )
    # A reflected non-credential marker header (adapter may flag it) is a weaker signal.
    reflected = headers.get("_reflected_inbound")
    if reflected:
        return ScanFinding(
            cid, title, "OBSERVATION", "low",
            "The server reflected a client-supplied header back in its response.",
            {"reflected_inbound": reflected},
            "Confirm no sensitive inbound header is echoed; avoid reflecting request "
            "headers you do not control.",
        )
    return ScanFinding(
        cid, title, "OK", "info",
        "No credential-bearing header was observed in the server's responses.",
        {"response_headers_seen": len(headers), "credential_headers": []},
        "No action; keep auth and upstream credential headers out of responses.",
    )


def check_transport_tls_hygiene(profile: TargetProfile, live: Optional[Callable]) -> ScanFinding:
    """RISK when a non-loopback target is served over cleartext transport."""
    cid, title = "transport-tls-hygiene", "Transport TLS hygiene"
    transport = (profile.transport or "").lower()
    url = profile.url or ""
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    host = _host_of(url)
    is_loopback = host is not None and host.lower() in _LOOPBACK_HOSTS
    is_cleartext = transport in {"http", "ws"} or scheme in {"http", "ws"}
    is_tls = transport in {"https", "wss"} or scheme in {"https", "wss"}
    is_stdio = transport == "stdio" or scheme == "stdio"

    if is_stdio:
        return ScanFinding(
            cid, title, "OK", "info",
            "The target uses a local stdio transport; network TLS does not apply.",
            {"transport": transport or scheme},
            "No action for a local stdio transport.",
        )
    if not transport and not scheme:
        return ScanFinding(
            cid, title, "INCONCLUSIVE", "info",
            "No transport or URL scheme was recorded.",
            {"transport": None, "url": _present(url)},
            "Record the target URL and transport so TLS can be assessed.",
        )
    if is_cleartext and not is_loopback:
        return ScanFinding(
            cid, title, "RISK", "high",
            "A non-loopback target is reached over cleartext (no TLS); credentials and MCP "
            "traffic are exposed on the wire.",
            {"transport": transport or scheme, "host": host, "loopback": False},
            "Serve the target over TLS (https/wss). Cleartext is acceptable only on a local "
            "loopback address.",
        )
    if is_cleartext and is_loopback:
        return ScanFinding(
            cid, title, "OK", "info",
            "Cleartext transport is confined to a loopback address.",
            {"transport": transport or scheme, "host": host, "loopback": True},
            "No action; keep cleartext on loopback only.",
        )
    if is_tls:
        return ScanFinding(
            cid, title, "OK", "info",
            "The target is reached over TLS.",
            {"transport": transport or scheme, "host": host},
            "No action; transport is encrypted.",
        )
    return ScanFinding(
        cid, title, "INCONCLUSIVE", "info",
        "The transport could not be classified as TLS or cleartext.",
        {"transport": transport or scheme, "url": _present(url)},
        "Record an explicit transport token (http/https/ws/wss/stdio).",
    )


def _present(value: Any) -> Any:
    """Report only *whether* a sensitive string was present, not its content."""
    if value is None:
        return None
    text = str(value)
    return {"present": bool(text), "len": len(text)} if text else {"present": False, "len": 0}


# Ordered catalog. The CLI/report layer renders findings in this order.
CHECKS = (
    check_auth_not_required,
    check_session_id_as_bearer,
    check_cachescope_mislabel_signal,
    check_token_exchange_present,
    check_header_leakage,
    check_transport_tls_hygiene,
)


def run_checks(profile: TargetProfile, *, live: Optional[Callable] = None) -> List[ScanFinding]:
    """Run the safe check catalog over ``profile`` and return graded findings.

    ``live``, if given, is an optional callable the catalog may use for a *few*
    extra safe, read-only, single-identity probes (never destructive, never
    multi-user). It is always optional: with ``live=None`` every check grades
    from the profile alone. Each check is isolated — one raising never sinks the
    scan; it is reported as INCONCLUSIVE instead.
    """
    findings: List[ScanFinding] = []
    for check in CHECKS:
        try:
            findings.append(check(profile, live))
        except Exception as exc:  # a broken check must not break the scan
            findings.append(
                ScanFinding(
                    getattr(check, "__name__", "unknown-check").replace("check_", "").replace("_", "-"),
                    "Check error",
                    "INCONCLUSIVE",
                    "info",
                    "This check could not be evaluated against the profile.",
                    {"error": type(exc).__name__},
                    "Report this as a scanner bug; the target was not assessed for this signal.",
                )
            )
    return findings
