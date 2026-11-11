"""The delegation-fidelity probe (XID-10).

The leading-edge class. When an MCP server acts on behalf of a user by calling
an upstream API (OAuth token exchange / on-behalf-of / an A2A hop), it must
carry *who it is acting for* faithfully. This probe drives the target as two
identities, watches what arrives at an upstream it controls, and checks that the
delegation was neither dropped nor forged.

Unlike the read and subscription probes, B never reads anything. Instead the
tool owns a :class:`MockUpstream`; the target server is configured to call it;
and the probe inspects the calls that arrive. It can only test a server whose
upstream you can point at the mock — i.e. a server you operate — which is
exactly the authorized-only rule.

It drives the target as A, then B, then A again — the second A call catches a
deputy that cached or bled one caller's exchanged token into another's request.
Only the per-user upstream calls (tools/call, resources/read) are graded; a
gateway's registration, discovery, refresh and health traffic runs on a
separate credential and is ignored.

Checks (all must hold, or the server is vulnerable):

* ``subject_preserved``       — the upstream sees the real user, not the server's own account
* ``actor_present``           — the acting agent is identified
* ``audience_correct``        — the token is minted for this upstream, not reusable elsewhere
* ``scope_narrowed``          — the call does not carry a broad/admin scope
* ``no_token_reuse``          — each principal gets its own exchanged token
* ``no_cross_identity_bleed`` — A's later call stays A's, on a token that is not B's
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from .guard import authorize
from .mcp_client import MCPClient
from .probe import Identity, ProbeError

__all__ = [
    "UpstreamCall",
    "MockUpstream",
    "DelegationReport",
    "run_delegation_probe",
]

FAILURE_CLASS = (
    "delegation dropped or forged (on-behalf-of / token-exchange confused-deputy)"
)


@dataclass
class UpstreamCall:
    subject: Optional[str] = None
    actor: Optional[str] = None
    audience: Any = None  # str | list[str] | None — a JWT `aud` may be either
    scope: Any = None     # str (space-delimited) | list[str] | None
    token: Optional[str] = None
    # The token's issuer (`iss`). Identity is (issuer, subject): two users named
    # "alice" from different login providers are different principals, and a
    # deputy that keys on subject alone would conflate them.
    issuer: Optional[str] = None
    # The upstream resource server sets this False when it received a token it
    # could not validate or decode. Such a call is *inconclusive*, not a leak:
    # the probe cannot read the delegated identity, so it makes no claim.
    parsed: bool = True
    parse_error: Optional[str] = None
    # The MCP method the upstream served this call under. A gateway makes
    # non-user calls too (registration, tools/list discovery, health, refresh)
    # on a separate credential; only tools/call (and resources/read) carry the
    # per-user exchange, so the probe grades those and ignores the rest.
    method: str = "tools/call"


def _as_set(value: Any) -> set:
    """Normalize a JWT audience/scope claim to a set of strings.

    Accepts a list, a single string, or a space-delimited string (the OAuth
    scope encoding); ``None`` and empties collapse to the empty set.
    """
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(v) for v in value if v is not None}
    text = str(value).strip()
    if not text:
        return set()
    return set(text.split())


class MockUpstream:
    """An upstream API you control; records the delegated identity of each call."""

    def __init__(self, audience: str):
        self.expected_audience = audience
        self.calls: List[UpstreamCall] = []

    def receive(
        self,
        *,
        subject: Optional[str] = None,
        actor: Optional[str] = None,
        audience: Any = None,
        scope: Any = None,
        token: Optional[str] = None,
        issuer: Optional[str] = None,
        parsed: bool = True,
        parse_error: Optional[str] = None,
        method: str = "tools/call",
    ) -> None:
        self.calls.append(
            UpstreamCall(
                subject=subject,
                actor=actor,
                audience=audience,
                scope=scope,
                token=token,
                issuer=issuer,
                parsed=parsed,
                parse_error=parse_error,
                method=method,
            )
        )

    def graded_calls(self) -> List[UpstreamCall]:
        """Only the calls the probe grades: per-user tool and resource calls."""
        return [c for c in self.calls if c.method in ("tools/call", "resources/read")]


@dataclass
class DelegationReport:
    target: str
    authorization: str
    identity_a: str
    identity_b: str
    checks: Dict[str, bool]
    failures: List[str]
    vulnerable: bool
    detail: str
    calls: Any = field(default=None, repr=False)

    def failure_class(self) -> str:
        """The class of problem, matched to which checks failed.

        A missing actor alone is *impersonation* (the acting agent is not
        identified), not a dropped/forged subject — call it what it is.
        """
        if self.failures == ["actor_present"]:
            return ("impersonation: the exchanged token carries no acting-agent "
                    "('act') claim, so the agent acting for the user is invisible")
        return FAILURE_CLASS

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "probe": "delegation",
            "target": self.target,
            "authorization": self.authorization,
            "identity_a": self.identity_a,
            "identity_b": self.identity_b,
            "checks": self.checks,
            "failures": self.failures,
            "vulnerable": self.vulnerable,
            "detail": self.detail,
        }
        if self.vulnerable:
            data["failure_class"] = self.failure_class()
        return data

    def summary(self) -> str:
        if self.vulnerable:
            return (
                f"LEAK: delegation integrity failed ({', '.join(self.failures)}) "
                f"between {self.identity_a!r} and {self.identity_b!r} — {self.failure_class()}."
            )
        return (
            "OK: delegation preserved subject and actor, used the correct audience "
            "and a narrowed scope, and minted a distinct token per principal."
        )


def run_delegation_probe(
    target: str,
    identity_a: Identity,
    identity_b: Identity,
    *,
    upstream: MockUpstream,
    trigger: Callable[[MCPClient], Any],
    expected_subject_a: str,
    expected_subject_b: str,
    expected_issuer_a: Optional[str] = None,
    expected_issuer_b: Optional[str] = None,
    disallowed_scopes: Iterable[str] = ("admin", "full", "*", "root"),
    require_actor: bool = True,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> DelegationReport:
    """Drive the target as A, B, then A again; inspect what reached ``upstream``.

    ``trigger`` is given a connected client and must cause the target to make
    its on-behalf-of upstream call. Authorized first, like every probe. The
    A, B, A order is load-bearing: the second A call, on the same connection
    after B, catches a deputy that cached or bled B's token into A's request.
    Only the per-user upstream calls (tools/call, resources/read) are graded.

    ``require_actor`` controls whether a missing ``act`` claim counts as a
    failure. RFC 8693 *delegation* carries the acting agent in ``act``;
    *impersonation* deliberately omits it. Leave it True to hold a server to
    delegation (the acting agent must be identifiable); set it False to test a
    server that impersonates by design, where the actor check is reported but
    not counted against it.

    If the authoritative upstream call for either principal arrived with a
    token the upstream could not validate or decode (``parsed is False``), the
    probe raises :class:`ProbeError`: that is inconclusive, never "no leak" and
    never a forged-delegation finding.
    """
    decision = authorize(
        target, authorized=authorized, authorization_note=authorization_note
    )

    def leg(client: MCPClient, label: str) -> UpstreamCall:
        """Trigger one on-behalf-of call and return the tool/resource call it drove.

        Grades only the per-user call (tools/call or resources/read); a gateway's
        discovery/registration/health traffic on its own credential is ignored.
        """
        seen = len(upstream.calls)
        trigger(client)
        new = upstream.calls[seen:]
        graded = [c for c in new if c.method in ("tools/call", "resources/read")]
        if not graded:
            raise ProbeError(
                f"target made no per-user upstream call for {label!r}; probe "
                f"inconclusive (is the server pointed at the upstream, and did "
                f"the trigger cause a tools/call?)"
            )
        return graded[-1]

    client_a = identity_a.connect()
    client_b: Optional[MCPClient] = None
    try:
        client_a.initialize()
        client_b = identity_b.connect()
        client_b.initialize()
        # A, then B, then A again on the SAME A connection: the second A call
        # catches a deputy that cached or bled B's token into A's next call.
        call_a = leg(client_a, identity_a.label)
        call_b = leg(client_b, identity_b.label)
        call_a2 = leg(client_a, identity_a.label)
    finally:
        _safe_close(client_a)
        if client_b is not None:
            _safe_close(client_b)

    # An undecodable token on any graded call means the upstream could not read
    # the delegated identity at all: inconclusive, not a verdict.
    for label, call in (
        (identity_a.label, call_a),
        (identity_b.label, call_b),
        (identity_a.label, call_a2),
    ):
        if not call.parsed:
            raise ProbeError(
                f"the upstream could not validate/decode {label!r}'s delegated "
                f"token ({call.parse_error or 'unparseable'}); the probe is "
                f"inconclusive (not 'no leak', not a forged-delegation finding)."
            )

    disallowed = {s.lower() for s in disallowed_scopes}

    def scope_narrowed(call: UpstreamCall) -> bool:
        # A broad/admin scope present is the failure. An absent scope is not a
        # broadening we can prove, so it does not fail this check.
        return not ({s.lower() for s in _as_set(call.scope)} & disallowed)

    def audience_ok(call: UpstreamCall) -> bool:
        return upstream.expected_audience in _as_set(call.audience)

    actor_ok = bool(call_a.actor) and bool(call_b.actor) and bool(call_a2.actor)

    def is_a(call: UpstreamCall) -> bool:
        # Identity is (issuer, subject) when an issuer is expected, so a same-
        # named user from another provider is not mistaken for A.
        if call.subject != expected_subject_a:
            return False
        return expected_issuer_a is None or call.issuer == expected_issuer_a

    def is_b(call: UpstreamCall) -> bool:
        if call.subject != expected_subject_b:
            return False
        return expected_issuer_b is None or call.issuer == expected_issuer_b

    checks = {
        "subject_preserved": is_a(call_a) and is_b(call_b) and is_a(call_a2),
        "actor_present": actor_ok,
        "audience_correct": audience_ok(call_a)
        and audience_ok(call_b)
        and audience_ok(call_a2),
        "scope_narrowed": scope_narrowed(call_a)
        and scope_narrowed(call_b)
        and scope_narrowed(call_a2),
        "no_token_reuse": bool(call_a.token)
        and bool(call_b.token)
        and call_a.token != call_b.token,
        # A's second call (after B) must still be A, on a token that is not B's:
        # catches a deputy that cached or bled B's exchanged token into A's call.
        "no_cross_identity_bleed": is_a(call_a2)
        and call_a2.token != call_b.token,
    }
    # actor_present is advisory when the caller allows impersonation.
    counted = {name: ok for name, ok in checks.items()
               if require_actor or name != "actor_present"}
    failures = [name for name, ok in counted.items() if not ok]
    vulnerable = bool(failures)

    return DelegationReport(
        target=decision.target,
        authorization=decision.reason,
        identity_a=identity_a.label,
        identity_b=identity_b.label,
        checks=checks,
        failures=failures,
        vulnerable=vulnerable,
        detail="delegation was dropped or forged: " + ", ".join(failures)
        if vulnerable
        else "delegation preserved across both principals",
        calls=[vars(call_a), vars(call_b), vars(call_a2)],
    )


def _safe_close(client: MCPClient) -> None:
    try:
        client.close()
    except Exception:
        pass
