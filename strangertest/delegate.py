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
    # Scope narrowing (CoSAI MCP Security v2.0, 3.3.2) and issuer binding
    # (CoSAI 3.2.2 / 3.3.2): separate checks with their own 3-grade results.
    "token_fingerprint",
    "grade_scope_call",
    "combine_scope_grades",
    "ScopeNarrowingResult",
    "run_scope_narrowing_probe",
    "observe_one_call",
    "IssuerBindingResult",
    "grade_issuer_unregistered",
    "run_issuer_unregistered_probe",
    "grade_issuer_email_crossprovider",
    "gate_run_problems",
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
    # The per-request nonce the probe put in the tool arguments (or resource
    # URI) and the upstream read back out, so each upstream call can be tied to
    # the client request that caused it. None = not sent or not forwarded.
    nonce: Optional[str] = None


def request_nonce(params: Any) -> Optional[str]:
    """The probe nonce in a forwarded MCP request's params: ``arguments.nonce``
    for tools/call, or a ``nonce`` query parameter on a resources/read URI."""
    if not isinstance(params, dict):
        return None
    args = params.get("arguments")
    if isinstance(args, dict) and isinstance(args.get("nonce"), str):
        return args["nonce"]
    uri = params.get("uri")
    if isinstance(uri, str) and "nonce=" in uri:
        from urllib.parse import parse_qs, urlsplit
        vals = parse_qs(urlsplit(uri).query).get("nonce")
        if vals:
            return vals[0]
    return None


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
        nonce: Optional[str] = None,
    ) -> None:
        self.calls.append(
            UpstreamCall(
                nonce=nonce,
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


# ===========================================================================
# Scope narrowing and issuer binding (XID-10 additions).
#
# These are NEW checks with their own results. They do not touch the six
# checks above: ``scope_narrowed`` keeps its old meaning (no broad/admin scope
# at the upstream) and every existing DelegationReport is unchanged.
#
# Grades: FAIL (= a leak was observed), OK, INCONCLUSIVE, and OBSERVATION
# (a fact we report without calling it a pass or a leak). A leak that is
# observed is FAIL whatever the controls say; controls only decide whether OK
# (or an OBSERVATION) may stand. Nothing is OK that was not observed.
#
# --- SCOPE NARROWING (CoSAI MCP Security v2.0, 3.3.2) ----------------------
# Per graded upstream call, compare (a) the subject token's scope, (b) the
# ``scope`` the deputy sent in its exchange request (None = parameter absent),
# (c) what the AS issued, (d) what reached the upstream:
#   * (d) holds anything (a) lacks                          -> FAIL scope_exceeded
#   * (c) known and (d) holds anything (c) lacks             -> FAIL scope_exceeds_issued
#   * (d) narrower than (a) AND equal to (b)                 -> OK narrowed
#   * (d) equal to (a) because (b) was absent (or was (a))   -> OBSERVATION not_narrowed
#   * anything else (narrower but != (b), AS narrowed alone, -> INCONCLUSIVE
#     claim absent, token undecodable, request not observed)
#
# Ways this check could lie, and the unit test that pins each
# (tests/test_scope_issuer.py):
#   False FAIL
#   S1 scope as a JSON list vs a space-delimited string, or in another order
#      -> compared as sets.                  test_scope_list_vs_string_order_is_not_a_fail
#   S2 discovery / registration traffic on the gateway's own credential
#      (tools/list) carrying a broad scope, i.e. state that changes with no
#      user acting -> only tools/call and resources/read are graded.
#                                             test_discovery_traffic_with_broad_scope_ignored
#   S3 a failing control (e.g. broken fixture not run) turned into a FAIL
#      -> controls never produce FAIL.        test_failed_control_never_produces_fail
#   False OK
#   S4 the AS narrowed on its own while the gateway asked for nothing
#      -> INCONCLUSIVE, never OK.             test_as_alone_narrowed_is_not_ok
#   S5 subject scope equal to the configured scope, so narrowing cannot be
#      seen -> control subject_scope_broader_than_configured.
#                                             test_subject_not_broader_is_inconclusive
#   S6 scope claim absent at the upstream -> INCONCLUSIVE.
#                                             test_scope_claim_absent_is_inconclusive
#   S7 token undecodable at the upstream -> INCONCLUSIVE.
#                                             test_undecodable_token_is_inconclusive
#   S8 feature not supported / request refused as malformed: no per-user
#      upstream call at all -> INCONCLUSIVE.  test_no_upstream_call_is_inconclusive
#   S9 broken fixture never shown to fail in this run -> INCONCLUSIVE.
#                                             test_broken_fixture_not_shown_blocks_ok
#   S10 one call fine, another exceeded -> FAIL (worst call wins).
#                                             test_one_exceeded_call_fails_the_run
#   S11 exchange request not observed (no AS record for the token)
#      -> cannot say who narrowed -> INCONCLUSIVE.
#                                             test_request_not_observed_is_inconclusive
#   S12 narrower than the subject but not what was requested -> INCONCLUSIVE.
#                                             test_narrower_but_not_requested_is_inconclusive
#   S13 a seen leak downgraded by failing controls -> stays FAIL.
#                                             test_seen_scope_leak_not_downgraded_by_controls
#   Missed FAIL
#   S14 the AS granted a narrower scope, but the upstream saw more than the
#      grant (the subject token forwarded, or the grant widened) -> FAIL
#      scope_exceeds_issued, even when (d) equals (a).
#                                             test_full_subject_scope_after_narrower_grant_is_fail
#                                             test_any_superset_of_grant_is_fail
#
# --- ISSUER BINDING (CoSAI 3.2.2 / 3.3.2) ---------------------------------
# Test A: a user token signed by a TRUSTED key but carrying an UNREGISTERED
# issuer. Every request (control before, probe, control after) carries its
# own nonce in the tool arguments, and the upstream records it, so each
# upstream call is tied to the request that caused it, whenever it arrives.
# FAIL = the probe request returned a successful result, OR any upstream call
# carried the probe's nonce (whatever identity it carried), OR a nonce-less
# call is tied to the probe token. OK = refused, nothing with the probe's
# nonce reached the upstream, AND both controls reached it with theirs.
#
# Ways this check could lie, and the pinning test:
#   False FAIL
#   I1 unrelated traffic reaching the upstream while nobody acts -> a call
#      with no known nonce is never blamed on the probe; it is INCONCLUSIVE
#      (a call tied to the probe token is still FAIL).
#                                             test_unattributed_unlinked_call_is_inconclusive
#                                             test_unattributed_linked_call_fails
#   I2 a failing control turned into a FAIL. test_issuer_control_failure_never_fails
#   I9 a DELAYED control call landing while the probe is in flight -> it
#      carries the control's nonce, so it is the control's.
#                                             test_delayed_control_call_attributed_by_nonce
#   I10 a refusal inside a tool result (isError) read as success.
#                                             test_tool_error_result_is_a_refusal
#   False OK
#   I3 refusal caused by a malformed request, not by the issuer -> positive
#      control must reach the upstream.       test_control_not_reached_is_inconclusive
#   I4 feature not supported (gateway makes no per-user call at all) -> same
#      positive control.                      test_control_not_reached_is_inconclusive
#   I5 the gateway broke mid-run -> control repeated after the probe.
#                                             test_control_after_failing_is_inconclusive
#   I6 the AS (not the gateway) stopped it: the gateway passed the token to the
#      exchange -> INCONCLUSIVE.              test_exchange_attempted_is_not_ok
#   I7 broken fixture never shown to fail -> INCONCLUSIVE.
#                                             test_issuer_broken_fixture_not_shown_blocks_ok
#   I8 a seen leak downgraded by failing controls -> stays FAIL.
#                                             test_seen_issuer_leak_not_downgraded
#   I10 the gateway answered the probe itself, with no upstream call -> FAIL
#      on the probe's own outcome.            test_probe_success_fails_with_no_upstream_call
#   I11 the gateway swapped another identity in for the probe caller -> the
#      probe's nonce makes it FAIL whatever identity it carried.
#                                             test_probe_nonce_call_fails_whatever_identity
#   I12 the target drops the nonce -> the controls cannot be seen with their
#      nonces, so no OK.                      test_nonce_stripped_is_inconclusive_never_ok
#
# Test B (provider X token claiming an email bound to provider Y) has no rule
# of its own; it is RECORDED. The only FAIL it can produce follows the rule
# already used by the delegation probe (identity is (issuer, subject)): X's
# token reaching the upstream as Y's principal. A same-named subject under a
# different issuer is not Y (test_same_sub_other_issuer_is_not_y), and Y's
# email in the claim alone is an OBSERVATION, not a FAIL
# (test_email_alone_is_observation_not_fail).
# ===========================================================================

import hashlib as _hashlib
import re as _re
import time as _time
from typing import Tuple

GRADE_FAIL = "FAIL"
GRADE_OK = "OK"
GRADE_INCONCLUSIVE = "INCONCLUSIVE"
GRADE_OBSERVATION = "OBSERVATION"

SCOPE_COSAI = "CoSAI MCP Security v2.0, 3.3.2"
ISSUER_COSAI = "CoSAI MCP Security v2.0, 3.2.2 / 3.3.2"

_GRADED_METHODS = ("tools/call", "resources/read")
_JWT_SHAPE = _re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def token_fingerprint(token: Optional[str]) -> Optional[str]:
    """``sha256:<12 hex>``: the only form a token is ever stored in."""
    if not token:
        return None
    return "sha256:" + _hashlib.sha256(token.encode()).hexdigest()[:12]


def _redact(text: Any, limit: int = 300) -> str:
    return _JWT_SHAPE.sub(lambda m: token_fingerprint(m.group(0)) or "", str(text))[:limit]


def _call_dict(call: Any) -> Dict[str, Any]:
    d = dict(vars(call)) if not isinstance(call, dict) else dict(call)
    if "token" in d:
        d["token"] = token_fingerprint(d.get("token")) if d.get("token") and not str(
            d.get("token")).startswith("sha256:") else d.get("token")
    return d


def _scope_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(v) for v in value)
    return str(value)


def grade_scope_call(
    *,
    subject_scope: Any,
    upstream_scope: Any,
    requested_scope: Any = None,
    requested_observed: bool = False,
    issued_scope: Any = None,
    parsed: bool = True,
) -> Dict[str, Any]:
    """Grade ONE upstream call for scope narrowing; returns a plain dict.

    ``requested_scope`` None with ``requested_observed`` True means the deputy
    sent no ``scope`` parameter; ``requested_observed`` False means we did not
    see the exchange request at all.
    """
    rec: Dict[str, Any] = {
        "subject_scope": _scope_text(subject_scope),
        "requested_scope": _scope_text(requested_scope),
        "requested_observed": requested_observed,
        "issued_scope": _scope_text(issued_scope),
        "upstream_scope": _scope_text(upstream_scope),
    }
    sub = _as_set(subject_scope)
    up = _as_set(upstream_scope)
    req = _as_set(requested_scope)
    iss = _as_set(issued_scope) if issued_scope is not None else None

    # Who narrowed: a plain record of each hop, never a verdict on its own.
    who: List[str] = []
    if not requested_observed:
        who.append("exchange request not observed")
    elif requested_scope is None or not req:
        who.append("gateway requested no scope")
    else:
        who.append(f"gateway requested {rec['requested_scope']!r}")
    if iss is not None:
        who.append(f"AS issued {rec['issued_scope']!r}")
        if upstream_scope is not None and up != iss:
            who.append("upstream scope differs from what the AS issued "
                       "(the deputy did not forward the exchanged token's scope)")
    if requested_observed and not req and iss is not None and iss < sub:
        who.append("the AS alone narrowed (the gateway requested nothing)")
    elif requested_observed and req and req < sub:
        who.append("narrowing requested by the gateway")
    rec["who_narrowed"] = "; ".join(who)

    def out(grade: str, label: str, reason: str) -> Dict[str, Any]:
        rec.update(grade=grade, label=label, reason=reason)
        return rec

    if not parsed:
        return out(GRADE_INCONCLUSIVE, "inconclusive",
                   "the upstream could not decode the delegated token")
    if subject_scope is None:
        return out(GRADE_INCONCLUSIVE, "inconclusive", "subject token scope unknown")
    if upstream_scope is None:
        return out(GRADE_INCONCLUSIVE, "inconclusive",
                   "no scope claim at the upstream (not observed)")
    extra = up - sub
    if extra:
        return out(GRADE_FAIL, "scope_exceeded",
                   f"upstream scope holds {sorted(extra)} that the subject token lacked")
    over_grant = (up - iss) if iss is not None else set()
    if over_grant:
        return out(GRADE_FAIL, "scope_exceeds_issued",
                   f"scope at upstream exceeds what the AS issued: {sorted(over_grant)} "
                   f"reached the upstream but the AS granted only {rec['issued_scope']!r}")
    if up == sub:
        if not requested_observed:
            return out(GRADE_INCONCLUSIVE, "inconclusive",
                       "scope equals the subject's, but the exchange request was not observed")
        if requested_scope is None or not req:
            return out(GRADE_OBSERVATION, "not_narrowed",
                       "the gateway requested no scope, so the subject's full scope reached the upstream")
        if req == sub:
            return out(GRADE_OBSERVATION, "not_narrowed",
                       "the gateway requested the subject's full scope")
        return out(GRADE_INCONCLUSIVE, "inconclusive",
                   "the gateway requested a narrower scope but the full subject scope "
                   "reached the upstream")
    # up is a strict subset of sub
    if not requested_observed:
        return out(GRADE_INCONCLUSIVE, "inconclusive",
                   "narrower than the subject, but the exchange request was not observed")
    if requested_scope is None or not req:
        return out(GRADE_INCONCLUSIVE, "inconclusive",
                   "narrower than the subject, but the gateway requested nothing "
                   "(narrowed by someone else, not the gateway)")
    if up == req:
        return out(GRADE_OK, "narrowed",
                   "narrower than the subject and equal to what the gateway requested")
    return out(GRADE_INCONCLUSIVE, "inconclusive",
               "narrower than the subject but not equal to what the gateway requested")


@dataclass
class ScopeNarrowingResult:
    grade: str
    label: str
    reason: str
    per_call: List[Dict[str, Any]]
    controls: Dict[str, bool]
    target: str = ""
    observations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"probe": "scope_narrowing", "cosai": SCOPE_COSAI,
                "grade": self.grade, "label": self.label, "reason": self.reason,
                "target": self.target, "controls": self.controls,
                "observations": self.observations, "per_call": self.per_call}

    def summary(self) -> str:
        return f"[{self.grade}] scope narrowing: {self.label} — {self.reason}"


def combine_scope_grades(per_call: List[Dict[str, Any]],
                         controls: Dict[str, bool]) -> Tuple[str, str, str]:
    """Combine per-call grades: worst call wins; controls gate OK/OBSERVATION only."""
    if not per_call:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "no per-user upstream call was observed (feature unsupported or request refused)")
    fails = [c for c in per_call if c.get("grade") == GRADE_FAIL]
    if fails:
        # A seen leak is a FAIL whatever the controls say.
        return GRADE_FAIL, fails[0].get("label", "scope_exceeded"), fails[0]["reason"]
    inc = [c for c in per_call if c.get("grade") == GRADE_INCONCLUSIVE]
    if inc:
        return GRADE_INCONCLUSIVE, "inconclusive", inc[0]["reason"]
    failed_controls = sorted(k for k, ok in controls.items() if not ok)
    if failed_controls:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "control(s) failed: " + ", ".join(failed_controls))
    if all(c.get("grade") == GRADE_OK for c in per_call):
        return GRADE_OK, "narrowed", per_call[0]["reason"]
    obs = [c for c in per_call if c.get("grade") == GRADE_OBSERVATION]
    return GRADE_OBSERVATION, "not_narrowed", obs[0]["reason"]


def observe_one_call(identity: Identity, upstream: MockUpstream,
                     trigger: Callable[[MCPClient], Any]) -> Tuple[List[UpstreamCall], Optional[str]]:
    """Connect as ``identity``, fire ``trigger`` once, return the graded upstream
    calls it caused and the (redacted) error, if the target refused."""
    seen = len(upstream.calls)
    err: Optional[str] = None
    client = None
    try:
        client = identity.connect()
        client.initialize()
        trigger(client)
    except Exception as exc:  # a refusal is data here, not a crash
        err = _redact(f"{type(exc).__name__}: {exc}")
    finally:
        if client is not None:
            _safe_close(client)
    new = [c for c in upstream.calls[seen:] if c.method in _GRADED_METHODS]
    return new, err


def run_scope_narrowing_probe(
    target: str,
    identity_a: Identity,
    identity_b: Identity,
    *,
    upstream: MockUpstream,
    trigger: Callable[[MCPClient], Any],
    subject_scope: Any,
    configured_scope: Any,
    exchange_lookup: Callable[[Optional[str]], Optional[Dict[str, Any]]],
    controls: Optional[Dict[str, bool]] = None,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> ScopeNarrowingResult:
    """Drive A, B, A once each; grade each per-user upstream call's scope.

    ``subject_scope`` is the scope the gate put in each user's token.
    ``configured_scope`` is what the gateway is configured to request.
    ``exchange_lookup(fingerprint)`` returns the AS's record of the exchange
    that issued the token with that fingerprint (keys ``requested_scope``,
    ``issued_scope``) or None. ``controls`` must carry ``broken_fixture_failed``
    for an OK to be possible.
    """
    decision = authorize(target, authorized=authorized, authorization_note=authorization_note)
    controls = dict(controls or {})
    controls.setdefault("broken_fixture_failed", False)
    controls["subject_scope_broader_than_configured"] = (
        _as_set(configured_scope) < _as_set(subject_scope))
    per_call: List[Dict[str, Any]] = []
    observations: List[str] = []
    for ident in (identity_a, identity_b, identity_a):
        calls, err = observe_one_call(ident, upstream, trigger)
        if err:
            observations.append(f"{ident.label}: target refused/errored: {err}")
        if not calls:
            observations.append(f"{ident.label}: no per-user upstream call")
        for call in calls:
            fp = token_fingerprint(call.token)
            rec = exchange_lookup(fp) if call.parsed else None
            g = grade_scope_call(
                subject_scope=subject_scope, upstream_scope=call.scope,
                requested_scope=(rec or {}).get("requested_scope"),
                requested_observed=rec is not None,
                issued_scope=(rec or {}).get("issued_scope"), parsed=call.parsed)
            g.update(principal=ident.label, method=call.method, token=fp,
                     subject=call.subject, issuer=call.issuer,
                     exchange_actor_present=(rec or {}).get("actor_present"),
                     exchange_requested_audience=(rec or {}).get("requested_audience"))
            per_call.append(g)
    expected_calls = 3
    if per_call and len({(c["principal"]) for c in per_call}) < 2:
        observations.append("only one principal produced upstream calls")
    grade, label, reason = combine_scope_grades(per_call, controls)
    if grade != GRADE_FAIL and len(per_call) < expected_calls:
        grade, label, reason = (GRADE_INCONCLUSIVE, "inconclusive",
                                f"only {len(per_call)} of {expected_calls} legs reached the upstream")
    return ScopeNarrowingResult(grade=grade, label=label, reason=reason, per_call=per_call,
                                controls=controls, target=decision.target,
                                observations=observations)


@dataclass
class IssuerBindingResult:
    probe: str
    grade: str
    label: str
    reason: str
    controls: Dict[str, bool]
    evidence: Dict[str, Any] = field(default_factory=dict)
    target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"probe": self.probe, "cosai": ISSUER_COSAI, "grade": self.grade,
                "label": self.label, "reason": self.reason, "target": self.target,
                "controls": self.controls, "evidence": self.evidence}

    def summary(self) -> str:
        return f"[{self.grade}] {self.probe}: {self.label} — {self.reason}"


def grade_issuer_unregistered(
    *,
    probe_succeeded: Optional[bool],
    probe_calls: List[Dict[str, Any]],
    unattributed_calls: List[Dict[str, Any]],
    control_before: bool,
    control_after: bool,
    exchange_attempted: Optional[bool],
    controls: Dict[str, bool],
    quiet_baseline_calls: int = 0,
) -> Tuple[str, str, str]:
    """Grade Test A.

    ``probe_succeeded``: the unregistered-issuer request's own outcome (True =
    a successful result came back; None = unknown). ``probe_calls``: graded
    upstream calls carrying the PROBE request's nonce. ``unattributed_calls``:
    graded upstream calls in the run that carry no known nonce, each with a
    ``linked`` bool (tied to the probe token by fingerprint, exchange record or
    issuer). Calls carrying a control's nonce are the control's, whenever they
    arrive, so they never reach this function as probe evidence."""
    if probe_succeeded:
        return (GRADE_FAIL, "unregistered_issuer_request_succeeded",
                "the request with the unregistered issuer returned a successful result")
    if probe_calls:
        idents = sorted({(str(c.get("issuer")), str(c.get("subject"))) for c in probe_calls})
        return (GRADE_FAIL, "unregistered_issuer_reached_upstream",
                f"{len(probe_calls)} upstream call(s) carried the unregistered-issuer "
                f"request's nonce (identity at the upstream: {idents})")
    linked = [c for c in unattributed_calls if c.get("linked")]
    if linked:
        return (GRADE_FAIL, "unregistered_issuer_reached_upstream",
                f"{len(linked)} upstream call(s) without a nonce carried the "
                "unregistered-issuer principal or token")
    if unattributed_calls:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                f"{len(unattributed_calls)} upstream call(s) carried no known nonce and "
                "cannot be tied to any request (quiet baseline: "
                f"{quiet_baseline_calls} call(s))")
    if probe_succeeded is None:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "the unregistered-issuer request's own outcome is unknown")
    if not control_before:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "positive control (registered issuer, otherwise identical) did not reach "
                "the upstream with its nonce: a refusal cannot be attributed to the issuer")
    if not control_after:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "positive control failed after the probe: the target may have broken mid-run")
    if exchange_attempted is None:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "the AS exchange log was not observed, so who refused is unknown")
    if exchange_attempted:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "the gateway passed the unregistered-issuer token on to the token "
                "exchange; it was stopped later, not by the gateway")
    failed = sorted(k for k, ok in controls.items() if not ok)
    if failed:
        return (GRADE_INCONCLUSIVE, "inconclusive", "control(s) failed: " + ", ".join(failed))
    return (GRADE_OK, "rejected",
            "the gateway refused the unregistered issuer before any exchange, and nothing "
            "reached the upstream; the registered-issuer control did reach it")


def make_nonce(tag: str) -> str:
    """A unique per-request nonce, safe to put in tool arguments or a URI."""
    import secrets
    return f"st-{tag}-{secrets.token_hex(6)}"


def observe_nonce_call(identity: Identity,
                       trigger: Callable[[MCPClient, str], Any],
                       nonce: str) -> Tuple[Optional[bool], Optional[str]]:
    """Connect as ``identity`` and fire ``trigger(client, nonce)`` once.

    Returns (succeeded, redacted error). ``succeeded`` is True only when a
    result came back that is not a tool error (``isError``); a JSON-RPC error,
    a transport error or ``isError: true`` is a refusal."""
    client = None
    try:
        client = identity.connect()
        client.initialize()
        result = trigger(client, nonce)
    except Exception as exc:  # a refusal is data here, not a crash
        return False, _redact(f"{type(exc).__name__}: {exc}")
    finally:
        if client is not None:
            _safe_close(client)
    if isinstance(result, dict) and result.get("isError"):
        return False, _redact(f"tool error result: {result.get('content')}")
    return True, None


def run_issuer_unregistered_probe(
    target: str,
    *,
    control_identity: Identity,
    probe_identity: Identity,
    upstream: MockUpstream,
    trigger: Callable[[MCPClient, str], Any],
    probe_token_fp: Optional[str],
    probe_issuer: str,
    exchange_records: Optional[Callable[[], List[Dict[str, Any]]]],
    controls: Optional[Dict[str, bool]] = None,
    quiet_seconds: float = 1.0,
    settle_seconds: float = 0.0,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> IssuerBindingResult:
    """Test A: quiet baseline, control, probe (unregistered issuer), control.

    ``trigger(client, nonce)`` must put ``nonce`` in the request (a tool
    argument or the resource URI) and the upstream must record it
    (``MockUpstream.receive(nonce=...)``), so every upstream call is tied to the
    request that caused it. ``settle_seconds`` waits after the last request
    before the calls are attributed."""
    decision = authorize(target, authorized=authorized, authorization_note=authorization_note)
    controls = dict(controls or {})
    controls.setdefault("broken_fixture_failed", False)
    n0 = len(upstream.calls)
    if quiet_seconds > 0:
        _time.sleep(quiet_seconds)
    quiet = len([c for c in upstream.calls[n0:] if c.method in _GRADED_METHODS])
    n1 = len(upstream.calls)

    nonces = {"control_before": make_nonce("cb"), "probe": make_nonce("probe"),
              "control_after": make_nonce("ca")}
    before_ok, before_err = observe_nonce_call(control_identity, trigger,
                                               nonces["control_before"])
    ex_before = len(exchange_records()) if exchange_records else 0
    probe_ok, probe_err = observe_nonce_call(probe_identity, trigger, nonces["probe"])
    new_ex = exchange_records()[ex_before:] if exchange_records else None
    after_ok, after_err = observe_nonce_call(control_identity, trigger,
                                             nonces["control_after"])
    if settle_seconds > 0:
        _time.sleep(settle_seconds)

    probe_issued = set()
    exchange_attempted: Optional[bool] = None
    if new_ex is not None:
        mine = [r for r in new_ex if r.get("subject_fp") == probe_token_fp]
        exchange_attempted = bool(mine)
        probe_issued = {r.get("issued_fp") for r in mine if r.get("issued_fp")}

    by_nonce: Dict[str, List[Dict[str, Any]]] = {k: [] for k in nonces}
    unattributed: List[Dict[str, Any]] = []
    owner = {v: k for k, v in nonces.items()}
    for c in upstream.calls[n1:]:
        if c.method not in _GRADED_METHODS:
            continue
        d = _call_dict(c)
        d["linked"] = (d.get("token") == probe_token_fp or d.get("token") in probe_issued
                       or c.issuer == probe_issuer)
        if c.nonce in owner:
            by_nonce[owner[c.nonce]].append(d)
        else:
            unattributed.append(d)
    before, after = by_nonce["control_before"], by_nonce["control_after"]
    grade, label, reason = grade_issuer_unregistered(
        probe_succeeded=probe_ok, probe_calls=by_nonce["probe"],
        unattributed_calls=unattributed, control_before=bool(before),
        control_after=bool(after), exchange_attempted=exchange_attempted,
        controls=controls, quiet_baseline_calls=quiet)
    controls_out = dict(controls, control_before_reached=bool(before),
                        control_after_reached=bool(after), quiet_baseline=(quiet == 0))
    evidence = {
        "probe_issuer": probe_issuer, "probe_token": probe_token_fp,
        "nonces": nonces,
        "probe_succeeded": probe_ok, "probe_error": probe_err,
        "probe_upstream_calls": by_nonce["probe"],
        "unattributed_calls": unattributed,
        "control_before_succeeded": before_ok,
        "control_before_calls": before, "control_before_error": before_err,
        "control_after_succeeded": after_ok,
        "control_after_calls": after, "control_after_error": after_err,
        "quiet_baseline_calls": quiet, "quiet_seconds": quiet_seconds,
        "exchange_attempted_with_probe_token": exchange_attempted,
        "exchange_records_for_probe_token": [
            r for r in (new_ex or []) if r.get("subject_fp") == probe_token_fp],
    }
    return IssuerBindingResult(probe="issuer_unregistered", grade=grade, label=label,
                               reason=reason, controls=controls_out, evidence=evidence,
                               target=decision.target)


def grade_issuer_email_crossprovider(
    *,
    probe_calls: List[Dict[str, Any]],
    control_reached: bool,
    x_issuer: str,
    y_issuer: str,
    y_subject: str,
    claimed_email: str,
) -> Tuple[str, str, str]:
    """Test B: provider X's token claiming an email bound to provider Y.

    Recorded, not judged by a new rule. FAIL only when X's token reached the
    upstream AS Y's principal (identity = (issuer, subject)); otherwise an
    OBSERVATION of what happened, or INCONCLUSIVE without a working control.
    """
    as_y = [c for c in probe_calls
            if c.get("issuer") == y_issuer and c.get("subject") == y_subject]
    if as_y:
        return (GRADE_FAIL, "x_token_acted_as_y",
                f"provider X's token reached the upstream as provider Y's principal "
                f"({y_issuer}, {y_subject})")
    if probe_calls:
        idents = sorted({(str(c.get("issuer")), str(c.get("subject"))) for c in probe_calls})
        emails = sorted({str(c.get("email")) for c in probe_calls})
        return (GRADE_OBSERVATION, "accepted_as_x",
                f"accepted; the upstream saw identity {idents} (X's own), with email "
                f"claim {emails}" + (" — Y's email carried in X's identity"
                                     if claimed_email in emails else ""))
    if not control_reached:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "refused, but the control (provider X token with its own email) did not "
                "reach the upstream either")
    return (GRADE_OBSERVATION, "rejected",
            "refused: nothing reached the upstream, while provider X's token with its "
            "own email did")


# Positive controls a gate run must pass to be a VALID run. A run with a
# failed control is still saved (its grade stays honest), but the gate marks
# it run_valid=False and exits non-zero.
_REQUIRED_CONTROLS = (
    "subject_scope_broader_than_configured",
    "control_before_reached",
    "control_after_reached",
    "y_reached_upstream",
    "x_control_reached_upstream",
)


def gate_run_problems(payload: Dict[str, Any]) -> List[str]:
    """Problems that make a saved gate run invalid (empty list = valid):
    the in-gate broken fixture did not FAIL, or a positive control failed."""
    problems: List[str] = []
    broken = payload.get("broken_fixture")
    if broken is not None and broken.get("grade") != GRADE_FAIL:
        problems.append(f"broken fixture {broken.get('name')!r} gave {broken.get('grade')}, "
                        "not FAIL: this run cannot show the check can fail")
    controls = payload.get("controls") or {}
    for name in _REQUIRED_CONTROLS:
        if name in controls and not controls[name]:
            problems.append(f"positive control {name} failed")
    return problems
