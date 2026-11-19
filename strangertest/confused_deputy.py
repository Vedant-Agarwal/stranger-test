"""The confused-deputy / token-passthrough confirming probe.

Everyone writes about the confused deputy; this probe *observes* it. When an MCP
server (a "deputy") acts on a caller's behalf toward an upstream API, it must
mint a token for THAT upstream carrying the caller's identity. Two well-known
ways it goes wrong, both forbidden:

* **token passthrough** — the deputy forwards the caller's *inbound* token to the
  upstream unchanged, or with an audience that was never issued for that
  upstream. The MCP authorization spec is explicit that a server MUST NOT accept
  or forward a token that was not issued for it. We catch this by owning the
  upstream and comparing the token that arrives against the one the caller
  presented: same fingerprint, or a wrong ``aud``, is the leak.

* **confused deputy (own authority)** — on a request the caller's narrow /
  wrong-audience token does not authorize, the deputy reaches for its OWN
  (higher) service-account credential instead of refusing. We catch this when
  the token at the upstream carries the DEPUTY's own subject, not the caller's.

Like the delegation probe (:mod:`strangertest.delegate`), B never reads anything
and nothing is trusted but what arrives at a :class:`~strangertest.delegate.MockUpstream`
we control. So this can only test a deputy whose upstream you can point at the
mock — a server you operate — which is exactly the authorized-only rule.

Grades (three, and only three):

* ``FAIL``         — a leak was OBSERVED: the inbound token (or a wrong-audience
                     token) reached the upstream, or the deputy acted on the
                     caller's under-scoped request with its own authority.
* ``OK``           — the deputy either exchanged to the correct audience with the
                     caller's identity preserved, OR refused the request and made
                     no upstream call (while a benign control proved it can reach
                     the upstream). Only ever stands when the in-run broken
                     fixture was shown to FAIL and the positive control passed.
* ``INCONCLUSIVE`` — nothing was observed, the upstream could not decode the
                     token, a control failed, or the broken fixture was not shown
                     to fail in this run.

A FAIL that was observed is a FAIL whatever the controls say; controls only
decide whether an OK (or a refusal) may stand. Nothing is OK that was not
observed. Tokens are only ever handled as ``sha256:`` fingerprints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .delegate import (
    GRADE_FAIL,
    GRADE_INCONCLUSIVE,
    GRADE_OK,
    MockUpstream,
    observe_one_call,
    token_fingerprint,
)
from .guard import authorize
from .mcp_client import MCPClient
from .probe import Identity

__all__ = [
    "CallerSpec",
    "ConfusedDeputyResult",
    "grade_confused_deputy_call",
    "combine_confused_deputy_grades",
    "run_confused_deputy_probe",
    "token_fingerprint",
]

SPEC_REF = (
    "MCP Authorization (token passthrough forbidden: a server MUST NOT forward a "
    "token not issued for it) / CoSAI MCP Security v2.0 (confused deputy)"
)

# The deputy's own service-account subject(s) a real confused deputy would reach
# for. The caller can override; this is only the default the practice fixture
# uses.
DEFAULT_DEPUTY_SUBJECTS = ("svc-deputy",)


def _aud_set(value: Any) -> set:
    """Normalize a JWT ``aud`` (list | str | None) to a set of strings."""
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(v) for v in value if v is not None}
    text = str(value).strip()
    return set(text.split()) if text else set()


def _scope_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(v) for v in value)
    return str(value)


@dataclass
class CallerSpec:
    """One caller of the deputy: how to connect, and the identity that connection
    carries. ``inbound_token_fp`` is the ``sha256:`` fingerprint of the token the
    caller presents to the deputy, so a passthrough can be recognised when that
    same fingerprint turns up at the upstream. ``subject`` is the ``sub`` claim in
    that inbound token (the identity the upstream should see on the caller's
    behalf)."""

    identity: Identity
    subject: str
    inbound_token_fp: Optional[str]


def grade_confused_deputy_call(
    *,
    caller_subject: Optional[str],
    inbound_token_fp: Optional[str],
    upstream_subject: Optional[str],
    upstream_audience: Any,
    upstream_scope: Any,
    upstream_token_fp: Optional[str],
    expected_audience: str,
    deputy_subjects: Any = DEFAULT_DEPUTY_SUBJECTS,
    parsed: bool = True,
) -> Dict[str, Any]:
    """Grade ONE upstream call the deputy made on a caller's behalf.

    Returns a plain dict with ``grade`` / ``label`` / ``reason`` and the observed
    facts. Order matters: the most specific, strongest leak wins. A token the
    upstream could not decode is INCONCLUSIVE, never a verdict.
    """
    deps = {str(s) for s in deputy_subjects}
    aud = _aud_set(upstream_audience)
    rec: Dict[str, Any] = {
        "caller_subject": caller_subject,
        "inbound_token": inbound_token_fp,
        "upstream_subject": upstream_subject,
        "upstream_audience": upstream_audience,
        "upstream_scope": _scope_text(upstream_scope),
        "upstream_token": upstream_token_fp,
        "expected_audience": expected_audience,
    }

    def out(grade: str, label: str, reason: str) -> Dict[str, Any]:
        rec.update(grade=grade, label=label, reason=reason)
        return rec

    if not parsed:
        return out(GRADE_INCONCLUSIVE, "inconclusive",
                   "the upstream could not decode the token that arrived")

    # (1) TOKEN PASSTHROUGH: the caller's own inbound token reached the upstream.
    if inbound_token_fp and upstream_token_fp and upstream_token_fp == inbound_token_fp:
        return out(GRADE_FAIL, "token_passthrough",
                   "the caller's inbound token reached the upstream unchanged "
                   f"(same fingerprint {upstream_token_fp}); the deputy forwarded a "
                   "token not issued for this upstream")

    # (1b) WRONG AUDIENCE: a token minted for something other than this upstream.
    if upstream_audience is not None and expected_audience not in aud:
        return out(GRADE_FAIL, "wrong_audience",
                   f"the token at the upstream carries audience {sorted(aud)}, not "
                   f"{expected_audience!r}; it was not issued for this upstream")

    # (2) CONFUSED DEPUTY: the deputy acted with its OWN service credential.
    if upstream_subject in deps and upstream_subject != caller_subject:
        return out(GRADE_FAIL, "own_authority",
                   f"the token at the upstream is the deputy's own account "
                   f"({upstream_subject!r}), not the caller {caller_subject!r}: the "
                   "deputy used its own (higher) authority instead of refusing")

    # OK: a faithful exchange — caller's identity, this upstream's audience, and a
    # freshly minted token (not the inbound one).
    if (upstream_subject == caller_subject
            and expected_audience in aud
            and (not inbound_token_fp or upstream_token_fp != inbound_token_fp)):
        return out(GRADE_OK, "exchanged",
                   "the deputy minted a fresh token for this upstream carrying the "
                   "caller's identity")

    # Anything else we cannot call a pass or a leak.
    if upstream_subject not in (caller_subject, None) and upstream_subject not in deps:
        return out(GRADE_INCONCLUSIVE, "inconclusive",
                   f"the upstream saw subject {upstream_subject!r}, neither the caller "
                   f"{caller_subject!r} nor a known deputy account {sorted(deps)}")
    if upstream_audience is None:
        return out(GRADE_INCONCLUSIVE, "inconclusive",
                   "no audience claim at the upstream: cannot tell the token was "
                   "minted for this upstream")
    return out(GRADE_INCONCLUSIVE, "inconclusive",
               "the upstream call did not clearly preserve the caller's identity "
               "nor match a known leak shape")


def combine_confused_deputy_grades(
    per_call: List[Dict[str, Any]],
    controls: Dict[str, bool],
    *,
    control_reached: bool,
) -> Tuple[str, str, str]:
    """Combine the per-call grades into one verdict.

    Worst call wins. A seen leak is FAIL whatever the controls say. An OK (an
    exchange that stood, or a deliberate refusal) requires every control to have
    passed — which includes the in-run broken fixture having FAILED.
    """
    if per_call:
        fails = [c for c in per_call if c.get("grade") == GRADE_FAIL]
        if fails:
            return GRADE_FAIL, fails[0]["label"], fails[0]["reason"]
        inc = [c for c in per_call if c.get("grade") == GRADE_INCONCLUSIVE]
        if inc:
            return GRADE_INCONCLUSIVE, "inconclusive", inc[0]["reason"]
        failed = sorted(k for k, ok in controls.items() if not ok)
        if failed:
            return (GRADE_INCONCLUSIVE, "inconclusive",
                    "control(s) failed: " + ", ".join(failed))
        return (GRADE_OK, "exchanged",
                "every on-behalf-of call preserved the caller's identity and the "
                "upstream's own audience")

    # No sensitive upstream call at all: either a deliberate refusal, or the
    # harness could not observe anything.
    if not control_reached:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "the deputy made no upstream call for the sensitive request AND the "
                "benign positive control did not reach the upstream either (feature "
                "unsupported, request malformed, or the harness is blind)")
    failed = sorted(k for k, ok in controls.items() if not ok)
    if failed:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "control(s) failed: " + ", ".join(failed))
    return (GRADE_OK, "refused",
            "the deputy made no upstream call for the sensitive request while the "
            "benign control did reach the upstream: a deliberate refusal, not a leak")


@dataclass
class ConfusedDeputyResult:
    grade: str
    label: str
    reason: str
    per_call: List[Dict[str, Any]]
    controls: Dict[str, bool]
    target: str = ""
    observations: List[str] = field(default_factory=list)
    broken_fixture: Optional[Dict[str, Any]] = None

    @property
    def vulnerable(self) -> bool:
        return self.grade == GRADE_FAIL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probe": "confused_deputy",
            "spec": SPEC_REF,
            "grade": self.grade,
            "label": self.label,
            "reason": self.reason,
            "target": self.target,
            "controls": self.controls,
            "observations": self.observations,
            "broken_fixture": self.broken_fixture,
            "per_call": self.per_call,
        }

    def summary(self) -> str:
        if self.grade == GRADE_FAIL:
            return (f"LEAK: confused deputy / token passthrough — {self.label}: "
                    f"{self.reason}")
        return f"[{self.grade}] confused deputy: {self.label} — {self.reason}"


def _control_reached(upstream: MockUpstream, callers, benign_trigger,
                     expected_audience) -> bool:
    """Positive control: a benign on-behalf-of call reaches the upstream with the
    caller's own identity and this upstream's audience. Proves the deputy works
    and the harness can see upstream calls, so a refusal (no call) is meaningful.
    """
    reached = False
    for caller in callers:
        calls, _ = observe_one_call(caller.identity, upstream, benign_trigger)
        for call in calls:
            if (call.parsed and call.subject == caller.subject
                    and expected_audience in _aud_set(call.audience)):
                reached = True
    return reached


def run_confused_deputy_probe(
    target: str,
    caller_a: CallerSpec,
    caller_b: CallerSpec,
    *,
    upstream: MockUpstream,
    sensitive_trigger: Callable[[MCPClient], Any],
    benign_trigger: Callable[[MCPClient], Any],
    expected_audience: str,
    deputy_subjects: Any = DEFAULT_DEPUTY_SUBJECTS,
    broken_fixture: Optional[Callable[[], "ConfusedDeputyResult"]] = None,
    controls: Optional[Dict[str, bool]] = None,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> ConfusedDeputyResult:
    """Drive the deputy as A, B, A on the sensitive on-behalf-of call; grade what
    reached ``upstream``.

    ``sensitive_trigger`` must cause the deputy to make the on-behalf-of upstream
    call under test. ``benign_trigger`` is a request the deputy should always be
    able to serve by a faithful exchange; it establishes the positive control
    (the deputy reaches the upstream at all), without which a "no call" could not
    be read as a refusal.

    ``broken_fixture`` is a zero-arg callable that runs THIS probe against a
    deliberately-leaky deputy and returns its result; it is run in the same call,
    and unless it comes back FAIL no OK can stand. This is how "every OK is backed
    by a broken-fixture-fails control in the same run" is enforced structurally.
    """
    decision = authorize(target, authorized=authorized,
                         authorization_note=authorization_note)
    controls = dict(controls or {})
    controls.setdefault("broken_fixture_failed", False)

    broken_dict: Optional[Dict[str, Any]] = None
    if broken_fixture is not None:
        bf = broken_fixture()
        controls["broken_fixture_failed"] = (bf.grade == GRADE_FAIL)
        broken_dict = {"grade": bf.grade, "label": bf.label, "reason": bf.reason}

    callers = (caller_a, caller_b)
    control_reached = _control_reached(upstream, callers, benign_trigger,
                                       expected_audience)
    controls["control_reached_upstream"] = control_reached

    per_call: List[Dict[str, Any]] = []
    observations: List[str] = []
    # A, then B, then A again, like the delegation probe: the second A catches a
    # deputy that cached or bled another caller's token into A's next call.
    for caller in (caller_a, caller_b, caller_a):
        calls, err = observe_one_call(caller.identity, upstream, sensitive_trigger)
        if err:
            observations.append(f"{caller.identity.label}: deputy refused/errored: {err}")
        if not calls:
            observations.append(f"{caller.identity.label}: no upstream call "
                                "(refused, or feature unsupported)")
        for call in calls:
            g = grade_confused_deputy_call(
                caller_subject=caller.subject,
                inbound_token_fp=caller.inbound_token_fp,
                upstream_subject=call.subject,
                upstream_audience=call.audience,
                upstream_scope=call.scope,
                upstream_token_fp=token_fingerprint(call.token),
                expected_audience=expected_audience,
                deputy_subjects=deputy_subjects,
                parsed=call.parsed,
            )
            g.update(principal=caller.identity.label, method=call.method)
            per_call.append(g)

    grade, label, reason = combine_confused_deputy_grades(
        per_call, controls, control_reached=control_reached)

    return ConfusedDeputyResult(
        grade=grade, label=label, reason=reason, per_call=per_call,
        controls=controls, target=decision.target, observations=observations,
        broken_fixture=broken_dict)
