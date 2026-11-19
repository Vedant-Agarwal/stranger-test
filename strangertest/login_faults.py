"""Login server misbehaves: does the gateway still fail closed? (XID-10, deeper)

The existing exchange-failure check makes the login server answer HTTP 400
``invalid_grant``. This module grades the other ways a login server goes wrong:

* ``http_500``            -- the token endpoint answers HTTP 500
* ``unreachable``         -- nothing listens on the token endpoint (connection refused)
* ``slow``                -- the token endpoint holds the request past a normal timeout
* ``malformed_not_json``  -- HTTP 200 whose body is not JSON
* ``malformed_no_token``  -- HTTP 200 JSON with no ``access_token``

Per mode, a gate makes a CONTROL call first (login server healthy, a fresh user),
then the PROBE call (fault on, another fresh user, so no cached exchange can
hide the fault), each with its own nonce. It records every upstream call tied
to each nonce and what the caller got back.

Grades (one per mode):

* FAIL -- a probe-nonce call reached the upstream with NO Authorization (the
  brief's rule); or with the caller's own inbound token (token passthrough); or
  as another identity. A leak that is observed is FAIL whatever the controls say.
* OK -- nothing with the probe's nonce reached the upstream, the caller got an
  error, the control reached the upstream authenticated, the fault was shown to
  be exercised, the window was quiet, and the fall-through fixture FAILED the
  same check in this run.
* OBSERVATION ``reached_upstream_authenticated`` -- the probe reached the upstream
  as the right user on an exchanged token: the fault did not bite (for ``slow``,
  the gateway waited it out). Not OK: the failure path was never taken.
* INCONCLUSIVE -- anything else.

Ways this could lie, and the unit test that pins each (tests/test_login_faults.py):

False LEAK
  F1 discovery / health traffic with no Authorization while nobody acts -> only
     tools/call and resources/read carrying the PROBE's nonce are blamed.
                                  test_unattributed_no_auth_call_is_not_blamed
  F2 a delayed CONTROL call landing during the fault window -> it carries the
     control's nonce, so it is the control's.
                                  test_delayed_control_call_is_the_controls
  F3 the probe user's own exchanged token, issued before the fault (cache) ->
     not a leak; and the probe uses a fresh user so no cache entry exists.
                                  test_authenticated_arrival_is_observation_not_fail
  F4 a failing control turned into a FAIL -> controls never produce FAIL.
                                  test_failed_control_never_fails
False OK
  O1 refusal caused by a malformed request, not the fault -> the control must
     reach the upstream authenticated, with its nonce, first.
                                  test_control_not_reached_is_inconclusive
  O2 the fault never exercised (the gateway did not call the login server, or
     answered from a cache) -> fault hits must be > 0 where countable.
                                  test_fault_not_exercised_is_inconclusive
  O3 the gateway answers the caller with success but nothing upstream ->
     INCONCLUSIVE, not OK.        test_caller_success_without_upstream_is_inconclusive
  O4 a call that arrives AFTER the caller already got its error (slow mode) ->
     the gate settles until the slow response is due before grading.
                                  test_late_unauthenticated_arrival_fails
  O5 the gateway strips the nonce, so a leak could not be tied to the probe ->
     the control must arrive WITH its nonce, and any unattributed call during
     the window blocks OK.        test_nonce_stripped_is_inconclusive
  O6 the broken fixture not shown to fail the same check in this run.
                                  test_broken_fixture_not_failed_blocks_ok
  O7 an unparseable token at the upstream -> cannot say who it was.
                                  test_unparsed_token_is_inconclusive
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

GRADE_FAIL = "FAIL"
GRADE_OK = "OK"
GRADE_INCONCLUSIVE = "INCONCLUSIVE"
GRADE_OBSERVATION = "OBSERVATION"

FAULT_MODES = ("http_500", "unreachable", "slow", "malformed_not_json", "malformed_no_token")

# token_kind values a gate assigns to each upstream call (by fingerprint).
TOKEN_NONE = "none"            # no Authorization header at all
TOKEN_INBOUND = "inbound"      # the caller's own inbound token, unexchanged
TOKEN_EXCHANGED = "exchanged"  # a token the login server issued in an exchange
TOKEN_OTHER = "other"          # anything else (e.g. a service credential)


def classify_token(token_fp: Optional[str], *, inbound_fps, issued_fps) -> str:
    """Which kind of credential an upstream call carried (by fingerprint)."""
    if not token_fp:
        return TOKEN_NONE
    if token_fp in inbound_fps:
        return TOKEN_INBOUND
    if token_fp in issued_fps:
        return TOKEN_EXCHANGED
    return TOKEN_OTHER


def grade_login_fault(
    *,
    probe_calls: List[Dict[str, Any]],
    unattributed_calls: List[Dict[str, Any]],
    control_reached_authenticated: bool,
    caller_succeeded: Optional[bool],
    fault_hits: Optional[int],
    expected_subject: str,
    expected_issuer: Optional[str],
    broken_fixture_failed: Optional[bool],
) -> Tuple[str, str, str]:
    """Grade ONE fault mode. Returns ``(grade, label, reason)``.

    ``probe_calls``: graded upstream calls carrying the PROBE request's nonce,
    each a dict with ``token_kind`` (see :func:`classify_token`), ``parsed``,
    ``subject``, ``issuer``. ``unattributed_calls``: graded calls in the fault
    window with no known nonce. ``fault_hits``: requests the faulty endpoint saw
    while faulty (None = not observable, e.g. nothing was listening).
    """
    # --- an observed leak is FAIL, whatever else happened ------------------
    no_auth = [c for c in probe_calls if c.get("token_kind") == TOKEN_NONE]
    if no_auth:
        return (GRADE_FAIL, "forwarded_unauthenticated",
                f"{len(no_auth)} upstream call(s) with the probe's nonce arrived with no "
                "Authorization header while the login server was failing")
    inbound = [c for c in probe_calls if c.get("token_kind") == TOKEN_INBOUND]
    if inbound:
        return (GRADE_FAIL, "forwarded_inbound_token",
                f"{len(inbound)} upstream call(s) with the probe's nonce carried the caller's "
                "own inbound token (no exchange) while the login server was failing")
    wrong = [c for c in probe_calls if c.get("parsed") and (
        c.get("subject") != expected_subject
        or (expected_issuer is not None and c.get("issuer") != expected_issuer))]
    if wrong:
        idents = sorted({(str(c.get("issuer")), str(c.get("subject"))) for c in wrong})
        return (GRADE_FAIL, "wrong_identity",
                f"the probe's request reached the upstream as {idents}, not "
                f"({expected_issuer}, {expected_subject})")
    # --- nothing provably wrong; can we say more? --------------------------
    if unattributed_calls:
        kinds = sorted({str(c.get("token_kind")) for c in unattributed_calls})
        return (GRADE_INCONCLUSIVE, "inconclusive",
                f"{len(unattributed_calls)} upstream call(s) in the fault window carried no "
                f"known nonce (credential kinds {kinds}); they cannot be tied to a request")
    if probe_calls:
        unparsed = [c for c in probe_calls if not c.get("parsed")]
        others = [c for c in probe_calls if c.get("token_kind") == TOKEN_OTHER]
        if unparsed or others:
            return (GRADE_INCONCLUSIVE, "inconclusive",
                    "the probe's request reached the upstream on a credential that could "
                    "not be identified")
        return (GRADE_OBSERVATION, "reached_upstream_authenticated",
                "the probe's request reached the upstream as the right user on an exchanged "
                "token: the fault did not bite, so the failure path was not taken")
    if not control_reached_authenticated:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "the control (healthy login server) did not reach the upstream authenticated "
                "with its nonce: a refusal cannot be attributed to the fault")
    if fault_hits == 0:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "the gateway never called the faulty login server: the fault was not exercised")
    if caller_succeeded is None:
        return (GRADE_INCONCLUSIVE, "inconclusive", "the caller's outcome is unknown")
    if caller_succeeded:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "the caller got a successful result, yet nothing reached the upstream")
    if not broken_fixture_failed:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "the fall-through fixture did not FAIL this check in this run")
    return (GRADE_OK, "fails_closed",
            "nothing with the probe's nonce reached the upstream and the caller got an error; "
            "the control reached it authenticated first"
            + ("" if fault_hits else " (attempts not observable: nothing was listening)"))


def worst(grades: List[str]) -> str:
    """FAIL > INCONCLUSIVE > OBSERVATION > OK, for a one-word run summary."""
    for g in (GRADE_FAIL, GRADE_INCONCLUSIVE, GRADE_OBSERVATION, GRADE_OK):
        if g in grades:
            return g
    return GRADE_INCONCLUSIVE
