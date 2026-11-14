"""Scope narrowing (CoSAI 3.3.2) and issuer binding (CoSAI 3.2.2/3.3.2).

Stdlib only. Each test pins one way the checks could give a false FAIL or a
false OK (the list is in strangertest/delegate.py, S1-S14 and I1-I12).
"""

import os
import sys
import unittest

from strangertest.delegate import (
    GRADE_FAIL,
    GRADE_INCONCLUSIVE,
    GRADE_OBSERVATION,
    GRADE_OK,
    MockUpstream,
    combine_scope_grades,
    gate_run_problems,
    grade_issuer_email_crossprovider,
    grade_issuer_unregistered,
    grade_scope_call,
    run_delegation_probe,
    run_issuer_unregistered_probe,
    run_scope_narrowing_probe,
    token_fingerprint,
)
from strangertest.mcp_client import MCPClient, Transport
from strangertest.probe import Identity

_INTEGRATION = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "integration")
if _INTEGRATION not in sys.path:
    sys.path.insert(0, _INTEGRATION)
import local_as  # noqa: E402  (importable without pyjwt: pure helpers only)

AUD = "https://upstream.test/mcp"
BROAD = "read:notes write:notes admin"
ALL_CONTROLS = {"broken_fixture_failed": True}


def g(**kw):
    kw.setdefault("subject_scope", BROAD)
    kw.setdefault("requested_observed", True)
    return grade_scope_call(**kw)


# ---------------------------------------------------------------- per call
class ScopeCallGradeTests(unittest.TestCase):
    def test_narrowed_to_request_is_ok(self):
        r = g(upstream_scope="read:notes", requested_scope="read:notes",
              issued_scope="read:notes")
        self.assertEqual((r["grade"], r["label"]), (GRADE_OK, "narrowed"))
        self.assertIn("narrowing requested by the gateway", r["who_narrowed"])

    def test_exceeding_subject_is_fail(self):
        r = g(upstream_scope="read:notes delete:all", requested_scope="read:notes")
        self.assertEqual((r["grade"], r["label"]), (GRADE_FAIL, "scope_exceeded"))
        self.assertIn("delete:all", r["reason"])

    def test_no_request_full_scope_is_observation_not_narrowed(self):
        r = g(upstream_scope=BROAD, requested_scope=None, issued_scope=BROAD)
        self.assertEqual((r["grade"], r["label"]), (GRADE_OBSERVATION, "not_narrowed"))
        self.assertIn("gateway requested no scope", r["who_narrowed"])

    def test_requested_full_scope_is_observation_not_narrowed(self):
        r = g(upstream_scope=BROAD, requested_scope=BROAD)
        self.assertEqual(r["label"], "not_narrowed")

    # S1
    def test_scope_list_vs_string_order_is_not_a_fail(self):
        r = g(upstream_scope=["read:notes"], requested_scope="read:notes",
              subject_scope=["admin", "write:notes", "read:notes"])
        self.assertEqual(r["grade"], GRADE_OK)
        r2 = g(upstream_scope="write:notes read:notes", requested_scope="read:notes write:notes")
        self.assertEqual(r2["grade"], GRADE_OK)

    # S4
    def test_as_alone_narrowed_is_not_ok(self):
        r = g(upstream_scope="read:notes", requested_scope=None, issued_scope="read:notes")
        self.assertEqual(r["grade"], GRADE_INCONCLUSIVE)
        self.assertIn("AS alone narrowed", r["who_narrowed"])

    # S6
    def test_scope_claim_absent_is_inconclusive(self):
        r = g(upstream_scope=None, requested_scope="read:notes")
        self.assertEqual(r["grade"], GRADE_INCONCLUSIVE)

    # S7
    def test_undecodable_token_is_inconclusive(self):
        r = g(upstream_scope=None, parsed=False)
        self.assertEqual(r["grade"], GRADE_INCONCLUSIVE)

    # S11
    def test_request_not_observed_is_inconclusive(self):
        self.assertEqual(g(upstream_scope="read:notes", requested_observed=False)["grade"],
                         GRADE_INCONCLUSIVE)
        self.assertEqual(g(upstream_scope=BROAD, requested_observed=False)["grade"],
                         GRADE_INCONCLUSIVE)
        # ...but an exceeded scope is a FAIL even without the request.
        self.assertEqual(g(upstream_scope="root", requested_observed=False)["grade"],
                         GRADE_FAIL)

    # S12
    def test_narrower_but_not_requested_is_inconclusive(self):
        r = g(upstream_scope="read:notes", requested_scope="read:notes write:notes")
        self.assertEqual(r["grade"], GRADE_INCONCLUSIVE)

    def test_deputy_changed_scope_after_exchange_is_recorded(self):
        r = g(upstream_scope="read:notes write:notes admin delete:all",
              requested_scope="read:notes", issued_scope="read:notes")
        self.assertEqual(r["grade"], GRADE_FAIL)
        self.assertIn("differs from what the AS issued", r["who_narrowed"])


    # S14: the AS granted less than the subject held, but the upstream saw more
    # than the grant (the deputy forwarded the subject token, or widened it).
    def test_full_subject_scope_after_narrower_grant_is_fail(self):
        r = g(upstream_scope=BROAD, requested_scope="read:notes", issued_scope="read:notes")
        self.assertEqual((r["grade"], r["label"]), (GRADE_FAIL, "scope_exceeds_issued"))
        self.assertIn("exceeds what the AS issued", r["reason"])
        self.assertIn("write:notes", r["reason"])

    def test_any_superset_of_grant_is_fail(self):
        r = g(upstream_scope="read:notes write:notes", requested_scope="read:notes",
              issued_scope="read:notes")
        self.assertEqual((r["grade"], r["label"]), (GRADE_FAIL, "scope_exceeds_issued"))
        # ...also when the gateway requested nothing and the AS narrowed alone.
        r2 = g(upstream_scope="read:notes write:notes", requested_scope=None,
               issued_scope="read:notes")
        self.assertEqual(r2["grade"], GRADE_FAIL)

    def test_equal_to_grant_is_not_an_issued_fail(self):
        # issued == subject (no scope requested): full scope is NOT_NARROWED, not FAIL.
        r = g(upstream_scope=BROAD, requested_scope=None, issued_scope=BROAD)
        self.assertEqual(r["grade"], GRADE_OBSERVATION)
        # issued unknown: no issued-scope FAIL can be claimed.
        r2 = g(upstream_scope=BROAD, requested_scope="read:notes")
        self.assertNotEqual(r2["label"], "scope_exceeds_issued")

    def test_issued_fail_label_survives_combine(self):
        r = g(upstream_scope=BROAD, requested_scope="read:notes", issued_scope="read:notes")
        self.assertEqual(combine_scope_grades([r], ALL_CONTROLS)[:2],
                         (GRADE_FAIL, "scope_exceeds_issued"))


class ScopeCombineTests(unittest.TestCase):
    ok = {"grade": GRADE_OK, "reason": "ok"}
    obs = {"grade": GRADE_OBSERVATION, "reason": "not narrowed"}
    bad = {"grade": GRADE_FAIL, "reason": "exceeded"}
    inc = {"grade": GRADE_INCONCLUSIVE, "reason": "?"}

    # S8
    def test_no_upstream_call_is_inconclusive(self):
        self.assertEqual(combine_scope_grades([], ALL_CONTROLS)[0], GRADE_INCONCLUSIVE)

    # S9
    def test_broken_fixture_not_shown_blocks_ok(self):
        grade = combine_scope_grades([self.ok] * 3, {"broken_fixture_failed": False})[0]
        self.assertEqual(grade, GRADE_INCONCLUSIVE)
        self.assertEqual(combine_scope_grades([self.ok] * 3, ALL_CONTROLS)[0], GRADE_OK)

    # S10
    def test_one_exceeded_call_fails_the_run(self):
        self.assertEqual(combine_scope_grades([self.ok, self.bad, self.ok], ALL_CONTROLS)[0],
                         GRADE_FAIL)

    # S3 / S13
    def test_failed_control_never_produces_fail(self):
        grade = combine_scope_grades([self.ok, self.obs], {"broken_fixture_failed": False})[0]
        self.assertNotEqual(grade, GRADE_FAIL)

    def test_seen_scope_leak_not_downgraded_by_controls(self):
        grade, label, _ = combine_scope_grades(
            [self.bad], {"broken_fixture_failed": False, "anything": False})
        self.assertEqual((grade, label), (GRADE_FAIL, "scope_exceeded"))

    def test_observation_when_not_narrowed(self):
        self.assertEqual(combine_scope_grades([self.obs, self.ok], ALL_CONTROLS)[:2],
                         (GRADE_OBSERVATION, "not_narrowed"))

    def test_inconclusive_call_beats_ok(self):
        self.assertEqual(combine_scope_grades([self.ok, self.inc], ALL_CONTROLS)[0],
                         GRADE_INCONCLUSIVE)


# ------------------------------------------------- in-memory deputy harness
class FakeAS:
    """Records exchanges like integration/local_as.py (fingerprints only), with
    the same cap: issued = requested ∩ subject, or the subject's scope."""

    def __init__(self):
        self.records = []
        self._n = 0

    def exchange(self, subject_token, subject_scope, requested):
        self._n += 1
        issued_tok = f"x-{self._n}-{subject_token}"
        issued = local_as.cap_scope(requested, subject_scope)
        self.records.append({"subject_fp": token_fingerprint(subject_token),
                             "requested_scope": requested, "issued_scope": issued,
                             "issued_fp": token_fingerprint(issued_tok),
                             "actor_present": True})
        return issued_tok, issued

    def lookup(self, fp):
        for r in self.records:
            if r["issued_fp"] == fp:
                return r
        return None


class Deputy:
    """Fake deputy. scope_mode: request (asks read:notes) | none (asks nothing)
    | escalate (forwards a self-minted broad token) | refuse (no upstream call).
    issuer_mode: any (no iss check) | checked (iss must be registered)."""

    REGISTERED = {"https://provx.test", "https://provy.test", "https://local-as.test"}

    def __init__(self, upstream, as_, scope_mode="request", issuer_mode="any",
                 discovery_scope=None):
        self.up, self.as_ = upstream, as_
        self.scope_mode, self.issuer_mode = scope_mode, issuer_mode
        self.discovery_scope = discovery_scope
        self.strip_nonce = False
        self.delay_registered_calls = False
        self.pending = []

    def handle(self, t, msg):
        mid, method = msg.get("id"), msg.get("method")
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2026-07-28", "capabilities": {"tools": {}}}}
        if method != "tools/call":
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no"}}
        nonce = ((msg.get("params") or {}).get("arguments") or {}).get("nonce")
        if self.strip_nonce:
            nonce = None
        if self.pending:  # a delayed upstream call from the PREVIOUS request lands now
            self.up.receive(**self.pending.pop(0))
        unregistered = t.iss not in self.REGISTERED
        if self.issuer_mode == "checked" and unregistered:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32001,
                                                           "message": "untrusted issuer"}}
        if self.issuer_mode == "accept_silent" and unregistered:
            # BROKEN: answers the unregistered caller with a result, no upstream call.
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [], "isError": False}}
        if self.issuer_mode == "tool_error" and unregistered:
            # SAFE: refuses inside a tool result (isError), no upstream call.
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "untrusted issuer"}], "isError": True}}
        if self.issuer_mode == "static" and unregistered:
            # BROKEN: swaps its own service credential in for the unregistered caller.
            self.up.receive(subject="svc", issuer="https://local-as.test", actor=None,
                            audience=AUD, scope="read:notes", token="svc-token", nonce=nonce)
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": []}}
        if self.scope_mode == "refuse":
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32000, "message": "bad"}}
        if self.discovery_scope:
            self.up.receive(method="tools/list", subject="svc", scope=self.discovery_scope,
                            token="svc-token")
        if self.scope_mode == "escalate":
            tok, scope = f"minted-{t.token}", "read:notes write:notes admin delete:all"
        else:
            req = "read:notes" if self.scope_mode == "request" else None
            tok, scope = self.as_.exchange(t.token, t.scope, req)
        call = dict(subject=t.sub, issuer=t.iss, actor="gw", audience=AUD,
                    scope=scope, token=tok, nonce=nonce)
        if self.delay_registered_calls and not unregistered:
            self.delay_registered_calls = False  # only the first (control-before) call
            self.pending.append(call)  # lands during the NEXT request
        else:
            self.up.receive(**call)
        return {"jsonrpc": "2.0", "id": mid, "result": {"content": []}}


class _T(Transport):
    def __init__(self, server, sub, iss, token, scope):
        self.server, self.sub, self.iss, self.token, self.scope = server, sub, iss, token, scope

    def request(self, message):
        return self.server.handle(self, message)

    def notify(self, message):
        pass


def ident(server, label, sub, iss="https://local-as.test", scope=BROAD, token=None):
    tok = token or f"user-{sub}-{iss}"
    return Identity(label=label, connect=lambda: MCPClient(_T(server, sub, iss, tok, scope)))


def trig(c):
    c.call_tool("do", {})


def scope_run(scope_mode, controls=ALL_CONTROLS, subject=BROAD, configured="read:notes",
              discovery_scope=None):
    up, as_ = MockUpstream(AUD), FakeAS()
    dep = Deputy(up, as_, scope_mode=scope_mode, discovery_scope=discovery_scope)
    return run_scope_narrowing_probe(
        "http://localhost/practice",
        ident(dep, "A", "alice", scope=subject), ident(dep, "B", "bob", scope=subject),
        upstream=up, trigger=trig, subject_scope=subject, configured_scope=configured,
        exchange_lookup=as_.lookup, controls=dict(controls))


class ScopeProbeTests(unittest.TestCase):
    def test_safe_deputy_ok(self):
        r = scope_run("request")
        self.assertEqual((r.grade, r.label), (GRADE_OK, "narrowed"), r.reason)
        self.assertEqual(len(r.per_call), 3)
        self.assertEqual(r.to_dict()["cosai"], "CoSAI MCP Security v2.0, 3.3.2")

    def test_no_request_is_observation(self):
        r = scope_run("none")
        self.assertEqual((r.grade, r.label), (GRADE_OBSERVATION, "not_narrowed"))

    def test_escalating_deputy_fails(self):
        r = scope_run("escalate")
        self.assertEqual((r.grade, r.label), (GRADE_FAIL, "scope_exceeded"))

    def test_escalation_fails_even_with_every_control_failed(self):
        r = scope_run("escalate", controls={"broken_fixture_failed": False},
                      subject="read:notes", configured="read:notes")
        self.assertEqual(r.grade, GRADE_FAIL)

    # S5
    def test_subject_not_broader_is_inconclusive(self):
        r = scope_run("request", subject="read:notes", configured="read:notes")
        self.assertEqual(r.grade, GRADE_INCONCLUSIVE)
        self.assertFalse(r.controls["subject_scope_broader_than_configured"])

    # S8 (refusal from a malformed request / unsupported feature)
    def test_refusing_deputy_is_inconclusive(self):
        r = scope_run("refuse")
        self.assertEqual(r.grade, GRADE_INCONCLUSIVE)

    # S2
    def test_discovery_traffic_with_broad_scope_ignored(self):
        r = scope_run("request", discovery_scope="read:notes write:notes admin root:all")
        self.assertEqual(r.grade, GRADE_OK, r.reason)

    def test_old_scope_narrowed_check_unchanged(self):
        # The existing check's verdict on a fixture with an exceeded-but-not-
        # admin scope is unchanged by the new check (it still only bans admin etc).
        up, as_ = MockUpstream(AUD), FakeAS()
        dep = Deputy(up, as_, scope_mode="request")
        rep = run_delegation_probe(
            "http://localhost/practice", ident(dep, "A", "alice"), ident(dep, "B", "bob"),
            upstream=up, trigger=trig, expected_subject_a="alice", expected_subject_b="bob")
        self.assertEqual(set(rep.checks), {"subject_preserved", "actor_present",
                                           "audience_correct", "scope_narrowed",
                                           "no_token_reuse", "no_cross_identity_bleed"})
        self.assertTrue(rep.checks["scope_narrowed"])


# --------------------------------------------------------- issuer: test A
UNREG = "https://unregistered.test"


def ntrig(c, nonce):
    """The issuer probe's trigger: every request carries its own nonce."""
    return c.call_tool("do", {"nonce": nonce})


def issuer_run(issuer_mode, controls=ALL_CONTROLS, quiet=0.0, control_refuses=False,
               strip_nonce=False, delay_controls=False):
    up, as_ = MockUpstream(AUD), FakeAS()
    dep = Deputy(up, as_, scope_mode="request", issuer_mode=issuer_mode)
    dep.strip_nonce, dep.delay_registered_calls = strip_nonce, delay_controls
    probe_tok = "probe-token"
    probe = ident(dep, "P", "mallory", iss=UNREG, token=probe_tok)
    if control_refuses:
        control = ident(Deputy(up, as_, scope_mode="refuse"), "C", "mallory",
                        iss="https://provx.test")
    else:
        control = ident(dep, "C", "mallory", iss="https://provx.test")
    res = run_issuer_unregistered_probe(
        "http://localhost/practice", control_identity=control, probe_identity=probe,
        upstream=up, trigger=ntrig, probe_token_fp=token_fingerprint(probe_tok),
        probe_issuer=UNREG, exchange_records=lambda: list(as_.records),
        controls=dict(controls), quiet_seconds=quiet)
    return res


class IssuerUnregisteredTests(unittest.TestCase):
    def test_checking_deputy_ok(self):
        r = issuer_run("checked")
        self.assertEqual((r.grade, r.label), (GRADE_OK, "rejected"), r.reason)
        self.assertEqual(r.to_dict()["probe"], "issuer_unregistered")
        self.assertFalse(r.evidence["probe_succeeded"])

    def test_any_issuer_deputy_fails(self):
        r = issuer_run("any")
        self.assertEqual(r.grade, GRADE_FAIL, r.reason)
        self.assertTrue(r.evidence["probe_succeeded"])
        # fingerprints only, never the token
        self.assertTrue(r.evidence["probe_token"].startswith("sha256:"))

    def test_every_request_carries_its_own_nonce(self):
        r = issuer_run("checked")
        n = r.evidence["nonces"]
        self.assertEqual(len({n["control_before"], n["probe"], n["control_after"]}), 3)
        self.assertEqual(r.evidence["control_before_calls"][0]["nonce"], n["control_before"])
        self.assertEqual(r.evidence["control_after_calls"][0]["nonce"], n["control_after"])
        self.assertEqual(r.evidence["unattributed_calls"], [])

    # I10: the probe request itself returned a successful result
    def test_probe_success_fails_with_no_upstream_call(self):
        r = issuer_run("accept_silent")
        self.assertEqual((r.grade, r.label),
                         (GRADE_FAIL, "unregistered_issuer_request_succeeded"), r.reason)
        self.assertEqual(r.evidence["probe_upstream_calls"], [])

    # I10 (false FAIL): an isError tool result is a refusal, not a success
    def test_tool_error_result_is_a_refusal(self):
        r = issuer_run("tool_error")
        self.assertEqual(r.grade, GRADE_OK, r.reason)
        self.assertFalse(r.evidence["probe_succeeded"])

    # I11: a call carrying the probe's nonce fails whatever identity it carried
    def test_probe_nonce_call_fails_whatever_identity(self):
        r = issuer_run("static")
        self.assertEqual((r.grade, r.label),
                         (GRADE_FAIL, "unregistered_issuer_request_succeeded"), r.reason)
        self.assertEqual(r.evidence["probe_upstream_calls"][0]["subject"], "svc")

    # I9 replaced: a DELAYED control call landing while the probe is in flight
    # is attributed to the control by its nonce, so it is neither FAIL nor
    # INCONCLUSIVE.
    def test_delayed_control_call_attributed_by_nonce(self):
        r = issuer_run("checked", delay_controls=True)
        self.assertEqual(r.grade, GRADE_OK, r.reason)
        # the delayed call really did land after the control returned
        self.assertEqual(len(r.evidence["control_before_calls"]), 1)
        self.assertEqual(r.evidence["probe_upstream_calls"], [])

    # I12: the target dropped the nonce, so nothing can be attributed
    def test_nonce_stripped_is_inconclusive_never_ok(self):
        r = issuer_run("checked", strip_nonce=True)
        self.assertEqual(r.grade, GRADE_INCONCLUSIVE, r.reason)
        self.assertFalse(r.controls["control_before_reached"])

    def test_nonce_stripped_leak_still_fails(self):
        r = issuer_run("any", strip_nonce=True)
        self.assertEqual(r.grade, GRADE_FAIL, r.reason)

    # I3 / I4
    def test_control_not_reached_is_inconclusive(self):
        r = issuer_run("checked", control_refuses=True)
        self.assertEqual(r.grade, GRADE_INCONCLUSIVE)

    # I7
    def test_issuer_broken_fixture_not_shown_blocks_ok(self):
        r = issuer_run("checked", controls={"broken_fixture_failed": False})
        self.assertEqual(r.grade, GRADE_INCONCLUSIVE)

    # I8
    def test_seen_issuer_leak_not_downgraded(self):
        r = issuer_run("any", controls={"broken_fixture_failed": False},
                       control_refuses=True)
        self.assertEqual(r.grade, GRADE_FAIL)


class IssuerGradeTests(unittest.TestCase):
    base = dict(probe_succeeded=False, probe_calls=[], unattributed_calls=[],
                quiet_baseline_calls=0, control_before=True, control_after=True,
                exchange_attempted=False, controls=ALL_CONTROLS)

    def grade(self, **kw):
        return grade_issuer_unregistered(**{**self.base, **kw})[0]

    def test_clean_is_ok(self):
        self.assertEqual(self.grade(), GRADE_OK)

    # I10
    def test_probe_success_fails_whatever_the_controls(self):
        for kw in ({}, {"control_before": False}, {"controls": {"broken_fixture_failed": False}},
                   {"exchange_attempted": None}):
            self.assertEqual(self.grade(probe_succeeded=True, **kw), GRADE_FAIL, kw)

    # I11
    def test_probe_nonce_call_fails(self):
        other = {"issuer": "https://local-as.test", "subject": "svc", "linked": False}
        self.assertEqual(self.grade(probe_calls=[other], quiet_baseline_calls=5), GRADE_FAIL)

    # I1: unattributed calls are never blamed on the probe
    def test_unattributed_unlinked_call_is_inconclusive(self):
        for quiet in (0, 3):
            self.assertEqual(self.grade(unattributed_calls=[{"linked": False}],
                                        quiet_baseline_calls=quiet), GRADE_INCONCLUSIVE)

    def test_unattributed_linked_call_fails(self):
        self.assertEqual(self.grade(unattributed_calls=[{"linked": True}],
                                    quiet_baseline_calls=5), GRADE_FAIL)

    def test_delayed_control_path_is_gone(self):
        with self.assertRaises(TypeError):
            grade_issuer_unregistered(**{**self.base, "control_principal": ("i", "s")})

    # I2
    def test_issuer_control_failure_never_fails(self):
        for kw in ({"control_before": False}, {"control_after": False},
                   {"controls": {"broken_fixture_failed": False}},
                   {"exchange_attempted": None}, {"probe_succeeded": None}):
            self.assertEqual(self.grade(**kw), GRADE_INCONCLUSIVE, kw)

    # I5
    def test_control_after_failing_is_inconclusive(self):
        self.assertEqual(self.grade(control_after=False), GRADE_INCONCLUSIVE)

    # I6
    def test_exchange_attempted_is_not_ok(self):
        self.assertEqual(self.grade(exchange_attempted=True), GRADE_INCONCLUSIVE)


# --------------------------------------------------------- issuer: test B
class EmailCrossProviderTests(unittest.TestCase):
    X, Y = "https://provx.test", "https://provy.test"

    def grade(self, calls, control=True):
        return grade_issuer_email_crossprovider(
            probe_calls=calls, control_reached=control, x_issuer=self.X, y_issuer=self.Y,
            y_subject="carol-y", claimed_email="carol@provy.test")

    def test_x_token_as_y_principal_fails(self):
        self.assertEqual(self.grade([{"issuer": self.Y, "subject": "carol-y"}])[0], GRADE_FAIL)

    def test_same_sub_other_issuer_is_not_y(self):
        g_, label, _ = self.grade([{"issuer": self.X, "subject": "carol-y",
                                    "email": "carol@provy.test"}])
        self.assertEqual((g_, label), (GRADE_OBSERVATION, "accepted_as_x"))

    def test_email_alone_is_observation_not_fail(self):
        g_, _, reason = self.grade([{"issuer": self.X, "subject": "carol-x",
                                     "email": "carol@provy.test"}])
        self.assertEqual(g_, GRADE_OBSERVATION)
        self.assertIn("Y's email", reason)

    def test_rejected_is_observation_with_control(self):
        self.assertEqual(self.grade([])[:2], (GRADE_OBSERVATION, "rejected"))

    def test_rejected_without_control_is_inconclusive(self):
        self.assertEqual(self.grade([], control=False)[0], GRADE_INCONCLUSIVE)


# ----------------------------------------------------------- local AS helpers
class GateRunProblemsTests(unittest.TestCase):
    def test_valid_run_has_no_problems(self):
        self.assertEqual(gate_run_problems({
            "broken_fixture": {"name": "x", "grade": "FAIL"},
            "controls": {"control_before_reached": True, "control_after_reached": True}}), [])

    def test_broken_fixture_not_failing_is_a_problem(self):
        self.assertEqual(len(gate_run_problems({"broken_fixture": {"name": "x",
                                                                   "grade": "OK"}})), 1)

    def test_failed_positive_control_is_a_problem(self):
        for k in ("control_before_reached", "control_after_reached",
                  "subject_scope_broader_than_configured", "x_control_reached_upstream"):
            self.assertEqual(len(gate_run_problems({"controls": {k: False}})), 1, k)


class LocalASHelperTests(unittest.TestCase):
    def test_cap_never_grants_beyond_subject(self):
        self.assertEqual(local_as.cap_scope("read:notes admin", "read:notes write:notes"),
                         "read:notes")
        self.assertEqual(local_as.cap_scope("delete:all", "read:notes"), "")

    def test_cap_without_request_issues_subject_scope(self):
        self.assertEqual(local_as.cap_scope(None, BROAD), BROAD)
        self.assertEqual(local_as.cap_scope("  ", BROAD), BROAD)

    def test_cap_keeps_requested_order_and_dedups(self):
        self.assertEqual(local_as.cap_scope("write:notes read:notes read:notes", BROAD),
                         "write:notes read:notes")

    def test_fingerprints_match_between_as_and_probe(self):
        self.assertEqual(local_as.token_fingerprint("abc"), token_fingerprint("abc"))
        self.assertTrue(token_fingerprint("abc").startswith("sha256:"))

    def test_subject_key_selection(self):
        issuers = {"https://provx.test": "provx", "https://local-as.test": "as"}
        kids = {"k1": "provx"}
        self.assertEqual(local_as.select_subject_key("https://provx.test", "k1", issuers, kids,
                                                     lax=False)[0], "provx")
        self.assertIsNone(local_as.select_subject_key(UNREG, "k1", issuers, kids,
                                                      lax=False)[0])
        self.assertEqual(local_as.select_subject_key(UNREG, "k1", issuers, kids,
                                                     lax=True)[0], "provx")


if __name__ == "__main__":
    unittest.main()
