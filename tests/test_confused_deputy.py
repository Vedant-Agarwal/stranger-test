"""Loopback tests for the confused-deputy / token-passthrough probe.

Every server binds 127.0.0.1 on a port in 4600-4699 (never 4000/4444/8790) and
is torn down in a finally. Tokens are only ever compared as fingerprints.

The run is self-checking: the probe runs a deliberately-leaky deputy as an
in-run broken fixture and will not return OK unless that fixture was shown to
FAIL in the same run, so every OK here is backed by an observed failure.
"""

import socket
import threading
import unittest
from contextlib import contextmanager

from strangertest.confused_deputy import (
    ConfusedDeputyResult,
    CallerSpec,
    combine_confused_deputy_grades,
    grade_confused_deputy_call,
    run_confused_deputy_probe,
    token_fingerprint,
)
from strangertest.mcp_client import MCPClient
from strangertest.practice_confused_deputy_http import (
    DEPUTY_SUBJECT,
    GATEWAY_AUDIENCE,
    HTTPMockUpstream,
    build_confused_deputy_server,
    make_caller_token,
)
from strangertest.probe import Identity
from strangertest.transports import HTTPTransport

AUD = "https://api.myserver.example/mcp"  # the upstream's own audience
PORT_LO, PORT_HI = 4600, 4699
FORBIDDEN_PORTS = {4000, 4444, 8790}


def _free_port() -> int:
    """A free TCP port in 4600-4699 (never a forbidden one)."""
    for port in range(PORT_LO, PORT_HI + 1):
        if port in FORBIDDEN_PORTS:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("no free port in 4600-4699")


@contextmanager
def harness(mode):
    upstream = HTTPMockUpstream(AUD, port=_free_port()).start()
    server = build_confused_deputy_server(
        mode, upstream.url, upstream.expected_audience, port=_free_port())
    for addr in (upstream._server.server_address, server.server_address):
        assert PORT_LO <= addr[1] <= PORT_HI and addr[1] not in FORBIDDEN_PORTS, addr
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/mcp", upstream
    finally:
        server.shutdown()
        server.server_close()
        upstream.stop()


def _caller(url, subject):
    token = make_caller_token(subject)
    identity = Identity(
        label=subject,
        connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {token}"})),
    )
    return CallerSpec(identity=identity, subject=subject,
                      inbound_token_fp=token_fingerprint(token))


def _sensitive(client):
    client.call_tool("call_upstream", {})


def _benign(client):
    client.call_tool("benign_upstream", {})


def _run(mode, *, with_broken_fixture=True, **kw):
    """Run the probe against ``mode``. When ``with_broken_fixture`` is set, a
    fresh leaky deputy is run as the in-run broken fixture in the SAME call."""
    def broken_fixture():
        with harness("leaky") as (burl, bup):
            return run_confused_deputy_probe(
                burl, _caller(burl, "alice"), _caller(burl, "bob"),
                upstream=bup, sensitive_trigger=_sensitive, benign_trigger=_benign,
                expected_audience=AUD, broken_fixture=None, **kw)

    with harness(mode) as (url, upstream):
        return run_confused_deputy_probe(
            url, _caller(url, "alice"), _caller(url, "bob"),
            upstream=upstream, sensitive_trigger=_sensitive, benign_trigger=_benign,
            expected_audience=AUD,
            broken_fixture=broken_fixture if with_broken_fixture else None, **kw)


class ConfusedDeputyOverHTTPTests(unittest.TestCase):
    # -- the two headline modes -------------------------------------------
    def test_leaky_passthrough_is_a_leak(self):
        report = _run("leaky", with_broken_fixture=False)
        self.assertIsInstance(report, ConfusedDeputyResult)
        self.assertEqual(report.grade, "FAIL")
        self.assertEqual(report.label, "token_passthrough")
        self.assertTrue(report.vulnerable)
        self.assertIn("LEAK", report.summary())

    def test_safe_exchange_is_ok(self):
        report = _run("safe")
        self.assertEqual(report.grade, "OK", report.reason)
        self.assertEqual(report.label, "exchanged")
        # The OK only stands because the in-run broken fixture was shown to FAIL.
        self.assertTrue(report.controls["broken_fixture_failed"])
        self.assertEqual(report.broken_fixture["grade"], "FAIL")
        self.assertTrue(report.controls["control_reached_upstream"])

    # -- the other leak shapes --------------------------------------------
    def test_own_authority_is_a_leak(self):
        report = _run("own_authority", with_broken_fixture=False)
        self.assertEqual(report.grade, "FAIL")
        self.assertEqual(report.label, "own_authority")
        # The deputy's own account, with its broad scope, reached the upstream.
        leak = next(c for c in report.per_call if c["grade"] == "FAIL")
        self.assertEqual(leak["upstream_subject"], DEPUTY_SUBJECT)

    def test_wrong_audience_is_a_leak(self):
        report = _run("wrong_audience", with_broken_fixture=False)
        self.assertEqual(report.grade, "FAIL")
        self.assertEqual(report.label, "wrong_audience")

    def test_safe_refuse_is_ok_refused(self):
        report = _run("safe_refuse")
        self.assertEqual(report.grade, "OK", report.reason)
        self.assertEqual(report.label, "refused")
        # Refusal only reads as OK because the benign control DID reach upstream.
        self.assertTrue(report.controls["control_reached_upstream"])
        self.assertEqual(report.per_call, [])

    # -- controls behave --------------------------------------------------
    def test_broken_fixture_is_graded_fail_in_run(self):
        report = _run("safe")
        self.assertIsNotNone(report.broken_fixture)
        self.assertEqual(report.broken_fixture["grade"], "FAIL")

    def test_no_broken_fixture_blocks_ok(self):
        # Without a broken fixture shown to fail, a clean exchange cannot be OK.
        report = _run("safe", with_broken_fixture=False)
        self.assertEqual(report.grade, "INCONCLUSIVE")
        self.assertFalse(report.controls["broken_fixture_failed"])

    def test_seen_leak_not_downgraded_by_missing_controls(self):
        # A leak stays FAIL even with no broken fixture and nothing else set.
        report = _run("leaky", with_broken_fixture=False)
        self.assertEqual(report.grade, "FAIL")

    def test_positive_control_reached_upstream(self):
        report = _run("safe")
        self.assertTrue(report.controls["control_reached_upstream"])

    def test_authorization_is_enforced(self):
        from strangertest.guard import AuthorizationError
        from strangertest.delegate import MockUpstream  # no socket: authorize raises first
        with self.assertRaises(AuthorizationError):
            run_confused_deputy_probe(
                "https://not-local.example/mcp",
                CallerSpec(Identity("a", lambda: None), "alice", None),
                CallerSpec(Identity("b", lambda: None), "bob", None),
                upstream=MockUpstream(AUD),
                sensitive_trigger=_sensitive, benign_trigger=_benign,
                expected_audience=AUD)


class GraderUnitTests(unittest.TestCase):
    """The pure grader, with no server in the loop."""

    def test_passthrough_detected_by_fingerprint(self):
        g = grade_confused_deputy_call(
            caller_subject="alice", inbound_token_fp="sha256:abc",
            upstream_subject="alice", upstream_audience=GATEWAY_AUDIENCE,
            upstream_scope="read:notes", upstream_token_fp="sha256:abc",
            expected_audience=AUD)
        self.assertEqual(g["grade"], "FAIL")
        self.assertEqual(g["label"], "token_passthrough")

    def test_wrong_audience_without_passthrough(self):
        g = grade_confused_deputy_call(
            caller_subject="alice", inbound_token_fp="sha256:abc",
            upstream_subject="alice", upstream_audience="https://other/api",
            upstream_scope="read:notes", upstream_token_fp="sha256:zzz",
            expected_audience=AUD)
        self.assertEqual(g["label"], "wrong_audience")

    def test_own_authority_subject(self):
        g = grade_confused_deputy_call(
            caller_subject="alice", inbound_token_fp="sha256:abc",
            upstream_subject="svc-deputy", upstream_audience=AUD,
            upstream_scope="admin", upstream_token_fp="sha256:zzz",
            expected_audience=AUD, deputy_subjects=("svc-deputy",))
        self.assertEqual(g["label"], "own_authority")

    def test_faithful_exchange_is_ok(self):
        g = grade_confused_deputy_call(
            caller_subject="alice", inbound_token_fp="sha256:abc",
            upstream_subject="alice", upstream_audience=AUD,
            upstream_scope="read:notes", upstream_token_fp="sha256:fresh",
            expected_audience=AUD)
        self.assertEqual(g["grade"], "OK")
        self.assertEqual(g["label"], "exchanged")

    def test_undecodable_is_inconclusive(self):
        g = grade_confused_deputy_call(
            caller_subject="alice", inbound_token_fp="sha256:abc",
            upstream_subject=None, upstream_audience=None, upstream_scope=None,
            upstream_token_fp=None, expected_audience=AUD, parsed=False)
        self.assertEqual(g["grade"], "INCONCLUSIVE")

    def test_aud_as_list_is_accepted(self):
        g = grade_confused_deputy_call(
            caller_subject="alice", inbound_token_fp="sha256:abc",
            upstream_subject="alice", upstream_audience=[AUD, "urn:other"],
            upstream_scope=["read:notes"], upstream_token_fp="sha256:fresh",
            expected_audience=AUD)
        self.assertEqual(g["grade"], "OK")

    def test_combine_seen_leak_beats_failed_controls(self):
        per_call = [{"grade": "FAIL", "label": "token_passthrough", "reason": "x"}]
        grade, label, _ = combine_confused_deputy_grades(
            per_call, {"broken_fixture_failed": False}, control_reached=False)
        self.assertEqual(grade, "FAIL")

    def test_combine_ok_needs_controls(self):
        per_call = [{"grade": "OK", "label": "exchanged", "reason": "x"}]
        grade, _, _ = combine_confused_deputy_grades(
            per_call, {"broken_fixture_failed": False}, control_reached=True)
        self.assertEqual(grade, "INCONCLUSIVE")
        grade2, _, _ = combine_confused_deputy_grades(
            per_call, {"broken_fixture_failed": True}, control_reached=True)
        self.assertEqual(grade2, "OK")

    def test_combine_refused_needs_positive_control(self):
        grade, _, _ = combine_confused_deputy_grades(
            [], {"broken_fixture_failed": True}, control_reached=False)
        self.assertEqual(grade, "INCONCLUSIVE")
        grade2, label, _ = combine_confused_deputy_grades(
            [], {"broken_fixture_failed": True}, control_reached=True)
        self.assertEqual((grade2, label), ("OK", "refused"))


if __name__ == "__main__":
    unittest.main()
