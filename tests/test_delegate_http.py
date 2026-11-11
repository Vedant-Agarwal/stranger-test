import threading
import unittest
from contextlib import contextmanager

from strangertest.delegate import DelegationReport, run_delegation_probe
from strangertest.mcp_client import MCPClient
from strangertest.practice_delegation_http import (
    HTTPMockUpstream,
    build_delegation_server,
)
from strangertest.probe import Identity, ProbeError
from strangertest.transports import HTTPTransport

AUD = "https://api.myserver.example/mcp"


@contextmanager
def harness(mode):
    upstream = HTTPMockUpstream(AUD).start()
    server = build_delegation_server(mode, upstream.url, upstream.expected_audience)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/mcp", upstream
    finally:
        server.shutdown()
        server.server_close()
        upstream.stop()


def _identity(url, token, label):
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {token}"})
        ),
    )


def _trigger(client):
    client.call_tool("do_upstream", {})


def _run(mode, upstream_out=None, **kw):
    with harness(mode) as (url, upstream):
        report = run_delegation_probe(
            url,
            _identity(url, "alice", "A"),
            _identity(url, "bob", "B"),
            upstream=upstream,
            trigger=_trigger,
            expected_subject_a="alice",
            expected_subject_b="bob",
            **kw,
        )
        if upstream_out is not None:
            upstream_out.append(upstream)
    return report


class DelegationOverHTTPTests(unittest.TestCase):
    def test_faithful_delegation_passes_over_http(self):
        seen = []
        report = _run("safe", seen)
        self.assertIsInstance(report, DelegationReport)
        self.assertFalse(report.vulnerable, report.failures)
        self.assertTrue(all(report.checks.values()))
        # Positive control: the upstream really did receive three calls (A, B, A).
        self.assertEqual(len(seen[0].calls), 3)

    def test_audience_as_list_passes_over_http(self):
        report = _run("safe_list_aud")
        self.assertFalse(report.vulnerable, report.failures)

    def test_static_credential_detected_over_http(self):
        report = _run("static_credential")
        self.assertTrue(report.vulnerable)
        self.assertIn("LEAK", report.summary())
        self.assertFalse(report.checks["subject_preserved"])
        self.assertFalse(report.checks["actor_present"])
        self.assertFalse(report.checks["no_token_reuse"])

    def test_wrong_audience_is_the_only_failure(self):
        report = _run("wrong_audience")
        self.assertEqual(report.failures, ["audience_correct"])

    def test_broad_scope_is_the_only_failure(self):
        report = _run("broad_scope")
        self.assertEqual(report.failures, ["scope_narrowed"])

    def test_impersonation_actor_optional_over_http(self):
        self.assertEqual(_run("impersonation").failures, ["actor_present"])
        self.assertFalse(_run("impersonation", require_actor=False).vulnerable)

    def test_token_passthrough_fails_audience_and_actor(self):
        report = _run("token_passthrough")
        self.assertTrue(report.vulnerable)
        self.assertFalse(report.checks["audience_correct"])
        self.assertFalse(report.checks["actor_present"])
        # Subject was preserved and tokens were distinct per caller.
        self.assertTrue(report.checks["subject_preserved"])
        self.assertTrue(report.checks["no_token_reuse"])

    def test_cached_token_reuse_detected_over_http(self):
        report = _run("cached_token_reuse")
        self.assertTrue(report.vulnerable)
        self.assertFalse(report.checks["no_cross_identity_bleed"])
        self.assertFalse(report.checks["no_token_reuse"])

    def test_opaque_token_is_inconclusive(self):
        with self.assertRaises(ProbeError):
            _run("opaque_token")


if __name__ == "__main__":
    unittest.main()
