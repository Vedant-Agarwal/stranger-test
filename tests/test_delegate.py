import unittest

from strangertest.delegate import (
    DelegationReport,
    MockUpstream,
    run_delegation_probe,
)
from strangertest.mcp_client import MCPClient, Transport
from strangertest.probe import Identity, ProbeError

AUD = "https://api.myserver.example/mcp"


def _result(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


class DelegatingServer:
    """Emits a chosen delegation profile to the upstream on each tool call.

    Profiles are hand-built UpstreamCall values so the probe's grading can be
    exercised one failure at a time (not an unrealistic everything-fails blob).
    """

    def __init__(self, upstream, mode):
        self.upstream = upstream
        self.mode = mode
        self._n = 0

    def handle(self, transport, msg):
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            return _result(mid, {
                "protocolVersion": "2026-07-28",
                "serverInfo": {"name": "deleg"},
                "capabilities": {"tools": {}},
            })
        if method == "tools/call" and msg["params"]["name"] == "do_upstream":
            self._n += 1
            self._emit(transport)
            return _result(mid, {"content": [{"type": "text", "text": "done"}]})
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": "no"}}

    def _emit(self, transport):
        up, n = self.upstream, self._n
        ident = transport.identity_id
        iss = getattr(transport, "issuer", None)
        if self.mode == "subject_only_cache":
            # Keys its cache on subject alone: a same-named user from another
            # provider is served the first one's token.
            if not hasattr(self, "_sc"):
                self._sc = {}
            if ident not in self._sc:
                self._sc[ident] = (ident, iss, f"tok-{ident}-{n}")
            sub, siss, tok = self._sc[ident]
            up.receive(subject=sub, issuer=siss, actor="agent-7", audience=AUD,
                       scope="read:notes", token=tok)
        elif self.mode == "safe":
            up.receive(subject=ident, issuer=iss, actor="agent-7", audience=AUD,
                       scope="read:notes", token=f"tok-{ident}-{n}")
        elif self.mode == "safe_list_aud":
            up.receive(subject=ident, actor="agent-7", audience=[AUD, "urn:other"],
                       scope=["read:notes"], token=f"tok-{ident}-{n}")
        elif self.mode == "static_credential":
            # Confused deputy: own service account, no actor, one reused token.
            up.receive(subject="svc-deputy", actor=None, audience=AUD,
                       scope="read:notes", token="static-master")
        elif self.mode == "impersonation":
            # Subject preserved, but the acting agent is invisible (no actor).
            up.receive(subject=ident, actor=None, audience=AUD,
                       scope="read:notes", token=f"tok-{ident}-{n}")
        elif self.mode == "cached_reuse":
            # Exchanges once, then serves everyone as the first identity.
            if not hasattr(self, "_cached"):
                self._cached = (ident, f"tok-{ident}-{n}")
            sub, tok = self._cached
            up.receive(subject=sub, actor="agent-7", audience=AUD,
                       scope="read:notes", token=tok)
        elif self.mode == "discovery":
            # A non-user discovery call on a separate credential precedes the
            # per-user tool call; the probe must ignore the former.
            up.receive(method="tools/list", subject="svc-deputy",
                       token=f"disc-{n}")
            up.receive(subject=ident, actor="agent-7", audience=AUD,
                       scope="read:notes", token=f"tok-{ident}-{n}")
        elif self.mode == "unparsed":
            up.receive(token="opaque", parsed=False, parse_error="not a JWT")
        else:
            raise ValueError(self.mode)


class _T(Transport):
    def __init__(self, server, identity_id, issuer=None):
        self.server = server
        self.identity_id = identity_id
        self.issuer = issuer

    def request(self, message):
        return self.server.handle(self, message)

    def notify(self, message):
        pass


def _identity(server, ident, label, issuer=None):
    return Identity(label=label,
                    connect=lambda: MCPClient(_T(server, ident, issuer)))


def _trigger(client):
    client.call_tool("do_upstream", {})


def _run(mode, **kw):
    up = MockUpstream(AUD)
    server = DelegatingServer(up, mode)
    return run_delegation_probe(
        "http://localhost/practice",
        _identity(server, "alice", "A"),
        _identity(server, "bob", "B"),
        upstream=up,
        trigger=_trigger,
        expected_subject_a="alice",
        expected_subject_b="bob",
        **kw,
    )


class DelegationProbeTests(unittest.TestCase):
    def test_safe_delegation_passes(self):
        report = _run("safe")
        self.assertIsInstance(report, DelegationReport)
        self.assertFalse(report.vulnerable)
        self.assertIn("OK", report.summary())
        self.assertTrue(all(report.checks.values()))
        self.assertNotIn("failure_class", report.to_dict())

    def test_audience_as_list_passes(self):
        # aud/scope delivered as JSON lists must grade the same as strings.
        report = _run("safe_list_aud")
        self.assertFalse(report.vulnerable, report.failures)
        self.assertTrue(report.checks["audience_correct"])
        self.assertTrue(report.checks["scope_narrowed"])

    def test_static_credential_fails_subject_actor_and_reuse_only(self):
        report = _run("static_credential")
        self.assertTrue(report.vulnerable)
        self.assertFalse(report.checks["subject_preserved"])
        self.assertFalse(report.checks["actor_present"])
        self.assertFalse(report.checks["no_token_reuse"])
        # audience and scope were fine: a graded result, not everything-fails.
        self.assertTrue(report.checks["audience_correct"])
        self.assertTrue(report.checks["scope_narrowed"])

    def test_impersonation_actor_is_optional(self):
        # With require_actor=False only the actor check would differ, and it is
        # not counted — so an impersonating server passes.
        strict = _run("impersonation")
        self.assertTrue(strict.vulnerable)
        self.assertEqual(strict.failures, ["actor_present"])
        lenient = _run("impersonation", require_actor=False)
        self.assertFalse(lenient.vulnerable, lenient.failures)

    def test_cached_reuse_fails_bleed_subject_and_reuse(self):
        report = _run("cached_reuse")
        self.assertTrue(report.vulnerable)
        self.assertFalse(report.checks["no_cross_identity_bleed"])
        self.assertFalse(report.checks["subject_preserved"])
        self.assertFalse(report.checks["no_token_reuse"])

    def test_discovery_traffic_is_ignored(self):
        # A tools/list call on the gateway's own credential must not be graded.
        report = _run("discovery")
        self.assertFalse(report.vulnerable, report.failures)
        self.assertTrue(all(report.checks.values()))

    def test_same_name_different_provider_distinguished(self):
        # Two users both named "alice" from different providers are different
        # principals: identity is (issuer, subject).
        def run(mode):
            up = MockUpstream(AUD)
            server = DelegatingServer(up, mode)
            return run_delegation_probe(
                "http://localhost/practice",
                _identity(server, "alice", "A", issuer="provX"),
                _identity(server, "alice", "B", issuer="provY"),
                upstream=up, trigger=_trigger,
                expected_subject_a="alice", expected_subject_b="alice",
                expected_issuer_a="provX", expected_issuer_b="provY",
            )
        self.assertFalse(run("safe").vulnerable, "faithful deputy preserves issuer")
        bled = run("subject_only_cache")
        self.assertTrue(bled.vulnerable)
        self.assertFalse(bled.checks["subject_preserved"])

    def test_unparseable_token_is_inconclusive(self):
        with self.assertRaises(ProbeError):
            _run("unparsed")

    def test_authorization_enforced_before_connecting(self):
        up = MockUpstream(AUD)

        def must_not_connect():
            raise AssertionError("connected before authorization passed")

        blocked = Identity(label="X", connect=must_not_connect)
        with self.assertRaises(Exception):
            run_delegation_probe(
                "https://mcp.example.com/",
                blocked,
                blocked,
                upstream=up,
                trigger=_trigger,
                expected_subject_a="a",
                expected_subject_b="b",
            )


if __name__ == "__main__":
    unittest.main()
