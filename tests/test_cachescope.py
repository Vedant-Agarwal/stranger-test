import unittest

from strangertest.cachescope import (
    INCONCLUSIVE, LEAK, OK, run_cachescope_probe,
)
from strangertest.guard import AuthorizationError
from strangertest.mcp_client import MCPClient
from strangertest.practice_cache_http import CacheStack, UpstreamConfig
from strangertest.probe import Identity, ProbeError
from strangertest.transports import HTTPTransport

URI = "note://shared/inbox"


def _identity(url, token, label):
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {token}"}, modern=True)
        ),
    )


def probe(stack, **kw):
    return run_cachescope_probe(
        stack.proxy_url,
        stack.upstream_url,
        _identity(stack.proxy_url, "alice", "A"),
        _identity(stack.proxy_url, "bob", "B"),
        direct_a=_identity(stack.upstream_url, "alice", "A-direct"),
        direct_b=_identity(stack.upstream_url, "bob", "B-direct"),
        uri=URI,
        upstream_calls=stack.upstream_calls,
        **kw,
    )


def run(upstream, mode, **stack_kw):
    with CacheStack(upstream, mode, **stack_kw) as stack:
        return probe(stack)


class HonouringTests(unittest.TestCase):
    def test_leaky_proxy_serves_private_result_to_b(self):
        r = run(UpstreamConfig("private"), "leaky")
        self.assertEqual(r.honouring.grade, LEAK)
        self.assertEqual(r.labelling.grade, OK)
        self.assertTrue(r.leaked)
        self.assertTrue(r.observations["caching_observed"])
        self.assertIn("failure_class", r.to_dict())

    def test_safe_proxy_passes(self):
        r = run(UpstreamConfig("private"), "safe")
        self.assertEqual(r.honouring.grade, OK)
        self.assertEqual(r.labelling.grade, OK)
        self.assertFalse(r.leaked)
        self.assertTrue(r.observations["caching_observed"])

    def test_non_caching_proxy_is_inconclusive_not_ok(self):
        r = run(UpstreamConfig("private"), "nocache")
        self.assertEqual(r.honouring.grade, INCONCLUSIVE)
        self.assertFalse(r.observations["caching_observed"])

    def test_proxy_skipping_private_is_inconclusive(self):
        r = run(UpstreamConfig("private"), "skip_private")
        self.assertEqual(r.honouring.grade, INCONCLUSIVE)

    def test_zero_ttl_means_no_caching_observed(self):
        r = run(UpstreamConfig("private", ttl_ms=0), "leaky")
        self.assertEqual(r.honouring.grade, INCONCLUSIVE)

    def test_public_shared_content_cached_ok(self):
        # Shared caching is allowed for a truthful public result.
        for mode in ("leaky", "safe"):
            r = run(UpstreamConfig("public", per_user=False), mode)
            self.assertFalse(r.leaked, mode)
            self.assertEqual(r.labelling.grade, INCONCLUSIVE)
            self.assertEqual(r.honouring.grade, INCONCLUSIVE)  # nothing private

    def test_identical_content_has_nothing_to_leak(self):
        r = run(UpstreamConfig("private", per_user=False), "leaky")
        self.assertEqual(r.honouring.grade, INCONCLUSIVE)
        self.assertFalse(r.leaked)


class LeakBeforeControlsTests(unittest.TestCase):
    def test_leak_without_caching_observed_is_leak(self):
        # Item 1/10a: the proxy hits the origin every time (count rises, so the
        # caching control fails) yet serves A's private result to B.
        r = run(UpstreamConfig("private"), "stale_shared")
        self.assertFalse(r.observations["caching_observed"])
        self.assertEqual(r.honouring.grade, LEAK)
        self.assertTrue(r.leaked)


class UnstableContentTests(unittest.TestCase):
    def test_clock_style_public_content_is_inconclusive_not_leak(self):
        # Item 2/10b: public label, content changes on every read.
        for mode in ("leaky", "safe"):
            r = run(UpstreamConfig("public", per_user=False, unstable=True), mode)
            self.assertEqual(r.labelling.grade, INCONCLUSIVE, mode)
            self.assertIn("unstable", r.labelling.detail)
            self.assertFalse(r.leaked, mode)
            self.assertFalse(r.observations["origin_stable"])

    def test_unstable_per_user_private_never_leak(self):
        r = run(UpstreamConfig("private", unstable=True), "leaky")
        self.assertNotEqual(r.honouring.grade, LEAK)
        self.assertEqual(r.labelling.grade, INCONCLUSIVE)


class LabellingTests(unittest.TestCase):
    def test_identical_content_is_inconclusive_not_ok(self):
        for scope in ("public", "private", None):
            r = run(UpstreamConfig(scope, per_user=False), "safe")
            self.assertEqual(r.labelling.grade, INCONCLUSIVE, scope)
            self.assertIn("not identity-specific", r.labelling.detail)
            self.assertEqual(r.honouring.grade, INCONCLUSIVE, scope)
            self.assertFalse(r.leaked)

    def test_public_label_on_per_user_content_is_leak(self):
        for mode in ("leaky", "safe"):
            r = run(UpstreamConfig("public"), mode)
            self.assertEqual(r.labelling.grade, LEAK, mode)
            self.assertTrue(r.leaked)
        self.assertIn(
            "labelled cacheScope=public",
            run(UpstreamConfig("public"), "safe").to_dict()["failure_class"][0],
        )

    def test_public_mislabel_shared_by_proxy_not_double_counted_as_honouring(self):
        r = run(UpstreamConfig("public"), "leaky")
        self.assertEqual(r.labelling.grade, LEAK)
        self.assertEqual(r.honouring.grade, INCONCLUSIVE)

    def test_missing_scope_is_observation_not_leak(self):
        r = run(UpstreamConfig(None), "safe")
        self.assertEqual(r.labelling.grade, INCONCLUSIVE)
        self.assertIn("unlabelled", r.labelling.detail)
        self.assertTrue(r.observations["unlabelled"])
        self.assertFalse(r.leaked)

    def test_private_correctly_labelled_ok(self):
        r = run(UpstreamConfig("private"), "safe")
        self.assertEqual(r.labelling.grade, OK)
        self.assertTrue(r.observations["content_differs_per_identity"])

    def test_invalid_scope_value_is_inconclusive(self):
        r = run(UpstreamConfig("everyone"), "safe")
        self.assertEqual(r.labelling.grade, INCONCLUSIVE)


class ObservationTests(unittest.TestCase):
    def test_hints_passed_through(self):
        r = run(UpstreamConfig("private", ttl_ms=5000), "safe")
        self.assertTrue(r.observations["hints_passed_through"])
        self.assertEqual(r.observations["origin_ttl_ms"], 5000)
        self.assertEqual(r.observations["origin_cache_scope"], "private")

    def test_hints_rewritten_by_proxy(self):
        r = run(UpstreamConfig("private"), "safe",
                rewrite_hints={"cacheScope": "public"})
        self.assertFalse(r.observations["hints_passed_through"])


class BReceivedTests(unittest.TestCase):
    def test_records_what_b_received(self):
        cases = [
            (UpstreamConfig("private"), "leaky", "a"),
            (UpstreamConfig("private"), "stale_shared", "a"),
            (UpstreamConfig("private"), "safe", "own"),
            (UpstreamConfig("private"), "nocache", "own"),
            (UpstreamConfig("private", unstable=True), "safe", "other"),
        ]
        for up, mode, want in cases:
            r = run(up, mode)
            self.assertEqual(r.observations["b_received"], want, mode)

    def test_b_read_error_is_recorded(self):
        class FailingRead(MCPClient):
            def read_resource(self, uri, *a, **k):
                raise RuntimeError("boom")

        with CacheStack(UpstreamConfig("private"), "safe") as stack:
            bad_b = Identity(
                label="B",
                connect=lambda: FailingRead(HTTPTransport(
                    stack.proxy_url,
                    headers={"Authorization": "Bearer bob"}, modern=True)),
            )
            r = run_cachescope_probe(
                stack.proxy_url, stack.upstream_url,
                _identity(stack.proxy_url, "alice", "A"), bad_b,
                direct_a=_identity(stack.upstream_url, "alice", "A"),
                direct_b=_identity(stack.upstream_url, "bob", "B"),
                uri=URI, upstream_calls=stack.upstream_calls,
            )
        self.assertEqual(r.observations["b_received"], "error")
        self.assertEqual(r.honouring.grade, INCONCLUSIVE)


class GuardAndErrorTests(unittest.TestCase):
    def test_guard_refuses_remote_target_before_any_request(self):
        with CacheStack(UpstreamConfig(), "safe") as stack:
            before = stack.upstream_calls()
            with self.assertRaises(AuthorizationError):
                run_cachescope_probe(
                    "https://mcp.example.com/mcp",
                    stack.upstream_url,
                    _identity(stack.proxy_url, "alice", "A"),
                    _identity(stack.proxy_url, "bob", "B"),
                    direct_a=_identity(stack.upstream_url, "alice", "A"),
                    direct_b=_identity(stack.upstream_url, "bob", "B"),
                    uri=URI,
                    upstream_calls=stack.upstream_calls,
                )
            self.assertEqual(stack.upstream_calls(), before)

    def test_guard_refuses_remote_upstream(self):
        with CacheStack(UpstreamConfig(), "safe") as stack:
            with self.assertRaises(AuthorizationError):
                run_cachescope_probe(
                    stack.proxy_url,
                    "https://origin.example.com/mcp",
                    _identity(stack.proxy_url, "alice", "A"),
                    _identity(stack.proxy_url, "bob", "B"),
                    direct_a=_identity(stack.upstream_url, "alice", "A"),
                    direct_b=_identity(stack.upstream_url, "bob", "B"),
                    uri=URI,
                    upstream_calls=stack.upstream_calls,
                )

    def test_unreachable_cache_raises_probe_error(self):
        with CacheStack(UpstreamConfig(), "safe") as stack:
            ident = _identity("http://127.0.0.1:1/mcp", "alice", "A")
            with self.assertRaises(ProbeError):
                run_cachescope_probe(
                    "http://127.0.0.1:1/mcp",
                    stack.upstream_url,
                    ident,
                    _identity("http://127.0.0.1:1/mcp", "bob", "B"),
                    direct_a=_identity(stack.upstream_url, "alice", "A"),
                    direct_b=_identity(stack.upstream_url, "bob", "B"),
                    uri=URI,
                    upstream_calls=stack.upstream_calls,
                )

    def test_unreachable_origin_raises_probe_error(self):
        with CacheStack(UpstreamConfig(), "safe") as stack:
            with self.assertRaises(ProbeError):
                run_cachescope_probe(
                    stack.proxy_url,
                    "http://127.0.0.1:1/mcp",
                    _identity(stack.proxy_url, "alice", "A"),
                    _identity(stack.proxy_url, "bob", "B"),
                    direct_a=_identity("http://127.0.0.1:1/mcp", "alice", "A"),
                    direct_b=_identity("http://127.0.0.1:1/mcp", "bob", "B"),
                    uri=URI,
                    upstream_calls=stack.upstream_calls,
                )


if __name__ == "__main__":
    unittest.main()
