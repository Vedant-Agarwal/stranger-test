"""Stand up the practice state-handle server on loopback and grade the probe.

Ports are confined to 4600-4699 (never 4000/4444/8790). Every server started
here is shut down in a ``finally``.
"""

import socket
import threading
import unittest
from contextlib import contextmanager

from strangertest.guard import AuthorizationError
from strangertest.practice_statehandle_http import FORBIDDEN_PORTS, build_server
from strangertest.probe import Identity
from strangertest.statehandle import (
    INCONCLUSIVE,
    LEAK,
    OBSERVATION,
    OK,
    StateHandlePlan,
    run_statehandle_probe,
    statehandle_canary,
    statehandle_identity,
    _contains_exact,
    _default_extract_handle,
)

PORT_RANGE = range(4600, 4700)


def _build_in_range(mode, **kwargs):
    """Build a server bound to a free port in 4600-4699 (never a forbidden one)."""
    last = None
    for port in PORT_RANGE:
        if port in FORBIDDEN_PORTS:
            continue
        try:
            return build_server(mode, port=port, **kwargs)
        except OSError as exc:
            last = exc
    raise RuntimeError(f"no free port in {PORT_RANGE.start}-{PORT_RANGE.stop - 1}: {last}")


@contextmanager
def running_server(mode, **kwargs):
    server = _build_in_range(mode, **kwargs)
    assert PORT_RANGE.start <= server.server_address[1] < PORT_RANGE.stop
    assert server.server_address[1] not in FORBIDDEN_PORTS
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    finally:
        server.shutdown()
        server.server_close()


def _canary_against(leaky_url, **kw):
    """A canary bound to a known-leaky server (the broken-fixture self-check)."""
    return lambda: statehandle_canary(
        statehandle_identity(leaky_url, "canary-a", "CA"),
        statehandle_identity(leaky_url, "canary-b", "CB"),
        **kw,
    )


def probe(url, canary=None, **kw):
    return run_statehandle_probe(
        url,
        statehandle_identity(url, "alice", "A"),
        statehandle_identity(url, "bob", "B"),
        canary=canary,
        **kw,
    )


class LeakyTests(unittest.TestCase):
    def test_leaky_leaks(self):
        with running_server("leaky") as url:
            r = probe(url)
        self.assertEqual(r.grade, LEAK, r.detail)
        self.assertTrue(r.leaked)
        self.assertIn("LEAK", r.summary())
        self.assertEqual(r.to_dict()["failure_class"].startswith("state-handle"), True)
        # The positive control (A reads its own state) still passed on a leaky server.
        self.assertEqual(r.controls["a_own_read"], "passed")

    def test_leaky_leaks_even_without_a_canary(self):
        # A confirmed leak is observed directly; it needs no broken-fixture check.
        with running_server("leaky") as url:
            r = probe(url, canary=None)
        self.assertEqual(r.grade, LEAK)


class SafeTests(unittest.TestCase):
    def test_safe_passes_with_canary(self):
        with running_server("safe") as safe_url, running_server("leaky") as leaky_url:
            r = probe(safe_url, canary=_canary_against(leaky_url))
        self.assertEqual(r.grade, OK, r.detail)
        self.assertFalse(r.leaked)
        self.assertIn("OK", r.summary())
        self.assertEqual(r.controls["b_own_read"], "passed")
        self.assertEqual(r.controls["forged_handle"], "refused")
        self.assertIn("fired", r.controls["canary"])

    def test_handles_recorded_only_as_fingerprints(self):
        with running_server("safe") as safe_url, running_server("leaky") as leaky_url:
            r = probe(safe_url, canary=_canary_against(leaky_url))
        self.assertTrue(r.controls["handle_a"].startswith("sha256:"))
        self.assertTrue(r.controls["handle_b"].startswith("sha256:"))
        # No raw handle ("sh-...") anywhere in the serialised report.
        import json as _json
        self.assertNotIn("sh-", _json.dumps(r.to_dict()))


class CanaryGateTests(unittest.TestCase):
    """OK requires the broken-fixture self-check (canary) to fire in this run."""

    def test_safe_without_canary_is_inconclusive_never_ok(self):
        with running_server("safe") as url:
            r = probe(url, canary=None)
        self.assertEqual(r.grade, INCONCLUSIVE)
        self.assertNotEqual(r.grade, OK)
        self.assertIn("canary", r.detail.lower())

    def test_canary_pointed_at_a_safe_server_does_not_fire(self):
        # A canary that is not actually leaky must not let OK through.
        with running_server("safe") as safe_url, running_server("safe") as other_safe:
            r = probe(safe_url, canary=_canary_against(other_safe))
        self.assertEqual(r.grade, INCONCLUSIVE)
        self.assertEqual(r.controls["canary"], "DID NOT fire")

    def test_canary_fires_against_leaky(self):
        with running_server("leaky") as leaky_url:
            self.assertTrue(_canary_against(leaky_url)())
        with running_server("safe") as safe_url:
            self.assertFalse(_canary_against(safe_url)())


class FalsePassControlTests(unittest.TestCase):
    def test_forged_control_fails_when_forged_accepted(self):
        # accept_forged: owner-bound on real handles, but a forged handle is not
        # refused. Refusal is then not evidence of binding -> never OK.
        with running_server("accept_forged") as url, running_server("leaky") as leaky_url:
            r = probe(url, canary=_canary_against(leaky_url))
        self.assertEqual(r.grade, INCONCLUSIVE)
        self.assertNotEqual(r.grade, OK)
        self.assertTrue(r.controls["forged_handle"].startswith("FAILED"))

    def test_both_controls_behave_on_safe(self):
        with running_server("safe") as url, running_server("leaky") as leaky_url:
            r = probe(url, canary=_canary_against(leaky_url))
        self.assertEqual(r.controls["a_own_read"], "passed")
        self.assertEqual(r.controls["b_own_read"], "passed")
        self.assertEqual(r.controls["forged_handle"], "refused")


class InconclusiveTests(unittest.TestCase):
    def test_no_handle_feature_is_inconclusive(self):
        with running_server("no_handle") as url, running_server("leaky") as leaky_url:
            r = probe(url, canary=_canary_against(leaky_url))
        self.assertEqual(r.grade, INCONCLUSIVE)
        self.assertIn("state handle", r.detail)

    def test_blind_observer_positive_control_fails(self):
        with running_server("break_own_read") as url, running_server("leaky") as leaky_url:
            r = probe(url, canary=_canary_against(leaky_url))
        self.assertEqual(r.grade, INCONCLUSIVE)
        self.assertIn("positive control", r.detail)

    def test_unreachable_server_is_inconclusive(self):
        with running_server("safe") as url:
            pass  # server now shut down
        # No second server: setup fails at A.initialize(), before any canary,
        # and nothing else can have rebound the freed port.
        r = probe(url)
        self.assertEqual(r.grade, INCONCLUSIVE)

    def test_mode_switch_in_place(self):
        # A gate swaps leaky -> safe on the SAME server.
        server = _build_in_range("leaky")
        thread = threading.Thread(
            target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            with running_server("leaky") as leaky_url:
                self.assertEqual(probe(url).grade, LEAK)
                server.store.reset("safe")
                self.assertEqual(server.store.handles, {})
                self.assertEqual(probe(url, canary=_canary_against(leaky_url)).grade, OK)
        finally:
            server.shutdown()
            server.server_close()


class JwtIdentityTests(unittest.TestCase):
    """identity_from='jwt': a per-request exchanged token still names one user."""

    import base64 as _b64
    import itertools as _it
    import json as _json
    _counter = _it.count()

    @classmethod
    def _jwt(cls, claims):
        enc = lambda d: cls._b64.urlsafe_b64encode(
            cls._json.dumps(d).encode()).rstrip(b"=").decode()
        return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"

    def _rotating_identity(self, url, sub, label):
        # A fresh token on every request, same principal.
        from strangertest.mcp_client import MCPClient
        from strangertest.transports import HTTPTransport

        jwt_cls = type(self)

        class _Rotating(HTTPTransport):
            def _headers(self_):
                h = super()._headers()
                h["Authorization"] = "Bearer " + jwt_cls._jwt(
                    {"iss": "https://local-as.test", "sub": sub,
                     "n": next(jwt_cls._counter)})
                return h

        return Identity(label, lambda: MCPClient(_Rotating(url)))

    def _rprobe(self, url, canary=None):
        return run_statehandle_probe(
            url,
            self._rotating_identity(url, "alice", "A"),
            self._rotating_identity(url, "bob", "B"),
            canary=canary,
        )

    def test_safe_with_rotating_tokens_is_ok(self):
        with running_server("safe", identity_from="jwt") as url, \
                running_server("leaky", identity_from="jwt") as leaky_url:
            canary = lambda: statehandle_canary(
                self._rotating_identity(leaky_url, "canary-a", "CA"),
                self._rotating_identity(leaky_url, "canary-b", "CB"))
            self.assertEqual(self._rprobe(url, canary=canary).grade, OK)

    def test_leaky_with_rotating_tokens_leaks(self):
        with running_server("leaky", identity_from="jwt") as url:
            self.assertEqual(self._rprobe(url).grade, LEAK)

    def test_header_identity_cannot_follow_rotating_tokens(self):
        # Why the jwt option exists: keyed on the raw header, A cannot reach its
        # own state (each request is a new token), so the probe must not say OK.
        with running_server("safe") as url:
            self.assertNotEqual(self._rprobe(url).grade, OK)


class GuardTests(unittest.TestCase):
    def test_public_target_refused_before_any_connection(self):
        def boom():
            raise AssertionError("connected despite refusal")

        with self.assertRaises(AuthorizationError):
            run_statehandle_probe(
                "https://mcp.example.com/mcp", Identity("A", boom), Identity("B", boom))


class HelperTests(unittest.TestCase):
    def test_exact_leaf_match_only(self):
        self.assertTrue(_contains_exact({"a": [{"t": "m1"}]}, "m1"))
        self.assertFalse(_contains_exact({"a": "xm1x"}, "m1"))
        self.assertFalse(_contains_exact({"m1": 1}, "m1"))

    def test_extract_handle_reads_structured_or_top_level_only(self):
        self.assertEqual(
            _default_extract_handle({"structuredContent": {"handle": "sh-x"}}), "sh-x")
        self.assertEqual(_default_extract_handle({"handle": "sh-z"}), "sh-z")
        # A plain acknowledgement text is NOT treated as a handle.
        self.assertIsNone(
            _default_extract_handle({"content": [{"type": "text", "text": "opened"}]}))
        self.assertIsNone(_default_extract_handle({"content": []}))

    def test_plan_defaults(self):
        plan = StateHandlePlan()
        self.assertEqual(plan.open_tool, "open_state")
        self.assertEqual(plan.read_tool, "read_state")
        self.assertTrue(plan.forged_handle().startswith("sh-forged-"))


if __name__ == "__main__":
    unittest.main()


class IdentityDistinctnessTests(unittest.TestCase):
    """A handle replay is a cross-user LEAK only when A and B are distinct
    principals. A server that collapses them (shared session / credential), or
    exposes no principal signal, grades OBSERVATION, not LEAK — this is the
    false-positive precision fix (e.g. an identity-collapsing gateway)."""

    def test_collapse_is_observation_not_leak(self):
        # B reaches A's state, but the server maps both to one principal.
        with running_server("leaky") as leaky_url, running_server("collapse") as url:
            r = probe(url, canary=_canary_against(leaky_url))
        self.assertEqual(r.grade, OBSERVATION, r.detail)
        self.assertFalse(r.leaked)
        self.assertIn("COLLAPSED", r.controls["identities"])
        self.assertIn("identity collapse", r.summary())
        self.assertNotIn("failure_class", r.to_dict())

    def test_no_principal_signal_is_observation_not_leak(self):
        # A leaky server, but with no way to confirm A and B are distinct.
        plan = StateHandlePlan(principal_of=lambda client: None)
        with running_server("leaky") as leaky_url, running_server("leaky") as url:
            r = probe(url, canary=_canary_against(leaky_url), plan=plan)
        self.assertEqual(r.grade, OBSERVATION, r.detail)
        self.assertFalse(r.leaked)
        self.assertIn("UNVERIFIED", r.controls["identities"])

    def test_distinct_principals_still_leak(self):
        # The genuine cross-user leak: distinct principals, handle treated as auth.
        with running_server("leaky") as url:
            r = probe(url)
        self.assertEqual(r.grade, LEAK, r.detail)
        self.assertEqual(r.controls["identities"], "distinct")
