"""Unit tests for the safe scan check catalog.

Every check is driven with hand-built synthetic :class:`TargetProfile` fixtures.
Each check has BOTH a risky case (asserting the intended RISK/OBSERVATION grade)
and a benign false-pass control (a clean server must grade OK, not light up), plus
an INCONCLUSIVE case where the profile lacks the data. No network, no live target.
"""

import unittest

from strangertest.scan.checks import run_checks, CHECKS
from strangertest.scan.model import (
    AuthInfo,
    CacheInfo,
    ScanFinding,
    SessionInfo,
    TargetProfile,
    GRADES,
    SEVERITIES,
)


def _by_id(findings):
    return {f.check_id: f for f in findings}


def benign_profile():
    """A clean, well-configured server: every check should grade OK."""
    return TargetProfile(
        url="https://good.example.com/mcp",
        reachable=True,
        transport="https",
        protocol_version="2026-07-28",
        server_info={"name": "good"},
        auth=AuthInfo(required=True, scheme="Bearer", token_exchange_hint=False,
                      oauth_metadata={"issuer": "https://idp.example", "grant_types_supported": []},
                      www_authenticate='Bearer realm="mcp"'),
        capabilities={"resources": {}, "tools": {}},
        session=SessionInfo(issues_session_id=True, echoes_inbound_session_id=False,
                            accepts_forged_session_id=False),
        cache=CacheInfo(advertises_cachescope=True, forces_private=True, ttl_ms=1000),
        headers={"content-type": "application/json", "mcp-session-id": "abc"},
    )


class ContractTest(unittest.TestCase):
    def test_run_checks_emits_valid_findings(self):
        findings = run_checks(benign_profile())
        self.assertEqual(len(findings), len(CHECKS))
        ids = [f.check_id for f in findings]
        self.assertEqual(len(ids), len(set(ids)), "check_ids must be unique")
        for f in findings:
            self.assertIsInstance(f, ScanFinding)
            self.assertIn(f.grade, GRADES)
            self.assertIn(f.severity_hint, SEVERITIES)
            self.assertTrue(f.rationale)
            self.assertTrue(f.recommendation)
            self.assertIsInstance(f.evidence, dict)

    def test_benign_server_never_lights_up(self):
        findings = run_checks(benign_profile())
        for f in findings:
            self.assertIn(f.grade, ("OK", "OBSERVATION", "INCONCLUSIVE"))
            self.assertNotEqual(f.grade, "RISK", f"{f.check_id} must not RISK on a clean server")

    def test_benign_server_is_all_ok(self):
        # The benign fixture is deliberately fully specified: every check -> OK.
        by = _by_id(run_checks(benign_profile()))
        for cid in ("auth-not-required", "session-id-as-bearer", "cachescope-mislabel-signal",
                    "token-exchange-present", "header-leakage", "transport-tls-hygiene"):
            self.assertEqual(by[cid].grade, "OK", f"{cid} should be OK on the clean server")

    def test_a_broken_check_is_isolated_as_inconclusive(self):
        # Passing a non-profile object makes checks raise internally; run_checks
        # must still return one finding per check, each graded INCONCLUSIVE.
        class Weird:
            pass
        findings = run_checks(Weird())
        self.assertEqual(len(findings), len(CHECKS))
        self.assertTrue(all(f.grade == "INCONCLUSIVE" for f in findings))


class AuthNotRequiredTest(unittest.TestCase):
    def test_risky_no_auth(self):
        p = benign_profile()
        p.auth = AuthInfo(required=False)
        f = _by_id(run_checks(p))["auth-not-required"]
        self.assertEqual(f.grade, "RISK")
        self.assertEqual(f.severity_hint, "high")

    def test_benign_auth_required(self):
        f = _by_id(run_checks(benign_profile()))["auth-not-required"]
        self.assertEqual(f.grade, "OK")

    def test_inconclusive_when_unknown(self):
        p = benign_profile()
        p.auth = AuthInfo(required=None)
        f = _by_id(run_checks(p))["auth-not-required"]
        self.assertEqual(f.grade, "INCONCLUSIVE")

    def test_unreachable_is_inconclusive(self):
        p = benign_profile()
        p.reachable = False
        p.auth = AuthInfo(required=None)
        f = _by_id(run_checks(p))["auth-not-required"]
        self.assertEqual(f.grade, "INCONCLUSIVE")

    def test_live_fallback_resolves_unknown(self):
        p = benign_profile()
        p.auth = AuthInfo(required=None)

        def live(method, *, authenticated=False):
            # unauthenticated initialize succeeds -> auth not required
            return {"ok": True}

        f = _by_id(run_checks(p, live=live))["auth-not-required"]
        self.assertEqual(f.grade, "RISK")
        self.assertEqual(f.evidence.get("source"), "live_probe")

    def test_broken_live_does_not_crash(self):
        p = benign_profile()
        p.auth = AuthInfo(required=None)

        def live(*a, **k):
            raise RuntimeError("adapter live contract mismatch")

        f = _by_id(run_checks(p, live=live))["auth-not-required"]
        self.assertEqual(f.grade, "INCONCLUSIVE")


class SessionIdAsBearerTest(unittest.TestCase):
    def test_risky_forged_accepted(self):
        p = benign_profile()
        p.session = SessionInfo(issues_session_id=True, echoes_inbound_session_id=True,
                                accepts_forged_session_id=True)
        f = _by_id(run_checks(p))["session-id-as-bearer"]
        self.assertEqual(f.grade, "RISK")
        self.assertIn("lab deep-check", f.recommendation)

    def test_observation_echoes_but_not_probed(self):
        p = benign_profile()
        p.session = SessionInfo(issues_session_id=True, echoes_inbound_session_id=True,
                                accepts_forged_session_id=None)
        f = _by_id(run_checks(p))["session-id-as-bearer"]
        self.assertEqual(f.grade, "OBSERVATION")

    def test_benign_bound_session(self):
        f = _by_id(run_checks(benign_profile()))["session-id-as-bearer"]
        self.assertEqual(f.grade, "OK")

    def test_inconclusive_no_data(self):
        p = benign_profile()
        p.session = SessionInfo()
        f = _by_id(run_checks(p))["session-id-as-bearer"]
        self.assertEqual(f.grade, "INCONCLUSIVE")


class CacheScopeTest(unittest.TestCase):
    def test_observation_no_cachescope(self):
        p = benign_profile()
        p.cache = CacheInfo(advertises_cachescope=False)
        f = _by_id(run_checks(p))["cachescope-mislabel-signal"]
        self.assertEqual(f.grade, "OBSERVATION")
        self.assertIn("lab cachescope probe", f.recommendation)

    def test_observation_public_labeled(self):
        p = benign_profile()
        p.cache = CacheInfo(advertises_cachescope=True, forces_private=False, ttl_ms=5000)
        f = _by_id(run_checks(p))["cachescope-mislabel-signal"]
        self.assertEqual(f.grade, "OBSERVATION")

    def test_benign_private_labeled(self):
        f = _by_id(run_checks(benign_profile()))["cachescope-mislabel-signal"]
        self.assertEqual(f.grade, "OK")

    def test_inconclusive_no_resources_no_cache(self):
        p = benign_profile()
        p.capabilities = {"tools": {}}
        p.cache = CacheInfo()
        f = _by_id(run_checks(p))["cachescope-mislabel-signal"]
        self.assertEqual(f.grade, "INCONCLUSIVE")


class TokenExchangeTest(unittest.TestCase):
    def test_observation_hint(self):
        p = benign_profile()
        p.auth = AuthInfo(required=True, token_exchange_hint=True,
                          oauth_metadata={"issuer": "https://idp.example"})
        f = _by_id(run_checks(p))["token-exchange-present"]
        self.assertEqual(f.grade, "OBSERVATION")
        self.assertIn("lab", f.recommendation)

    def test_observation_grant_type_in_metadata(self):
        p = benign_profile()
        p.auth = AuthInfo(required=True, oauth_metadata={
            "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"]})
        f = _by_id(run_checks(p))["token-exchange-present"]
        self.assertEqual(f.grade, "OBSERVATION")

    def test_benign_no_exchange(self):
        f = _by_id(run_checks(benign_profile()))["token-exchange-present"]
        self.assertEqual(f.grade, "OK")

    def test_inconclusive_no_metadata(self):
        p = benign_profile()
        p.auth = AuthInfo(required=True, token_exchange_hint=None, oauth_metadata=None)
        f = _by_id(run_checks(p))["token-exchange-present"]
        self.assertEqual(f.grade, "INCONCLUSIVE")


class HeaderLeakageTest(unittest.TestCase):
    def test_risky_authorization_in_response(self):
        p = benign_profile()
        p.headers = {"content-type": "application/json",
                     "Authorization": "Bearer sk-secret-value-123"}
        f = _by_id(run_checks(p))["header-leakage"]
        self.assertEqual(f.grade, "RISK")
        self.assertIn("authorization", f.evidence["leaked_headers"])
        # the secret must appear only as a fingerprint, never raw
        fps = f.evidence["fingerprints"]["authorization"]
        self.assertTrue(fps.startswith("sha256:"))
        self.assertNotIn("sk-secret-value-123", str(f.evidence))

    def test_risky_oidc_passthrough(self):
        p = benign_profile()
        p.headers = {"x-amzn-oidc-accesstoken": "eyJ..."}
        f = _by_id(run_checks(p))["header-leakage"]
        self.assertEqual(f.grade, "RISK")

    def test_observation_reflected_marker(self):
        p = benign_profile()
        p.headers = {"content-type": "application/json", "_reflected_inbound": ["x-probe-marker"]}
        f = _by_id(run_checks(p))["header-leakage"]
        self.assertEqual(f.grade, "OBSERVATION")

    def test_benign_clean_headers(self):
        f = _by_id(run_checks(benign_profile()))["header-leakage"]
        self.assertEqual(f.grade, "OK")

    def test_inconclusive_no_headers(self):
        p = benign_profile()
        p.headers = {}
        f = _by_id(run_checks(p))["header-leakage"]
        self.assertEqual(f.grade, "INCONCLUSIVE")


class TransportTLSTest(unittest.TestCase):
    def test_risky_cleartext_remote(self):
        p = benign_profile()
        p.url = "http://remote.example.com/mcp"
        p.transport = "http"
        f = _by_id(run_checks(p))["transport-tls-hygiene"]
        self.assertEqual(f.grade, "RISK")

    def test_benign_tls(self):
        f = _by_id(run_checks(benign_profile()))["transport-tls-hygiene"]
        self.assertEqual(f.grade, "OK")

    def test_cleartext_loopback_is_ok(self):
        p = benign_profile()
        p.url = "http://127.0.0.1:8000/mcp"
        p.transport = "http"
        f = _by_id(run_checks(p))["transport-tls-hygiene"]
        self.assertEqual(f.grade, "OK")
        self.assertTrue(f.evidence["loopback"])

    def test_localhost_hostname_is_loopback(self):
        p = benign_profile()
        p.url = "http://localhost:3000/mcp"
        p.transport = "http"
        f = _by_id(run_checks(p))["transport-tls-hygiene"]
        self.assertEqual(f.grade, "OK")

    def test_stdio_is_ok(self):
        p = benign_profile()
        p.url = None
        p.transport = "stdio"
        f = _by_id(run_checks(p))["transport-tls-hygiene"]
        self.assertEqual(f.grade, "OK")

    def test_inconclusive_no_transport(self):
        p = benign_profile()
        p.url = ""
        p.transport = None
        f = _by_id(run_checks(p))["transport-tls-hygiene"]
        self.assertEqual(f.grade, "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
