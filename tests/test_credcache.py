"""Tests for the same-user-credentials token-exchange cache probe (XID-10).

Reproduces the CVE-2026-110195 class against in-process practice deputies: the
broken (user-only cache) deputy must FAIL, the credential-scoped and no-cache
deputies must pass, and every way the probe could return a *false* FAIL or a
*false* OK is guarded and tested.
"""

import unittest

from strangertest.guard import AuthorizationError
from strangertest.probe import ProbeError
from strangertest.delegate import UpstreamCall, token_fingerprint
from strangertest.credcache import (
    Credential,
    Verdict,
    run_same_user_credentials_probe,
    _grade_cold,
    _grade_warm,
    FAIL,
    OK,
    INCONCLUSIVE,
)
from strangertest.practice_credcache import PracticeDeputy, CredSpec, parse_token

# One user, two credentials: a broad session JWT and a restricted API token.
CREDS = {
    "insession-alice": CredSpec("alice", frozenset({"read", "write", "admin"})),
    "apitoken-alice": CredSpec("alice", frozenset({"read"})),
}
URI = lambda n: f"note://cred-cache?nonce={n}"  # noqa: E731


def run(deputy, *, cred2="apitoken-alice", expire=True, target="http://deputy.localhost/mcp",
        authorized=False, note=None):
    return run_same_user_credentials_probe(
        target=target,
        upstream_target="http://upstream.localhost/mcp",
        user="alice",
        cred1=Credential("session", "insession-alice"),
        cred2=Credential("apitoken", cred2),
        read_resource=deputy.read_resource,
        uri_for=URI,
        upstream_calls=deputy.recorded_calls,
        fresh_cache=deputy.reset_cache,
        expire_cache=deputy.expire_all if expire else None,
        exchange_attempts=deputy.exchange_count,
        authorized=authorized,
        authorization_note=note,
    )


class BrokenFixtureTests(unittest.TestCase):
    """Condition 2: the broken fixture must FAIL before any real result counts."""

    def test_user_only_cache_fails(self):
        rep = run(PracticeDeputy("user_only", CREDS))
        self.assertEqual(rep.cold_control.grade, OK, rep.cold_control.detail)
        self.assertEqual(rep.grade, FAIL, rep.warm.detail)
        self.assertTrue(rep.vulnerable)
        self.assertIn("minted for credential 1", rep.warm.detail)
        self.assertIn("same-user-credentials", rep.to_dict()["probe"])
        self.assertIn(FAIL, rep.summary())

    def test_scope_from_user_cache_fails_by_scope(self):
        # Fresh token per credential (distinct fingerprint) but a user-keyed
        # scope cache, so credential 2's own token carries credential 1's scope.
        rep = run(PracticeDeputy("scope_from_user_cache", CREDS))
        self.assertEqual(rep.cold_control.grade, OK, rep.cold_control.detail)
        self.assertEqual(rep.grade, FAIL, rep.warm.detail)
        self.assertIn("scope", rep.warm.detail)
        # The two tokens must be distinct — otherwise this would be the
        # token-reuse path, not the scope path we mean to exercise.
        self.assertNotEqual(
            rep.observations.get("warm_cred2_token"),
            rep.observations.get("warm_populate_token"),
        )


class SafeFixtureTests(unittest.TestCase):
    """Every OK needs the broken fixture above to FAIL the same check."""

    def test_user_plus_credential_is_ok_caches_per_credential(self):
        rep = run(PracticeDeputy("user_plus_credential", CREDS))
        self.assertEqual(rep.cold_control.grade, OK, rep.cold_control.detail)
        self.assertEqual(rep.grade, OK, rep.warm.detail)
        self.assertFalse(rep.vulnerable)
        self.assertNotEqual(
            rep.observations["warm_cred2_token"], rep.observations["warm_populate_token"]
        )
        # The same-credential repeat was a cache hit, so we can claim per-credential.
        self.assertTrue(rep.observations["cache_hit_observed"])
        self.assertIn("caches per credential", rep.warm.detail)

    def test_no_cache_is_ok_caching_not_observed(self):
        rep = run(PracticeDeputy("no_cache", CREDS))
        self.assertEqual(rep.grade, OK, rep.warm.detail)
        # No cache hit on the repeat, so we must NOT claim the key includes the cred.
        self.assertFalse(rep.observations["cache_hit_observed"])
        self.assertIn("caching not observed", rep.warm.detail)
        self.assertNotIn("includes the credential", rep.warm.detail)


class FalseLeakGuardTests(unittest.TestCase):
    """The probe must never report FAIL for something it did not actually see."""

    def test_static_token_is_inconclusive_not_fail(self):
        # Deputy mints ONE token for everyone (no per-subject exchange). Warm
        # credential 2 does carry credential 1's token — but that is not a cache
        # collision, and the cold control proves it, so the grade is INCONCLUSIVE.
        rep = run(PracticeDeputy("static_token", CREDS))
        self.assertEqual(rep.cold_control.grade, INCONCLUSIVE)
        self.assertIn("SAME upstream token", rep.cold_control.detail)
        self.assertEqual(rep.grade, INCONCLUSIVE)
        self.assertFalse(rep.vulnerable)

    def test_grade_cold_same_token_is_inconclusive(self):
        call = lambda: UpstreamCall(token="ut~alice~read~1", scope=["read"], method="resources/read")  # noqa: E731
        v = _grade_cold(call(), call(), {})
        self.assertEqual(v.grade, INCONCLUSIVE)

    def test_cold_failure_forces_warm_inconclusive(self):
        # Even if the warm calls look like a leak, a failed cold control blocks FAIL.
        cold = Verdict(INCONCLUSIVE, "observer blind")
        pop = UpstreamCall(token="ut~alice~admin~1", method="resources/read")
        warm = UpstreamCall(token="ut~alice~admin~1", method="resources/read")  # same fp as pop
        v = _grade_warm(cold, pop, warm, None, None, False, {})
        self.assertEqual(v.grade, INCONCLUSIVE)


class FalseOkGuardTests(unittest.TestCase):
    """The probe must never report OK for something it could not observe."""

    def test_unobserved_cred2_call_is_inconclusive_not_ok(self):
        # The deputy serves credential 2 from a shared local content cache without
        # forwarding, so the owned upstream never sees credential 2's call.
        rep = run(PracticeDeputy("content_cache_user", CREDS))
        self.assertEqual(rep.cold_control.grade, OK, rep.cold_control.detail)
        self.assertEqual(rep.grade, INCONCLUSIVE)
        self.assertIn("credential 2", rep.warm.detail)
        self.assertNotEqual(rep.grade, OK)

    def test_grade_warm_missing_populate_is_inconclusive(self):
        cold = Verdict(OK, "distinct")
        warm = UpstreamCall(token="ut~alice~read~9", scope=["read"], method="resources/read")
        v = _grade_warm(cold, None, warm, None, None, False, {})
        self.assertEqual(v.grade, INCONCLUSIVE)
        self.assertIn("populate", v.detail)

    def test_grade_warm_missing_cred2_is_inconclusive(self):
        cold = Verdict(OK, "distinct")
        pop = UpstreamCall(token="ut~alice~admin~1", method="resources/read")
        v = _grade_warm(cold, pop, None, None, None, False, {})
        self.assertEqual(v.grade, INCONCLUSIVE)
        self.assertNotEqual(v.grade, OK)


class ObservationAndHygieneTests(unittest.TestCase):
    def test_expired_cache_observation_recorded(self):
        rep = run(PracticeDeputy("user_only", CREDS), expire=True)
        self.assertIn("after_expiry_cred2_token", rep.observations)
        self.assertTrue(rep.observations["after_expiry_distinct_from_cred1"])

    def test_tokens_only_ever_fingerprinted(self):
        import json

        rep = run(PracticeDeputy("user_only", CREDS))
        dumped = json.dumps(rep.to_dict())
        self.assertNotIn("ut~", dumped)  # no raw exchanged token anywhere
        self.assertIn("sha256:", dumped)  # only fingerprints

    def test_unknown_credential_raises_probeerror(self):
        with self.assertRaises(ProbeError):
            run(PracticeDeputy("user_only", CREDS), cred2="apitoken-bob-UNKNOWN")


class GuardTests(unittest.TestCase):
    def test_remote_target_refused_without_authorization(self):
        with self.assertRaises(AuthorizationError):
            run(PracticeDeputy("user_only", CREDS), target="https://gw.example/mcp")

    def test_remote_target_runs_when_authorized(self):
        rep = run(
            PracticeDeputy("user_only", CREDS),
            target="https://gw.example/mcp",
            authorized=True,
            note="me@example, staging",
        )
        self.assertEqual(rep.grade, FAIL)


class PracticeDeputyUnitTests(unittest.TestCase):
    def test_parse_token_roundtrip(self):
        from strangertest.practice_credcache import mint

        tok = mint("alice", frozenset({"read", "write"}), 7)
        user, scope, parsed = parse_token(tok)
        self.assertTrue(parsed)
        self.assertEqual(user, "alice")
        self.assertEqual(scope, frozenset({"read", "write"}))

    def test_parse_token_rejects_non_token(self):
        user, scope, parsed = parse_token("eyJ.payload.sig")
        self.assertFalse(parsed)


if __name__ == "__main__":
    unittest.main()
