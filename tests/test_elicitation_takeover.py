import json
import socket
import threading
import unittest
from contextlib import contextmanager

from strangertest.elicitation_takeover import (
    INCONCLUSIVE,
    LEAK,
    OK,
    forbidden_secret_field,
    run_elicitation_takeover_probe,
)
from strangertest.mcp_client import MCPClient
from strangertest.practice_elicitation_http import build_server, make_test_jwt
from strangertest.probe import Identity
from strangertest.transports import HTTPTransport

# Loopback, 4600-4649 (4650-4699 is used by test_login_faults; never 4000/4444/8790).
_PORT_LO, _PORT_HI = 4600, 4649

# Obvious fake test subjects (not real credentials).
SUB_A = "user-alice-A"
SUB_B = "user-bob-B"


def _free_port():
    for port in range(_PORT_LO, _PORT_HI + 1):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            s.close()
            continue
        s.close()
        return port
    raise unittest.SkipTest("no free port in 4600-4649")


@contextmanager
def running_server(mode):
    server = build_server(mode, port=_free_port())
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    finally:
        server.shutdown()
        server.server_close()


def _identity(url, sub, label):
    token = make_test_jwt(sub)
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {token}"}, modern=True)
        ),
    )


def _probe(url, a_sub=SUB_A, b_sub=SUB_B):
    return run_elicitation_takeover_probe(
        url, _identity(url, a_sub, "A"), _identity(url, b_sub, "B")
    )


class LeakAndSafeTests(unittest.TestCase):
    def test_broken_fixture_leaks_before_safe_is_trusted(self):
        # The leaky fixture MUST fail (LEAK) in the same run, before any OK is
        # trusted: that is what makes the safe OK meaningful.
        with running_server("leaky") as url:
            leaky = _probe(url)
        self.assertEqual(leaky.grade, LEAK, leaky.detail)
        self.assertEqual(leaky.checks["binding"].grade, LEAK)
        self.assertIn("binding", leaky.leaked_checks)
        self.assertIn("takeover", leaky.summary())
        self.assertEqual(
            leaky.to_dict()["failure_class"],
            "cross-user elicitation binding / account-takeover leak",
        )

        with running_server("safe") as url:
            safe = _probe(url)
        self.assertEqual(safe.grade, OK, safe.detail)
        self.assertEqual(safe.checks["binding"].grade, OK)
        self.assertEqual(safe.checks["form_secret"].grade, OK)
        self.assertIn("OK", safe.summary())

    def test_leaky_binds_attack_grant_to_starter_A(self):
        with running_server("leaky") as url:
            report = _probe(url)
        # The attack grant bound to A's fingerprint, not B's.
        self.assertEqual(
            report.fingerprints["attack_bound"], report.fingerprints["identity_a"]
        )
        self.assertNotEqual(
            report.fingerprints["attack_bound"], report.fingerprints["identity_b"]
        )

    def test_form_secret_leak_in_same_run_as_safe_ok(self):
        # A second broken fixture: a form-mode elicitation requesting a password.
        with running_server("leaky_form_secret") as url:
            bad = _probe(url)
        self.assertEqual(bad.grade, LEAK, bad.detail)
        self.assertEqual(bad.checks["form_secret"].grade, LEAK)
        self.assertEqual(
            bad.to_dict()["failure_class"],
            "forbidden-secret request in form-mode elicitation",
        )
        # Binding itself is correct in this mode (bound to the completer).
        self.assertEqual(bad.checks["binding"].grade, OK)

        with running_server("safe") as url:
            good = _probe(url)
        self.assertEqual(good.grade, OK, good.detail)


class ControlTests(unittest.TestCase):
    def test_indistinguishable_identities_are_inconclusive(self):
        # If A and B present the same subject, no binding can be attributed.
        with running_server("safe") as url:
            report = _probe(url, a_sub=SUB_A, b_sub=SUB_A)
        self.assertEqual(report.grade, INCONCLUSIVE)
        self.assertIn("indistinguishable", report.detail)

    def test_no_elicitation_is_inconclusive(self):
        with running_server("no_elicit") as url:
            report = _probe(url)
        self.assertEqual(report.grade, INCONCLUSIVE)
        self.assertIn("does not elicit", report.detail)

    def test_fingerprints_only_no_raw_subject_or_token(self):
        with running_server("leaky") as url:
            report = _probe(url)
        blob = json.dumps(report.to_dict())
        # No raw subject and no raw fake-JWT material ever appears in output.
        self.assertNotIn(SUB_A, blob)
        self.assertNotIn(SUB_B, blob)
        self.assertNotIn(make_test_jwt(SUB_A), blob)
        for value in report.fingerprints.values():
            if value is not None:
                self.assertTrue(value.startswith("sha256:"), value)


class ForbiddenSecretUnitTests(unittest.TestCase):
    def test_form_password_is_forbidden(self):
        desc = {
            "mode": "form",
            "requestedSchema": {"properties": {"account_password": {"format": "password"}}},
        }
        self.assertEqual(forbidden_secret_field(desc), "account_password")

    def test_form_api_key_name_is_forbidden(self):
        desc = {
            "mode": "form",
            "requestedSchema": {"properties": {"my_api_key": {"type": "string"}}},
        }
        self.assertEqual(forbidden_secret_field(desc), "my_api_key")

    def test_url_mode_never_forbidden(self):
        self.assertIsNone(forbidden_secret_field({"mode": "url", "url": "http://x.test"}))

    def test_form_without_secret_is_ok(self):
        desc = {
            "mode": "form",
            "requestedSchema": {"properties": {"display_name": {"type": "string"}}},
        }
        self.assertIsNone(forbidden_secret_field(desc))


if __name__ == "__main__":
    unittest.main()
