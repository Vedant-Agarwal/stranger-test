"""`stranger-test confirm` — the Tier-2 CLI. Each deep test's --demo mode must run
its bundled leaky + safe fixtures on loopback and come back with the leaky server
caught and the safe server clean. Loopback only; the demos start/stop their own
servers in 4600-4699."""

import io
import unittest
from contextlib import redirect_stdout, redirect_stderr

from strangertest.cli import main
from strangertest import deep_tests as dt


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class ConfirmList(unittest.TestCase):
    def test_list_shows_all_five(self):
        code, out, _ = _run(["confirm", "--list"])
        self.assertEqual(code, 0)
        for tid in ("state-handle", "confused-deputy", "tasks-idor", "elicitation", "subscriptions"):
            self.assertIn(tid, out)

    def test_unknown_test_is_usage_error(self):
        code, _, err = _run(["confirm", "no-such-test", "--demo"])
        self.assertEqual(code, 3)
        self.assertIn("unknown test", err)


class ConfirmDemo(unittest.TestCase):
    """Every registered test, in --demo mode, catches its leaky fixture (exit 0)."""

    def _check(self, tid):
        code, out, _ = _run(["confirm", tid, "--demo"])
        self.assertEqual(code, 0, f"{tid}: {out}")
        self.assertIn("VERDICT: the test WORKS", out)

    def test_state_handle(self):
        self._check("state-handle")

    def test_confused_deputy(self):
        self._check("confused-deputy")

    def test_tasks_idor(self):
        self._check("tasks-idor")

    def test_elicitation(self):
        self._check("elicitation")

    def test_subscriptions(self):
        self._check("subscriptions")


class ConfirmSafety(unittest.TestCase):
    def test_nonloopback_target_refused(self):
        code, _, err = _run(["confirm", "tasks-idor", "https://example.com/mcp",
                             "--token-a", "a", "--token-b", "b"])
        self.assertEqual(code, 3)
        self.assertIn("not a loopback target", err)

    def test_lab_only_test_without_demo_explains(self):
        code, _, err = _run(["confirm", "confused-deputy", "http://127.0.0.1:4600/mcp",
                             "--token-a", "a", "--token-b", "b"])
        self.assertEqual(code, 3)
        self.assertIn("lab test", err)

    def test_registry_maps_scanner_checks(self):
        # the Tier-1 -> Tier-2 pointer the scanner report uses
        self.assertEqual(dt.confirm_hint("session-id-as-bearer").split()[2], "state-handle")
        self.assertIsNone(dt.confirm_hint("transport-tls-hygiene"))


if __name__ == "__main__":
    unittest.main()
