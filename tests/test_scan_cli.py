"""Tests for the one-command `scan` CLI, the renderers and exit codes.

These run standalone against the bundled mock profile/findings, so they pass
before the adapter and check-catalog siblings land. We force the mock via
STRANGERTEST_SCAN_MOCK so the CLI never tries a real network pass.

    .../cfvenv/bin/python -m unittest tests.test_scan_cli
"""

import io
import json
import os
import unittest
from contextlib import redirect_stdout, redirect_stderr

from strangertest.cli import main
from strangertest.scan import _mock
from strangertest.scan import report as R


class RendererTests(unittest.TestCase):
    def setUp(self):
        self.profile = _mock.mock_profile()
        self.findings = _mock.mock_findings()

    # -- human ---------------------------------------------------------------
    def test_human_has_server_summary_and_grades(self):
        text = R.human_report(self.profile, self.findings, color=False)
        self.assertIn("stranger-test scan", text)
        self.assertIn("practice-mcp", text)       # server name
        self.assertIn("2026-07-28", text)          # protocol version
        for grade in ("RISK", "OBSERVATION", "OK", "INCONCLUSIVE"):
            self.assertIn(grade, text)
        self.assertIn("VERDICT:", text)
        self.assertIn("lab deep-check", text)      # footer

    def test_human_shows_severity_hint(self):
        text = R.human_report(self.profile, self.findings, color=False)
        self.assertIn("high", text)
        self.assertIn("XID-SESSION-FORGE", text)

    def test_human_no_color_has_no_ansi(self):
        text = R.human_report(self.profile, self.findings, color=False)
        self.assertNotIn("\033[", text)

    def test_human_color_has_ansi(self):
        text = R.human_report(self.profile, self.findings, color=True)
        self.assertIn("\033[", text)

    def test_human_unreachable(self):
        text = R.human_report(_mock.unreachable_profile(), [], color=False)
        self.assertIn("UNREACHABLE", text)
        self.assertIn("unreachable", text.lower())

    # -- json ----------------------------------------------------------------
    def test_json_shape(self):
        data = json.loads(R.json_report(self.profile, self.findings))
        self.assertIn("profile", data)
        self.assertIn("findings", data)
        self.assertEqual(data["profile"]["url"], self.profile.url)
        self.assertEqual(len(data["findings"]), len(self.findings))
        f0 = data["findings"][0]
        for key in ("check_id", "title", "grade", "severity_hint",
                    "rationale", "evidence", "recommendation"):
            self.assertIn(key, f0)

    def test_json_profile_fields(self):
        data = json.loads(R.json_report(self.profile, self.findings))
        prof = data["profile"]
        for key in ("url", "reachable", "transport", "protocol_version",
                    "server_info", "auth", "capabilities", "session", "cache",
                    "headers", "errors", "fingerprints"):
            self.assertIn(key, prof)
        for key in ("required", "scheme", "oauth_metadata",
                    "token_exchange_hint", "www_authenticate"):
            self.assertIn(key, prof["auth"])

    def test_json_never_echoes_raw_bearer(self):
        # A raw token must never appear anywhere in the JSON output.
        raw = R.json_report(self.profile, self.findings)
        self.assertNotIn("supersecret-bearer-xyz", raw)

    def test_json_redacts_sensitive_headers(self):
        p = _mock.mock_profile()
        p.headers["authorization"] = "Bearer supersecret-bearer-xyz"
        data = json.loads(R.json_report(p, []))
        self.assertEqual(data["profile"]["headers"]["authorization"], "<redacted>")
        self.assertNotIn("supersecret-bearer-xyz", json.dumps(data))

    # -- sarif ---------------------------------------------------------------
    def test_sarif_shape(self):
        log = json.loads(R.sarif_report(self.profile, self.findings))
        self.assertEqual(log["version"], "2.1.0")
        self.assertIn("$schema", log)
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "stranger-test")
        self.assertEqual(len(run["results"]), len(self.findings))
        # one rule per distinct check_id
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertIn("XID-SESSION-FORGE", rule_ids)
        # levels are valid SARIF levels
        for res in run["results"]:
            self.assertIn(res["level"], ("none", "note", "warning", "error"))
            self.assertEqual(res["locations"][0]["physicalLocation"]
                             ["artifactLocation"]["uri"], self.profile.url)

    def test_sarif_risk_high_is_error(self):
        log = json.loads(R.sarif_report(self.profile, self.findings))
        by_rule = {r["ruleId"]: r for r in log["runs"][0]["results"]}
        self.assertEqual(by_rule["XID-SESSION-FORGE"]["level"], "error")   # RISK/high
        self.assertEqual(by_rule["XID-CACHE-SHARED"]["level"], "warning")  # RISK/medium

    # -- exit codes ----------------------------------------------------------
    def test_exit_code_risk(self):
        self.assertEqual(R.exit_code(self.findings), R.EXIT_RISK)

    def test_exit_code_clean(self):
        self.assertEqual(R.exit_code(_mock.clean_findings()), R.EXIT_OK)

    def test_exit_code_empty(self):
        self.assertEqual(R.exit_code([]), R.EXIT_OK)


class _CLIMixin:
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        env = os.environ.get("STRANGERTEST_SCAN_MOCK")
        os.environ["STRANGERTEST_SCAN_MOCK"] = "1"
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = main(argv)
        finally:
            if env is None:
                os.environ.pop("STRANGERTEST_SCAN_MOCK", None)
            else:
                os.environ["STRANGERTEST_SCAN_MOCK"] = env
        return code, out.getvalue(), err.getvalue()


class ScanCLITests(_CLIMixin, unittest.TestCase):
    URL = "http://127.0.0.1:4600/mcp"

    def test_human_scan_exit_risk(self):
        code, out, _ = self._run(["scan", self.URL])
        self.assertEqual(code, R.EXIT_RISK)  # mock has RISK findings
        self.assertIn("VERDICT:", out)
        self.assertIn("lab deep-check", out)

    def test_json_scan(self):
        code, out, _ = self._run(["scan", self.URL, "--json"])
        data = json.loads(out)
        self.assertIn("profile", data)
        self.assertIn("findings", data)
        self.assertEqual(code, R.EXIT_RISK)

    def test_sarif_scan(self):
        code, out, _ = self._run(["scan", self.URL, "--sarif"])
        log = json.loads(out)
        self.assertEqual(log["version"], "2.1.0")
        self.assertEqual(code, R.EXIT_RISK)

    def test_bearer_is_never_echoed(self):
        secret = "supersecret-bearer-xyz"
        code, out, err = self._run(
            ["scan", self.URL, "--bearer", secret, "--json"])
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, err)

    def test_nonloopback_refused_without_flag(self):
        code, out, err = self._run(["scan", "https://mcp.example.com/mcp"])
        self.assertEqual(code, R.EXIT_ERROR)
        self.assertIn("refused", err.lower())
        self.assertNotIn("VERDICT", out)

    def test_nonloopback_allowed_prints_reminder(self):
        code, out, err = self._run(
            ["scan", "https://mcp.example.com/mcp", "--allow-nonloopback"])
        self.assertIn("only scan servers you are authorized to test", err)
        # with the flag the mock profile is reachable -> findings -> exit 1
        self.assertEqual(code, R.EXIT_RISK)


class ScanExitCodeTests(unittest.TestCase):
    """Drive the scan flow directly against each mock profile so the full
    exit-code scheme (0 / 1 / 2) is covered without a real adapter."""

    def test_render_clean_is_zero(self):
        buf = io.StringIO()
        code = R.render(_mock.clean_profile(), _mock.clean_findings(),
                        fmt="human", stream=buf)
        self.assertEqual(code, R.EXIT_OK)

    def test_render_risk_is_one(self):
        buf = io.StringIO()
        code = R.render(_mock.mock_profile(), _mock.mock_findings(),
                        fmt="human", stream=buf)
        self.assertEqual(code, R.EXIT_RISK)


if __name__ == "__main__":
    unittest.main()
