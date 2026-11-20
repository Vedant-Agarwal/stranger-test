"""The GitHub Action's runner script (ci/action_run.sh), driven the way
action.yml drives it: inputs as environment variables. Targets are the bundled
practice servers on loopback (4600-4699), started and stopped in-process."""

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager

from strangertest import deep_tests as dt
from strangertest.practice_http import build_server as build_plain
from strangertest.practice_statehandle_http import build_server as build_statehandle

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "ci", "action_run.sh")
BASH = shutil.which("bash")


@contextmanager
def _serving(make):
    server = make(dt._free_port())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    finally:
        server.shutdown()
        server.server_close()


def _run(**env):
    full = dict(os.environ)
    for key in list(full):
        if key.startswith("ST_") or key == "GITHUB_OUTPUT":
            del full[key]
    full["ST_CMD"] = f"{sys.executable} -m strangertest"
    full["PYTHONPATH"] = ROOT
    full.update(env)
    proc = subprocess.run([BASH, SCRIPT], env=full, cwd=ROOT,
                          capture_output=True, text=True, timeout=120)
    return proc.returncode, proc.stdout + proc.stderr


@unittest.skipUnless(BASH, "bash not available")
class ActionRunInputs(unittest.TestCase):
    def test_missing_url_is_bad_input(self):
        code, out = _run()
        self.assertEqual(code, 3)
        self.assertIn("'url' is required", out)

    def test_confirm_without_test_is_bad_input(self):
        code, out = _run(ST_MODE="confirm", ST_URL="http://127.0.0.1:4601/mcp")
        self.assertEqual(code, 3)
        self.assertIn("needs 'test'", out)

    def test_bad_fail_on_is_bad_input(self):
        code, _ = _run(ST_URL="http://127.0.0.1:4601/mcp", ST_FAIL_ON="sometimes")
        self.assertEqual(code, 3)

    def test_nonloopback_is_refused_by_default(self):
        code, out = _run(ST_MODE="confirm", ST_TEST="state-handle",
                         ST_URL="https://mcp.example.com/mcp")
        self.assertEqual(code, 3)
        self.assertIn("refused", out)


@unittest.skipUnless(BASH, "bash not available")
class ActionRunConfirm(unittest.TestCase):
    def _confirm(self, mode, **env):
        with _serving(lambda p: build_statehandle(mode, port=p)) as url:
            return _run(ST_MODE="confirm", ST_TEST="state-handle", ST_URL=url,
                        ST_TOKEN_A="alice", ST_TOKEN_B="bob", **env)

    def test_leaky_server_fails_the_gate(self):
        code, out = self._confirm("leaky")
        self.assertEqual(code, 1, out)
        self.assertIn("LEAK", out)

    def test_safe_server_passes(self):
        code, out = self._confirm("safe")
        self.assertEqual(code, 0, out)

    def test_never_reports_but_does_not_fail(self):
        code, out = self._confirm("leaky", ST_FAIL_ON="never")
        self.assertEqual(code, 0, out)
        self.assertIn("exit code: 1", out)

    def test_collapsed_identities_fail_only_on_inconclusive(self):
        code, out = self._confirm("collapse")
        self.assertEqual(code, 0, out)
        self.assertIn("OBSERVATION", out)
        self.assertIn("::warning::", out)
        code, out = self._confirm("collapse", ST_FAIL_ON="inconclusive")
        self.assertEqual(code, 1, out)

    def test_exit_code_is_written_to_github_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out")
            code, out = self._confirm("leaky", GITHUB_OUTPUT=path)
            self.assertEqual(code, 1, out)
            with open(path) as fh:
                self.assertIn("exit-code=1", fh.read())


@unittest.skipUnless(BASH, "bash not available")
class ActionRunScan(unittest.TestCase):
    def test_scan_writes_sarif_and_tokens_stay_out_of_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            sarif = os.path.join(tmp, "st.sarif")
            with _serving(lambda p: build_plain("safe", port=p)) as url:
                code, out = _run(ST_URL=url, ST_SARIF_FILE=sarif,
                                 ST_BEARER="tok-do-not-print-123456")
            self.assertIn(code, (0, 1), out)
            with open(sarif) as fh:
                body = fh.read()
            self.assertIn('"version": "2.1.0"', body)
            self.assertNotIn("tok-do-not-print-123456", body + out)

    def test_unreachable_target_fails_the_gate(self):
        # Nothing was scanned, so the default gate must not pass.
        url = f"http://127.0.0.1:{dt._free_port()}/mcp"
        code, out = _run(ST_URL=url)
        self.assertEqual(code, 1, out)
        self.assertIn("exit code: 2", out)
        self.assertIn("nothing was scanned", out)
        code, out = _run(ST_URL=url, ST_FAIL_ON="never")
        self.assertEqual(code, 0, out)


@unittest.skipUnless(BASH, "bash not available")
class ActionRunAgentMemory(unittest.TestCase):
    """The agent-memory test through the action's runner, against the bundled
    stand-in agent server. Its URL is the server's base URL, not an MCP path."""

    AGENT = dict(ST_ASSISTANT="memory",
                 ST_SAVE_INPUT='{"action": "save", "key": "st-probe", "value": "{marker}"}',
                 ST_RECALL_INPUT='{"action": "recall", "key": "st-probe"}',
                 ST_WHOAMI_FIELD="whoami")

    def _run(self, mode, **env):
        from strangertest.practice_agent_memory_http import build_server
        with _serving(lambda p: build_server(mode, port=p)) as mcp_url:
            base = mcp_url[: -len("/mcp")]
            options = dict(ST_MODE="confirm", ST_TEST="agent-memory", ST_URL=base,
                           ST_TOKEN_A="tok-alice", ST_TOKEN_B="tok-bob")
            options.update(env)
            return _run(**options)

    def test_leaky_agent_server_fails_the_gate_with_two_tokens_only(self):
        code, out = self._run("leaky")
        self.assertEqual(code, 1, out)
        self.assertIn("LEAK", out)

    def test_safe_agent_server_passes_with_every_option(self):
        code, out = self._run("safe", ST_NAMESPACE_A="alice.notes", **self.AGENT)
        self.assertEqual(code, 0, out)
        self.assertIn("agent_recall", out)
        self.assertNotIn("NOT_RUN        agent_recall", out)

    def test_namespace_b_reaches_the_tool(self):
        code, out = self._run("prefixbug", ST_TOKEN_B="tok-ali",
                              ST_NAMESPACE_A="alice.notes", ST_NAMESPACE_B="ali")
        self.assertEqual(code, 1, out)
        self.assertIn("LEAK           store_search_own_prefix", out)

    def test_no_authentication_is_a_warning_not_a_pass_or_fail(self):
        code, out = self._run("open")
        self.assertEqual(code, 0, out)
        self.assertIn("::warning::", out)
        code, out = self._run("open", ST_FAIL_ON="inconclusive")
        self.assertEqual(code, 1, out)

    def test_bad_json_input_is_bad_input(self):
        code, out = self._run("safe", ST_SAVE_INPUT="{not json")
        self.assertEqual(code, 3, out)


if __name__ == "__main__":
    unittest.main()
