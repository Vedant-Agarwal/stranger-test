import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

from strangertest.cli import main
from strangertest.mcp_client import MCPClient
from strangertest.transports import StdioTransport


class StdioTransportTests(unittest.TestCase):
    """Exercises the real subprocess transport against the practice server."""

    def test_initialize_and_list_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "s.json")
            command = [sys.executable, "-m", "strangertest.practice_server"]
            client = MCPClient(
                StdioTransport(
                    command,
                    env={
                        "STRANGERTEST_MODE": "safe",
                        "STRANGERTEST_IDENTITY": "x",
                        "STRANGERTEST_STORE": store,
                    },
                )
            )
            try:
                info = client.initialize()
                self.assertEqual(info["serverInfo"]["name"], "practice")
                names = [t["name"] for t in client.list_tools()]
                self.assertIn("kv_set", names)
                self.assertIn("kv_get", names)
            finally:
                client.close()


class CliPracticeTests(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_leaky_mode_finds_leak_and_exits_1(self):
        code, out = self._run(["practice"])
        self.assertEqual(code, 1)
        self.assertIn("LEAK", out)

    def test_safe_mode_is_clean_and_exits_0(self):
        code, out = self._run(["practice", "--safe"])
        self.assertEqual(code, 0)
        self.assertIn("OK", out)

    def test_json_report(self):
        code, out = self._run(["practice", "--json"])
        self.assertEqual(code, 1)
        self.assertIn('"leaked": true', out)
        self.assertIn("failure_class", out)

    def test_no_subcommand_prints_help(self):
        code, _ = self._run([])
        self.assertEqual(code, 3)


class CliHelpTests(unittest.TestCase):
    def _help_text(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit) as cm, redirect_stdout(out):
            main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        return out.getvalue()

    def test_epilog_describes_gate_only_checks(self):
        text = self._help_text()
        # delegation/scope/issuer need both; the cache check needs only a
        # recording upstream.
        self.assertIn(
            "delegation, scope and issuer checks need a login server", text
        )
        self.assertIn("the private-cache check needs a recording upstream", text)
        # The old wording lumped the cache check in with a login server.
        self.assertNotIn("private-cache checks each need a login server", text)


if __name__ == "__main__":
    unittest.main()
