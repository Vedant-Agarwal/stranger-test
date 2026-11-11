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
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
