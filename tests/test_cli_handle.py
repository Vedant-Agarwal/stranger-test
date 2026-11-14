import io
import json
import threading
import unittest
from contextlib import contextmanager, redirect_stdout, redirect_stderr

from strangertest.cli import main
from strangertest.practice_handle_http import build_server


@contextmanager
def handle_server(mode, **kwargs):
    server = build_server(mode, **kwargs)
    t = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    t.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    finally:
        server.shutdown()
        server.server_close()


class CliHandleTests(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_leaky_server_leaks_and_exits_1(self):
        with handle_server("leaky") as url:
            code, out, _ = self._run(
                ["handle", url, "--token-a", "alice", "--token-b", "bob"]
            )
        self.assertEqual(code, 1)
        self.assertIn("LEAK", out)

    def test_safe_server_is_clean_and_exits_0(self):
        with handle_server("safe") as url:
            code, out, _ = self._run(
                ["handle", url, "--token-a", "alice", "--token-b", "bob"]
            )
        self.assertEqual(code, 0)
        self.assertIn("OK", out)

    def test_no_tasks_extension_is_inconclusive_exit_2(self):
        with handle_server("safe", no_tasks=True) as url:
            code, out, _ = self._run(
                ["handle", url, "--token-a", "alice", "--token-b", "bob"]
            )
        self.assertEqual(code, 2)
        self.assertIn("INCONCLUSIVE", out)

    def test_public_target_refused_without_authorization_exit_3(self):
        code, _, err = self._run(
            ["handle", "https://mcp.example.com/mcp", "--token-a", "alice",
             "--token-b", "bob"]
        )
        self.assertEqual(code, 3)
        self.assertIn("refused", err)
        # the command line points at the flag, not the Python kwarg
        self.assertIn("--authorized", err)
        self.assertIn("re-run", err)

    def test_json_holds_grade(self):
        with handle_server("leaky") as url:
            code, out, _ = self._run(
                ["handle", url, "--token-a", "alice", "--token-b", "bob", "--json"]
            )
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["grade"], "LEAK")

    def test_help_lists_handle(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit) as cm, redirect_stdout(out):
            main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("handle", out.getvalue())


if __name__ == "__main__":
    unittest.main()
