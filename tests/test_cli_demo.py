import io
import json
import unittest
from contextlib import redirect_stdout, redirect_stderr

from strangertest.cli import main


class CliDemoTests(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def _assert_contrast(self, out):
        # The demonstration shows a leak in leaky mode and none in safe mode.
        self.assertIn("LEAK", out)
        self.assertIn("OK", out)

    def test_demo_default_probe_is_cache(self):
        code, out, _ = self._run(["demo"])
        self.assertEqual(code, 0)
        self._assert_contrast(out)

    def test_demo_cache(self):
        code, out, _ = self._run(["demo", "--probe", "cache"])
        self.assertEqual(code, 0)
        self._assert_contrast(out)

    def test_demo_handle(self):
        code, out, _ = self._run(["demo", "--probe", "handle"])
        self.assertEqual(code, 0)
        self._assert_contrast(out)

    def test_demo_cachescope(self):
        code, out, _ = self._run(["demo", "--probe", "cachescope"])
        self.assertEqual(code, 0)
        self._assert_contrast(out)

    def test_demo_json_holds_both_modes_and_grade(self):
        code, out, _ = self._run(["demo", "--probe", "handle", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["leaky"]["grade"], "LEAK")
        self.assertEqual(data["safe"]["grade"], "OK")

    def test_unknown_probe_is_usage_error_exit_3(self):
        # A bad --probe is an argparse usage error: it raises SystemExit(3)
        # (the process still exits 3 via `raise SystemExit(main())`).
        err = io.StringIO()
        with self.assertRaises(SystemExit) as cm, redirect_stderr(err):
            main(["demo", "--probe", "nope"])
        self.assertEqual(cm.exception.code, 3)

    def test_help_lists_demo(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit) as cm, redirect_stdout(out):
            main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("demo", out.getvalue())


if __name__ == "__main__":
    unittest.main()
