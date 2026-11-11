import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from strangertest.cli import main
from strangertest.source_audit import (
    CONFIDENCE,
    audit_file,
    audit_source,
    survey,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _by_tool(handlers):
    return {h.tool: h for h in handlers}


class LeakyFixtureTests(unittest.TestCase):
    def setUp(self):
        self.handlers = _by_tool(audit_file(os.path.join(FIXTURES, "leaky_server.py")))

    def test_finds_every_decorated_handler(self):
        self.assertEqual(
            set(self.handlers),
            {"save_note", "read_note", "search_notes", "read_archive", "add", "help_topic"},
        )

    def test_shared_global_handlers_are_flagged(self):
        self.assertTrue(self.handlers["save_note"].flagged)
        self.assertTrue(self.handlers["save_note"].writes)
        self.assertTrue(self.handlers["read_note"].flagged)
        self.assertFalse(self.handlers["read_note"].writes)

    def test_storage_call_is_flagged_and_decorator_name_is_used(self):
        h = self.handlers["search_notes"]
        self.assertTrue(h.flagged)
        self.assertTrue(any("execute" in s for s in h.state_signals))

    def test_state_reached_through_same_file_helper_is_flagged(self):
        self.assertTrue(self.handlers["read_archive"].flagged)

    def test_pure_handler_is_not_flagged(self):
        self.assertFalse(self.handlers["add"].touches_state)
        self.assertFalse(self.handlers["add"].flagged)

    def test_constant_table_is_not_shared_state(self):
        self.assertFalse(self.handlers["help_topic"].flagged)


class SafeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.handlers = _by_tool(audit_file(os.path.join(FIXTURES, "safe_server.py")))

    def test_handlers_touch_state_but_none_is_flagged(self):
        self.assertEqual(len(self.handlers), 3)
        for h in self.handlers.values():
            self.assertTrue(h.touches_state, h.tool)
            self.assertFalse(h.flagged, h.tool)

    def test_identity_found_through_helper(self):
        self.assertTrue(self.handlers["read_note"].identity_refs)

    def test_identity_found_in_sql_string(self):
        self.assertIn("owner_id", self.handlers["search_notes"].identity_refs)


class DispatcherTests(unittest.TestCase):
    def setUp(self):
        self.handlers = _by_tool(audit_file(os.path.join(FIXTURES, "lowlevel_server.py")))

    def test_dispatcher_is_split_into_branches(self):
        self.assertEqual(
            set(self.handlers), {"put_item_shared", "get_rows", "get_my_rows", "ping"}
        )
        self.assertTrue(all(h.kind == "dispatch-branch" for h in self.handlers.values()))

    def test_branches_are_judged_separately(self):
        self.assertTrue(self.handlers["put_item_shared"].flagged)
        self.assertTrue(self.handlers["get_rows"].flagged)
        self.assertFalse(self.handlers["get_my_rows"].flagged)
        self.assertFalse(self.handlers["ping"].touches_state)

    def test_db_session_receiver_is_not_caller_identity(self):
        # ``self.db.session.execute`` must not clear the handler.
        self.assertEqual(self.handlers["get_rows"].identity_refs, [])


class AuditSourceTests(unittest.TestCase):
    def test_non_mcp_file_yields_nothing(self):
        src = "def tool(f):\n    return f\n\n@tool\ndef x():\n    open('a')\n"
        self.assertEqual(audit_source(src), [])

    def test_shared_dispatcher_preamble_clears_every_branch(self):
        src = (
            "# mcp\n"
            "@server.call_tool()\n"
            "async def call_tool(name, arguments):\n"
            "    require_auth(arguments['token'])\n"
            "    if name == 'a':\n"
            "        return db.get('a')\n"
            "    if name == 'b':\n"
            "        return db.get('b')\n"
        )
        handlers = audit_source(src)
        self.assertEqual(len(handlers), 2)
        self.assertTrue(all(h.touches_state and not h.flagged for h in handlers))

    def test_add_tool_registration(self):
        src = (
            "# mcp\n"
            "STORE = []\n"
            "def remember(text):\n"
            "    STORE.append(text)\n"
            "mcp.add_tool(remember)\n"
        )
        handlers = audit_source(src)
        self.assertEqual([h.tool for h in handlers], ["remember"])
        self.assertTrue(handlers[0].flagged)

    def test_tool_called_as_function_with_alias(self):
        src = (
            "# mcp\n"
            "class S(FastMCP):\n"
            "    def setup(self):\n"
            "        async def find(query):\n"
            "            return await self.qdrant_connector.search(query)\n"
            "        find_tool = find\n"
            "        self.tool(find_tool, name='find')\n"
        )
        handlers = audit_source(src)
        self.assertEqual(len(handlers), 1)
        self.assertTrue(handlers[0].flagged)

    def test_execute_prefixed_method_is_a_storage_call(self):
        src = (
            "# mcp\n"
            "@mcp.tool()\n"
            "async def tables():\n"
            "    return await driver_for().execute_query('SELECT 1')\n"
        )
        self.assertTrue(audit_source(src)[0].flagged)

    def test_mcp_transport_session_is_not_identity(self):
        src = (
            "# mcp\n"
            "LOG = []\n"
            "@mcp.tool()\n"
            "async def note(text, ctx):\n"
            "    await ctx.session.send_log_message('info', text)\n"
            "    LOG.append(text)\n"
        )
        self.assertTrue(audit_source(src)[0].flagged)

    def test_syntax_error_is_raised(self):
        with self.assertRaises(SyntaxError):
            audit_source("# mcp\ndef broken(:\n")


class SurveyTests(unittest.TestCase):
    def test_survey_counts_fixture_directory(self):
        report = survey(FIXTURES)
        counts = report.counts()
        self.assertEqual(counts["files_scanned"], 3)
        self.assertEqual(counts["handlers"], 13)
        self.assertEqual(counts["flagged"], 6)
        self.assertEqual(counts["parse_errors"], 0)
        self.assertFalse(report.network_hints)

    def test_survey_records_parse_errors_and_network_hints(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "bad.py"), "w") as f:
                f.write("# mcp\ndef broken(:\n")
            with open(os.path.join(tmp, "web.py"), "w") as f:
                f.write("# mcp\nmcp.run(transport='streamable-http')\n")
            os.mkdir(os.path.join(tmp, "tests"))
            with open(os.path.join(tmp, "tests", "t.py"), "w") as f:
                f.write("# mcp\n")
            report = survey(tmp)
            self.assertEqual(report.files_scanned, 2)
            self.assertEqual(len(report.parse_errors), 1)
            self.assertEqual(report.network_hints, ["web.py"])
            self.assertEqual(survey(tmp, include_tests=True).files_scanned, 3)

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            survey(os.path.join(FIXTURES, "nope"))


class CliSurveyTests(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_text_summary(self):
        code, out, _ = self._run(["survey", FIXTURES])
        self.assertEqual(code, 0)
        self.assertIn("CANDIDATE [low]", out)
        self.assertIn("'save_note'", out)
        self.assertIn("not confirmed leaks", out)

    def test_json_report(self):
        code, out, _ = self._run(["survey", FIXTURES, "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["confidence"], CONFIDENCE)
        self.assertEqual(data["counts"]["flagged"], 6)
        self.assertEqual(len(data["findings"]), 6)
        self.assertNotIn("handlers", data)

    def test_json_all_includes_cleared_handlers(self):
        _, out, _ = self._run(["survey", FIXTURES, "--json", "--all"])
        self.assertEqual(len(json.loads(out)["handlers"]), 13)

    def test_single_file_path(self):
        code, out, _ = self._run(["survey", os.path.join(FIXTURES, "safe_server.py")])
        self.assertEqual(code, 0)
        self.assertNotIn("CANDIDATE", out)

    def test_missing_path_exits_2(self):
        code, _, err = self._run(["survey", os.path.join(FIXTURES, "nope")])
        self.assertEqual(code, 2)
        self.assertIn("no such path", err)


if __name__ == "__main__":
    unittest.main()
