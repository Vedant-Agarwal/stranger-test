"""The agent-memory isolation probe against the bundled stand-in server.

Every target is a local practice server on 127.0.0.1, ports 4600-4699, started
and stopped in-process. Nothing reaches the network."""

import io
import json
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout

from strangertest import deep_tests as dt
from strangertest.agent_memory import (
    INCONCLUSIVE, LEAK, OBSERVATION, OK, run_agent_memory_probe,
)
from strangertest.cli import main
from strangertest.guard import AuthorizationError
from strangertest.practice_agent_memory_http import MODES, build_server

AGENT = dict(dt._PRACTICE_AGENT)
A, B = "tok-alice", "tok-bob"


@contextmanager
def serving(mode):
    server = build_server(mode, port=dt._free_port())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def probe(mode, **overrides):
    options = dict(namespace_a=["alice", "notes"], authorized=True, **AGENT)
    options.update(overrides)
    with serving(mode) as url:
        return run_agent_memory_probe(url, A, B, **options)


def outcomes(report):
    return {p["name"]: p["outcome"] for p in report.paths}


class Grades(unittest.TestCase):
    def test_leaky_server_is_a_leak_on_every_path(self):
        report = probe("leaky")
        self.assertEqual(report.grade, LEAK, report.summary())
        self.assertTrue(report.leaked)
        got = outcomes(report)
        self.assertEqual(got.pop("store_search_own_prefix"), "NOT_RUN")  # no namespace_b given
        self.assertEqual(set(got.values()), {"LEAK"}, report.summary())
        self.assertEqual(len(report.paths), 9)

    def test_safe_server_is_ok(self):
        report = probe("safe")
        self.assertEqual(report.grade, OK, report.summary())
        got = outcomes(report)
        # A safe server refuses an un-namespaced search even from A, so that one
        # path cannot be exercised; every other path is exercised and clean.
        self.assertEqual(got.pop("store_search_all"), "NOT_EXERCISED")
        self.assertEqual(got.pop("store_search_own_prefix"), "NOT_RUN")
        self.assertEqual(set(got.values()), {"OK"}, report.summary())
        self.assertTrue(report.controls["auth_enforced"])
        self.assertTrue(report.controls["a_agent_recall_sees_marker"])

    def test_agent_that_recalls_nothing_cannot_pass_the_recall_path(self):
        report = probe("broken")
        self.assertEqual(outcomes(report)["agent_recall"], "NOT_EXERCISED")
        self.assertFalse(report.controls["a_agent_recall_sees_marker"])

    def test_no_authentication_is_an_observation_not_a_leak(self):
        report = probe("open")
        self.assertEqual(report.grade, OBSERVATION, report.summary())
        self.assertFalse(report.controls["auth_enforced"])
        self.assertIn("does not authenticate", report.detail)

    def test_unreadable_server_is_inconclusive_never_ok(self):
        report = probe("broken")
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertNotIn("OK", set(outcomes(report).values()))
        self.assertNotIn("LEAK", set(outcomes(report).values()))

    def test_visible_namespace_name_is_an_observation(self):
        report = probe("meta")
        self.assertEqual(report.grade, OBSERVATION, report.summary())
        self.assertNotIn("LEAK", set(outcomes(report).values()))
        self.assertTrue(report.controls["b_sees_a_namespace_name"])

    def test_same_reported_identity_is_an_observation(self):
        # "key" is the same in A's and B's run output, standing in for an app
        # that maps both tokens to one user.
        report = probe("leaky", whoami_field="key")
        self.assertEqual(report.grade, OBSERVATION, report.summary())
        self.assertIn("same identity", report.detail)


class NamespaceBoundary(unittest.TestCase):
    """B's own-namespace search with prefix-sibling ids (ali / alice)."""

    def _run(self, mode, **overrides):
        options = dict(namespace_a=["alice", "notes"], namespace_b=["ali"], authorized=True)
        options.update(overrides)
        with serving(mode) as url:
            return run_agent_memory_probe(url, "tok-alice", "tok-ali", **options)

    def test_string_prefix_store_leaks_on_the_own_namespace_path_only(self):
        report = self._run("prefixbug")
        got = outcomes(report)
        self.assertEqual(got["store_search_own_prefix"], "LEAK", report.summary())
        # The app's ownership check still blocks the direct reads of A's namespace.
        self.assertEqual(got["store_get"], "OK")
        self.assertEqual(got["store_search_namespace"], "OK")
        self.assertEqual(report.grade, LEAK)

    def test_segment_prefix_store_is_clean(self):
        report = self._run("safe")
        self.assertEqual(outcomes(report)["store_search_own_prefix"], "OK", report.summary())
        self.assertEqual(report.grade, OK)

    def test_not_run_without_prefix_sibling_ids(self):
        with serving("prefixbug") as url:
            report = run_agent_memory_probe(url, A, B, namespace_a=["alice", "notes"],
                                            namespace_b=["bob"], authorized=True)
        self.assertEqual(outcomes(report)["store_search_own_prefix"], "NOT_RUN")
        self.assertEqual(report.grade, OK)   # bob/alice are not siblings, so nothing crosses
        report = self._run("prefixbug", namespace_b=None)
        self.assertEqual(outcomes(report)["store_search_own_prefix"], "NOT_RUN")

    def test_segment_prefix_of_a_is_not_treated_as_sibling(self):
        # ("alice",) IS a segment prefix of ("alice","notes"): that is A's own
        # space, not a boundary case, so the path must not run.
        report = self._run("prefixbug", namespace_b=["alice"])
        self.assertEqual(outcomes(report)["store_search_own_prefix"], "NOT_RUN")


class PartialRuns(unittest.TestCase):
    def test_without_agent_inputs_those_paths_are_not_run(self):
        for mode, grade in (("leaky", LEAK), ("safe", OK)):
            report = probe(mode, assistant_id=None, save_input=None, recall_input=None)
            self.assertEqual(report.grade, grade, report.summary())
            got = outcomes(report)
            for name in ("thread_state", "thread_history", "agent_recall"):
                self.assertEqual(got[name], "NOT_RUN")

    def test_store_paths_not_exercised_when_a_cannot_write_there(self):
        # A safe server refuses a namespace that is not the caller's own, so the
        # Store paths cannot be exercised; the thread paths still decide.
        report = probe("safe", namespace_a=None)
        got = outcomes(report)
        self.assertEqual(report.grade, OK, report.summary())
        self.assertEqual(got["store_get"], "NOT_EXERCISED")
        self.assertEqual(got["thread_get"], "OK")
        self.assertTrue(any("not exercised" in o for o in report.observations))

    def test_recall_input_must_not_carry_the_marker(self):
        report = probe("safe", recall_input={"action": "recall", "key": "{marker}"})
        self.assertEqual(outcomes(report)["agent_recall"], "NOT_RUN")


class Hint(unittest.TestCase):
    TWO_TOKENS = dict(assistant_id=None, save_input=None, recall_input=None, whoami_field=None)

    def test_two_token_run_names_the_flags_that_were_left_out(self):
        report = probe("leaky", **self.TWO_TOKENS)
        hint = report.hint()
        self.assertEqual(len(hint.splitlines()), 1, hint)
        for flag in ("--assistant", "--save-input", "--recall-input", "--namespace-b"):
            self.assertIn(flag, hint)
        self.assertIn("docs/AGENT-MEMORY.md", hint)

    def test_only_the_missing_flags_are_named(self):
        hint = probe("leaky").hint()            # agent inputs given, no namespace_b
        self.assertIn("--namespace-b", hint)
        self.assertNotIn("--assistant", hint)
        hint = probe("leaky", recall_input=None).hint()
        self.assertIn("--recall-input", hint)
        self.assertNotIn("--save-input", hint)

    def test_no_hint_when_everything_ran(self):
        with serving("prefixbug") as url:
            report = run_agent_memory_probe(
                url, A, "tok-ali", namespace_a=["alice", "notes"], namespace_b=["ali"],
                authorized=True, **AGENT)
        self.assertNotIn("NOT_RUN", outcomes(report).values(), report.summary())
        self.assertEqual(report.hint(), "")

    def test_no_hint_when_the_run_stopped_before_any_path(self):
        with serving("safe") as url:
            report = run_agent_memory_probe(url, A, A, authorized=True)
        self.assertEqual(report.hint(), "")

    def test_hint_is_text_only_and_never_in_json(self):
        report = probe("leaky", **self.TWO_TOKENS)
        self.assertNotIn("hint", report.summary())
        self.assertNotIn("AGENT-MEMORY", json.dumps(report.to_dict()))
        self.assertNotIn("missing_inputs", report.to_dict())
        flags = ["--token-a", A, "--token-b", B]
        with serving("leaky") as url:
            code, out, _ = _cli(["confirm", "agent-memory", url] + flags)
            json_code, json_out, _ = _cli(["confirm", "agent-memory", url, "--json"] + flags)
        self.assertEqual((code, json_code), (1, 1))
        self.assertTrue(out.rstrip().splitlines()[-1].startswith("hint: "), out)
        self.assertEqual(json.loads(json_out)["grade"], LEAK)   # still one clean JSON document
        self.assertNotIn("hint", json_out)

    def test_demo_output_carries_no_hint(self):
        _, out, _ = _cli(["confirm", "agent-memory", "--demo"])
        self.assertNotIn("hint:", out)


class Refusals(unittest.TestCase):
    def test_one_token_for_both_identities_is_inconclusive(self):
        with serving("leaky") as url:
            report = run_agent_memory_probe(url, A, A, authorized=True)
        self.assertEqual(report.grade, INCONCLUSIVE)

    def test_unreachable_server_is_inconclusive(self):
        url = f"http://127.0.0.1:{dt._free_port()}"
        report = run_agent_memory_probe(url, A, B, timeout=2.0)
        self.assertEqual(report.grade, INCONCLUSIVE)
        self.assertIn("could not be reached", report.detail)

    def test_non_local_target_needs_authorization(self):
        with self.assertRaises(AuthorizationError):
            run_agent_memory_probe("https://agents.example.com", A, B)

    def test_practice_server_rejects_unknown_mode(self):
        self.assertIn("leaky", MODES)
        with self.assertRaises(ValueError):
            build_server("nonsense")


class ReportHygiene(unittest.TestCase):
    def test_no_token_or_marker_in_the_report(self):
        report = probe("leaky")
        dumped = json.dumps(report.to_dict()) + report.summary()
        self.assertNotIn(A, dumped)
        self.assertNotIn(B, dumped)
        self.assertNotIn("st-mem-", dumped)
        self.assertTrue(report.fingerprints["marker"].startswith("sha256:"))
        self.assertNotEqual(report.fingerprints["token_a"], report.fingerprints["token_b"])


def _cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CommandLine(unittest.TestCase):
    def test_demo_catches_leaky_and_clears_safe(self):
        code, out, _ = _cli(["confirm", "agent-memory", "--demo"])
        self.assertEqual(code, 0, out)
        self.assertIn("VERDICT: the test WORKS", out)

    def test_demo_dict_includes_the_prefixbug_fixture(self):
        res = dt._demo_agent_memory()
        self.assertEqual(res["prefixbug"].grade, LEAK)
        self.assertEqual(outcomes(res["prefixbug"])["store_search_own_prefix"], "LEAK")

    def test_listed(self):
        code, out, _ = _cli(["confirm", "--list"])
        self.assertEqual(code, 0)
        self.assertIn("agent-memory", out)

    def test_target_run_exit_codes(self):
        flags = ["--token-a", A, "--token-b", B, "--namespace-a", "alice.notes",
                 "--assistant", "memory",
                 "--save-input", json.dumps(AGENT["save_input"]),
                 "--recall-input", json.dumps(AGENT["recall_input"])]
        with serving("leaky") as url:
            code, out, _ = _cli(["confirm", "agent-memory", url] + flags)
        self.assertEqual(code, 1, out)
        self.assertIn("LEAK", out)
        with serving("safe") as url:
            code, out, _ = _cli(["confirm", "agent-memory", url] + flags)
        self.assertEqual(code, 0, out)
        with serving("open") as url:
            code, out, _ = _cli(["confirm", "agent-memory", url] + flags)
        self.assertEqual(code, 2, out)

    def test_bad_json_option_is_a_usage_error(self):
        with serving("safe") as url:
            code, _, err = _cli(["confirm", "agent-memory", url, "--token-a", A, "--token-b", B,
                                 "--save-input", "{not json"])
        self.assertEqual(code, 3)
        self.assertIn("not valid JSON", err)


if __name__ == "__main__":
    unittest.main()
