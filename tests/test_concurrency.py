"""Two users at the same time: grading guards (each case named in
strangertest/concurrency.py) and the in-run racy/safe fixture. Standard library only."""

import unittest

from strangertest.concurrency import check_markers, grade_concurrent, make_markers
from strangertest.practice_concurrency_http import run_concurrency_fixture

MK = {"A": "mkA-aaaaaaaaaaaaaaaaaaaaaaaa", "B": "mkB-bbbbbbbbbbbbbbbbbbbbbbbb"}
IDS = {"A": ("https://as.test", "alice"), "B": ("https://as.test", "bob")}
PROVEN = {"proven": True}


def req(label, n, text=None, error=None):
    return {"label": label, "nonce": n, "text": f"note={MK[label]}" if text is None else text,
            "error": error}


def up(n, sub, iss="https://as.test", parsed=True, method="tools/call"):
    return {"method": method, "nonce": n, "parsed": parsed, "issuer": iss, "subject": sub}


def base():
    reqs = [req("A", "a1"), req("B", "b1"), req("A", "a2"), req("B", "b2")]
    calls = [up("a1", "alice"), up("b1", "bob"), up("a2", "alice"), up("b2", "bob")]
    return reqs, calls


def grade(reqs, calls, *, max_inflight=4, fixture=PROVEN):
    return grade_concurrent(requests=reqs, upstream_calls=calls, markers=MK, identities=IDS,
                            max_inflight=max_inflight, fixture=fixture)


class GradeTests(unittest.TestCase):
    def test_clean_run_is_ok(self):
        self.assertEqual(grade(*base())[:2], ("OK", "isolated"))

    def test_other_marker_in_response_fails(self):
        reqs, calls = base()
        reqs[0]["text"] = f"note={MK['B']}"
        self.assertEqual(grade(reqs, calls)[:2], ("FAIL", "cross_identity_response"))

    def test_wrong_subject_upstream_fails(self):
        reqs, calls = base()
        calls[0] = up("a1", "bob")
        self.assertEqual(grade(reqs, calls)[:2], ("FAIL", "wrong_subject_upstream"))

    def test_same_subject_other_issuer_fails(self):
        reqs, calls = base()
        calls[0] = up("a1", "alice", iss="https://other.test")
        self.assertEqual(grade(reqs, calls)[0], "FAIL")

    # C1
    def test_markers_must_not_overlap(self):
        with self.assertRaises(ValueError):
            check_markers({"A": "mk-1", "B": "xmk-1x"})
        m = make_markers()
        self.assertNotIn(m["A"], m["B"])
        self.assertNotIn(m["B"], m["A"])

    # C2
    def test_discovery_traffic_is_not_graded(self):
        reqs, calls = base()
        calls.append(up(None, "gateway-svc", method="tools/list"))
        self.assertEqual(grade(reqs, calls)[0], "OK")

    # C3
    def test_duplicate_nonce_same_identity_is_not_a_leak(self):
        reqs, calls = base()
        calls.append(up("a1", "alice"))
        self.assertEqual(grade(reqs, calls)[0], "OK")

    # C4
    def test_error_response_is_inconclusive_not_fail(self):
        reqs, calls = base()
        reqs[1] = req("B", "b1", text=None, error="HTTP 429")
        reqs[1]["text"] = None
        self.assertEqual(grade(reqs, calls)[0], "INCONCLUSIVE")

    # C5
    def test_same_user_new_token_is_not_a_leak(self):
        reqs, calls = base()
        for c in calls:
            c["token"] = f"sha256:{c['nonce']}"   # every call a different token
        self.assertEqual(grade(reqs, calls)[0], "OK")

    # C6
    def test_serialized_is_observation_not_ok(self):
        self.assertEqual(grade(*base(), max_inflight=1)[:2], ("OBSERVATION", "serialized"))

    # C7
    def test_nonce_stripped_is_inconclusive(self):
        reqs, calls = base()
        for c in calls:
            c["nonce"] = None
        self.assertEqual(grade(reqs, calls)[0], "INCONCLUSIVE")

    # C8
    def test_request_without_upstream_call_is_inconclusive(self):
        reqs, calls = base()
        self.assertEqual(grade(reqs, calls[:-1])[0], "INCONCLUSIVE")

    # C9
    def test_fixture_not_proven_blocks_ok(self):
        for fx in (None, {"proven": False}, {}):
            self.assertEqual(grade(*base(), fixture=fx)[0], "INCONCLUSIVE", fx)

    # C10
    def test_unparsed_upstream_token_is_inconclusive(self):
        reqs, calls = base()
        calls[2] = up("a2", None, iss=None, parsed=False)
        self.assertEqual(grade(reqs, calls)[0], "INCONCLUSIVE")

    # C11
    def test_seen_leak_not_downgraded_by_controls(self):
        reqs, calls = base()
        reqs[3]["text"] = f"note={MK['A']}"
        self.assertEqual(grade(reqs, calls, max_inflight=1, fixture=None)[0], "FAIL")


class FixtureTests(unittest.TestCase):
    """The concurrency is what is tested: the racy deputy passes A, B, A one at
    a time and FAILs the concurrent probe; the safe one never FAILs it."""

    def test_racy_fails_concurrent_passes_serial(self):
        out = run_concurrency_fixture(pairs=20)
        self.assertFalse(out["racy"]["serial_vulnerable"])
        self.assertEqual(out["racy"]["concurrent_grade"], "FAIL")
        self.assertNotEqual(out["safe"]["concurrent_grade"], "FAIL")
        self.assertGreaterEqual(out["racy"]["max_inflight"], 2)
        self.assertTrue(out["proven"])


if __name__ == "__main__":
    unittest.main()
