"""The generated CoSAI rule table (integration/gen_results.py).

gen_results needs pyjwt[crypto]; under the stdlib-only test run these tests
are skipped. Run them with a venv that has it:
    <venv>/bin/python -m unittest tests.test_gen_results
"""

import importlib
import os
import sys
import unittest

_INTEGRATION = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "integration")
try:
    import jwt  # noqa: F401
    if _INTEGRATION not in sys.path:
        sys.path.insert(0, _INTEGRATION)
    gr = importlib.import_module("gen_results")
except Exception:  # pragma: no cover - dependency missing
    gr = None


@unittest.skipIf(gr is None, "needs pyjwt[crypto] (integration/gen_results.py)")
class HandleCellTests(unittest.TestCase):
    def test_agentgateway_cell_is_per_config(self):
        cell = gr._row_handle("agentgateway")
        self.assertIn("token exchange = [OK](sample-runs/agentgateway-handle-token-exchange-safe.json)", cell)
        self.assertIn("passthrough = [OK](sample-runs/agentgateway-handle-safe.json) "
                      "but violates the no-passthrough rule", cell)
        self.assertIn("shared credential = [LEAK](sample-runs/"
                      "agentgateway-handle-shared-credential-safe.json) (configuration risk)", cell)

    def test_contextforge_cell_names_the_reason(self):
        self.assertIn("tasks extension not forwarded", gr._row_handle("contextforge"))


@unittest.skipIf(gr is None, "needs pyjwt[crypto] (integration/gen_results.py)")
class ObservationLabelTests(unittest.TestCase):
    def test_observation_gets_its_own_label(self):
        cell = gr._cell("OBSERVATION", "x.json", label="not_narrowed")
        self.assertTrue(cell.startswith("[NOT NARROWED](x.json)"), cell)
        self.assertNotIn("INCONCLUSIVE", cell)

    def test_unknown_observation_label_is_an_error(self):
        with self.assertRaises(gr.GenError):
            gr._cell("OBSERVATION", "x.json", label="")

    def test_gateway_that_does_not_cache_is_not_inconclusive(self):
        for gw in ("contextforge", "agentgateway"):
            cell = gr._row_cache(gw)
            self.assertIn("[DOES NOT CACHE]", cell)
            self.assertNotIn("INCONCLUSIVE", cell)

    def test_tasks_not_forwarded_is_not_supported(self):
        cell = gr._row_handle("contextforge")
        self.assertIn("[NOT SUPPORTED]", cell)
        self.assertNotIn("INCONCLUSIVE", cell)

    def test_table_never_shows_observation_as_inconclusive(self):
        text = "\n".join(gr._cosai_table())
        self.assertNotIn("shown as INCONCLUSIVE", text)
        self.assertIn("NOT NARROWED", text)


@unittest.skipIf(gr is None, "needs pyjwt[crypto] (integration/gen_results.py)")
class DelegationRowTests(unittest.TestCase):
    def rows(self):
        return {r[0]: r for r in gr.COSAI_RULES}

    def test_new_rows_present_and_generated(self):
        rows = self.rows()
        for name in ("No token passthrough", "Audience restriction on the upstream token",
                     "Own token per user"):
            self.assertIn(name, rows)
            for gw in ("contextforge", "agentgateway"):
                cell = rows[name][3](gw)
                self.assertTrue(cell.startswith(f"[OK](sample-runs/{gw}-delegation.json)"), cell)

    def test_rows_fail_on_a_failed_check(self):
        rows = self.rows()
        real = gr._sample
        cases = {"No token passthrough": "actor_present",
                 "Audience restriction on the upstream token": "audience_correct",
                 "Own token per user": "no_token_reuse"}
        for name, check in cases.items():
            def fake(n, check=check):
                d, link = real(n)
                d = dict(d, checks=dict(d["checks"], **{check: False}))
                return d, link
            gr._sample = fake
            try:
                self.assertTrue(rows[name][3]("agentgateway").startswith("[FAIL]"), name)
            finally:
                gr._sample = real

    def test_caller_supplied_actor_note(self):
        text = "\n".join(gr._cosai_table())
        self.assertIn("caller-supplied", text)
        self.assertIn("x-actor-token", text)


if __name__ == "__main__":
    unittest.main()
