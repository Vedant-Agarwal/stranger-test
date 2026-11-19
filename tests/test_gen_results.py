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


@unittest.skipIf(gr is None, "needs pyjwt[crypto] (integration/gen_results.py)")
class LiteLLMColumnTests(unittest.TestCase):
    def test_third_column_label(self):
        names = [n for _, n in gr.GATEWAYS]
        self.assertEqual(names[2], "LiteLLM 1.109.1 (an LLM gateway with MCP features)")

    def test_identity_side_by_side(self):
        for gw in ("contextforge", "agentgateway"):
            cell = gr._row_identity(gw)
            self.assertIn(f"default: [OK](sample-runs/{gw}-delegation.json)", cell)
            self.assertIn(f"act_from_client: [OK](sample-runs/{gw}-delegation-act_from_client.json)", cell)

    def test_litellm_identity_is_not_supported_not_fail(self):
        cell = gr._row_identity("litellm")
        self.assertTrue(cell.startswith("[NOT SUPPORTED](sample-runs/litellm-delegation.json)"), cell)
        self.assertNotIn("[FAIL]", cell)
        self.assertIn("litellm-delegation-act_from_client.json", cell)

    def test_litellm_identity_fails_if_gateway_sent_actor_and_it_failed(self):
        real = gr._sample

        def fake(n):
            d, link = real(n)
            if n == "litellm-delegation.json":
                d = dict(d, exchanges_client_auth=[dict(e, actor_present=True)
                                                   for e in d["exchanges_client_auth"]])
            return d, link
        gr._sample = fake
        try:
            self.assertIn("default: [FAIL]", gr._row_identity("litellm"))
        finally:
            gr._sample = real

    def test_unproven_pass_is_inconclusive(self):
        real = gr._sample

        def fake(n):
            d, link = real(n)
            if n == "litellm-delegation.json":
                d = dict(d, check_grades=dict(d["check_grades"], no_token_reuse="INCONCLUSIVE"))
            return d, link
        gr._sample = fake
        try:
            rows = {r[0]: r for r in gr.COSAI_RULES}
            self.assertTrue(rows["Own token per user"][3]("litellm").startswith("[INCONCLUSIVE]"))
        finally:
            gr._sample = real

    def test_litellm_cells(self):
        self.assertIn("[DOES NOT CACHE]", gr._row_cache("litellm"))
        self.assertEqual(gr._row_handle("litellm").count("[NOT SUPPORTED]"), 3)
        cell = gr._row_issuer("litellm")
        self.assertTrue(cell.startswith(
            "[DELEGATED TO LOGIN SERVER](sample-runs/litellm-issuer_unregistered.json)"), cell)
        self.assertIn("strict login server = [refused, nothing upstream](sample-runs/"
                      "litellm-issuer_unregistered-strict_login_server.json)", cell)
        self.assertIn("lax login server = [call reached the upstream]", cell)
        self.assertNotIn("[FAIL]", cell)
        self.assertIn("passthrough config flagged: [FAIL]", gr._row_passthrough("litellm"))

    def test_issuer_mapping_needs_both_observations(self):
        real = gr._sample

        def fake(n):
            d, link = real(n)
            if n == "litellm-issuer_unregistered-strict_login_server.json":
                ev = dict(d["evidence"], probe_upstream_calls=[{"subject": "mallory"}])
                d = dict(d, evidence=ev)
            return d, link
        gr._sample = fake
        try:  # strict run let the call through: no mapping, the probe's FAIL shows
            self.assertTrue(gr._row_issuer("litellm").startswith("[FAIL]"))
        finally:
            gr._sample = real

    def test_issuer_probe_grades_unchanged_in_runs(self):
        lax, _ = gr._sample("litellm-issuer_unregistered.json")
        strict, _ = gr._sample("litellm-issuer_unregistered-strict_login_server.json")
        self.assertEqual((lax["grade"], strict["grade"]), ("FAIL", "INCONCLUSIVE"))

    def test_issuer_known_limit_line(self):
        self.assertIn("on LiteLLM's open-source build it happens only at the login server",
                      open(os.path.join(_INTEGRATION, "RESULTS.md")).read())

    def test_act_from_client_runs_stay_out_of_scenario_tables(self):
        for d in gr._cf_rows():
            self.assertFalse(d.get("as_act_from_client"))
        for d in gr._agw_runs().values():
            self.assertFalse(d.get("as_act_from_client"))

    def test_litellm_observations(self):
        text = "\n".join(gr._cosai_table())
        for s in ("LiteLLM, protocol version", "does not inspect the user's token",
                  "the caller's key and the user token are independent",
                  "Missing or invalid subject token"):
            self.assertIn(s, text)


@unittest.skipIf(gr is None, "needs pyjwt[crypto] (integration/gen_results.py)")
class ToolHiveSectionTests(unittest.TestCase):
    """The ToolHive results-layer section: label mappings only; run grades
    stay as the probes recorded them."""

    def setUp(self):
        self.text = "\n".join(gr._toolhive_section())

    def test_section_present_and_two_modes(self):
        self.assertIn("## Stacklok ToolHive v0.65.0", self.text)
        self.assertIn("thv run <remote-url>", self.text)
        self.assertIn("thv vmcp serve", self.text)

    def test_actor_not_supported_with_act_from_client_ok(self):
        self.assertIn("[NOT SUPPORTED](sample-runs/toolhive-delegation.json)", self.text)
        self.assertIn("act_from_client](sample-runs/toolhive-delegation-act_from_client.json)",
                      self.text)
        self.assertIn("actor_present=OK", self.text)

    def test_two_issuers_not_applicable_label(self):
        self.assertIn("NOT APPLICABLE: second issuer refused at gateway", self.text)
        # The run keeps its own grade (INCONCLUSIVE), not relabelled in the run.
        ti = gr._th("toolhive-two_issuers.json")[0]
        self.assertEqual(ti.get("grade"), "INCONCLUSIVE")
        self.assertIn("the run grades **INCONCLUSIVE**", self.text)

    def test_crossprovider_shows_run_valid_false_reason(self):
        xp = gr._th("toolhive-issuer_email_crossprovider.json")[0]
        self.assertIs(xp.get("run_valid"), False)
        self.assertIn("run_valid=False", self.text)
        self.assertIn("positive control", self.text)

    def test_issuer_unregistered_rejected_ok(self):
        iu = gr._th("toolhive-issuer_unregistered.json")[0]
        self.assertEqual(iu.get("grade"), "OK")
        self.assertIn("[OK](sample-runs/toolhive-issuer_unregistered.json)", self.text)

    def test_inbound_validation_extra_observation(self):
        self.assertIn("VALIDATES INBOUND](sample-runs/toolhive-inbound-validation.json)", self.text)

    def test_cache_does_not_cache(self):
        self.assertIn("DOES NOT CACHE](sample-runs/toolhive-cache.json)", self.text)

    def test_same_user_credentials_no_cache_hit_both_modes(self):
        # Neither mode observed a cache hit, so the section must not claim
        # "caches per credential"; it must say cache hit observed = False.
        self.assertEqual(self.text.count("cache hit observed = False"), 2)
        self.assertNotIn("caches per credential", self.text)
        for name in ("toolhive-same-user-credentials.json",
                     "toolhive-vmcp-same-user-credentials.json"):
            d = gr._th(name)[0]
            self.assertEqual(d["cold_control"]["grade"], "OK")
            self.assertEqual(d["warm"]["grade"], "OK")
            self.assertFalse(d["observations"].get("cache_hit_observed"))

    def test_vmcp_reexchange_observation_not_a_bug(self):
        self.assertIn("each request re-exchanged", self.text)
        self.assertIn("not a bug", self.text)
        self.assertIn("Kubernetes operator deployment", self.text)
        self.assertIn("not tested", self.text)
        self.assertIn("subjectProviderName", self.text)
        self.assertIn("not run", self.text)

    def test_dev_flags_disclosed(self):
        self.assertIn("--jwks-allow-private-ip", self.text)
        self.assertIn("--oidc-insecure-allow-http", self.text)
        self.assertIn("only where keys are fetched from", self.text)


@unittest.skipIf(gr is None, "needs pyjwt[crypto] (integration/gen_results.py)")
class ToolHiveColumnTests(unittest.TestCase):
    """ToolHive standalone is a fourth CoSAI-table column; a probe it did not
    run shows NOT RUN. The three full-suite gateways and the observation loops
    are unaffected (GATEWAYS stays length 3)."""

    def test_table_gateways_adds_toolhive_only_to_table(self):
        # GATEWAYS (the full-suite gateways and the observation loops) stays 3;
        # TABLE_GATEWAYS adds the focused-subset columns (ToolHive, then Kuadrant).
        self.assertEqual(len(gr.GATEWAYS), 3)
        table = [g for g, _ in gr.TABLE_GATEWAYS]
        self.assertIn("toolhive", table)
        self.assertNotIn("toolhive", [g for g, _ in gr.GATEWAYS])

    def test_toolhive_column_header_present(self):
        text = "\n".join(gr._cosai_table())
        self.assertIn("ToolHive 0.65.0 (standalone)", text)

    def test_handle_row_is_not_run(self):
        self.assertTrue(gr._row_handle("toolhive").startswith("NOT RUN"), gr._row_handle("toolhive"))

    def test_cache_row_does_not_cache(self):
        self.assertIn("DOES NOT CACHE", gr._row_cache("toolhive"))

    def test_passthrough_not_fail_for_no_actor_gateway(self):
        # ToolHive sends no actor; the no-passthrough cell must be read from
        # user_token_reached_upstream, not actor_present (which would wrongly FAIL).
        cell = gr._row_passthrough("toolhive")
        self.assertTrue(cell.startswith("[OK]"), cell)
        self.assertIn("no user token reached the upstream", cell)

    def test_identity_is_not_supported_with_act_from_client(self):
        cell = gr._row_identity("toolhive")
        self.assertIn("NOT SUPPORTED", cell)
        self.assertIn("toolhive-delegation-act_from_client.json", cell)


@unittest.skipIf(gr is None, "needs pyjwt[crypto] (integration/gen_results.py)")
class KuadrantSectionAndColumnTests(unittest.TestCase):
    """Kuadrant is the 5th CoSAI column (NOT RUN where a probe wasn't run) and
    keeps its own section for the label, the direct-route caveat and the
    aud-passthrough observation. Results-layer only; run grades unchanged."""

    def test_fifth_column_present(self):
        self.assertEqual(len(gr.TABLE_GATEWAYS), 5)
        self.assertEqual([g for g, _ in gr.TABLE_GATEWAYS][-1], "kuadrant")
        text = "\n".join(gr._cosai_table())
        self.assertIn("Kuadrant 1.6.0 (Authorino, direct route)", text)

    def test_not_run_where_not_run(self):
        for row in (gr._row_scope, gr._row_issuer, gr._row_handle, gr._row_cache,
                    gr._row_passthrough):
            self.assertTrue(row("kuadrant").startswith("NOT RUN"), row("kuadrant"))

    def test_identity_not_supported_no_act_from_client(self):
        cell = gr._row_identity("kuadrant")
        self.assertIn("NOT SUPPORTED", cell)
        self.assertIn("act_from_client not run", cell)

    def test_audience_and_own_token_ok(self):
        self.assertTrue(gr._row_audience("kuadrant").startswith("[OK]"))
        self.assertTrue(gr._row_own_token("kuadrant").startswith("[OK]"))

    def test_section_keeps_label_caveat_and_observation(self):
        text = "\n".join(gr._kuadrant_section())
        self.assertIn("minimally adapted", text)
        self.assertIn("mcp router/broker was **not** in the path", text)
        self.assertIn("forwarded unchanged, by design", text)
        self.assertIn("By design — all headers forwarded", text)
        self.assertIn("fails closed", text)


@unittest.skipIf(gr is None, "needs pyjwt[crypto] (integration/gen_results.py)")
class CVE59822SectionTests(unittest.TestCase):
    """The CVE-2026-59822 regression section (FIXED versions only) and its
    committed fingerprint-only sample runs."""

    def setUp(self):
        self.runs = {"1.84.0": gr._cve59822_run("1_84_0"),
                     "1.109.1": gr._cve59822_run("1_109_1")}

    def test_sample_runs_present_and_pass(self):
        for ver, d in self.runs.items():
            self.assertIsNotNone(d, f"missing CVE-59822 sample run for {ver}")
            self.assertEqual(d["cve"], "CVE-2026-59822")
            self.assertEqual(d["gateway_version"], ver)
            r = d["result"]
            self.assertEqual(r["status"], "PASS")
            self.assertTrue(r["invalid_rejected"])
            self.assertTrue(r["valid_accepted"])
            self.assertEqual(r["invalid_cases_establishing_a_session"], [])
            self.assertTrue(d["broken_fixture_in_run"]["caught"])

    def test_fixed_versions_only_no_affected(self):
        # Every sampled version must be >= the first fixed release (1.84.0).
        for d in self.runs.values():
            major, minor = (int(x) for x in d["gateway_version"].split(".")[:2])
            self.assertGreaterEqual((major, minor), (1, 84))

    def test_invalid_rejected_valid_accepted_in_cases(self):
        for d in self.runs.values():
            c = d["cases"]
            for case in ("no_bearer", "garbage_bearer", "forged_bearer"):
                self.assertFalse(c[case]["session_established"], case)
            self.assertTrue(c["valid_bearer"]["session_established"])

    def test_no_secret_in_sample_run(self):
        import json
        for d in self.runs.values():
            blob = json.dumps(d)
            self.assertNotIn("sk-st-", blob)
            self.assertNotIn("sk-smoke", blob)
            self.assertIn("sha256:", d["master_key"])

    def test_results_section_and_required_label(self):
        text = open(os.path.join(_INTEGRATION, "RESULTS.md")).read()
        self.assertIn("## Validation against CVE-2026-59822", text)
        self.assertIn("validated against the fix for CVE-2026-59822 (fixed versions "
                      "1.84.0, 1.109.1; invalid/forged tokens rejected)", text)
        self.assertIn("GHSA-7488-6r32-c95q", text)
        # the positive control and a rejection both appear in the table
        self.assertIn("200 (session)", text)
        self.assertIn("no session", text)


if __name__ == "__main__":
    unittest.main()
