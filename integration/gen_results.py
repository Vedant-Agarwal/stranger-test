"""Generate integration/RESULTS.md from REAL probe output.

Runs the thin-deputy fixtures live (so the fixture table reflects exactly what
the probe reports — not a hand-typed guess) and folds in the latest saved
ContextForge and agentgateway run per scenario. Run with a venv that has
pyjwt[crypto]:

    python integration/gen_results.py
"""
from __future__ import annotations

import glob
import json
import os
import sys
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

class GenError(Exception):
    """Raised when the results page cannot be generated honestly."""


try:
    import jwt  # noqa: F401,E402
    from local_as import LocalAS  # noqa: E402
except Exception as _exc:  # missing dependency: cannot run, so exit non-zero
    print(f"ERROR: gen_results needs pyjwt[crypto] + cryptography ({_exc})",
          file=sys.stderr)
    sys.exit(2)
import xid10_thin_deputy_gate as g  # noqa: E402

DELEGATION_PROBE = "xid10-delegation"
FIXTURES = ["safe", "static_credential", "token_passthrough", "cached_token_reuse"]
FIXTURE_DESC = {
    "safe": "faithful delegation (control — must pass)",
    "static_credential": "forwards the gateway's own service token for everyone",
    "token_passthrough": "forwards the inbound user token unexchanged",
    "cached_token_reuse": "exchanges once, reuses that token for all callers",
    "conflated_issuer": "serves one provider's token for a same-named user of another",
    "two_issuers": "two same-named users from different providers (control — must pass)",
}


def _fixture_rows():
    as_ = LocalAS()
    srv = as_.serve()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    as_url = f"http://127.0.0.1:{srv.server_address[1]}"
    rows = []
    try:
        for mode in FIXTURES:
            r = g.run_mode(as_, as_url, mode)
            rows.append((mode, r.vulnerable, r.failures))
        rows.append(("two_issuers (safe)", *(
            lambda r: (r.vulnerable, r.failures))(g.run_two_issuer(as_, as_url, False))))
        rows.append(("conflated_issuer", *(
            lambda r: (r.vulnerable, r.failures))(g.run_two_issuer(as_, as_url, True))))
    finally:
        srv.shutdown(); srv.server_close()
    # A detection-proof table is only honest if the controls pass and every
    # broken fixture is flagged. Otherwise refuse to write it.
    for name, vuln, _ in rows:
        must_flag = name not in ("safe", "two_issuers (safe)")
        if bool(vuln) != must_flag:
            raise GenError(f"fixture {name!r}: vulnerable={vuln}, expected {must_flag}")
    return rows


def _load(f):
    """Load one run file. A file that exists but cannot be read is an error,
    never silently skipped."""
    try:
        with open(f) as fh:
            return json.load(fh)
    except Exception as exc:
        raise GenError(f"cannot read run file {f}: {exc}") from exc


def _run_files(pattern):
    """Live runs under runs/ if any match, else the committed sample-runs/
    fallback — so a fresh clone with no local runs still regenerates the same
    tables from the redacted samples. Per-pattern: a gateway with live runs
    uses them even if another gateway only has samples."""
    live = sorted(glob.glob(os.path.join(_HERE, "runs", pattern)))
    if live:
        return live
    return sorted(glob.glob(os.path.join(_HERE, "sample-runs", pattern)))


def _cf_rows():
    # The 1.1.1 scenario table: committed samples provide the baseline rows, and
    # any live scenario run overrides its (mode, trigger). The 1.0.6
    # exchange-failure finding has its own schema/section and is excluded here
    # (it would otherwise shadow the samples, since it shares the glob prefix).
    latest = {}
    samples = sorted(glob.glob(os.path.join(_HERE, "sample-runs", "contextforge-*.json")))
    live = sorted(glob.glob(os.path.join(_HERE, "runs", "contextforge-*.json")))
    if not samples + live:
        raise GenError("no ContextForge runs under integration/runs/ or sample-runs/")
    for f in samples + live:
        d = _load(f)
        # Only the XID-10 delegation scenarios belong in this table; other
        # probes (1.0.6 exchange failure, cachescope, ...) share the prefix.
        if d.get("probe") != DELEGATION_PROBE:
            continue
        latest[(d.get("mode"), d.get("trigger", "tool"))] = d
    return [latest[k] for k in sorted(latest)]


def _cf106_run():
    """The latest ContextForge 1.0.6 resource-read exchange-failure run (live
    under runs/, else the committed sample)."""
    files = _run_files("contextforge-1.0.6-resource-exchange-fail*.json")
    if not files:
        raise GenError("no ContextForge 1.0.6 exchange-failure run found")
    return _load(files[-1])


def _cf111_run():
    """The latest ContextForge 1.1.1 resource-read exchange-failure run (live
    under runs/, else the committed sample)."""
    files = _run_files("contextforge-1.1.1-resource-exchange-fail*.json")
    if not files:
        raise GenError("no ContextForge 1.1.1 exchange-failure run found")
    return _load(files[-1])


def _read_call(d, mode):
    for c in d.get("upstream_calls", []):
        if c.get("method") == "resources/read" and c.get("as_mode_at_time") == mode:
            return c
    return None


def _cf111_fail_summary(d):
    """From a 1.1.1 run: (any_fail_read_reached_upstream, all_callers_errored)."""
    tr = d.get("test_reads", [])
    reached = any(t.get("resources_read_reached_upstream") for t in tr)
    errored = bool(tr) and all(t.get("caller_error") for t in tr)
    return reached, errored


# agentgateway: the four scenario rows, in run order, then side checks.
AGW_SCENARIOS = [("delegation", "tool"), ("impersonation", "tool"),
                 ("two_issuers", "tool"), ("delegation", "resource")]
AGW_FIXTURES = {"broken_passthrough":
                "no exchange; `preserveToken` forwards the inbound user token"}


def _agw_runs():
    latest = {}
    for f in _run_files("agentgateway-*.json"):
        d = _load(f)
        if d.get("probe") != DELEGATION_PROBE:
            continue
        latest[(d.get("mode"), d.get("trigger", "tool"))] = d
    missing = [k for k in AGW_SCENARIOS + [(m, "tool") for m in AGW_FIXTURES]
               if k not in latest]
    if missing:
        raise GenError(f"agentgateway runs missing for {missing}")
    return latest


def _verdict(vulnerable):
    return "FLAGGED" if vulnerable else "OK (not vulnerable)"


# ---------------------------------------------------------------- CoSAI table
# One row per CoSAI MCP Security v2.0 rule, one column per gateway. Every cell
# is read from a saved run (linked); NOT TESTED rows link the design note. A
# missing or unreadable run for a tested rule is an error, never a blank cell.
GATEWAYS = [("contextforge", "ContextForge 1.1.1"), ("agentgateway", "agentgateway 1.7.0")]
_GRADE_CELL = {"OK": "OK", "FAIL": "FAIL", "LEAK": "FAIL", "INCONCLUSIVE": "INCONCLUSIVE"}


def _sample(name):
    path = os.path.join(_HERE, "sample-runs", name)
    if not os.path.exists(path):
        raise GenError(f"CoSAI table: sample run {name} is missing")
    d = _load(path)
    if d.get("run_valid") is False:
        raise GenError(f"CoSAI table: sample run {name} has run_valid=false")
    return d, f"sample-runs/{name}"


# An OBSERVATION is a fact that is neither a pass nor a leak. It is shown
# under its own label, never as INCONCLUSIVE (which means "could not tell").
_OBSERVATION_LABELS = {
    "not_narrowed": "NOT NARROWED",
    "does_not_cache": "DOES NOT CACHE",
    "not_supported": "NOT SUPPORTED",
    "accepted_as_x": "ACCEPTED AS X",
    "rejected": "REJECTED",
}


def _cell(grade, link, note="", label=None):
    if grade == "OBSERVATION":
        text = _OBSERVATION_LABELS.get(label or "")
        if text is None:
            raise GenError(f"CoSAI table: observation with unknown label {label!r} in {link}")
    else:
        text = _GRADE_CELL.get(grade)
        if text is None:
            raise GenError(f"CoSAI table: unknown grade {grade!r} in {link}")
    return f"[{text}]({link})" + (f" ({note})" if note else "")


def _row_identity(gw):
    d, link = _sample(f"{gw}-delegation.json")
    c = d.get("checks") or {}
    if "subject_preserved" not in c or "actor_present" not in c:
        raise GenError(f"CoSAI table: {link} lacks subject/actor checks")
    ok = c["subject_preserved"] and c["actor_present"]
    note = "subject + actor, delegation scenario"
    if "caller-supplied" in str(d.get("actor_source") or ""):
        note += "; actor is caller-supplied, see the note below"
    return _cell("OK" if ok else "FAIL", link, note)


def _row_scope(gw):
    d, link = _sample(f"{gw}-scope_narrowing.json")
    if d.get("probe") != "scope_narrowing":
        raise GenError(f"CoSAI table: {link} is not a scope_narrowing run")
    req = {str(c.get("requested_scope")) for c in d.get("per_call") or []}
    if not req or req & {"None", ""}:
        raise GenError(f"CoSAI table: {link} is not the configured-scope variant")
    return _cell(d.get("grade"), link, d.get("label", ""), label=d.get("label"))


def _row_issuer(gw):
    d, link = _sample(f"{gw}-issuer_unregistered.json")
    if d.get("probe") != "issuer_unregistered":
        raise GenError(f"CoSAI table: {link} is not an issuer_unregistered run")
    return _cell(d.get("grade"), link, d.get("label", ""))


def _handle_run(name, *, counts, variant):
    d, link = _sample(name)
    if d.get("probe") != "handle" or d.get("counts_toward_gateway_verdict") is not counts:
        raise GenError(f"CoSAI table: {link} is not a handle run with "
                       f"counts_toward_gateway_verdict={counts}")
    if variant is not None and d.get("agw_config") != variant:
        raise GenError(f"CoSAI table: {link} is not the {variant} config")
    return d, link


def _row_handle(gw):
    if gw != "agentgateway":
        d, link = _handle_run(f"{gw}-handle-trial.json", counts=True, variant=None)
        fwd = ((d.get("trial") or {}).get("forwarding") or {})
        if (d.get("trial") or {}).get("completed") and fwd and not any(fwd.values()):
            # A completed trial in which nothing of the tasks extension got
            # through: the gateway does not support it. A fact, not a "could
            # not tell".
            return _cell("OBSERVATION", link, "tasks extension not forwarded",
                         label="not_supported")
        return _cell(d.get("grade"), link, "tasks not forwarded")
    # agentgateway: one result per upstream-auth config we ran it with.
    tx, tx_link = _handle_run("agentgateway-handle-token-exchange-safe.json",
                              counts=True, variant="token-exchange")
    if not (tx.get("token_exchange_at_upstream") or {}).get("observed"):
        raise GenError(f"CoSAI table: {tx_link} did not observe token exchange at the upstream")
    pt, pt_link = _handle_run("agentgateway-handle-safe.json", counts=False, variant="per-user")
    if pt.get("violates_no_token_passthrough") is not True:
        raise GenError(f"CoSAI table: {pt_link} lacks violates_no_token_passthrough")
    sc, sc_link = _handle_run("agentgateway-handle-shared-credential-safe.json",
                              counts=False, variant="shared-credential")
    for d, link in ((tx, tx_link), (pt, pt_link), (sc, sc_link)):
        fixture = ((d.get("controls") or {}).get("broken_fixture_through_same_gateway") or {})
        if not fixture.get("detected"):
            raise GenError(f"CoSAI table: {link}: the leaky fixture was not detected")
    def raw(d):
        if d.get("grade") not in ("OK", "LEAK", "INCONCLUSIVE"):
            raise GenError(f"CoSAI table: unknown handle grade {d.get('grade')!r}")
        return d["grade"]

    return (f"token exchange = [{raw(tx)}]({tx_link}); "
            f"passthrough = [{raw(pt)}]({pt_link}) but violates the no-passthrough rule; "
            f"shared credential = [{raw(sc)}]({sc_link}) (configuration risk)")


def _row_cache(gw):
    d, link = _sample(f"{gw}-cachescope-private.json")
    if d.get("probe") != "cachescope":
        raise GenError(f"CoSAI table: {link} is not a cachescope run")
    trial = d.get("caching_trial") or {}
    if d.get("grade_honouring") == "INCONCLUSIVE" and trial.get("caches") is False:
        reads = trial.get("origin_reads_per_gateway_read")
        return _cell("OBSERVATION", link, f"origin reads per gateway read: {reads}",
                     label="does_not_cache")
    return _cell(d.get("grade_honouring"), link)


def _delegation_check(gw, checks):
    d, link = _sample(f"{gw}-delegation.json")
    if d.get("probe") != DELEGATION_PROBE:
        raise GenError(f"CoSAI table: {link} is not an {DELEGATION_PROBE} run")
    c = d.get("checks") or {}
    missing = [k for k in checks if k not in c]
    if missing:
        raise GenError(f"CoSAI table: {link} lacks checks {missing}")
    return ("OK" if all(c[k] for k in checks) else "FAIL"), link


def _row_passthrough(gw):
    # A passed-through user token reaches the upstream with no actor and the
    # gateway's own audience (the thin-deputy token_passthrough fixture fails
    # exactly these two checks); an exchanged one has both.
    grade, link = _delegation_check(gw, ("actor_present", "audience_correct"))
    return _cell(grade, link, "upstream token is an exchanged one: act present, aud = upstream")


def _row_audience(gw):
    grade, link = _delegation_check(gw, ("audience_correct",))
    return _cell(grade, link, "aud of the token sent upstream; the gateway's own inbound "
                              "aud check is not tested")


def _row_own_token(gw):
    grade, link = _delegation_check(gw, ("no_token_reuse", "no_cross_identity_bleed"))
    return _cell(grade, link, "A, B, A: distinct token per user, no cross-user reuse")


def _not_tested(note):
    return lambda gw: f"NOT TESTED ([design note](../notes/{note}))"


COSAI_RULES = [
    # (rule, section / row, level at which it is a MUST, cell function)
    ("Distinct actor and subject carried through token exchange",
     "3.3.2 Identity: User identity propagation", "L3", _row_identity),
    ("Scope narrows at each hop, never exceeds the delegating principal",
     "3.3.2 Authorization: Scope narrowing on delegation", "L3 (L2 SHOULD)", _row_scope),
    ("Tokens bound to the issuer that issued them (unregistered issuer refused)",
     "3.2.2 Secure Delegation (bullet: bind tokens to issuer)", "no level in 3.2.2", _row_issuer),
    ("No token passthrough",
     "3.3.2 Authorization: Token passthrough", "L2 (L3: token exchange)", _row_passthrough),
    ("Audience restriction on the upstream token",
     "3.3.2 Authorization: Audience restriction", "L3 (L2 SHOULD)", _row_audience),
    ("Own token per user",
     "3.3.2 Identity: User identity propagation (nearest row; none names per-user tokens)",
     "L3", _row_own_token),
    ("Task handles scoped to the authenticated principal",
     "3.3.2 State: Explicit state handle integrity", "L2", _row_handle),
    ("Private results never cached across users",
     "3.3.2 Tool output: Cacheable result handling", "L3 (L2 SHOULD)", _row_cache),
    ("Delegation chain preserved for audit",
     "3.3.2 Identity: User identity propagation", "L4",
     _not_tested("design-delegation-chain.md")),
    ("Defined / enforced maximum delegation depth",
     "3.3.2 Authorization: Delegation depth", "L3 (L2 SHOULD)",
     _not_tested("design-delegation-chain.md")),
    ("Sender-constrained tokens (DPoP or mTLS)",
     "3.3.2 Authorization: Token binding", "L3",
     _not_tested("design-sender-bound.md")),
]


def _cosai_table():
    L = ["## CoSAI MCP Security v2.0: rule by rule\n",
         "_Every cell is generated from the linked saved run; LEAK is shown as "
         "FAIL; an OBSERVATION (a fact that is neither a pass nor a leak) is shown "
         "under its own label (NOT NARROWED, DOES NOT CACHE, NOT SUPPORTED), never "
         "as INCONCLUSIVE. Levels are the CoSAI 3.3.1 levels (L3 Production, "
         "L4 Regulated)._\n",
         "| Rule | Section | Level (MUST) | " + " | ".join(n for _, n in GATEWAYS) + " |",
         "|---|---|---|" + "---|" * len(GATEWAYS)]
    for rule, sect, level, fn in COSAI_RULES:
        L.append(f"| {rule} | {sect} | {level} | " + " | ".join(fn(g) for g, _ in GATEWAYS) + " |")
    L.append("")
    # Observations that are recorded but are not a cell.
    obs = []
    for gw, name in GATEWAYS:
        d, link = _sample(f"{gw}-scope_narrowing-noscopes.json")
        obs.append(f"- {name}, exchange configured with **no scope**: "
                   f"{_cell(d.get('grade'), link, label=d.get('label'))} — {d.get('reason')}")
        d, link = _sample(f"{gw}-issuer_email_crossprovider.json")
        obs.append(f"- {name}, provider-X token claiming an email bound to provider Y: "
                   f"{_cell(d.get('grade'), link, label=d.get('label'))} — {d.get('reason')}")
    d, link = _sample("agentgateway-delegation.json")
    src = d.get("actor_source") or ""
    if "caller-supplied" not in src:
        raise GenError(f"{link}: expected a caller-supplied actor, got {src!r}")
    cf, cf_link = _sample("contextforge-delegation.json")
    cf_actor = sorted({str(c.get("actor")) for c in cf.get("recorded_calls") or []})
    obs.append(f"- **Caller-supplied actor.** agentgateway's actor is whatever the caller "
               f"sends in `x-actor-token` ([run]({link}): {src}); agentgateway cannot mint "
               "its own actor token. So its \"actor present\" and \"distinct actor and "
               "subject\" OKs show that the gateway forwards a caller-supplied actor into "
               "the exchange, not that the gateway asserts its own identity. Whether "
               "anything binds that actor to the calling client was not tested. ContextForge "
               f"uses its own client credentials (actor at the upstream: {cf_actor}, "
               f"[run]({cf_link})).")
    obs.append("- The agentgateway task-handle cell lists each upstream-auth config we "
               "ran: token exchange is the compliant one; passthrough forwards the user's "
               "own token; a shared credential uses `backendAuth.key`, a documented option "
               "([agentgateway docs: Static keys and passthrough](https://agentgateway.dev/"
               "docs/standalone/latest/documentation/configuration/security/backend-authn/"
               "key/)), so its LEAK is a configuration risk, not a gateway defect.")
    for gw, name in GATEWAYS:
        # The run where the origin labelled user-specific content "public":
        # what did the gateway hand the client?
        d, link = _sample(f"{gw}-cachescope-public.json")
        lab = d.get("gateway_label_at_client") or {}
        obs.append(f"- {name}, origin labels a user-specific read `cacheScope: "
                   f"{lab.get('origin_cacheScope')}`: the client receives "
                   f"`{lab.get('cacheScope')}` (`ttlMs` {lab.get('origin_ttlMs')} -> "
                   f"{lab.get('ttlMs')}; [run]({link}), change: {lab.get('change')}). "
                   "Observation only; the gateway is not graded on labelling.")
    L.append("Recorded observations (not graded cells):\n")
    L.extend(obs)
    L.append("")
    return L


def main():
    fx = _fixture_rows()
    cf = _cf_rows()
    agw = _agw_runs()
    out = os.path.join(_HERE, "RESULTS.md")
    L = []
    L.append("# XID-10 results\n")
    L.append("_Generated by `integration/gen_results.py` from live probe runs — "
             "do not hand-edit the tables._\n")
    L.append("Delegation-fidelity probe (XID-10: on-behalf-of / RFC 8693 "
             "token-exchange confused-deputy). Two axes of evidence: a real "
             "third-party gateway, and deliberately-broken fixtures the probe "
             "must catch. Bearer tokens are never stored; run files under "
             "`integration/runs/` keep a `sha256:` fingerprint per call. "
             "Reproduce via `integration/CONTEXTFORGE_GATE.md` and "
             "`integration/AGENTGATEWAY_GATE.md`.\n")

    L.extend(_cosai_table())

    L.append("## ContextForge 1.1.1 (real gateway)\n")
    if cf:
        L.append("| Scenario | Trigger | Verdict | Failed checks |")
        L.append("|---|---|---|---|")
        for d in cf:
            fails = ", ".join(d.get("failures") or []) or "—"
            L.append(f"| {d.get('mode')} | {d.get('trigger','tool')} | "
                     f"{_verdict(d.get('vulnerable'))} | {fails} |")
        L.append("")
        any_cache = any(d.get("a_first_eq_a_third_token") for d in cf)
        L.append(f"- ContextForge caches the exchange per user "
                 f"(A's 1st and 3rd calls carried the same token): "
                 f"`{any_cache}` — so the no-reuse/bleed checks are meaningful here.")
        L.append("- No vulnerability was *found* in ContextForge 1.1.1 on these "
                 "scenarios; external users were granted tool execution via an "
                 "ordinary team role, not admin.\n")
    else:
        L.append("_No saved ContextForge runs found under `integration/runs/`._\n")

    cf106 = _cf106_run()
    cf111 = _cf111_run()
    if cf106 and cf111:
        ok6 = _read_call(cf106, "ok")
        bad6 = _read_call(cf106, "fail")
        ok1 = _read_call(cf111, "ok")
        f1_reached, f1_errored = _cf111_fail_summary(cf111)
        n_tests = len(cf111.get("test_reads", []))
        L.append("## Validation against a known, fixed bug\n")
        L.append("The same method, run against two ContextForge versions, shows a "
                 "behavior present in **1.0.6** and fixed in **1.1.1**. An oauth "
                 "token-exchange gateway serves a resource **template**; an uncached "
                 "template instance is read over MCP (the federated path — a cached "
                 "catalogued resource is served locally and never federates, so it "
                 "would prove nothing). The authorization server first succeeds "
                 "(control), then returns HTTP 400 for the exchange (test). A "
                 "recording upstream logs each call's **header names** (not full "
                 "requests) and whether an `Authorization` header was present. The "
                 "inbound caller is the CF **admin** JWT (3-part, so CF's "
                 "`looks_like_jwt()` guard passes and a real exchange is attempted); "
                 "**untested with an ordinary, non-admin user**. Loopback only; "
                 f"1.0.6 runs from the official container (`{cf106.get('image')}`), "
                 f"1.1.1 is installed via {cf111.get('install', 'pip')}.\n")
        L.append("| Version | exchange succeeds (control): upstream read / `Authorization` | exchange fails (HTTP 400): upstream read / `Authorization` / caller |")
        L.append("|---|---|---|")
        L.append(f"| **1.0.6** | {bool(ok6)} / **present** (`Bearer`) | "
                 f"{bool(bad6)} / **ABSENT** / content returned |")
        L.append(f"| **1.1.1** | {bool(ok1)} / **present** (`Bearer`) | "
                 f"{f1_reached} / — / **error (fails closed)** |")
        L.append("")
        if ok6 and bad6:
            extra = sorted(set(ok6.get("header_names", [])) - set(bad6.get("header_names", [])))
            L.append(f"- **1.0.6:** the failed-exchange upstream read has the **same "
                     f"header names as the successful one, minus** "
                     f"{', '.join('`'+h+'`' for h in extra) or '—'}. The finding is "
                     "that **the gateway sends an unauthenticated request upstream** "
                     "instead of failing closed. What the upstream does with it "
                     "depends on the upstream: this test upstream answers without "
                     "checking the token, so CF returned content; a real upstream "
                     "that requires a token would refuse the request.")
        L.append(f"- **1.1.1:** when the exchange fails, **no `resources/read` "
                 "reaches the upstream** and the caller gets an error "
                 "(`Token exchange failed … Contact your administrator`) — the "
                 f"gateway **fails closed**. Deterministic across {n_tests} test "
                 "reads; the control read reached the upstream **with** "
                 "`Authorization`, so the read path works and the fail result is "
                 "not a harness artifact.")
        L.append("- **Root cause (source):** in 1.0.6 the `resource_service` "
                 "token-exchange branch only logs on failure and falls through "
                 "with no auth header; **1.1.1 raises `ResourceError(...)`** and "
                 "fails closed. \"1.1.1 fixes it\" now rests on the live 1.1.1 run "
                 "above, not only on reading source. **1.1.0 not tested.**")
        L.append("- Reproduce: 1.0.6 `integration/CONTEXTFORGE_1.0.6_GATE.md` "
                 "(`integration/xid10_cf106_resource_exchange_fail.py`); 1.1.1 "
                 "`integration/CONTEXTFORGE_1.1.1_GATE.md` "
                 "(`integration/xid10_cf111_resource_exchange_fail.py`). Tokens "
                 "redacted to `sha256:` fingerprints in the saved runs.\n")

    L.append("## agentgateway 1.7.0 (real gateway)\n")
    agw_rows = [agw[k] for k in AGW_SCENARIOS if k in agw]
    if agw_rows:
        ver = agw_rows[0].get("gateway_version_full", {})
        L.append(f"Official release binary v{ver.get('version')} (git "
                 f"`{str(ver.get('git_revision'))[:12]}`), configured by file "
                 "only (`backendAuth.oauthTokenExchange` on the MCP target, "
                 "pointed at the local AS; inbound users validated by `jwtAuth`; "
                 "no gateway-side RBAC). MCP `2026-07-28` on both sides.\n")
        L.append("**The actor is the caller, not the gateway.** agentgateway "
                 "cannot obtain its own actor token; it must come from the "
                 "incoming request. Here the calling agent sends a "
                 "client-credentials token for `agent-client` in `x-actor-token`, "
                 "so `actor_present` means the caller's actor was carried "
                 "through the exchange, not that the gateway identified itself.\n")
        L.append("| Scenario | Trigger | Verdict | Failed checks |")
        L.append("|---|---|---|---|")
        for d in agw_rows:
            fails = ", ".join(d.get("failures") or []) or "—"
            L.append(f"| {d.get('mode')} | {d.get('trigger','tool')} | "
                     f"{_verdict(d.get('vulnerable'))} | {fails} |")
        L.append("")
        fx_agw = [(m, agw[(m, "tool")]) for m in AGW_FIXTURES if (m, "tool") in agw]
        if fx_agw:
            L.append("Detection through agentgateway itself (deliberately broken "
                     "config, same gate; must be flagged):\n")
            L.append("| Fixture | What it does | Verdict | Failed checks |")
            L.append("|---|---|---|---|")
            for m, d in fx_agw:
                L.append(f"| `{m}` | {AGW_FIXTURES[m]} | "
                         f"{_verdict(d.get('vulnerable'))} | "
                         f"{', '.join(d.get('failures') or []) or '—'} |")
            L.append("")
        cache = [d.get("a_first_eq_a_third_token") for d in agw_rows]
        L.append(f"- agentgateway caches the exchange per user (A's 1st and 3rd "
                 f"calls carried the same token): `{all(cache)}` in every row.")
        leaked = any(d.get("actor_header_reached_upstream") for d in agw_rows)
        L.append(f"- The caller's `x-actor-token` header reached the upstream: "
                 f"`{leaked}` (agentgateway strips it before forwarding).")
        L.append("- With the delegation config and no `x-actor-token`, "
                 "agentgateway answered HTTP 400 and made no upstream call: it "
                 "fails closed rather than falling back to impersonation "
                 "(observed by the gate's `delegation_missing_actor` mode; no "
                 "run file, since the probe cannot start).")
        L.append("- No vulnerability was *found* in agentgateway 1.7.0 on these "
                 "scenarios. The same checks did fail on the broken config above "
                 "and on the thin-deputy fixtures below.\n")
    else:
        L.append("_No saved agentgateway runs found under `integration/runs/`._\n")

    L.append("## Detection proof — leaky fixtures (thin deputy, real RFC 8693 exchange)\n")
    L.append("Each is a deliberately-broken deputy; the probe must flag it (the "
             "`safe`/`two_issuers (safe)` controls must pass).\n")
    L.append("| Fixture | What it does | Verdict | Failed checks |")
    L.append("|---|---|---|---|")
    for name, vuln, fails in fx:
        desc = FIXTURE_DESC.get(name.split(" ")[0], FIXTURE_DESC.get(name, ""))
        L.append(f"| `{name}` | {desc} | {_verdict(vuln)} | "
                 f"{', '.join(fails) or '—'} |")
    L.append("")

    L.append("## Known limits\n")
    L.append("- The two-provider (same-name, different-issuer) check relies on "
             "`orig_iss`, a claim the bundled test authorization server adds to "
             "the exchanged token. Real authorization servers do not emit it, so "
             "this specific check currently exercises the probe only against the "
             "test login server, not an arbitrary production IdP.")
    L.append("- Each test provider (provX/provY) has its own signing key; the AS "
             "validates a subject token only with the key of its own issuer. The "
             "unregistered-issuer test runs against an AS in `--lax-subject-issuer` "
             "mode (recorded per run), so a gateway that let the token through "
             "would not be hidden by the AS refusing it.")
    L.append("- The clean ContextForge result covers the scenarios above on "
             "version **1.1.1 only**.")
    L.append("- The clean agentgateway result covers **1.7.0 only**, with the "
             "actor supplied by the caller (agentgateway has no way to mint a "
             "gateway actor token from config).")
    L.append("- The **1.0.6** missing-auth-on-exchange-failure catch above was "
             "observed against the official v1.0.6 container (1.0.6 is not cleanly "
             "pip-installable, so a period-correct container is required). It is a "
             "since-fixed historical behavior: the pip-installed **1.1.1** fails "
             "closed on the same test (live run above), confirming the fix.\n")

    with open(out, "w") as f:
        f.write("\n".join(L))
    print(f"wrote {out}")
    print("fixture rows:")
    for r in fx:
        print(" ", r)


if __name__ == "__main__":
    try:
        main()
    except GenError as exc:
        print(f"ERROR: {exc}; RESULTS.md not written", file=sys.stderr)
        sys.exit(1)
