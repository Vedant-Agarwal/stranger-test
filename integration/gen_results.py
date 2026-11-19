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
        if d.get("probe") != DELEGATION_PROBE or d.get("as_act_from_client"):
            continue  # act_from_client runs are shown in the CoSAI identity row only
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


def _samecred_run(version):
    """The latest same-user-credentials token-exchange cache run for a CF
    version (live under runs/, else the committed sample). Reproduces the
    CVE-2026-110195 cache-key collision; see CONTEXTFORGE_SAMECRED_GATE.md."""
    files = _run_files(f"contextforge-{version}-samecred-cache*.json")
    return _load(files[-1]) if files else None


def _cve59822_run(tag):
    """The latest LiteLLM CVE-2026-59822 regression run for a FIXED version
    (live under runs/, else the committed sample). `tag` is the version with
    dots as underscores, e.g. "1_84_0"; see xid10_litellm_cve59822_gate.py."""
    files = _run_files(f"litellm-cve59822-{tag}*.json")
    return _load(files[-1]) if files else None


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
        if d.get("probe") != DELEGATION_PROBE or d.get("as_act_from_client"):
            continue
        latest[(d.get("mode"), d.get("trigger", "tool"))] = d
    missing = [k for k in AGW_SCENARIOS + [(m, "tool") for m in AGW_FIXTURES]
               if k not in latest]
    if missing:
        raise GenError(f"agentgateway runs missing for {missing}")
    return latest


# LiteLLM: scenario rows, then side checks (deliberately broken configs).
LL_SCENARIOS = ["delegation", "delegation-act_from_client", "two_issuers"]
LL_FIXTURES = {"passthrough": "`auth_type: true_passthrough` forwards the caller's own token",
               "shared_credential": "`auth_type: bearer_token`: one static token for every user"}


def _ll_runs():
    out = {}
    for name in LL_SCENARIOS + list(LL_FIXTURES):
        d, link = _sample(f"litellm-{name}.json")
        if d.get("probe") != DELEGATION_PROBE:
            raise GenError(f"{link} is not an {DELEGATION_PROBE} run")
        out[name] = (d, link)
    return out


def _verdict(vulnerable):
    return "FLAGGED" if vulnerable else "OK (not vulnerable)"


# ---------------------------------------------------------------- CoSAI table
# One row per CoSAI MCP Security v2.0 rule, one column per gateway. Every cell
# is read from a saved run (linked); NOT TESTED rows link the design note. A
# missing or unreadable run for a tested rule is an error, never a blank cell.
GATEWAYS = [("contextforge", "ContextForge 1.1.1"), ("agentgateway", "agentgateway 1.7.0"),
            ("litellm", "LiteLLM 1.109.1 (an LLM gateway with MCP features)")]
# The CoSAI table additionally shows ToolHive's STANDALONE (`thv run`) mode as a
# fourth column. ToolHive ran a focused subset, so a probe it did not run shows
# NOT RUN. The vMCP details and the full label mappings live in the ToolHive
# section below. The observation loops AFTER the table use GATEWAYS (the three
# full-suite gateways) only, since ToolHive did not run those probes.
TABLE_GATEWAYS = GATEWAYS + [("toolhive", "ToolHive 0.65.0 (standalone)"),
                             ("kuadrant", "Kuadrant 1.6.0 (Authorino, direct route)")]
_GRADE_CELL = {"OK": "OK", "FAIL": "FAIL", "LEAK": "FAIL", "INCONCLUSIVE": "INCONCLUSIVE"}


def _not_run(note=""):
    return "NOT RUN" + (f" ({note})" if note else "")


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
    "delegated_to_login_server": "DELEGATED TO LOGIN SERVER",
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


def _identity_grade(d, link):
    c = d.get("checks") or {}
    if "subject_preserved" not in c or "actor_present" not in c:
        raise GenError(f"CoSAI table: {link} lacks subject/actor checks")
    grades = d.get("check_grades")
    if grades:  # runs that grade each check against in-run broken fixtures
        g = [grades.get("subject_preserved"), grades.get("actor_present")]
        if "FAIL" in g:
            return "FAIL"
        return "OK" if g == ["OK", "OK"] else "INCONCLUSIVE"
    return "OK" if (c["subject_preserved"] and c["actor_present"]) else "FAIL"


def _gateway_sends_actor(d):
    """Did the gateway itself put an actor into the exchange (actor_token)?
    From the per-exchange login-server log when the run has one, else from
    the actor seen at the upstream."""
    ex = d.get("exchanges_client_auth")
    if ex:
        return any(e.get("actor_present") for e in ex)
    return bool((d.get("checks") or {}).get("actor_present"))


def _row_identity(gw):
    if gw == "kuadrant":
        # Kuadrant ran delegation only (no act_from_client run). Authorino sends
        # no actor_token on the exchange -> impersonation (actor_present FAIL).
        d, link = _sample("kuadrant-delegation.json")
        g = (d.get("check_grades") or {}).get("actor_present")
        return (f"[NOT SUPPORTED]({link}) (Authorino sends no actor_token on the exchange -> "
                f"impersonation; actor_present={g}); act_from_client not run")
    d, link = _sample(f"{gw}-delegation.json")
    a, alink = _sample(f"{gw}-delegation-act_from_client.json")
    if not a.get("as_act_from_client"):
        raise GenError(f"CoSAI table: {alink} was not run with act_from_client")
    if d.get("as_act_from_client"):
        raise GenError(f"CoSAI table: {link} was run with act_from_client")
    if not _gateway_sends_actor(d) and not _gateway_sends_actor(a):
        src = sorted({str(e.get("act_source")) for e in a.get("exchanges_client_auth") or []})
        actors = sorted({str(c.get("actor")) for c in a.get("recorded_calls") or []})
        return (f"[NOT SUPPORTED]({link}) (the gateway sends no actor_token in either login-"
                f"server mode); with act_from_client the login server sets act from the "
                f"gateway's client authentication: [{_identity_grade(a, alink)}]({alink}) "
                f"(actor at the upstream: {actors}, act source: {src})")
    note = "subject + actor"
    if "caller-supplied" in str(d.get("actor_source") or ""):
        note += "; actor is caller-supplied, see the note below"
    actors = sorted({str(c.get("actor")) for c in a.get("recorded_calls") or []})
    return (f"default: {_cell(_identity_grade(d, link), link, note)}; act_from_client: "
            f"{_cell(_identity_grade(a, alink), alink, f'actor at the upstream: {actors}')}")


def _row_scope(gw):
    if gw == "kuadrant":
        return _not_run("scope_narrowing not run for Kuadrant (scope_narrowed is OK within delegation)")
    d, link = _sample(f"{gw}-scope_narrowing.json")
    if d.get("probe") != "scope_narrowing":
        raise GenError(f"CoSAI table: {link} is not a scope_narrowing run")
    req = {str(c.get("requested_scope")) for c in d.get("per_call") or []}
    if not req or req & {"None", ""}:
        raise GenError(f"CoSAI table: {link} is not the configured-scope variant")
    return _cell(d.get("grade"), link, d.get("label", ""), label=d.get("label"))


def _issuer_delegated(lax, strict):
    """LiteLLM's issuer binding is the login server's, read from two runs of the
    same probe: against the lax AS the token was passed to the exchange, granted
    and reached the upstream; against the strict AS it was passed to the exchange,
    refused, and nothing reached the upstream. Only when both runs show exactly
    that is the cell mapped (here, at the results layer; the probe's own grades,
    FAIL and INCONCLUSIVE, are kept in the runs)."""
    le, se = lax.get("evidence") or {}, strict.get("evidence") or {}
    lax_ok = ((lax.get("login_server") or {}).get("lax_subject_issuer") is True
              and lax.get("grade") == "FAIL" and le.get("exchange_attempted_with_probe_token")
              and bool(le.get("probe_upstream_calls"))
              and (lax.get("broken_fixture") or {}).get("grade") == "FAIL")
    strict_ok = ((strict.get("login_server") or {}).get("lax_subject_issuer") is False
                 and strict.get("observation_only") is True
                 and se.get("exchange_attempted_with_probe_token")
                 and not se.get("probe_upstream_calls") and not se.get("unattributed_calls")
                 and se.get("control_before_succeeded") and se.get("control_after_succeeded")
                 and all(str(r.get("outcome", "")).startswith("refused")
                         for r in se.get("exchange_records_for_probe_token") or [{}]))
    return bool(lax_ok and strict_ok)


def _row_issuer(gw):
    if gw == "kuadrant":
        return _not_run("issuer_unregistered not run for Kuadrant")
    d, link = _sample(f"{gw}-issuer_unregistered.json")
    if d.get("probe") != "issuer_unregistered":
        raise GenError(f"CoSAI table: {link} is not an issuer_unregistered run")
    if gw == "litellm":
        s, s_link = _sample("litellm-issuer_unregistered-strict_login_server.json")
        if s.get("probe") != "issuer_unregistered":
            raise GenError(f"CoSAI table: {s_link} is not an issuer_unregistered run")
        if _issuer_delegated(d, s):
            return (_cell("OBSERVATION", link, label="delegated_to_login_server")
                    + f": strict login server = [refused, nothing upstream]({s_link}); "
                    f"lax login server = [call reached the upstream]({link})")
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
    if gw == "toolhive":
        return _not_run("task-handle probe not run for ToolHive")
    if gw == "kuadrant":
        return _not_run("task-handle probe not run for Kuadrant")
    if gw == "litellm":
        parts = []
        for cfg, label in (("token-exchange", "token exchange"), ("passthrough", "passthrough"),
                           ("shared-credential", "shared credential")):
            d, link = _sample(f"litellm-handle-trial-{cfg}.json")
            if d.get("probe") != "handle" or d.get("ll_config") != cfg:
                raise GenError(f"CoSAI table: {link} is not the LiteLLM {cfg} handle trial")
            trial = d.get("trial") or {}
            fwd = trial.get("forwarding") or {}
            if trial.get("completed") and fwd and not any(fwd.values()):
                parts.append(f"{label} = [NOT SUPPORTED]({link})")
            else:
                parts.append(f"{label} = {_cell(d.get('grade'), link)}")
        return "; ".join(parts) + " (tasks extension not forwarded)"
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
    if gw == "kuadrant":
        return _not_run("cachescope probe not run for Kuadrant")
    if gw == "toolhive":
        # ToolHive did not run the cachescope probe; it ran a simpler cache
        # trial, which showed it does not cache on the standalone path (so
        # cross-user caching of private results cannot occur). DOES NOT CACHE.
        d, link = _sample("toolhive-cache.json")
        trial = d.get("caching_trial") or {}
        if trial.get("caches") is False:
            n = trial.get("new_exchanges_for_two_reads")
            return _cell("OBSERVATION", link, f"{n} exchanges for two reads (cache trial, not the "
                         "cachescope probe)", label="does_not_cache")
        return _not_run("cachescope probe not run for ToolHive")
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
    if not all(c[k] for k in checks):
        return "FAIL", link
    grades = d.get("check_grades")
    if grades and any(grades.get(k) != "OK" for k in checks):
        # A pass not shown able to fail by an in-run fixture is not an OK.
        return "INCONCLUSIVE", link
    return "OK", link


def _row_passthrough_litellm():
    """LiteLLM sends no actor, so 'act present' cannot show the upstream token
    was exchanged. Use what was observed instead: every upstream bearer was a
    token the AS issued by exchange (none was the user's), aud = upstream; and
    the deliberately broken true_passthrough config through LiteLLM itself
    fails audience_correct."""
    d, link = _sample("litellm-delegation.json")
    fx, fx_link = _sample("litellm-passthrough.json")
    if "user_token_reached_upstream" not in d:
        raise GenError(f"CoSAI table: {link} lacks user_token_reached_upstream")
    if "audience_correct" not in (fx.get("failures") or []):
        raise GenError(f"CoSAI table: {fx_link}: the passthrough config was not flagged")
    if d["user_token_reached_upstream"] or not d["checks"].get("audience_correct"):
        return _cell("FAIL", link, "a user token reached the upstream")
    grade = (d.get("check_grades") or {}).get("audience_correct", "INCONCLUSIVE")
    return _cell(grade, link, "every upstream bearer was issued by the AS exchange, aud = "
                              f"upstream; no act (none sent); passthrough config flagged: "
                              f"[FAIL]({fx_link})")


def _row_passthrough(gw):
    if gw == "litellm":
        return _row_passthrough_litellm()
    if gw == "kuadrant":
        # Kuadrant sends no actor, so the generic actor-based check does not
        # apply; a dedicated passthrough run (user_token_reached_upstream) was
        # not recorded, so NOT RUN. (The aud==server pass-through is in the
        # Kuadrant section, as a by-design observation.)
        return _not_run("no dedicated passthrough run for Kuadrant")
    if gw == "toolhive":
        # Like LiteLLM, ToolHive sends no actor, so "act present" cannot show the
        # upstream token was exchanged. Use what was observed: no user token
        # reached the upstream, and aud was the upstream's. No passthrough-config
        # fixture was run for ToolHive (noted).
        d, link = _sample("toolhive-delegation.json")
        if "user_token_reached_upstream" not in d:
            raise GenError(f"CoSAI table: {link} lacks user_token_reached_upstream")
        if d["user_token_reached_upstream"] or not (d.get("checks") or {}).get("audience_correct"):
            return _cell("FAIL", link, "a user token reached the upstream")
        return _cell("OK", link, "exchanged token upstream (aud = upstream); no user token "
                     "reached the upstream; actor NOT SUPPORTED; no passthrough-config fixture run")
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


def _litellm_observations():
    d, link = _sample("litellm-delegation.json")
    iu, iu_link = _sample("litellm-issuer_unregistered.json")
    ius, ius_link = _sample("litellm-issuer_unregistered-strict_login_server.json")
    ef, ef_link = _sample("litellm-exchange_fail.json")
    cs, cs_link = _sample("litellm-cachescope-private.json")
    ups = sorted({u.get("answered") for u in d.get("upstream_init_versions") or []})
    calls = d.get("recorded_calls") or []
    out = [
        f"- **LiteLLM, protocol version.** By default LiteLLM 1.109.1 advertises only "
        f"2024-11-05..2025-11-25; the client asked for 2026-07-28 and got "
        f"`{d.get('client_negotiated_version')}`, and LiteLLM opened the upstream with "
        f"`initialize` at {ups} ([run]({link})). 2026-07-28 is opt-in "
        "(`general_settings.mcp_advertised_versions`, used only for the task-handle trial).",
        f"- **LiteLLM does not inspect the user's token** in the open-source build used here "
        "(no JWT auth configured; that is a licensed feature): the unregistered-issuer token "
        f"was passed to the token exchange (`exchange_attempted_with_probe_token`: "
        f"{(iu.get('evidence') or {}).get('exchange_attempted_with_probe_token')}, "
        f"lax login server: [run]({iu_link}); strict login server: "
        f"{(ius.get('evidence') or {}).get('exchange_attempted_with_probe_token')}, "
        f"[run]({ius_link})). Its issuer binding is whatever the login server enforces.",
        f"- **LiteLLM: the caller's key and the user token are independent.** One LiteLLM key "
        f"(`{d.get('master_key')}`) carried alice, bob, alice; the upstream saw "
        f"{[c.get('subject') for c in calls]} on distinct exchanged tokens, and never the key "
        f"(`litellm_key_reached_upstream`: {d.get('litellm_key_reached_upstream')}; "
        f"[run]({link})). The key is not bound to a user.",
        f"- **LiteLLM, exchange failure**: [{ef.get('grade')}]({ef_link}) ({ef.get('reason')}). "
        f"The caller gets HTTP 200 with a tool error on `/mcp`: "
        f"\"{_ll_error_text(ef)}\"; on the per-server endpoint "
        f"`/mcp/notes` a call with no user token is HTTP "
        f"{(ef.get('per_server_endpoint_no_token') or {}).get('status')} with `WWW-Authenticate`. "
        f"The fall-through fixture through the same check: "
        f"[{(ef.get('broken_fixture') or {}).get('grade')}]({ef_link}).",
        f"- **LiteLLM, cache labels**: at 2025-11-25 there is no `cacheScope`; the origin added "
        f"`cacheScope`/`ttlMs` to the read result and the client received keys "
        f"{sorted({k for r in (cs.get('caching_trial') or {}).get('reads') or [] for k in r.get('result_keys') or []})} "
        f"([run]({cs_link})).",
    ]
    return out


def _ll_error_text(ef):
    import re as _re
    raw = str(ef.get("caller_error_text") or "")
    m = _re.search(r'"text": "([^"]+)"', raw.replace('\\"', '"'))
    return (m.group(1) if m else raw)[:240]


def _cosai_table():
    L = ["## CoSAI MCP Security v2.0: rule by rule\n",
         "_Every cell is generated from the linked saved run; LEAK is shown as "
         "FAIL; an OBSERVATION (a fact that is neither a pass nor a leak) is shown "
         "under its own label (NOT NARROWED, DOES NOT CACHE, NOT SUPPORTED, "
         "DELEGATED TO LOGIN SERVER), never as INCONCLUSIVE. Labels are mapped here, "
         "at the results layer; the probes' grading is unchanged and each run keeps "
         "the probe's own grade. DELEGATED TO LOGIN SERVER (LiteLLM, unregistered "
         "issuer) is read from two runs of the same probe: the strict login server "
         "refused the token and nothing reached the upstream; the lax one granted it "
         "and the call reached the upstream (the probe grades these INCONCLUSIVE and "
         "FAIL). The **ToolHive** column is its standalone (`thv run`) mode; "
         "**NOT RUN** marks a probe not run for ToolHive (its vMCP results and the "
         "full label mappings are in the ToolHive section below). Levels are the "
         "CoSAI 3.3.1 levels (L3 Production, L4 Regulated)._\n",
         "| Rule | Section | Level (MUST) | " + " | ".join(n for _, n in TABLE_GATEWAYS) + " |",
         "|---|---|---|" + "---|" * len(TABLE_GATEWAYS)]
    for rule, sect, level, fn in COSAI_RULES:
        L.append(f"| {rule} | {sect} | {level} | "
                 + " | ".join(fn(g) for g, _ in TABLE_GATEWAYS) + " |")
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
        if gw == "litellm":
            continue  # LiteLLM speaks 2025-11-25: no cacheScope label to relay; see below
        # The run where the origin labelled user-specific content "public":
        # what did the gateway hand the client?
        d, link = _sample(f"{gw}-cachescope-public.json")
        lab = d.get("gateway_label_at_client") or {}
        obs.append(f"- {name}, origin labels a user-specific read `cacheScope: "
                   f"{lab.get('origin_cacheScope')}`: the client receives "
                   f"`{lab.get('cacheScope')}` (`ttlMs` {lab.get('origin_ttlMs')} -> "
                   f"{lab.get('ttlMs')}; [run]({link}), change: {lab.get('change')}). "
                   "Observation only; the gateway is not graded on labelling.")
    for gw, name in GATEWAYS[:2]:
        d, link = _sample(f"{gw}-impersonation-act_from_client.json")
        ex = d.get("exchanges_client_auth") or []
        actors = sorted({str(c.get("actor")) for c in d.get("recorded_calls") or []})
        obs.append(f"- {name}, impersonation config (no actor_token) with the login server in "
                   f"`act_from_client` mode: client authentication sent "
                   f"{sorted({str(e.get('client_auth_method')) for e in ex})}, act source "
                   f"{sorted({str(e.get('act_source')) for e in ex})}, actor at the upstream "
                   f"{actors} ([run]({link})).")
    obs.extend(_litellm_observations())
    obs.extend(_concurrency_observations())
    obs.extend(_login_fault_observations())
    obs.extend(_actor_observation())
    L.append("Recorded observations (not graded cells):\n")
    L.extend(obs)
    L.append("")
    return L


# Two users at the same time (strangertest/concurrency.py): an identity check,
# graded on identity only. One line per gateway.
_CONC_SETUP = {
    "contextforge": lambda d: ("pip install, single process, SQLite; rate limit raised through "
                               "its documented settings: `RATE_LIMIT_MEDIUM_RPM="
                               f"{(d.get('env') or {}).get('RATE_LIMIT_MEDIUM_RPM')}`, "
                               "`RATE_LIMIT_MEDIUM_BURST="
                               f"{(d.get('env') or {}).get('RATE_LIMIT_MEDIUM_BURST')}`"),
    "agentgateway": lambda d: "release binary, default settings, delegation config",
    "litellm": lambda d: "default settings: single process, no database; token-exchange config",
}


def _concurrency_observations():
    out = []
    for gw, name in GATEWAYS:
        d, link = _sample(f"{gw}-concurrent.json")
        if d.get("probe") != "concurrent_identities":
            raise GenError(f"{link} is not a concurrent_identities run")
        fx = d.get("broken_fixture") or {}
        if fx.get("proven") is not True or fx.get("concurrent_grade") != "FAIL":
            raise GenError(f"{link}: the racy fixture did not FAIL in this run")
        sessions = 2 * int(d.get("pairs") or 0)
        if d.get("grade") == "FAIL":
            text = f"identity CROSSED under {sessions} concurrent sessions ({d.get('label')})"
        elif d.get("grade") == "OK":
            text = f"no identity crossing under {sessions} concurrent sessions"
        else:
            raise GenError(f"{link}: concurrent grade {d.get('grade')}, not OK or FAIL")
        out.append(f"- {name}, two users at the same time: [{text}]({link}) ({_CONC_SETUP[gw](d)}); "
                   f"racy fixture in the same run: FAIL (and it passes the one-at-a-time probe).")
    return out


# The login server misbehaves (strangertest/login_faults.py): per mode, did the
# probe request reach the upstream, and what did the caller get.
_FAULT_LABELS = [("http_500", "HTTP 500"), ("unreachable", "unreachable"),
                 ("slow", "slow"), ("malformed_not_json", "not JSON"),
                 ("malformed_no_token", "no token")]


def _caller_text(detail):
    import re
    text = str(detail or "")
    if text.startswith("{"):
        try:
            r = json.loads(text)
            parts = [c.get("text", "") for c in r.get("content") or [] if isinstance(c, dict)]
            text = ("tool error: " if r.get("isError") else "result: ") + " ".join(parts)
        except ValueError:
            pass
    text = re.sub(r" from http://127\.0\.0\.1:\d+\S*", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= 160 else text[:157] + "..."


def _login_fault_observations():
    out = []
    for gw, name in GATEWAYS:
        d, link = _sample(f"{gw}-login_faults.json")
        if d.get("probe") != "login_faults":
            raise GenError(f"{link} is not a login_faults run")
        modes = d.get("modes") or {}
        groups = {}
        for key, label in _FAULT_LABELS:
            m = modes.get(key)
            if m is None:
                raise GenError(f"{link}: mode {key} missing")
            if (m.get("broken_fixture") or {}).get("grade") != "FAIL":
                raise GenError(f"{link}: fall-through fixture did not FAIL in mode {key}")
            if not any(c.get("token_kind") == "exchanged"
                       for c in (m.get("control") or {}).get("upstream_calls") or []):
                raise GenError(f"{link}: control did not reach the upstream in mode {key}")
            pr = m.get("probe") or {}
            if pr.get("reached_without_authorization"):
                reached = "REACHED the upstream with no Authorization"
            elif pr.get("reached_upstream"):
                reached = "reached the upstream authenticated"
            else:
                reached = "nothing reached the upstream"
            sig = (reached, _caller_text((pr.get("caller") or {}).get("detail")), m.get("grade"))
            groups.setdefault(sig, []).append(label)
        why = (f" (it waited out the {d.get('slow_seconds'):g} s slow login server, so the "
               "failure path was not taken)")
        parts = [f"{', '.join(labels)}: {reached}; the caller got \"{text}\" [{grade}]"
                 + (why if grade == "OBSERVATION" and labels == ["slow"] else "")
                 for (reached, text, grade), labels in groups.items()]
        out.append(f"- {name}, the login server misbehaves ([run]({link}); a working control "
                   "reached the upstream first in each mode; the fall-through fixture FAILED "
                   "every mode in the same run): " + "; ".join(parts) + ".")
    return out


_AGW_ACTOR_SOURCE = "crates/agentgateway/src/http/auth/oauth/mod.rs"


def _actor_observation():
    d, link = _sample("agentgateway-actor_lies.json")
    m, mlink = _sample("agentgateway-actor_lies-may_act.json")
    for x, lk in ((d, link), (m, mlink)):
        if x.get("probe") != "actor_lies" or x.get("grade") != "OBSERVATION":
            raise GenError(f"{lk} is not an actor_lies OBSERVATION run")
        if not x.get("control_reached_upstream_with_actor"):
            raise GenError(f"{lk}: the control did not reach the upstream with its actor")
    names = {"other_client": "another client's actor token", "expired": "an expired actor token",
             "other_audience": "an actor token for another audience"}

    def cases(x):
        bits = []
        for k, label in names.items():
            c = x["cases"][k]
            arrived = c.get("what_arrived_upstream") or []
            what = (f"reached the upstream as actor {sorted({str(a.get('actor')) for a in arrived})}"
                    if arrived else c.get("observation", "").replace("_", " "))
            bits.append(f"{label}: {what}")
        return "; ".join(bits)
    return [f"- **agentgateway 1.7.0, lying caller** (OBSERVATION): the actor token is "
            "forwarded unchecked by default; enforceMayAct compares claims without verifying "
            "them; validating the actor is left to the login server (source: "
            f"`{_AGW_ACTOR_SOURCE}`, v1.7.0: `actor_token_from_request`, `may_act_authorizes`, "
            "`decode_unverified_jwt_claims`). Default config ([run]("
            f"{link})): {cases(d)}. With `enforceMayAct` ([run]({mlink})): {cases(m)}. "
            "The test login server checks an actor token's signature, issuer and expiry, not "
            "its audience."]


def _litellm_section():
    runs = _ll_runs()
    d0 = runs["delegation"][0]
    v = d0.get("gateway_versions") or {}
    L = ["## LiteLLM 1.109.1 (an LLM gateway with MCP features)\n",
         f"`litellm[proxy]=={v.get('litellm')}` from pip (licence `{v.get('license')}`, MCP SDK "
         f"{v.get('mcp')}), open-source build: no licence key, no database. Configured by file "
         "only (`auth_type: oauth2_token_exchange` on the MCP server, pointed at the local AS; "
         "the caller sends a throwaway master key in `x-litellm-api-key` and the user token in "
         "`Authorization`). MCP `2025-11-25` on both sides (LiteLLM's default set). See "
         "`integration/LITELLM_GATE.md`.\n",
         "**No actor from the gateway.** LiteLLM's RFC 8693 request has no `actor_token`; it "
         "does authenticate itself to the token endpoint (`client_secret_post`). Only a login "
         "server that derives `act` from that client authentication (`act_from_client`) puts an "
         "actor into the token.\n",
         "| Scenario | Login server | Verdict | Failed checks | Per-check grades (in-run fixtures) |",
         "|---|---|---|---|---|"]
    for name in LL_SCENARIOS:
        d, link = runs[name]
        mode = "act_from_client" if d.get("as_act_from_client") else "default"
        grades = ", ".join(f"{k}={g}" for k, g in (d.get("check_grades") or {}).items())
        L.append(f"| [{d.get('mode')}]({link}) | {mode} | {_verdict(d.get('vulnerable'))} | "
                 f"{', '.join(d.get('failures') or []) or '—'} | {grades} |")
    L.append("")
    L.append("Detection through LiteLLM itself (deliberately broken configs, same gate; must "
             "be flagged):\n")
    L.append("| Fixture | What it does | Verdict | Failed checks |")
    L.append("|---|---|---|---|")
    for name, desc in LL_FIXTURES.items():
        d, link = runs[name]
        L.append(f"| [`{name}`]({link}) | {desc} | {_verdict(d.get('vulnerable'))} | "
                 f"{', '.join(d.get('failures') or []) or '—'} |")
    L.append("")
    L.append(f"- LiteLLM caches the exchange per subject token (A's 1st and 3rd calls carried "
             f"the same token): `{all(runs[n][0].get('a_first_eq_a_third_token') for n in LL_SCENARIOS)}`.")
    sent = sorted({m for n in LL_SCENARIOS for m in runs[n][0].get("litellm_sent_client_credentials") or []})
    L.append(f"- Client authentication LiteLLM sent to the token endpoint: {sent}.")
    L.append("- A check is graded OK only when one of the thin-deputy fixtures run in the same "
             "run failed it (the per-check grades above).\n")
    return L


def _th(name):
    """Load a ToolHive sample-run, allowing run_valid=False (the issuer_email
    crossprovider run is intentionally run_valid=False: its positive control
    cannot be established because ToolHive binds to one issuer)."""
    path = os.path.join(_HERE, "sample-runs", name)
    if not os.path.exists(path):
        raise GenError(f"ToolHive section: sample run {name} is missing")
    return _load(path), f"sample-runs/{name}"


def _toolhive_section():
    """Stacklok ToolHive v0.65.0, presented as its own section rather than a
    fourth column in the CoSAI table: ToolHive ran a focused subset of the
    probes across TWO deployment modes (standalone `thv run` and `thv vmcp
    serve`), which the single-column table does not model. Labels are mapped
    here at the results layer; every run keeps the probe's own grade."""
    d, dl = _th("toolhive-delegation.json")
    a, al = _th("toolhive-delegation-act_from_client.json")
    sc, scl = _th("toolhive-scope_narrowing.json")
    ns, nsl = _th("toolhive-scope_narrowing-noscopes.json")
    iu, iul = _th("toolhive-issuer_unregistered.json")
    ti, til = _th("toolhive-two_issuers.json")
    xp, xpl = _th("toolhive-issuer_email_crossprovider.json")
    iv, ivl = _th("toolhive-inbound-validation.json")
    ef, efl = _th("toolhive-exchange_fail.json")
    ca, cal = _th("toolhive-cache.json")
    su, sul = _th("toolhive-same-user-credentials.json")
    vm, vml = _th("toolhive-vmcp-same-user-credentials.json")
    v = d.get("gateway_versions") or {}
    dg = d.get("check_grades") or {}
    ag = a.get("check_grades") or {}
    a_actors = sorted({str(c.get("actor")) for c in a.get("recorded_calls") or []})
    caching = (ca.get("caching_trial") or {})

    # Actor label (same treatment as LiteLLM): NOT SUPPORTED by default, OK via
    # act_from_client. The run grades are kept (delegation actor_present FAIL;
    # act_from_client OK).
    actor_cell = (f"[NOT SUPPORTED]({dl}) — default: no actor_token on the proxy->upstream "
                  f"exchange (actor_present={dg.get('actor_present')}); with "
                  f"[act_from_client]({al}) the login server sets `act` from the gateway's "
                  f"`client_secret_basic` (actor_present={ag.get('actor_present')}, actor at "
                  f"the upstream {a_actors})")
    # two_issuers: results-layer label NOT APPLICABLE; the run keeps INCONCLUSIVE.
    ti_cell = (f"[NOT APPLICABLE: second issuer refused at gateway]({til}) — the run grades "
               f"**{ti.get('grade')}**; ToolHive binds to one configured OIDC issuer, so the "
               f"second issuer is rejected (HTTP 401) before any exchange and the A/B "
               f"conflation cannot be exercised")
    # crossprovider: shown with its run_valid=False reason; run keeps OBSERVATION.
    xp_cell = (f"[{xp.get('label')}]({xpl}) (run grades **{xp.get('grade')}**, "
               f"run_valid={xp.get('run_valid')}) — {xp.get('reason')}. "
               f"{xp.get('why_positive_control_failed')}")

    L = ["## Stacklok ToolHive v0.65.0\n",
         f"Release binary `thv` v{v.get('version')} (commit `{str(v.get('commit'))[:12]}`, "
         "Apache-2.0), sha256-verified against the published checksums; loopback only. Run in "
         "**two modes**: the standalone proxy (`thv run <remote-url>`) and the Virtual MCP server "
         "(`thv vmcp serve`). The caller sends a user JWT; ToolHive validates it (incoming OIDC) "
         "and injects the RFC 8693 exchanged token upstream. See `integration/TOOLHIVE_GATE.md`.\n",
         "_ToolHive's standalone (`thv run`) mode is the fourth column of the CoSAI table above "
         "(NOT RUN where a probe was not run). This section adds the vMCP results and the full "
         "label mappings. Labels are mapped at the results layer; each run keeps the probe's own "
         "grade._\n",
         f"**Dev flags.** `--jwks-allow-private-ip` and `--oidc-insecure-allow-http` are set only "
         "because the login server (local_as) is on `http://127.0.0.1`; they change **only where "
         "keys are fetched from**, not the token-exchange or validation logic being tested "
         f"(recorded in every run, e.g. [delegation]({dl})).\n",
         "| Check (XID-10 / CoSAI) | ToolHive standalone (`thv run`) |",
         "|---|---|",
         f"| Distinct actor and subject | {actor_cell} |",
         f"| Scope narrows, never exceeds subject | {_cell(sc.get('grade'), scl, sc.get('label',''), label=sc.get('label'))} "
         f"(no-scopes variant: [{_OBSERVATION_LABELS.get(ns.get('label'),'')}]({nsl}) — {ns.get('reason')}) |",
         f"| Unregistered issuer refused | {_cell(iu.get('grade'), iul, iu.get('label',''))} — refused at the gateway before any exchange |",
         f"| Two issuers (same user) | {ti_cell} |",
         f"| Cross-provider email | {xp_cell} |",
         f"| Inbound token validated by the gateway (extra observation) | [{iv.get('observation')}]({ivl}) — provx control reached the upstream; provy→401, unregistered-issuer→401 (invalid issuer), wrong-audience→401 (invalid audience) |",
         f"| No token passthrough | [{'OK' if not d.get('user_token_reached_upstream') else 'FAIL'}]({dl}) — the exchanged token is injected upstream; no user token reached the upstream (`user_token_reached_upstream`={d.get('user_token_reached_upstream')}); actor NOT SUPPORTED (see above) |",
         f"| Audience restriction | [{dg.get('audience_correct')}]({dl}) — aud of the upstream token |",
         f"| Own token per user | [{'OK' if dg.get('no_token_reuse')=='OK' and dg.get('no_cross_identity_bleed')=='OK' else 'see run'}]({dl}) — A,B,A: distinct token per user, no cross-user reuse |",
         f"| Exchange failure | {_cell(ef.get('grade'), efl, ef.get('reason',''))} — fails closed |",
         f"| Private results cached across users | [{ca.get('observation')}]({cal}) — {caching.get('new_exchanges_for_two_reads')} exchange(s) for two reads; a fresh exchange per read on this path |",
         "",
         "**Same-user-credentials (CVE-2026-110195 class), both modes.** Two credentials of one "
         "user (same scope); the AS mints a distinct upstream token per exchange so reuse would be "
         "visible.",
         f"- **Standalone (`thv run`):** cold control [{su['cold_control']['grade']}]({sul}), warm "
         f"[{su['warm']['grade']}]({sul}); **cache hit observed = "
         f"{su['observations'].get('cache_hit_observed')}**. {su['warm']['detail']}. The vMCP "
         "token cache does not apply to the standalone proxy; ToolHive exchanged a fresh token per "
         "read, so caching was **not observed** (not claimed).",
         f"- **vMCP (`thv vmcp serve`):** cold control [{vm['cold_control']['grade']}]({vml}), warm "
         f"[{vm['warm']['grade']}]({vml}); **cache hit observed = "
         f"{vm['observations'].get('cache_hit_observed')}**. Observation: on `thv vmcp serve`, each "
         f"request re-exchanged (exchanges per read: {vm['reexchange_evidence']['exchanges_per_read']}, "
         "a distinct upstream token each time), so the source-level token cache "
         "(`pkg/vmcp/cache/cache.go`: `{backend}:{hash(subject_token)}:{audience}`) was **not "
         "exercised in this mode**. This is an observation of this deployment mode, **not a bug**; "
         "the Kubernetes operator deployment, where backend sessions may persist and the cache may "
         "apply, was **not tested**. `subjectProviderName` (exchange a stored upstream token) was "
         "**not run** — it requires ToolHive's embedded authorization server.\n",
         "- ToolHive persists no tokens/secrets on these paths (no secrets provider configured). "
         "No grader was changed; the labels above are results-layer only.\n"]
    return L


def _kuadrant_section():
    d, dl = _sample("kuadrant-delegation.json")
    ef, efl = _sample("kuadrant-exchange_fail.json")
    dg = d.get("check_grades") or {}
    L = [f"## {d.get('gateway_version')}\n",
         f"_{d.get('gateway_label')}._\n",
         "The RFC 8693 token exchange in the Kuadrant MCP Gateway is performed by **Authorino** "
         "via an `AuthPolicy` (the gateway's broker/router does not do it). This gate drives the "
         "existing probes through an Istio Gateway whose `mcps` listener carries the sample "
         "token-exchange policy, **minimally adapted** (`integration/kuadrant/"
         "kuadrant-mcps-auth-policy.yaml`: only the issuer/token-endpoint URLs changed and Vault "
         "removed) — the mcp router/broker was **not** in the path, so this driver sets "
         "`x-mcp-servername` itself, as the router would (client-supplied values of that header "
         "are not graded or reported). Istio 1.27.0, Gateway API v1.4.1, Kuadrant 1.6.0 "
         "(Authorino v0.28.0, mcp-controller v1.0.2), local kind cluster; loopback only; see "
         "`integration/KUADRANT_GATE.md`.\n",
         "| Probe | Result |",
         "|---|---|",
         f"| delegation (A, B, A) | `actor_present` **{dg.get('actor_present')}** — Authorino sends "
         f"no `actor_token`, so this is impersonation; `subject_preserved`/`audience_correct`"
         f"/`scope_narrowed`/`no_token_reuse`/`no_cross_identity_bleed` all **OK** ([run]({dl})), "
         "each gated by an in-run thin-deputy broken fixture |",
         f"| exchange failure (token endpoint HTTP 500 / non-JSON / no `access_token` / slow) | "
         f"[{ef.get('grade')}]({efl}) — {ef.get('reason')}. The user's own token reached the "
         f"upstream in **none** of the modes (`user_token_reached_upstream_any_mode`="
         f"{ef.get('user_token_reached_upstream_any_mode')}): the gateway **fails closed** when a "
         "token that needs exchange cannot be exchanged |",
         "",
         "- **Observation (not graded as a leak): a token already scoped to the server "
         "(`aud` = the server name) is forwarded unchanged, by design.** The exchange runs only "
         "when the inbound `aud` != the target server (`x-mcp-servername`); a token already scoped "
         "to that server skips the exchange and is forwarded as-is. This is documented — "
         "kagenti/mcp-gateway v1.0.2 `docs/design/security-architecture.md`: \"The client's "
         "Authorization header is always forwarded to upstream servers ... token exchange "
         "(RFC 8693) ... as a best practice ... replacing the client's token with one of reduced "
         "scope and specific audience\"; and its threat-model table lists \"Client OAuth tokens "
         "forwarded to backends without token exchange — By design — all headers forwarded.\" The "
         "forwarded token is the holder's own, already scoped to that server, so no access is "
         "gained; see `notes/kuadrant-aud-passthrough.md`.",
         f"- The driver set `x-mcp-servername` = `{d.get('driver_set_x_mcp_servername')}` as the "
         "mcp router would; client-supplied values of that header are not graded or reported.\n"]
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
             "Reproduce via `integration/CONTEXTFORGE_GATE.md`, "
             "`integration/AGENTGATEWAY_GATE.md` and `integration/LITELLM_GATE.md`.\n")

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

    cve_bad = _samecred_run("1.0.11")
    cve_fixed = _samecred_run("1.1.1")
    if cve_bad and cve_fixed:
        L.append("## Validation against CVE-2026-110195\n")
        L.append("[CVE-2026-110195](https://www.cve.org/CVERecord?id=CVE-2026-110195) "
                 "(IBM ContextForge MCP Gateway; [advisory]"
                 "(https://www.ibm.com/support/pages/node/7296695); affected "
                 "1.0.0–1.0.11, fixed in **1.1.0**; reported by Nick Simpson): the RFC "
                 "8693 token-exchange cache keyed only on (gateway, user, audience) and "
                 "omitted the inbound credential, so the upstream token minted for one "
                 "credential of a user was served to another credential of the same "
                 "user. The [`same-user-credentials` probe](../strangertest/credcache.py) "
                 "**reproduces the cache-key collision described in the CVE** — it is "
                 "**not a new discovery**. One user, two credentials (a session JWT and "
                 "an api-token JWT); a fresh token-exchange gateway per cold run; a "
                 "recording upstream ties each federated call to the credential that "
                 "caused it. A cold-cache control (each credential must mint its own "
                 "distinct upstream token) gates the warm test. Loopback only; tokens "
                 "redacted to `sha256:` fingerprints.\n")
        L.append("| Version | cold control | warm: credential 2's upstream token | verdict |")
        L.append("|---|---|---|---|")
        L.append(f"| **1.0.11** | {cve_bad['cold_control']['grade']} | "
                 f"**credential 1's token (reused)** | {_verdict(cve_bad['vulnerable'])} |")
        L.append(f"| **1.1.1** | {cve_fixed['cold_control']['grade']} | "
                 f"its own distinct token | {_verdict(cve_fixed['vulnerable'])} |")
        L.append("")
        L.append("- **1.0.11:** credential 2's federated call reached the upstream "
                 "carrying the token minted for credential 1 (identical fingerprint): "
                 "the gateway **reused a cached upstream token across two credentials of "
                 "the same user.**")
        cve_110 = _samecred_run("1.1.0")
        first_fixed = "" if not cve_110 else (
            f" **1.1.0** (the first fixed release) behaves like 1.1.1 here "
            f"({_verdict(cve_110['vulnerable'])}).")
        L.append("- **1.1.1:** credential 2's call triggered its own fresh exchange and "
                 "carried its own distinct token; a cache hit on the same-credential "
                 "repeat confirms the gateway still caches, so it now caches **per "
                 "credential** and the collision is gone." + first_fixed)
        L.append("- **Scope and privilege.** In every run both credentials carried the "
                 "**same scope**, and the ContextForge caller was an **admin**, so the "
                 "reproduction shows **token reuse** (credential 2 received credential "
                 "1's exact upstream token), not a privilege escalation to a scope "
                 "credential 2 lacked. The probe also flags scope escalation — a "
                 "distinct token carrying a scope only credential 1 holds — but that "
                 "path is exercised by the practice fixtures, not these live runs.")
        L.append("- **Root cause (source):** `services/token_exchange_cache.py` keyed "
                 "on `(gateway_id, user_email, audience)`; the fix adds the inbound "
                 "`subject_token` to the key (and bumps the namespace to `v2`). "
                 "Confirmed from both the version diff and the live runs above.")
        agw_cve = _run_files("agentgateway-1.7.0-samecred-cache*.json")
        agw_cve = _load(agw_cve[-1]) if agw_cve else None
        if agw_cve:
            L.append(f"- **agentgateway 1.7.0 — not this class ({_verdict(agw_cve['vulnerable'])}).** "
                     "The same probe (release binary, sha256-verified; cold cache = "
                     "process restart) shows credential 2 triggering its own fresh "
                     "exchange and carrying its own distinct token: agentgateway "
                     "re-exchanges per credential rather than reusing a cached "
                     "per-user token.")
        else:
            L.append("- **agentgateway 1.7.0 — not run.**")
        L.append("- **LiteLLM 1.109.1 — expected OK from its cache key, not run.** "
                 "LiteLLM caches exchanged tokens keyed on the **subject token** "
                 "(plus tenant and exchange config, per `LITELLM_GATE.md`), so two "
                 "credentials of one user already get distinct entries; the probe was "
                 "not run against it here.")
        L.append("- Reproduce: `integration/CONTEXTFORGE_SAMECRED_GATE.md` "
                 "(`integration/xid10_cf_samecred_cache.py`) for ContextForge, "
                 "`integration/xid10_agw_samecred_cache.py` for agentgateway. Tokens "
                 "redacted to `sha256:` fingerprints in the saved runs.\n")

    cve598 = {"1.84.0": _cve59822_run("1_84_0"), "1.109.1": _cve59822_run("1_109_1")}
    if all(cve598.values()):
        adv = cve598["1.84.0"]["advisory"]
        pr = cve598["1.84.0"]["fix_pr"]
        L.append("## Validation against CVE-2026-59822\n")
        L.append(f"[CVE-2026-59822]({adv}) (LiteLLM: MCP authentication bypass via the OAuth2 "
                 "passthrough fallback; CVSS v4.0 8.8; affected **< 1.84.0**, fixed in "
                 f"**1.84.0**, [PR #26463]({pr})): before the fix, an MCP request whose "
                 "`Authorization` bearer failed LiteLLM key validation fell back to an "
                 "anonymous session for **any** MCP server; the fix re-raises the auth error "
                 "unless **every** target server is operator-configured `auth_type=oauth2`. "
                 "This is a **regression check on the FIXED versions only** — no affected "
                 "(< 1.84.0) version is installed or run, and no bypass step is recorded. "
                 "Against a non-oauth2 server (`auth_type: none`) the existing "
                 "[inbound-validation probe](xid10_litellm_gate.py) (`http_status`, unchanged) "
                 "sends MCP `initialize` with four bearers; a session established = HTTP 200 "
                 "with an `initialize` result. An in-run **fail-open deputy** (grants a session "
                 "to any/no bearer) is checked the same way and must be caught. Loopback only; "
                 "the master key and the forged JWT are stored as `sha256:` fingerprints.\n")
        L.append("| Fixed version | no bearer | garbage bearer | forged bearer (untrusted key) "
                 "| valid bearer | verdict |")
        L.append("|---|---|---|---|---|---|")

        def _cell(case):
            est = case["session_established"]
            return f"{case['status']} ({'session' if est else 'no session'})"

        for ver in ("1.84.0", "1.109.1"):
            d = cve598[ver]
            c = d["cases"]
            r = d["result"]
            verdict = ("rejects invalid; admits valid" if r["status"] == "PASS"
                       else f"**{r['status']}**")
            L.append(f"| **{ver}** | {_cell(c['no_bearer'])} | {_cell(c['garbage_bearer'])} | "
                     f"{_cell(c['forged_bearer'])} | {_cell(c['valid_bearer'])} | {verdict} |")
        L.append("")
        caught = all(cve598[v]["broken_fixture_in_run"]["caught"] for v in cve598)
        L.append("- On both fixed versions the **no / garbage / forged** bearer established no "
                 "session (the upstream was never reached) and only the **valid** LiteLLM key "
                 "did; the status code differs by version (1.84.0 surfaces the re-raised auth "
                 "error as 500, 1.109.1 as 401/400) but the admission outcome is identical.")
        L.append(f"- The in-run fail-open deputy was caught by the same check on both versions "
                 f"(`caught={caught}`), so each OK rests on a check shown able to fail, not on "
                 "reading source.")
        L.append("- **validated against the fix for CVE-2026-59822 (fixed versions 1.84.0, "
                 f"1.109.1; invalid/forged tokens rejected)** — advisory {adv}.")
        L.append("- Reproduce: `integration/LITELLM_CVE59822_GATE.md` "
                 "(`integration/xid10_litellm_cve59822_gate.py`), FIXED versions only. Tokens "
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

    L.extend(_litellm_section())

    L.extend(_toolhive_section())

    L.extend(_kuadrant_section())

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
    L.append("- The LiteLLM result covers **1.109.1 only**, the open-source build (no JWT "
             "auth, no database), MCP 2025-11-25 (its default), one config per scenario. "
             "Its actor result depends on the login server: LiteLLM sends no actor_token.")
    L.append("- Whether issuer validation happens at the gateway or at the login server "
             "is a deployment choice; on LiteLLM's open-source build it happens only at "
             "the login server.")
    L.append("- The `act_from_client` login-server mode (an actor taken from the gateway's "
             "client authentication) is a feature of the bundled test login server; whether "
             "a production IdP does this is outside these runs.")
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
