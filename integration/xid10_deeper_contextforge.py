"""Deeper XID-10 scenarios against ContextForge 1.1.1 (admin API + config only).

DEEPER_MODE:
  login_faults   the login server misbehaves (strangertest.login_faults)
  concurrent     many interleaved A and B calls at once (strangertest.concurrency)

Run with the ContextForge venv and the ContextForge .env loaded (the admin
token is minted locally, as in xid10_contextforge_gate.py). Env (ports 4600-4699,
never 4000/4444/8790): AS_BASE, CF_URL, UPSTREAM_PORT, FAULT_PORT, FIXTURE_PORT
(fixtures use FIXTURE_PORT..+3). Optional: CONC_PAIRS (50), SLOW_SECONDS (45),
FAULT_MODES. Users are external SSO users of the local AS, provisioned through
their own first sign-in and granted a team-scoped developer role (not admin).
Tokens are stored as sha256 fingerprints only.
"""

from __future__ import annotations

import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import deeper_common as dc  # noqa: E402

AS_BASE = dc.url_port("AS_BASE")
dc.url_port("CF_URL")
dc.env_port("UPSTREAM_PORT")
FAULT_PORT = dc.env_port("FAULT_PORT")
FIXTURE_PORT = dc.env_port("FIXTURE_PORT")
dc.port_46xx(FIXTURE_PORT + 3, "FIXTURE_PORT+3")

import xid10_contextforge_gate as g  # noqa: E402
from login_faults_harness import (FallThroughDeputy, FaultyTokenEndpoint,  # noqa: E402
                                  run_fault_modes)
from strangertest.concurrency import make_markers, run_concurrent_probe  # noqa: E402
from strangertest.mcp_client import MCPClient  # noqa: E402
from strangertest.practice_concurrency_http import run_concurrency_fixture  # noqa: E402
from strangertest.probe import Identity  # noqa: E402
from strangertest.transports import HTTPTransport  # noqa: E402


def issue(sub):
    return g.as_issue_k(sub, email=f"{sub}@local-as.test")


def client(url, tok, timeout=30):
    return MCPClient(HTTPTransport(url, headers={"Authorization": f"Bearer {tok}"},
                                   timeout=timeout))


def prepare_users(vs_url, subs):
    toks = {s: issue(s) for s in subs}
    for s, t in toks.items():
        g.provision(vs_url, t, s)
    new = g.ensure_tool_access([f"{s}@local-as.test" for s in subs])
    if new:
        g.wait_role_cache()
    return toks


def base_record(mode, oc):
    _, ver = g.cf("GET", "/version", g.cf_admin_token())
    return {"gateway": "ContextForge",
            "gateway_version": (ver or {}).get("app", {}).get("version"),
            "deeper_mode": mode,
            "gateway_config": {"oauth_config": {k: v for k, v in oc.items()
                                                if k not in ("client_secret", "discovery")},
                               "oauth_config_sha256": g.hashlib_sha(oc)},
            "endpoints": {"as_base": AS_BASE, "cf_url": g.CF, "upstream_port": g.UPSTREAM_PORT,
                          "fault_port": FAULT_PORT,
                          "fixture_ports": [FIXTURE_PORT, FIXTURE_PORT + 3]},
            "env": {k: os.environ.get(k) for k in ("SSO_ENABLED", "SSO_API_TOKEN_AUTH_ENABLED",
                                                   "SSRF_ALLOW_LOCALHOST",
                                                   "MCP_CLIENT_CONNECT_MODE", "RATE_LIMIT_MEDIUM_RPM",
                                                   "RATE_LIMIT_MEDIUM_BURST")},
            "login_server": g.as_facts(),
            "authorization_note": "external users granted tools.execute via a team-scoped "
                                  "developer role (not admin)"}


def mode_login_faults(up, tok):
    modes = dc.fault_modes_from_env()
    ep = FaultyTokenEndpoint(FAULT_PORT, AS_BASE,
                             slow_seconds=float(os.environ.get("SLOW_SECONDS", "45"))).start()
    fx = None
    try:
        vs_url, tool, oc = g.setup_cf_gateway(up, tok, ["read:notes"], token_url=ep.url)
        subs = [f"lf-{k}-{m}" for m in modes for k in ("ctl", "p")]
        toks = prepare_users(vs_url, subs)
        users = {s[3:]: {"token": toks[s], "subject": s, "issuer": g.AS_ISSUER} for s in subs}
        fusers = {k: {"token": issue(f"fx-{k}"), "subject": f"fx-{k}", "issuer": g.AS_ISSUER}
                  for k in users}
        fx = FallThroughDeputy(FIXTURE_PORT, ep.url, up.url).start()
        out = run_fault_modes(
            modes=modes, endpoint=ep, upstream=up, as_base=AS_BASE, users=users,
            call=lambda t, n, to: dc.mcp_call(lambda tt: client(vs_url, t, tt), tool, n, to),
            fixture_call=lambda t, n, to: dc.mcp_call(lambda tt: client(fx.url, t, tt),
                                                      "read_note", n, to),
            fixture_users=fusers, caller_timeout=200, redact=dc.redact)
        dc.save_run("contextforge", "login_faults", {
            **base_record("login_faults", oc), "probe": "login_faults", **out,
            "gateway_token_endpoint_timeout": "30 s per request, up to 3 attempts "
                                              "(mcpgateway/services/oauth_manager.py "
                                              "request_timeout=30, max_retries=3)",
            "users": "fresh user per control and per probe, per mode (no cached exchange)",
            "virtual_server": vs_url})
    finally:
        if fx:
            fx.stop()
        ep.stop()


def mode_concurrent(up, tok):
    pairs = int(os.environ.get("CONC_PAIRS", "50"))
    fixture = run_concurrency_fixture(pairs, deputy_ports=(FIXTURE_PORT + 1, FIXTURE_PORT + 2),
                                      upstream_port=FIXTURE_PORT + 3, redact=dc.redact)
    print(f"fixture: racy concurrent={fixture['concurrent_grade']} serial_vulnerable="
          f"{fixture['serial_vulnerable']} safe_not_fail={fixture['safe_concurrent_not_fail']}")
    vs_url, tool, oc = g.setup_cf_gateway(up, tok, ["read:notes"])
    toks = prepare_users(vs_url, ["alice", "bob"])
    markers = make_markers()
    up.notes = {(g.AS_ISSUER, "alice"): markers["A"], (g.AS_ISSUER, "bob"): markers["B"]}
    up.hold_seconds = float(os.environ.get("UPSTREAM_HOLD", "0.05"))
    res = run_concurrent_probe(
        vs_url,
        Identity(label="A", connect=lambda: client(vs_url, toks["alice"], 180)),
        Identity(label="B", connect=lambda: client(vs_url, toks["bob"], 180)),
        upstream=up, trigger=lambda c, n: c.call_tool(tool, {"nonce": n}), markers=markers,
        identities={"A": (g.AS_ISSUER, "alice"), "B": (g.AS_ISSUER, "bob")}, pairs=pairs,
        fixture=fixture, settle_seconds=2, redact=dc.redact, authorized=True,
        authorization_note="local ContextForge started for this test")
    print(res.summary())
    d = res.to_dict()
    tokens = {}
    for c in d["upstream_calls"]:
        tokens.setdefault(c["subject"], set()).add(c["token"])
    dc.save_run("contextforge", "concurrent", {
        **base_record("concurrent", oc), **d, "upstream_hold_seconds": up.hold_seconds,
        "distinct_upstream_tokens_per_subject": {k: len(v) for k, v in tokens.items()},
        "markers": {k: v[:8] + "..." for k, v in markers.items()},
        "broken_fixture": {"name": "racy practice deputy (per-user state in one shared slot)",
                           **fixture}, "virtual_server": vs_url})


def main():
    mode = os.environ.get("DEEPER_MODE", "")
    if mode not in dc.DEEPER_MODES:
        raise SystemExit(f"DEEPER_MODE must be one of {dc.DEEPER_MODES}")
    g.upsert_provider("local-as", g.AS_ISSUER, AS_BASE, "/jwks")
    up = g.Upstream(g.UPSTREAM_AUD, _jwks(),
                    g.AS_ISSUER).start()
    print(f"=== ContextForge DEEPER_MODE {mode}  upstream {up.url} ===")
    try:
        tok = g.cf_admin_token()
        if mode == "login_faults":
            mode_login_faults(up, tok)
        else:
            mode_concurrent(up, tok)
    finally:
        up.stop()


def _jwks():
    import json
    import urllib.request
    with urllib.request.urlopen(f"{AS_BASE}/jwks", timeout=10) as r:
        return json.loads(r.read())


if __name__ == "__main__":
    t0 = time.time()
    main()
    print(f"done in {time.time() - t0:.0f}s")
