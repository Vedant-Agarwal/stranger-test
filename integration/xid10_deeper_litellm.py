"""Deeper XID-10 scenario against LiteLLM 1.109.1 (config file only).

DEEPER_MODE:
  concurrent    many interleaved A and B calls at once (strangertest.concurrency)
  login_faults  the login server misbehaves (strangertest.login_faults); LiteLLM's
                token endpoint is pointed at the faulty endpoint (FAULT_PORT)

Env (ports 4600-4699, never 4000/4444/8790): AS_BASE, LL_PORT, UPSTREAM_PORT,
FIXTURE_BASE (the in-run fixtures use FIXTURE_BASE..+2), FAULT_PORT
(login_faults), LL_BIN (the venv's ``litellm``). Optional: CONC_PAIRS (50),
UPSTREAM_HOLD (0.05), SLOW_SECONDS (45), FAULT_MODES. LiteLLM runs on
its default settings with the token-exchange config; a throwaway master key is
generated per run. Tokens and keys are stored as sha256 fingerprints only.
"""

from __future__ import annotations

import os
import secrets
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import deeper_common as dc  # noqa: E402

AS_BASE = dc.url_port("AS_BASE")
LL_PORT = dc.env_port("LL_PORT")
UP_PORT = dc.env_port("UPSTREAM_PORT")
FX = dc.env_port("FIXTURE_BASE")
dc.port_46xx(FX + 2, "FIXTURE_BASE+2")

import xid10_litellm_gate as g  # noqa: E402
from login_faults_harness import (FallThroughDeputy, FaultyTokenEndpoint,  # noqa: E402
                                  run_fault_modes)
from strangertest.concurrency import make_markers, run_concurrent_probe  # noqa: E402
from strangertest.practice_concurrency_http import run_concurrency_fixture  # noqa: E402
from strangertest.probe import Identity  # noqa: E402


def main():
    mode = os.environ.get("DEEPER_MODE")
    if mode not in ("concurrent", "login_faults"):
        raise SystemExit("DEEPER_MODE must be concurrent or login_faults")
    ll_bin = os.environ.get("LL_BIN") or sys.exit("ERROR: set LL_BIN")
    versions = g.litellm_versions(ll_bin)
    if versions["litellm"] != g.PINNED_VERSION:
        raise SystemExit(f"ERROR: LiteLLM {versions['litellm']} installed; pinned "
                         f"{g.PINNED_VERSION}")
    if mode == "login_faults":
        return mode_login_faults(ll_bin, versions)
    pairs = int(os.environ.get("CONC_PAIRS", "50"))
    fixture = run_concurrency_fixture(pairs, deputy_ports=(FX, FX + 1), upstream_port=FX + 2,
                                      redact=dc.redact)
    print(f"fixture: racy concurrent={fixture['concurrent_grade']} serial_vulnerable="
          f"{fixture['serial_vulnerable']} safe_not_fail={fixture['safe_concurrent_not_fail']}")
    up = g.Recorder(UP_PORT, g._get(f"{AS_BASE}/jwks")).start()
    secret = secrets.token_hex(16)
    gw = g.LiteLLM(ll_bin, g.CONFIGS["delegation"], LL_PORT, {
        "UPSTREAM_URL": f"http://127.0.0.1:{UP_PORT}/mcp", "TOKEN_ENDPOINT": f"{AS_BASE}/token",
        "CLIENT_SECRET": secret})
    try:
        gw.start()
        print(f"LiteLLM up @ {gw.url}")
        markers = make_markers()
        up.notes = {f"{g.AS_ISSUER}|alice": markers["A"], f"{g.AS_ISSUER}|bob": markers["B"]}
        up.hold_seconds = float(os.environ.get("UPSTREAM_HOLD", "0.05"))
        ta, tb = g.as_issue(AS_BASE, "alice"), g.as_issue(AS_BASE, "bob")
        tool, client_ver = g.discover_tool(gw, ta)
        res = run_concurrent_probe(
            gw.url,
            Identity(label="A", connect=lambda: g.MCPClient(g.HTTPTransport(
                gw.url, headers=gw.headers(ta), timeout=180))),
            Identity(label="B", connect=lambda: g.MCPClient(g.HTTPTransport(
                gw.url, headers=gw.headers(tb), timeout=180))),
            upstream=up, trigger=lambda c, n: c.call_tool(tool, {"nonce": n}), markers=markers,
            identities={"A": (g.AS_ISSUER, "alice"), "B": (g.AS_ISSUER, "bob")}, pairs=pairs,
            fixture=fixture, settle_seconds=2, redact=dc.redact, authorized=True,
            authorization_note="local LiteLLM started by this driver")
        print(res.summary())
        d = res.to_dict()
        tokens = {}
        for c in d["upstream_calls"]:
            tokens.setdefault(c["subject"], set()).add(c["token"])
        dc.save_run("litellm", "concurrent", {
            "gateway": "litellm", "gateway_label": "an LLM gateway with MCP features",
            "gateway_version": versions["litellm"], "gateway_versions": versions,
            "deeper_mode": "concurrent", **gw.record(),
            "setup": "LiteLLM defaults (single process, no database), token-exchange config",
            "endpoints": {"as_base": AS_BASE, "litellm": LL_PORT, "upstream": UP_PORT,
                          "fixture_ports": [FX, FX + 2]},
            "login_server": g.login_facts(AS_BASE), "client_negotiated_version": client_ver,
            **d, "upstream_hold_seconds": up.hold_seconds,
            "distinct_upstream_tokens_per_subject": {k: len(v) for k, v in tokens.items()},
            "markers": {k: v[:8] + "..." for k, v in markers.items()},
            "broken_fixture": {"name": "racy practice deputy (per-user state in one shared slot)",
                               **fixture}})
    except Exception:
        print("--- LiteLLM log tail (redacted) ---\n" + gw.tail())
        raise
    finally:
        gw.stop()
        up.stop()


def mode_login_faults(ll_bin, versions):
    modes = dc.fault_modes_from_env()
    fault_port = dc.env_port("FAULT_PORT")
    ep = FaultyTokenEndpoint(fault_port, AS_BASE,
                             slow_seconds=float(os.environ.get("SLOW_SECONDS", "45"))).start()
    up = g.Recorder(UP_PORT, g._get(f"{AS_BASE}/jwks")).start()
    gw = g.LiteLLM(ll_bin, g.CONFIGS["delegation"], LL_PORT, {
        "UPSTREAM_URL": f"http://127.0.0.1:{UP_PORT}/mcp", "TOKEN_ENDPOINT": ep.url,
        "CLIENT_SECRET": secrets.token_hex(16)})
    fx = None
    try:
        gw.start()
        print(f"LiteLLM up @ {gw.url}")
        tool, client_ver = g.discover_tool(gw, g.as_issue(AS_BASE, "lf-discover"))

        def user(name):
            return {"token": g.as_issue(AS_BASE, name), "subject": name, "issuer": g.AS_ISSUER}
        users = {f"{k}-{m}": user(f"lf-{k}-{m}") for m in modes for k in ("ctl", "p")}
        fusers = {k: user(f"fx-{k}") for k in users}
        fx = FallThroughDeputy(FX, ep.url, f"http://127.0.0.1:{UP_PORT}/mcp").start()
        out = run_fault_modes(
            modes=modes, endpoint=ep, upstream=up, as_base=AS_BASE, users=users,
            call=lambda t, n, to: dc.mcp_call(lambda tt: g.MCPClient(g.HTTPTransport(
                gw.url, headers=gw.headers(t), timeout=tt)), tool, n, to),
            fixture_call=lambda t, n, to: dc.mcp_call(lambda tt: g.MCPClient(g.HTTPTransport(
                fx.url, headers={"Authorization": f"Bearer {t}"}, timeout=tt)),
                "read_note", n, to),
            fixture_users=fusers, caller_timeout=200, redact=dc.redact)
        dc.save_run("litellm", "login_faults", {
            "gateway": "litellm", "gateway_label": "an LLM gateway with MCP features",
            "gateway_version": versions["litellm"], "gateway_versions": versions,
            "deeper_mode": "login_faults", "probe": "login_faults", **gw.record(),
            "setup": "LiteLLM defaults (single process, no database), token-exchange config "
                     "with its token endpoint pointed at the faulty endpoint",
            "endpoints": {"as_base": AS_BASE, "litellm": LL_PORT, "upstream": UP_PORT,
                          "fault_port": fault_port, "fixture_port": FX},
            "login_server": g.login_facts(AS_BASE), "client_negotiated_version": client_ver,
            **out, "users": "fresh user per control and per probe, per mode (no cached exchange)"})
    except Exception:
        print("--- LiteLLM log tail (redacted) ---\n" + gw.tail())
        raise
    finally:
        if fx:
            fx.stop()
        gw.stop()
        up.stop()
        ep.stop()


if __name__ == "__main__":
    main()
