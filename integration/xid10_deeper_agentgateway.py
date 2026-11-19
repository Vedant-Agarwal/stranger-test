"""Deeper XID-10 scenarios against agentgateway 1.7.0 (config file only).

DEEPER_MODE:
  login_faults        the login server misbehaves (strangertest.login_faults)
  concurrent          many interleaved A and B calls at once (strangertest.concurrency)
  actor_lies          the caller supplies a lying actor token (observation only)
  actor_lies_may_act  the same, with agentgateway's opt-in actorToken.enforceMayAct

Env (all ports 4600-4699, never 4000/4444/8790): AS_BASE, AGW_URL, AGW_ADMIN_PORT,
UPSTREAM_PORT, FAULT_PORT (faulty token endpoint), FIXTURE_PORT (fixtures use
FIXTURE_PORT..+3), AGW_BIN. Optional: CONC_PAIRS (50), SLOW_SECONDS (45),
FAULT_MODES (comma list). The AS must be started with
``--client agent-client:<s> --client other-agent:<s>`` for actor_lies.
Tokens are stored as sha256 fingerprints only.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.request
from urllib.parse import urlencode

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import deeper_common as dc  # noqa: E402

AS_BASE = dc.url_port("AS_BASE")
AGW_URL_CHECK = dc.url_port("AGW_URL")
for _n in ("AGW_ADMIN_PORT", "UPSTREAM_PORT", "FAULT_PORT", "FIXTURE_PORT"):
    dc.env_port(_n)
FAULT_PORT = dc.env_port("FAULT_PORT")
FIXTURE_PORT = dc.env_port("FIXTURE_PORT")
dc.port_46xx(FIXTURE_PORT + 3, "FIXTURE_PORT+3")
os.environ["TOKEN_ENDPOINT_HOST"] = f"127.0.0.1:{FAULT_PORT}"

import xid10_agentgateway_gate as g  # noqa: E402
from login_faults_harness import (FallThroughDeputy, FaultyTokenEndpoint,  # noqa: E402
                                  run_fault_modes)
from strangertest.concurrency import make_markers, run_concurrent_probe  # noqa: E402
from strangertest.delegate import make_nonce  # noqa: E402
from strangertest.mcp_client import MCPClient  # noqa: E402
from strangertest.practice_concurrency_http import run_concurrency_fixture  # noqa: E402
from strangertest.probe import Identity  # noqa: E402
from strangertest.transports import HTTPTransport  # noqa: E402

AGW_DOCS = {
    "source_v1.7.0_actor_spec": "crates/agentgateway/src/http/auth/oauth/mod.rs (ActorTokenSpec, "
                                "actor_token_from_request, may_act_authorizes, "
                                "decode_unverified_jwt_claims)",
    "crd_v1.7.0": "controller/install/helm/agentgateway-crds/templates/"
                  "agentgateway.dev_agentgatewaypolicies.yaml (actorToken, mayAct)",
}
OTHER_AUD = "https://other-service.test"


def issue(sub, *, may_act=None, aud=g.API_AUD):
    q = {"sub": sub, "aud": aud, "scope": "read:notes"}
    if may_act:
        q["may_act"] = json.dumps(may_act)
    with urllib.request.urlopen(f"{AS_BASE}/issue?{urlencode(q)}", timeout=10) as r:
        return json.loads(r.read())["access_token"]


def issue_actor(client_id, *, ttl=None, aud=None):
    q = {"client_id": client_id}
    if ttl is not None:
        q["ttl"] = str(ttl)
    if aud is not None:
        q["aud"] = aud
    with urllib.request.urlopen(f"{AS_BASE}/issue-client?{urlencode(q)}", timeout=10) as r:
        return json.loads(r.read())["access_token"]


def client(user_tok, actor_tok, timeout=30):
    return MCPClient(HTTPTransport(g.AGW_URL, headers={
        "Authorization": f"Bearer {user_tok}", "x-actor-token": actor_tok},
        modern=True, timeout=timeout))


def discover(user_tok, actor_tok):
    c = client(user_tok, actor_tok)
    try:
        c.initialize()
        tools = c.list_tools()
    finally:
        c.close()
    if not tools:
        raise SystemExit("no tools discovered through agentgateway")
    return tools[0]["name"]


def exchanges():
    return g._get(f"{AS_BASE}/exchanges")


def base_record(config_path, gw, version, mode):
    with open(config_path) as f:
        text = f.read()
    return {"gateway": "agentgateway", "gateway_version": version.get("version"),
            "gateway_version_full": version, "deeper_mode": mode,
            "gateway_config_path": os.path.relpath(config_path, g._REPO),
            "gateway_config_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "gateway_run_config": gw.run_config_text,
            "endpoints": {"as_base": AS_BASE, "agw_url": g.AGW_URL,
                          "agw_admin_port": g.AGW_ADMIN_PORT, "upstream_port": g.UPSTREAM_PORT,
                          "fault_port": FAULT_PORT, "fixture_ports": [FIXTURE_PORT, FIXTURE_PORT + 3]},
            "login_server": g.login_server_facts()}


# ---------------------------------------------------------------- scenario 1
def mode_login_faults(up, gw, base):
    modes = dc.fault_modes_from_env()
    actor = g.as_actor_token()
    tool = discover(issue("lf-discover"), actor)
    users = {f"{k}-{m}": None for m in modes for k in ("ctl", "p")}
    for k in users:
        users[k] = {"token": issue(f"lf-{k}"), "subject": f"lf-{k}", "issuer": g.AS_ISSUER}
    fusers = {k: {"token": issue(f"fx-{k}"), "subject": f"fx-{k}", "issuer": g.AS_ISSUER}
              for k in users}
    fx = FallThroughDeputy(FIXTURE_PORT, EP.url, f"http://127.0.0.1:{g.UPSTREAM_PORT}/mcp").start()
    try:
        out = run_fault_modes(
            modes=modes, endpoint=EP, upstream=up, as_base=AS_BASE, users=users,
            call=lambda tok, n, t: dc.mcp_call(lambda to: client(tok, actor, to), tool, n, t),
            fixture_call=lambda tok, n, t: dc.mcp_call(
                lambda to: MCPClient(HTTPTransport(fx.url, headers={
                    "Authorization": f"Bearer {tok}"}, timeout=to)), "read_note", n, t),
            fixture_users=fusers, caller_timeout=120, redact=dc.redact)
    finally:
        fx.stop()
    dc.save_run("agentgateway", "login_faults", {
        **base, "probe": "login_faults", **out,
        "gateway_token_endpoint_timeout": "10 s default (crates/agentgateway/src/http/auth/oauth/"
                                          "transport.rs DEFAULT_TOKEN_ENDPOINT_TIMEOUT)",
        "users": "fresh user per control and per probe, per mode (no cached exchange)"})


# ---------------------------------------------------------------- scenario 2
def mode_concurrent(up, gw, base):
    pairs = int(os.environ.get("CONC_PAIRS", "50"))
    fixture = run_concurrency_fixture(pairs, deputy_ports=(FIXTURE_PORT + 1, FIXTURE_PORT + 2),
                                      upstream_port=FIXTURE_PORT + 3, redact=dc.redact)
    print(f"fixture: racy concurrent={fixture['concurrent_grade']} serial_vulnerable="
          f"{fixture['serial_vulnerable']} safe_not_fail={fixture['safe_concurrent_not_fail']}")
    markers = make_markers()
    up.notes = {(g.AS_ISSUER, "alice"): markers["A"], (g.AS_ISSUER, "bob"): markers["B"]}
    up.hold_seconds = float(os.environ.get("UPSTREAM_HOLD", "0.05"))
    actor = g.as_actor_token()
    ta, tb = issue("alice"), issue("bob")
    tool = discover(ta, actor)
    res = run_concurrent_probe(
        g.AGW_URL,
        Identity(label="A", connect=lambda: client(ta, actor, 120)),
        Identity(label="B", connect=lambda: client(tb, actor, 120)),
        upstream=up, trigger=lambda c, n: c.call_tool(tool, {"nonce": n}), markers=markers,
        identities={"A": (g.AS_ISSUER, "alice"), "B": (g.AS_ISSUER, "bob")}, pairs=pairs,
        fixture=fixture, settle_seconds=2, redact=dc.redact, authorized=True,
        authorization_note="local agentgateway started by this driver")
    print(res.summary())
    d = res.to_dict()
    tokens = {}
    for c in d["upstream_calls"]:
        tokens.setdefault(c["subject"], set()).add(c["token"])
    dc.save_run("agentgateway", "concurrent", {
        **base, **d, "upstream_hold_seconds": up.hold_seconds,
        "distinct_upstream_tokens_per_subject": {k: len(v) for k, v in tokens.items()},
        "markers": {k: v[:8] + "..." for k, v in markers.items()},
        "broken_fixture": {"name": "racy practice deputy (per-user state in one shared slot)",
                           **fixture}})


# ---------------------------------------------------------------- scenario 3
CASES = (
    ("control", dict(client_id=g.ACTOR_CLIENT_ID, aud=g.AS_ISSUER),
     "a valid actor token for the calling agent (agent-client), audience = the login server"),
    ("other_client", dict(client_id="other-agent", aud=g.AS_ISSUER),
     "a valid actor token for a DIFFERENT registered client (other-agent)"),
    ("expired", dict(client_id=g.ACTOR_CLIENT_ID, aud=g.AS_ISSUER, ttl=-120),
     "the calling agent's actor token, expired 120 s ago"),
    ("other_audience", dict(client_id=g.ACTOR_CLIENT_ID, aud=OTHER_AUD),
     f"the calling agent's actor token with audience {OTHER_AUD}"),
)


def classify_actor_case(*, reached, upstream_actor, expected_actor, exchange_rec,
                        caller_ok):
    """Observation label for one lying-caller case (never a grade)."""
    if reached:
        if upstream_actor == expected_actor:
            return "forwarded_to_upstream"
        return "reached_with_other_actor"
    if exchange_rec is None:
        return "refused_by_gateway" if not caller_ok else "inconclusive"
    if str(exchange_rec.get("outcome", "")).startswith("refused"):
        return "refused_by_login_server"
    return "inconclusive"


def mode_actor_lies(up, gw, base, may_act):
    facts = base["login_server"]
    missing = {"agent-client", "other-agent"} - set(facts.get("clients") or [])
    if missing:
        raise SystemExit(f"actor_lies needs the AS started with --client for {sorted(missing)}")
    claim = {"sub": g.ACTOR_CLIENT_ID} if may_act else None
    tool = discover(issue("al-discover", may_act=claim), issue_actor(g.ACTOR_CLIENT_ID,
                                                                     aud=g.AS_ISSUER))
    results = {}
    for name, spec, what in CASES:
        user = f"al-{name}{'-ma' if may_act else ''}"
        utok = issue(user, may_act=claim)
        atok = issue_actor(spec["client_id"], ttl=spec.get("ttl"), aud=spec.get("aud"))
        nonce = make_nonce(name)
        n_ex = len(exchanges())
        n_up = len(up.calls)
        out = dc.mcp_call(lambda to: client(utok, atok, to), tool, nonce, 30)
        time.sleep(1.5)
        mine = [r for r in exchanges()[n_ex:] if r.get("actor_fp") == dc.fp(atok)]
        rec = mine[-1] if mine else None
        calls = [c for c in up.calls[n_up:] if c.nonce == nonce
                 and c.method in ("tools/call", "resources/read")]
        up_actor = calls[0].actor if calls else None
        label = classify_actor_case(reached=bool(calls), upstream_actor=up_actor,
                                    expected_actor=spec["client_id"], exchange_rec=rec,
                                    caller_ok=out["succeeded"])
        results[name] = {
            "what_was_sent": what,
            "sent": {"user": user, "user_token": dc.fp(utok), "subject_may_act": claim,
                     "actor_token": dc.fp(atok), "actor_client_id": spec["client_id"],
                     "actor_audience": spec.get("aud"),
                     "actor_ttl": spec.get("ttl", "default (3600 s)")},
            "caller": out,
            "exchange_attempted_with_this_actor": rec is not None,
            "login_server_record": None if rec is None else {
                k: rec.get(k) for k in ("outcome", "actor_check", "actor_sub", "actor_aud",
                                        "subject_sub", "actor_present")},
            "what_arrived_upstream": [{"subject": c.subject, "actor": c.actor,
                                       "issuer": c.issuer, "audience": c.audience,
                                       "token": dc.fp(c.token)} for c in calls],
            "observation": label,
        }
        print(f"  {name}: {label}  (upstream actor={up_actor}, exchange="
              f"{(rec or {}).get('outcome')})")
    control_ok = results["control"]["observation"] == "forwarded_to_upstream"
    name = "actor_lies-may_act" if may_act else "actor_lies"
    dc.save_run("agentgateway", name, {
        **base, "probe": "actor_lies", "grade": "OBSERVATION",
        "label": "actor_validation_observed" if control_ok else "inconclusive",
        "control_reached_upstream_with_actor": control_ok,
        "note": ("Not graded: agentgateway may intend the login server to validate the actor "
                 "token. The local login server checks an actor token's signature, issuer and "
                 "expiry, NOT its audience; so an arrival upstream in other_audience shows "
                 "only that neither agentgateway nor this login server checked it."),
        "config_actor_check": "actorToken.enforceMayAct: true" if may_act else
                              "none (actorToken.enforceMayAct not set; default false)",
        "cases": results, "docs": AGW_DOCS})


def main():
    mode = os.environ.get("DEEPER_MODE", "")
    configs = {"login_faults": "xid10-login-faults.yaml", "concurrent": "xid10-delegation.yaml",
               "actor_lies": "xid10-delegation.yaml",
               "actor_lies_may_act": "xid10-actor-may-act.yaml"}
    if mode not in configs:
        raise SystemExit(f"DEEPER_MODE must be one of {sorted(configs)}")
    config_path = os.path.join(_HERE, "agentgateway", configs[mode])
    version = g.agw_version()
    print(f"=== agentgateway {version.get('version')} DEEPER_MODE {mode} ===")
    global EP
    EP = FaultyTokenEndpoint(FAULT_PORT, AS_BASE,
                             slow_seconds=float(os.environ.get("SLOW_SECONDS", "45"))).start()
    up = g.Upstream(g.UPSTREAM_AUD, g._get(f"{AS_BASE}/jwks"), g.AS_ISSUER, g.UPSTREAM_PORT).start()
    gw = g.Gateway(config_path)
    try:
        gw.start()
        time.sleep(1)
        base = base_record(config_path, gw, version, mode)
        if mode == "login_faults":
            mode_login_faults(up, gw, base)
        elif mode == "concurrent":
            mode_concurrent(up, gw, base)
        else:
            mode_actor_lies(up, gw, base, may_act=(mode == "actor_lies_may_act"))
    except Exception:
        print("--- agentgateway log tail (redacted) ---\n" + gw.tail(30))
        raise
    finally:
        gw.stop()
        up.stop()
        EP.stop()


EP = None

if __name__ == "__main__":
    main()
