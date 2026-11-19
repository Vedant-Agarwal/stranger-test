"""XID-10 gate against a REAL third-party gateway: Stacklok ToolHive (v0.65.0).

Drives the existing delegation / scope / issuer / exchange-failure / cache /
same-user-credentials probes through a running ToolHive STANDALONE proxy
(``thv run <remote-url>``) configured, by CLI flags only, for RFC 8693 token
exchange against the local AS. ToolHive is the deputy under test; local_as is
the IdP; a recording MCP server (started here) is the upstream.

Why ``thv run`` and not ``thv proxy``: only ``thv run`` exposes
``--jwks-allow-private-ip`` and ``--oidc-insecure-allow-http``, which a loopback
local_as needs (ToolHive otherwise refuses to fetch a JWKS from 127.0.0.1).
``thv run <URL>`` runs a *remote* MCP server as a workload, proxying to the URL —
no container image is built, so no Docker image is pulled for the server itself.

Prerequisites (integration/TOOLHIVE_GATE.md has the recipe):
  * the ``thv`` v0.65.0 binary, path in THV_BIN, sha256-verified against the
    release checksums (the operator installs it; the version is recorded per run)
  * local_as serving on AS_BASE (started by the operator, so its mode is explicit
    and recorded in every run)
  * this driver run with a Python that has pyjwt[crypto]

Modes (TH_MODE), mirroring the LiteLLM gate plus the CVE probe:
  delegation                 A, B, A: the six checks (+ in-run thin-deputy fixtures)
  two_issuers                same, alice@provX vs alice@provY (+ conflated fixture)
  scope_narrowing            CoSAI 3.3.2 (TH_GW_SCOPES=NONE: no --token-exchange-scopes)
  issuer_unregistered        needs the AS started --lax-subject-issuer
  issuer_unregistered_strict the same probe against the default (strict) AS
  issuer_email_crossprovider
  exchange_fail              control first, then the exchange fails (+ fall-through fixture)
  cache                      does ToolHive cache the exchanged token on this path?
  same_user_credentials      CVE-2026-110195 class: two credentials of one user

Ports: AS_BASE, TH_PROXY_PORT, UPSTREAM_PORT and FIXTURE_BASE (fixture AS N,
thin upstream N+2, thin deputy N+3, switchable token endpoint N+4, fall-through
fixture N+5) are REQUIRED, must be 4600-4699, never 4000/4444/8790.

Not a unittest; an operator-driven gate. Tokens are stored as sha256 fingerprints
only; secrets (client secret) never.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import jwt  # noqa: F401
    from local_as import LocalAS  # noqa: F401
except Exception as exc:  # pragma: no cover
    print(f"ERROR: cannot run the ToolHive gate: needs pyjwt[crypto] ({exc})", file=sys.stderr)
    sys.exit(2)

# Generic, gateway-agnostic helpers reused from the LiteLLM gate: the recording
# upstream, the thin-deputy fixtures, the per-check grading, the switchable token
# endpoint and the fall-through fixture, plus token fingerprinting/redaction.
from xid10_litellm_gate import (  # noqa: E402
    Recorder, SwitchableTokenEndpoint, FallThroughDeputy, thin_fixtures,
    check_grades, fp, redact, _get, _call, login_facts, exchanges_since,
    as_issue, http_status, PROVX, PROVY, UNREGISTERED, AS_ISSUER, UPSTREAM_AUD,
)
from strangertest.delegate import (  # noqa: E402
    UpstreamCall, gate_run_problems, grade_issuer_email_crossprovider, make_nonce,
    observe_one_call, request_nonce, run_delegation_probe,
    run_issuer_unregistered_probe, run_scope_narrowing_probe,
)
from strangertest.credcache import (  # noqa: E402
    Credential, run_same_user_credentials_probe, FAIL, OK, INCONCLUSIVE,
)
from strangertest.mcp_client import MCPClient  # noqa: E402
from strangertest.transports import HTTPTransport  # noqa: E402
from strangertest.probe import Identity, ProbeError  # noqa: E402

PINNED_VERSION = "0.65.0"
USER_AUD = "toolhive-api"          # ToolHive validates this against --oidc-audience
SERVER = "notes"
CLIENT_ID = "toolhive-gw"
FORBIDDEN_PORTS = {4000, 4444, 8790}
PORT_RANGE = range(4600, 4700)     # 46xx for the ToolHive gate
DOCS = {
    "backend_auth": "https://docs.stacklok.com/toolhive/concepts/backend-auth",
    "token_exchange": "https://docs.stacklok.com/toolhive/guides-cli/token-exchange",
    "vmcp_auth": "https://docs.stacklok.com/toolhive/guides-vmcp/authentication",
}


# ------------------------------------------------------------------ ports
def _port(name):
    raw = os.environ.get(name)
    if not raw:
        raise SystemExit(f"ERROR: refusing to start: set {name} explicitly")
    port = int(raw)
    if port in FORBIDDEN_PORTS or port not in PORT_RANGE:
        raise SystemExit(f"ERROR: refusing port {port} for {name}: must be 4600-4699, "
                         f"never {sorted(FORBIDDEN_PORTS)}")
    return port


def require_endpoints():
    as_base = os.environ.get("AS_BASE") or ""
    u = urlparse(as_base)
    if u.hostname != "127.0.0.1" or not u.port:
        raise SystemExit("ERROR: refusing to start: AS_BASE must be http://127.0.0.1:<46xx>")
    os.environ["_AS_PORT"] = str(u.port)
    ports = {"as": _port("_AS_PORT"), "proxy": _port("TH_PROXY_PORT"),
             "upstream": _port("UPSTREAM_PORT"), "fixture_base": _port("FIXTURE_BASE")}
    fx = ports["fixture_base"]
    for off in range(6):
        os.environ["_FX"] = str(fx + off)
        _port("_FX")
    used = [ports["as"], ports["proxy"], ports["upstream"]] + list(range(fx, fx + 6))
    if len(set(used)) != len(used):
        raise SystemExit(f"ERROR: refusing: ports overlap: {used}")
    return as_base.rstrip("/"), ports


# ---------------------------------------------------------------- ToolHive
def thv_version(thv_bin):
    # Isolated HOME so the version/update check writes nothing to the real home dir.
    tmp = tempfile.mkdtemp(prefix="xid10-thv-ver-")
    env = dict(os.environ, HOME=tmp, XDG_CONFIG_HOME=os.path.join(tmp, "cfg"),
               XDG_DATA_HOME=os.path.join(tmp, "data"), XDG_STATE_HOME=os.path.join(tmp, "state"),
               XDG_CACHE_HOME=os.path.join(tmp, "cache"))
    try:
        out = subprocess.check_output([thv_bin, "version"], text=True, env=env)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    v = {"raw": out.strip()}
    for line in out.splitlines():
        if line.startswith("ToolHive "):
            v["version"] = line.split()[1].lstrip("v")
        elif line.startswith("Commit:"):
            v["commit"] = line.split(":", 1)[1].strip()
    return v


class ToolHive:
    """A ToolHive standalone proxy (``thv run <remote-url>``), managed as a
    workload. Keeps its log file path and prints it only redacted.

    ``token_url`` is the exchange endpoint (the AS, or the switchable endpoint for
    the exchange-fail mode). ``scopes`` is the exchanged-token scope list (empty
    for the no-scopes scope-narrowing variant). The caller sends only
    ``Authorization: Bearer <user JWT>`` — ToolHive validates it (incoming OIDC)
    and injects the exchanged token upstream (replacing Authorization)."""

    DEV_FLAGS = {
        "flags": ["--jwks-allow-private-ip", "--oidc-insecure-allow-http"],
        "why": ("needed ONLY because the login server (local_as) is on localhost over HTTP: they "
                "relax ToolHive's refusal to fetch a JWKS/OIDC endpoint from a private/loopback IP "
                "over plain HTTP. They do NOT change the token-exchange or token-validation logic "
                "being tested — only where the keys are fetched from."),
    }

    def __init__(self, thv_bin, proxy_port, target_url, as_base, token_url, *,
                 scopes=("read:notes",), client_secret=None, oidc_issuer=AS_ISSUER,
                 oidc_audience=USER_AUD, oidc_jwks_path="/jwks", ready_issuer=None,
                 ready_key=None, modern=False):
        self.bin = thv_bin
        self.port = proxy_port
        self.target_url = target_url
        self.as_base = as_base
        self.token_url = token_url
        self.scopes = list(scopes)
        self.client_secret = client_secret or secrets.token_hex(16)
        self.oidc_issuer = oidc_issuer
        self.oidc_audience = oidc_audience
        self.oidc_jwks_path = oidc_jwks_path
        self.ready_issuer = ready_issuer   # issuer/key for the readiness-probe token
        self.ready_key = ready_key
        self.modern = modern
        self.name = "xid10th-" + secrets.token_hex(3)
        self.url = f"http://127.0.0.1:{proxy_port}/mcp"
        self.logfile = None
        self.lines = []
        self._tmp = None

    def _args(self):
        args = [self.bin, "run", self.target_url, "--name", self.name,
                "--transport", "streamable-http", "--proxy-port", str(self.port),
                "--host", "127.0.0.1",
                "--oidc-issuer", self.oidc_issuer,
                "--oidc-jwks-url", f"{self.as_base}{self.oidc_jwks_path}",
                "--oidc-audience", self.oidc_audience,
                "--jwks-allow-private-ip", "--oidc-insecure-allow-http",
                "--token-exchange-url", self.token_url,
                "--token-exchange-audience", UPSTREAM_AUD,
                "--token-exchange-client-id", CLIENT_ID,
                "--token-exchange-client-secret", self.client_secret,
                "--token-exchange-subject-token-type", "access_token"]
        for s in self.scopes:
            args += ["--token-exchange-scopes", s]
        return args

    def _recorded_args(self):
        return [("<client-secret>" if a == self.client_secret else a) for a in self._args()]

    def _env(self):
        self._tmp = self._tmp or tempfile.mkdtemp(prefix="xid10-toolhive-")
        return dict(os.environ, HOME=self._tmp,
                    XDG_CONFIG_HOME=os.path.join(self._tmp, "cfg"),
                    XDG_DATA_HOME=os.path.join(self._tmp, "data"),
                    XDG_STATE_HOME=os.path.join(self._tmp, "state"),
                    XDG_CACHE_HOME=os.path.join(self._tmp, "cache"))

    def start(self, timeout=90):
        env = self._env()
        p = subprocess.run(self._args(), env=env, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        self.lines = out.splitlines()
        if p.returncode != 0:
            raise RuntimeError("thv run failed:\n" + self.tail())
        for line in self.lines:
            m = re.search(r'"logging to"\s*,\s*"path"\s*:\s*"([^"]+)"', line) or \
                re.search(r'"path"\s*:\s*"([^"]*toolhive/logs/[^"]+)"', line)
            if m:
                self.logfile = m.group(1)
                break
        # Readiness: the background JWKS fetch must complete before validation
        # works, so poll an authenticated initialize until it is not a 401.
        probe = as_issue(self.as_base, "readyprobe", aud=self.oidc_audience,
                         iss=self.ready_issuer, key=self.ready_key)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                c = MCPClient(HTTPTransport(self.url, headers={"Authorization": f"Bearer {probe}"},
                                           modern=self.modern))
                c.initialize()
                try:
                    c.close()
                except Exception:  # noqa: BLE001
                    pass
                return self
            except Exception as e:  # noqa: BLE001
                if "401" not in str(e) and "Connection" not in str(e) and "refused" not in str(e):
                    time.sleep(0.5)
                else:
                    time.sleep(0.5)
        raise RuntimeError("ToolHive proxy did not become ready:\n" + self.tail())

    def tail(self, n=40):
        lines = list(self.lines)
        if self.logfile and os.path.exists(self.logfile):
            try:
                with open(self.logfile) as f:
                    lines += f.read().splitlines()
            except Exception:  # noqa: BLE001
                pass
        return "\n".join(redact(l) for l in lines[-n:])

    def stop(self):
        env = self._env()
        for cmd in (["stop", self.name], ["rm", self.name]):
            try:
                subprocess.run([self.bin, *cmd], env=env, capture_output=True, text=True, timeout=40)
            except Exception:  # noqa: BLE001
                pass
        # belt-and-braces: kill any proxy still bound to our port
        subprocess.run(["/usr/bin/pkill", "-f", f"proxy-port {self.port}"], capture_output=True)
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)

    def client(self, user_token=None, *, url=None, modern=None):
        h = {"Authorization": f"Bearer {user_token}"} if user_token else {}
        return MCPClient(HTTPTransport(url or self.url, headers=h,
                                       modern=self.modern if modern is None else modern))

    def record(self):
        return {"workload_name": self.name,
                "gateway_cli": self._recorded_args()[1:],  # drop the binary path
                "client_secret": fp(self.client_secret),
                "logfile": os.path.relpath(self.logfile, self._tmp) if self.logfile and self._tmp else None,
                "log_tail": self.tail(60)}


# ------------------------------------------------------------------ save
def save(name, payload, *, tag=""):
    runs_dir = os.path.join(_HERE, "runs")
    os.makedirs(runs_dir, exist_ok=True)
    out = os.path.join(runs_dir, f"toolhive-{name}{tag}-{int(time.time())}.json")
    text = json.dumps(payload, indent=2, default=str)
    from xid10_litellm_gate import _JWT_RE
    if _JWT_RE.search(text):
        raise SystemExit("refusing to save: a JWT is in the run")
    with open(out, "w") as f:
        f.write(text)
    print(f"saved run -> {out}")
    return out


def save_checked(name, payload):
    problems = gate_run_problems(payload)
    payload = {**payload, "run_valid": not problems, "run_problems": problems}
    save(name, payload)
    if problems:
        for p in problems:
            print(f"ERROR: {p}", file=sys.stderr)
        raise SystemExit(1)


# --------------------------------------------------------------- helpers
def ident(gw, label, token_fn):
    return Identity(label=label, connect=lambda: gw.client(token_fn()))


def discover_tool(gw, token):
    c = gw.client(token)
    try:
        init = c.initialize()
        tools = c.list_tools()
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass
    if not tools:
        raise SystemExit("no tools discovered through ToolHive")
    return tools[0]["name"], init.get("protocolVersion")


# ------------------------------------------------------------------ modes
def mode_delegation(mode, gw, up, as_base, ports, base):
    two = mode == "two_issuers"
    if two:
        pa, pb = ("A", "alice", PROVX, "alice@provx.test"), ("B", "alice", PROVY, "alice@provy.test")
    else:
        pa, pb = ("A", "alice", None, None), ("B", "bob", None, None)
    issue = lambda who, iss, email: as_issue(as_base, who, iss=iss, email=email, aud=USER_AUD)  # noqa: E731
    tool, client_ver = discover_tool(gw, issue(pa[1], pa[2], pa[3]))
    n_ex = len(_get(f"{as_base}/exchanges"))
    n_req = len(up.requests)
    try:
        rep = run_delegation_probe(
            gw.url,
            ident(gw, pa[0], lambda: issue(pa[1], pa[2], pa[3])),
            ident(gw, pb[0], lambda: issue(pb[1], pb[2], pb[3])),
            upstream=up, trigger=lambda c: c.call_tool(tool, {}),
            expected_subject_a=pa[1], expected_subject_b=pb[1],
            expected_issuer_a=pa[2] or AS_ISSUER, expected_issuer_b=pb[2] or AS_ISSUER)
    except Exception as e:  # noqa: BLE001 — ProbeError, or a raw 401 when provy is refused
        if two:
            # ToolHive binds to one configured issuer (provx); the second issuer
            # (provy) is refused at the gateway (HTTP 401) before any exchange, so
            # the A/B conflation this probe checks cannot be exercised. Record the
            # probe's own INCONCLUSIVE with the reason (grader unchanged), run the
            # broken fixtures for the record, and do not crash the gate.
            fixtures = thin_fixtures(ports["fixture_base"], two_issuers=True)
            print(f"INCONCLUSIVE (two_issuers): {redact(e)}")
            save("two_issuers", {
                **base, "probe": "xid10-delegation", "mode": "two_issuers",
                "grade": "INCONCLUSIVE", "vulnerable": None,
                "inconclusive_reason": redact(str(e))[:400],
                "why": ("ToolHive validates the inbound issuer and binds to ONE configured OIDC "
                        "issuer (provx). The second issuer (provy) is rejected at the gateway with "
                        "HTTP 401 before any token exchange, so the two same-named-user/two-issuer "
                        "conflation this probe looks for cannot occur. The rejection is the safe "
                        "outcome; see the inbound_validation observation row."),
                "broken_fixtures_in_run": {"fixtures": fixtures, "controls": ["safe", "two_issuers (safe)"],
                                           "note": "thin-deputy fixtures run in this run for the record"}})
            return
        print(f"INCONCLUSIVE: {redact(e)}")
        print("--- ToolHive log tail (redacted) ---\n" + gw.tail())
        raise
    print("CHECKS:", json.dumps(rep.checks))
    print("VULNERABLE:", rep.vulnerable, "FAILURES:", rep.failures)
    exch = exchanges_since(as_base, n_ex)
    fixtures = thin_fixtures(ports["fixture_base"], two_issuers=two)
    controls = ("safe", "two_issuers (safe)") if two else ("safe",)
    grades = check_grades(rep.checks, fixtures, controls)
    print("CHECK GRADES:", json.dumps(grades))
    reqs = up.requests[n_req:]
    payload = {
        **base, "probe": "xid10-delegation", "mode": mode, "trigger": "tool",
        "checks": rep.checks, "vulnerable": rep.vulnerable, "failures": rep.failures,
        "summary": redact(rep.summary()), "check_grades": grades,
        "broken_fixtures_in_run": {"fixtures": fixtures, "controls": list(controls),
                                   "note": "thin-deputy fixtures run in this run; a check is graded "
                                           "OK only if one of them failed it"},
        "a_first_eq_a_third_token": (len(rep.calls) >= 3
                                     and rep.calls[0].get("token") == rep.calls[2].get("token")),
        "recorded_calls": [_call(c) for c in rep.calls],
        "exchanges_client_auth": exch,
        "toolhive_sent_client_credentials": sorted({str(e.get("client_auth_method")) for e in exch}),
        "actor_source": ("none configured: ToolHive's RFC 8693 request carries no actor_token on "
                         "the proxy->upstream path, so this is impersonation (actor_present FAIL)"),
        "actor_observation": (
            "with local_as act_from_client + valid client_secret_basic (this run)" if base["as_act_from_client"]
            else "NOT SUPPORTED: ToolHive sends no actor_token on the proxy->upstream exchange "
                 "(same as LiteLLM); the act_from_client run shows whether an actor can instead "
                 "appear from the gateway's client credentials"),
        "client_negotiated_version": client_ver,
        "user_token_reached_upstream": False,
    }
    issued = {r.get("issued_fp") for r in _get(f"{as_base}/exchanges")}
    payload["user_token_reached_upstream"] = any(
        r.get("authorization") and r["authorization"] not in issued for r in reqs)
    save(mode, payload, tag="-act_from_client" if base["as_act_from_client"] else "")


def mode_scope(gw, up, as_base, ports, base, scopes_none):
    import xid10_thin_deputy_gate as thin
    fx = ports["fixture_base"]
    broken = thin.run_scope_fixture(as_base, "scope_escalation", controls={},
                                    upstream_port=fx + 2, deputy_port=fx + 3)
    print(f"broken fixture: {broken.summary()}")
    subj = thin.SUBJECT_SCOPE_BROAD
    tool, _ = discover_tool(gw, as_issue(as_base, "alice", scope=subj, aud=USER_AUD))
    res = run_scope_narrowing_probe(
        gw.url, ident(gw, "A", lambda: as_issue(as_base, "alice", scope=subj, aud=USER_AUD)),
        ident(gw, "B", lambda: as_issue(as_base, "bob", scope=subj, aud=USER_AUD)), upstream=up,
        trigger=lambda c: c.call_tool(tool, {}), subject_scope=subj,
        configured_scope="" if scopes_none else "read:notes",
        exchange_lookup=thin.exchange_lookup_http(as_base),
        controls={"broken_fixture_failed": broken.grade == "FAIL"})
    print(res.summary())
    name = "scope_narrowing-noscopes" if scopes_none else "scope_narrowing"
    payload = {**res.to_dict(), **base, "mode": name,
               "gateway_scopes_config": None if scopes_none else ["read:notes"],
               "broken_fixture": {"name": "thin_deputy scope_escalation", "grade": broken.grade,
                                  "reason": broken.reason}}
    save_checked(name, payload)


def mode_issuer_unregistered(gw, up, as_base, ports, base, *, strict=False):
    import xid10_thin_deputy_gate as thin
    lax = bool(base["login_server"]["lax_subject_issuer"])
    if strict and lax:
        raise SystemExit("issuer_unregistered_strict needs the AS WITHOUT --lax-subject-issuer")
    if not strict and not lax:
        raise SystemExit("issuer_unregistered needs the AS started with --lax-subject-issuer")
    fx = ports["fixture_base"]
    broken = None
    if not strict:
        broken = thin.run_issuer_fixture(as_base, "issuer_any", controls={},
                                         upstream_port=fx + 2, deputy_port=fx + 3)
        print(f"broken fixture: {broken.summary()}")
    control_tok = as_issue(as_base, "mallory", iss=PROVX, email="mallory@provx.test", key="provx", aud=USER_AUD)
    probe_tok = as_issue(as_base, "mallory", iss=UNREGISTERED, email="mallory@provx.test", key="provx", aud=USER_AUD)
    tool, _ = discover_tool(gw, control_tok)
    res = run_issuer_unregistered_probe(
        gw.url, control_identity=ident(gw, "control", lambda: control_tok),
        probe_identity=ident(gw, "probe", lambda: probe_tok), upstream=up,
        trigger=lambda c, n: c.call_tool(tool, {"nonce": n}), probe_token_fp=fp(probe_tok),
        probe_issuer=UNREGISTERED, exchange_records=lambda: _get(f"{as_base}/exchanges"),
        controls={} if strict else {"broken_fixture_failed": broken.grade == "FAIL"},
        quiet_seconds=3, settle_seconds=2)
    print(res.summary())
    ev = res.evidence
    print(f"  probe error: {ev['probe_error']}  exchange attempted: "
          f"{ev['exchange_attempted_with_probe_token']}")
    save_checked("issuer_unregistered-strict_login_server" if strict else "issuer_unregistered", {
        **res.to_dict(), **base,
        "signing_key_of_probe": "provx (ToolHive validates the inbound token's issuer against "
                                "--oidc-issuer; the probe token's iss is unregistered)",
        **({"observation_only": True,
            "observation": "where issuer validation happens: the same probe against the default "
                           "(strict) login server; not graded, no broken fixture"}
           if strict else
           {"broken_fixture": {"name": "thin_deputy issuer_any", "grade": broken.grade,
                               "reason": broken.reason}})})


def mode_email_crossprovider(gw, up, as_base, ports, base):
    y_email = "carol@provy.test"
    y_tok = as_issue(as_base, "carol-y", iss=PROVY, email=y_email, aud=USER_AUD)
    dave_tok = as_issue(as_base, "dave-x", iss=PROVX, email="dave@provx.test", aud=USER_AUD)
    probe_tok = as_issue(as_base, "carol-x", iss=PROVX, email=y_email, aud=USER_AUD)
    # Discover with a provx token: ToolHive is bound to issuer provx, so the provy
    # Y token (y_tok) is refused at the gateway and cannot be used to discover.
    tool, _ = discover_tool(gw, dave_tok)
    trig = lambda c: c.call_tool(tool, {})  # noqa: E731
    y_calls, y_err = observe_one_call(ident(gw, "Y", lambda: y_tok), up, trig)
    x_calls, x_err = observe_one_call(ident(gw, "Xctl", lambda: dave_tok), up, trig)
    p_calls, p_err = observe_one_call(ident(gw, "probe", lambda: probe_tok), up, trig)
    pc = [{"subject": c.subject, "issuer": c.issuer, "token": fp(c.token),
           "email": up.emails.get(fp(c.token)), "scope": c.scope} for c in p_calls]
    grade, label, reason = grade_issuer_email_crossprovider(
        probe_calls=pc, control_reached=bool(x_calls), x_issuer=PROVX, y_issuer=PROVY,
        y_subject="carol-y", claimed_email=y_email)
    print(f"[{grade}] {label}: {reason}")
    save_checked("issuer_email_crossprovider", {
        **base, "probe": "issuer_email_crossprovider",
        "cosai": "CoSAI MCP Security v2.0, 3.2.2 / 3.3.2",
        "why_positive_control_failed": (
            "ToolHive binds to ONE configured OIDC issuer (provx), so the probe's Y token "
            "(issuer provy) is refused at the gateway and never reaches the upstream — the "
            "positive control (y_reached_upstream) cannot be established here, so the run is "
            "marked run_valid=False. The X-side observation still holds: the provx token reached "
            "the upstream as its own provx identity (not conflated), carrying Y's email claim. A "
            "full cross-provider conflation check needs a gateway that accepts both issuers."),
        "grade": grade, "label": label, "reason": reason,
        "controls": {"y_reached_upstream": bool(y_calls), "x_control_reached_upstream": bool(x_calls)},
        "observations": {"gateway_has_user_store": False, "probe_accepted": bool(p_calls),
                         "probe_error": p_err, "probe_upstream_calls": pc,
                         "y_upstream_identity": [(c.issuer, c.subject) for c in y_calls],
                         "y_error": y_err, "x_control_error": x_err}})


def _call_with_nonce(client_fn, tool, nonce):
    c = client_fn()
    try:
        c.initialize()
        r = c.call_tool(tool, {"nonce": nonce})
        return {"result": redact(json.dumps(r))[:500], "is_error": bool(r.get("isError"))}
    except Exception as e:  # noqa: BLE001
        return {"error": redact(e)[:500], "is_error": True}
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass


def grade_exchange_fail(*, control_reached, fail_reached, no_auth_reached, caller_errored,
                        broken_fixture_failed):
    if fail_reached or no_auth_reached:
        return "FAIL", "reached_upstream", "a request made while the exchange failed reached the upstream"
    if not control_reached:
        return "INCONCLUSIVE", "inconclusive", "the control did not reach the upstream"
    if not caller_errored:
        return "INCONCLUSIVE", "inconclusive", "the caller did not receive an error"
    if not broken_fixture_failed:
        return "INCONCLUSIVE", "inconclusive", "the fall-through fixture did not FAIL in this run"
    return "OK", "fails_closed", ("nothing reached the upstream while the exchange failed; the "
                                  "caller got an error; the control reached it first")


def mode_exchange_fail(gw, up, as_base, ports, base, switch):
    tok_ctl = as_issue(as_base, "alice", aud=USER_AUD)
    tool, _ = discover_tool(gw, tok_ctl)
    n = {k: make_nonce(k) for k in ("control", "fail", "noauth", "fx_control", "fx_fail")}
    switch.fail = False
    ctl = _call_with_nonce(lambda: gw.client(tok_ctl), tool, n["control"])
    hits0 = dict(switch.hits)
    switch.fail = True
    fail = _call_with_nonce(lambda: gw.client(as_issue(as_base, "alice", aud=USER_AUD)), tool, n["fail"])
    hits1 = dict(switch.hits)
    noauth = _call_with_nonce(lambda: gw.client(None), tool, n["noauth"])
    hits2 = dict(switch.hits)
    switch.fail = False
    time.sleep(1)
    fxd = FallThroughDeputy(ports["fixture_base"] + 5, switch.url,
                            f"http://127.0.0.1:{ports['upstream']}/mcp").start()
    try:
        fx_client = lambda tok: MCPClient(HTTPTransport(fxd.url, headers={  # noqa: E731
            "Authorization": f"Bearer {tok}"}))
        _ = _call_with_nonce(lambda: fx_client(as_issue(as_base, "alice", aud=USER_AUD)), "read_note", n["fx_control"])
        switch.fail = True
        fx_fail = _call_with_nonce(lambda: fx_client(as_issue(as_base, "alice", aud=USER_AUD)), "read_note", n["fx_fail"])
        switch.fail = False
    finally:
        fxd.stop()
    fx_grade = grade_exchange_fail(
        control_reached=bool(up.by_nonce(n["fx_control"])), fail_reached=bool(up.by_nonce(n["fx_fail"])),
        no_auth_reached=False, caller_errored=fx_fail.get("is_error", False), broken_fixture_failed=True)
    grade, label, reason = grade_exchange_fail(
        control_reached=any(r.get("authorization") for r in up.by_nonce(n["control"])),
        fail_reached=bool(up.by_nonce(n["fail"])), no_auth_reached=bool(up.by_nonce(n["noauth"])),
        caller_errored=fail.get("is_error", False) and noauth.get("is_error", False),
        broken_fixture_failed=fx_grade[0] == "FAIL")
    print(f"[{grade}] {label}: {reason}")
    upstream_view = {k: [{kk: r.get(kk) for kk in ("method", "authorization", "header_names")}
                         for r in up.by_nonce(v)] for k, v in n.items()}
    save("exchange_fail", {
        **base, "probe": "exchange_fail", "grade": grade, "label": label, "reason": reason, "nonces": n,
        "calls": {"control": ctl, "exchange_fails_new_token": fail, "exchange_fails_no_authorization": noauth},
        "token_endpoint_hits": {"after_control": hits0, "after_fail_call": hits1, "after_no_auth_call": hits2},
        "token_endpoint_requests": switch.requests,
        "upstream_requests_by_nonce": upstream_view,
        "broken_fixture": {"name": "fall-through deputy (forwards with no Authorization when the "
                                   "exchange fails)", "grade": fx_grade[0], "reason": fx_grade[2]},
        "caller_error_text": fail.get("result") or fail.get("error")})


def mode_cache(gw, up, as_base, ports, base):
    """Trial: A calls the same tool twice through ToolHive. Count the exchanges
    the AS saw: a second call with no new exchange AND the same upstream token =
    ToolHive cached (per subject token). On the standalone path it exchanges per
    request (DOES NOT CACHE)."""
    tok = as_issue(as_base, "alice", aud=USER_AUD)
    tool, _ = discover_tool(gw, tok)
    nonces = [make_nonce("cache1"), make_nonce("cache2")]
    n_ex0 = len([e for e in _get(f"{as_base}/exchanges") if e.get("outcome") == "granted"])
    c = gw.client(tok)
    try:
        c.initialize()
        for nn in nonces:
            c.call_tool(tool, {"nonce": nn})
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass
    calls = [up.by_nonce(nn) for nn in nonces]
    toks = [(cs[-1].get("authorization") if cs else None) for cs in calls]
    n_ex1 = len([e for e in _get(f"{as_base}/exchanges") if e.get("outcome") == "granted"])
    new_exchanges = n_ex1 - n_ex0
    caches = (toks[0] is not None and toks[0] == toks[1] and new_exchanges <= 1)
    print(f"exchanges for two reads: {new_exchanges}  same upstream token: {toks[0] == toks[1]} -> caches={caches}")
    save("cache", {
        **base, "probe": "cache", "stage": "caching_trial",
        "observation": "CACHES" if caches else "DOES NOT CACHE",
        "caching_trial": {"caches": caches, "new_exchanges_for_two_reads": new_exchanges,
                          "second_read_token_equals_first": toks[0] == toks[1],
                          "upstream_tokens": toks},
        "note": ("ToolHive exchanged a fresh token per read on this path, so the cachescope probe "
                 "has nothing to test here (DOES NOT CACHE)" if not caches else
                 "ToolHive reused the exchanged token; the vMCP path caches per (backend, "
                 "hash(subject_token), audience)")})


# ------------------------------------------- same-user-credentials (CVE class)
class SameCredDeputy:
    """Drives the same-user-credentials probe through ToolHive. On the standalone
    proxy path there is no exchange cache, so ``fresh_cache`` is a no-op and a
    cache hit is simply never observed (reported, not inferred)."""

    def __init__(self, gw, tool_name):
        self.gw = gw
        self.tool = tool_name

    def fresh_cache(self):
        return None  # standalone path keeps no exchange cache to reset

    def read_resource(self, token, nonce):
        c = self.gw.client(token)
        try:
            c.initialize()
            return c.call_tool(self.tool, {"nonce": nonce})
        finally:
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass


def mode_same_user_credentials(gw, up, as_base, ports, base):
    user = "alice"
    cred1 = as_issue(as_base, user, scope="read:notes", aud=USER_AUD)
    cred2 = as_issue(as_base, user, scope="read:notes", aud=USER_AUD)
    if cred1 == cred2:
        raise SystemExit("the two credentials are byte-identical; aborting")
    tool, _ = discover_tool(gw, cred1)

    def upstream_calls():
        out = []
        for r in up.requests:
            if r.get("method") != "tools/call":
                continue
            out.append(UpstreamCall(nonce=r.get("nonce"), token=r.get("authorization"),
                                    audience=UPSTREAM_AUD, scope=None, subject=None,
                                    issuer="local-as.test", parsed=True, method="tools/call"))
        return out

    def granted_exchanges():
        return len([e for e in _get(f"{as_base}/exchanges") if e.get("outcome") == "granted"])

    deputy = SameCredDeputy(gw, tool)
    report = run_same_user_credentials_probe(
        target=gw.url, upstream_target=f"http://127.0.0.1:{ports['upstream']}/mcp", user=user,
        cred1=Credential("session", cred1), cred2=Credential("apitoken", cred2),
        read_resource=deputy.read_resource, uri_for=lambda n: n,
        upstream_calls=upstream_calls, fresh_cache=deputy.fresh_cache,
        expire_cache=None, exchange_attempts=granted_exchanges,
        authorized=True, authorization_note="localhost ToolHive CVE-2026-110195-class check")
    print("cold control:", report.cold_control.grade, "-", report.cold_control.detail)
    print("warm test:   ", report.warm.grade, "-", report.warm.detail)
    print("cache hit observed:", report.observations.get("cache_hit_observed"))
    print("VERDICT:", report.summary())
    save_checked("same-user-credentials", {
        **base, "probe": "same-user-credentials", "cve": "CVE-2026-110195",
        "method": ("two inbound login JWTs for one user (alice), same scope; ToolHive exchanges "
                   "each at the local AS; recording upstream ties each read to its nonce; the AS "
                   "mints a distinct upstream token per exchange so token reuse is visible"),
        "user": user, "credentials": {"cred1": "session JWT", "cred2": "api-token JWT (same user)"},
        "cold_control": report.cold_control.to_dict(), "warm": report.warm.to_dict(),
        "grade": report.grade, "vulnerable": report.vulnerable,
        "exchange_attempts_total_granted": granted_exchanges(),
        "observations": report.observations, "summary": report.summary(),
        "scope_and_privilege": ("both credentials carried the same scope (read:notes); this shows "
                                "token reuse across credentials, not privilege escalation")})


# --------------------------------------------- inbound issuer/signature validation
def _try_call(gw, tool, token):
    """Attempt initialize + one tool call as this inbound token; report whether it
    reached the upstream or was refused at the gateway (and the status/text)."""
    c = gw.client(token)
    try:
        c.initialize()
        r = c.call_tool(tool, {"nonce": make_nonce("inval")})
        return {"accepted": True, "reached_upstream": True, "is_error": bool(r.get("isError"))}
    except Exception as e:  # noqa: BLE001
        msg = redact(str(e))[:300]
        status = 401 if "401" in msg else (403 if "403" in msg else None)
        return {"accepted": False, "reached_upstream": False, "status": status, "error": msg}
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass


def mode_inbound_validation(gw, up, as_base, ports, base):
    """Observation (not a graded leak check): ToolHive validates the inbound
    token's issuer + signature + audience itself, against the ONE configured OIDC
    issuer + JWKS. This is unlike LiteLLM (which defers inbound validation to the
    AS). The gate configures ToolHive for issuer provx and shows: a provx token
    reaches the upstream; a provy token (different issuer+key) and an
    unregistered-issuer token (provx-signed, so the signature verifies but the
    issuer does not match) are both refused at the gateway before any exchange.
    This is where the two-issuer / unregistered-issuer / cross-provider scenarios
    land for a gateway that validates at the door."""
    control = as_issue(as_base, "alice", iss=PROVX, email="alice@provx.test", key="provx", aud=USER_AUD)
    other_issuer = as_issue(as_base, "alice", iss=PROVY, email="alice@provy.test", key="provy", aud=USER_AUD)
    # Unregistered issuer, but signed with provx's key (kid is in the configured
    # JWKS) so the signature verifies and only the issuer claim is wrong.
    unregistered = as_issue(as_base, "mallory", iss=UNREGISTERED, email="mallory@provx.test",
                            key="provx", aud=USER_AUD)
    wrong_aud = as_issue(as_base, "alice", iss=PROVX, email="alice@provx.test", key="provx",
                         aud="some-other-audience")
    tool, _ = discover_tool(gw, control)
    obs = {
        "configured_issuer": PROVX,
        "configured_jwks": f"{as_base}/jwks/provx",
        "configured_audience": USER_AUD,
        "control_provx_registered_issuer": _try_call(gw, tool, control),
        "other_issuer_provy": _try_call(gw, tool, other_issuer),
        "unregistered_issuer_provx_signed": _try_call(gw, tool, unregistered),
        "wrong_audience_provx": _try_call(gw, tool, wrong_aud),
    }
    safe = (obs["control_provx_registered_issuer"]["reached_upstream"]
            and not obs["other_issuer_provy"]["reached_upstream"]
            and not obs["unregistered_issuer_provx_signed"]["reached_upstream"]
            and not obs["wrong_audience_provx"]["reached_upstream"])
    label = "VALIDATES INBOUND" if safe else "DOES NOT VALIDATE INBOUND"
    print(f"[OBSERVATION] inbound validation: {label}")
    for k in ("control_provx_registered_issuer", "other_issuer_provy",
              "unregistered_issuer_provx_signed", "wrong_audience_provx"):
        print(f"   {k}: {json.dumps(obs[k])}")
    save("inbound-validation", {
        **base, "probe": "inbound_validation", "graded": False,
        "observation": label,
        "note": ("ToolHive validates the inbound token (issuer + signature + audience) itself, "
                 "against the single configured OIDC issuer + JWKS, and refuses a mismatch at the "
                 "gateway with HTTP 401 BEFORE any token exchange. Because it binds to one issuer, "
                 "the existing two_issuers / issuer_unregistered / issuer_email_crossprovider "
                 "probes (which drive A/B traffic from two different issuers through one gateway) "
                 "do not apply as graded leak checks here — a second-issuer or unregistered-issuer "
                 "token never reaches the exchange. This observation records that behaviour using "
                 "the same scenarios."),
        "observations": obs})


# ------------------------------------------------------------------ main
# The existing issuer probes (two_issuers / issuer_unregistered /
# issuer_email_crossprovider) are run UNCHANGED, with their own grades, so the
# issuer row is comparable with the other gateways. Because ToolHive validates
# the inbound issuer and binds to ONE configured issuer, those runs are driven
# with ToolHive configured for issuer provx (so the control token validates);
# the `inbound_validation` observation is an EXTRA row, not a replacement.
ISSUER_MODES = ("two_issuers", "issuer_unregistered", "issuer_email_crossprovider")
MODES = ("delegation", "scope_narrowing", "exchange_fail", "cache",
         "same_user_credentials", "inbound_validation") + ISSUER_MODES


def main():
    as_base, ports = require_endpoints()
    thv_bin = os.environ.get("THV_BIN") or sys.exit("ERROR: set THV_BIN (the thv v0.65.0 binary)")
    mode = os.environ.get("TH_MODE", "delegation")
    if mode not in MODES:
        raise SystemExit(f"unknown TH_MODE {mode}")
    scopes_none = os.environ.get("TH_GW_SCOPES", "").strip().upper() == "NONE"
    ver = thv_version(thv_bin)
    if ver.get("version") != PINNED_VERSION:
        raise SystemExit(f"ERROR: ToolHive {ver.get('version')} installed; this gate is pinned "
                         f"to {PINNED_VERSION}")
    facts = login_facts(as_base)
    print(f"=== MODE {mode}  ToolHive {ver.get('version')} (commit {ver.get('commit', '?')[:12]})  AS {facts}")
    up = Recorder(ports["upstream"], _get(f"{as_base}/jwks")).start()
    switch = None
    token_url = f"{as_base}/token"
    if mode == "exchange_fail":
        switch = SwitchableTokenEndpoint(ports["fixture_base"] + 4, as_base).start()
        token_url = switch.url
    scopes = [] if (mode == "scope_narrowing" and scopes_none) else ["read:notes"]
    # inbound_validation binds ToolHive to one provider issuer (provx) so it can
    # show a mismatching issuer being refused at the gateway.
    # inbound_validation and the issuer probes bind ToolHive to one provider
    # issuer (provx) so the control token validates and a mismatching issuer is
    # refused at the gateway.
    oidc_kw = (dict(oidc_issuer=PROVX, oidc_jwks_path="/jwks/provx",
                    ready_issuer=PROVX, ready_key="provx")
               if mode in (("inbound_validation",) + ISSUER_MODES) else {})
    gw = ToolHive(thv_bin, ports["proxy"], f"http://127.0.0.1:{ports['upstream']}", as_base,
                  token_url, scopes=scopes, client_secret=os.environ.get("TH_CLIENT_SECRET"),
                  **oidc_kw)
    base = {"gateway": "toolhive", "gateway_label": "Stacklok ToolHive (standalone proxy)",
            "gateway_version": ver.get("version"), "gateway_versions": ver,
            "gateway_mode": "standalone (thv run <remote-url>)",
            "install": f"release binary thv v{PINNED_VERSION} (Apache-2.0), sha256-verified, loopback only",
            "endpoints": {"as_base": as_base, **ports}, "login_server": facts,
            "as_act_from_client": bool(facts.get("act_from_client")),
            "client_transport": "HTTPTransport (legacy Streamable HTTP)",
            "caller_auth": "Authorization: Bearer <user JWT> (ToolHive validates it: incoming OIDC "
                           "with --oidc-issuer/--oidc-jwks-url/--oidc-audience, "
                           "--jwks-allow-private-ip + --oidc-insecure-allow-http for the loopback AS)",
            "token_exchange": "RFC 8693 to the local AS; client auth client_secret_basic; the "
                              "exchanged token replaces Authorization upstream",
            "dev_flags": ToolHive.DEV_FLAGS,
            "docs": DOCS}
    try:
        gw.start()
        base.update(gw.record())
        # Note 2: ToolHive makes one unauthenticated initialize probe to the
        # target at workload startup. Record it explicitly and exclude it from
        # grading (the probes grade only per-nonce / per-identity caller traffic).
        pre = [{k: r.get(k) for k in ("method", "authorization", "mcp_protocol_version")}
               for r in up.requests]
        base["startup_probe"] = {
            "gateway_startup_requests_no_auth": [r for r in pre if not r.get("authorization")],
            "driver_readiness_requests_authed": [r for r in pre if r.get("authorization")],
            "note": "ToolHive makes an unauthenticated initialize probe to the target at workload "
                    "startup (gateway_startup_requests_no_auth); this driver then issues one "
                    "authenticated readiness probe to wait for the JWKS fetch "
                    "(driver_readiness_requests_authed). BOTH are excluded from grading, which "
                    "uses only per-nonce / per-identity caller traffic."}
        print(f"ToolHive up @ {gw.url} (workload {gw.name})  startup probe: {len(pre)} request(s)")
        if mode in ("delegation", "two_issuers"):
            mode_delegation(mode, gw, up, as_base, ports, base)
        elif mode == "scope_narrowing":
            mode_scope(gw, up, as_base, ports, base, scopes_none)
        elif mode == "inbound_validation":
            mode_inbound_validation(gw, up, as_base, ports, base)
        elif mode == "issuer_unregistered":
            mode_issuer_unregistered(gw, up, as_base, ports, base)
        elif mode == "issuer_email_crossprovider":
            mode_email_crossprovider(gw, up, as_base, ports, base)
        elif mode == "exchange_fail":
            mode_exchange_fail(gw, up, as_base, ports, base, switch)
        elif mode == "cache":
            mode_cache(gw, up, as_base, ports, base)
        elif mode == "same_user_credentials":
            mode_same_user_credentials(gw, up, as_base, ports, base)
    except Exception:
        print("--- ToolHive log tail (redacted) ---\n" + gw.tail())
        raise
    finally:
        gw.stop()
        up.stop()
        if switch:
            switch.stop()


if __name__ == "__main__":
    main()
