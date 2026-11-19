"""XID-10 gate against Kuadrant 1.6.0 Authorino token exchange (option b).

Label for all results: "Kuadrant 1.6.0 Authorino token exchange (sample policy,
minimally adapted) on a direct route; the mcp router/broker was not in the path".

The RFC 8693 exchange in the Kuadrant MCP Gateway is performed by **Authorino**
via an AuthPolicy. This gate drives the existing probes through an Istio Gateway
whose `mcps` listener carries the minimally-adapted sample AuthPolicy
(`integration/kuadrant/kuadrant-mcps-auth-policy.yaml`); the mcp router/broker is
NOT in the path, so **this driver sets `x-mcp-servername` itself, as the router
would** (it is the exchange audience and the scoped-audience-check subject). We do
NOT grade or report anything about client-supplied values of that header — in the
real deployment the router owns it.

Loopback only. local_as (the IdP + token endpoint) is on 127.0.0.1 and reached by
the cluster via host.docker.internal (see notes/kuadrant-networking.md). The
recording upstream is on 127.0.0.1:UPSTREAM_PORT and the gateway routes to it via
a Service/EndpointSlice at the Docker-Desktop host IP. The probe client reaches
the gateway via `kubectl port-forward` (GW_URL).

Operator-driven (not a unittest): the cluster, the applied resources and the
port-forward are set up by integration/KUADRANT_GATE.md; this driver assumes
GW_URL is reachable and local_as is serving on AS_BASE with issuer
http://host.docker.internal:4610. Tokens are stored as sha256 fingerprints only.

Env (required): AS_BASE (http://127.0.0.1:46xx), GW_URL (http://127.0.0.1:<pf>/),
UPSTREAM_PORT, FIXTURE_BASE, SWITCH_PORT (the host switchable token endpoint, for
exchange_fail). KUA_MODE picks the mode.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import jwt
except Exception as exc:  # pragma: no cover
    print(f"ERROR: needs pyjwt[crypto] ({exc})", file=sys.stderr)
    sys.exit(2)

from strangertest.delegate import (MockUpstream, request_nonce, run_delegation_probe,  # noqa: E402
                                   run_scope_narrowing_probe, make_nonce, gate_run_problems)
from strangertest.mcp_client import MCPClient  # noqa: E402
from strangertest.transports import HTTPTransport  # noqa: E402
from strangertest.probe import Identity, ProbeError  # noqa: E402
from xid10_litellm_gate import (thin_fixtures, check_grades, SwitchableTokenEndpoint,  # noqa: E402
                                 FallThroughDeputy, fp, redact, _get, _call, exchanges_since)

ISSUER = "http://host.docker.internal:4610"
SERVER = "svc1"                 # x-mcp-servername (the router would set this)
UPSTREAM_AUD = SERVER           # the exchange sets audience = x-mcp-servername
CALLER_AUD = "caller-aud"       # inbound user-token aud (!= SERVER, so the exchange runs)
USER_SCOPE = "openid read:notes"   # must include openid (the sample's exchange requests scope: openid)
LABEL = ("Kuadrant 1.6.0 Authorino token exchange (sample policy, minimally adapted) "
         "on a direct route; the mcp router/broker was not in the path")
FORBIDDEN_PORTS = {4000, 4444, 8790}
PORT_RANGE = range(4600, 4700)


def _port(name):
    raw = os.environ.get(name)
    if not raw:
        raise SystemExit(f"ERROR: set {name}")
    port = int(raw)
    if port in FORBIDDEN_PORTS or port not in PORT_RANGE:
        raise SystemExit(f"ERROR: refusing port {port} for {name}: 4600-4699 only")
    return port


# ------------------------------------------------------- recording upstream
class KuaRecorder(MockUpstream):
    """Recording Streamable-HTTP MCP upstream on the host; the Istio gateway
    routes to it. Decodes the (Authorino-exchanged) bearer with the AS JWKS and
    the AS issuer, records each call (and the x-mcp-servername header)."""

    def __init__(self, port, jwks, issuer):
        MockUpstream.__init__(self, UPSTREAM_AUD)
        self._key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
        self._issuer = issuer
        self.requests = []
        outer = self
        tool = {"name": "read_note", "description": "Read the caller's note.",
                "inputSchema": {"type": "object", "properties": {"nonce": {"type": "string"}}}}

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, obj, code=200, extra=None):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                self._send({"ok": True}, 200)

            def do_DELETE(self):
                self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                auth = self.headers.get("Authorization", "")
                bearer = auth[7:] if auth.startswith("Bearer ") else (auth or "")
                try:
                    msg = json.loads(raw)
                except ValueError:
                    self._send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "p"}}); return
                m, mid = msg.get("method"), msg.get("id")
                params = msg.get("params") or {}
                outer.requests.append({"method": m, "nonce": request_nonce(params),
                                       "authorization": fp(bearer) if bearer else None,
                                       "x_mcp_servername": self.headers.get("x-mcp-servername")})
                if m == "initialize":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": params.get("protocolVersion") or "2025-06-18",
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "upstream", "version": "1.0"}}},
                        extra={"Mcp-Session-Id": "up-" + hashlib.sha256(raw).hexdigest()[:8]})
                    return
                if mid is None:
                    self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers(); return
                if m == "tools/list":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [tool]}}); return
                if m in ("tools/call", "resources/read"):
                    outer._rec(m, bearer, params)
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "content": [{"type": "text", "text": "ok"}], "isError": False}}); return
                if m == "ping":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {}}); return
                self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no"}})

        self._srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        self._srv.allow_reuse_address = True

    def _rec(self, method, bearer, params):
        nonce = request_nonce(params)
        if not bearer:
            self.receive(token=None, parsed=False, parse_error="no Authorization", method=method, nonce=nonce)
            return
        try:
            c = jwt.decode(bearer, self._key, algorithms=["RS256"], issuer=self._issuer,
                           options={"verify_aud": False, "require": ["exp", "iss"]})
        except Exception as e:  # noqa: BLE001
            self.receive(token=bearer, parsed=False, parse_error=type(e).__name__, method=method, nonce=nonce)
            return
        act = c.get("act")
        self.receive(subject=c.get("sub"), actor=act.get("sub") if isinstance(act, dict) else None,
                     audience=c.get("aud"), scope=c.get("scope"), token=bearer,
                     issuer=c.get("orig_iss") or c.get("iss"), method=method, nonce=nonce)

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start(); return self

    def stop(self):
        self._srv.shutdown(); self._srv.server_close()

    def by_nonce(self, nonce):
        return [r for r in self.requests if r.get("nonce") == nonce]


# --------------------------------------------------------------- gateway
class Kuadrant:
    """The Istio gateway (reached via the port-forward). The caller sends
    Authorization: Bearer <user JWT> and x-mcp-servername; Authorino validates,
    exchanges at the AS, and injects the exchanged token upstream."""

    def __init__(self, gw_url):
        self.url = gw_url.rstrip("/") + "/"

    def client(self, user_token=None, *, servername=SERVER):
        h = {}
        if user_token:
            h["Authorization"] = f"Bearer {user_token}"
        if servername:
            h["x-mcp-servername"] = servername
        return MCPClient(HTTPTransport(self.url, headers=h))


def as_issue(as_base, sub, *, iss=None, email=None, scope=USER_SCOPE, aud=CALLER_AUD):
    q = {"sub": sub, "aud": aud, "scope": scope}
    for k, v in (("iss", iss), ("email", email)):
        if v:
            q[k] = v
    return _get(f"{as_base}/issue?{urlencode(q)}")["access_token"]


def ident(gw, label, token_fn):
    return Identity(label=label, connect=lambda: gw.client(token_fn()))


def discover_tool(gw, token):
    c = gw.client(token)
    try:
        c.initialize()
        tools = c.list_tools()
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass
    if not tools:
        raise SystemExit("no tools discovered through the Kuadrant gateway")
    return tools[0]["name"]


BASE = None


def save(name, payload):
    runs = os.path.join(_HERE, "runs")
    os.makedirs(runs, exist_ok=True)
    out = os.path.join(runs, f"kuadrant-{name}-{int(time.time())}.json")
    from xid10_litellm_gate import _JWT_RE
    text = json.dumps(payload, indent=2, default=str)
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


# ------------------------------------------------------------------ modes
def mode_delegation(gw, up, as_base, ports, base):
    tool = discover_tool(gw, as_issue(as_base, "alice"))
    n_ex = len(_get(f"{as_base}/exchanges"))
    try:
        rep = run_delegation_probe(
            gw.url,
            ident(gw, "A", lambda: as_issue(as_base, "alice")),
            ident(gw, "B", lambda: as_issue(as_base, "bob")),
            upstream=up, trigger=lambda c: c.call_tool(tool, {}),
            expected_subject_a="alice", expected_subject_b="bob",
            expected_issuer_a=ISSUER, expected_issuer_b=ISSUER)
    except ProbeError as e:
        print(f"INCONCLUSIVE: {redact(e)}")
        raise
    print("CHECKS:", json.dumps(rep.checks))
    fixtures = thin_fixtures(ports["fixture_base"])
    grades = check_grades(rep.checks, fixtures, ("safe",))
    print("CHECK GRADES:", json.dumps(grades))
    save("delegation", {
        **base, "probe": "xid10-delegation", "mode": "delegation", "trigger": "tool",
        "checks": rep.checks, "vulnerable": rep.vulnerable, "failures": rep.failures,
        "summary": redact(rep.summary()), "check_grades": grades,
        "broken_fixtures_in_run": {"fixtures": fixtures, "controls": ["safe"]},
        "recorded_calls": [_call(c) for c in rep.calls],
        "exchange_audience": UPSTREAM_AUD,
        "driver_set_x_mcp_servername": SERVER,
        "x_mcp_servername_note": ("set by this driver as the mcp router would; client-supplied "
                                  "values of this header are NOT graded or reported"),
        "actor_source": "none: Authorino sends no actor_token on the exchange (impersonation)"})


def mode_scope_narrowing(gw, up, as_base, ports, base):
    import xid10_thin_deputy_gate as thin
    fx = ports["fixture_base"]
    broken = thin.run_scope_fixture(as_base, "scope_escalation", controls={},
                                    upstream_port=fx + 2, deputy_port=fx + 3)
    print(f"broken fixture: {broken.summary()}")
    subj = thin.SUBJECT_SCOPE_BROAD + " openid"
    tool = discover_tool(gw, as_issue(as_base, "alice", scope=subj))
    res = run_scope_narrowing_probe(
        gw.url, ident(gw, "A", lambda: as_issue(as_base, "alice", scope=subj)),
        ident(gw, "B", lambda: as_issue(as_base, "bob", scope=subj)), upstream=up,
        trigger=lambda c: c.call_tool(tool, {}), subject_scope=subj,
        configured_scope="openid",
        exchange_lookup=thin.exchange_lookup_http(as_base),
        controls={"broken_fixture_failed": broken.grade == "FAIL"})
    print(res.summary())
    save_checked("scope_narrowing", {
        **res.to_dict(), **base, "mode": "scope_narrowing",
        "gateway_scopes_config": ["openid"],
        "driver_set_x_mcp_servername": SERVER,
        "broken_fixture": {"name": "thin_deputy scope_escalation", "grade": broken.grade,
                           "reason": broken.reason}})


def _call_with_nonce(client_fn, tool, nonce):
    c = client_fn()
    try:
        c.initialize()
        r = c.call_tool(tool, {"nonce": nonce})
        return {"result": redact(json.dumps(r))[:300], "is_error": bool(r.get("isError"))}
    except Exception as e:  # noqa: BLE001
        return {"error": redact(e)[:300], "is_error": True}
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass


def grade_exchange_fail(*, control_reached, fail_reached, caller_errored, broken_fixture_failed):
    if fail_reached:
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
    """The exchange token endpoint (SWITCH) forwards (control), then fails per
    mode. A user token with aud != server NEEDS the exchange, so a failure must
    fail closed. We test every fault mode."""
    tool = discover_tool(gw, as_issue(as_base, "alice"))
    results = {}
    try:
        switch_set(switch, "forward")
        n = make_nonce("ctl")
        ctl = _call_with_nonce(lambda: gw.client(as_issue(as_base, "alice")), tool, n)
        control_reached = any(r.get("authorization") for r in up.by_nonce(n))
        for mode in ("http_500", "bad_body", "no_token", "slow"):
            switch_set(switch, mode)
            nn = make_nonce(mode)
            call = _call_with_nonce(lambda: gw.client(as_issue(as_base, "alice")), tool, nn)
            reached = up.by_nonce(nn)
            # Did the USER's own token reach the upstream? (the failure concern)
            user_leaked = any(r.get("authorization") for r in reached)
            results[mode] = {"caller": call, "reached_upstream": bool(reached),
                             "user_token_reached_upstream": user_leaked,
                             "upstream_calls": [{k: r.get(k) for k in ("method", "authorization")} for r in reached]}
        switch_set(switch, "forward")
        time.sleep(1)
        # broken fall-through fixture (same switch, forwards with no auth on failure)
        fxd = FallThroughDeputy(ports["fixture_base"] + 5, switch_url(switch),
                                f"http://127.0.0.1:{ports['upstream']}/mcp").start()
        try:
            fxc = lambda tok: MCPClient(HTTPTransport(fxd.url, headers={"Authorization": f"Bearer {tok}"}))  # noqa: E731
            fxn = make_nonce("fx_control"); fxfn = make_nonce("fx_fail")
            _call_with_nonce(lambda: fxc(as_issue(as_base, "alice")), "read_note", fxn)
            switch_set(switch, "http_500")
            fx_fail = _call_with_nonce(lambda: fxc(as_issue(as_base, "alice")), "read_note", fxfn)
            switch_set(switch, "forward")
        finally:
            fxd.stop()
        fx_grade = grade_exchange_fail(control_reached=bool(up.by_nonce(fxn)),
                                       fail_reached=bool(up.by_nonce(fxfn)),
                                       caller_errored=fx_fail.get("is_error", False),
                                       broken_fixture_failed=True)
    finally:
        pass
    any_fail_reached = any(v["reached_upstream"] for v in results.values())
    any_user_leak = any(v["user_token_reached_upstream"] for v in results.values())
    grade, label, reason = grade_exchange_fail(
        control_reached=control_reached, fail_reached=any_fail_reached,
        caller_errored=all(v["caller"].get("is_error") for v in results.values()),
        broken_fixture_failed=fx_grade[0] == "FAIL")
    print(f"[{grade}] {label}: {reason}")
    save("exchange_fail", {
        **base, "probe": "exchange_fail", "grade": grade, "label": label, "reason": reason,
        "control": {"reached_upstream": control_reached, "caller": ctl},
        "modes": results,
        "user_token_reached_upstream_any_mode": any_user_leak,
        "note": ("a user token with aud != server needs the exchange; on exchange failure the "
                 "gateway must fail closed. (A token with aud == server is a separate, by-design "
                 "no-exchange pass-through — see notes/kuadrant-aud-passthrough.md — not an "
                 "exchange-failure case, so it is not exercised here.)"),
        "broken_fixture": {"name": "fall-through deputy (forwards with no auth on exchange failure)",
                           "grade": fx_grade[0], "reason": fx_grade[2]},
        "driver_set_x_mcp_servername": SERVER})


# switchable endpoint helpers (the SwitchableTokenEndpoint runs on the host; the
# AuthPolicy's exchange URL points at it for exchange_fail)
def switch_set(switch, mode):
    urllib.request.urlopen(urllib.request.Request(f"{switch}/mode?m={mode}", data=b"", method="POST"), timeout=5).read()


def switch_url(switch):
    return f"{switch}/token"


def require():
    as_base = os.environ.get("AS_BASE") or ""
    u = urlparse(as_base)
    if u.hostname != "127.0.0.1" or not u.port:
        raise SystemExit("ERROR: AS_BASE must be http://127.0.0.1:<46xx>")
    os.environ["_AS_PORT"] = str(u.port)
    ports = {"as": _port("_AS_PORT"), "upstream": _port("UPSTREAM_PORT"), "fixture_base": _port("FIXTURE_BASE")}
    gw_url = os.environ.get("GW_URL") or sys.exit("ERROR: set GW_URL (the gateway port-forward)")
    return as_base.rstrip("/"), gw_url, ports


def main():
    as_base, gw_url, ports = require()
    mode = os.environ.get("KUA_MODE", "delegation")
    up = KuaRecorder(ports["upstream"], _get(f"{as_base}/jwks"), ISSUER).start()
    gw = Kuadrant(gw_url)
    base = {"gateway": "kuadrant", "gateway_label": LABEL,
            "gateway_version": "Kuadrant operator 1.6.0 (Authorino v0.28.0, mcp-controller v1.0.2)",
            "mode_note": "option (b): Authorino exchange on a direct HTTPRoute; mcp router/broker not in path",
            "install": "kind st-kuadrant; Istio 1.27.0; Gateway API v1.4.1; Kuadrant 1.6.0 (Helm); loopback only",
            "authpolicy": "integration/kuadrant/kuadrant-mcps-auth-policy.yaml (sample, minimally adapted)",
            "endpoints": {"as_base": as_base, "gw_url": gw_url, **ports},
            "caller_auth": "Authorization: Bearer <user JWT (openid scope)>; x-mcp-servername set by the driver"}
    switch = os.environ.get("SWITCH_URL")  # e.g. http://127.0.0.1:4613
    try:
        if mode == "delegation":
            mode_delegation(gw, up, as_base, ports, base)
        elif mode == "scope_narrowing":
            mode_scope_narrowing(gw, up, as_base, ports, base)
        elif mode == "exchange_fail":
            if not switch:
                raise SystemExit("exchange_fail needs SWITCH_URL (host switchable token endpoint) "
                                 "and the AuthPolicy pointed at it")
            mode_exchange_fail(gw, up, as_base, ports, base, switch)
        else:
            raise SystemExit(f"unknown KUA_MODE {mode}")
    finally:
        up.stop()


if __name__ == "__main__":
    main()
