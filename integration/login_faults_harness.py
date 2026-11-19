"""Shared harness for the "login server misbehaves" scenario (all three gates).

* :class:`FaultyTokenEndpoint` -- sits where the gateway expects its token
  endpoint. In ``forward`` it relays each POST to the real local AS; in a fault
  mode (``strangertest.login_faults.FAULT_MODES``) it answers HTTP 500, stops
  listening (connection refused), holds the request past a normal timeout, or
  answers HTTP 200 with a body that is not JSON / JSON with no access_token.
  It counts requests per state and keeps only form-parameter NAMES.
* :class:`FallThroughDeputy` -- the BROKEN fixture: a minimal MCP deputy that
  exchanges the caller's token and, when the exchange fails in ANY way, forwards
  the tools/call upstream with no Authorization. Every OK must come with this
  fixture FAILING the same check, through the same faulty endpoint, in the run.
* :func:`run_fault_modes` -- the per-mode procedure every gate uses (control,
  fault, probe, settle, fixture, grade).

Loopback only. Tokens are fingerprinted; nothing here stores a token.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlencode

from strangertest.delegate import make_nonce
from strangertest.login_faults import (FAULT_MODES, TOKEN_EXCHANGED, TOKEN_NONE, classify_token,
                                       grade_login_fault, worst)

FORBIDDEN_PORTS = {4000, 4444, 8790}
PORT_RANGE = range(4600, 4700)
UPSTREAM_VERSION = "2025-11-25"


def fp(t):
    return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else None


def port_46xx(port: int, name: str) -> int:
    if port in FORBIDDEN_PORTS or port not in PORT_RANGE:
        raise SystemExit(f"ERROR: refusing port {port} for {name}: must be 4600-4699, "
                         f"never {sorted(FORBIDDEN_PORTS)}")
    return port


class _HTTP4(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class FaultyTokenEndpoint:
    """A token endpoint that can be told to misbehave (see module docstring)."""

    def __init__(self, port: int, as_base: str, *, slow_seconds: float = 45.0):
        self.port = port_46xx(port, "faulty token endpoint")
        self.as_base = as_base.rstrip("/")
        self.slow_seconds = slow_seconds
        self.mode = "forward"
        self.hits: Dict[str, int] = {}
        self.requests: List[Dict[str, Any]] = []
        self.pending = 0
        self._lock = threading.Lock()
        self._srv: Optional[_HTTP4] = None
        self.url = f"http://127.0.0.1:{port}/token"
        self.host = f"127.0.0.1:{port}"

    # -- lifecycle --------------------------------------------------------
    def _handler(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _raw(self, code, body: bytes, ctype="application/json"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                params = parse_qs(body.decode(errors="replace"))
                mode = outer.mode
                rec = {"state": mode, "t": time.time(),
                       "grant_type": (params.get("grant_type") or [None])[0],
                       "param_names": sorted(params.keys()),
                       "basic_auth": self.headers.get("Authorization", "")[:6].lower() == "basic "}
                with outer._lock:
                    outer.hits[mode] = outer.hits.get(mode, 0) + 1
                    outer.requests.append(rec)
                try:
                    if mode == "http_500":
                        self._raw(500, b'{"error":"server_error"}')
                    elif mode == "malformed_not_json":
                        self._raw(200, b"<html><body>login server maintenance</body></html>",
                                  "text/html")
                    elif mode == "malformed_no_token":
                        self._raw(200, b'{"token_type":"Bearer","expires_in":3600}')
                    elif mode == "slow":
                        with outer._lock:
                            outer.pending += 1
                        try:
                            time.sleep(outer.slow_seconds)
                            code, out = outer._forward(body, self.headers)
                            self._raw(code, out)
                            rec["slow_reply"] = "delivered"
                        except (BrokenPipeError, ConnectionResetError):
                            rec["slow_reply"] = "client gone"
                        finally:
                            with outer._lock:
                                outer.pending -= 1
                    else:
                        code, out = outer._forward(body, self.headers)
                        self._raw(code, out)
                except (BrokenPipeError, ConnectionResetError):
                    rec["reply"] = "client gone"
        return H

    def _forward(self, body, headers):
        h = {"Content-Type": headers.get("Content-Type", "application/x-www-form-urlencoded")}
        if headers.get("Authorization"):
            h["Authorization"] = headers["Authorization"]
        req = urllib.request.Request(f"{self.as_base}/token", data=body, method="POST", headers=h)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read() or b"{}"

    def _listen(self):
        self._srv = _HTTP4(("127.0.0.1", self.port), self._handler())
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def _close(self):
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None

    def start(self):
        self._listen()
        return self

    def stop(self):
        self._close()

    def set_mode(self, mode: str) -> None:
        if mode not in ("forward",) + FAULT_MODES:
            raise ValueError(mode)
        if mode == "unreachable":
            self._close()           # nothing listens: connection refused
        elif self._srv is None:
            self._listen()
        self.mode = mode

    def fault_hits(self, mode: str) -> Optional[int]:
        if mode == "unreachable":
            return None             # a refused connection never reaches us
        return self.hits.get(mode, 0)

    def wait_idle(self, cap: float) -> None:
        deadline = time.monotonic() + cap
        while self.pending and time.monotonic() < deadline:
            time.sleep(0.5)


class FallThroughDeputy:
    """BROKEN fixture: exchanges the caller's token at ``token_url``; on ANY
    failure (HTTP error, refused, timeout, unparseable body, no token) it
    forwards the tools/call to the upstream with NO Authorization."""

    def __init__(self, port, token_url, upstream_url, *, exchange_timeout=10):
        self.url = f"http://127.0.0.1:{port_46xx(port, 'fall-through fixture')}/mcp"
        outer = self
        self.exchange_errors: List[str] = []

        def upstream_call(msg, token):
            h = {"Content-Type": "application/json", "Accept": "application/json"}
            if token:
                h["Authorization"] = f"Bearer {token}"
            init = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": UPSTREAM_VERSION, "capabilities": {},
                "clientInfo": {"name": "fallthrough", "version": "0"}}}
            with urllib.request.urlopen(urllib.request.Request(
                    upstream_url, data=json.dumps(init).encode(), headers=h), timeout=10) as r:
                sid = r.headers.get("Mcp-Session-Id")
            h2 = dict(h, **({"Mcp-Session-Id": sid} if sid else {}),
                      **{"MCP-Protocol-Version": UPSTREAM_VERSION})
            with urllib.request.urlopen(urllib.request.Request(
                    upstream_url, data=json.dumps(msg).encode(), headers=h2), timeout=10) as r:
                return json.loads(r.read())

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, obj):
                b = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_POST(self):
                msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                m, mid = msg.get("method"), msg.get("id")
                if mid is None:
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if m == "initialize":
                    self._json({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": UPSTREAM_VERSION, "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fallthrough", "version": "0"}}})
                    return
                if m == "tools/list":
                    self._json({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                        {"name": "read_note", "inputSchema": {"type": "object"}}]}})
                    return
                if m == "tools/call":
                    auth = self.headers.get("Authorization", "")
                    subject = auth[7:] if auth.startswith("Bearer ") else ""
                    token = None
                    body = urlencode({
                        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                        "subject_token": subject, "audience": "https://upstream.test/mcp",
                        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"}).encode()
                    try:
                        with urllib.request.urlopen(urllib.request.Request(
                                token_url, data=body, method="POST"),
                                timeout=exchange_timeout) as r:
                            token = json.loads(r.read()).get("access_token")
                    except Exception as e:  # noqa: BLE001  -- BROKEN: falls through
                        outer.exchange_errors.append(type(e).__name__)
                        token = None
                    out = upstream_call(msg, token)
                    self._json({"jsonrpc": "2.0", "id": mid, "result": out.get("result")})
                    return
                self._json({"jsonrpc": "2.0", "id": mid,
                            "error": {"code": -32601, "message": "no"}})

        self._srv = _HTTP4(("127.0.0.1", port), H)

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


def _exchanges(as_base):
    with urllib.request.urlopen(f"{as_base}/exchanges", timeout=10) as r:
        return json.loads(r.read())


def _graded(calls):
    return [c for c in calls if c.method in ("tools/call", "resources/read")]


def _call_view(c, inbound_fps, issued_fps):
    tfp = fp(c.token) if c.token and not str(c.token).startswith("sha256:") else c.token
    return {"method": c.method, "nonce": c.nonce, "token": tfp,
            "token_kind": classify_token(tfp, inbound_fps=inbound_fps, issued_fps=issued_fps),
            "parsed": c.parsed, "subject": c.subject, "issuer": c.issuer, "actor": c.actor,
            "parse_error": (c.parse_error or "")[:120] if not c.parsed else None}


def run_fault_modes(
    *,
    modes,
    endpoint: FaultyTokenEndpoint,
    upstream,
    as_base: str,
    users: Dict[str, Dict[str, Any]],
    call: Callable[[str, str, float], Dict[str, Any]],
    fixture_call: Callable[[str, str, float], Dict[str, Any]],
    fixture_users: Dict[str, Dict[str, Any]],
    caller_timeout: float,
    redact: Callable[[Any], str],
    log=print,
    settle_seconds: float = 3.0,
) -> Dict[str, Any]:
    """Run every mode in ``modes``; return {"modes": {mode: result}, "grade": worst}.

    ``users[f"ctl-{mode}"]`` / ``users[f"p-{mode}"]``: {"token", "subject",
    "issuer"} -- fresh, distinct users per mode (no cache can hide a fault).
    ``call(token, nonce, timeout)`` drives one tools/call through the gateway
    and returns {"succeeded", "detail"}; ``fixture_call`` the same through the
    fall-through fixture (which uses ``fixture_users``)."""
    inbound_fps = {fp(u["token"]) for u in list(users.values()) + list(fixture_users.values())}
    results: Dict[str, Any] = {}
    for mode in modes:
        log(f"--- login server fault: {mode} ---")
        nonces = {k: make_nonce(f"{k}-{mode}") for k in ("ctl", "probe", "fx_ctl", "fx_probe")}
        known = set(nonces.values())
        ctl_u, probe_u = users[f"ctl-{mode}"], users[f"p-{mode}"]
        fctl_u, fprobe_u = fixture_users[f"ctl-{mode}"], fixture_users[f"p-{mode}"]

        endpoint.set_mode("forward")
        start = len(upstream.calls)
        ctl = call(ctl_u["token"], nonces["ctl"], 30.0)
        endpoint.set_mode(mode)
        t0 = time.monotonic()
        probe = call(probe_u["token"], nonces["probe"], caller_timeout)
        elapsed = round(time.monotonic() - t0, 2)
        hits = endpoint.fault_hits(mode)
        # Settle: late arrivals (a slow reply landing after the caller gave up,
        # a gateway retry) must be seen before grading.
        if mode == "slow":
            endpoint.wait_idle(cap=endpoint.slow_seconds * 4 + 30)
        time.sleep(settle_seconds)
        endpoint.set_mode("forward")
        window = _graded(upstream.calls[start:])

        # Broken fixture through the SAME faulty endpoint and the same upstream.
        fstart = len(upstream.calls)
        fx_ctl = fixture_call(fctl_u["token"], nonces["fx_ctl"], 30.0)
        endpoint.set_mode(mode)
        fx_probe = fixture_call(fprobe_u["token"], nonces["fx_probe"], caller_timeout)
        if mode == "slow":
            endpoint.wait_idle(cap=endpoint.slow_seconds + 30)
        time.sleep(settle_seconds)
        endpoint.set_mode("forward")
        fwindow = _graded(upstream.calls[fstart:])

        issued = {r.get("issued_fp") for r in _exchanges(as_base) if r.get("issued_fp")}

        def view(calls):
            return [_call_view(c, inbound_fps, issued) for c in calls]

        by = {k: view([c for c in window + fwindow if c.nonce == n]) for k, n in nonces.items()}
        unattributed = view([c for c in window if c.nonce not in known])
        funattributed = view([c for c in fwindow if c.nonce not in known])

        def ctl_ok(calls, user):
            return any(c["token_kind"] == TOKEN_EXCHANGED and c["parsed"]
                       and c["subject"] == user["subject"] for c in calls)

        fx_grade = grade_login_fault(
            probe_calls=by["fx_probe"], unattributed_calls=funattributed,
            control_reached_authenticated=ctl_ok(by["fx_ctl"], fctl_u),
            caller_succeeded=fx_probe.get("succeeded"), fault_hits=endpoint.fault_hits(mode),
            expected_subject=fprobe_u["subject"], expected_issuer=fprobe_u.get("issuer"),
            broken_fixture_failed=True)
        grade = grade_login_fault(
            probe_calls=by["probe"], unattributed_calls=unattributed,
            control_reached_authenticated=ctl_ok(by["ctl"], ctl_u),
            caller_succeeded=probe.get("succeeded"), fault_hits=hits,
            expected_subject=probe_u["subject"], expected_issuer=probe_u.get("issuer"),
            broken_fixture_failed=fx_grade[0] == "FAIL")
        log(f"[{grade[0]}] {mode}: {grade[1]} -- {grade[2]}")
        log(f"   fixture: [{fx_grade[0]}] {fx_grade[1]}")
        probe_reached = by["probe"]
        results[mode] = {
            "grade": grade[0], "label": grade[1], "reason": grade[2],
            "nonces": nonces,
            "control": {"user": ctl_u["subject"], "caller": ctl, "upstream_calls": by["ctl"]},
            "probe": {"user": probe_u["subject"], "caller": probe, "caller_elapsed_s": elapsed,
                      "upstream_calls": probe_reached,
                      "reached_upstream": bool(probe_reached),
                      "reached_without_authorization": any(
                          c["token_kind"] == TOKEN_NONE for c in probe_reached)},
            "login_server_hits_in_fault": hits,
            "unattributed_calls_in_window": unattributed,
            "broken_fixture": {"name": "fall-through deputy (forwards with no Authorization "
                                       "when the exchange fails in any way)",
                               "grade": fx_grade[0], "label": fx_grade[1], "reason": fx_grade[2],
                               "control": fx_ctl, "probe": fx_probe,
                               "upstream_calls": by["fx_probe"]},
        }
    endpoint.set_mode("forward")
    return {"modes": results, "grade": worst([r["grade"] for r in results.values()]),
            "token_endpoint_requests": [
                {k: r.get(k) for k in ("state", "grant_type", "param_names", "basic_auth",
                                       "slow_reply", "reply")} for r in endpoint.requests],
            "slow_seconds": endpoint.slow_seconds, "caller_timeout_s": caller_timeout}
