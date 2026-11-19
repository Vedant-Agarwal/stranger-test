"""Login server misbehaves: grading guards (each false-LEAK / false-OK case named
in strangertest/login_faults.py) and the harness end to end against a local
fail-closed deputy and the fall-through fixture. Standard library only."""

import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from strangertest.login_faults import (FAULT_MODES, classify_token, grade_login_fault,
                                       worst)

_INTEGRATION = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "integration")
if _INTEGRATION not in sys.path:
    sys.path.insert(0, _INTEGRATION)


def call(kind="exchanged", sub="p", iss="https://as.test", parsed=True, nonce="n-probe"):
    return {"token_kind": kind, "subject": sub, "issuer": iss, "parsed": parsed,
            "nonce": nonce}


def grade(**kw):
    args = dict(probe_calls=[], unattributed_calls=[], control_reached_authenticated=True,
                caller_succeeded=False, fault_hits=1, expected_subject="p",
                expected_issuer="https://as.test", broken_fixture_failed=True)
    args.update(kw)
    return grade_login_fault(**args)


class GradeTests(unittest.TestCase):
    def test_safe_run_is_ok(self):
        self.assertEqual(grade()[0], "OK")

    def test_no_authorization_is_fail(self):
        g = grade(probe_calls=[call("none", parsed=False, sub=None)])
        self.assertEqual(g[:2], ("FAIL", "forwarded_unauthenticated"))

    def test_inbound_token_is_fail(self):
        self.assertEqual(grade(probe_calls=[call("inbound")])[:2],
                         ("FAIL", "forwarded_inbound_token"))

    def test_wrong_identity_is_fail(self):
        self.assertEqual(grade(probe_calls=[call(sub="someone-else")])[:2],
                         ("FAIL", "wrong_identity"))

    # F1
    def test_unattributed_no_auth_call_is_not_blamed(self):
        g = grade(unattributed_calls=[call("none", nonce=None)])
        self.assertEqual(g[0], "INCONCLUSIVE")

    # F2
    def test_delayed_control_call_is_the_controls(self):
        # A control call landing in the window carries the control's nonce; the
        # gate puts it under the control, never under probe_calls -> no FAIL.
        self.assertEqual(grade(probe_calls=[])[0], "OK")

    # F3
    def test_authenticated_arrival_is_observation_not_fail(self):
        g = grade(probe_calls=[call("exchanged")], caller_succeeded=True)
        self.assertEqual(g[:2], ("OBSERVATION", "reached_upstream_authenticated"))

    # F4
    def test_failed_control_never_fails(self):
        for kw in ({"control_reached_authenticated": False}, {"broken_fixture_failed": False},
                   {"fault_hits": 0}, {"caller_succeeded": None}):
            self.assertEqual(grade(**kw)[0], "INCONCLUSIVE", kw)

    # O1
    def test_control_not_reached_is_inconclusive(self):
        self.assertEqual(grade(control_reached_authenticated=False)[0], "INCONCLUSIVE")

    # O2
    def test_fault_not_exercised_is_inconclusive(self):
        self.assertIn("not exercised", grade(fault_hits=0)[2])
        # not observable (unreachable) does not block OK, and says so
        g = grade(fault_hits=None)
        self.assertEqual(g[0], "OK")
        self.assertIn("not observable", g[2])

    # O3
    def test_caller_success_without_upstream_is_inconclusive(self):
        self.assertEqual(grade(caller_succeeded=True)[0], "INCONCLUSIVE")

    # O4
    def test_late_unauthenticated_arrival_fails(self):
        # the caller already got an error; the call arrived later, unauthenticated
        g = grade(probe_calls=[call("none", parsed=False)], caller_succeeded=False)
        self.assertEqual(g[0], "FAIL")

    # O5
    def test_nonce_stripped_is_inconclusive(self):
        g = grade(control_reached_authenticated=False,
                  unattributed_calls=[call("exchanged", nonce=None)])
        self.assertEqual(g[0], "INCONCLUSIVE")

    # O6
    def test_broken_fixture_not_failed_blocks_ok(self):
        self.assertEqual(grade(broken_fixture_failed=False)[0], "INCONCLUSIVE")

    # O7
    def test_unparsed_token_is_inconclusive(self):
        self.assertEqual(grade(probe_calls=[call("other", parsed=False)])[0], "INCONCLUSIVE")

    def test_seen_leak_not_downgraded_by_controls(self):
        g = grade(probe_calls=[call("none", parsed=False)], control_reached_authenticated=False,
                  broken_fixture_failed=False, fault_hits=0)
        self.assertEqual(g[0], "FAIL")

    def test_classify_token(self):
        self.assertEqual(classify_token(None, inbound_fps=set(), issued_fps=set()), "none")
        self.assertEqual(classify_token("a", inbound_fps={"a"}, issued_fps={"a"}), "inbound")
        self.assertEqual(classify_token("b", inbound_fps=set(), issued_fps={"b"}), "exchanged")
        self.assertEqual(classify_token("c", inbound_fps=set(), issued_fps=set()), "other")

    def test_worst(self):
        self.assertEqual(worst(["OK", "OBSERVATION"]), "OBSERVATION")
        self.assertEqual(worst(["OK", "INCONCLUSIVE", "FAIL"]), "FAIL")


# ------------------------------------------------------------ harness, live
class _Srv(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class FakeAS:
    """/token issues alg:none tokens for the subject; /exchanges lists issued fps."""

    def __init__(self):
        from login_faults_harness import fp
        from strangertest.practice_delegation_http import decode_token, encode_token
        self.issued = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _j(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                self._j(200, [{"issued_fp": f} for f in outer.issued])

            def do_POST(self):
                from urllib.parse import parse_qs
                q = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
                sub = decode_token(q.get("subject_token", [""])[0]).get("sub")
                tok = encode_token({"sub": sub, "aud": "https://upstream.test/mcp",
                                    "n": len(outer.issued)})
                outer.issued.append(fp(tok))
                self._j(200, {"access_token": tok, "token_type": "Bearer"})

        self.srv = _Srv(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def fail_closed_deputy(token_url, upstream_url, timeout):
    """A correct deputy: on any exchange problem it returns an error, never
    calls the upstream."""
    import json as _j

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _j(self, obj):
            b = _j.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            from urllib.parse import urlencode
            msg = _j.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            m, mid = msg.get("method"), msg.get("id")
            if mid is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if m == "initialize":
                self._j({"jsonrpc": "2.0", "id": mid, "result": {
                    "protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {}}})
                return
            auth = self.headers.get("Authorization", "")[7:]
            try:
                body = urlencode({"grant_type": "x", "subject_token": auth}).encode()
                with urllib.request.urlopen(urllib.request.Request(
                        token_url, data=body, method="POST"), timeout=timeout) as r:
                    tok = _j.loads(r.read())["access_token"]
            except Exception as e:  # noqa: BLE001  -- fails closed
                self._j({"jsonrpc": "2.0", "id": mid,
                         "error": {"code": -32000, "message": f"exchange failed: {type(e).__name__}"}})
                return
            req = urllib.request.Request(upstream_url, data=_j.dumps(msg).encode(), headers={
                "Content-Type": "application/json", "Authorization": f"Bearer {tok}"})
            with urllib.request.urlopen(req, timeout=10) as r:
                out = _j.loads(r.read())
            self._j({"jsonrpc": "2.0", "id": mid, "result": out.get("result")})

    srv = _Srv(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _free_46xx(n):
    import socket
    out = []
    for port in range(4650, 4700):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
            out.append(port)
        except OSError:
            continue
        finally:
            s.close()
        if len(out) == n:
            return out
    raise unittest.SkipTest("no free 46xx ports")


class HarnessTests(unittest.TestCase):
    """run_fault_modes end to end: a fail-closed deputy grades OK in every mode,
    and the fall-through fixture FAILs every mode through the same endpoint."""

    @classmethod
    def setUpClass(cls):
        from login_faults_harness import FaultyTokenEndpoint
        from strangertest.practice_concurrency_http import MarkerUpstream
        cls.p_ep, cls.p_fx = _free_46xx(2)
        cls.as_ = FakeAS()
        cls.up = MarkerUpstream("https://upstream.test/mcp", {}, hold_seconds=0).start()
        cls.ep = FaultyTokenEndpoint(cls.p_ep, cls.as_.base, slow_seconds=1.5).start()
        cls.dep = fail_closed_deputy(cls.ep.url, cls.up.url, timeout=0.5)

    @classmethod
    def tearDownClass(cls):
        cls.dep.shutdown()
        cls.dep.server_close()
        cls.ep.stop()
        cls.up.stop()
        cls.as_.stop()

    def test_fail_closed_ok_and_fixture_fails_every_mode(self):
        from login_faults_harness import FallThroughDeputy, run_fault_modes
        from strangertest.mcp_client import MCPClient
        from strangertest.practice_delegation_http import encode_token
        from strangertest.transports import HTTPTransport

        def mk(prefix):
            return {f"{k}-{m}": {"token": encode_token({"sub": f"{prefix}{k}{m}"}),
                                 "subject": f"{prefix}{k}{m}", "issuer": None}
                    for m in FAULT_MODES for k in ("ctl", "p")}

        def drive(url):
            def go(token, nonce, timeout):
                c = MCPClient(HTTPTransport(url, headers={"Authorization": f"Bearer {token}"},
                                            timeout=timeout))
                try:
                    c.initialize()
                    r = c.call_tool("read_note", {"nonce": nonce})
                    return {"succeeded": not r.get("isError"), "detail": "ok"}
                except Exception as e:  # noqa: BLE001
                    return {"succeeded": False, "detail": type(e).__name__}
                finally:
                    c.close()
            return go

        fx = FallThroughDeputy(self.p_fx, self.ep.url, self.up.url, exchange_timeout=0.5).start()
        try:
            out = run_fault_modes(
                modes=FAULT_MODES, endpoint=self.ep, upstream=self.up, as_base=self.as_.base,
                users=mk("g"), call=drive(f"http://127.0.0.1:{self.dep.server_address[1]}/mcp"),
                fixture_call=drive(fx.url), fixture_users=mk("f"), caller_timeout=10,
                redact=str, log=lambda *a: None, settle_seconds=0.3)
        finally:
            fx.stop()
        for mode, r in out["modes"].items():
            self.assertEqual(r["grade"], "OK", (mode, r["reason"]))
            self.assertEqual(r["broken_fixture"]["grade"], "FAIL", mode)
            self.assertEqual(r["broken_fixture"]["label"], "forwarded_unauthenticated", mode)
        self.assertIsNone(out["modes"]["unreachable"]["login_server_hits_in_fault"])
        self.assertGreater(out["modes"]["http_500"]["login_server_hits_in_fault"], 0)

    def test_unreachable_really_refuses(self):
        self.ep.set_mode("unreachable")
        try:
            with self.assertRaises(urllib.error.URLError) as cm:
                urllib.request.urlopen(urllib.request.Request(self.ep.url, data=b"x"), timeout=2)
            self.assertIsInstance(cm.exception.reason, ConnectionRefusedError)
        finally:
            self.ep.set_mode("forward")

    def test_malformed_bodies(self):
        for mode, check in (("malformed_not_json", lambda b: self.assertRaises(
                ValueError, json.loads, b)),
                ("malformed_no_token", lambda b: self.assertNotIn("access_token", json.loads(b)))):
            self.ep.set_mode(mode)
            try:
                with urllib.request.urlopen(urllib.request.Request(self.ep.url, data=b"a=b"),
                                            timeout=5) as r:
                    self.assertEqual(r.status, 200)
                    check(r.read())
            finally:
                self.ep.set_mode("forward")

    def test_refuses_ports_outside_46xx(self):
        from login_faults_harness import FaultyTokenEndpoint
        for bad in (4000, 4444, 8790, 4590):
            with self.assertRaises(SystemExit):
                FaultyTokenEndpoint(bad, "http://127.0.0.1:1")


if __name__ == "__main__":
    unittest.main()
