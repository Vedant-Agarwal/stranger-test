"""LOCAL fixture for the concurrent-identities probe: a deputy whose per-user
state is shared across concurrent requests (``racy``), and a correct one (``safe``).

* :class:`MarkerUpstream` -- an MCP-ish upstream (JSON-RPC over HTTP) that reads
  the caller's identity from the bearer token and answers each tools/call with
  THAT identity's note (its marker). Records nonce, identity and overlap.
* :func:`build_concurrency_deputy` -- an MCP server whose ``read_note`` tool makes
  an on-behalf-of call upstream. ``safe`` keeps the caller in a local variable.
  ``racy`` stores it in one shared slot, waits (as if exchanging the token), then
  reads the slot back: correct one request at a time, wrong under concurrency.

Tokens are unsigned JWT-shaped blobs, as in ``practice_delegation_http``. Never
expose these on a network; loopback only.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from .concurrency import InflightMixin
from .delegate import MockUpstream, request_nonce
from .practice_delegation_http import decode_token, encode_token

AGENT = "stranger-test-agent"


class _Srv(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256


def _send(handler, obj, code=200):
    body = json.dumps(obj).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class MarkerUpstream(InflightMixin, MockUpstream):
    """Answers tools/call with the note of the token's subject."""

    def __init__(self, audience: str, notes: Dict[str, str], *, hold_seconds: float = 0.05,
                 port: int = 0):
        MockUpstream.__init__(self, audience)
        self._inflight_init()
        self.hold_seconds = hold_seconds
        self.notes = dict(notes)
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else None
                claims = decode_token(token) if token else {}
                params = msg.get("params") or {}
                outer.enter()
                try:
                    act = claims.get("act")
                    outer.receive(subject=claims.get("sub"), audience=claims.get("aud"),
                                  actor=act.get("sub") if isinstance(act, dict) else None,
                                  scope=claims.get("scope"), token=token,
                                  parsed=bool(claims), method=msg.get("method", "tools/call"),
                                  nonce=request_nonce(params))
                    note = outer.notes.get(claims.get("sub"), "no-note")
                finally:
                    outer.leave()
                _send(self, {"jsonrpc": "2.0", "id": msg.get("id"), "result": {
                    "content": [{"type": "text", "text": f"note={note}"}], "isError": False}})

        self._srv = _Srv(("127.0.0.1", port), H)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._srv.server_address[1]}/mcp"

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


def build_concurrency_deputy(mode: str, upstream_url: str, audience: str, *,
                             exchange_seconds: float = 0.03, port: int = 0) -> ThreadingHTTPServer:
    if mode not in ("safe", "racy"):
        raise ValueError(mode)
    shared: Dict[str, Optional[str]] = {"caller": None}   # racy: ONE slot for everyone
    counter = {"n": 0}
    lock = threading.Lock()

    def mint(sub: str) -> str:
        with lock:
            counter["n"] += 1
            n = counter["n"]
        return encode_token({"sub": sub, "act": {"sub": AGENT}, "aud": audience,
                             "scope": "read:notes", "n": n})

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            m, mid = msg.get("method"), msg.get("id")
            if mid is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if m == "initialize":
                _send(self, {"jsonrpc": "2.0", "id": mid, "result": {
                    "protocolVersion": "2026-07-28", "capabilities": {"tools": {}},
                    "serverInfo": {"name": f"concurrency-{mode}"}}})
                return
            if m == "tools/list":
                _send(self, {"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                    {"name": "read_note", "inputSchema": {"type": "object"}}]}})
                return
            if m != "tools/call":
                _send(self, {"jsonrpc": "2.0", "id": mid,
                             "error": {"code": -32601, "message": "no"}})
                return
            auth = self.headers.get("Authorization", "")
            caller = decode_token(auth[7:]).get("sub") if auth.startswith("Bearer ") else None
            if mode == "racy":
                shared["caller"] = caller          # BROKEN: per-user state in a shared slot
                time.sleep(exchange_seconds)       # ...the token exchange takes a moment...
                token = mint(shared["caller"])     # ...and reads back whoever wrote last
            else:
                time.sleep(exchange_seconds)
                token = mint(caller)
            req = urllib.request.Request(upstream_url, data=json.dumps(
                {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                 "params": msg.get("params") or {}}).encode(), method="POST",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=30) as r:
                out = json.loads(r.read())
            _send(self, {"jsonrpc": "2.0", "id": mid, "result": out.get("result")})

    return _Srv(("127.0.0.1", port), H)


def run_concurrency_fixture(pairs: int = 50, *, deputy_ports=(0, 0), upstream_port: int = 0,
                            redact=str) -> Dict[str, Any]:
    """In-run proof for the concurrent probe: the RACY deputy must FAIL it while
    PASSING the one-at-a-time delegation probe; the SAFE deputy must not FAIL it.
    Returns a plain dict for the saved run."""
    from .concurrency import make_markers, run_concurrent_probe
    from .delegate import run_delegation_probe
    from .mcp_client import MCPClient
    from .probe import Identity
    from .transports import HTTPTransport

    aud = "https://upstream.test/mcp"
    markers = make_markers()
    up = MarkerUpstream(aud, {"alice": markers["A"], "bob": markers["B"]},
                        port=upstream_port).start()
    out: Dict[str, Any] = {"pairs": pairs}
    servers = []
    try:
        for mode, port in zip(("racy", "safe"), deputy_ports):
            srv = build_concurrency_deputy(mode, up.url, aud, port=port)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            servers.append(srv)
            url = f"http://127.0.0.1:{srv.server_address[1]}/mcp"

            def ident(label, sub, url=url):
                tok = encode_token({"sub": sub})
                return Identity(label=label, connect=lambda: MCPClient(HTTPTransport(
                    url, headers={"Authorization": f"Bearer {tok}"})))

            serial = run_delegation_probe(
                url, ident("A", "alice"), ident("B", "bob"), upstream=up,
                trigger=lambda c: c.call_tool("read_note", {}),
                expected_subject_a="alice", expected_subject_b="bob", authorized=True,
                authorization_note="local practice fixture")
            conc = run_concurrent_probe(
                url, ident("A", "alice"), ident("B", "bob"), upstream=up,
                trigger=lambda c, n: c.call_tool("read_note", {"nonce": n}),
                markers=markers, identities={"A": (None, "alice"), "B": (None, "bob")},
                pairs=pairs, fixture=None, settle_seconds=0.2, redact=redact,
                authorized=True, authorization_note="local practice fixture")
            out[mode] = {"serial_vulnerable": serial.vulnerable,
                         "serial_failures": serial.failures,
                         "concurrent_grade": conc.grade, "concurrent_label": conc.label,
                         "concurrent_reason": conc.reason, "max_inflight": conc.max_inflight}
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()
        up.stop()
    racy, safe = out.get("racy", {}), out.get("safe", {})
    out["concurrent_grade"] = racy.get("concurrent_grade")
    out["serial_vulnerable"] = racy.get("serial_vulnerable")
    out["safe_concurrent_not_fail"] = safe.get("concurrent_grade") != "FAIL"
    out["proven"] = (racy.get("concurrent_grade") == "FAIL"
                     and racy.get("serial_vulnerable") is False
                     and out["safe_concurrent_not_fail"])
    return out
