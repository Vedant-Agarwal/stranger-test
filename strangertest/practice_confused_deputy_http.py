"""LOCAL HTTP harness for the confused-deputy / token-passthrough probe.

A single-process MCP "deputy" server that acts on a caller's behalf toward an
upstream it is pointed at. It exposes two tools:

* ``benign_upstream``  — in EVERY mode, a faithful on-behalf-of call: mint a
  fresh token for the upstream carrying the caller's identity (the positive
  control the probe uses to prove the deputy can reach the upstream at all).
* ``call_upstream``    — the sensitive on-behalf-of call under test; what it does
  depends on ``mode``.

Modes:

* ``"safe"``          — a proper (RFC 8693-style) exchange: a fresh token whose
  ``sub`` is the caller, ``act`` names the agent, ``aud`` is THIS upstream, scope
  narrowed. -> OK (exchanged).
* ``"safe_refuse"``   — refuses the sensitive request (no upstream call); the
  benign control still works. -> OK (refused).
* ``"leaky"``         — token passthrough: forwards the caller's INBOUND token to
  the upstream unchanged. Its audience is the gateway's own id, never this
  upstream's. -> FAIL (token_passthrough).
* ``"own_authority"`` — reaches for the deputy's OWN static service-account
  credential (a different ``sub``, a broad scope) instead of refusing the
  caller's under-scoped request. -> FAIL (own_authority).
* ``"wrong_audience"``— exchanges the caller's identity faithfully but mints the
  token for a DIFFERENT upstream. -> FAIL (wrong_audience).

Tokens are unsigned, JWT-shaped ``alg:none`` blobs (``header.payload.sig``);
decoding just reads the payload. The caller's inbound token is one too, minted
for the gateway's own audience (see :func:`make_caller_token`) — exactly a token
that was NOT issued for the upstream, which is why forwarding it is a leak.

NEVER expose any of this on a network. The upstream recorder is reused from
:mod:`strangertest.practice_delegation_http`.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

from .practice_delegation_http import (  # reused, not modified
    HTTPMockUpstream,
    decode_token,
    encode_token,
)

__all__ = [
    "GATEWAY_AUDIENCE",
    "DEPUTY_SUBJECT",
    "HTTPMockUpstream",
    "encode_token",
    "decode_token",
    "make_caller_token",
    "build_confused_deputy_server",
]

# A caller's inbound token is minted FOR the gateway (the deputy), not the
# upstream — the normal case. A faithful deputy must exchange it for an
# upstream-audience token; forwarding it as-is is the passthrough leak.
GATEWAY_AUDIENCE = "https://gateway.self/mcp"
DEPUTY_SUBJECT = "svc-deputy"


def make_caller_token(subject: str, scope: str = "read:notes",
                      audience: str = GATEWAY_AUDIENCE) -> str:
    """The token a caller presents to the deputy: issued for the gateway, with a
    narrow scope. Not issued for any upstream."""
    return encode_token({"sub": subject, "aud": audience, "scope": scope})


def build_confused_deputy_server(
    mode: str,
    upstream_url: str,
    upstream_audience: str,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    agent = "stranger-test-agent"
    counter = {"n": 0}
    # The confused deputy's own static service-account credential: a real
    # (decodable) token for the deputy's OWN account, with a broad scope.
    static_credential = encode_token({
        "sub": DEPUTY_SUBJECT,
        "aud": upstream_audience,
        "scope": "admin read:notes write:notes",
    })

    def faithful(caller_sub: str) -> str:
        counter["n"] += 1
        return encode_token({
            "sub": caller_sub,
            "act": {"sub": agent},
            "aud": upstream_audience,
            "scope": "read:notes",
            "nonce": counter["n"],
        })

    def sensitive_token(inbound: str, caller_sub: str):
        """The token the sensitive tool sends upstream, or None to refuse."""
        if mode == "safe":
            return faithful(caller_sub)
        if mode == "safe_refuse":
            return None  # refuse: make no upstream call
        if mode == "leaky":
            return inbound  # token passthrough: forward the caller's token as-is
        if mode == "own_authority":
            return static_credential  # the deputy's own (higher) authority
        if mode == "wrong_audience":
            counter["n"] += 1
            return encode_token({
                "sub": caller_sub, "act": {"sub": agent},
                "aud": "https://other.example/api", "scope": "read:notes",
                "nonce": counter["n"],
            })
        raise ValueError(f"unknown confused-deputy mode {mode!r}")

    def call_upstream(token: str) -> bool:
        req = urllib.request.Request(
            upstream_url, data=b"{}", method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read()
            return True
        except Exception:  # pragma: no cover - network error path
            return False

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            inbound = self.headers.get("Authorization", "anonymous")
            if inbound.startswith("Bearer "):
                inbound = inbound[7:]
            try:
                msg = json.loads(raw)
            except ValueError:
                self.send_response(400)
                self.end_headers()
                return
            resp = self._handle(inbound, msg)
            if resp is None:
                self.send_response(202)
                self.end_headers()
                return
            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _result(self, mid):
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": "done"}]}}

        def _handle(self, inbound, msg):
            method = msg.get("method")
            mid = msg.get("id")
            if method == "initialize":
                return {"jsonrpc": "2.0", "id": mid, "result": {
                    "protocolVersion": "2026-07-28",
                    "serverInfo": {"name": "practice-confused-deputy"},
                    "capabilities": {"tools": {}},
                }}
            if method == "notifications/initialized":
                return None
            if method == "tools/list":
                return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                    {"name": "call_upstream"}, {"name": "benign_upstream"}]}}
            if method == "tools/call":
                name = msg.get("params", {}).get("name")
                caller_sub = decode_token(inbound).get("sub")
                if name == "benign_upstream":
                    # Faithful in every mode: the positive control.
                    call_upstream(faithful(caller_sub or "unknown"))
                    return self._result(mid)
                if name == "call_upstream":
                    token = sensitive_token(inbound, caller_sub or "unknown")
                    if token is None:
                        return {"jsonrpc": "2.0", "id": mid, "error": {
                            "code": -32000,
                            "message": "refused: caller not authorized for this upstream"}}
                    call_upstream(token)
                    return self._result(mid)
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": "no such method"}}

    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:  # pragma: no cover - manual runner
    mode = os.environ.get("STRANGERTEST_MODE", "leaky")
    upstream_url = os.environ["STRANGERTEST_UPSTREAM"]
    audience = os.environ.get("STRANGERTEST_AUDIENCE", upstream_url)
    port = int(os.environ.get("STRANGERTEST_PORT", "0"))
    if port in (8790, 4444, 4000):
        raise SystemExit(f"ERROR: refusing reserved port {port}")
    server = build_confused_deputy_server(mode, upstream_url, audience, port=port)
    bound = server.server_address[1]
    print(f"practice-confused-deputy [{mode}] on http://127.0.0.1:{bound}/mcp "
          f"-> {upstream_url}")
    server.serve_forever()


if __name__ == "__main__":
    main()
