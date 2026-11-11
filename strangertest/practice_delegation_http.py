"""LOCAL HTTP harness for the XID-10 delegation probe.

Two pieces, both for servers you operate:

* :class:`HTTPMockUpstream` — an upstream API you control that records the
  delegated identity (decoded from the inbound bearer token) of each call.
* :func:`build_delegation_server` — a single-process MCP server whose
  ``do_upstream`` tool makes an on-behalf-of call to a configured upstream,
  faithfully (safe) or by reusing its own static master credential (leaky).

Tokens are unsigned JWT-shaped blobs (``header.payload.sig``); decoding just
reads the payload claims. NEVER expose either on a network.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

from .delegate import MockUpstream

__all__ = [
    "encode_token",
    "decode_token",
    "HTTPMockUpstream",
    "build_delegation_server",
]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def encode_token(claims: Dict[str, Any]) -> str:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    return f"{header}.{payload}."


def decode_token(token: str) -> Dict[str, Any]:
    try:
        return json.loads(_b64url_decode(token.split(".")[1]))
    except Exception:
        return {}


class HTTPMockUpstream(MockUpstream):
    """A MockUpstream that also runs a real HTTP listener and records callers."""

    def __init__(self, audience: str, host: str = "127.0.0.1", port: int = 0):
        super().__init__(audience)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)  # body ignored; identity rides in the token
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else auth
                parts = token.split(".")
                if len(parts) != 3 or not parts[1]:
                    # Not a JWT-shaped token: a real resource server cannot read
                    # a delegated identity from it. Record it as unparseable.
                    outer.receive(token=token, parsed=False,
                                  parse_error="token is not a decodable JWT")
                    self._ok()
                    return
                try:
                    claims = json.loads(_b64url_decode(parts[1]))
                except Exception as exc:
                    outer.receive(token=token, parsed=False, parse_error=str(exc))
                    self._ok()
                    return
                act = claims.get("act")
                if isinstance(act, dict):
                    actor = act.get("sub")
                else:
                    actor = str(act) if act else None
                outer.receive(
                    subject=claims.get("sub"),
                    actor=actor,
                    audience=claims.get("aud"),
                    scope=claims.get("scope"),
                    token=token,
                    parsed=True,
                )
                self._ok()

            def _ok(self):
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer((host, port), Handler)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[0], self._server.server_address[1]
        return f"http://{host}:{port}/"

    def start(self) -> "HTTPMockUpstream":
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def build_delegation_server(
    mode: str,
    upstream_url: str,
    upstream_audience: str,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    agent = "stranger-test-agent"
    counter = {"n": 0}
    cache: Dict[str, str] = {}
    # A confused deputy's static service-account token: a real (decodable) JWT
    # for the server's OWN account, reused for every caller — subject dropped,
    # no actor, same token each time.
    static_credential = encode_token({
        "sub": "svc-deputy",
        "aud": upstream_audience,
        "scope": "read:notes",
    })

    def mint(caller: str) -> str:
        counter["n"] += 1
        n = counter["n"]
        faithful = {
            "sub": caller,
            "act": {"sub": agent},
            "aud": upstream_audience,
            "scope": "read:notes",
            "nonce": n,
        }
        if mode == "safe":
            return encode_token(faithful)
        if mode == "safe_list_aud":
            # Faithful, but aud is a list and scope is a list (both legal JWT shapes).
            return encode_token({**faithful, "aud": [upstream_audience, "urn:other"],
                                 "scope": ["read:notes"]})
        if mode in ("static_credential", "leaky"):
            return static_credential  # same token for everyone
        if mode == "impersonation":
            # Subject preserved, but no `act`: the acting agent is invisible.
            return encode_token({"sub": caller, "aud": upstream_audience,
                                 "scope": "read:notes", "nonce": n})
        if mode == "token_passthrough":
            # The banned pattern: forward the inbound user token unexchanged —
            # audience is the gateway's own id, not the upstream, and no actor.
            return encode_token({"sub": caller, "aud": "https://gateway.self/mcp",
                                 "scope": "read:notes profile", "nonce": n})
        if mode == "cached_token_reuse":
            # Exchanges once, then hands every later caller the first token: a
            # second caller is served as the first identity.
            if not cache:
                cache["t"] = encode_token(faithful)
            return cache["t"]
        if mode == "wrong_audience":
            return encode_token({**faithful, "aud": "https://other.example/api"})
        if mode == "broad_scope":
            return encode_token({**faithful, "scope": "admin read:notes"})
        if mode == "opaque_token":
            # Not a JWT: the upstream cannot read a delegated identity -> inconclusive.
            return f"opaque-not-a-jwt-{n}"
        raise ValueError(f"unknown delegation mode {mode!r}")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            caller = self.headers.get("Authorization", "anonymous")
            if caller.startswith("Bearer "):
                caller = caller[7:]
            try:
                msg = json.loads(raw)
            except ValueError:
                self.send_response(400)
                self.end_headers()
                return
            resp = self._handle(caller, msg)
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

        def _handle(self, caller, msg):
            method = msg.get("method")
            mid = msg.get("id")
            if method == "initialize":
                return {"jsonrpc": "2.0", "id": mid, "result": {
                    "protocolVersion": "2026-07-28",
                    "serverInfo": {"name": "practice-delegation"},
                    "capabilities": {"tools": {}},
                }}
            if method == "notifications/initialized":
                return None
            if method == "tools/list":
                return {"jsonrpc": "2.0", "id": mid,
                        "result": {"tools": [{"name": "do_upstream"}]}}
            if method == "tools/call" and msg.get("params", {}).get("name") == "do_upstream":
                token = mint(caller)
                req = urllib.request.Request(
                    upstream_url, data=b"{}", method="POST",
                    headers={"Content-Type": "application/json",
                             "Authorization": f"Bearer {token}"},
                )
                try:
                    with urllib.request.urlopen(req, timeout=10) as r:
                        r.read()
                except Exception as exc:  # pragma: no cover - network error path
                    return {"jsonrpc": "2.0", "id": mid,
                            "error": {"code": -32000, "message": str(exc)}}
                return {"jsonrpc": "2.0", "id": mid,
                        "result": {"content": [{"type": "text", "text": "done"}]}}
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": "no"}}

    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:  # pragma: no cover - manual runner
    mode = os.environ.get("STRANGERTEST_MODE", "leaky")
    upstream_url = os.environ["STRANGERTEST_UPSTREAM"]
    audience = os.environ.get("STRANGERTEST_AUDIENCE", upstream_url)
    port = int(os.environ.get("STRANGERTEST_PORT", "0"))
    server = build_delegation_server(mode, upstream_url, audience, port=port)
    bound = server.server_address[1]
    print(f"practice-delegation [{mode}] on http://127.0.0.1:{bound}/mcp -> {upstream_url}")
    server.serve_forever()


if __name__ == "__main__":
    main()
