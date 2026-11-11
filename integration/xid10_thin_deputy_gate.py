"""XID-10 Phase 1 gate: the delegation probe against a real token exchange.

Everything here is real except the deputy's size: a real local Authorization
Server (``local_as``) signs RS256 tokens and performs the RFC 8693 exchange; a
thin MCP "deputy" server performs a genuine exchange at that AS and forwards the
result to a real upstream MCP server; the upstream validates every token against
the AS's published JWKS before recording the delegated identity. The stdlib
Stranger Test probe drives the deputy as alice and bob (plus a second alice
call) and must flag each leaky deputy mode for the right reason and pass the
faithful one.

This is the "thin deputy" milestone: it proves the probe works against genuine
signed tokens and a genuine exchange, ahead of pointing it at a third-party
gateway (ContextForge). The deputy is ours; the AS exchange, the crypto, and the
upstream validation are real.

Run (needs pyjwt[crypto]):  python integration/xid10_thin_deputy_gate.py
"""

from __future__ import annotations

import json
import os
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
for p in (_REPO_ROOT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import jwt
    from local_as import LocalAS, TOKEN_EXCHANGE_GRANT, JWT_TOKEN_TYPE
except Exception as exc:  # pragma: no cover - environment gate
    print(f"SKIP: XID-10 thin-deputy gate needs pyjwt[crypto] ({exc}).")
    sys.exit(0)

from strangertest.delegate import MockUpstream, run_delegation_probe
from strangertest.mcp_client import MCPClient
from strangertest.probe import Identity, ProbeError
from strangertest.transports import HTTPTransport

UPSTREAM_AUD = "https://upstream.test/mcp"
GATEWAY_CLIENT = "gateway-client"

failures: list = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(name)


# --------------------------------------------------------------------------
# A real upstream MCP server that validates every token against the AS JWKS.
# --------------------------------------------------------------------------
class RecordingUpstream(MockUpstream):
    def __init__(self, audience: str, jwks: Dict[str, Any], issuer: str):
        super().__init__(audience)
        self._issuer = issuer
        self._verify_key = jwt.algorithms.RSAAlgorithm.from_jwk(
            json.dumps(jwks["keys"][0])
        )
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                auth = self.headers.get("Authorization", "")
                bearer = auth[7:] if auth.startswith("Bearer ") else auth
                try:
                    msg = json.loads(raw)
                except ValueError:
                    self._send({"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32700, "message": "parse"}})
                    return
                method = msg.get("method")
                mid = msg.get("id")
                if method == "initialize":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": "2026-07-28",
                        "serverInfo": {"name": "upstream", "version": "1.0"},
                        "capabilities": {"tools": {"listChanged": False}}}})
                    return
                if method == "notifications/initialized":
                    self.send_response(202)
                    self.end_headers()
                    return
                if method == "tools/list":
                    # Discovery: advertise a real tool so a gateway can find it.
                    outer._record("tools/list", bearer)
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [{
                        "name": "read_note",
                        "description": "Read the caller's note.",
                        "inputSchema": {"type": "object", "properties": {},
                                        "additionalProperties": False},
                    }]}})
                    return
                if method in ("tools/call", "resources/read"):
                    outer._record(method, bearer)
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "content": [{"type": "text", "text": "ok"}], "isError": False}})
                    return
                self._send({"jsonrpc": "2.0", "id": mid,
                            "error": {"code": -32601, "message": "no"}})

            def _send(self, obj):
                body = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)

    def _record(self, method: str, bearer: str) -> None:
        try:
            # Verify signature, issuer AND expiry — not just the signature.
            claims = jwt.decode(bearer, self._verify_key, algorithms=["RS256"],
                                issuer=self._issuer,
                                options={"verify_aud": False, "verify_exp": True,
                                         "verify_iss": True, "require": ["exp", "iss"]})
        except Exception as exc:
            self.receive(token=bearer, parsed=False, parse_error=str(exc), method=method)
            return
        act = claims.get("act")
        actor = act.get("sub") if isinstance(act, dict) else None
        self.receive(subject=claims.get("sub"), actor=actor,
                     audience=claims.get("aud"), scope=claims.get("scope"),
                     token=bearer, issuer=claims.get("orig_iss") or claims.get("iss"),
                     parsed=True, method=method)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}/mcp"

    def start(self):
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


# --------------------------------------------------------------------------
# The thin deputy MCP server: a genuine RFC 8693 exchange, then forward.
# --------------------------------------------------------------------------
def build_deputy(mode: str, as_token_url: str, upstream_url: str,
                 gateway_client_token: str) -> ThreadingHTTPServer:
    cache: Dict[str, str] = {}

    def exchange(subject_token: str, *, with_actor: bool) -> str:
        data = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": subject_token,
            "subject_token_type": JWT_TOKEN_TYPE,
            "audience": UPSTREAM_AUD,
            "scope": "read:notes",
        }
        if with_actor:
            data["actor_token"] = gateway_client_token
            data["actor_token_type"] = JWT_TOKEN_TYPE
        req = urllib.request.Request(
            as_token_url, data=urllib.parse.urlencode(data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())["access_token"]

    def forward_token(caller_bearer: str) -> str:
        if mode == "safe":
            return exchange(caller_bearer, with_actor=True)
        if mode == "static_credential":
            return gateway_client_token  # own credential, every caller, reused
        if mode == "token_passthrough":
            return caller_bearer  # inbound user token, unexchanged
        if mode == "cached_token_reuse":
            if "t" not in cache:
                cache["t"] = exchange(caller_bearer, with_actor=True)
            return cache["t"]
        raise ValueError(mode)

    def call_upstream(method: str, bearer: str) -> None:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": {"name": "read_note"}}).encode()
        req = urllib.request.Request(
            upstream_url, data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {bearer}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            auth = self.headers.get("Authorization", "")
            caller = auth[7:] if auth.startswith("Bearer ") else auth
            try:
                msg = json.loads(raw)
            except ValueError:
                self._send({"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32700, "message": "parse"}})
                return
            method, mid = msg.get("method"), msg.get("id")
            if method == "initialize":
                self._send({"jsonrpc": "2.0", "id": mid, "result": {
                    "protocolVersion": "2026-07-28",
                    "serverInfo": {"name": "deputy"},
                    "capabilities": {"tools": {}}}})
                return
            if method == "notifications/initialized":
                self.send_response(202)
                self.end_headers()
                return
            if method == "tools/call" and msg.get("params", {}).get("name") == "do_upstream":
                try:
                    token = forward_token(caller)
                    # A discovery call on the gateway's OWN credential (ignored
                    # by the probe) precedes the per-user tool call.
                    call_upstream("tools/list", gateway_client_token)
                    call_upstream("tools/call", token)
                except Exception as exc:  # exchange/forward failed -> surface as error
                    self._send({"jsonrpc": "2.0", "id": mid,
                                "error": {"code": -32000, "message": str(exc)}})
                    return
                self._send({"jsonrpc": "2.0", "id": mid,
                            "result": {"content": [{"type": "text", "text": "done"}]}})
                return
            self._send({"jsonrpc": "2.0", "id": mid,
                        "error": {"code": -32601, "message": "no"}})

        def _send(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def _identity(url: str, user_token: str, label: str) -> Identity:
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {user_token}"})),
    )


def run_mode(as_: LocalAS, as_url: str, mode: str) -> Any:
    upstream = RecordingUpstream(UPSTREAM_AUD, as_.jwks(), as_.issuer).start()
    gateway_client_token = as_.issue_client_token(GATEWAY_CLIENT)
    deputy = build_deputy(mode, f"{as_url}/token", upstream.url, gateway_client_token)
    threading.Thread(target=deputy.serve_forever, daemon=True).start()
    deputy_url = f"http://127.0.0.1:{deputy.server_address[1]}/mcp"
    alice = as_.issue_user_token("alice", scope="read:notes")
    bob = as_.issue_user_token("bob", scope="read:notes")
    try:
        return run_delegation_probe(
            deputy_url,
            _identity(deputy_url, alice, "A"),
            _identity(deputy_url, bob, "B"),
            upstream=upstream,
            trigger=lambda c: c.call_tool("do_upstream", {}),
            expected_subject_a="alice",
            expected_subject_b="bob",
        )
    finally:
        deputy.shutdown()
        deputy.server_close()
        upstream.stop()


PROVX, PROVY = "https://provx.test", "https://provy.test"


def run_two_issuer(as_: LocalAS, as_url: str, conflate: bool) -> Any:
    """Two users both named 'alice' from different providers (provX/provY).

    safe deputy exchanges each → distinct orig_iss → probe passes. The
    conflated deputy serves the second caller the FIRST's exchanged token
    (orig_iss=provX) → the probe must FAIL it on subject/identity, proving the
    (issuer, name) grading actually catches a cross-issuer mix-up.
    """
    upstream = RecordingUpstream(UPSTREAM_AUD, as_.jwks(), as_.issuer).start()
    gateway_client_token = as_.issue_client_token(GATEWAY_CLIENT)
    mode = "cached_token_reuse" if conflate else "safe"
    deputy = build_deputy(mode, f"{as_url}/token", upstream.url, gateway_client_token)
    threading.Thread(target=deputy.serve_forever, daemon=True).start()
    deputy_url = f"http://127.0.0.1:{deputy.server_address[1]}/mcp"
    ax = as_.issue_user_token("alice", scope="read:notes", issuer=PROVX, email="alice@provx.test")
    ay = as_.issue_user_token("alice", scope="read:notes", issuer=PROVY, email="alice@provy.test")
    try:
        return run_delegation_probe(
            deputy_url,
            _identity(deputy_url, ax, "A"),
            _identity(deputy_url, ay, "B"),
            upstream=upstream,
            trigger=lambda c: c.call_tool("do_upstream", {}),
            expected_subject_a="alice", expected_subject_b="alice",
            expected_issuer_a=PROVX, expected_issuer_b=PROVY,
        )
    finally:
        deputy.shutdown()
        deputy.server_close()
        upstream.stop()


def main() -> None:
    as_ = LocalAS()
    as_server = as_.serve()
    threading.Thread(target=as_server.serve_forever, daemon=True).start()
    as_url = f"http://127.0.0.1:{as_server.server_address[1]}"
    try:
        # Faithful delegation: clean.
        safe = run_mode(as_, as_url, "safe")
        check("faithful delegation passes", not safe.vulnerable, safe.summary())
        check("all checks hold under faithful delegation",
              all(safe.checks.values()), str(safe.checks))

        # Static credential: subject dropped, no actor, one reused token.
        sc = run_mode(as_, as_url, "static_credential")
        check("static credential detected", sc.vulnerable, str(sc.failures))
        check("  -> subject not preserved", not sc.checks["subject_preserved"])
        check("  -> no actor", not sc.checks["actor_present"])
        check("  -> token reused across principals", not sc.checks["no_token_reuse"])

        # Passthrough: inbound user token forwarded unexchanged.
        pt = run_mode(as_, as_url, "token_passthrough")
        check("token passthrough detected", pt.vulnerable, str(pt.failures))
        check("  -> wrong audience", not pt.checks["audience_correct"])
        check("  -> no actor (passthrough)", not pt.checks["actor_present"])
        check("  -> subject still preserved", pt.checks["subject_preserved"])

        # Cached token reuse: A's later call bled into by B's identity.
        cr = run_mode(as_, as_url, "cached_token_reuse")
        check("cached token reuse detected", cr.vulnerable, str(cr.failures))
        check("  -> cross-identity bleed", not cr.checks["no_cross_identity_bleed"])

        # Two issuers, same username. Safe keeps them distinct; the conflated
        # deputy serves one provider's token for the other and MUST be caught
        # (this is the leaky fixture the issuer-aware grading demands).
        ti_safe = run_two_issuer(as_, as_url, conflate=False)
        check("two issuers, same name, kept distinct passes",
              not ti_safe.vulnerable, ti_safe.summary())
        ti_bad = run_two_issuer(as_, as_url, conflate=True)
        check("conflated issuer DETECTED", ti_bad.vulnerable, str(ti_bad.failures))
        check("  -> subject/identity not preserved across issuers",
              not ti_bad.checks["subject_preserved"])
    finally:
        as_server.shutdown()
        as_server.server_close()

    print()
    if failures:
        print(f"GATE FAILED: {failures}")
        sys.exit(1)
    print("GATE PASSED: probe grades a real RFC 8693 exchange correctly.")


if __name__ == "__main__":
    main()
