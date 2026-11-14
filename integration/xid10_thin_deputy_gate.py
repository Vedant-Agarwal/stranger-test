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
    print(f"ERROR: cannot run the XID-10 thin-deputy gate: needs pyjwt[crypto] ({exc}).",
          file=sys.stderr)
    sys.exit(2)

from strangertest.delegate import (MockUpstream, run_delegation_probe,
                                   run_issuer_unregistered_probe,
                                   request_nonce, run_scope_narrowing_probe,
                                   token_fingerprint)
from strangertest.mcp_client import MCPClient
from strangertest.probe import Identity, ProbeError
from strangertest.transports import HTTPTransport

UPSTREAM_AUD = "https://upstream.test/mcp"
GATEWAY_CLIENT = "gateway-client"

# Scope-narrowing fixtures: the user holds a BROAD scope, the deputy is meant to
# request read:notes. The escalating deputy forwards more than the user had.
SUBJECT_SCOPE_BROAD = "read:notes write:notes admin"
CONFIGURED_SCOPE = "read:notes"
SCOPE_ESCALATED = "read:notes write:notes admin delete:all"
UNREGISTERED_ISSUER = "https://unregistered.test"

# Ports that belong to processes this gate must never touch.
FORBIDDEN_PORTS = {8790, 4444}


def _port_ok(port: int) -> int:
    if port in FORBIDDEN_PORTS:
        raise SystemExit(f"ERROR: refusing to use reserved port {port}")
    return port


def _ports() -> Dict[str, int]:
    """THIN_PORT_BASE=N pins AS=N, lax AS=N+1, upstream=N+2, deputy=N+3.
    Unset = ephemeral (library use, e.g. gen_results); the gate's main()
    requires it to be set explicitly."""
    base = int(os.environ.get("THIN_PORT_BASE", "0"))
    for port in range(base, base + 4) if base else ():
        _port_ok(port)
    if not base:
        return {"as": 0, "as_lax": 0, "upstream": 0, "deputy": 0}
    return {"as": base, "as_lax": base + 1, "upstream": base + 2, "deputy": base + 3}

failures: list = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(name)


# --------------------------------------------------------------------------
# A real upstream MCP server that validates every token against the AS JWKS.
# --------------------------------------------------------------------------
class RecordingUpstream(MockUpstream):
    def __init__(self, audience: str, jwks: Dict[str, Any], issuer: str, port: int = 0):
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
                        "inputSchema": {"type": "object",
                                        "properties": {"nonce": {"type": "string"}},
                                        "additionalProperties": False},
                    }]}})
                    return
                if method in ("tools/call", "resources/read"):
                    outer._record(method, bearer, msg.get("params"))
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

        self._server = ThreadingHTTPServer(("127.0.0.1", _port_ok(port)), Handler)

    def _record(self, method: str, bearer: str, params: Any = None) -> None:
        nonce = request_nonce(params)
        try:
            # Verify signature, issuer AND expiry — not just the signature.
            claims = jwt.decode(bearer, self._verify_key, algorithms=["RS256"],
                                issuer=self._issuer,
                                options={"verify_aud": False, "verify_exp": True,
                                         "verify_iss": True, "require": ["exp", "iss"]})
        except Exception as exc:
            self.receive(token=bearer, parsed=False, parse_error=str(exc), method=method,
                         nonce=nonce)
            return
        act = claims.get("act")
        actor = act.get("sub") if isinstance(act, dict) else None
        self.receive(subject=claims.get("sub"), actor=actor,
                     audience=claims.get("aud"), scope=claims.get("scope"),
                     token=bearer, issuer=claims.get("orig_iss") or claims.get("iss"),
                     parsed=True, method=method, nonce=nonce)

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
                 gateway_client_token: str, port: int = 0,
                 registered_issuers: Optional[Dict[str, str]] = None) -> ThreadingHTTPServer:
    """Modes: safe | static_credential | token_passthrough | cached_token_reuse
    (the original fixtures) plus, for the new checks:
      scope_no_request   — exchanges like safe but sends NO scope parameter
      scope_escalation   — BROKEN: forwards a token it minted for itself (via
                           the AS's dev /issue) carrying more scope than the
                           user had; the AS cap cannot stop it, so a scope FAIL
                           can only come from the deputy
      issuer_any         — BROKEN: accepts any issuer (no iss check; = safe)
      issuer_checked     — safe, plus: the inbound token's iss must be in
                           ``registered_issuers`` (iss -> JWKS URL) and its
                           signature must verify under THAT issuer's key
    """
    cache: Dict[str, str] = {}
    as_base = as_token_url.rsplit("/", 1)[0]

    def exchange(subject_token: str, *, with_actor: bool,
                 scope: Optional[str] = "read:notes") -> str:
        data = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": subject_token,
            "subject_token_type": JWT_TOKEN_TYPE,
            "audience": UPSTREAM_AUD,
        }
        if scope is not None:
            data["scope"] = scope
        if with_actor:
            data["actor_token"] = gateway_client_token
            data["actor_token_type"] = JWT_TOKEN_TYPE
        req = urllib.request.Request(
            as_token_url, data=urllib.parse.urlencode(data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())["access_token"]

    def check_issuer(caller_bearer: str) -> None:
        iss = jwt.decode(caller_bearer, options={"verify_signature": False}).get("iss")
        jwks_url = (registered_issuers or {}).get(iss)
        if not jwks_url:
            raise PermissionError(f"untrusted issuer {iss!r}")
        with urllib.request.urlopen(jwks_url, timeout=10) as r:
            jwks = json.loads(r.read())
        key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
        jwt.decode(caller_bearer, key, algorithms=["RS256"], issuer=iss,
                   options={"verify_aud": False})

    def forward_token(caller_bearer: str) -> str:
        if mode in ("safe", "issuer_any"):
            return exchange(caller_bearer, with_actor=True)
        if mode == "issuer_checked":
            check_issuer(caller_bearer)
            return exchange(caller_bearer, with_actor=True)
        if mode == "scope_no_request":
            return exchange(caller_bearer, with_actor=True, scope=None)
        if mode == "scope_escalation":
            # Mint our own token for the user with a broad scope, bypassing
            # the exchange (and so the AS's scope cap).
            sub = jwt.decode(caller_bearer, options={"verify_signature": False}).get("sub")
            q = urllib.parse.urlencode({"sub": sub, "aud": UPSTREAM_AUD, "act": GATEWAY_CLIENT,
                                        "scope": SCOPE_ESCALATED})
            with urllib.request.urlopen(f"{as_base}/issue?{q}", timeout=10) as r:
                return json.loads(r.read())["access_token"]
        if mode == "static_credential":
            return gateway_client_token  # own credential, every caller, reused
        if mode == "token_passthrough":
            return caller_bearer  # inbound user token, unexchanged
        if mode == "cached_token_reuse":
            if "t" not in cache:
                cache["t"] = exchange(caller_bearer, with_actor=True)
            return cache["t"]
        raise ValueError(mode)

    def call_upstream(method: str, bearer: str, arguments: Optional[dict] = None) -> None:
        params: Dict[str, Any] = {"name": "read_note"}
        if arguments:
            params["arguments"] = arguments  # forwarded as received (carries the nonce)
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": params}).encode()
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
                    call_upstream("tools/call", token,
                                  msg.get("params", {}).get("arguments") or None)
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

    return ThreadingHTTPServer(("127.0.0.1", _port_ok(port)), Handler)


def _identity(url: str, user_token: str, label: str) -> Identity:
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {user_token}"})),
    )


def run_mode(as_: LocalAS, as_url: str, mode: str) -> Any:
    p = _ports()
    upstream = RecordingUpstream(UPSTREAM_AUD, as_.jwks(), as_.issuer, p["upstream"]).start()
    gateway_client_token = as_.issue_client_token(GATEWAY_CLIENT)
    deputy = build_deputy(mode, f"{as_url}/token", upstream.url, gateway_client_token,
                          p["deputy"])
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
    p = _ports()
    upstream = RecordingUpstream(UPSTREAM_AUD, as_.jwks(), as_.issuer, p["upstream"]).start()
    gateway_client_token = as_.issue_client_token(GATEWAY_CLIENT)
    mode = "cached_token_reuse" if conflate else "safe"
    deputy = build_deputy(mode, f"{as_url}/token", upstream.url, gateway_client_token,
                          p["deputy"])
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


# --------------------------------------------------------------------------
# Scope narrowing and issuer binding fixtures (new checks). These talk to the
# AS over HTTP only, so the real-gateway gates can run them against their own
# AS as the in-run "broken fixture" control.
# --------------------------------------------------------------------------
def _get_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def as_issue_http(as_base: str, sub: str, **q: Any) -> str:
    params = {"sub": sub, **{k: v for k, v in q.items() if v is not None}}
    return _get_json(f"{as_base}/issue?{urllib.parse.urlencode(params)}")["access_token"]


def as_client_token_http(as_base: str, client_id: str = GATEWAY_CLIENT) -> str:
    body = urllib.parse.urlencode({"grant_type": "client_credentials",
                                   "client_id": client_id}).encode()
    req = urllib.request.Request(f"{as_base}/token", data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())["access_token"]


def exchange_lookup_http(as_base: str):
    def lookup(fp):
        for rec in _get_json(f"{as_base}/exchanges"):
            if fp and rec.get("issued_fp") == fp:
                return rec
        return None
    return lookup


def run_scope_fixture(as_base: str, mode: str, *, controls: Dict[str, bool],
                      upstream_port: int = 0, deputy_port: int = 0) -> Any:
    """Thin deputy scope fixture: safe (requests read:notes) -> OK;
    scope_no_request -> OBSERVATION not_narrowed; scope_escalation -> FAIL."""
    upstream = RecordingUpstream(UPSTREAM_AUD, _get_json(f"{as_base}/jwks"),
                                 "https://local-as.test", upstream_port).start()
    deputy = build_deputy(mode, f"{as_base}/token", upstream.url,
                          as_client_token_http(as_base), deputy_port)
    threading.Thread(target=deputy.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{deputy.server_address[1]}/mcp"
    alice = as_issue_http(as_base, "alice", scope=SUBJECT_SCOPE_BROAD)
    bob = as_issue_http(as_base, "bob", scope=SUBJECT_SCOPE_BROAD)
    try:
        return run_scope_narrowing_probe(
            url, _identity(url, alice, "A"), _identity(url, bob, "B"),
            upstream=upstream, trigger=lambda c: c.call_tool("do_upstream", {}),
            subject_scope=SUBJECT_SCOPE_BROAD, configured_scope=CONFIGURED_SCOPE,
            exchange_lookup=exchange_lookup_http(as_base), controls=controls)
    finally:
        deputy.shutdown(); deputy.server_close(); upstream.stop()


def run_issuer_fixture(as_base: str, mode: str, *, controls: Dict[str, bool],
                       upstream_port: int = 0, deputy_port: int = 0) -> Any:
    """Thin deputy issuer fixture (needs a LAX AS so the AS does not mask the
    deputy): issuer_checked -> OK; issuer_any -> FAIL."""
    upstream = RecordingUpstream(UPSTREAM_AUD, _get_json(f"{as_base}/jwks"),
                                 "https://local-as.test", upstream_port).start()
    registered = {"https://provx.test": f"{as_base}/jwks/provx",
                  "https://provy.test": f"{as_base}/jwks/provy",
                  "https://local-as.test": f"{as_base}/jwks"}
    deputy = build_deputy(mode, f"{as_base}/token", upstream.url,
                          as_client_token_http(as_base), deputy_port,
                          registered_issuers=registered)
    threading.Thread(target=deputy.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{deputy.server_address[1]}/mcp"
    common = dict(scope="read:notes", email="mallory@provx.test", key="provx")
    control_tok = as_issue_http(as_base, "mallory", iss="https://provx.test", **common)
    probe_tok = as_issue_http(as_base, "mallory", iss=UNREGISTERED_ISSUER, **common)
    try:
        return run_issuer_unregistered_probe(
            url, control_identity=_identity(url, control_tok, "control"),
            probe_identity=_identity(url, probe_tok, "probe"),
            upstream=upstream, trigger=lambda c, n: c.call_tool("do_upstream", {"nonce": n}),
            probe_token_fp=token_fingerprint(probe_tok), probe_issuer=UNREGISTERED_ISSUER,
            exchange_records=lambda: _get_json(f"{as_base}/exchanges"),
            controls=controls, quiet_seconds=0.5)
    finally:
        deputy.shutdown(); deputy.server_close(); upstream.stop()


def run_new_checks(as_base: str, lax_as_base: str, p: Dict[str, int]) -> Dict[str, Any]:
    """Broken fixture first (it is the control that allows OK), then the rest."""
    kw = dict(upstream_port=p["upstream"], deputy_port=p["deputy"])
    out: Dict[str, Any] = {}
    esc = run_scope_fixture(as_base, "scope_escalation", controls={}, **kw)
    ctl = {"broken_fixture_failed": esc.grade == "FAIL"}
    out["scope_escalation"] = esc
    out["scope_safe"] = run_scope_fixture(as_base, "safe", controls=ctl, **kw)
    out["scope_no_request"] = run_scope_fixture(as_base, "scope_no_request", controls=ctl, **kw)
    anyi = run_issuer_fixture(lax_as_base, "issuer_any", controls={}, **kw)
    ictl = {"broken_fixture_failed": anyi.grade == "FAIL"}
    out["issuer_any"] = anyi
    out["issuer_checked"] = run_issuer_fixture(lax_as_base, "issuer_checked", controls=ictl, **kw)
    return out


def main() -> None:
    if not os.environ.get("THIN_PORT_BASE"):
        raise SystemExit("ERROR: refusing to start: set THIN_PORT_BASE explicitly "
                         "(AS, lax AS, upstream, deputy on N..N+3)")
    p = _ports()
    as_ = LocalAS()
    as_server = as_.serve(port=_port_ok(p["as"]))
    threading.Thread(target=as_server.serve_forever, daemon=True).start()
    as_url = f"http://127.0.0.1:{as_server.server_address[1]}"
    # A second, LAX AS (accepts any issuer it holds a key for) for the issuer
    # fixtures, so the AS cannot mask the deputy's own issuer decision.
    lax_as = LocalAS(lax_subject_issuer=True)
    lax_server = lax_as.serve(port=_port_ok(p["as_lax"]))
    threading.Thread(target=lax_server.serve_forever, daemon=True).start()
    lax_url = f"http://127.0.0.1:{lax_server.server_address[1]}"
    print(f"AS {as_url}  lax AS {lax_url}  ports {p}")
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

        # New checks: scope narrowing (CoSAI 3.3.2), issuer binding (3.2.2/3.3.2).
        new = run_new_checks(as_url, lax_url, p)
        for name, r in new.items():
            print(f"  {name}: {r.summary()}")
        check("scope escalation (broken) FAILS scope narrowing",
              new["scope_escalation"].grade == "FAIL", new["scope_escalation"].reason)
        check("scope safe deputy is OK (narrowed)",
              new["scope_safe"].grade == "OK", new["scope_safe"].reason)
        check("scope no-request deputy is OBSERVATION not_narrowed",
              (new["scope_no_request"].grade, new["scope_no_request"].label)
              == ("OBSERVATION", "not_narrowed"), new["scope_no_request"].reason)
        check("issuer-any deputy (broken) FAILS issuer binding",
              new["issuer_any"].grade == "FAIL", new["issuer_any"].reason)
        check("issuer-checked deputy is OK (rejected)",
              new["issuer_checked"].grade == "OK", new["issuer_checked"].reason)
        out = os.environ.get("THIN_NEW_CHECKS_OUT")
        if out:
            with open(out, "w") as f:
                json.dump({"endpoints": {"as_base": as_url, "lax_as_base": lax_url,
                                         "ports": p},
                           **{k: v.to_dict() for k, v in new.items()}}, f, indent=2)
            print(f"saved new-check fixture results -> {out}")
    finally:
        as_server.shutdown()
        as_server.server_close()
        lax_server.shutdown()
        lax_server.server_close()

    print()
    if failures:
        print(f"GATE FAILED: {failures}")
        sys.exit(1)
    print("GATE PASSED: probe grades a real RFC 8693 exchange correctly.")


if __name__ == "__main__":
    main()
