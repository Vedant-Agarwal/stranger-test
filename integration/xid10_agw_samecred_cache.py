"""Same-user-credentials token-exchange cache probe against agentgateway 1.7.0.

The agentgateway counterpart of ``xid10_cf_samecred_cache.py`` (ContextForge).
It drives the :mod:`strangertest.credcache` probe through a real agentgateway
v1.7.0 release binary configured for RFC 8693 token exchange, with TWO inbound
credentials for one user, and checks whether agentgateway reuses a cached
upstream token across them (the class of CVE-2026-110195).

agentgateway is config-file driven and keeps its exchange cache in-process, so a
**cold cache** is a process restart (``fresh_cache`` = stop + start). Everything
is loopback only, on 46xx ports; the AS and recording upstream are the same
deterministic ones the ContextForge gate uses (a distinct inbound subject_token
always yields a distinct upstream token), and ``local_as`` provides the JWKS
agentgateway's ``jwtAuth`` validates inbound users against, plus the two inbound
JWTs. Tokens are only ever recorded as sha256 fingerprints.

Prerequisite: the agentgateway v1.7.0 binary at AGW_BIN (its sha256 must be
verified against the published checksum before use).
Env: AGW_BIN, AGW_PORT (4631), AGW_ADMIN_PORT (4634), AS_PORT (4621),
     UP_PORT (4622).
"""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "integration"))

from strangertest.credcache import Credential, run_same_user_credentials_probe  # noqa: E402
from strangertest.delegate import UpstreamCall, request_nonce  # noqa: E402
from strangertest.mcp_client import MCPClient  # noqa: E402
from strangertest.transports import HTTPTransport  # noqa: E402
from local_as import LocalAS  # noqa: E402

AGW_BIN = os.environ.get("AGW_BIN", "agentgateway")
AGW_PORT = int(os.environ.get("AGW_PORT", "4631"))
AGW_ADMIN_PORT = int(os.environ.get("AGW_ADMIN_PORT", "4634"))
AS_PORT = int(os.environ.get("AS_PORT", "4621"))
UP_PORT = int(os.environ.get("UP_PORT", "4622"))
TARGET_AUD = "https://upstream.test/mcp"
INBOUND_AUD = "agentgateway-api"
FORBIDDEN_PORTS = (4000, 4444, 8790)
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"

for _p in (AGW_PORT, AGW_ADMIN_PORT, AS_PORT, UP_PORT):
    assert _p not in FORBIDDEN_PORTS and 4600 <= _p <= 4699, f"port {_p} out of the 46xx range"

as_signer = LocalAS(issuer="https://local-as.test")
upstream_records = []
as_attempts = []


def fp(t):
    return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else None


def xchg_token(subject_token, aud):
    sfp = hashlib.sha256((subject_token or "").encode()).hexdigest()[:16]
    return "xchg-" + hashlib.sha256((sfp + "|" + aud).encode()).hexdigest()


class _HTTP4(ThreadingHTTPServer):
    allow_reuse_address = True


# ------------------------------------------------------------- upstream
TOOL = {"name": "read_note", "description": "Read the caller's note.",
        "inputSchema": {"type": "object", "properties": {"nonce": {"type": "string"}},
                        "additionalProperties": False}}


class UpHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        try:
            msg = json.loads(self.rfile.read(n))
        except ValueError:
            msg = {}
        m, mid = msg.get("method"), msg.get("id")
        auth = self.headers.get("Authorization", "")
        bearer = auth[7:] if auth.startswith("Bearer ") else (auth or None)
        if m in ("initialize", "server/discover"):
            pv = (msg.get("params") or {}).get("protocolVersion") or "2026-07-28"
            self._send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": pv,
                "capabilities": {"tools": {"listChanged": False}, "resources": {}},
                "serverInfo": {"name": "upstream", "version": "1.0"},
                "supportedVersions": ["2026-07-28", "2025-11-25"]}})
            return
        if m == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return
        if m == "tools/list":
            self._send({"jsonrpc": "2.0", "id": mid, "result": {
                "tools": [TOOL], "resultType": "complete", "cacheScope": "private", "ttlMs": 0}})
            return
        if m == "tools/call":
            params = msg.get("params") or {}
            upstream_records.append({
                "method": "tools/call",
                "nonce": request_nonce(params),
                "auth_present": bool(auth),
                "token_fp": fp(bearer) if bearer else None,
                "ts": time.time(),
            })
            self._send({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "ok"}], "isError": False,
                "resultType": "complete"}})
            return
        self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no"}})


# ------------------------------------------------------------------- AS
class ASHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.rstrip("/") in ("/jwks", "/.well-known/jwks.json"):
            self._json(200, as_signer.jwks())
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/token":
            self._json(404, {"error": "not_found"})
            return
        n = int(self.headers.get("Content-Length", "0"))
        params = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
        grant = params.get("grant_type")
        is_exchange = grant in (TOKEN_EXCHANGE_GRANT, "token-exchange")
        subject = params.get("subject_token", "")
        aud = params.get("audience") or TARGET_AUD
        as_attempts.append({"grant_type": grant, "is_exchange": is_exchange,
                            "subject_token_fp": fp(subject) if subject else None,
                            "ts": time.time()})
        if is_exchange:
            tok = xchg_token(subject, aud)
        else:
            tok = "actor-" + hashlib.sha256((params.get("client_id", "") + aud).encode()).hexdigest()[:24]
        self._json(200, {"access_token": tok, "token_type": "Bearer", "expires_in": 3600,
                         "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                         "scope": params.get("scope", "read:notes")})


CONFIG_YAML = f"""# Same-user-credentials gate: agentgateway as the token-exchange deputy.
# Loopback only. Ports are all 46xx.
config:
  adminAddr: 127.0.0.1:{AGW_ADMIN_PORT}
  statsAddr: "off"
  readinessAddr: "off"
gateways:
  xid10:
    port: {AGW_PORT}
    bindAddress: 127.0.0.1
routes:
- name: xid10-mcp
  gateways: xid10
  policies:
    jwtAuth:
      mode: strict
      providers:
      - issuer: https://local-as.test
        audiences: [{INBOUND_AUD}]
        jwks:
          url: http://127.0.0.1:{AS_PORT}/jwks
  backends:
  - mcp:
      statefulMode: stateful
      targets:
      - name: upstream
        mcp:
          host: http://127.0.0.1:{UP_PORT}/mcp
        policies:
          backendAuth:
            oauthTokenExchange:
              host: 127.0.0.1:{AS_PORT}
              path: /token
              subjectToken:
                source:
                  expression: jwt.rawToken.unredacted()
                tokenType: urn:ietf:params:oauth:token-type:jwt
              actorToken:
                source:
                  header:
                    name: x-actor-token
                tokenType: urn:ietf:params:oauth:token-type:jwt
              audiences: [{TARGET_AUD}]
              scopes: [read:notes]
"""


def agw_version():
    out = subprocess.check_output([AGW_BIN, "--version"], stderr=subprocess.STDOUT)
    try:
        return json.loads(out.decode())
    except Exception:
        return {"raw": out.decode().strip()}


class Gateway:
    """Run agentgateway on a throwaway config copy; restart = cold exchange cache."""

    def __init__(self):
        self.proc = None
        self._tmpdir = None
        self.lines = []

    def start(self, timeout=30):
        for bad in FORBIDDEN_PORTS:
            assert str(bad) not in CONFIG_YAML, f"config names forbidden port {bad}"
        self._tmpdir = tempfile.mkdtemp(prefix="xid10-agwcve-")
        cfg = os.path.join(self._tmpdir, "config.yaml")
        with open(cfg, "w") as f:
            f.write(CONFIG_YAML)
        self.proc = subprocess.Popen([AGW_BIN, "-f", cfg], cwd=self._tmpdir,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1)
        threading.Thread(target=self._pump, daemon=True).start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("agentgateway exited early:\n" + self.tail())
            try:
                socket.create_connection(("127.0.0.1", AGW_PORT), timeout=1).close()
                time.sleep(0.5)
                return self
            except OSError:
                time.sleep(0.3)
        raise RuntimeError("agentgateway did not open its port:\n" + self.tail())

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))

    def tail(self, n=30):
        return "\n".join(self.lines[-n:])

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    def restart(self):
        self.stop()
        self.start()


class AGWDeputy:
    def __init__(self, gw, actor_token):
        self.gw = gw
        self.actor = actor_token
        self.tool_name = None

    def fresh_cache(self):
        self.gw.restart()

    def _headers(self, token):
        return {"Authorization": f"Bearer {token}", "x-actor-token": self.actor}

    def read_resource(self, token, nonce):
        url = f"http://127.0.0.1:{AGW_PORT}/mcp"
        # agentgateway 1.7.0 requires MCP-Protocol-Version on every request.
        c = MCPClient(HTTPTransport(url, headers=self._headers(token), modern=True))
        try:
            c.initialize()
            if self.tool_name is None:
                tools = c.list_tools()
                if not tools:
                    raise RuntimeError("agentgateway exposed no tools")
                self.tool_name = next((t.get("name") for t in tools
                                       if str(t.get("name", "")).endswith("read_note")),
                                      tools[0].get("name"))
            return c.call_tool(self.tool_name, {"nonce": nonce})
        finally:
            try:
                c.close()
            except Exception:
                pass


def build_upstream_calls():
    out = []
    for rec in upstream_records:
        if rec.get("method") != "tools/call":
            continue
        out.append(UpstreamCall(nonce=rec.get("nonce"), token=rec.get("token_fp"),
                                audience=TARGET_AUD, scope=None, subject=None,
                                issuer="local-as.test", parsed=True, method="tools/call"))
    return out


def main():
    up = _HTTP4(("127.0.0.1", UP_PORT), UpHandler)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    asrv = _HTTP4(("127.0.0.1", AS_PORT), ASHandler)
    threading.Thread(target=asrv.serve_forever, daemon=True).start()
    time.sleep(0.3)

    ver = agw_version()
    print(f"agentgateway {ver}  AS @127.0.0.1:{AS_PORT}  upstream @127.0.0.1:{UP_PORT}  gw @:{AGW_PORT}")

    # Two credentials for one user: two inbound JWTs (distinct jti), same sub
    # and the SAME scope -- so a reused token is token reuse, not a privilege
    # escalation. local_as._sign adds a unique jti, so the tokens still differ.
    USER = "alice"
    cred1_jwt = as_signer.issue_user_token(USER, scope="read:notes",
                                           audience=INBOUND_AUD)   # "session"
    cred2_jwt = as_signer.issue_user_token(USER, scope="read:notes",
                                           audience=INBOUND_AUD)   # "api token"
    assert cred1_jwt != cred2_jwt
    actor = "actor-" + hashlib.sha256(b"agent-client" + TARGET_AUD.encode()).hexdigest()[:24]

    gw = Gateway()
    deputy = AGWDeputy(gw, actor)
    try:
        report = run_same_user_credentials_probe(
            target=f"http://127.0.0.1:{AGW_PORT}/mcp",
            upstream_target=f"http://127.0.0.1:{UP_PORT}/mcp",
            user=USER,
            cred1=Credential("session", cred1_jwt),
            cred2=Credential("apitoken", cred2_jwt),
            read_resource=deputy.read_resource,
            uri_for=lambda n: n,
            upstream_calls=build_upstream_calls,
            fresh_cache=deputy.fresh_cache,
            expire_cache=None,
            exchange_attempts=lambda: sum(1 for a in as_attempts if a["is_exchange"]),
            authorized=True,
            authorization_note="localhost CVE-2026-110195 reproduction",
        )
    finally:
        gw.stop()

    print("\n================ RESULT ================")
    print("cold control:", report.cold_control.grade, "-", report.cold_control.detail)
    print("warm test:   ", report.warm.grade, "-", report.warm.detail)
    print("exchange attempts seen by AS:", sum(1 for a in as_attempts if a["is_exchange"]))
    print("VERDICT:", report.summary())

    out = {
        "probe": "same-user-credentials",
        "cve": "CVE-2026-110195",
        "gateway": "agentgateway",
        "gateway_version": ver,
        "install": "release binary v1.7.0 (sha256-verified), loopback only",
        "method": ("two inbound JWTs for one user (same sub, distinct jti); config-only "
                   "token-exchange; cold cache = process restart; deterministic AS mints "
                   "a distinct upstream token per inbound subject_token; recording "
                   "upstream ties each federated tools/call to its nonce"),
        "user": USER,
        "cold_control": report.cold_control.to_dict(),
        "warm": report.warm.to_dict(),
        "grade": report.grade,
        "vulnerable": report.vulnerable,
        "exchange_attempts": len([a for a in as_attempts if a["is_exchange"]]),
        "exchange_subject_fingerprints": sorted(
            {a["subject_token_fp"] for a in as_attempts if a["is_exchange"] and a["subject_token_fp"]}),
        "observations": report.observations,
        "upstream_calls": [r for r in upstream_records if r.get("method") == "tools/call"],
        "summary": report.summary(),
    }
    runs = os.path.join(REPO, "integration", "runs")
    os.makedirs(runs, exist_ok=True)
    path = os.path.join(runs, f"agentgateway-1.7.0-samecred-cache-{int(time.time())}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print("saved ->", path)


if __name__ == "__main__":
    main()
