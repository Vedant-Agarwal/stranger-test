"""Live reproduction of CVE-2026-110195: does a ContextForge gateway reuse a
cached RFC 8693 upstream token across two credentials of the SAME user?

CVE-2026-110195 (IBM ContextForge MCP Gateway, affected 1.0.0-1.0.11, fixed in
1.1.0; reported by Nick Simpson): the token-exchange cache keyed only on
(gateway, user, audience) and omitted the inbound credential, so the upstream
token minted for one credential of a user was served to another credential of
the same user. The fix added the inbound ``subject_token`` to the cache key.

This gate drives the :mod:`strangertest.credcache` probe against a running
ContextForge gateway with TWO inbound credentials for one user (two distinct
login JWTs for the same account -- a session-style and an api-token-style
credential; both authenticate as the same user, so the vulnerable key collides,
and the distinguishing factor is exactly the inbound credential the fix added
to the key). It is the real-gateway counterpart of the in-process practice
fixtures in :mod:`strangertest.practice_credcache`.

Method (loopback only):
  * Recording upstream (both loopback families): records every POST -- method,
    the bearer token fingerprint, and the resource URI (which carries the
    probe's per-request nonce), so each read is tied to the leg that caused it.
  * Deterministic AS: POST /token answers client_credentials (the gateway's
    discovery sub-config) with an opaque token, and a token-exchange grant with
    an access_token that is a deterministic function of the inbound
    subject_token and audience -- so a DISTINCT inbound credential always yields
    a DISTINCT upstream token, and a cache hit (no fresh exchange) reuses a
    byte-identical one. Every exchange attempt is recorded with the
    subject_token fingerprint.
  * ``fresh_cache`` registers a FRESH token-exchange gateway + virtual server
    (new gateway id => cold cache). The probe uses it between the two cold
    controls and before the warm run.
  * The probe then: cold control (each credential alone, on its own fresh
    gateway, must mint a distinct upstream token); warm test (credential 1
    populates the cache, credential 2 hits it) -- FAIL if credential 2's
    upstream call carried credential 1's token.

Tokens are only ever recorded as sha256 fingerprints; full JWTs are never written.

Prerequisites:
  * A pip-installed ContextForge serving at CF_URL with SSRF_ALLOW_LOCALHOST=true
    and its sqlite DB at CF_DB.
  * Run with that CF's venv (pyjwt[crypto] + cryptography) and its .env loaded
    (JWT_SECRET etc.), so create_jwt_token mints tokens CF accepts.
Env: CF_URL, CF_DB, CF_VERSION, CF_REST_PREFIX (default /v1), CF_UP_PORT,
     CF_AS_PORT.
"""
from __future__ import annotations
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from strangertest.credcache import (  # noqa: E402
    Credential,
    run_same_user_credentials_probe,
    FAIL,
    OK,
    INCONCLUSIVE,
)
from strangertest.delegate import UpstreamCall, request_nonce  # noqa: E402
from strangertest.mcp_client import MCPClient  # noqa: E402
from strangertest.transports import HTTPTransport  # noqa: E402

CF = os.environ.get("CF_URL", "http://127.0.0.1:4611")
CF_DB = os.environ.get("CF_DB", "")
CF_VERSION = os.environ.get("CF_VERSION", "unknown")
PREFIX = os.environ.get("CF_REST_PREFIX", "/v1")
UP_PORT = int(os.environ.get("CF_UP_PORT", "4622"))
AS_PORT = int(os.environ.get("CF_AS_PORT", "4621"))
TARGET_AUD = "https://upstream.test/mcp"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"

upstream_records = []   # every upstream POST
as_attempts = []        # every AS /token attempt


def fp(t):
    return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else None


def xchg_token(subject_token, aud):
    """A deterministic upstream token: distinct inbound credential -> distinct
    token; the same credential re-exchanged -> the same token."""
    sfp = hashlib.sha256((subject_token or "").encode()).hexdigest()[:16]
    return "xchg-" + hashlib.sha256((sfp + "|" + aud).encode()).hexdigest()


class _HTTP4(ThreadingHTTPServer):
    allow_reuse_address = True


class _HTTP6(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True


def _dual(port, handler):
    servers = [_HTTP4(("127.0.0.1", port), handler), _HTTP6(("::1", port), handler)]
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return servers


# ------------------------------------------------------------- upstream
# The upstream advertises a single tool that takes a per-request ``nonce`` so
# each federated tools/call can be tied back to the leg that caused it. The
# token-exchange cache is keyed on (gateway, user, audience) regardless of
# whether the federated call is a tool or a resource, so the tool path
# exercises the CVE just as a resource read would — and ContextForge's
# registration-time discovery reliably finds tools.
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

    def do_GET(self):
        self._send({"ok": True})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        try:
            msg = json.loads(raw)
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
        if m == "resources/list":
            self._send({"jsonrpc": "2.0", "id": mid, "result": {
                "resources": [], "resultType": "complete", "cacheScope": "private", "ttlMs": 0}})
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
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path.rstrip("/") not in ("/token", "/token-ex"):
            self._json(404, {"error": "not_found"})
            return
        n = int(self.headers.get("Content-Length", "0"))
        params = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
        grant = params.get("grant_type")
        is_exchange = grant in (TOKEN_EXCHANGE_GRANT, "token-exchange")
        subject = params.get("subject_token", "")
        aud = params.get("audience") or TARGET_AUD
        as_attempts.append({
            "grant_type": grant,
            "is_exchange": is_exchange,
            "subject_token_fp": fp(subject) if subject else None,
            "ts": time.time(),
        })
        if is_exchange:
            tok = xchg_token(subject, aud)
        else:
            tok = "disc-" + hashlib.sha256((params.get("client_id", "") + aud).encode()).hexdigest()[:24]
        self._json(200, {"access_token": tok, "token_type": "Bearer", "expires_in": 3600,
                         "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                         "scope": params.get("scope", "read:notes")})


# --------------------------------------------------------------- CF REST
def mint_jwt(email, expires):
    out = subprocess.check_output(
        [sys.executable, "-m", "mcpgateway.utils.create_jwt_token",
         "-u", email, "--admin", "-e", str(expires)],
        stderr=subprocess.DEVNULL)
    return out.decode().strip().splitlines()[-1]


def cf(method, path, tok, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(CF + path, data=data, method=method, headers={
        "Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"_error": e.read().decode("utf-8", "replace")[:600]}


def template_ids_from_db(gid):
    if not CF_DB or not os.path.exists(CF_DB):
        return []
    try:
        con = sqlite3.connect(f"file:{CF_DB}?mode=ro", uri=True, timeout=10)
        try:
            cur = con.execute("SELECT id FROM resources WHERE gateway_id=?", (gid,))
            return [str(r[0]) for r in cur.fetchall() if r[0] is not None]
        finally:
            con.close()
    except Exception as e:
        print(f"  DB id lookup failed: {e}")
        return []


def _oauth_config(as_base):
    return {
        "grant_type": "token-exchange",
        "token_url": f"{as_base}/token",
        "target_audience": TARGET_AUD,
        "subject_token_source": "inbound_user_jwt",
        "client_id": "forge", "client_secret": "unused",
        "scopes": ["read:notes"],
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "discovery": {"grant_type": "client_credentials",
                      "token_url": f"{as_base}/token",
                      "client_id": "forge", "client_secret": "unused",
                      "scopes": ["read:notes"]},
    }


class CFDeputy:
    """Registers/discards a fresh token-exchange gateway + virtual server so the
    probe can get a cold exchange cache on demand; drives reads through it."""

    def __init__(self, admin_tok, as_base):
        self.admin = admin_tok
        self.as_base = as_base
        self.gid = None
        self.sid = None
        self.vs_url = None
        self.tool_name = None
        self.generation = 0

    def _discard(self):
        if self.sid:
            cf("DELETE", f"{PREFIX}/servers/{self.sid}", self.admin)
        if self.gid:
            cf("DELETE", f"{PREFIX}/gateways/{self.gid}", self.admin)
        self.sid = self.gid = self.vs_url = self.tool_name = None

    def fresh_cache(self):
        """Cold cache: a brand-new gateway id (and thus a new cache key space)."""
        self._discard()
        self.generation += 1
        gen = self.generation
        gw = {"name": f"xid10cve_{int(time.time())}_{gen}",
              "url": f"http://127.0.0.1:{UP_PORT}/mcp",
              "transport": "STREAMABLEHTTP", "authType": "oauth",
              "visibility": "public", "oauthConfig": _oauth_config(self.as_base)}
        st, resp = cf("POST", f"{PREFIX}/gateways", self.admin, gw)
        if st >= 300:
            raise RuntimeError(f"register gateway failed HTTP {st}: {json.dumps(resp)[:300]}")
        self.gid = resp.get("id")
        cf("POST", f"{PREFIX}/gateways/{self.gid}/tools/refresh", self.admin, {})
        mine = []
        for _ in range(10):
            st, tools = cf("GET", f"{PREFIX}/tools", self.admin)
            allt = tools if isinstance(tools, list) else tools.get("data", [])
            mine = [t for t in allt
                    if (t.get("gatewayId") == self.gid or t.get("gateway_id") == self.gid)
                    and t.get("id") is not None]
            if mine:
                break
            time.sleep(1.0)
        if not mine:
            raise RuntimeError("no tool discovered for the fresh gateway")
        tool_id = mine[0].get("id")
        self.tool_name = mine[0].get("name")
        st, srv = cf("POST", f"{PREFIX}/servers", self.admin, {"server": {
            "name": f"vs-cve-{int(time.time())}-{gen}", "visibility": "public",
            "associated_tools": [tool_id]}})
        if st >= 300:
            raise RuntimeError(f"create virtual server failed HTTP {st}: {json.dumps(srv)[:300]}")
        self.sid = srv.get("id")
        self.vs_url = f"{CF}/servers/{self.sid}/mcp"

    def read_resource(self, token, nonce):
        """Drive one federated tools/call as this inbound credential, carrying
        the probe's nonce (named read_resource to match the probe's callback)."""
        if not self.vs_url:
            raise RuntimeError("no current virtual server (call fresh_cache first)")
        c = MCPClient(HTTPTransport(self.vs_url, headers={"Authorization": f"Bearer {token}"}))
        try:
            c.initialize()
            return c.call_tool(self.tool_name, {"nonce": nonce})
        finally:
            try:
                c.close()
            except Exception:
                pass


def build_upstream_calls():
    """Translate recorded upstream tools/call POSTs into UpstreamCall objects the
    probe grades, tagging each with the nonce the federated call carried."""
    out = []
    for rec in upstream_records:
        if rec.get("method") != "tools/call":
            continue
        out.append(UpstreamCall(
            nonce=rec.get("nonce"),
            token=rec.get("token_fp"),   # already a fingerprint; probe keeps it as-is
            audience=TARGET_AUD,
            scope=None,
            subject=None,
            issuer="local-as.test",
            parsed=True,
            method="tools/call",
        ))
    return out


def main():
    _dual(UP_PORT, UpHandler)
    _dual(AS_PORT, ASHandler)
    time.sleep(0.4)
    as_base = f"http://127.0.0.1:{AS_PORT}"
    print(f"upstream @127.0.0.1:{UP_PORT}  AS @{as_base}  CF @{CF} ({CF_VERSION}, prefix {PREFIX!r})  DB={CF_DB or '(none)'}")

    admin = mint_jwt("admin@example.com", 1900)
    # Two credentials for ONE user: two distinct login JWTs for the same
    # (bootstrapped) account. Different expiries guarantee distinct token bytes.
    # Both authenticate as the same user, so a (gateway, user, audience) cache
    # key collides; the inbound credential is the only distinguishing factor --
    # exactly what the fix added to the key.
    USER = "admin@example.com"
    cred1_jwt = mint_jwt(USER, 1800)   # "session"
    cred2_jwt = mint_jwt(USER, 1500)   # "api token"
    if cred1_jwt == cred2_jwt:
        print("WARNING: the two credentials are byte-identical; aborting")
        return

    deputy = CFDeputy(admin, as_base)
    try:
        report = run_same_user_credentials_probe(
            target=CF,
            upstream_target=f"http://127.0.0.1:{UP_PORT}/mcp",
            user=USER,
            cred1=Credential("session", cred1_jwt),
            cred2=Credential("apitoken", cred2_jwt),
            read_resource=deputy.read_resource,
            uri_for=lambda n: n,
            upstream_calls=build_upstream_calls,
            fresh_cache=deputy.fresh_cache,
            expire_cache=None,   # live TTL/skew makes expiry unreliable; the
                                 # expired case is covered by the practice unit test
            exchange_attempts=lambda: sum(1 for a in as_attempts if a["is_exchange"]),
            authorized=True,
            authorization_note="localhost CVE-2026-110195 reproduction",
        )
    finally:
        deputy._discard()

    print("\n================ RESULT ================")
    print("cold control:", report.cold_control.grade, "-", report.cold_control.detail)
    print("warm test:   ", report.warm.grade, "-", report.warm.detail)
    print("exchange attempts seen by AS:", sum(1 for a in as_attempts if a["is_exchange"]))
    print("VERDICT:", report.summary())

    out = {
        "probe": "same-user-credentials",
        "cve": "CVE-2026-110195",
        "gateway": "ContextForge",
        "gateway_version": CF_VERSION,
        "install": f"pip (mcp-contextforge-gateway=={CF_VERSION}), loopback only",
        "method": ("two inbound login JWTs for one user (alice); fresh token-exchange "
                   "gateway per cold run; deterministic AS mints a distinct upstream "
                   "token per inbound subject_token; recording upstream ties each read "
                   "to its nonce"),
        "user": USER,
        "credentials": {"cred1": "session JWT", "cred2": "api-token JWT (same user)"},
        "cold_control": report.cold_control.to_dict(),
        "warm": report.warm.to_dict(),
        "grade": report.grade,
        "vulnerable": report.vulnerable,
        "exchange_attempts": len([a for a in as_attempts if a["is_exchange"]]),
        "exchange_subject_fingerprints": sorted(
            {a["subject_token_fp"] for a in as_attempts if a["is_exchange"] and a["subject_token_fp"]}
        ),
        "observations": report.observations,
        "upstream_calls": [r for r in upstream_records if r.get("method") == "tools/call"],
        "summary": report.summary(),
    }
    runs = os.path.join(REPO, "integration", "runs")
    os.makedirs(runs, exist_ok=True)
    path = os.path.join(runs, f"contextforge-{CF_VERSION}-samecred-cache-{int(time.time())}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print("saved ->", path)


if __name__ == "__main__":
    main()
