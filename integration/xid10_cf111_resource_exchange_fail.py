"""Independent reproduction, 1.1.1 side: does ContextForge 1.1.1 FAIL CLOSED
when the RFC 8693 token exchange fails on a federated resources/read?

This is the sibling of ``xid10_cf106_resource_exchange_fail.py`` (the 1.0.6
gate) and uses the SAME method, adapted only as far as 1.1.1 requires:

  * 1.1.1 is pip-installed (not a container), so it runs on the host at
    127.0.0.1 -- the AS and the recording upstream are reached at 127.0.0.1
    directly (no ``host.docker.internal``), the admin token is minted with the
    local ``mcpgateway.utils.create_jwt_token`` (no ``docker exec``), and the
    resource-template ids are read from the sqlite DB file read-only (no
    ``docker exec``).
  * 1.1.1's REST routes are ``/v1/...`` (not the un-prefixed 1.0.6 routes).
  * A token-exchange gateway in 1.1.1 skips registration-time discovery unless
    its ``oauthConfig`` carries a ``discovery`` client-credentials sub-config,
    so one is supplied (the toggleable AS answers ``client_credentials`` in
    both modes; only the token-EXCHANGE grant is toggled to fail).

Method (loopback only):
  * Recording upstream (both loopback families) -- echoes the client's
    requested protocolVersion; records every POST: method, whether
    Authorization was present, header names, token fingerprint, AS mode.
  * Toggleable AS: POST /token returns a freshly signed RS256 token for a
    token-exchange grant in "ok" mode and HTTP 400 invalid_grant in "fail"
    mode; client_credentials (discovery) always succeeds; /toggle?mode=ok|fail
    flips the exchange mode; /jwks for completeness.
  * Register a FRESH oauth token-exchange gateway in the running CF 1.1.1
    (token_url -> this AS /token, url -> this upstream), refresh to discover
    the resource template, expose it on a virtual server.
  * As the admin JWT (3-part; passes CF's looks_like_jwt guard so a real
    exchange is attempted):
      1. discovery (AS=ok) registers the template
      2. CONTROL read (AS=ok): proves the read path reaches upstream WITH auth
      3. TEST reads x3 (AS=fail): observe whether resources/read reaches the
         upstream and, if so, whether it carries an Authorization header, and
         what the caller received (error or content).

Never persists full JWTs -- tokens are reduced to sha256 fingerprints.

Grading (per the brief):
  * FAILS CLOSED            -- control passed, and in every test read no
                              resources/read reached the upstream and the
                              caller got an error.
  * FORWARDS UNAUTHENTICATED -- control passed, and a test read reached the
                              upstream with no Authorization header.
  * INCONCLUSIVE            -- control failed, or the read path was unreachable,
                              or the three test reads disagreed.

Prerequisites:
  * A pip-installed ContextForge 1.1.1 serving at CF_URL (default 127.0.0.1:4145),
    with SSRF_ALLOW_LOCALHOST=true, its sqlite DB at CF_DB.
  * Run with the CF venv (pyjwt[crypto] + cryptography) and the CF .env loaded
    (JWT_SECRET etc.), so create_jwt_token mints an admin token CF accepts.
Env overrides: CF_URL, CF_DB, CF_UP_PORT, CF_AS_PORT, CF_TEST_READS.
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

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "integration"))
import jwt as _jwt  # noqa: E402
from local_as import LocalAS  # noqa: E402

CF = os.environ.get("CF_URL", "http://127.0.0.1:4145")
CF_DB = os.environ.get("CF_DB", "")
UP_PORT = int(os.environ.get("CF_UP_PORT", "8797"))
AS_PORT = int(os.environ.get("CF_AS_PORT", "8795"))
N_TEST_READS = int(os.environ.get("CF_TEST_READS", "3"))
TARGET_AUD = "https://upstream.test/mcp"

AS_MODE = {"mode": "ok"}
upstream_calls = []
as_attempts = []
as_signer = LocalAS(issuer="https://local-as.test")

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def fp(t):
    return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else None


class _HTTP4(ThreadingHTTPServer):
    allow_reuse_address = True


class _HTTP6(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True


def _dual(port, handler):
    s4 = _HTTP4(("127.0.0.1", port), handler)
    s6 = _HTTP6(("::1", port), handler)
    for s in (s4, s6):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return s4, s6


# ------------------------------------------------------------- upstream
class UpHandler(BaseHTTPRequestHandler):
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
        upstream_calls.append({
            "method": m,
            "auth_header_present": bool(auth),
            "auth_scheme": (auth.split(" ", 1)[0] if auth else None),
            "token_fp": fp(bearer) if bearer else None,
            "header_names": sorted(self.headers.keys()),
            "as_mode_at_time": AS_MODE["mode"],
            "ts": time.time(),
        })
        sys.stderr.write(f"  UPSTREAM {m!s:30} auth={bool(auth)!s:5} mode={AS_MODE['mode']}\n")
        sys.stderr.flush()
        if m == "initialize":
            pv = (msg.get("params") or {}).get("protocolVersion") or "2025-06-18"
            self._send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": pv,
                "capabilities": {"tools": {"listChanged": False},
                                 "resources": {"subscribe": False, "listChanged": False}},
                "serverInfo": {"name": "upstream", "version": "1.0"}}})
            return
        if m == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return
        if m == "tools/list":
            self._send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                {"name": "read_note", "description": "Read the caller's note.",
                 "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}]}})
            return
        if m == "resources/list":
            self._send({"jsonrpc": "2.0", "id": mid, "result": {"resources": [
                {"uri": "note://repro", "name": "note", "mimeType": "text/plain"}]}})
            return
        if m == "resources/templates/list":
            self._send({"jsonrpc": "2.0", "id": mid, "result": {"resourceTemplates": [
                {"uriTemplate": "note://{id}", "name": "note-template", "mimeType": "text/plain"}]}})
            return
        if m == "resources/read":
            uri = (msg.get("params") or {}).get("uri", "note://repro")
            self._send({"jsonrpc": "2.0", "id": mid, "result": {"contents": [
                {"uri": uri, "mimeType": "text/plain", "text": "ok"}]}})
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
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        p = u.path.rstrip("/")
        if p in ("/jwks", "/.well-known/jwks.json"):
            self._json(200, as_signer.jwks())
            return
        if p == "/toggle":
            q = parse_qs(u.query)
            AS_MODE["mode"] = q.get("mode", ["ok"])[0]
            self._json(200, {"mode": AS_MODE["mode"]})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        from urllib.parse import parse_qs
        p = self.path.rstrip("/")
        if p not in ("/token", "/token-ex"):
            self._json(404, {"error": "not_found"})
            return
        n = int(self.headers.get("Content-Length", "0"))
        params = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
        grant = params.get("grant_type")
        is_exchange = grant == TOKEN_EXCHANGE_GRANT or grant == "token-exchange"
        as_attempts.append({"mode": AS_MODE["mode"], "grant_type": grant,
                            "is_exchange": is_exchange, "ts": time.time()})
        sys.stderr.write(f"  AS /token grant={grant} exchange={is_exchange} -> mode={AS_MODE['mode']}\n")
        sys.stderr.flush()
        # Only the token-EXCHANGE grant is toggled. client_credentials (used by
        # the gateway's discovery sub-config) always succeeds, so discovery is
        # not what we are testing.
        if is_exchange and AS_MODE["mode"] == "fail":
            self._json(400, {"error": "invalid_grant", "error_description": "exchange refused (test)"})
            return
        sub = "client"
        if is_exchange:
            try:
                c = _jwt.decode(params.get("subject_token", ""), options={"verify_signature": False})
                sub = c.get("sub") or c.get("username") or "unknown"
            except Exception:
                sub = "unknown"
        tok = as_signer._sign({"sub": sub, "aud": params.get("audience") or TARGET_AUD,
                               "scope": params.get("scope", "read:notes")})
        self._json(200, {"access_token": tok, "token_type": "Bearer", "expires_in": 3600,
                         "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                         "scope": params.get("scope", "read:notes")})


# --------------------------------------------------------------- CF REST
def admin_token():
    # Local (pip) install: mint with the CF venv; the gate must run with the CF
    # .env loaded so JWT_SECRET matches the running server.
    out = subprocess.check_output(
        [sys.executable, "-m", "mcpgateway.utils.create_jwt_token",
         "-u", "admin@example.com", "--admin", "-e", "1800"],
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
    """Read resource ids (static + template) for this gateway straight from the
    sqlite DB, read-only. Templates are filtered out of GET /v1/resources."""
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
        print(f"DB id lookup failed: {e}")
        return []


def main():
    _dual(UP_PORT, UpHandler)
    _dual(AS_PORT, ASHandler)
    time.sleep(0.4)
    as_base = f"http://127.0.0.1:{AS_PORT}"
    print(f"upstream @ 127.0.0.1:{UP_PORT}  AS @ {as_base}  CF @ {CF}  DB={CF_DB or '(none)'}")

    tok = admin_token()
    oauth_config = {
        "grant_type": "token-exchange",
        "token_url": f"{as_base}/token",
        "target_audience": TARGET_AUD,
        "subject_token_source": "inbound_user_jwt",
        "client_id": "forge", "client_secret": "unused",
        "scopes": ["read:notes"],
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        # 1.1.1: a token-exchange gateway skips registration-time discovery
        # unless a discovery credential is given -- use client credentials.
        "discovery": {"grant_type": "client_credentials",
                      "token_url": f"{as_base}/token",
                      "client_id": "forge", "client_secret": "unused",
                      "scopes": ["read:notes"]},
    }
    gw = {"name": f"xid10cf111_{int(time.time())}",
          "url": f"http://127.0.0.1:{UP_PORT}/mcp",
          "transport": "STREAMABLEHTTP", "authType": "oauth",
          "visibility": "public", "oauthConfig": oauth_config}

    AS_MODE["mode"] = "ok"
    st, resp = cf("POST", "/v1/gateways", tok, gw)
    print(f"register gateway -> HTTP {st}")
    if st >= 300:
        print(json.dumps(resp)[:600])
        return
    gid = resp.get("id")
    print(f"gateway id = {gid}")

    st, rr = cf("POST", f"/v1/gateways/{gid}/tools/refresh", tok, {})
    print(f"tools/refresh -> HTTP {st}: {json.dumps(rr)[:200]}")

    # find resources for this gateway (static ones via API; templates via DB)
    res_id = None
    my_ids = []
    for _ in range(12):
        st, res = cf("GET", "/v1/resources", tok)
        allr = res if isinstance(res, list) else res.get("data", [])
        mine = [r for r in allr if r.get("gatewayId") == gid or r.get("gateway_id") == gid]
        if mine:
            my_ids = [r.get("id") for r in mine if r.get("id") is not None]
            res_id = mine[0].get("id")
            print(f"discovered resources (API): {[(r.get('id'), r.get('uri')) for r in mine]}")
            break
        time.sleep(1.5)
    db_ids = template_ids_from_db(gid)
    if db_ids:
        my_ids = db_ids
        print(f"all resource ids for gateway (incl templates, from DB): {my_ids}")
    if not my_ids and not res_id:
        print("NO RESOURCE DISCOVERED; aborting (INCONCLUSIVE)")
        return

    def mark(label):
        upstream_calls.append({"_marker": label, "ts": time.time()})

    res_uri = "note://repro"

    # Federated reads must go through a virtual-server MCP endpoint.
    st, srv = cf("POST", "/v1/servers", tok, {"server": {
        "name": f"vs-cf111-{int(time.time())}", "visibility": "public",
        "associated_resources": my_ids or [res_id]}})
    print(f"create virtual server -> HTTP {st}: {json.dumps(srv)[:160]}")
    if st >= 300:
        print("could not create virtual server; aborting (INCONCLUSIVE)")
        return
    sid = srv.get("id")
    vs_url = f"{CF}/servers/{sid}/mcp"
    print(f"virtual server MCP: {vs_url}")

    from strangertest.mcp_client import MCPClient
    from strangertest.transports import HTTPTransport

    read_results = {}

    def do_read(label, mode, uri):
        AS_MODE["mode"] = mode
        mark(label)
        print(f"\n--- {label} (AS={mode}) read {uri} ---")
        caller_error = None
        caller_got_content = False
        c = MCPClient(HTTPTransport(vs_url, headers={"Authorization": f"Bearer {tok}"}))
        try:
            c.initialize()
            out = c.read_resource(uri)
            caller_got_content = True
            print(f"  read_resource -> {json.dumps(out)[:160]}")
        except Exception as e:
            caller_error = f"{type(e).__name__}: {str(e)[:200]}"
            print(f"  read_resource error: {caller_error}")
        finally:
            try:
                c.close()
            except Exception:
                pass
        read_results[label] = {"caller_error": caller_error,
                               "caller_got_content": caller_got_content}

    # discovery already happened in ok mode at refresh.
    # 2. CONTROL (AS=ok): proves resources/read reaches upstream WITH auth.
    do_read("CONTROL", "ok", "note://live-ok")
    # 3. TEST x N (AS=fail): distinct uncached instances to force federation.
    for i in range(1, N_TEST_READS + 1):
        do_read(f"TEST{i}", "fail", f"note://live-fail-{i}")
    # cached static read under fail, for completeness.
    do_read("CACHED", "fail", res_uri)

    time.sleep(0.5)

    # ---- analyze ----
    def phase_calls(label):
        out, cur = [], None
        for c in upstream_calls:
            if "_marker" in c:
                cur = c["_marker"]
                continue
            if cur == label:
                out.append(c)
        return out

    def reads_in(label):
        return [c for c in phase_calls(label) if c["method"] == "resources/read"]

    control_read = reads_in("CONTROL")
    test_labels = [f"TEST{i}" for i in range(1, N_TEST_READS + 1)]
    per_test = []
    for lbl in test_labels:
        rds = reads_in(lbl)
        per_test.append({
            "phase": lbl,
            "resources_read_reached_upstream": bool(rds),
            "auth_present": (rds[0]["auth_header_present"] if rds else None),
            "caller_error": read_results[lbl]["caller_error"],
            "caller_got_content": read_results[lbl]["caller_got_content"],
        })

    print("\n================ SUMMARY ================")
    print(f"CONTROL  resources/read upstream: {bool(control_read)}; "
          f"auth: {control_read[0]['auth_header_present'] if control_read else 'n/a'}")
    for t in per_test:
        print(f"{t['phase']}  read upstream: {t['resources_read_reached_upstream']}; "
              f"auth: {t['auth_present']}; caller_error: {bool(t['caller_error'])}")

    # determinism: the test reads must agree.
    sigs = {(t["resources_read_reached_upstream"], t["auth_present"], bool(t["caller_error"]))
            for t in per_test}
    deterministic = len(sigs) == 1

    if not control_read:
        verdict = "INCONCLUSIVE: control read did not reach upstream -- read path broken, cannot trust the fail-phase observation"
    elif not deterministic:
        verdict = f"INCONCLUSIVE: the {N_TEST_READS} test reads disagreed: {sorted(sigs)}"
    elif any(t["resources_read_reached_upstream"] and t["auth_present"] is False for t in per_test):
        verdict = "FORWARDS UNAUTHENTICATED: resources/read forwarded upstream with NO Authorization header when the token exchange failed"
    elif any(t["resources_read_reached_upstream"] for t in per_test):
        verdict = "NOT FAIL-CLOSED (authenticated): resources/read reached upstream WITH an Authorization header during exchange failure"
    elif all((not t["resources_read_reached_upstream"]) and t["caller_error"] for t in per_test):
        verdict = "FAILS CLOSED: no resources/read reached upstream while the exchange was failing, and the caller got an error (control read DID reach upstream, so the read path works)"
    else:
        verdict = "INCONCLUSIVE: no upstream read during the fail phase, but the caller did not get an error"
    print("\nVERDICT:", verdict)

    out = {
        "probe": "xid10-resource-read-exchange-failure",
        "gateway": "ContextForge", "gateway_version": "1.1.1",
        "install": "pip (mcp-contextforge-gateway==1.1.1), loopback only",
        "method": ("fresh oauth token-exchange gateway via /v1 REST; toggleable AS returns "
                   "a signed token for a token-exchange grant in ok mode and HTTP 400 "
                   "invalid_grant in fail mode (client_credentials discovery always "
                   "succeeds); recorder echoes the client's requested protocolVersion; "
                   f"{N_TEST_READS} test reads of distinct uncached template instances"),
        "oauth_config": {**oauth_config, "client_secret": "REDACTED",
                         "discovery": {**oauth_config["discovery"], "client_secret": "REDACTED"}},
        "upstream_url": gw["url"],
        "inbound_caller": "admin JWT (3-part; CF looks_like_jwt guard passes, real exchange attempted)",
        "trigger": "MCP resources/read via virtual server POST /servers/{id}/mcp (the federated read path)",
        "control_read_reached_upstream": bool(control_read),
        "control_read_auth_present": control_read[0]["auth_header_present"] if control_read else None,
        "test_reads": per_test,
        "test_reads_deterministic": deterministic,
        "as_attempts": as_attempts,
        "upstream_calls": [c for c in upstream_calls if "_marker" not in c],
        "phase_markers": [c for c in upstream_calls if "_marker" in c],
        "verdict": verdict,
    }
    runs = os.path.join(REPO, "integration", "runs")
    os.makedirs(runs, exist_ok=True)
    path = os.path.join(runs, f"contextforge-1.1.1-resource-exchange-fail-repro-{int(time.time())}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print("saved ->", path)

    # cleanup what we created
    cf("DELETE", f"/v1/servers/{sid}", tok)
    cf("DELETE", f"/v1/gateways/{gid}", tok)
    print("deleted virtual server", sid, "and gateway", gid)


if __name__ == "__main__":
    main()
