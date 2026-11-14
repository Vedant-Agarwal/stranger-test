"""Independent reproduction: does ContextForge 1.0.6 forward a resources/read
to the upstream with NO Authorization header when the RFC 8693 token exchange
FAILS?

Design (loopback only; container reaches host via host.docker.internal):
  * Recording upstream (host, both loopback families) -- SDK-faithful MCP server
    that ECHOES the client's requested protocolVersion (always supported), so
    the MCP SDK client never aborts initialize for a version mismatch. Records
    every POST: method, whether Authorization was present, header names, token
    fingerprint, and the AS mode at that instant.
  * Toggleable AS (host, both loopback families): /token-ex returns a freshly
    signed RS256 token in "ok" mode and HTTP 400 invalid_grant in "fail" mode;
    /toggle?mode=ok|fail flips it; /jwks for completeness.
  * Register a FRESH oauth token-exchange gateway in the running CF 1.0.6
    container, using the known-good 1.0.6 oauthConfig field names, token_url ->
    this AS, url -> this upstream.
  * Three reads of the SAME resource, as the admin JWT (3-part; passes CF's
    looks_like_jwt guard so a real exchange is attempted):
      1. discovery (AS=ok) registers the resource
      2. CONTROL read (AS=ok): proves the read path reaches upstream WITH auth
         -- so a "no read" later cannot be a recorder artifact.
      3. TEST read (AS=fail): observe whether resources/read reaches the
         upstream, and if so whether it carries an Authorization header.

Never persists full JWTs -- tokens are reduced to sha256 fingerprints.

RESULT (official image ghcr.io/ibm/mcp-context-forge:v1.0.6, loopback only):
  Reproduced. When the exchange succeeds the upstream resources/read carries
  Authorization: Bearer <exchanged>. When the exchange returns HTTP 400 the
  upstream still receives initialize + notifications/initialized + resources/read
  with the SAME header names MINUS Authorization -- i.e. the gateway sends an
  unauthenticated request instead of failing closed. (This test upstream answers
  without checking the token, so CF returns content; a real upstream that
  requires a token would refuse.) Inbound caller is the CF admin JWT; untested
  with an ordinary user. Source: in 1.0.6 the token-exchange `except` only logs;
  1.1.1's source adds `raise ResourceError(...)` and fails closed. 1.1.0 not
  tested. The federated read path is reached only for uncached resources /
  resource templates; a cached catalogued resource is served locally and never
  federates, which is why a plain read looks "fail-closed".

Prerequisites:
  * A ContextForge v1.0.6 container reachable at CF_URL (default 127.0.0.1:4446),
    port-mapped to host loopback only, started with
    --add-host=host.docker.internal:host-gateway so it can reach host services.
    Its name (for the admin-token `docker exec`) is $CF_CONTAINER.
  * Run with a Python that has pyjwt[crypto] + cryptography on sys.path.
Env overrides: CF_URL, CF_CONTAINER, CF_UP_PORT, CF_AS_PORT.
"""
from __future__ import annotations
import hashlib
import json
import os
import socket
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

CF = os.environ.get("CF_URL", "http://127.0.0.1:4446")
CONTAINER = os.environ.get("CF_CONTAINER", "cf106-xid10")
UP_PORT = int(os.environ.get("CF_UP_PORT", "8796"))
AS_PORT = int(os.environ.get("CF_AS_PORT", "8793"))
TARGET_AUD = "https://upstream.test/mcp"

AS_MODE = {"mode": "ok"}
upstream_calls = []
as_attempts = []
as_signer = LocalAS(issuer="https://local-as.test")


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
        if p != "/token-ex":
            self._json(404, {"error": "not_found"})
            return
        n = int(self.headers.get("Content-Length", "0"))
        params = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
        as_attempts.append({"mode": AS_MODE["mode"], "grant_type": params.get("grant_type"), "ts": time.time()})
        sys.stderr.write(f"  AS /token-ex grant={params.get('grant_type')} -> mode={AS_MODE['mode']}\n")
        sys.stderr.flush()
        if AS_MODE["mode"] == "fail":
            self._json(400, {"error": "invalid_grant", "error_description": "exchange refused (test)"})
            return
        sub = "unknown"
        try:
            c = _jwt.decode(params.get("subject_token", ""), options={"verify_signature": False})
            sub = c.get("sub") or c.get("username") or "unknown"
        except Exception:
            pass
        tok = as_signer._sign({"sub": sub, "aud": params.get("audience") or TARGET_AUD,
                               "scope": params.get("scope", "read:notes")})
        self._json(200, {"access_token": tok, "token_type": "Bearer", "expires_in": 3600,
                         "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                         "scope": params.get("scope", "read:notes")})


# --------------------------------------------------------------- CF REST
def admin_token():
    out = subprocess.check_output(
        ["docker", "exec", CONTAINER, "sh", "-lc",
         "python -m mcpgateway.utils.create_jwt_token -u admin@example.com --admin -e 1800 2>/dev/null | tail -1"])
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


def main():
    _dual(UP_PORT, UpHandler)
    _dual(AS_PORT, ASHandler)
    time.sleep(0.4)
    print(f"upstream @ host.docker.internal:{UP_PORT}  AS @ host.docker.internal:{AS_PORT}")

    tok = admin_token()
    oauth_config = {
        "grant_type": "token-exchange",
        "token_url": f"http://host.docker.internal:{AS_PORT}/token-ex",
        "target_audience": TARGET_AUD,
        "subject_token_source": "inbound_user_jwt",
        "client_id": "forge", "client_secret": "unused",
        "scopes": ["read:notes"],
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    }
    gw = {"name": f"xid10repro_{int(time.time())}",
          "url": f"http://host.docker.internal:{UP_PORT}/mcp",
          "transport": "STREAMABLEHTTP", "authType": "oauth",
          "visibility": "public", "oauthConfig": oauth_config}

    AS_MODE["mode"] = "ok"
    st, resp = cf("POST", "/gateways", tok, gw)
    print(f"register gateway -> HTTP {st}")
    if st >= 300:
        print(json.dumps(resp)[:600])
        return
    gid = resp.get("id")
    print(f"gateway id = {gid}")

    # trigger MCP discovery (initialize/tools/list/resources/list) against upstream
    st, rr = cf("POST", f"/gateways/{gid}/tools/refresh?include_resources=true&include_prompts=false", tok, {})
    print(f"tools/refresh -> HTTP {st}: {json.dumps(rr)[:200]}")

    # find the resource(s) for this gateway
    res_id = None
    my_ids = []
    for _ in range(12):
        st, res = cf("GET", "/resources", tok)
        allr = res if isinstance(res, list) else res.get("data", [])
        mine = [r for r in allr if r.get("gatewayId") == gid or r.get("gateway_id") == gid]
        if mine:
            my_ids = [r.get("id") for r in mine if r.get("id") is not None]
            res_id = mine[0].get("id")
            print(f"discovered resources: {[(r.get('id'), r.get('uri')) for r in mine]}")
            break
        time.sleep(1.5)
    if not res_id:
        print("NO RESOURCE DISCOVERED; aborting")
        return

    # Templates are filtered out of GET /resources; pull every resource id for
    # this gateway (static + template) straight from the container DB.
    try:
        q = ("python - <<'PY'\nimport sqlite3\nc=sqlite3.connect('/tmp/mcp.db');cur=c.cursor()\n"
             f"print('\\n'.join(r[0] for r in cur.execute(\"SELECT id FROM resources WHERE gateway_id='{gid}'\")))\nPY")
        ids = subprocess.check_output(["docker", "exec", CONTAINER, "sh", "-lc", q]).decode().split()
        if ids:
            my_ids = ids
            print(f"all resource ids for gateway (incl templates): {my_ids}")
    except Exception as e:
        print(f"DB id lookup failed: {e}")

    def mark(label):
        upstream_calls.append({"_marker": label, "ts": time.time()})

    res_uri = "note://repro"

    # Federated resource reads must go through a virtual-server MCP endpoint
    # (/servers/{id}/mcp) -- CF itself says so ("use /servers/{id}/mcp"). Create
    # a virtual server exposing the discovered resource.
    st, srv = cf("POST", "/servers", tok, {"server": {
        "name": f"vs-repro-{int(time.time())}", "visibility": "public",
        "associated_resources": my_ids or [res_id]}})
    print(f"create virtual server -> HTTP {st}: {json.dumps(srv)[:160]}")
    if st >= 300:
        print("could not create virtual server; aborting")
        return
    sid = srv.get("id")
    vs_url = f"{CF}/servers/{sid}/mcp"
    print(f"virtual server MCP: {vs_url}")

    from strangertest.mcp_client import MCPClient
    from strangertest.transports import HTTPTransport

    def do_read(label, mode, uri):
        AS_MODE["mode"] = mode
        mark(label)
        print(f"\n--- {label} (AS={mode}) read {uri} ---")
        c = MCPClient(HTTPTransport(vs_url, headers={"Authorization": f"Bearer {tok}"}))
        try:
            c.initialize()
            out = c.read_resource(uri)
            print(f"  read_resource -> {json.dumps(out)[:160]}")
        except Exception as e:
            print(f"  read_resource error: {type(e).__name__}: {str(e)[:200]}")
        finally:
            try:
                c.close()
            except Exception:
                pass

    # Read UNCACHED template-instance URIs so CF must federate via invoke_resource
    # (the live RFC 8693 exchange path), not serve a cached catalog entry.
    # 2. CONTROL (AS=ok): proves resources/read reaches upstream WITH auth.
    do_read("=== CONTROL READ (AS=ok) ===", "ok", "note://live-ok")
    # 3. TEST (AS=fail): the question.
    do_read("=== TEST READ (AS=fail) ===", "fail", "note://live-fail")
    # also try the cached static resource under fail, for completeness
    do_read("=== CACHED READ (AS=fail) ===", "fail", res_uri)

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

    control = phase_calls("=== CONTROL READ (AS=ok) ===")
    test = phase_calls("=== TEST READ (AS=fail) ===")
    control_read = [c for c in control if c["method"] == "resources/read"]
    test_read = [c for c in test if c["method"] == "resources/read"]

    print("\n================ SUMMARY ================")
    print(f"CONTROL (ok)  upstream methods: {[c['method'] for c in control]}")
    print(f"   resources/read reached upstream: {bool(control_read)}; "
          f"auth present: {control_read[0]['auth_header_present'] if control_read else 'n/a'}")
    print(f"TEST (fail)   upstream methods: {[c['method'] for c in test]}")
    print(f"   resources/read reached upstream: {bool(test_read)}; "
          f"auth present: {test_read[0]['auth_header_present'] if test_read else 'n/a'}")

    if not control_read:
        verdict = "INCONCLUSIVE: control read did not reach upstream -- recorder/read path broken, cannot trust the fail-phase observation"
    elif test_read and not test_read[0]["auth_header_present"]:
        verdict = "BUG REPRODUCED: resources/read forwarded upstream with NO Authorization header when the token exchange failed"
    elif test_read and test_read[0]["auth_header_present"]:
        verdict = "NOT THE BUG: resources/read forwarded upstream but WITH an Authorization header during exchange failure"
    else:
        verdict = "FAIL CLOSED: no resources/read reached upstream while the exchange was failing (control read DID reach upstream, so the read path works)"
    print("\nVERDICT:", verdict)

    out = {
        "probe": "xid10-resource-read-exchange-failure",
        "gateway": "ContextForge", "gateway_version": "1.0.6",
        "image": "ghcr.io/ibm/mcp-context-forge:v1.0.6",
        "container": CONTAINER,
        "method": "fresh oauth token-exchange gateway; toggleable AS returns a signed token in ok mode and HTTP 400 invalid_grant in fail mode; recorder echoes the client's requested protocolVersion so the MCP SDK never aborts initialize",
        "oauth_config": {**oauth_config, "client_secret": "REDACTED"},
        "upstream_url": gw["url"],
        "inbound_caller": "admin JWT (3-part; CF looks_like_jwt guard passes, real exchange attempted)",
        "trigger": "MCP resources/read via virtual server POST /servers/{id}/mcp (the federated read path CF directs clients to)",
        "control_read_reached_upstream": bool(control_read),
        "control_read_auth_present": control_read[0]["auth_header_present"] if control_read else None,
        "test_read_reached_upstream": bool(test_read),
        "test_read_auth_present": test_read[0]["auth_header_present"] if test_read else None,
        "as_attempts": as_attempts,
        "upstream_calls": [c for c in upstream_calls if "_marker" not in c],
        "phase_markers": [c for c in upstream_calls if "_marker" in c],
        "verdict": verdict,
    }
    runs = os.path.join(REPO, "integration", "runs")
    os.makedirs(runs, exist_ok=True)
    path = os.path.join(runs, f"contextforge-1.0.6-resource-exchange-fail-repro-{int(time.time())}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print("saved ->", path)

    # cleanup the virtual server + gateway we created
    cf("DELETE", f"/servers/{sid}", tok)
    cf("DELETE", f"/gateways/{gid}", tok)
    print("deleted virtual server", sid, "and gateway", gid)


if __name__ == "__main__":
    main()
