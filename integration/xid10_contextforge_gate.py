"""XID-10 gate against a REAL third-party gateway: IBM ContextForge 1.1.1.

Drives the delegation probe through a running ContextForge gateway configured
for RFC 8693 token exchange against the local AS. ContextForge is the deputy
under test; local_as is the IdP; a recording MCP server is the upstream.

Prerequisites (see integration/CONTEXTFORGE_GATE.md for the full recipe):
  * ContextForge 1.1.1 running on http://127.0.0.1:4444 with, in its .env:
      SSO_ENABLED=true, SSO_API_TOKEN_AUTH_ENABLED=true, SSRF_ALLOW_LOCALHOST=true
  * run from the CF home dir with its .env sourced, in a venv that has both
    mcpgateway and pyjwt installed.

This is NOT a unittest; it is an operator-driven gate. Verbose by design.
"""

from __future__ import annotations

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


class _HTTP4(ThreadingHTTPServer):
    allow_reuse_address = True


class _HTTP6(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True


# 2026-07-28 cacheable-result fields the SDK validates on list results.
_RESULT = {"resultType": "complete"}
_LIST_RESULT = {"resultType": "complete", "cacheScope": "private", "ttlMs": 0}

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import jwt  # noqa: F401
    from local_as import LocalAS
except Exception as exc:  # pragma: no cover
    print(f"ERROR: cannot run the XID-10 ContextForge gate: needs pyjwt[crypto] + local_as "
          f"({exc})", file=sys.stderr)
    sys.exit(2)

from strangertest.delegate import (MockUpstream, grade_issuer_email_crossprovider,
                                   observe_one_call, run_delegation_probe,
                                   run_issuer_unregistered_probe, run_scope_narrowing_probe,
                                   gate_run_problems, request_nonce)
from strangertest.mcp_client import MCPClient
from strangertest.probe import Identity, ProbeError
from strangertest.transports import HTTPTransport

CF = os.environ.get("CF_URL", "http://127.0.0.1:4444")
AS_ISSUER = "https://local-as.test"
API_AUD = "mcpgateway-api"
UPSTREAM_AUD = "https://upstream.test/mcp"


def jlog(label, obj):
    print(f"  {label}: {json.dumps(obj)[:300]}")


# ---------------------------------------------------------------- upstream
class Upstream(MockUpstream):
    """Modern-JSON MCP upstream: answers server/discover + tools/list +
    tools/call + resources/read, validating each bearer against local_as JWKS."""

    def __init__(self, audience, jwks, issuer):
        super().__init__(audience)
        self._iss = issuer
        self._key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
        self.emails = {}  # token fingerprint -> email claim
        outer = self
        TOOL = {"name": "read_note", "description": "Read the caller's note.",
                "inputSchema": {"type": "object", "properties": {"nonce": {"type": "string"}},
                                "additionalProperties": False}}

        class H(BaseHTTPRequestHandler):
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
                sys.stderr.write(f"UPSTREAM GET {self.path}\n"); sys.stderr.flush()
                self._send({"error": "use POST"}, 405)

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(n)
                sys.stderr.write(f"UPSTREAM POST {self.path} :: {raw[:160]!r}\n"); sys.stderr.flush()
                auth = self.headers.get("Authorization", "")
                bearer = auth[7:] if auth.startswith("Bearer ") else auth
                try:
                    msg = json.loads(raw)
                except ValueError:
                    self._send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse"}})
                    return
                m, mid = msg.get("method"), msg.get("id")
                meta = {"io.modelcontextprotocol/serverInfo": {"name": "upstream", "version": "1.0"}}
                if m in ("initialize", "server/discover"):
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": "2026-07-28",
                        "capabilities": {"tools": {"listChanged": False}, "resources": {}},
                        "serverInfo": {"name": "upstream", "version": "1.0"},
                        "supportedVersions": ["2026-07-28", "2025-11-25"],
                        "_meta": meta, **_RESULT}})
                    return
                if m == "notifications/initialized":
                    self.send_response(202); self.end_headers(); return
                if m == "tools/list":
                    outer._rec("tools/list", bearer)
                    self._send({"jsonrpc": "2.0", "id": mid,
                                "result": {"tools": [TOOL], **_LIST_RESULT}})
                    return
                if m == "resources/list":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "resources": [{"uri": "note://caller", "name": "note"}], **_LIST_RESULT}})
                    return
                if m == "resources/read":
                    outer._rec(m, bearer, msg.get("params"))
                    uri = (msg.get("params") or {}).get("uri", "note://caller")
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "contents": [{"uri": uri, "mimeType": "text/plain", "text": "ok"}],
                        **_RESULT}})
                    return
                if m == "tools/call":
                    outer._rec(m, bearer, msg.get("params"))
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "content": [{"type": "text", "text": "ok"}], "isError": False, **_RESULT}})
                    return
                self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no"}})

        # Listen on BOTH loopback families on the same port, so CF reaches us
        # whether localhost resolves to 127.0.0.1 or ::1 — loopback only.
        self._srv4 = _HTTP4(("127.0.0.1", _port_ok(UPSTREAM_PORT)), H)
        self._port = self._srv4.server_address[1]
        self._srv6 = _HTTP6(("::1", self._port), H)
        self._nonce = int(time.time())

    def _rec(self, method, bearer, params=None):
        nonce = request_nonce(params)
        try:
            c = jwt.decode(bearer, self._key, algorithms=["RS256"], issuer=self._iss,
                           options={"verify_aud": False, "verify_exp": True, "require": ["exp", "iss"]})
        except Exception as e:
            self.receive(token=bearer, parsed=False, parse_error=str(e), method=method,
                         nonce=nonce)
            return
        act = c.get("act")
        # Side record (not part of UpstreamCall): the email claim per token.
        self.emails[_fp(bearer)] = c.get("email")
        # Identity is the ORIGINAL login provider (orig_iss), not the exchange
        # AS — so a gateway that conflates same-named users from two providers
        # is caught. Fall back to iss for non-exchange tokens.
        self.receive(subject=c.get("sub"),
                     actor=act.get("sub") if isinstance(act, dict) else None,
                     audience=c.get("aud"), scope=c.get("scope"), token=bearer,
                     issuer=c.get("orig_iss") or c.get("iss"), parsed=True, method=method,
                     nonce=nonce)

    @property
    def url(self):
        # CF rejects IPv6 URLs and rewrites 127.0.0.1 -> localhost; we listen on
        # both loopback families at this port, so either resolution reaches us.
        # With a fixed UPSTREAM_PORT, a per-run path keeps each registration's
        # URL unique (CF refuses a second gateway with the same URL); the
        # upstream answers on any path.
        if UPSTREAM_PORT:
            return f"http://127.0.0.1:{self._port}/mcp/r{self._nonce}"
        return f"http://127.0.0.1:{self._port}/mcp"

    def start(self):
        for s in (self._srv4, self._srv6):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        return self

    def stop(self):
        for s in (self._srv4, self._srv6):
            s.shutdown(); s.server_close()


# ------------------------------------------------------------- CF helpers
def cf_admin_token():
    out = subprocess.check_output(
        [sys.executable, "-m", "mcpgateway.utils.create_jwt_token",
         "-u", "admin@example.com", "--admin", "-e", "600"],
        stderr=subprocess.DEVNULL)
    return out.decode().strip().splitlines()[-1]


def cf(method, path, tok, body=None):
    url = CF + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"_error": e.read().decode("utf-8", "replace")[:500]}


class CFApiMissing(SystemExit):
    """A ContextForge admin API the gate needs is not served."""


PROVIDER_API = "/auth/sso/admin/providers"


def _admin(tok):
    return tok or cf_admin_token()


def _require_api(st, resp, what, hint):
    """A 404/405 on the collection route means the API is not served at all
    (older ContextForge, or the router is switched off) -- say so plainly."""
    if st in (404, 405):
        raise CFApiMissing(
            f"ERROR: ContextForge does not serve {what} (HTTP {st}). {hint}")
    if st >= 300:
        raise SystemExit(f"ERROR: {what} -> HTTP {st}: {json.dumps(resp)[:300]}")


def _sso(method, path, tok, body=None, tries=4):
    """cf() for the SSO admin API, which 1.1.1 rate-limits (CRITICAL_SSO tier,
    10 requests/minute): on HTTP 429 wait the advertised reset and retry."""
    for _ in range(tries):
        st, resp = cf(method, path, tok, body)
        if st != 429:
            return st, resp
        try:
            wait = int(json.loads(resp.get("_error", "{}")).get("reset_in_seconds", 60))
        except (ValueError, AttributeError):
            wait = 60
        print(f"  SSO admin API rate limit (429); waiting {wait + 1}s")
        time.sleep(wait + 1)
    return st, resp


def provider_payload(pid, issuer, as_base, jwks_path="/jwks"):
    """The SSOProvider fields the gate configures. `client_secret` is a
    placeholder: ContextForge encrypts it; these providers only validate
    bearer tokens (trusted_for_api_auth) and never run a login flow."""
    return {
        "name": pid, "display_name": pid, "provider_type": "oidc",
        "client_id": "forge", "client_secret": "unused",
        "authorization_url": f"{as_base}/authorize", "token_url": f"{as_base}/token",
        "userinfo_url": f"{as_base}/userinfo", "issuer": issuer,
        "jwks_uri": f"{as_base}{jwks_path}", "scope": "openid",
        "trusted_domains": [], "auto_create_users": True, "team_mapping": {},
        "provider_metadata": {}, "trusted_for_api_auth": True, "api_audience": API_AUD}


def upsert_provider(pid, issuer, as_base, jwks_path="/jwks", tok=None):
    """Create or update an SSOProvider trusted for external API auth through
    ContextForge's supported admin API (1.1.1: POST/PUT
    /auth/sso/admin/providers, admin bearer). POST creates; on a repeat run
    the id already exists and PUT replaces every field (PUT needs
    api_audience whenever trusted_for_api_auth is true). Both calls make
    ContextForge drop its trusted-provider cache."""
    tok = _admin(tok)
    body = provider_payload(pid, issuer, as_base, jwks_path)
    st, existing = _sso("GET", PROVIDER_API, tok)
    _require_api(st, existing, f"GET {PROVIDER_API}",
                 "It needs ContextForge >= 1.1.1 started with SSO_ENABLED=true "
                 "(the SSO router, which holds the provider API, is mounted only then).")
    ids = {p.get("id") for p in existing} if isinstance(existing, list) else set()
    if pid in ids:
        st, resp = _sso("PUT", f"{PROVIDER_API}/{pid}", tok, {**body, "is_enabled": True})
        verb = "PUT"
    else:
        st, resp = _sso("POST", PROVIDER_API, tok, {"id": pid, **body})
        verb = "POST"
    if st >= 300:
        raise SystemExit(f"ERROR: {verb} {PROVIDER_API} ({pid}) -> HTTP {st}: "
                         f"{json.dumps(resp)[:300]}")
    # Read back what ContextForge stored, so a silently ignored field fails here.
    st, got = _sso("GET", f"{PROVIDER_API}/{pid}", tok)
    want = {k: body[k] for k in ("issuer", "jwks_uri", "trusted_for_api_auth", "api_audience")}
    have = {k: (got or {}).get(k) for k in want}
    if st != 200 or have != want or not (got or {}).get("is_enabled"):
        raise SystemExit(f"ERROR: provider {pid} read back as {have} "
                         f"(enabled={(got or {}).get('is_enabled')}), expected {want}")
    print(f"  provider {pid}: {verb} via API (issuer {issuer})")


TEAM_NAME = "xid10-team"


def _team_id(tok):
    st, resp = cf("GET", f"/teams/?search_query={TEAM_NAME}&limit=50", tok)
    _require_api(st, resp, "GET /teams/", "Team management needs EMAIL_AUTH_ENABLED=true.")
    teams = resp if isinstance(resp, list) else (resp.get("teams") or resp.get("data") or [])
    for t in teams:
        if t.get("name") == TEAM_NAME:
            return t.get("id")
    st, resp = cf("POST", "/teams/", tok, {"name": TEAM_NAME, "slug": TEAM_NAME,
                                          "description": "XID-10 gate",
                                          "visibility": "private"})
    if st >= 300:
        raise SystemExit(f"ERROR: POST /teams/ -> HTTP {st}: {json.dumps(resp)[:300]}")
    return resp.get("id")


def _add_member_db(team_id, email):
    """The one remaining database write: team membership for a fixture user
    whose reserved-domain address the membership API refuses (see caller)."""
    import uuid
    from mcpgateway.db import EmailTeamMember, SessionLocal
    with SessionLocal() as db:
        if not db.query(EmailTeamMember).filter_by(team_id=team_id, user_email=email).first():
            db.add(EmailTeamMember(id=uuid.uuid4().hex, team_id=team_id, user_email=email,
                                   role="member", is_active=True))
            db.commit()


def ensure_tool_access(emails, tok=None):
    """Grant the external users tool-execution access the ORDINARY way: a
    team-scoped `developer` role (which carries tools.execute), NOT admin.
    All through ContextForge's supported admin APIs (1.1.1):
      GET  /rbac/roles                       -> the developer role id
      GET/POST /teams/                       -> the xid10-team (admin is owner)
      GET  /auth/email/admin/users/{email}   -> provisioned? admin?
      PATCH /auth/email/admin/users/{email}  -> is_admin false (only if set)
      POST /teams/{id}/members               -> member
      POST /rbac/users/{email}/roles         -> developer, scope team

    External SSO users get session-semantics tokens, so ContextForge's
    streamable RBAC checks across all their team roles; a developer role in any
    team satisfies the tools.execute gate without admin privileges. (Tool
    RBAC is orthogonal to the delegation behaviour XID-10 tests.)
    Returns how many role grants were new in this call.
    """
    from urllib.parse import quote
    tok = _admin(tok)
    st, roles = cf("GET", "/rbac/roles", tok)
    _require_api(st, roles, "GET /rbac/roles", "")
    dev = next((r for r in roles if r.get("name") == "developer"), None)
    if dev is None:
        raise SystemExit("ERROR: ContextForge has no 'developer' role")
    team_id = _team_id(tok)
    granted = 0
    for e in emails:
        q = quote(e, safe="")
        st, u = cf("GET", f"/auth/email/admin/users/{q}", tok)
        if st == 404:
            # Must be provisioned by its own provider first -- skip, don't
            # create (creating here binds the email to the default provider).
            print(f"  warn: {e} not provisioned yet; skipping role grant")
            continue
        if st >= 300:
            raise SystemExit(f"ERROR: GET user {e} -> HTTP {st}: {json.dumps(u)[:300]}")
        if u.get("is_admin"):
            st, r = cf("PATCH", f"/auth/email/admin/users/{q}", tok, {"is_admin": False})
            if st >= 300:
                raise SystemExit(f"ERROR: PATCH user {e} -> HTTP {st}: {json.dumps(r)[:300]}")
        st, r = cf("POST", f"/teams/{team_id}/members", tok, {"email": e, "role": "member"})
        if st == 422 and "special-use or reserved name" in json.dumps(r):
            # 1.1.1's membership APIs (POST /teams/{id}/members, team seed
            # members, invitations) all type the address as EmailStr, which
            # rejects reserved domains such as .test. No supported API can add
            # these fixture users, so this one write stays in the database.
            _add_member_db(team_id, e)
            print(f"  {e}: membership via database (API rejects the reserved .test domain)")
        elif st >= 300 and st != 409:
            raise SystemExit(f"ERROR: add {e} to {TEAM_NAME} -> HTTP {st}: {json.dumps(r)[:300]}")
        st, have = cf("GET", f"/rbac/users/{q}/roles", tok)
        if st >= 300:
            raise SystemExit(f"ERROR: GET roles of {e} -> HTTP {st}: {json.dumps(have)[:300]}")
        if not any(h.get("role_id") == dev["id"] and h.get("scope_id") == team_id
                   and h.get("is_active", True) for h in have):
            st, r = cf("POST", f"/rbac/users/{q}/roles", tok,
                       {"role_id": dev["id"], "scope": "team", "scope_id": team_id})
            if st >= 300:
                raise SystemExit(f"ERROR: grant developer to {e} -> HTTP {st}: "
                                 f"{json.dumps(r)[:300]}")
            granted += 1
        print(f"  {e}: developer role in {TEAM_NAME} (team scope) via API")
    return granted


def wait_for_auth(as_: LocalAS, timeout=75):
    alice = as_.issue_user_token("alice", scope="read:notes", audience=API_AUD)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        req = urllib.request.Request(CF + "/version", headers={"Authorization": f"Bearer {alice}"})
        try:
            with urllib.request.urlopen(req, timeout=10):
                return True
        except urllib.error.HTTPError:
            time.sleep(5)
    return False


AS_BASE = os.environ.get("AS_BASE", "http://127.0.0.1:8790")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "0"))
# Ports that belong to other people's processes: never use them unless told to.
FORBIDDEN_PORTS = {8790, 4444}


def _port_ok(port):
    if port in FORBIDDEN_PORTS:
        raise SystemExit(f"ERROR: refusing to use reserved port {port}")
    return port


def _fp(t):
    import hashlib
    return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else t


def require_endpoints():
    """Refuse to run unless the AS and gateway URLs were set explicitly, and
    neither uses a reserved port. Returns the endpoints for the saved run."""
    from urllib.parse import urlparse
    for var in ("AS_BASE", "CF_URL"):
        if not os.environ.get(var):
            raise SystemExit(f"ERROR: refusing to start: set {var} explicitly")
    for url in (AS_BASE, CF):
        _port_ok(urlparse(url).port)
    return {"as_base": AS_BASE, "cf_url": CF, "upstream_port": UPSTREAM_PORT}


def as_issue(sub, aud=API_AUD, scope="read:notes", iss=None, email=None):
    from urllib.parse import urlencode
    q = {"sub": sub, "aud": aud, "scope": scope}
    if iss:
        q["iss"] = iss
    if email:
        q["email"] = email
    with urllib.request.urlopen(f"{AS_BASE}/issue?{urlencode(q)}", timeout=10) as r:
        return json.loads(r.read())["access_token"]


def main():
    endpoints = require_endpoints()
    mode = os.environ.get("XID10_MODE", "delegation")
    if mode in NEW_MODES:
        return main_new(mode, endpoints)
    # Persistent local_as and ContextForge run externally; the
    # SSOProvider row already points CF at this AS.
    with urllib.request.urlopen(f"{AS_BASE}/jwks", timeout=10) as r:
        jwks = json.loads(r.read())
    up = Upstream(UPSTREAM_AUD, jwks, AS_ISSUER).start()
    print(f"upstream @ {up.url}  (AS @ {AS_BASE})")
    # self-reachability: confirm CF can reach us the way it will (localhost)
    for host in (f"127.0.0.1:{up._port}", f"localhost:{up._port}", f"[::1]:{up._port}"):
        try:
            urllib.request.urlopen(f"http://{host}/", timeout=3)
            print(f"  self-reach {host}: OK")
        except urllib.error.HTTPError as e:
            print(f"  self-reach {host}: reachable ({e.code})")
        except Exception as e:
            print(f"  self-reach {host}: UNREACHABLE {type(e).__name__}")
    mode = os.environ.get("XID10_MODE", "delegation")
    print(f"=== MODE: {mode} ===")
    # Per-mode principals (label, sub, inbound issuer, email) and providers.
    if mode == "two_issuers":
        # Same username "alice" from two different login providers (the
        # cross-provider confusion class): the gateway must keep them distinct
        # through the exchange.
        principals = [("A", "alice", "https://provx.test", "alice@provx.test"),
                      ("B", "alice", "https://provy.test", "alice@provy.test")]
        # Each provider has its OWN signing key, served at /jwks/<name>.
        upsert_provider("provx", "https://provx.test", AS_BASE, "/jwks/provx")
        upsert_provider("provy", "https://provy.test", AS_BASE, "/jwks/provy")
        delegation_actor = True
    else:
        principals = [("A", "alice", None, "alice@local-as.test"),
                      ("B", "bob", None, "bob@local-as.test")]
        upsert_provider("local-as", AS_ISSUER, AS_BASE)
        delegation_actor = (mode == "delegation")
    try:
        tok = cf_admin_token()
        oauth_config = {
            "grant_type": "token-exchange", "token_url": f"{AS_BASE}/token",
            "target_audience": UPSTREAM_AUD, "subject_token_source": "inbound_user_jwt",
            "client_id": "forge",
            "client_secret": "unused", "token_endpoint_auth_method": "client_secret_post",
            "scopes": ["read:notes"],
            # token-exchange gateways skip registration-time discovery (no user
            # token yet) unless a discovery credential is given — use client creds.
            "discovery": {"grant_type": "client_credentials", "token_url": f"{AS_BASE}/token",
                          "client_id": "forge", "client_secret": "unused",
                          "token_endpoint_auth_method": "client_secret_post",
                          "scopes": ["read:notes"]}}
        # Delegation carries an actor token (act claim); impersonation omits it.
        if delegation_actor:
            oauth_config["actor_token_source"] = "client_credentials"
        gw = {"name": f"xid10-{int(time.time())}", "url": up.url,
              "transport": "STREAMABLEHTTP", "authType": "oauth",
              "visibility": "public", "oauthConfig": oauth_config}
        st, resp = cf("POST", "/v1/gateways", tok, gw)
        print(f"register gateway -> HTTP {st}")
        jlog("gateway", resp)
        if st >= 300:
            return
        gid = resp.get("id")
        # discover tools
        st, rr = cf("POST", f"/v1/gateways/{gid}/tools/refresh", tok, {})
        print(f"tools/refresh -> HTTP {st}")
        # discovery may be async; poll briefly
        mine = []
        for _ in range(10):
            st, tools = cf("GET", "/v1/tools", tok)
            allt = tools if isinstance(tools, list) else tools.get("data", [])
            mine = [t for t in allt
                    if t.get("gatewayId") == gid or t.get("gateway_id") == gid]
            if allt:
                break
            time.sleep(2)
        print(f"discovered tools for gateway: {[t.get('name') for t in mine]}")
        jlog("all tools (sample)", (tools if isinstance(tools, list) else tools)[:2]
             if isinstance(tools, list) else tools)
        if not mine:
            print("stopping: no tools discovered"); return
        tool_id = mine[0].get("id")
        tool_name = mine[0].get("name")
        # discover resources too (for the resources/read path)
        st, res = cf("GET", "/v1/resources", tok)
        allr = res if isinstance(res, list) else (res.get("data", []) if isinstance(res, dict) else [])
        myres = [r for r in allr if r.get("gatewayId") == gid or r.get("gateway_id") == gid]
        res_ids = [r.get("id") for r in myres if r.get("id") is not None]
        res_uri = myres[0].get("uri") if myres else None
        print(f"discovered resources: {[r.get('uri') for r in myres]}")
        # virtual server exposing the tool + resource (body is wrapped in `server`)
        st, srv = cf("POST", "/v1/servers", tok,
                     {"server": {"name": f"vs-{int(time.time())}",
                                 "visibility": "public",
                                 "associated_tools": [tool_id],
                                 "associated_resources": res_ids}})
        print(f"create virtual server -> HTTP {st}")
        jlog("server", srv)
        if st >= 300:
            return
        sid = srv.get("id")
        vs_url = f"{CF}/servers/{sid}/mcp"
        print(f"gateway={gid} server={sid} tool={tool_name}")
        print(f"virtual server MCP: {vs_url}")

        # Provision each principal under its OWN provider FIRST (an initialize
        # call binds the email to the right provider), waiting out the 60s
        # trusted-provider cache. Only then grant roles — pre-creating the user
        # here would bind the email to the default provider and block the real
        # provider's sign-in (ContextForge: one email -> one provider).
        import urllib.request as _u
        for (_, sub, iss, email) in principals:
            t = as_issue(sub, iss=iss, email=email)
            deadline = time.monotonic() + 80
            while time.monotonic() < deadline:
                r = _u.Request(vs_url, data=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"w","version":"0"}}}',
                               method="POST", headers={"Authorization": f"Bearer {t}",
                               "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
                try:
                    _u.urlopen(r, timeout=10); print(f"provisioned {email} ({iss})"); break
                except urllib.error.HTTPError as e:
                    if e.code != 401:
                        print(f"provisioned {email} (HTTP {e.code})"); break
                    time.sleep(5)
        if ensure_tool_access([p[3] for p in principals]):
            # A role granted just now is invisible until CF's 60 s role cache
            # entry from the first sign-in expires (the new modes always wait).
            wait_role_cache()

        def ident(label, sub, iss, email):
            return Identity(label=label, connect=lambda: MCPClient(HTTPTransport(
                vs_url, headers={"Authorization":
                                 f"Bearer {as_issue(sub, iss=iss, email=email)}"})))

        (la, sa, ia, ea), (lb, sb, ib, eb) = principals
        trigger_kind = os.environ.get("XID10_TRIGGER", "tool")
        if trigger_kind == "resource" and res_uri:
            trigger = lambda c: c.read_resource(res_uri)
            print(f"trigger: resources/read {res_uri}")
        else:
            trigger = lambda c: c.call_tool(tool_name, {})
            print(f"trigger: tools/call {tool_name}")
        print("=== running delegation probe through ContextForge ===")
        # The exchange carries the end user's ORIGINAL issuer (orig_iss), so
        # identity is graded on (orig_iss, subject): a gateway conflating two
        # same-named users from different providers would be caught.
        report = run_delegation_probe(
            vs_url, ident(la, sa, ia, ea), ident(lb, sb, ib, eb),
            upstream=up, trigger=trigger,
            expected_subject_a=sa, expected_subject_b=sb,
            expected_issuer_a=(ia or AS_ISSUER), expected_issuer_b=(ib or AS_ISSUER))
        print("CHECKS:", json.dumps(report.checks))
        print("VULNERABLE:" , report.vulnerable, "FAILURES:", report.failures)
        print(report.summary())

        # Save the run: mode, checks, the three recorded upstream calls, versions.
        _, ver = cf("GET", "/version", tok)
        cf_ver = (ver or {}).get("app", {}).get("version") if isinstance(ver, dict) else None
        runs_dir = os.path.join(_HERE, "runs")
        os.makedirs(runs_dir, exist_ok=True)
        out = os.path.join(runs_dir, f"contextforge-{mode}-{int(time.time())}.json")
        # Redact bearer tokens to a short fingerprint — never persist full JWTs.
        import hashlib
        def _fp(t):
            return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else t
        redacted_calls = [{**c, "token": _fp(c.get("token"))} for c in report.calls]
        with open(out, "w") as f:
            json.dump({
                "probe": "xid10-delegation", "mode": mode, "trigger": trigger_kind,
                "gateway": "ContextForge", "gateway_version": cf_ver,
                "authorization_note": "external users granted tools.execute via a "
                                      "team-scoped developer role (not admin)",
                "checks": report.checks, "vulnerable": report.vulnerable,
                "failures": report.failures, "summary": report.summary(),
                # Whether A's first and third (A-B-A) calls carried the same
                # exchanged token — i.e. ContextForge caches the exchange per
                # user (so the no-reuse/bleed checks are meaningful here).
                "a_first_eq_a_third_token": (
                    len(report.calls) >= 3
                    and report.calls[0].get("token") == report.calls[2].get("token")),
                "recorded_calls": redacted_calls,
                "endpoints": endpoints,
            }, f, indent=2)
        print(f"saved run -> {out}")
    finally:
        up.stop()


# =========================================================================
# New checks: scope narrowing (CoSAI 3.3.2) and issuer binding (3.2.2/3.3.2)
# =========================================================================
NEW_MODES = ("scope_narrowing", "issuer_unregistered", "issuer_email_crossprovider")
UNREGISTERED = "https://unregistered.test"
PROVX, PROVY = "https://provx.test", "https://provy.test"
FIXTURE_PORT = int(os.environ.get("FIXTURE_PORT", "0"))  # thin-fixture upstream; +1 deputy


def _gw_scopes():
    """XID10_GW_SCOPES: space-separated scopes ContextForge requests in the
    exchange (oauth_config.scopes). Default 'read:notes'; 'NONE' -> []."""
    raw = os.environ.get("XID10_GW_SCOPES", "read:notes")
    return [] if raw.strip().upper() == "NONE" else raw.split()


def setup_cf_gateway(up, tok, scopes, delegation_actor=True):
    """Register the upstream as an oauth token-exchange gateway, discover its
    tool, expose it on a virtual server. Returns (vs_url, tool_name, oauth_config)."""
    oauth_config = {
        "grant_type": "token-exchange", "token_url": f"{AS_BASE}/token",
        "target_audience": UPSTREAM_AUD, "subject_token_source": "inbound_user_jwt",
        "client_id": "forge", "client_secret": "unused",
        "token_endpoint_auth_method": "client_secret_post",
        "scopes": scopes,
        "discovery": {"grant_type": "client_credentials", "token_url": f"{AS_BASE}/token",
                      "client_id": "forge", "client_secret": "unused",
                      "token_endpoint_auth_method": "client_secret_post",
                      "scopes": ["read:notes"]}}
    if delegation_actor:
        oauth_config["actor_token_source"] = "client_credentials"
    gw = {"name": f"xid10-{int(time.time())}", "url": up.url, "transport": "STREAMABLEHTTP",
          "authType": "oauth", "visibility": "public", "oauthConfig": oauth_config}
    st, resp = cf("POST", "/v1/gateways", tok, gw)
    print(f"register gateway -> HTTP {st}")
    if st >= 300:
        raise SystemExit(f"gateway registration failed: {json.dumps(resp)[:300]}")
    gid = resp.get("id")
    cf("POST", f"/v1/gateways/{gid}/tools/refresh", tok, {})
    mine = []
    for _ in range(10):
        _, tools = cf("GET", "/v1/tools", tok)
        allt = tools if isinstance(tools, list) else tools.get("data", [])
        mine = [t for t in allt if t.get("gatewayId") == gid or t.get("gateway_id") == gid]
        if mine:
            break
        time.sleep(2)
    if not mine:
        raise SystemExit("no tools discovered")
    st, srv = cf("POST", "/v1/servers", tok, {"server": {
        "name": f"vs-{int(time.time())}", "visibility": "public",
        "associated_tools": [mine[0].get("id")]}})
    if st >= 300:
        raise SystemExit(f"virtual server failed: {json.dumps(srv)[:300]}")
    vs_url = f"{CF}/servers/{srv.get('id')}/mcp"
    print(f"virtual server MCP: {vs_url}  tool={mine[0].get('name')}")
    return vs_url, mine[0].get("name"), oauth_config


def provision(vs_url, token, label, timeout=80):
    """Sign the user in once (initialize) so CF provisions it under its own
    provider; waits out CF's trusted-provider cache. Returns the last HTTP code."""
    deadline = time.monotonic() + timeout
    code = None
    while time.monotonic() < deadline:
        r = urllib.request.Request(vs_url, data=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"w","version":"0"}}}',
                                   method="POST", headers={"Authorization": f"Bearer {token}",
                                   "Content-Type": "application/json",
                                   "Accept": "application/json, text/event-stream"})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                code = resp.status
            break
        except urllib.error.HTTPError as e:
            code = e.code
            if e.code != 401:
                break
            time.sleep(5)
    print(f"provision {label}: HTTP {code}")
    return code


def wait_role_cache():
    """CF caches a user's roles for 60s (AuthCache role_ttl); a role granted
    right after first sign-in is not visible until that entry expires."""
    secs = int(os.environ.get("CF_ROLE_CACHE_WAIT", "65"))
    print(f"waiting {secs}s for ContextForge's role cache")
    time.sleep(secs)


def fixed_ident(url, label, token):
    return Identity(label=label, connect=lambda: MCPClient(HTTPTransport(
        url, headers={"Authorization": f"Bearer {token}"})))


def as_facts():
    with urllib.request.urlopen(f"{AS_BASE}/.well-known/openid-configuration", timeout=10) as r:
        d = json.loads(r.read())
    return {"lax_subject_issuer": d.get("x_lax_subject_issuer"),
            "providers": d.get("x_providers"), "scope_cap": d.get("x_scope_cap")}


def as_exchanges():
    with urllib.request.urlopen(f"{AS_BASE}/exchanges", timeout=10) as r:
        return json.loads(r.read())


def as_issue_k(sub, *, iss=None, email=None, scope="read:notes", key=None):
    from urllib.parse import urlencode
    q = {"sub": sub, "aud": API_AUD, "scope": scope}
    for k, v in (("iss", iss), ("email", email), ("key", key)):
        if v:
            q[k] = v
    with urllib.request.urlopen(f"{AS_BASE}/issue?{urlencode(q)}", timeout=10) as r:
        return json.loads(r.read())["access_token"]


def cf_user_provider(email, tok=None):
    """Which provider an email is bound to (or None), via the admin user API
    (GET /auth/email/admin/users/{email} -> auth_provider)."""
    from urllib.parse import quote
    st, u = cf("GET", f"/auth/email/admin/users/{quote(email, safe='')}", _admin(tok))
    if st == 404:
        return None
    if st >= 300:
        raise SystemExit(f"ERROR: GET user {email} -> HTTP {st}: {json.dumps(u)[:300]}")
    return u.get("auth_provider")


def save_new_run(name, payload):
    """Save the run (always), marked run_valid / run_problems; exit 1 with an
    ERROR line per problem when the broken fixture did not FAIL or a positive
    control failed. An honest grade with all controls fine returns normally."""
    problems = gate_run_problems(payload)
    payload = {**payload, "run_valid": not problems, "run_problems": problems}
    _save_new_run(name, payload)
    if problems:
        for prob in problems:
            print(f"ERROR: {prob}", file=sys.stderr)
        raise SystemExit(1)


def _save_new_run(name, payload):
    runs_dir = os.path.join(_HERE, "runs")
    os.makedirs(runs_dir, exist_ok=True)
    out = os.path.join(runs_dir, f"contextforge-{name}-{int(time.time())}.json")
    text = json.dumps(payload, indent=2, default=str)
    import re
    if re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.", text):
        raise SystemExit("refusing to save: a JWT-shaped string is in the run")
    with open(out, "w") as f:
        f.write(text)
    print(f"saved run -> {out}")


def main_new(mode, endpoints):
    import xid10_thin_deputy_gate as thin
    with urllib.request.urlopen(f"{AS_BASE}/jwks", timeout=10) as r:
        jwks = json.loads(r.read())
    facts = as_facts()
    print(f"=== MODE: {mode} ===  AS {AS_BASE} facts={facts}")
    if mode.startswith("issuer_unregistered") and not facts.get("lax_subject_issuer"):
        raise SystemExit("issuer_unregistered needs the AS started with --lax-subject-issuer "
                         "(otherwise the AS, not the gateway, could be what refuses)")
    up = Upstream(UPSTREAM_AUD, jwks, AS_ISSUER).start()
    endpoints = dict(endpoints, upstream_url=up.url,
                     fixture_ports=[FIXTURE_PORT, FIXTURE_PORT + 1] if FIXTURE_PORT else "ephemeral")
    _, ver = cf("GET", "/version", cf_admin_token())
    cf_ver = (ver or {}).get("app", {}).get("version") if isinstance(ver, dict) else None
    base = {"gateway": "ContextForge", "gateway_version": cf_ver, "mode": mode,
            "endpoints": endpoints, "as_facts": facts,
            "env": {k: os.environ.get(k) for k in (
                "SSO_API_TOKEN_AUTH_ENABLED", "SSO_ALLOW_PROVIDER_LINKING",
                "SSRF_ALLOW_LOCALHOST", "MCP_CLIENT_CONNECT_MODE")},
            "sso_allow_provider_linking_default": "false (mcpgateway/config.py "
                                                  "sso_allow_provider_linking)"}
    fx = dict(upstream_port=FIXTURE_PORT, deputy_port=FIXTURE_PORT + 1 if FIXTURE_PORT else 0)
    try:
        tok = cf_admin_token()
        if mode == "scope_narrowing":
            scopes = _gw_scopes()
            # In-run broken fixture: the thin deputy that forwards more scope
            # than the user had must FAIL against this same AS, or no OK.
            broken = thin.run_scope_fixture(AS_BASE, "scope_escalation", controls={}, **fx)
            print(f"broken fixture: {broken.summary()}")
            upsert_provider("local-as", AS_ISSUER, AS_BASE, "/jwks")
            vs_url, tool_name, oc = setup_cf_gateway(up, tok, scopes)
            subj = thin.SUBJECT_SCOPE_BROAD
            for sub in ("alice", "bob"):
                provision(vs_url, as_issue_k(sub, email=f"{sub}@local-as.test", scope=subj), sub)
            ensure_tool_access(["alice@local-as.test", "bob@local-as.test"])
            wait_role_cache()

            def ident(label, sub):
                return Identity(label=label, connect=lambda: MCPClient(HTTPTransport(
                    vs_url, headers={"Authorization": "Bearer " + as_issue_k(
                        sub, email=f"{sub}@local-as.test", scope=subj)})))
            res = run_scope_narrowing_probe(
                vs_url, ident("A", "alice"), ident("B", "bob"), upstream=up,
                trigger=lambda c: c.call_tool(tool_name, {}),
                subject_scope=subj, configured_scope=" ".join(scopes),
                exchange_lookup=thin.exchange_lookup_http(AS_BASE),
                controls={"broken_fixture_failed": broken.grade == "FAIL"})
            print(res.summary())
            for c in res.per_call:
                print(f"  {c['principal']}: {c['grade']} who={c['who_narrowed']}")
            name = "scope_narrowing" + ("" if scopes == ["read:notes"] else
                                        "-" + ("noscopes" if not scopes else "custom"))
            save_new_run(name, {**res.to_dict(), **base,
                                "gateway_config": {"oauth_config_scopes": scopes,
                                                   "oauth_config_sha256": hashlib_sha(oc)},
                                "broken_fixture": {"name": "thin_deputy scope_escalation",
                                                   "grade": broken.grade,
                                                   "reason": broken.reason}})
        elif mode == "issuer_unregistered":
            broken = thin.run_issuer_fixture(AS_BASE, "issuer_any", controls={}, **fx)
            print(f"broken fixture: {broken.summary()}")
            upsert_provider("provx", PROVX, AS_BASE, "/jwks/provx")
            upsert_provider("provy", PROVY, AS_BASE, "/jwks/provy")
            vs_url, tool_name, oc = setup_cf_gateway(up, tok, ["read:notes"])
            common = dict(sub="mallory", email="mallory@provx.test", key="provx")
            control_tok = as_issue_k(common["sub"], iss=PROVX, email=common["email"], key="provx")
            probe_tok = as_issue_k(common["sub"], iss=UNREGISTERED, email=common["email"],
                                   key="provx")
            provision(vs_url, control_tok, "mallory via provx")
            ensure_tool_access([common["email"]])
            wait_role_cache()
            res = run_issuer_unregistered_probe(
                vs_url, control_identity=fixed_ident(vs_url, "control", control_tok),
                probe_identity=fixed_ident(vs_url, "probe", probe_tok), upstream=up,
                trigger=lambda c, n: c.call_tool(tool_name, {"nonce": n}),
                probe_token_fp=_fp(probe_tok), probe_issuer=UNREGISTERED,
                exchange_records=as_exchanges,
                controls={"broken_fixture_failed": broken.grade == "FAIL"}, quiet_seconds=3,
                settle_seconds=2)
            print(res.summary())
            save_new_run("issuer_unregistered", {**res.to_dict(), **base,
                         "signing_key_of_probe": "provx (trusted by ContextForge for provx)",
                         "gateway_config": {"providers": {"provx": "/jwks/provx",
                                                          "provy": "/jwks/provy"},
                                            "oauth_config_sha256": hashlib_sha(oc)},
                         "broken_fixture": {"name": "thin_deputy issuer_any",
                                            "grade": broken.grade, "reason": broken.reason}})
        elif mode == "issuer_email_crossprovider":
            upsert_provider("provx", PROVX, AS_BASE, "/jwks/provx")
            upsert_provider("provy", PROVY, AS_BASE, "/jwks/provy")
            vs_url, tool_name, oc = setup_cf_gateway(up, tok, ["read:notes"])
            trig = lambda c: c.call_tool(tool_name, {})
            y_email = "carol@provy.test"
            y_tok = as_issue_k("carol-y", iss=PROVY, email=y_email)
            dave_tok = as_issue_k("dave-x", iss=PROVX, email="dave@provx.test")
            probe_tok = as_issue_k("carol-x", iss=PROVX, email=y_email)
            y_code = provision(vs_url, y_tok, "carol via provY (binds the email)")
            d_code = provision(vs_url, dave_tok, "dave via provX (control)")
            ensure_tool_access([y_email, "dave@provx.test"])
            wait_role_cache()
            bound_before = cf_user_provider(y_email)
            y_calls, y_err = observe_one_call(fixed_ident(vs_url, "Y", y_tok), up, trig)
            x_calls, x_err = observe_one_call(fixed_ident(vs_url, "Xctl", dave_tok), up, trig)
            p_calls, p_err = observe_one_call(fixed_ident(vs_url, "probe", probe_tok), up, trig)
            bound_after = cf_user_provider(y_email)
            pc = [{"subject": c.subject, "issuer": c.issuer, "token": _fp(c.token),
                   "email": up.emails.get(_fp(c.token)), "scope": c.scope} for c in p_calls]
            grade, label, reason = grade_issuer_email_crossprovider(
                probe_calls=pc, control_reached=bool(x_calls), x_issuer=PROVX,
                y_issuer=PROVY, y_subject="carol-y", claimed_email=y_email)
            print(f"[{grade}] {label}: {reason}")
            print(f"  email bound to provider before={bound_before} after={bound_after}; "
                  f"probe error={p_err}")
            save_new_run("issuer_email_crossprovider", {
                "probe": "issuer_email_crossprovider",
                "cosai": "CoSAI MCP Security v2.0, 3.2.2 / 3.3.2",
                "grade": grade, "label": label, "reason": reason, **base,
                "controls": {"y_reached_upstream": bool(y_calls),
                             "x_control_reached_upstream": bool(x_calls)},
                "observations": {
                    "provisioning_http": {"carol_via_provy": y_code, "dave_via_provx": d_code},
                    "email_bound_provider_before": bound_before,
                    "email_bound_provider_after": bound_after,
                    "probe_accepted": bool(p_calls), "probe_error": p_err,
                    "probe_upstream_calls": pc,
                    "y_upstream_identity": [(c.issuer, c.subject) for c in y_calls],
                    "y_error": y_err, "x_control_error": x_err},
                "gateway_config": {"providers": {"provx": "/jwks/provx", "provy": "/jwks/provy"},
                                   "oauth_config_sha256": hashlib_sha(oc)}})
    finally:
        up.stop()


def hashlib_sha(obj):
    import hashlib
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


if __name__ == "__main__":
    main()
