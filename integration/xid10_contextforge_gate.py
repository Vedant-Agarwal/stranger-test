"""XID-10 gate against a REAL third-party gateway: IBM ContextForge 1.1.1.

Drives the delegation probe through a running ContextForge gateway configured
for RFC 8693 token exchange against the local AS. ContextForge is the deputy
under test; local_as is the IdP; a recording MCP server is the upstream.

Prerequisites (see integration/CONTEXTFORGE_GATE.md for the full recipe):
  * ContextForge 1.1.1 running on http://127.0.0.1:4444 with, in its .env:
      SSO_API_TOKEN_AUTH_ENABLED=true, SSRF_ALLOW_LOCALHOST=true
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
    print(f"SKIP: needs pyjwt[crypto] + local_as ({exc})")
    sys.exit(0)

from strangertest.delegate import MockUpstream, run_delegation_probe
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
        outer = self
        TOOL = {"name": "read_note", "description": "Read the caller's note.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}

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
                    outer._rec(m, bearer)
                    uri = (msg.get("params") or {}).get("uri", "note://caller")
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "contents": [{"uri": uri, "mimeType": "text/plain", "text": "ok"}],
                        **_RESULT}})
                    return
                if m == "tools/call":
                    outer._rec(m, bearer)
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "content": [{"type": "text", "text": "ok"}], "isError": False, **_RESULT}})
                    return
                self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no"}})

        # Listen on BOTH loopback families on the same port, so CF reaches us
        # whether localhost resolves to 127.0.0.1 or ::1 — loopback only.
        self._srv4 = _HTTP4(("127.0.0.1", 0), H)
        self._port = self._srv4.server_address[1]
        self._srv6 = _HTTP6(("::1", self._port), H)

    def _rec(self, method, bearer):
        try:
            c = jwt.decode(bearer, self._key, algorithms=["RS256"], issuer=self._iss,
                           options={"verify_aud": False, "verify_exp": True, "require": ["exp", "iss"]})
        except Exception as e:
            self.receive(token=bearer, parsed=False, parse_error=str(e), method=method)
            return
        act = c.get("act")
        # Identity is the ORIGINAL login provider (orig_iss), not the exchange
        # AS — so a gateway that conflates same-named users from two providers
        # is caught. Fall back to iss for non-exchange tokens.
        self.receive(subject=c.get("sub"),
                     actor=act.get("sub") if isinstance(act, dict) else None,
                     audience=c.get("aud"), scope=c.get("scope"), token=bearer,
                     issuer=c.get("orig_iss") or c.get("iss"), parsed=True, method=method)

    @property
    def url(self):
        # CF rejects IPv6 URLs and rewrites 127.0.0.1 -> localhost; we listen on
        # both loopback families at this port, so either resolution reaches us.
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


def upsert_provider(pid, issuer, as_base):
    """Insert/replace an SSOProvider trusted for external API auth, with the
    given id and issuer, validating tokens against the live AS JWKS."""
    from mcpgateway.db import SSOProvider, SessionLocal
    from mcpgateway.config import get_settings
    from mcpgateway.services.encryption_service import get_encryption_service
    sec = get_encryption_service(get_settings().auth_encryption_secret).encrypt_secret("unused")
    with SessionLocal() as db:
        old = db.get(SSOProvider, pid)
        if old:
            db.delete(old); db.commit()
        db.add(SSOProvider(
            id=pid, name=pid, display_name=pid,
            provider_type="oidc", is_enabled=True, client_id="forge",
            client_secret_encrypted=sec, authorization_url=f"{as_base}/authorize",
            token_url=f"{as_base}/token", userinfo_url=f"{as_base}/userinfo",
            issuer=issuer, jwks_uri=f"{as_base}/jwks", trusted_for_api_auth=True,
            api_audience=API_AUD, trusted_domains=[], scope="openid",
            auto_create_users=True, team_mapping={}, provider_metadata={}))
        db.commit()


def ensure_tool_access(emails):
    """Grant the external users tool-execution access the ORDINARY way: a
    team-scoped `developer` role (which carries tools.execute), NOT admin.

    External SSO users get session-semantics tokens, so ContextForge's
    streamable RBAC checks across all their team roles; a developer role in any
    team satisfies the tools.execute gate without admin privileges. This keeps
    the run on a normal authorization path. (ContextForge's tool-execution RBAC
    is orthogonal to the delegation behavior XID-10 actually tests.)
    """
    import uuid
    from mcpgateway.db import (SessionLocal, EmailUser, EmailTeam,
                               EmailTeamMember, UserRole, Role)
    with SessionLocal() as db:
        dev = db.query(Role).filter_by(name="developer").first()
        team = db.query(EmailTeam).filter_by(name="xid10-team").first()
        if team is None:
            team = EmailTeam(id=uuid.uuid4().hex, name="xid10-team", slug="xid10-team",
                             description="XID-10 gate", created_by=emails[0],
                             is_personal=False, visibility="private", is_active=True)
            db.add(team); db.flush()
        for e in emails:
            u = db.query(EmailUser).filter_by(email=e).first()
            if u is None:
                # Must be provisioned by its own provider first — skip, don't
                # create (creating here binds the email to the default provider).
                print(f"  warn: {e} not provisioned yet; skipping role grant")
                continue
            u.is_admin = False
            if not db.query(EmailTeamMember).filter_by(team_id=team.id, user_email=e).first():
                db.add(EmailTeamMember(id=uuid.uuid4().hex, team_id=team.id,
                                       user_email=e, role="member", is_active=True))
            if not db.query(UserRole).filter_by(user_email=e, role_id=dev.id,
                                                scope_id=team.id).first():
                db.add(UserRole(id=uuid.uuid4().hex, user_email=e, role_id=dev.id,
                                scope="team", scope_id=team.id, granted_by=emails[0],
                                is_active=True))
        db.commit()


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
    # Persistent local_as (8790) and ContextForge (4444) run externally; the
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
        # Same username "alice" from two different login providers (TrustGate's
        # bug): the gateway must keep them distinct through the exchange.
        principals = [("A", "alice", "https://provx.test", "alice@provx.test"),
                      ("B", "alice", "https://provy.test", "alice@provy.test")]
        upsert_provider("provx", "https://provx.test", AS_BASE)
        upsert_provider("provy", "https://provy.test", AS_BASE)
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
        ensure_tool_access([p[3] for p in principals])

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
            }, f, indent=2)
        print(f"saved run -> {out}")
    finally:
        up.stop()


if __name__ == "__main__":
    main()
