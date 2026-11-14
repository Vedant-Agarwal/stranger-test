"""XID-10 gate against a REAL third-party gateway: agentgateway (open source).

Drives the delegation probe through a running agentgateway configured (config
file only) for RFC 8693 token exchange against the local AS. agentgateway is the
deputy under test; local_as is the IdP; a recording MCP server is the upstream.

Prerequisites (see integration/AGENTGATEWAY_GATE.md for the full recipe):
  * local_as running on http://127.0.0.1:8790 (same AS as the ContextForge gate)
  * the agentgateway binary, path in AGW_BIN (verified v1.7.0)
  * a Python with pyjwt[crypto]

The driver starts agentgateway itself with the per-mode config from
integration/agentgateway/, so each saved run records the exact binary version
and the exact config text it ran with.

Modes (XID10_MODE): delegation | impersonation | two_issuers
Trigger (XID10_TRIGGER): tool (tools/call) | resource (resources/read)

This is NOT a unittest; it is an operator-driven gate. Verbose by design.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
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
except Exception as exc:  # pragma: no cover
    print(f"ERROR: cannot run the XID-10 agentgateway gate: needs pyjwt[crypto] ({exc})",
          file=sys.stderr)
    sys.exit(2)

from strangertest.delegate import (MockUpstream, grade_issuer_email_crossprovider,
                                   observe_one_call, run_delegation_probe,
                                   run_issuer_unregistered_probe, run_scope_narrowing_probe,
                                   gate_run_problems, request_nonce)
from strangertest.mcp_client import MCPClient
from strangertest.probe import Identity, ProbeError
from strangertest.transports import HTTPTransport

AGW_BIN = os.environ.get("AGW_BIN", "agentgateway")
AGW_URL = os.environ.get("AGW_URL", "http://127.0.0.1:3790/mcp")
AS_BASE = os.environ.get("AS_BASE", "http://127.0.0.1:8790")
AS_ISSUER = "https://local-as.test"
API_AUD = "agentgateway-api"
UPSTREAM_AUD = "https://upstream.test/mcp"
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "18790"))  # fixed: the config names it
ACTOR_CLIENT_ID = "agent-client"

CONFIGS = {
    "delegation": "xid10-delegation.yaml",
    "impersonation": "xid10-impersonation.yaml",
    "two_issuers": "xid10-two-issuers.yaml",
    # Side checks (not scenario rows):
    # a deliberately broken config: no exchange, user token passed through.
    "broken_passthrough": "xid10-broken-passthrough.yaml",
    # the delegation config, but the caller sends no x-actor-token.
    "delegation_missing_actor": "xid10-delegation.yaml",
    # New checks (scope narrowing, issuer binding):
    "scope_narrowing": "xid10-delegation.yaml",          # scopes: [read:notes]
    "scope_narrowing-noscopes": "xid10-scope-none.yaml",  # no scopes
    "issuer_unregistered": "xid10-two-issuers.yaml",
    "issuer_email_crossprovider": "xid10-two-issuers.yaml",
}
NEW_MODES = ("scope_narrowing", "issuer_unregistered", "issuer_email_crossprovider")
AGW_ADMIN_PORT = int(os.environ.get("AGW_ADMIN_PORT", "15790"))
FIXTURE_PORT = int(os.environ.get("FIXTURE_PORT", "0"))
FORBIDDEN_PORTS = {8790, 4444}
# The ports the repo configs name; substituted at run time (config-only).
_CFG_AS, _CFG_GW, _CFG_ADMIN, _CFG_UP = "127.0.0.1:8790", 3790, "127.0.0.1:15790", "127.0.0.1:18790"


def _port_ok(port):
    if port in FORBIDDEN_PORTS:
        raise SystemExit(f"ERROR: refusing to use reserved port {port}")
    return port


def require_endpoints():
    """Refuse to run unless the AS and gateway URLs were set explicitly and
    none of the ports is reserved. Returns the endpoints for the saved run."""
    from urllib.parse import urlparse
    for var in ("AS_BASE", "AGW_URL"):
        if not os.environ.get(var):
            raise SystemExit(f"ERROR: refusing to start: set {var} explicitly")
    for port in (urlparse(AS_BASE).port, urlparse(AGW_URL).port, AGW_ADMIN_PORT, UPSTREAM_PORT):
        _port_ok(port)
    return {"as_base": AS_BASE, "agw_url": AGW_URL, "agw_admin_port": AGW_ADMIN_PORT,
            "upstream_port": UPSTREAM_PORT}


def substitute_ports(text):
    """Rewrite the repo config's fixed ports to this run's ports (config only)."""
    from urllib.parse import urlparse
    as_hostport = urlparse(AS_BASE).netloc
    gw_port = urlparse(AGW_URL).port
    out = text.replace(_CFG_AS, as_hostport).replace(_CFG_ADMIN, f"127.0.0.1:{AGW_ADMIN_PORT}")
    out = out.replace(_CFG_UP, f"127.0.0.1:{UPSTREAM_PORT}")
    out = re.sub(r"(\n\s+port:\s*)%d\b" % _CFG_GW, lambda m: m.group(1) + str(gw_port), out)
    return out

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def redact(text: str) -> str:
    """Replace anything JWT-shaped with a short fingerprint before printing."""
    return _JWT_RE.sub(lambda m: _fp(m.group(0)), text)


def _fp(t):
    return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else t


def jlog(label, obj):
    print(f"  {label}: {redact(json.dumps(obj))[:300]}")


# ---------------------------------------------------------------- upstream
class Upstream(MockUpstream):
    """Modern-JSON MCP upstream: answers initialize/server/discover + tools/list +
    tools/call + resources/list + resources/read, validating each bearer
    against the local_as JWKS. Also notes, per graded call, whether the
    caller's x-actor-token header leaked through to the upstream, and the
    protocol version the gateway asked for on initialize."""

    def __init__(self, audience, jwks, issuer, port):
        super().__init__(audience)
        self._iss = issuer
        self._key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
        self.actor_header_seen = []      # one bool per graded call
        self.init_versions = []          # protocolVersion the gateway sent upstream
        self.methods_seen = []           # every method, in order (with auth y/n)
        self.upstream_proto_headers = set()  # MCP-Protocol-Version header values seen
        self.emails = {}                 # token fingerprint -> email claim (side record)
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
                self._send({"error": "use POST"}, 405)

            def do_DELETE(self):
                self.send_response(202); self.end_headers()

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(n)
                auth = self.headers.get("Authorization", "")
                bearer = auth[7:] if auth.startswith("Bearer ") else auth
                try:
                    msg = json.loads(raw)
                except ValueError:
                    self._send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse"}})
                    return
                m, mid = msg.get("method"), msg.get("id")
                outer.methods_seen.append((m, bool(bearer)))
                outer.upstream_proto_headers.add(self.headers.get("MCP-Protocol-Version"))
                sys.stderr.write(f"UPSTREAM POST {m} auth={'yes' if bearer else 'no'}\n")
                sys.stderr.flush()
                meta = {"io.modelcontextprotocol/serverInfo": {"name": "upstream", "version": "1.0"}}
                if m in ("initialize", "server/discover"):
                    outer.init_versions.append((msg.get("params") or {}).get("protocolVersion"))
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": "2026-07-28",
                        "capabilities": {"tools": {"listChanged": False}, "resources": {}},
                        "serverInfo": {"name": "upstream", "version": "1.0"},
                        "supportedVersions": ["2026-07-28", "2025-11-25"],
                        "_meta": meta, **_RESULT}})
                    return
                if m and m.startswith("notifications/"):
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
                if m in ("resources/read", "tools/call"):
                    outer.actor_header_seen.append(self.headers.get("x-actor-token") is not None)
                    outer._rec(m, bearer, msg.get("params"))
                    if m == "resources/read":
                        uri = (msg.get("params") or {}).get("uri", "note://caller")
                        result = {"contents": [{"uri": uri, "mimeType": "text/plain", "text": "ok"}]}
                    else:
                        result = {"content": [{"type": "text", "text": "ok"}], "isError": False}
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {**result, **_RESULT}})
                    return
                self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no"}})

        # Loopback only, on the fixed port the agentgateway config names.
        self._srv4 = _HTTP4(("127.0.0.1", _port_ok(port)), H)
        self._port = port

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
        self.emails[_fp(bearer)] = c.get("email")
        # Identity is the ORIGINAL login provider (orig_iss), not the exchange
        # AS — so a gateway that conflates same-named users from two providers
        # is caught. Fall back to iss for non-exchange tokens.
        self.receive(subject=c.get("sub"),
                     actor=act.get("sub") if isinstance(act, dict) else None,
                     audience=c.get("aud"), scope=c.get("scope"), token=bearer,
                     issuer=c.get("orig_iss") or c.get("iss"), parsed=True, method=method,
                     nonce=nonce)

    def start(self):
        threading.Thread(target=self._srv4.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv4.shutdown(); self._srv4.server_close()


# ------------------------------------------------------------- AS helpers
def as_issue(sub, aud=API_AUD, scope="read:notes", iss=None, email=None):
    from urllib.parse import urlencode
    q = {"sub": sub, "aud": aud, "scope": scope}
    if iss:
        q["iss"] = iss
    if email:
        q["email"] = email
    with urllib.request.urlopen(f"{AS_BASE}/issue?{urlencode(q)}", timeout=10) as r:
        return json.loads(r.read())["access_token"]


def as_actor_token(client_id=ACTOR_CLIENT_ID):
    """A client-credentials token for the calling agent (sent as x-actor-token)."""
    from urllib.parse import urlencode
    body = urlencode({"grant_type": "client_credentials", "client_id": client_id}).encode()
    req = urllib.request.Request(f"{AS_BASE}/token", data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())["access_token"]


# ------------------------------------------------------------- agw helpers
def agw_version():
    out = subprocess.check_output([AGW_BIN, "--version"], stderr=subprocess.STDOUT)
    return json.loads(out.decode())


class Gateway:
    """Run agentgateway with one config; keep its log in memory (never on disk),
    and print it only after JWT-shaped strings are fingerprinted."""

    def __init__(self, config_path):
        self.config_path = config_path
        self.lines = []
        self.proc = None

    def start(self, timeout=30):
        # agentgateway WRITES to its config file on startup (it adds a generated
        # config.session.key). Run it on a throwaway copy so the repo config
        # stays clean and no generated secret lands in git.
        import shutil, tempfile
        self._tmpdir = tempfile.mkdtemp(prefix="xid10-agw-")
        run_cfg = os.path.join(self._tmpdir, os.path.basename(self.config_path))
        with open(self.config_path) as f:
            self.run_config_text = substitute_ports(f.read())
        with open(run_cfg, "w") as f:
            f.write(self.run_config_text)
        for line in self.run_config_text.splitlines():
            if line.strip().startswith("#"):
                continue
            for bad in FORBIDDEN_PORTS:
                if re.search(r"(?<![0-9])%d(?![0-9])" % bad, line):
                    raise SystemExit(f"ERROR: refusing: run config still names port {bad}: "
                                     f"{line.strip()}")
        self.proc = subprocess.Popen([AGW_BIN, "-f", run_cfg], cwd=self._tmpdir,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1)
        threading.Thread(target=self._pump, daemon=True).start()
        host, port = AGW_URL.split("//", 1)[1].split("/", 1)[0].split(":")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("agentgateway exited early:\n" + self.tail())
            try:
                socket.create_connection((host, int(port)), timeout=1).close()
                return self
            except OSError:
                time.sleep(0.3)
        raise RuntimeError("agentgateway did not open its port:\n" + self.tail())

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))

    def tail(self, n=40):
        return "\n".join(redact(l) for l in self.lines[-n:])

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if getattr(self, "_tmpdir", None):
            import shutil
            shutil.rmtree(self._tmpdir, ignore_errors=True)


def main():
    endpoints = require_endpoints()
    mode = os.environ.get("XID10_MODE", "delegation")
    if mode in NEW_MODES:
        return main_new(mode, endpoints)
    trigger_kind = os.environ.get("XID10_TRIGGER", "tool")
    config_path = os.environ.get("AGW_CONFIG") or os.path.join(
        _HERE, "agentgateway", CONFIGS[mode])
    with open(config_path) as f:
        config_text = f.read()
    version = agw_version()
    print(f"=== MODE: {mode}  TRIGGER: {trigger_kind} ===")
    print(f"agentgateway {version.get('version')} ({version.get('git_revision')})")
    print(f"config: {config_path}  sha256:{hashlib.sha256(config_text.encode()).hexdigest()[:12]}")

    with urllib.request.urlopen(f"{AS_BASE}/jwks", timeout=10) as r:
        jwks = json.loads(r.read())
    up = Upstream(UPSTREAM_AUD, jwks, AS_ISSUER, UPSTREAM_PORT).start()
    print(f"upstream @ http://127.0.0.1:{UPSTREAM_PORT}/mcp  (AS @ {AS_BASE})")

    # Per-mode principals (label, sub, inbound issuer, email) and actor use.
    if mode == "two_issuers":
        # Same username "alice" from two different login providers: the
        # gateway must keep them distinct through the exchange.
        principals = [("A", "alice", "https://provx.test", "alice@provx.test"),
                      ("B", "alice", "https://provy.test", "alice@provy.test")]
        send_actor = True
    else:
        principals = [("A", "alice", None, "alice@local-as.test"),
                      ("B", "bob", None, "bob@local-as.test")]
        send_actor = mode in ("delegation", "broken_passthrough")

    gw = Gateway(config_path)
    report = None
    try:
        gw.start()
        print(f"agentgateway up @ {AGW_URL}")

        def headers_for(sub, iss, email):
            h = {"Authorization": f"Bearer {as_issue(sub, iss=iss, email=email)}"}
            if send_actor:
                # Delegation: the calling agent identifies itself; agentgateway
                # forwards this as the RFC 8693 actor_token.
                h["x-actor-token"] = as_actor_token()
            return h

        # Discover the tool / resource names as A (agentgateway may prefix them).
        (la, sa, ia, ea), (lb, sb, ib, eb) = principals
        disc = MCPClient(HTTPTransport(AGW_URL, headers=headers_for(sa, ia, ea), modern=True))
        try:
            init = disc.initialize()
            jlog("initialize (synthesized locally by the modern transport)", init)
            tools = disc.list_tools()
            print(f"tools via gateway: {[t.get('name') for t in tools]}")
            try:
                resources = disc.list_resources()
            except Exception as e:  # noqa: BLE001
                resources = []
                print(f"resources/list failed: {redact(str(e))}")
            print(f"resources via gateway: {[r.get('uri') for r in resources]}")
        except Exception as e:  # noqa: BLE001
            print(f"gateway refused discovery: {redact(str(e))}  (no run saved)")
            print(f"upstream methods seen: {up.methods_seen}")
            print("--- agentgateway log tail (redacted) ---\n" + gw.tail(10))
            raise
        finally:
            try:
                disc.close()
            except Exception:
                pass
        if not tools:
            print("stopping: no tools discovered"); return
        tool_name = tools[0]["name"]
        res_uri = resources[0]["uri"] if resources else None

        def ident(label, sub, iss, email):
            # agentgateway 1.7.0 requires MCP-Protocol-Version on every request
            # and, at 2026-07-28, has no initialize: use the modern transport.
            return Identity(label=label, connect=lambda: MCPClient(HTTPTransport(
                AGW_URL, headers=headers_for(sub, iss, email), modern=True)))

        if trigger_kind == "resource":
            if not res_uri:
                print("stopping: resource trigger requested but no resource discovered"); return
            trigger = lambda c: c.read_resource(res_uri)
            print(f"trigger: resources/read {res_uri}")
        else:
            trigger = lambda c: c.call_tool(tool_name, {})
            print(f"trigger: tools/call {tool_name}")

        print("=== running delegation probe through agentgateway ===")
        n_before = len(up.actor_header_seen)
        try:
            report = run_delegation_probe(
                AGW_URL, ident(la, sa, ia, ea), ident(lb, sb, ib, eb),
                upstream=up, trigger=trigger,
                expected_subject_a=sa, expected_subject_b=sb,
                expected_issuer_a=(ia or AS_ISSUER), expected_issuer_b=(ib or AS_ISSUER))
        except ProbeError as e:
            print(f"INCONCLUSIVE: {e}")
            print("--- agentgateway log tail (redacted) ---\n" + gw.tail())
            raise
        except Exception as e:  # noqa: BLE001
            print(f"ERROR during probe: {redact(str(e))}")
            print("--- agentgateway log tail (redacted) ---\n" + gw.tail())
            raise
        print("CHECKS:", json.dumps(report.checks))
        print("VULNERABLE:", report.vulnerable, "FAILURES:", report.failures)
        print(report.summary())
        actor_leaked = any(up.actor_header_seen[n_before:])
        print(f"x-actor-token header reached upstream: {actor_leaked}")
        print(f"upstream initialize protocolVersion(s) from gateway: {sorted(set(map(str, up.init_versions)))}")
        print(f"upstream MCP-Protocol-Version header(s): {sorted(map(str, up.upstream_proto_headers))}")

        # Save the run: mode, checks, the three recorded upstream calls, version, config.
        runs_dir = os.path.join(_HERE, "runs")
        os.makedirs(runs_dir, exist_ok=True)
        suffix = f"-{trigger_kind}" if trigger_kind != "tool" else ""
        out = os.path.join(runs_dir, f"agentgateway-{mode}{suffix}-{int(time.time())}.json")
        # Redact bearer tokens to a short fingerprint — never persist full JWTs.
        redacted_calls = [{**c, "token": _fp(c.get("token"))} for c in report.calls]
        with open(out, "w") as f:
            json.dump({
                "probe": "xid10-delegation", "mode": mode, "trigger": trigger_kind,
                "gateway": "agentgateway", "gateway_version": version.get("version"),
                "gateway_version_full": version,
                "gateway_config_path": os.path.relpath(config_path, _REPO),
                "gateway_config_sha256": hashlib.sha256(config_text.encode()).hexdigest(),
                "gateway_config": config_text,
                "authorization_note": "inbound users validated by jwtAuth against the "
                                      "local AS JWKS; no gateway-side RBAC configured",
                "actor_source": ("caller-supplied x-actor-token (client_credentials "
                                 f"token for {ACTOR_CLIENT_ID!r}), forwarded as actor_token"
                                 if send_actor else "none (no actor token sent or configured)"),
                "checks": report.checks, "vulnerable": report.vulnerable,
                "failures": report.failures, "summary": report.summary(),
                # Whether A's first and third (A-B-A) calls carried the same
                # exchanged token — i.e. agentgateway caches the exchange per user.
                "a_first_eq_a_third_token": (
                    len(report.calls) >= 3
                    and report.calls[0].get("token") == report.calls[2].get("token")),
                "actor_header_reached_upstream": actor_leaked,
                "upstream_init_protocol_versions": sorted(set(map(str, up.init_versions))),
                "upstream_protocol_version_headers": sorted(map(str, up.upstream_proto_headers)),
                "client_transport": "HTTPTransport(modern=True), MCP 2026-07-28",
                "upstream_methods_seen": up.methods_seen,
                "recorded_calls": redacted_calls,
                "endpoints": endpoints,
                "gateway_run_config_sha256": hashlib.sha256(
                    gw.run_config_text.encode()).hexdigest(),
            }, f, indent=2)
        print(f"saved run -> {out}")
    finally:
        gw.stop()
        up.stop()


# =========================================================================
# New checks: scope narrowing (CoSAI 3.3.2) and issuer binding (3.2.2/3.3.2)
# =========================================================================
UNREGISTERED = "https://unregistered.test"
PROVX, PROVY = "https://provx.test", "https://provy.test"


def as_issue_k(sub, *, iss=None, email=None, scope="read:notes", key=None):
    from urllib.parse import urlencode
    q = {"sub": sub, "aud": API_AUD, "scope": scope}
    for k, v in (("iss", iss), ("email", email), ("key", key)):
        if v:
            q[k] = v
    with urllib.request.urlopen(f"{AS_BASE}/issue?{urlencode(q)}", timeout=10) as r:
        return json.loads(r.read())["access_token"]


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def ident_tok(label, token_fn):
    """token_fn() -> user token; every connect also sends a fresh actor token."""
    return Identity(label=label, connect=lambda: MCPClient(HTTPTransport(
        AGW_URL, headers={"Authorization": f"Bearer {token_fn()}",
                          "x-actor-token": as_actor_token()}, modern=True)))


def discover_tool(token):
    c = MCPClient(HTTPTransport(AGW_URL, headers={"Authorization": f"Bearer {token}",
                                                  "x-actor-token": as_actor_token()},
                                modern=True))
    try:
        c.initialize()
        tools = c.list_tools()
    finally:
        try:
            c.close()
        except Exception:
            pass
    if not tools:
        raise SystemExit("no tools discovered through agentgateway")
    return tools[0]["name"]


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
    out = os.path.join(runs_dir, f"agentgateway-{name}-{int(time.time())}.json")
    text = json.dumps(payload, indent=2, default=str)
    if _JWT_RE.search(text):
        raise SystemExit("refusing to save: a JWT-shaped string is in the run")
    with open(out, "w") as f:
        f.write(text)
    print(f"saved run -> {out}")


def main_new(mode, endpoints):
    import xid10_thin_deputy_gate as thin
    scopes_none = os.environ.get("XID10_GW_SCOPES", "").strip().upper() == "NONE"
    cfg_key = "scope_narrowing-noscopes" if (mode == "scope_narrowing" and scopes_none) else mode
    config_path = os.environ.get("AGW_CONFIG") or os.path.join(_HERE, "agentgateway", CONFIGS[cfg_key])
    with open(config_path) as f:
        config_text = f.read()
    version = agw_version()
    oc = _get(f"{AS_BASE}/.well-known/openid-configuration")
    facts = {"lax_subject_issuer": oc.get("x_lax_subject_issuer"),
             "providers": oc.get("x_providers"), "scope_cap": oc.get("x_scope_cap")}
    print(f"=== MODE: {cfg_key} === agentgateway {version.get('version')}  AS {AS_BASE} {facts}")
    if mode == "issuer_unregistered" and not facts["lax_subject_issuer"]:
        raise SystemExit("issuer_unregistered needs the AS started with --lax-subject-issuer")
    fx = dict(upstream_port=FIXTURE_PORT, deputy_port=FIXTURE_PORT + 1 if FIXTURE_PORT else 0)
    broken = None
    if mode == "scope_narrowing":
        broken = thin.run_scope_fixture(AS_BASE, "scope_escalation", controls={}, **fx)
    elif mode == "issuer_unregistered":
        broken = thin.run_issuer_fixture(AS_BASE, "issuer_any", controls={}, **fx)
    if broken is not None:
        print(f"broken fixture: {broken.summary()}")
    up = Upstream(UPSTREAM_AUD, _get(f"{AS_BASE}/jwks"), AS_ISSUER, UPSTREAM_PORT).start()
    gw = Gateway(config_path)
    base = {"gateway": "agentgateway", "gateway_version": version.get("version"),
            "gateway_version_full": version, "mode": cfg_key,
            "gateway_config_path": os.path.relpath(config_path, _REPO),
            "gateway_config_sha256": hashlib.sha256(config_text.encode()).hexdigest(),
            "endpoints": dict(endpoints, fixture_ports=[fx["upstream_port"], fx["deputy_port"]]),
            "as_facts": facts,
            "actor_source": f"caller-supplied x-actor-token ({ACTOR_CLIENT_ID!r})"}
    try:
        gw.start()
        base["gateway_run_config_sha256"] = hashlib.sha256(gw.run_config_text.encode()).hexdigest()
        base["gateway_run_config"] = gw.run_config_text
        print(f"agentgateway up @ {AGW_URL}")
        if mode == "scope_narrowing":
            subj = thin.SUBJECT_SCOPE_BROAD
            configured = "" if scopes_none else "read:notes"
            tool = discover_tool(as_issue_k("alice", scope=subj))
            res = run_scope_narrowing_probe(
                AGW_URL, ident_tok("A", lambda: as_issue_k("alice", scope=subj)),
                ident_tok("B", lambda: as_issue_k("bob", scope=subj)), upstream=up,
                trigger=lambda c: c.call_tool(tool, {}), subject_scope=subj,
                configured_scope=configured, exchange_lookup=thin.exchange_lookup_http(AS_BASE),
                controls={"broken_fixture_failed": broken.grade == "FAIL"})
            print(res.summary())
            for c in res.per_call:
                print(f"  {c['principal']}: {c['grade']} who={c['who_narrowed']}")
            save_new_run(cfg_key, {**res.to_dict(), **base,
                                   "gateway_scopes_config": None if scopes_none else ["read:notes"],
                                   "broken_fixture": {"name": "thin_deputy scope_escalation",
                                                      "grade": broken.grade,
                                                      "reason": broken.reason}})
        elif mode == "issuer_unregistered":
            control_tok = as_issue_k("mallory", iss=PROVX, email="mallory@provx.test", key="provx")
            probe_tok = as_issue_k("mallory", iss=UNREGISTERED, email="mallory@provx.test",
                                   key="provx")
            tool = discover_tool(control_tok)
            res = run_issuer_unregistered_probe(
                AGW_URL, control_identity=ident_tok("control", lambda: control_tok),
                probe_identity=ident_tok("probe", lambda: probe_tok), upstream=up,
                trigger=lambda c, n: c.call_tool(tool, {"nonce": n}),
                probe_token_fp=_fp(probe_tok),
                probe_issuer=UNREGISTERED, exchange_records=lambda: _get(f"{AS_BASE}/exchanges"),
                controls={"broken_fixture_failed": broken.grade == "FAIL"}, quiet_seconds=3,
                settle_seconds=2)
            print(res.summary())
            ev = res.evidence
            print(f"  probe error: {ev['probe_error']}  exchange attempted: "
                  f"{ev['exchange_attempted_with_probe_token']}")
            save_new_run("issuer_unregistered", {**res.to_dict(), **base,
                         "signing_key_of_probe": "provx (trusted by jwtAuth for provx)",
                         "broken_fixture": {"name": "thin_deputy issuer_any",
                                            "grade": broken.grade, "reason": broken.reason}})
        elif mode == "issuer_email_crossprovider":
            y_email = "carol@provy.test"
            y_tok = as_issue_k("carol-y", iss=PROVY, email=y_email)
            dave_tok = as_issue_k("dave-x", iss=PROVX, email="dave@provx.test")
            probe_tok = as_issue_k("carol-x", iss=PROVX, email=y_email)
            tool = discover_tool(y_tok)
            trig = lambda c: c.call_tool(tool, {})
            y_calls, y_err = observe_one_call(ident_tok("Y", lambda: y_tok), up, trig)
            x_calls, x_err = observe_one_call(ident_tok("Xctl", lambda: dave_tok), up, trig)
            p_calls, p_err = observe_one_call(ident_tok("probe", lambda: probe_tok), up, trig)
            pc = [{"subject": c.subject, "issuer": c.issuer, "token": _fp(c.token),
                   "email": up.emails.get(_fp(c.token)), "scope": c.scope} for c in p_calls]
            grade, label, reason = grade_issuer_email_crossprovider(
                probe_calls=pc, control_reached=bool(x_calls), x_issuer=PROVX, y_issuer=PROVY,
                y_subject="carol-y", claimed_email=y_email)
            print(f"[{grade}] {label}: {reason}")
            save_new_run("issuer_email_crossprovider", {
                "probe": "issuer_email_crossprovider",
                "cosai": "CoSAI MCP Security v2.0, 3.2.2 / 3.3.2",
                "grade": grade, "label": label, "reason": reason, **base,
                "controls": {"y_reached_upstream": bool(y_calls),
                             "x_control_reached_upstream": bool(x_calls)},
                "observations": {
                    "gateway_has_user_store": False,
                    "probe_accepted": bool(p_calls), "probe_error": p_err,
                    "probe_upstream_calls": pc,
                    "y_upstream_identity": [(c.issuer, c.subject) for c in y_calls],
                    "y_error": y_err, "x_control_error": x_err}})
    finally:
        gw.stop()
        up.stop()


if __name__ == "__main__":
    main()
