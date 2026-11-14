"""Private-cache gate (CoSAI 3.2.7) against REAL gateways: ContextForge and agentgateway.

Drives ``strangertest.cachescope`` (the private-cached-results probe) through a
real MCP gateway in front of the practice per-user upstream, and, in the SAME
run set, through the practice caching proxy (the broken / safe fixtures), so a
gateway result is only ever graded OK next to a fixture that was shown to fail.

What one run does (all loopback, all on ports from the caller's port block):

1. Port policy: every port comes from an env var and must be in 4300-4399 and
   never 4444 / 8790 (other people's long-running services). The gate refuses
   to start otherwise. The ports and URLs used are written into the run.
2. Starts its own local AS (``local_as.LocalAS``) and a 2026-07-28 MCP upstream
   whose ``resources/read`` is ``practice_cache_http.UpstreamState``: per-user
   content (keyed on the verified JWT ``(orig_iss|iss, sub)``, so a direct read
   with the user's token and a gateway read with an exchanged token for the
   same user give the same content), ``cacheScope``/``ttlMs`` as configured,
   and a served-read counter (the caching control).
3. Puts the gateway in front of it:
   * ``agentgateway``: starts the binary on a port-substituted copy of
     ``integration/agentgateway/cachescope-tokenexchange.yaml`` (scratch dir).
   * ``contextforge``: an already running ContextForge (started by the
     operator on CS_GW_PORT); registers an RFC 8693 token-exchange gateway,
     a virtual server, and two ordinary (developer-role) users.
4. Records the MCP protocol version on both sides (client->gateway, and what
   the gateway sends upstream: discover/initialize params + the
   MCP-Protocol-Version header on each upstream request).
5. Trial: A reads the resource twice through the gateway; the origin read
   count per gateway read is recorded (no caching -> 1 each time).
6. Runs the probe through the gateway (A and B, distinct users validated by
   the gateway's inbound JWT auth), then a pass-through read recording
   ``cacheScope``/``ttlMs`` at the origin vs at the client.
7. Fixtures (same run set, same upstream, same users): practice proxy
   ``leaky`` (must give honouring LEAK) and ``safe`` (must give honouring OK);
   labelling controls: upstream ``public`` on per-user content (must give
   labelling LEAK) and ``private`` (must give labelling OK).
8. Grades. An observed leak is LEAK whatever the controls say. An OK on the
   gateway is kept only if the matching broken control failed in this run
   set; otherwise it is downgraded to INCONCLUSIVE.

Env:
  CS_GATEWAY         agentgateway | contextforge
  CS_UPSTREAM_SCOPE  private | public | none     (upstream label for the gateway run)
  CS_AS_PORT, CS_UPSTREAM_PORT, CS_GW_PORT, CS_FIXTURE_PORT   (required, 4300-4399)
  CS_AGW_ADMIN_PORT  (agentgateway only, required)
  CS_SCRATCH         dir for the AS key and the agentgateway config copy (required)
  AGW_BIN            agentgateway binary (agentgateway only)
  CS_OUT             output JSON path (default integration/runs/<gw>-cachescope-<scope>-<ts>.json)

ContextForge: run from the CF home with its .env sourced (CF_URL is derived
from CS_GW_PORT), in a venv that has mcpgateway + pyjwt.

NOT a unittest; an operator-driven gate. Bearer tokens are never printed or
saved; only ``sha256:`` fingerprints.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

# ------------------------------------------------------------ port policy
PORT_BLOCK = range(4300, 4400)
FORBIDDEN_PORTS = {4444, 8790}


class PortPolicyError(SystemExit):
    pass


def require_port(name: str) -> int:
    raw = os.environ.get(name)
    if not raw:
        raise PortPolicyError(f"REFUSE: {name} is not set (no default: set it from your port block 4300-4399)")
    try:
        port = int(raw)
    except ValueError:
        raise PortPolicyError(f"REFUSE: {name}={raw!r} is not a port")
    if port in FORBIDDEN_PORTS:
        raise PortPolicyError(f"REFUSE: {name}={port} is a forbidden port ({sorted(FORBIDDEN_PORTS)})")
    if port not in PORT_BLOCK:
        raise PortPolicyError(f"REFUSE: {name}={port} is outside the port block 4300-4399")
    return port


def check_url_port(url: str) -> None:
    m = re.match(r"^https?://(\[[^\]]+\]|[^/:]+)(?::(\d+))?", url)
    if not m:
        raise PortPolicyError(f"REFUSE: cannot parse URL {url!r}")
    host, port = m.group(1), m.group(2)
    if host not in ("127.0.0.1", "[::1]", "localhost"):
        raise PortPolicyError(f"REFUSE: {url!r} is not loopback")
    if port is None or int(port) in FORBIDDEN_PORTS or int(port) not in PORT_BLOCK:
        raise PortPolicyError(f"REFUSE: {url!r} uses a port outside 4300-4399 or a forbidden port")


try:
    import jwt  # noqa: F401
    from local_as import LocalAS
except Exception as exc:  # pragma: no cover
    # Cannot run is not a pass: exit non-zero so nothing reads this as clean.
    print(f"ERROR: cannot run, needs pyjwt[crypto] + local_as ({exc})", file=sys.stderr)
    sys.exit(2)

from strangertest.cachescope import INCONCLUSIVE, LEAK, OK, run_cachescope_probe
from strangertest.mcp_client import MCPClient, MCP_PROTOCOL_VERSION
from strangertest.practice_cache_http import (
    PROTOCOL_VERSION as PRACTICE_PROTOCOL_VERSION,
    ProxyState, UpstreamConfig, UpstreamState, _make_handler,
)
from strangertest.probe import Identity, ProbeError
from strangertest.transports import HTTPTransport

AS_ISSUER = "https://local-as.test"
UPSTREAM_AUD = "https://upstream.test/mcp"
URI = "note://cachescope/inbox"
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _fp(t):
    return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else t


def redact(text: str) -> str:
    return _JWT_RE.sub(lambda m: _fp(m.group(0)), str(text))


class _HTTP4(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class _HTTP6(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True


_RESULT = {"resultType": "complete"}
_LIST_RESULT = {"resultType": "complete", "cacheScope": "private", "ttlMs": 0}


# ---------------------------------------------------------------- upstream
class GateUpstream:
    """2026-07-28 MCP upstream on both loopback families at one port.

    Lists one resource (URI) and answers ``resources/read`` with
    ``UpstreamState`` (per-user content, configurable cacheScope/ttlMs, a read
    counter). The per-user key is the VERIFIED token identity, never the raw
    token, so content never embeds a bearer.
    """

    def __init__(self, port: int, as_: LocalAS, config: UpstreamConfig):
        self.state = UpstreamState(config)
        self.as_ = as_
        self.port = port
        self.log = []  # (method, MCP-Protocol-Version header, auth?, identity, source)
        self.discover_versions = []  # protocolVersion params on discover/initialize
        self.unverified_reads = 0
        self.raw_results = []  # (identity, cacheScope present, value, ttlMs) per read
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, obj, code=200):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _accepted(self):
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                self._send({"error": "use POST"}, 405)

            def do_DELETE(self):
                self._accepted()

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(n)
                auth = self.headers.get("Authorization", "")
                bearer = auth[7:] if auth.startswith("Bearer ") else auth
                try:
                    msg = json.loads(raw)
                except ValueError:
                    self._send({"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32700, "message": "parse"}})
                    return
                m, mid = msg.get("method"), msg.get("id")
                ident = outer.identity(bearer)
                # Direct probe clients tag themselves; everything else reached
                # us through the gateway (or, later, the fixture proxy).
                source = self.headers.get("X-Cachescope-Source") or "via-gateway-or-fixture"
                outer.log.append((m, self.headers.get("MCP-Protocol-Version"),
                                  bool(bearer), ident, source))
                if m in ("initialize", "server/discover"):
                    params = msg.get("params") or {}
                    outer.discover_versions.append(
                        (m, params.get("protocolVersion")
                         or (params.get("_meta") or {}).get("io.modelcontextprotocol/protocolVersion")
                         or self.headers.get("MCP-Protocol-Version")))
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": "2026-07-28",
                        "capabilities": {"resources": {}, "tools": {"listChanged": False}},
                        "serverInfo": {"name": "cachescope-upstream", "version": "1.0"},
                        "supportedVersions": ["2026-07-28"],
                        "ttlMs": 0, "cacheScope": "private",
                        "_meta": {"io.modelcontextprotocol/serverInfo":
                                  {"name": "cachescope-upstream", "version": "1.0"}},
                        **_RESULT}})
                    return
                if m and m.startswith("notifications/"):
                    self._accepted()
                    return
                if m == "tools/list":
                    self._send({"jsonrpc": "2.0", "id": mid,
                                "result": {"tools": [], **_LIST_RESULT}})
                    return
                if m == "prompts/list":
                    self._send({"jsonrpc": "2.0", "id": mid,
                                "result": {"prompts": [], **_LIST_RESULT}})
                    return
                if m == "resources/templates/list":
                    self._send({"jsonrpc": "2.0", "id": mid,
                                "result": {"resourceTemplates": [], **_LIST_RESULT}})
                    return
                if m == "resources/list":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "resources": [{"uri": URI, "name": "inbox",
                                       "mimeType": "text/plain"}], **_LIST_RESULT}})
                    return
                if m == "resources/read":
                    if ident.startswith("unverified"):
                        outer.unverified_reads += 1
                    resp = outer.state.handle(ident, msg)
                    r = resp.get("result") or {}
                    outer.raw_results.append(
                        (ident, "cacheScope" in r, r.get("cacheScope"), r.get("ttlMs")))
                    self._send(resp)
                    return
                self._send({"jsonrpc": "2.0", "id": mid,
                            "error": {"code": -32601, "message": f"no {m}"}})

        self._srv4 = _HTTP4(("127.0.0.1", port), H)
        try:
            self._srv6 = _HTTP6(("::1", port), H)
        except OSError:
            self._srv6 = None

    def identity(self, bearer: str) -> str:
        if not bearer:
            return "anonymous"
        try:
            c = self.as_.validate(bearer, verify_issuer=False)
        except Exception:
            return "unverified"
        return f"{c.get('orig_iss') or c.get('iss')}|{c.get('sub')}"

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def calls(self) -> int:
        return self.state.read_calls

    def start(self):
        for s in (self._srv4, self._srv6):
            if s is not None:
                threading.Thread(target=s.serve_forever, daemon=True).start()
        return self

    def stop(self):
        for s in (self._srv4, self._srv6):
            if s is not None:
                s.shutdown()
                s.server_close()


class FixtureProxy:
    """The practice caching proxy (``ProxyState``) on a fixed loopback port."""

    def __init__(self, port: int, upstream_url: str, mode: str):
        self.state = ProxyState(upstream_url, mode)
        self.srv = _HTTP4(("127.0.0.1", port), _make_handler(self.state.handle))
        self.url = f"http://127.0.0.1:{port}/mcp"

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever,
                         kwargs={"poll_interval": 0.01}, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


# ------------------------------------------------------------- utilities
def wait_port(port, timeout=30, proc=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


def read_raw(client, uri):
    r = client.read_resource(uri)
    return {"cacheScope_present": "cacheScope" in r, "cacheScope": r.get("cacheScope"),
            "ttlMs_present": "ttlMs" in r, "ttlMs": r.get("ttlMs"),
            "resultType": r.get("resultType"),
            "content_uris": [c.get("uri") for c in r.get("contents") or []]}


def run_probe(target, a, b, direct_a, direct_b, up, uri):
    try:
        rep = run_cachescope_probe(
            target, up.url, a, b, direct_a=direct_a, direct_b=direct_b,
            uri=uri, upstream_calls=up.calls)
    except ProbeError as e:
        return None, redact(e)
    return rep, None


def grades(rep):
    if rep is None:
        return {"labelling": INCONCLUSIVE, "honouring": INCONCLUSIVE}
    return {"labelling": rep.labelling.grade, "honouring": rep.honouring.grade}


# ------------------------------------------------------------- agentgateway
AGW_TEMPLATE = os.path.join(_HERE, "agentgateway", "cachescope-tokenexchange.yaml")
# Literal ports in the committed template; each is replaced from the env.
AGW_TEMPLATE_PORTS = {"gw": 4330, "admin": 4331, "as": 4390, "upstream": 4380}


def agw_setup(ports, scratch, as_):
    agw_bin = os.environ.get("AGW_BIN")
    if not agw_bin:
        raise SystemExit("REFUSE: AGW_BIN not set")
    with open(AGW_TEMPLATE) as f:
        template = f.read()
    text = template
    # Substitute ports; refuse if the template carries any port we do not map.
    found = set(int(p) for p in re.findall(r"127\.0\.0\.1:(\d+)", template)) | set(
        int(p) for p in re.findall(r"port:\s*(\d+)", template))
    unknown = found - set(AGW_TEMPLATE_PORTS.values())
    if unknown:
        raise SystemExit(f"REFUSE: config template carries unmapped ports {sorted(unknown)}")
    mapping = {AGW_TEMPLATE_PORTS[k]: ports[k] for k in AGW_TEMPLATE_PORTS}
    text = re.sub(r"(127\.0\.0\.1:)(\d+)", lambda m: m.group(1) + str(mapping[int(m.group(2))]), text)
    text = re.sub(r"(port:\s*)(\d+)", lambda m: m.group(1) + str(mapping[int(m.group(2))]), text)
    for p in set(int(x) for x in re.findall(r":(\d{2,5})\b", text)):
        if p in FORBIDDEN_PORTS:
            raise SystemExit(f"REFUSE: substituted config still names port {p}")
    run_dir = os.path.join(scratch, f"agw-run-{int(time.time())}")
    os.makedirs(run_dir)
    run_cfg = os.path.join(run_dir, "config.yaml")
    with open(run_cfg, "w") as f:
        f.write(text)
    version = json.loads(subprocess.check_output([agw_bin, "--version"]).decode())
    lines = []
    proc = subprocess.Popen([agw_bin, "-f", run_cfg], cwd=run_dir, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    threading.Thread(target=lambda: [lines.append(l.rstrip("\n")) for l in proc.stdout],
                     daemon=True).start()
    if not wait_port(ports["gw"], proc=proc):
        tail = "\n".join(redact(l) for l in lines[-30:])
        proc.terminate()
        raise SystemExit("agentgateway did not start:\n" + tail)
    url = f"http://127.0.0.1:{ports['gw']}/mcp"

    def ident(label, sub):
        return Identity(label=label, connect=lambda: MCPClient(HTTPTransport(
            url, headers={"Authorization": "Bearer " + as_.issue_user_token(
                sub, audience="agentgateway-api")}, modern=True)))

    def stop():
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(run_dir, ignore_errors=True)

    info = {
        "gateway": "agentgateway", "gateway_version": version.get("version"),
        "gateway_version_full": version, "gateway_pid": proc.pid,
        "gateway_config_template": os.path.relpath(AGW_TEMPLATE, _REPO),
        "gateway_config_template_sha256": hashlib.sha256(template.encode()).hexdigest(),
        "gateway_config_run": text,
        "client_transport": "HTTPTransport(modern=True): MCP-Protocol-Version 2026-07-28 "
                            "header + _meta envelope, no initialize",
        "inbound_auth": "jwtAuth strict, issuer local-as.test, audience agentgateway-api",
        "upstream_auth": "backendAuth.oauthTokenExchange (RFC 8693, no actor) per user",
        "log_tail": lambda: "\n".join(redact(l) for l in lines[-30:]),
    }
    return url, ident, stop, info


# ------------------------------------------------------------- ContextForge
def cf_setup(ports, scratch, as_, up):
    from xid10_contextforge_gate import ensure_tool_access, upsert_provider  # noqa
    import xid10_contextforge_gate as xcf
    cf_url = f"http://127.0.0.1:{ports['gw']}"
    check_url_port(cf_url)
    as_base = f"http://127.0.0.1:{ports['as']}"
    # The imported helpers read only API_AUD from that module; assert the
    # module's URL defaults are not used anywhere by us.
    xcf.CF = cf_url
    xcf.AS_BASE = as_base

    def cf(method, path, tok, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(cf_url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            return e.code, {"_error": redact(e.read().decode("utf-8", "replace")[:500])}

    tok = subprocess.check_output(
        [sys.executable, "-m", "mcpgateway.utils.create_jwt_token",
         "-u", "admin@example.com", "--admin", "-e", "1800"],
        stderr=subprocess.DEVNULL).decode().strip().splitlines()[-1]
    upsert_provider("local-as", AS_ISSUER, as_base)
    oauth = {
        "grant_type": "token-exchange", "token_url": f"{as_base}/token",
        "target_audience": UPSTREAM_AUD, "subject_token_source": "inbound_user_jwt",
        "client_id": "forge", "client_secret": "unused",
        "token_endpoint_auth_method": "client_secret_post", "scopes": ["read:notes"],
        "discovery": {"grant_type": "client_credentials", "token_url": f"{as_base}/token",
                      "client_id": "forge", "client_secret": "unused",
                      "token_endpoint_auth_method": "client_secret_post",
                      "scopes": ["read:notes"]}}
    st, gw = cf("POST", "/v1/gateways", tok, {
        "name": f"cachescope-{int(time.time())}", "url": up.url,
        "transport": "STREAMABLEHTTP", "authType": "oauth", "visibility": "public",
        "oauthConfig": oauth})
    print(f"CF register gateway -> HTTP {st} {redact(json.dumps(gw))[:200]}")
    if st >= 300:
        raise SystemExit("CF gateway registration failed")
    gid = gw.get("id")
    st, _ = cf("POST", f"/v1/gateways/{gid}/tools/refresh?include_resources=true", tok, {})
    print(f"CF refresh -> HTTP {st}")
    mine = []
    for _ in range(10):
        st, res = cf("GET", "/v1/resources", tok)
        allr = res if isinstance(res, list) else (res.get("data", []) if isinstance(res, dict) else [])
        mine = [r for r in allr if (r.get("gatewayId") or r.get("gateway_id")) == gid]
        if mine:
            break
        time.sleep(2)
    print(f"CF discovered resources: {[r.get('uri') for r in mine]}")
    if not mine:
        raise SystemExit("CF discovered no resource")
    gw_mode = gw.get("gatewayMode") or gw.get("gateway_mode")
    # Read-only DB lookup: did CF store a local copy of the catalogued
    # resource's content (which it could serve without federating)?
    from mcpgateway.db import Resource as DbResource, SessionLocal
    with SessionLocal() as db:
        stored = [{"uri": r.uri, "text_content_stored": r.text_content is not None,
                   "binary_content_stored": r.binary_content is not None}
                  for r in db.query(DbResource).filter_by(gateway_id=gid).all()]
    print(f"CF catalogued content stored locally: {stored}")
    st, srv = cf("POST", "/v1/servers", tok, {"server": {
        "name": f"cs-vs-{int(time.time())}", "visibility": "public",
        "associated_resources": [r["id"] for r in mine]}})
    print(f"CF virtual server -> HTTP {st}")
    if st >= 300:
        raise SystemExit(f"CF server create failed: {srv}")
    url = f"{cf_url}/servers/{srv['id']}/mcp"
    users = [("alice", "alice@local-as.test"), ("bob", "bob@local-as.test")]
    for sub, email in users:
        t = as_.issue_user_token(sub, audience="mcpgateway-api", email=email)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            r = urllib.request.Request(url, data=json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "provision", "version": "0"}}}).encode(),
                method="POST", headers={"Authorization": f"Bearer {t}",
                                        "Content-Type": "application/json",
                                        "Accept": "application/json, text/event-stream"})
            try:
                urllib.request.urlopen(r, timeout=15).read()
                print(f"CF provisioned {email}")
                break
            except urllib.error.HTTPError as e:
                if e.code != 401:
                    print(f"CF provisioned {email} (HTTP {e.code})")
                    break
                time.sleep(5)
    ensure_tool_access([u[1] for u in users])
    _, ver = cf("GET", "/version", tok)
    cf_ver = (ver or {}).get("app", {}).get("version") if isinstance(ver, dict) else None
    modern = os.environ.get("CS_CF_CLIENT", "modern") == "modern"
    emails = dict(users)

    def ident(label, sub):
        return Identity(label=label, connect=lambda: MCPClient(HTTPTransport(
            url, headers={"Authorization": "Bearer " + as_.issue_user_token(
                sub, audience="mcpgateway-api", email=emails[sub])}, modern=modern)))

    info = {
        "gateway": "ContextForge", "gateway_version": cf_ver,
        "gateway_mode": gw_mode, "cf_catalogued_content": stored, "cf_url": cf_url, "cf_gateway_id": gid,
        "cf_server_id": srv.get("id"),
        "client_transport": ("HTTPTransport(modern=True): MCP-Protocol-Version 2026-07-28 "
                             "header + _meta envelope, no initialize") if modern else
                            "HTTPTransport(legacy): initialize with protocolVersion 2026-07-28",
        "inbound_auth": "SSO provider trusted_for_api_auth (local AS JWKS, aud mcpgateway-api); "
                        "users granted a team-scoped developer role (not admin)",
        "upstream_auth": "oauth token-exchange gateway (RFC 8693, no actor) per user",
        "log_tail": lambda: "",
    }
    def stop():
        # Remove what this run registered in our own ContextForge, so the next
        # run's identical URI does not collide.
        for path in (f"/v1/servers/{srv.get('id')}", f"/v1/gateways/{gid}"):
            st, _ = cf("DELETE", path, tok)
            print(f"CF cleanup DELETE {path} -> HTTP {st}")

    return url, ident, stop, info


# ------------------------------------------------------------- main
def main():
    gateway = os.environ.get("CS_GATEWAY")
    if gateway not in ("agentgateway", "contextforge"):
        raise SystemExit("REFUSE: CS_GATEWAY must be agentgateway or contextforge")
    scope_env = os.environ.get("CS_UPSTREAM_SCOPE", "private")
    scope = None if scope_env == "none" else scope_env
    ports = {"as": require_port("CS_AS_PORT"), "upstream": require_port("CS_UPSTREAM_PORT"),
             "gw": require_port("CS_GW_PORT"), "fixture": require_port("CS_FIXTURE_PORT")}
    if gateway == "agentgateway":
        ports["admin"] = require_port("CS_AGW_ADMIN_PORT")
    if len(set(ports.values())) != len(ports):
        raise SystemExit(f"REFUSE: ports must be distinct: {ports}")
    scratch = os.environ.get("CS_SCRATCH")
    if not scratch or not os.path.isdir(scratch):
        raise SystemExit("REFUSE: CS_SCRATCH must be an existing directory")
    as_base = f"http://127.0.0.1:{ports['as']}"
    check_url_port(as_base)
    print(f"=== cachescope gate: {gateway}  upstream cacheScope={scope_env}  ports={ports} ===")

    as_ = LocalAS(issuer=AS_ISSUER, key_path=os.path.join(scratch, "as_key.pem"))
    as_srv = as_.serve(host="127.0.0.1", port=ports["as"])
    threading.Thread(target=as_srv.serve_forever, daemon=True).start()
    gw_config = UpstreamConfig(cache_scope=scope, per_user=True, ttl_ms=60000)
    up = GateUpstream(ports["upstream"], as_, gw_config).start()
    check_url_port(up.url)
    print(f"AS @ {as_base}   upstream @ {up.url} (+ [::1]:{ports['upstream']})")

    def direct(label, sub):
        return Identity(label=label, connect=lambda: MCPClient(HTTPTransport(
            up.url, headers={"Authorization": "Bearer " + as_.issue_user_token(
                sub, audience="agentgateway-api" if gateway == "agentgateway" else "mcpgateway-api",
                email=f"{sub}@local-as.test"),
                "X-Cachescope-Source": "direct"}, modern=True)))

    stop_gw = lambda: None
    out = {}
    try:
        if gateway == "agentgateway":
            gw_url, ident, stop_gw, info = agw_setup(ports, scratch, as_)
        else:
            gw_url, ident, stop_gw, info = cf_setup(ports, scratch, as_, up)
        check_url_port(gw_url)
        log_tail = info.pop("log_tail")
        print(f"gateway {info['gateway']} {info['gateway_version']} @ {gw_url}")
        log_mark = len(up.log)

        # Discover the URI as A through the gateway.
        disc = ident("A", "alice").connect()
        try:
            disc.initialize()
            listed = [r.get("uri") for r in disc.list_resources()]
        finally:
            disc.close()
        print(f"resources via gateway: {listed}")
        if URI not in listed:
            raise SystemExit(f"STOP: {URI} not exposed unchanged by the gateway: {listed}")

        # Step 1c trial: A reads twice; count origin reads per gateway read.
        trial = []
        c = ident("A", "alice").connect()
        try:
            c.initialize()
            for _ in range(2):
                before = up.calls()
                c.read_resource(URI)
                trial.append(up.calls() - before)
        finally:
            c.close()
        print(f"trial: origin reads per gateway read (A, twice): {trial}")

        # Probe through the gateway.
        rep, err = run_probe(gw_url, ident("A", "alice"), ident("B", "bob"),
                             direct("A-direct", "alice"), direct("B-direct", "bob"), up, URI)
        if rep is None:
            print(f"probe through gateway INCONCLUSIVE: {err}\n{log_tail()}")
        else:
            print("gateway probe:\n" + rep.summary())

        # Pass-through: what the client sees vs what the origin sent. A failure
        # here is recorded (and fails the run) rather than losing the run file.
        passthrough_error = None
        try:
            c = ident("A", "alice").connect()
            d = direct("A-direct", "alice").connect()
            try:
                c.initialize(); d.initialize()
                at_client = read_raw(c, URI)
                at_origin = read_raw(d, URI)
            finally:
                c.close(); d.close()
        except Exception as e:  # noqa: BLE001
            passthrough_error = redact(e)
            blank = {"cacheScope_present": None, "cacheScope": None, "ttlMs_present": None,
                     "ttlMs": None, "resultType": None, "content_uris": None}
            at_client, at_origin = dict(blank), dict(blank)

        def _change(field):
            if passthrough_error:
                return "unobserved (error)"
            pres = field + "_present"
            if (at_client[pres], at_client[field]) == (at_origin[pres], at_origin[field]):
                return "unchanged"
            if not at_client[pres]:
                return "dropped"
            return f"rewritten {at_origin[field]!r}->{at_client[field]!r}"

        passthrough = {"at_origin": at_origin, "at_client": at_client,
                       "cacheScope": _change("cacheScope"), "ttlMs": _change("ttlMs"),
                       "error": passthrough_error}
        print(f"passthrough: {json.dumps(passthrough)}")
        gw_log = [e for e in up.log[log_mark:] if e[4] != "direct"]

        # Fixtures and controls, same run set, same upstream and users.
        def fixture(mode, cfg):
            saved = up.state.config
            up.state.config = cfg
            try:
                with FixtureProxy(ports["fixture"], up.url, mode) as fx:
                    def fid(label, sub):
                        return Identity(label=label, connect=lambda: MCPClient(HTTPTransport(
                            fx.url, headers={"Authorization": "Bearer " + as_.issue_user_token(
                                sub, audience="fixture", email=f"{sub}@local-as.test")},
                            modern=True)))
                    r, e = run_probe(fx.url, fid("A", "alice"), fid("B", "bob"),
                                     direct("A-direct", "alice"), direct("B-direct", "bob"), up, URI)
            finally:
                up.state.config = saved
            g = grades(r)
            return {"proxy_mode": mode, "upstream_cache_scope": cfg.cache_scope,
                    "grades": g, "error": e,
                    "honouring_detail": r.honouring.detail if r else None,
                    "labelling_detail": r.labelling.detail if r else None,
                    "observations": r.observations if r else None}

        controls = {
            "broken_leaky_proxy_private": fixture("leaky", UpstreamConfig("private")),
            "safe_proxy_private": fixture("safe", UpstreamConfig("private")),
            "label_public_mislabel": fixture("safe", UpstreamConfig("public")),
            "label_private": fixture("safe", UpstreamConfig("private")),
        }
        expect = {"broken_leaky_proxy_private": ("honouring", LEAK),
                  "safe_proxy_private": ("honouring", OK),
                  "label_public_mislabel": ("labelling", LEAK),
                  "label_private": ("labelling", OK)}
        for k, (axis, want) in expect.items():
            controls[k]["expected"] = {axis: want}
            controls[k]["as_expected"] = controls[k]["grades"][axis] == want
            print(f"control {k}: {controls[k]['grades']}  expected {axis}={want} "
                  f"-> {'as expected' if controls[k]['as_expected'] else 'NOT AS EXPECTED'}")

        g = grades(rep)
        grade_lab, grade_hon = g["labelling"], g["honouring"]
        notes = []
        if grade_hon == OK and not controls["broken_leaky_proxy_private"]["as_expected"]:
            grade_hon = INCONCLUSIVE
            notes.append("honouring OK downgraded: the broken fixture did not fail in this run set")
        if grade_lab == OK and not controls["label_public_mislabel"]["as_expected"]:
            grade_lab = INCONCLUSIVE
            notes.append("labelling OK downgraded: the public-mislabel control did not give LEAK")

        upstream_versions = sorted(set(str(v) for (_, v, _, _, _) in gw_log))
        # Observation only (not graded): the cache label the gateway presented
        # to the client for this user-specific resource, next to the origin's.
        gateway_label = {
            "cacheScope_present": at_client["cacheScope_present"],
            "cacheScope": at_client["cacheScope"],
            "ttlMs": at_client["ttlMs"],
            "origin_cacheScope": at_origin["cacheScope"],
            "origin_ttlMs": at_origin["ttlMs"],
            "content_user_specific": (rep.observations.get("content_differs_per_identity")
                                      if rep else None),
            "change": passthrough["cacheScope"],
            "graded": False,
        }
        exit_reasons = []
        for k, ctl in controls.items():
            if not ctl["as_expected"]:
                exit_reasons.append(f"control {k} NOT as expected: expected {ctl['expected']}, "
                                    f"got {ctl['grades']}")
        if rep is None:
            exit_reasons.append(f"gateway probe could not observe (ProbeError): {err}")
        if passthrough_error:
            exit_reasons.append(f"pass-through read failed: {passthrough_error}")
        if up.unverified_reads:
            exit_reasons.append(f"upstream saw {up.unverified_reads} read(s) with an "
                                f"unverifiable token")
        out = {
            "probe": "cachescope", **info,
            "protocol_versions": {
                "client_to_gateway": MCP_PROTOCOL_VERSION,
                "client_to_gateway_note": info["client_transport"],
                "gateway_to_upstream_discover": sorted(set(map(str, up.discover_versions))),
                "gateway_to_upstream_header": upstream_versions,
                "upstream_speaks": PRACTICE_PROTOCOL_VERSION,
                "direct_probe_to_upstream": MCP_PROTOCOL_VERSION,
            },
            # The labelling grade is the ORIGIN's (the practice upstream), not
            # the gateway's; the gateway is never graded on labelling. What the
            # gateway showed the client is the separate observation below.
            "grade_labelling_origin": grade_lab, "grade_honouring": grade_hon,
            "gateway_label_at_client": gateway_label,
            "grade_notes": notes, "cosai": "3.2.7",
            # Labelling grades the ORIGIN (the practice upstream, whose label is
            # set by CS_UPSTREAM_SCOPE), never the gateway. Honouring grades the
            # gateway as a cache.
            "grade_labelling_subject": "origin (practice upstream, cacheScope set by the operator)",
            "grade_honouring_subject": f"gateway ({info['gateway']}) as a cache",
            "uri": URI,
            "upstream_config": {"cache_scope": scope, "per_user": True, "ttl_ms": 60000,
                                "unstable": False,
                                "content_key": "verified JWT (orig_iss|iss, sub); never the raw token"},
            "caching_trial": {"origin_reads_per_gateway_read": trial,
                              "caches": all(t == 0 for t in trial[1:]) if trial else None},
            "passthrough": passthrough,
            "probe_result": rep.to_dict() if rep else {"error": err},
            "controls": controls,
            "upstream_methods_from_gateway": [
                {"method": m, "mcp_protocol_version": v, "auth": a,
                 "identity": i} for (m, v, a, i, _) in gw_log],
            "upstream_unverified_reads": up.unverified_reads,
            "run_valid": not exit_reasons, "run_problems": exit_reasons,
            "ports": ports,
            "urls": {"as": as_base, "upstream": up.url, "gateway": gw_url,
                     "fixture": f"http://127.0.0.1:{ports['fixture']}/mcp"},
            "tokens": "never stored; content keyed on verified identity, not the token",
            "ts": int(time.time()),
        }
    finally:
        stop_gw()
        up.stop()
        as_srv.shutdown(); as_srv.server_close()

    print(f"GRADE labelling(origin)={out.get('grade_labelling_origin')} "
          f"honouring(gateway)={out.get('grade_honouring')} "
          f"gateway label at client={out['gateway_label_at_client']['cacheScope']!r}")
    dest = os.environ.get("CS_OUT") or os.path.join(
        _HERE, "runs", f"{gateway}-cachescope-{scope_env}-{int(time.time())}.json")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    text = json.dumps(out, indent=2, default=str)
    if _JWT_RE.search(text):
        raise SystemExit("REFUSE: a JWT-shaped string would be saved; not writing the run")
    with open(dest, "w") as f:
        f.write(text + "\n")
    print(f"saved run -> {dest}")
    if out["run_problems"]:
        # The run is saved with its grades, but detection is unproven (or the
        # gateway could not be observed) for this run set: exit 1.
        for r in out["run_problems"]:
            print(f"ERROR: {r}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
