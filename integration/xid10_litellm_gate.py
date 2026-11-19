"""XID-10 gate against a REAL third-party gateway: LiteLLM (an LLM gateway with MCP features).

Drives the delegation probe (and the scope / issuer / exchange-failure / cache
checks) through a running LiteLLM proxy configured, by its config file only, for
RFC 8693 token exchange against the local AS. LiteLLM is the deputy under test;
local_as is the IdP; a recording MCP server (started here) is the upstream.

Prerequisites (integration/LITELLM_GATE.md has the recipe):
  * local_as serving on AS_BASE (started by the operator, so its mode -- default,
    act_from_client, lax -- is explicit and recorded in every run)
  * LiteLLM 1.109.1 (pinned) installed in its own venv; LL_BIN = its `litellm`
  * this driver run with a Python that has pyjwt[crypto]

The driver starts LiteLLM itself on a temp copy of integration/litellm/<config>
with the ports, the client secret and (shared-credential only) a static token
substituted, and a throwaway master key generated per run.

Modes (LL_MODE):
  delegation                A, B, A: the six checks (+ in-run thin-deputy fixtures)
  two_issuers               same, alice@provX vs alice@provY (+ conflated fixture)
  passthrough               side check: true_passthrough config (must be flagged)
  shared_credential         side check: static bearer for everyone (must be flagged)
  scope_narrowing           CoSAI 3.3.2 (LL_GW_SCOPES=NONE: config with no scopes)
  issuer_unregistered       needs the AS started --lax-subject-issuer
  issuer_unregistered_strict  the same probe against the default (strict) AS:
                            records where issuer validation happens
  issuer_email_crossprovider
  exchange_fail             control first, then the exchange fails (+ fall-through fixture)
  cache                     does LiteLLM cache resources/read? (two reads as A)

Ports: AS_BASE, LL_PORT, UPSTREAM_PORT and FIXTURE_BASE (fixture AS N, thin
upstream N+2, thin deputy N+3, switchable token endpoint N+4, fall-through
fixture N+5) are REQUIRED, must be 4500-4699, never 4000/4444/8790.

Not a unittest; an operator-driven gate. Tokens are stored as sha256
fingerprints only; secrets (master key, client secret, static token) never.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata  # noqa: F401  (used through subprocess for the LiteLLM venv)
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import jwt
    from local_as import LocalAS
except Exception as exc:  # pragma: no cover
    print(f"ERROR: cannot run the LiteLLM gate: needs pyjwt[crypto] ({exc})", file=sys.stderr)
    sys.exit(2)

from strangertest.delegate import (MockUpstream, gate_run_problems,  # noqa: E402
                                   grade_issuer_email_crossprovider, make_nonce,
                                   observe_one_call, request_nonce, run_delegation_probe,
                                   run_issuer_unregistered_probe, run_scope_narrowing_probe)
from strangertest.concurrency import InflightMixin  # noqa: E402
from strangertest.mcp_client import MCPClient  # noqa: E402
from strangertest.probe import Identity, ProbeError  # noqa: E402
from strangertest.transports import HTTPTransport  # noqa: E402

PINNED_VERSION = "1.109.1"
AS_ISSUER = "https://local-as.test"
UPSTREAM_AUD = "https://upstream.test/mcp"
USER_AUD = "litellm-api"   # LiteLLM does not check it; recorded for completeness
SERVER = "notes"
CLIENT_ID = "litellm-gw"
FORBIDDEN_PORTS = {4000, 4444, 8790}
PORT_RANGE = range(4500, 4700)   # 45xx (original gate runs) or 46xx (deeper scenarios)
UPSTREAM_VERSION = "2025-11-25"   # what the upstream answers; LiteLLM's default set
LEGACY = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
PROVX, PROVY, UNREGISTERED = "https://provx.test", "https://provy.test", "https://unregistered.test"
CONFIGS = {
    "delegation": "xid10-token-exchange.yaml",
    "two_issuers": "xid10-token-exchange.yaml",
    "passthrough": "xid10-passthrough.yaml",
    "shared_credential": "xid10-shared-credential.yaml",
    "scope_narrowing": "xid10-token-exchange.yaml",
    "scope_narrowing-noscopes": "xid10-scope-none.yaml",
    "issuer_unregistered": "xid10-token-exchange.yaml",
    "issuer_unregistered_strict": "xid10-token-exchange.yaml",
    "issuer_email_crossprovider": "xid10-token-exchange.yaml",
    "exchange_fail": "xid10-token-exchange.yaml",   # endpoint = the switchable proxy
    "cache": "xid10-token-exchange.yaml",
}
DOCS = {
    "mcp_overview": "https://docs.litellm.ai/docs/mcp",
    "token_exchange": "https://docs.litellm.ai/docs/mcp_obo_auth",
    "passthrough": "https://docs.litellm.ai/docs/mcp_oauth_passthrough",
}
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_SK_RE = re.compile(r"sk-[A-Za-z0-9_-]{8,}")


def fp(t):
    return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else None


def redact(text) -> str:
    return _SK_RE.sub("sk-<redacted>", _JWT_RE.sub(lambda m: fp(m.group(0)), str(text)))


# ------------------------------------------------------------------ ports
def _port(name):
    raw = os.environ.get(name)
    if not raw:
        raise SystemExit(f"ERROR: refusing to start: set {name} explicitly")
    port = int(raw)
    if port in FORBIDDEN_PORTS or port not in PORT_RANGE:
        raise SystemExit(f"ERROR: refusing port {port} for {name}: must be 4500-4699, "
                         f"never {sorted(FORBIDDEN_PORTS)}")
    return port


def require_endpoints():
    as_base = os.environ.get("AS_BASE") or ""
    u = urlparse(as_base)
    if u.hostname != "127.0.0.1" or not u.port:
        raise SystemExit("ERROR: refusing to start: AS_BASE must be http://127.0.0.1:<45xx>")
    os.environ["_AS_PORT"] = str(u.port)
    ports = {"as": _port("_AS_PORT"), "litellm": _port("LL_PORT"),
             "upstream": _port("UPSTREAM_PORT"), "fixture_base": _port("FIXTURE_BASE")}
    fx = ports["fixture_base"]
    for off in range(6):
        os.environ["_FX"] = str(fx + off)
        _port("_FX")
    used = [ports["as"], ports["litellm"], ports["upstream"]] + list(range(fx, fx + 6))
    if len(set(used)) != len(used):
        raise SystemExit(f"ERROR: refusing: ports overlap: {used}")
    return as_base.rstrip("/"), ports


# --------------------------------------------------------------- upstream
class _HTTP4(ThreadingHTTPServer):
    allow_reuse_address = True


class Recorder(InflightMixin, MockUpstream):
    """Legacy Streamable-HTTP MCP upstream (JSON responses), the protocol LiteLLM
    1.109.1 speaks by default. Answers ``initialize`` with the requested version
    if it is a legacy one, else 2025-11-25; ``server/discover`` is
    method-not-found. Records every request (method, MCP-Protocol-Version,
    header names, Authorization fingerprint, nonce) and grades tools/call and
    resources/read through :class:`MockUpstream`. Counts resources/read served
    (the cache trial)."""

    def __init__(self, port, jwks):
        MockUpstream.__init__(self, UPSTREAM_AUD)
        self._inflight_init()
        # Off by default (existing modes unchanged): {"iss|sub": text} appends the
        # note of the token's identity to a tools/call result (concurrent probe).
        self.notes = {}
        self._key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
        self.requests = []
        self.init_versions = []
        self.emails = {}
        self.reads_served = 0
        self.resource_meta = {}   # optional fields added to resources/read results
        outer = self
        tool = {"name": "read_note", "description": "Read the caller's note.",
                "inputSchema": {"type": "object", "properties": {"nonce": {"type": "string"}}}}

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

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

            def _empty(self, code):
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                outer.requests.append({"http": "GET"})
                self._send({"error": "no GET stream"}, 405)

            def do_DELETE(self):
                outer.requests.append({"http": "DELETE"})
                self._empty(200)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                auth = self.headers.get("Authorization", "")
                bearer = auth[7:] if auth.startswith("Bearer ") else auth
                try:
                    msg = json.loads(raw)
                except ValueError:
                    self._send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse"}})
                    return
                m, mid = msg.get("method"), msg.get("id")
                params = msg.get("params") or {}
                outer.requests.append({
                    "method": m, "nonce": request_nonce(params),
                    "mcp_protocol_version": self.headers.get("MCP-Protocol-Version"),
                    "header_names": sorted(k.lower() for k in self.headers.keys()),
                    "authorization": fp(bearer) if bearer else None,
                    "litellm_key_header": self.headers.get("x-litellm-api-key") is not None})
                if m == "initialize":
                    req = params.get("protocolVersion")
                    ver = req if req in LEGACY else UPSTREAM_VERSION
                    outer.init_versions.append({"requested": req, "answered": ver})
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": ver,
                        "capabilities": {"tools": {"listChanged": False}, "resources": {}},
                        "serverInfo": {"name": "upstream", "version": "1.0"}}},
                        extra={"Mcp-Session-Id": "up-" + secrets.token_hex(4)})
                    return
                if mid is None:
                    self._empty(202)
                    return
                if m == "ping":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {}})
                    return
                if m == "tools/list":
                    outer._rec("tools/list", bearer, params)
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [tool]}})
                    return
                if m == "resources/list":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "resources": [{"uri": "note://caller", "name": "note",
                                       "mimeType": "text/plain"}]}})
                    return
                if m in ("tools/call", "resources/read"):
                    outer.enter()
                    try:
                        who = outer._rec(m, bearer, params)
                    finally:
                        outer.leave()
                    if m == "tools/call":
                        text = f"ok for {who}"
                        if outer.notes:
                            text += f" note={outer.notes.get(who, 'no-note')}"
                        res = {"content": [{"type": "text", "text": text}],
                               "isError": False}
                    else:
                        outer.reads_served += 1
                        res = {"contents": [{"uri": params.get("uri"), "mimeType": "text/plain",
                                             "text": f"note of {who} #{outer.reads_served}"}],
                               **outer.resource_meta}
                    self._send({"jsonrpc": "2.0", "id": mid, "result": res})
                    return
                self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no"}})

        self._srv = _HTTP4(("127.0.0.1", port), H)

    def _rec(self, method, bearer, params):
        nonce = request_nonce(params)
        if not bearer:
            self.receive(token=None, parsed=False, parse_error="no Authorization header",
                         method=method, nonce=nonce)
            return "nobody"
        try:
            c = jwt.decode(bearer, self._key, algorithms=["RS256"], issuer=AS_ISSUER,
                           options={"verify_aud": False, "require": ["exp", "iss"]})
        except Exception as e:  # noqa: BLE001
            self.receive(token=bearer, parsed=False, parse_error=type(e).__name__,
                         method=method, nonce=nonce)
            return "unparsed"
        act = c.get("act")
        self.emails[fp(bearer)] = c.get("email")
        self.receive(subject=c.get("sub"), actor=act.get("sub") if isinstance(act, dict) else None,
                     audience=c.get("aud"), scope=c.get("scope"), token=bearer,
                     issuer=c.get("orig_iss") or c.get("iss"), method=method, nonce=nonce)
        return f"{c.get('orig_iss') or c.get('iss')}|{c.get('sub')}"

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()

    def by_nonce(self, nonce):
        return [r for r in self.requests if r.get("nonce") == nonce]


# ------------------------------------------------- switchable token endpoint
class SwitchableTokenEndpoint:
    """Forwards POST /token to the AS until switched to fail; then answers HTTP
    400 invalid_grant (the RFC 8693 refusal). Counts hits per state and keeps
    the request's form-parameter NAMES (never values) and auth method."""

    def __init__(self, port, as_base):
        self.fail = False
        self.hits = {"forwarded": 0, "failed": 0}
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                names = sorted(parse_qs(body.decode()).keys())
                auth = self.headers.get("Authorization", "")
                outer.requests.append({"state": "fail" if outer.fail else "forward",
                                       "param_names": names,
                                       "basic_auth": auth[:6].lower() == "basic "})
                if outer.fail:
                    outer.hits["failed"] += 1
                    self._json(400, {"error": "invalid_grant",
                                     "error_description": "exchange refused (test)"})
                    return
                outer.hits["forwarded"] += 1
                h = {"Content-Type": self.headers.get("Content-Type", "")}
                if auth:
                    h["Authorization"] = auth
                req = urllib.request.Request(f"{as_base}/token", data=body, method="POST", headers=h)
                try:
                    with urllib.request.urlopen(req, timeout=10) as r:
                        self._json(r.status, json.loads(r.read()))
                except urllib.error.HTTPError as e:
                    self._json(e.code, json.loads(e.read() or b"{}"))

        self._srv = _HTTP4(("127.0.0.1", port), H)
        self.url = f"http://127.0.0.1:{port}/token"

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


class FallThroughDeputy:
    """BROKEN fixture for the exchange-failure check: a minimal MCP deputy that
    exchanges the caller's token and, when the exchange FAILS, forwards the
    tools/call to the upstream with NO Authorization header (ContextForge
    1.0.6's resource-read behaviour). The exchange-failure check must FAIL it."""

    def __init__(self, port, token_url, upstream_url):
        outer = self
        self.url = f"http://127.0.0.1:{port}/mcp"

        def upstream_call(msg, token):
            h = {"Content-Type": "application/json", "Accept": "application/json"}
            if token:
                h["Authorization"] = f"Bearer {token}"
            sid = None
            init = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": UPSTREAM_VERSION, "capabilities": {},
                "clientInfo": {"name": "fallthrough", "version": "0"}}}
            req = urllib.request.Request(upstream_url, data=json.dumps(init).encode(), headers=h)
            with urllib.request.urlopen(req, timeout=10) as r:
                sid = r.headers.get("Mcp-Session-Id")
            h2 = dict(h, **({"Mcp-Session-Id": sid} if sid else {}),
                      **{"MCP-Protocol-Version": UPSTREAM_VERSION})
            req = urllib.request.Request(upstream_url, data=json.dumps(msg).encode(), headers=h2)
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, obj):
                b = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_POST(self):
                msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                m, mid = msg.get("method"), msg.get("id")
                if mid is None:
                    self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers()
                    return
                if m == "initialize":
                    self._json({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": UPSTREAM_VERSION, "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fallthrough", "version": "0"}}})
                    return
                if m == "tools/list":
                    self._json({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                        {"name": "read_note", "inputSchema": {"type": "object"}}]}})
                    return
                if m == "tools/call":
                    auth = self.headers.get("Authorization", "")
                    subject = auth[7:] if auth.startswith("Bearer ") else ""
                    token = None
                    body = urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                                      "subject_token": subject, "audience": UPSTREAM_AUD,
                                      "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"}).encode()
                    try:
                        with urllib.request.urlopen(urllib.request.Request(
                                token_url, data=body, method="POST"), timeout=10) as r:
                            token = json.loads(r.read()).get("access_token")
                    except Exception:  # noqa: BLE001  -- BROKEN: falls through
                        token = None
                    out = upstream_call(msg, token)
                    self._json({"jsonrpc": "2.0", "id": mid, "result": out.get("result")})
                    return
                self._json({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no"}})

        self._srv = _HTTP4(("127.0.0.1", port), H)

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


# ---------------------------------------------------------------- LiteLLM
def litellm_versions(ll_bin):
    py = os.path.join(os.path.dirname(ll_bin), "python")
    code = ("import importlib.metadata as m, hashlib, json, pathlib\n"
            "d = m.distribution('litellm')\n"
            "rec = pathlib.Path(d._path) / 'RECORD'\n"
            "print(json.dumps({'litellm': d.version, 'mcp': m.version('mcp'),"
            " 'litellm_dist_record_sha256': hashlib.sha256(rec.read_bytes()).hexdigest(),"
            " 'license': d.metadata.get('License-Expression')}))")
    return json.loads(subprocess.check_output([py, "-I", "-c", code]).decode())


class LiteLLM:
    """Run LiteLLM on a temp copy of one config; keep its log in memory and
    print it only redacted."""

    def __init__(self, ll_bin, config_name, port, subs):
        self.bin = ll_bin
        self.port = port
        self.config_path = os.path.join(_HERE, "litellm", config_name)
        with open(self.config_path) as f:
            self.config_text = f.read()
        text = self.config_text
        for k, v in subs.items():
            text = text.replace("{{" + k + "}}", v)
        if "{{" in text.split("\n# ", 1)[-1].split("mcp_servers:", 1)[-1]:
            raise SystemExit("ERROR: unsubstituted placeholder in the LiteLLM run config")
        for bad in FORBIDDEN_PORTS:
            if re.search(r"(?<![0-9])%d(?![0-9])" % bad, text):
                raise SystemExit(f"ERROR: run config names forbidden port {bad}")
        self.run_text = text
        # The recorded copy: secrets as fingerprints.
        rec = text
        for k in ("CLIENT_SECRET", "STATIC_TOKEN"):
            if subs.get(k):
                rec = rec.replace(subs[k], fp(subs[k]))
        self.recorded_text = rec
        self.master_key = "sk-st-" + secrets.token_hex(16)
        self.lines = []
        self.proc = None
        self.url = f"http://127.0.0.1:{port}/mcp"

    def start(self, timeout=90):
        self._tmp = tempfile.mkdtemp(prefix="xid10-litellm-")
        cfg = os.path.join(self._tmp, "config.yaml")
        with open(cfg, "w") as f:
            f.write(self.run_text)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self._tmp,
               "LITELLM_MASTER_KEY": self.master_key, "LITELLM_LOCAL_MODEL_COST_MAP": "True",
               "LITELLM_TELEMETRY": "False", "LITELLM_LOG": "ERROR"}
        self.proc = subprocess.Popen([self.bin, "--config", cfg, "--host", "127.0.0.1",
                                      "--port", str(self.port)], cwd=self._tmp, env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1)
        threading.Thread(target=self._pump, daemon=True).start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("LiteLLM exited early:\n" + self.tail())
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health/liveliness",
                                            timeout=2) as r:
                    if r.status == 200:
                        return self
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        raise RuntimeError("LiteLLM did not come up:\n" + self.tail())

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))

    def tail(self, n=40):
        return "\n".join(redact(l) for l in self.lines[-n:])

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        if getattr(self, "_tmp", None):
            shutil.rmtree(self._tmp, ignore_errors=True)

    def headers(self, user_token=None, *, key=True):
        h = {"x-litellm-api-key": self.master_key} if key else {}
        if user_token:
            h["Authorization"] = f"Bearer {user_token}"
        return h

    def client(self, user_token=None, *, key=True, url=None):
        return MCPClient(HTTPTransport(url or self.url, headers=self.headers(user_token, key=key)))

    def record(self):
        return {"gateway_config_path": os.path.relpath(self.config_path, _REPO),
                "gateway_config_sha256": hashlib.sha256(self.config_text.encode()).hexdigest(),
                "gateway_run_config": self.recorded_text,
                "gateway_run_config_sha256": hashlib.sha256(self.recorded_text.encode()).hexdigest(),
                "master_key": fp(self.master_key)}


# ------------------------------------------------------------- AS helpers
def _get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def as_issue(as_base, sub, *, iss=None, email=None, scope="read:notes", key=None, aud=USER_AUD):
    q = {"sub": sub, "aud": aud, "scope": scope}
    for k, v in (("iss", iss), ("email", email), ("key", key)):
        if v:
            q[k] = v
    return _get(f"{as_base}/issue?{urlencode(q)}")["access_token"]


_EX_KEYS = ("seq", "subject_sub", "subject_iss", "actor_present", "requested_scope",
            "requested_audience", "client_auth_method", "client_id", "client_valid",
            "act_source", "outcome")


def login_facts(as_base):
    oc = _get(f"{as_base}/.well-known/openid-configuration")
    return {"client_auth": oc.get("x_client_auth"), "act_from_client": oc.get("x_act_from_client"),
            "clients": oc.get("x_clients"), "lax_subject_issuer": oc.get("x_lax_subject_issuer"),
            "providers": oc.get("x_providers"), "scope_cap": oc.get("x_scope_cap")}


def exchanges_since(as_base, n):
    return [{k: r.get(k) for k in _EX_KEYS} for r in _get(f"{as_base}/exchanges")[n:]]


def _call(c):
    d = {k: v for k, v in (vars(c) if not isinstance(c, dict) else c).items()}
    d["token"] = fp(d.get("token")) if d.get("token") and not str(d["token"]).startswith("sha256:") else d.get("token")
    return d


# --------------------------------------------------------------- fixtures
def thin_fixtures(fixture_base, two_issuers=False):
    """The thin-deputy fixtures run IN THIS RUN against an in-process AS, so
    every check graded OK here is shown able to fail. Returns
    {fixture: failures}."""
    import xid10_thin_deputy_gate as thin
    os.environ["THIN_PORT_BASE"] = str(fixture_base)   # upstream N+2, deputy N+3
    as_ = LocalAS()
    srv = as_.serve(port=fixture_base)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{fixture_base}"
    out = {}
    try:
        for mode in ("safe", "static_credential", "token_passthrough",
                     "cached_token_reuse", "scope_escalation"):
            out[mode] = thin.run_mode(as_, url, mode).failures
        if two_issuers:
            out["two_issuers (safe)"] = thin.run_two_issuer(as_, url, False).failures
            out["conflated_issuer"] = thin.run_two_issuer(as_, url, True).failures
    finally:
        srv.shutdown()
        srv.server_close()
    return out


def check_grades(checks, fixtures, controls):
    """Per check: FAIL if it failed; OK only if it passed AND some broken
    fixture failed it in this run (and the safe control passed); else
    INCONCLUSIVE. Never OK for something not shown able to fail."""
    safe_ok = all(not fixtures.get(c) for c in controls if c in fixtures)
    grades = {}
    for name, ok in checks.items():
        if not ok:
            grades[name] = "FAIL"
            continue
        proven = [f for f, fails in fixtures.items() if f not in controls and name in fails]
        grades[name] = "OK" if (proven and safe_ok) else "INCONCLUSIVE"
    return grades


# ------------------------------------------------------------------ save
def save(name, payload, *, tag=""):
    runs_dir = os.path.join(_HERE, "runs")
    os.makedirs(runs_dir, exist_ok=True)
    out = os.path.join(runs_dir, f"litellm-{name}{tag}-{int(time.time())}.json")
    text = json.dumps(payload, indent=2, default=str)
    if _JWT_RE.search(text) or "sk-st-" in text:
        raise SystemExit("refusing to save: a token or key is in the run")
    for s in payload.pop("_secrets", []) if isinstance(payload, dict) else []:
        if s and s in text:
            raise SystemExit("refusing to save: a secret is in the run")
    with open(out, "w") as f:
        f.write(text)
    print(f"saved run -> {out}")
    return out


# ------------------------------------------------------------------ modes
def ident(gw, label, token_fn):
    return Identity(label=label, connect=lambda: gw.client(token_fn()))


def discover_tool(gw, token):
    c = gw.client(token)
    try:
        init = c.initialize()
        tools = c.list_tools()
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass
    if not tools:
        raise SystemExit("no tools discovered through LiteLLM")
    return tools[0]["name"], init.get("protocolVersion")


def http_status(url, headers, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": UPSTREAM_VERSION, **headers})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return {"status": r.status, "www_authenticate": r.headers.get("WWW-Authenticate"),
                    "body": redact(r.read().decode()[:400])}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "www_authenticate": e.headers.get("WWW-Authenticate"),
                "body": redact(e.read().decode()[:400])}


def mode_delegation(mode, gw, up, as_base, ports, base):
    two = mode == "two_issuers"
    if two:
        pa, pb = ("A", "alice", PROVX, "alice@provx.test"), ("B", "alice", PROVY, "alice@provy.test")
    else:
        pa, pb = ("A", "alice", None, None), ("B", "bob", None, None)
    tool, client_ver = discover_tool(gw, as_issue(as_base, pa[1], iss=pa[2], email=pa[3]))
    n_ex = len(_get(f"{as_base}/exchanges"))
    n_req = len(up.requests)
    try:
        rep = run_delegation_probe(
            gw.url,
            ident(gw, pa[0], lambda: as_issue(as_base, pa[1], iss=pa[2], email=pa[3])),
            ident(gw, pb[0], lambda: as_issue(as_base, pb[1], iss=pb[2], email=pb[3])),
            upstream=up, trigger=lambda c: c.call_tool(tool, {}),
            expected_subject_a=pa[1], expected_subject_b=pb[1],
            expected_issuer_a=pa[2] or AS_ISSUER, expected_issuer_b=pb[2] or AS_ISSUER)
    except ProbeError as e:
        print(f"INCONCLUSIVE: {redact(e)}")
        print("--- LiteLLM log tail (redacted) ---\n" + gw.tail())
        raise
    print("CHECKS:", json.dumps(rep.checks))
    print("VULNERABLE:", rep.vulnerable, "FAILURES:", rep.failures)
    exch = exchanges_since(as_base, n_ex)
    fixtures = thin_fixtures(ports["fixture_base"], two_issuers=two)
    controls = ("safe", "two_issuers (safe)") if two else ("safe",)
    grades = check_grades(rep.checks, fixtures, controls)
    print("CHECK GRADES:", json.dumps(grades))
    print("FIXTURES:", json.dumps(fixtures))
    reqs = up.requests[n_req:]
    payload = {
        **base, "probe": "xid10-delegation", "mode": mode, "trigger": "tool",
        "checks": rep.checks, "vulnerable": rep.vulnerable, "failures": rep.failures,
        "summary": redact(rep.summary()), "check_grades": grades,
        "broken_fixtures_in_run": {"fixtures": fixtures, "controls": list(controls),
                                   "note": "thin-deputy fixtures (integration/xid10_thin_deputy_"
                                           "gate.py) run in this run; a check is graded OK only "
                                           "if one of them failed it"},
        "a_first_eq_a_third_token": (len(rep.calls) >= 3
                                     and rep.calls[0].get("token") == rep.calls[2].get("token")),
        "recorded_calls": [_call(c) for c in rep.calls],
        "exchanges_client_auth": exch,
        "litellm_sent_client_credentials": sorted({str(e.get("client_auth_method")) for e in exch}),
        "actor_source": ("none configured: LiteLLM's RFC 8693 form has no actor_token; "
                         "act, if any, comes from the login server's act_from_client mode"),
        "client_negotiated_version": client_ver,
        "upstream_init_versions": up.init_versions[-3:],
        "upstream_protocol_version_headers": sorted({str(r.get("mcp_protocol_version"))
                                                     for r in reqs if r.get("method")}),
        "litellm_key_reached_upstream": any(r.get("litellm_key_header") for r in reqs),
        "user_token_reached_upstream": False,  # set below
    }
    # Did any user token (not an exchanged one) reach the upstream? The user
    # tokens are minted per connect, so compare against the AS exchange log:
    # every upstream bearer must be an issued (exchanged) token.
    issued = {r.get("issued_fp") for r in _get(f"{as_base}/exchanges")}
    payload["user_token_reached_upstream"] = any(
        r.get("authorization") and r["authorization"] not in issued for r in reqs)
    tag = "-act_from_client" if base["as_act_from_client"] else ""
    save(mode, payload, tag=tag)


def mode_side_config(mode, gw, up, as_base, ports, base):
    """passthrough / shared_credential: deliberately broken LiteLLM configs; the
    same probe must flag them (detection through LiteLLM itself)."""
    tool, client_ver = discover_tool(gw, as_issue(as_base, "alice"))
    n_req = len(up.requests)
    rep = run_delegation_probe(
        gw.url, ident(gw, "A", lambda: as_issue(as_base, "alice")),
        ident(gw, "B", lambda: as_issue(as_base, "bob")), upstream=up,
        trigger=lambda c: c.call_tool(tool, {}), expected_subject_a="alice",
        expected_subject_b="bob", expected_issuer_a=AS_ISSUER, expected_issuer_b=AS_ISSUER)
    print("CHECKS:", json.dumps(rep.checks))
    print("VULNERABLE:", rep.vulnerable, "FAILURES:", rep.failures)
    reqs = up.requests[n_req:]
    save(mode, {**base, "probe": "xid10-delegation", "mode": mode, "trigger": "tool",
                "checks": rep.checks, "vulnerable": rep.vulnerable, "failures": rep.failures,
                "summary": redact(rep.summary()), "recorded_calls": [_call(c) for c in rep.calls],
                "a_first_eq_a_third_token": rep.calls[0].get("token") == rep.calls[2].get("token"),
                "client_negotiated_version": client_ver,
                "litellm_key_reached_upstream": any(r.get("litellm_key_header") for r in reqs),
                "deliberately_broken_config": True})


def mode_scope(gw, up, as_base, ports, base, scopes_none):
    import xid10_thin_deputy_gate as thin
    fx = ports["fixture_base"]
    broken = thin.run_scope_fixture(as_base, "scope_escalation", controls={},
                                    upstream_port=fx + 2, deputy_port=fx + 3)
    print(f"broken fixture: {broken.summary()}")
    subj = thin.SUBJECT_SCOPE_BROAD
    tool, _ = discover_tool(gw, as_issue(as_base, "alice", scope=subj))
    res = run_scope_narrowing_probe(
        gw.url, ident(gw, "A", lambda: as_issue(as_base, "alice", scope=subj)),
        ident(gw, "B", lambda: as_issue(as_base, "bob", scope=subj)), upstream=up,
        trigger=lambda c: c.call_tool(tool, {}), subject_scope=subj,
        configured_scope="" if scopes_none else "read:notes",
        exchange_lookup=thin.exchange_lookup_http(as_base),
        controls={"broken_fixture_failed": broken.grade == "FAIL"})
    print(res.summary())
    name = "scope_narrowing-noscopes" if scopes_none else "scope_narrowing"
    payload = {**res.to_dict(), **base, "mode": name,
               "gateway_scopes_config": None if scopes_none else ["read:notes"],
               "broken_fixture": {"name": "thin_deputy scope_escalation", "grade": broken.grade,
                                  "reason": broken.reason}}
    save_checked(name, payload)


def save_checked(name, payload):
    problems = gate_run_problems(payload)
    payload = {**payload, "run_valid": not problems, "run_problems": problems}
    save(name, payload)
    if problems:
        for p in problems:
            print(f"ERROR: {p}", file=sys.stderr)
        raise SystemExit(1)


def mode_issuer_unregistered(gw, up, as_base, ports, base, *, strict=False):
    import xid10_thin_deputy_gate as thin
    lax = bool(base["login_server"]["lax_subject_issuer"])
    if strict and lax:
        raise SystemExit("issuer_unregistered_strict needs the AS started WITHOUT "
                         "--lax-subject-issuer")
    if not strict and not lax:
        raise SystemExit("issuer_unregistered needs the AS started with --lax-subject-issuer")
    fx = ports["fixture_base"]
    broken = None
    if not strict:
        # A broken fixture can only fail against the lax AS; against the strict AS
        # the AS refuses the token, so the strict run is an observation (where the
        # issuer is validated), not a graded check, and carries no fixture.
        broken = thin.run_issuer_fixture(as_base, "issuer_any", controls={},
                                         upstream_port=fx + 2, deputy_port=fx + 3)
        print(f"broken fixture: {broken.summary()}")
    control_tok = as_issue(as_base, "mallory", iss=PROVX, email="mallory@provx.test", key="provx")
    probe_tok = as_issue(as_base, "mallory", iss=UNREGISTERED, email="mallory@provx.test", key="provx")
    tool, _ = discover_tool(gw, control_tok)
    res = run_issuer_unregistered_probe(
        gw.url, control_identity=ident(gw, "control", lambda: control_tok),
        probe_identity=ident(gw, "probe", lambda: probe_tok), upstream=up,
        trigger=lambda c, n: c.call_tool(tool, {"nonce": n}), probe_token_fp=fp(probe_tok),
        probe_issuer=UNREGISTERED, exchange_records=lambda: _get(f"{as_base}/exchanges"),
        controls={} if strict else {"broken_fixture_failed": broken.grade == "FAIL"},
        quiet_seconds=3,
        settle_seconds=2)
    print(res.summary())
    ev = res.evidence
    print(f"  probe error: {ev['probe_error']}  exchange attempted: "
          f"{ev['exchange_attempted_with_probe_token']}")
    save_checked("issuer_unregistered-strict_login_server" if strict else "issuer_unregistered", {
        **res.to_dict(), **base,
        "signing_key_of_probe": "provx (LiteLLM does not validate inbound tokens in this config)",
        **({"observation_only": True,
            "observation": "where issuer validation happens: the same probe against the "
                           "default (strict) login server; not graded, no broken fixture "
                           "(the AS refuses the token, so no fixture could fail here)"}
           if strict else
           {"broken_fixture": {"name": "thin_deputy issuer_any", "grade": broken.grade,
                               "reason": broken.reason}})})


def mode_email_crossprovider(gw, up, as_base, ports, base):
    y_email = "carol@provy.test"
    y_tok = as_issue(as_base, "carol-y", iss=PROVY, email=y_email)
    dave_tok = as_issue(as_base, "dave-x", iss=PROVX, email="dave@provx.test")
    probe_tok = as_issue(as_base, "carol-x", iss=PROVX, email=y_email)
    tool, _ = discover_tool(gw, y_tok)
    trig = lambda c: c.call_tool(tool, {})  # noqa: E731
    y_calls, y_err = observe_one_call(ident(gw, "Y", lambda: y_tok), up, trig)
    x_calls, x_err = observe_one_call(ident(gw, "Xctl", lambda: dave_tok), up, trig)
    p_calls, p_err = observe_one_call(ident(gw, "probe", lambda: probe_tok), up, trig)
    pc = [{"subject": c.subject, "issuer": c.issuer, "token": fp(c.token),
           "email": up.emails.get(fp(c.token)), "scope": c.scope} for c in p_calls]
    grade, label, reason = grade_issuer_email_crossprovider(
        probe_calls=pc, control_reached=bool(x_calls), x_issuer=PROVX, y_issuer=PROVY,
        y_subject="carol-y", claimed_email=y_email)
    print(f"[{grade}] {label}: {reason}")
    save_checked("issuer_email_crossprovider", {
        **base, "probe": "issuer_email_crossprovider",
        "cosai": "CoSAI MCP Security v2.0, 3.2.2 / 3.3.2",
        "grade": grade, "label": label, "reason": reason,
        "controls": {"y_reached_upstream": bool(y_calls), "x_control_reached_upstream": bool(x_calls)},
        "observations": {"gateway_has_user_store": False, "probe_accepted": bool(p_calls),
                         "probe_error": p_err, "probe_upstream_calls": pc,
                         "y_upstream_identity": [(c.issuer, c.subject) for c in y_calls],
                         "y_error": y_err, "x_control_error": x_err}})


def grade_exchange_fail(*, control_reached, fail_reached, no_auth_reached, caller_errored,
                        broken_fixture_failed):
    """FAIL if any request made while the exchange failed reached the upstream
    (whatever its Authorization). OK only if nothing reached it, the caller got
    an error, the control reached it first, and the fall-through fixture FAILed
    in this run. Else INCONCLUSIVE."""
    if fail_reached or no_auth_reached:
        return "FAIL", "reached_upstream", "a request made while the exchange failed reached the upstream"
    if not control_reached:
        return "INCONCLUSIVE", "inconclusive", "the control did not reach the upstream"
    if not caller_errored:
        return "INCONCLUSIVE", "inconclusive", "the caller did not receive an error"
    if not broken_fixture_failed:
        return "INCONCLUSIVE", "inconclusive", "the fall-through fixture did not FAIL in this run"
    return "OK", "fails_closed", ("nothing reached the upstream while the exchange failed; the "
                                  "caller got an error; the control reached it first")


def _call_with_nonce(client_fn, tool, nonce):
    c = client_fn()
    try:
        c.initialize()
        r = c.call_tool(tool, {"nonce": nonce})
        return {"result": redact(json.dumps(r))[:500], "is_error": bool(r.get("isError"))}
    except Exception as e:  # noqa: BLE001
        return {"error": redact(e)[:500], "is_error": True}
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass


def mode_exchange_fail(gw, up, as_base, ports, base, switch):
    tok_ctl = as_issue(as_base, "alice")
    tool, _ = discover_tool(gw, tok_ctl)
    n = {k: make_nonce(k) for k in ("control", "fail", "noauth", "fx_control", "fx_fail")}
    switch.fail = False
    ctl = _call_with_nonce(lambda: gw.client(tok_ctl), tool, n["control"])
    hits0 = dict(switch.hits)
    switch.fail = True
    fail = _call_with_nonce(lambda: gw.client(as_issue(as_base, "alice")), tool, n["fail"])
    hits1 = dict(switch.hits)
    noauth = _call_with_nonce(lambda: gw.client(None), tool, n["noauth"])
    hits2 = dict(switch.hits)
    per_server = http_status(f"http://127.0.0.1:{ports['litellm']}/mcp/{SERVER}",
                             gw.headers(None), {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                                "params": {"name": tool, "arguments": {}}})
    switch.fail = False
    time.sleep(1)
    # Broken fixture: same switchable endpoint, same upstream.
    fxd = FallThroughDeputy(ports["fixture_base"] + 5, switch.url, f"http://127.0.0.1:{ports['upstream']}/mcp").start()
    try:
        fx_client = lambda tok: MCPClient(HTTPTransport(fxd.url, headers={  # noqa: E731
            "Authorization": f"Bearer {tok}"}))
        fx_ctl = _call_with_nonce(lambda: fx_client(as_issue(as_base, "alice")), "read_note", n["fx_control"])
        switch.fail = True
        fx_fail = _call_with_nonce(lambda: fx_client(as_issue(as_base, "alice")), "read_note", n["fx_fail"])
        switch.fail = False
    finally:
        fxd.stop()
    fx_grade = grade_exchange_fail(
        control_reached=bool(up.by_nonce(n["fx_control"])), fail_reached=bool(up.by_nonce(n["fx_fail"])),
        no_auth_reached=False, caller_errored=fx_fail.get("is_error", False),
        broken_fixture_failed=True)
    grade, label, reason = grade_exchange_fail(
        control_reached=any(r.get("authorization") for r in up.by_nonce(n["control"])),
        fail_reached=bool(up.by_nonce(n["fail"])), no_auth_reached=bool(up.by_nonce(n["noauth"])),
        caller_errored=fail.get("is_error", False) and noauth.get("is_error", False),
        broken_fixture_failed=fx_grade[0] == "FAIL")
    print(f"[{grade}] {label}: {reason}")
    print(f"  fixture: {fx_grade}")
    upstream_view = {k: [{kk: r.get(kk) for kk in ("method", "authorization", "header_names")}
                         for r in up.by_nonce(v)] for k, v in n.items()}
    save("exchange_fail", {
        **base, "probe": "exchange_fail", "grade": grade, "label": label, "reason": reason,
        "nonces": n,
        "calls": {"control": ctl, "exchange_fails_new_token": fail, "exchange_fails_no_authorization": noauth},
        "token_endpoint_hits": {"after_control": hits0, "after_fail_call": hits1,
                                "after_no_auth_call": hits2},
        "token_endpoint_requests": switch.requests,
        "per_server_endpoint_no_token": per_server,
        "upstream_requests_by_nonce": upstream_view,
        "broken_fixture": {"name": "fall-through deputy (forwards with no Authorization when "
                                   "the exchange fails)", "grade": fx_grade[0], "reason": fx_grade[2],
                           "control": fx_ctl, "fail": fx_fail},
        "caller_error_text": fail.get("result") or fail.get("error")})


def mode_cache(gw, up, as_base, ports, base):
    """Trial: A reads the same resource twice through LiteLLM. Origin reads per
    gateway read = 1 each time -> no cache (DOES NOT CACHE). The cachescope
    probe needs a cache to test; it is not run when there is none."""
    tok = as_issue(as_base, "alice")
    c = gw.client(tok)
    out = {"reads": []}
    try:
        c.initialize()
        resources = c.list_resources()
        out["resources_via_gateway"] = [r.get("uri") for r in resources]
        uri = resources[0]["uri"] if resources else None
        if uri is None:
            raise SystemExit("no resource discovered through LiteLLM")
        up.resource_meta = {"cacheScope": "private", "ttlMs": 60000}
        per_read = []
        for _ in range(2):
            before = up.reads_served
            r = c.read_resource(uri)
            per_read.append(up.reads_served - before)
            contents = (r or {}).get("contents") or [{}]
            out["reads"].append({"text": contents[0].get("text"),
                                 "cacheScope_at_client": r.get("cacheScope"),
                                 "ttlMs_at_client": r.get("ttlMs"),
                                 "result_keys": sorted(r.keys())})
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass
    caches = any(n == 0 for n in per_read)
    print(f"origin reads per gateway read: {per_read} -> caches={caches}")
    save("cachescope-private", {
        **base, "probe": "cachescope", "stage": "caching_trial",
        "grade_honouring": "INCONCLUSIVE" if not caches else "NOT RUN",
        "caching_trial": {"caches": caches, "origin_reads_per_gateway_read": per_read,
                          "uri": uri, "origin_label": up.resource_meta, **out},
        "note": ("no cache: the cachescope probe has nothing to test, so it is not run "
                 "(DOES NOT CACHE)" if not caches else
                 "LiteLLM cached: run the cachescope probe before grading")})


# ------------------------------------------------------------------ main
def main():
    as_base, ports = require_endpoints()
    ll_bin = os.environ.get("LL_BIN") or sys.exit("ERROR: set LL_BIN (the venv's litellm)")
    mode = os.environ.get("LL_MODE", "delegation")
    scopes_none = os.environ.get("LL_GW_SCOPES", "").strip().upper() == "NONE"
    cfg_key = "scope_narrowing-noscopes" if (mode == "scope_narrowing" and scopes_none) else mode
    if cfg_key not in CONFIGS:
        raise SystemExit(f"unknown LL_MODE {mode}")
    versions = litellm_versions(ll_bin)
    if versions["litellm"] != PINNED_VERSION:
        raise SystemExit(f"ERROR: LiteLLM {versions['litellm']} installed; this gate is pinned "
                         f"to {PINNED_VERSION}")
    client_secret = os.environ.get("LL_CLIENT_SECRET") or secrets.token_hex(16)
    facts = login_facts(as_base)
    print(f"=== MODE {cfg_key}  LiteLLM {versions['litellm']} (mcp {versions['mcp']})  AS {facts}")
    up = Recorder(ports["upstream"], _get(f"{as_base}/jwks")).start()
    switch = None
    token_endpoint = f"{as_base}/token"
    if mode == "exchange_fail":
        switch = SwitchableTokenEndpoint(ports["fixture_base"] + 4, as_base).start()
        token_endpoint = switch.url
    subs = {"UPSTREAM_URL": f"http://127.0.0.1:{ports['upstream']}/mcp",
            "TOKEN_ENDPOINT": token_endpoint, "CLIENT_SECRET": client_secret}
    static = None
    if mode == "shared_credential":
        static = as_issue(as_base, "litellm-service", aud=UPSTREAM_AUD)
        subs["STATIC_TOKEN"] = static
    gw = LiteLLM(ll_bin, CONFIGS[cfg_key], ports["litellm"], subs)
    base = {"gateway": "litellm", "gateway_label": "an LLM gateway with MCP features",
            "gateway_version": versions["litellm"], "gateway_versions": versions,
            "install": f"pip litellm[proxy]=={PINNED_VERSION} in its own venv (open-source build, "
                       "no licence key, no database)",
            "endpoints": {"as_base": as_base, **ports}, "login_server": facts,
            "as_act_from_client": bool(facts.get("act_from_client")),
            "client_transport": "HTTPTransport (legacy Streamable HTTP); MCPClient asks for "
                                "2026-07-28, LiteLLM answers with its default set",
            "upstream_protocol_version": (f"{UPSTREAM_VERSION} (the upstream answers initialize with "
                                          "the requested legacy version; LiteLLM 1.109.1 advertises "
                                          "2024-11-05..2025-11-25 by default)"),
            "caller_auth": "x-litellm-api-key: throwaway master key; Authorization: Bearer <user JWT>",
            "docs": DOCS}
    try:
        gw.start()
        base.update(gw.record())
        print(f"LiteLLM up @ {gw.url}")
        if mode in ("delegation", "two_issuers"):
            mode_delegation(mode, gw, up, as_base, ports, base)
        elif mode in ("passthrough", "shared_credential"):
            mode_side_config(mode, gw, up, as_base, ports,
                             dict(base, static_credential=fp(static) if static else None))
        elif mode == "scope_narrowing":
            mode_scope(gw, up, as_base, ports, base, scopes_none)
        elif mode == "issuer_unregistered":
            mode_issuer_unregistered(gw, up, as_base, ports, base)
        elif mode == "issuer_unregistered_strict":
            mode_issuer_unregistered(gw, up, as_base, ports, base, strict=True)
        elif mode == "issuer_email_crossprovider":
            mode_email_crossprovider(gw, up, as_base, ports, base)
        elif mode == "exchange_fail":
            mode_exchange_fail(gw, up, as_base, ports, base, switch)
        elif mode == "cache":
            mode_cache(gw, up, as_base, ports, base)
    except Exception:
        print("--- LiteLLM log tail (redacted) ---\n" + gw.tail())
        raise
    finally:
        gw.stop()
        up.stop()
        if switch:
            switch.stop()


if __name__ == "__main__":
    main()
