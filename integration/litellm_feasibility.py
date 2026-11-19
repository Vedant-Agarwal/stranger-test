"""EXPLORATION ONLY: feasibility check of LiteLLM as a third XID-10 gateway.

Not a gate. No grades are saved to integration/runs/, nothing feeds
gen_results.py. It drives an already-running LiteLLM proxy (started by hand,
config in notes/litellm-feasibility.md) and an already-running local_as, and
starts its own recording upstream on 127.0.0.1:$UPSTREAM_PORT.

Caller -> LiteLLM:  x-litellm-api-key: <throwaway master key>
                    Authorization: Bearer <user JWT from local_as /issue>
LiteLLM -> local_as /token (RFC 8693, subject_token = the user JWT)
LiteLLM -> upstream (exchanged token)

Modes (LL_MODE):
  one          one tools/call as user A; print what reached the upstream
  probe        run_delegation_probe A, B, A (unchanged grading)
  fail         control call, then calls with the exchange endpoint failing
               (run LiteLLM with the /token-fail config for the second part)
  two_issuers  alice@provx vs alice@provy through the A, B, A probe
  unknown_iss  one call with a token from an issuer local_as does not know
  same_key     one LiteLLM key, A's token then B's token (A, B, A probe
               already does this; this mode just prints the two identities)
  no_user      a call with the LiteLLM key and no Authorization header

Tokens are printed and stored only as sha256 fingerprints.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import jwt  # noqa: E402

from strangertest.delegate import MockUpstream, request_nonce, run_delegation_probe  # noqa: E402
from strangertest.mcp_client import MCPClient  # noqa: E402
from strangertest.probe import Identity, ProbeError  # noqa: E402
from strangertest.transports import HTTPTransport  # noqa: E402

FORBIDDEN_PORTS = {4444, 8790}
AS_BASE = os.environ.get("AS_BASE", "")
LL_URL = os.environ.get("LL_URL", "")
LL_KEY = os.environ.get("LL_KEY", "")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "0"))
AS_ISSUER = "https://local-as.test"
UPSTREAM_AUD = "https://upstream.test/mcp"
LEGACY = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def fp(t):
    return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else None


def redact(s):
    return _JWT_RE.sub(lambda m: fp(m.group(0)), str(s))


def require():
    for var, val in (("AS_BASE", AS_BASE), ("LL_URL", LL_URL), ("LL_KEY", LL_KEY)):
        if not val:
            raise SystemExit(f"refusing to start: set {var}")
    for port in (urlparse(AS_BASE).port, urlparse(LL_URL).port, UPSTREAM_PORT):
        if not port or port in FORBIDDEN_PORTS:
            raise SystemExit(f"refusing port {port}")
        if not 4400 <= port <= 4499:
            raise SystemExit(f"refusing port {port}: outside 44xx")
    for u in (AS_BASE, LL_URL):
        if urlparse(u).hostname != "127.0.0.1":
            raise SystemExit(f"refusing non-loopback {u}")


class Recorder(MockUpstream):
    """Recording MCP upstream (legacy Streamable HTTP, JSON responses). Answers
    initialize with the client's requested version if it is a legacy one,
    otherwise 2025-11-25; answers server/discover with method-not-found so an
    'auto' client falls back to initialize (logged either way)."""

    def __init__(self, port):
        super().__init__(UPSTREAM_AUD)
        with urllib.request.urlopen(f"{AS_BASE}/jwks", timeout=10) as r:
            self._key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(json.loads(r.read())["keys"][0]))
        self.log = []  # every request: method, version header, header names, auth fp
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

            def do_GET(self):
                outer.log.append({"http": "GET", "path": self.path})
                self._send({"error": "no GET stream"}, 405)

            def do_DELETE(self):
                outer.log.append({"http": "DELETE", "path": self.path})
                self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()

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
                entry = {"method": m, "mcp_protocol_version": self.headers.get("MCP-Protocol-Version"),
                         "header_names": sorted(k.lower() for k in self.headers.keys()),
                         "authorization": fp(bearer) if bearer else None}
                if m == "initialize":
                    entry["requested_version"] = params.get("protocolVersion")
                outer.log.append(entry)
                sid = {"Mcp-Session-Id": "up-session-1"}
                if m == "initialize":
                    req = params.get("protocolVersion")
                    ver = req if req in LEGACY else "2025-11-25"
                    entry["answered_version"] = ver
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": ver,
                        "capabilities": {"tools": {"listChanged": False}, "resources": {}},
                        "serverInfo": {"name": "upstream", "version": "1.0"}}}, extra=sid)
                    return
                if mid is None:  # notification
                    self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers()
                    return
                if m == "server/discover":
                    self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "not found"}})
                    return
                if m == "ping":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {}}); return
                if m == "tools/list":
                    outer._rec("tools/list", bearer, params)
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [tool]}}); return
                if m == "resources/list":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "resources": [{"uri": "note://caller", "name": "note"}]}}); return
                if m in ("tools/call", "resources/read"):
                    outer._rec(m, bearer, params)
                    if m == "tools/call":
                        res = {"content": [{"type": "text", "text": "ok"}], "isError": False}
                    else:
                        res = {"contents": [{"uri": params.get("uri"), "mimeType": "text/plain", "text": "ok"}]}
                    self._send({"jsonrpc": "2.0", "id": mid, "result": res}); return
                self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no"}})

        class S(ThreadingHTTPServer):
            allow_reuse_address = True
        self._srv = S(("127.0.0.1", port), H)

    def _rec(self, method, bearer, params):
        nonce = request_nonce(params)
        if not bearer:
            self.receive(token=None, parsed=False, parse_error="no Authorization", method=method, nonce=nonce)
            return
        try:
            c = jwt.decode(bearer, self._key, algorithms=["RS256"], issuer=AS_ISSUER,
                           options={"verify_aud": False, "require": ["exp", "iss"]})
        except Exception as e:  # noqa: BLE001
            self.receive(token=bearer, parsed=False, parse_error=str(e), method=method, nonce=nonce)
            return
        act = c.get("act")
        self.receive(subject=c.get("sub"), actor=act.get("sub") if isinstance(act, dict) else None,
                     audience=c.get("aud"), scope=c.get("scope"), token=bearer,
                     issuer=c.get("orig_iss") or c.get("iss"), method=method, nonce=nonce)

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv.shutdown(); self._srv.server_close()


def issue(sub, iss=None, email=None, key=None):
    q = {"sub": sub, "aud": "litellm-api", "scope": "read:notes"}
    for k, v in (("iss", iss), ("email", email), ("key", key)):
        if v:
            q[k] = v
    with urllib.request.urlopen(f"{AS_BASE}/issue?{urlencode(q)}", timeout=10) as r:
        return json.loads(r.read())["access_token"]


def exchanges():
    with urllib.request.urlopen(f"{AS_BASE}/exchanges", timeout=10) as r:
        return json.loads(r.read())


def client(user_token=None, key=LL_KEY):
    h = {"x-litellm-api-key": key} if key else {}
    if user_token:
        h["Authorization"] = f"Bearer {user_token}"
    return MCPClient(HTTPTransport(LL_URL, headers=h))


def show_calls(up, start=0):
    for c in up.calls[start:]:
        d = {k: v for k, v in vars(c).items() if k != "token"}
        d["token"] = fp(c.token)
        print("  upstream graded-call record:", redact(json.dumps(d)))


def show_ex(n0):
    for r in exchanges()[n0:]:
        print("  AS exchange:", json.dumps({k: r.get(k) for k in (
            "seq", "subject_fp", "subject_iss", "subject_sub", "requested_scope", "requested_audience",
            "actor_present", "outcome", "issued_fp")}))


def one_call(label, tok, up, tool=None, key=LL_KEY):
    n_up, n_log, n_ex = len(up.calls), len(up.log), len(exchanges())
    c = client(tok, key=key)
    err = None
    try:
        init = c.initialize()
        print(f"[{label}] initialize -> protocolVersion {init.get('protocolVersion')}")
        if tool is None:
            tools = c.list_tools()
            print(f"[{label}] tools via LiteLLM: {[t.get('name') for t in tools]}")
            tool = tools[0]["name"]
        r = c.call_tool(tool, {})
        print(f"[{label}] tools/call {tool} -> {redact(json.dumps(r))[:300]}")
    except Exception as e:  # noqa: BLE001
        err = redact(e)[:600]
        print(f"[{label}] ERROR: {err}")
    finally:
        try:
            c.close()
        except Exception:
            pass
    print(f"[{label}] upstream requests:")
    for e in up.log[n_log:]:
        print("   ", json.dumps(e))
    show_calls(up, n_up)
    show_ex(n_ex)
    return tool, err


def main():
    require()
    mode = os.environ.get("LL_MODE", "one")
    up = Recorder(UPSTREAM_PORT).start()
    try:
        if mode in ("one", "fail", "no_user", "unknown_iss"):
            if mode == "no_user":
                one_call("no-user-token", None, up)
            elif mode == "unknown_iss":
                tool, _ = one_call("control provx", issue("mallory", iss="https://provx.test"), up)
                one_call("unknown issuer", issue("mallory", iss="https://unregistered.test", key="provx"),
                         up, tool)
            else:
                one_call("A", issue("alice"), up)
        elif mode == "fail3":
            # Needs the 'notesflip' server whose exchange endpoint is a scratch
            # forwarder (FLIP_URL) that can be switched to always fail.
            flip = os.environ["FLIP_URL"]
            if urlparse(flip).hostname != "127.0.0.1" or urlparse(flip).port in FORBIDDEN_PORTS:
                raise SystemExit("refusing FLIP_URL")

            def setflip(fail):
                req = urllib.request.Request(f"{flip}/flip?fail={1 if fail else 0}", data=b"", method="POST")
                with urllib.request.urlopen(req, timeout=5) as r:
                    return json.loads(r.read())
            print("flip:", setflip(False))
            tok1 = issue("alice")
            tool, err = one_call("control: exchange OK", tok1, up)
            print("flip:", setflip(True))
            one_call("test: exchange fails, NEW user token (cache miss)", issue("alice"), up, tool)
            one_call("test: exchange fails, no Authorization", None, up, tool)
            one_call("side: exchange fails, control's token (cached exchange)", tok1, up, tool)
            print("flip:", setflip(False))
        elif mode == "fail2":
            # Needs the two-server config: 'notes' (good exchange) and
            # 'notesfail' (exchange at /token-fail). Control first.
            tok = issue("alice")
            one_call("control: notes (exchange OK)", tok, up, "notes-read_note")
            one_call("test: notesfail (exchange fails)", tok, up, "notesfail-read_note")
            one_call("test: notesfail, no Authorization", None, up, "notesfail-read_note")
            n_log = len(up.log)
            c = client(tok)
            try:
                c.initialize()
                names = [t.get("name") for t in c.list_tools()]
                print(f"[tools/list with failing server present] {names}")
            except Exception as e:  # noqa: BLE001
                print(f"[tools/list] ERROR: {redact(e)[:400]}")
            finally:
                c.close()
            for e in up.log[n_log:]:
                print("   ", json.dumps(e))
        elif mode in ("probe", "two_issuers", "same_key"):
            if mode == "two_issuers":
                pa = ("A", "alice", "https://provx.test")
                pb = ("B", "alice", "https://provy.test")
            else:
                pa, pb = ("A", "alice", None), ("B", "bob", None)
            tool, err = one_call("discover as A", issue(pa[1], iss=pa[2]), up)
            if err:
                return
            n_ex = len(exchanges())
            ident = lambda lab, sub, iss: Identity(label=lab, connect=lambda: client(issue(sub, iss=iss)))
            try:
                rep = run_delegation_probe(
                    LL_URL, ident(*pa), ident(*pb), upstream=up,
                    trigger=lambda c: c.call_tool(tool, {}),
                    expected_subject_a=pa[1], expected_subject_b=pb[1],
                    expected_issuer_a=pa[2] or AS_ISSUER, expected_issuer_b=pb[2] or AS_ISSUER)
            except ProbeError as e:
                print("INCONCLUSIVE:", redact(e)); show_calls(up); show_ex(n_ex); return
            print("CHECKS:", json.dumps(rep.checks))
            print("FAILURES:", rep.failures)
            print(redact(rep.summary()))
            for i, c in enumerate(rep.calls):
                print(f"  call {i}: sub={c['subject']} iss={c['issuer']} act={c['actor']} aud={c['audience']} "
                      f"scope={c['scope']} token={fp(c['token'])}")
            print("a_first_eq_a_third_token:", rep.calls[0]["token"] == rep.calls[2]["token"])
            show_ex(n_ex)
        else:
            raise SystemExit(f"unknown LL_MODE {mode}")
    finally:
        up.stop()


if __name__ == "__main__":
    main()
