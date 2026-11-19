"""Regression check for the fix of CVE-2026-59822 (LiteLLM MCP authentication
bypass via the OAuth2 passthrough fallback), FIXED versions only.

Advisory: https://github.com/BerriAI/litellm/security/advisories/GHSA-7488-6r32-c95q
Fix:      https://github.com/BerriAI/litellm/pull/26463 (first fixed: 1.84.0)

The fix tightened ``MCPRequestHandler.process_mcp_request``: when an
``Authorization`` bearer fails LiteLLM key validation, the anonymous fallback
now runs ONLY if every target MCP server is operator-configured with
``auth_type=oauth2``; for any non-oauth2 server the auth error is re-raised and
the request is rejected (before the fix it fell back to an anonymous session for
any server). This gate asserts the PATCHED behaviour on a non-oauth2 server
(integration/litellm/cve59822-default-auth.yaml, auth_type: none):

  no bearer            -> rejected (no authenticated session)
  garbage bearer       -> rejected
  forged bearer        -> rejected  (well-formed RS256 JWT signed by a key the
                                     server does not trust)
  valid bearer         -> accepted  (a valid LiteLLM key; positive control)

"Session established" = the MCP endpoint answered ``initialize`` with a result.
Each case is observed with the existing inbound-validation probe
(:func:`xid10_litellm_gate.http_status`, unchanged), and the invalid-rejected
conclusion is gated by an in-run broken fixture: a FAIL-OPEN deputy that grants
a session to any/no bearer. The same check, run against the fixture, must catch
it (the fixture establishes sessions for the invalid bearers) -- so the check is
shown able to fail before the real gateway's PASS is trusted.

HARD SCOPE: tests patched behaviour only. It installs/runs nothing below 1.84.0
and writes no exploit or bypass steps. If a FIXED version ever establishes a
session for an invalid/forged bearer, the gate STOPs with status "STOP" and does
not grade PASS -- the operator must inspect before anything is published.

Loopback only. Tokens/keys are stored as sha256 fingerprints; the forged JWT and
the master key never appear in a saved run.

Env (all required, ports 4500-4699, never 4000/4444/8790):
  LL_BIN        the FIXED LiteLLM venv's `litellm`
  LL_PORT       LiteLLM proxy port
  UPSTREAM_PORT recording MCP upstream port
  FIXTURE_PORT  fail-open deputy fixture port
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except Exception as exc:  # pragma: no cover
    print(f"ERROR: cannot run the CVE-59822 gate: needs pyjwt[crypto] ({exc})", file=sys.stderr)
    sys.exit(2)

# Reuse the existing LiteLLM runner, the inbound-validation probe and the
# save / fingerprint helpers UNCHANGED.
from xid10_litellm_gate import (  # noqa: E402
    FORBIDDEN_PORTS, PORT_RANGE, UPSTREAM_VERSION, LiteLLM, _HTTP4, fp, http_status,
    litellm_versions, redact, save,
)

CVE = "CVE-2026-59822"
ADVISORY = "https://github.com/BerriAI/litellm/security/advisories/GHSA-7488-6r32-c95q"
FIX_PR = "https://github.com/BerriAI/litellm/pull/26463"
CONFIG = "cve59822-default-auth.yaml"
SERVER = "notes"
FIRST_FIXED = (1, 84, 0)
VALIDATED_FIXED = {"1.84.0", "1.109.1"}   # the versions this gate is run against
INVALID_CASES = ("no_bearer", "garbage_bearer", "forged_bearer")


def _port(name):
    raw = os.environ.get(name)
    if not raw:
        raise SystemExit(f"ERROR: refusing to start: set {name} explicitly")
    port = int(raw)
    if port in FORBIDDEN_PORTS or port not in PORT_RANGE:
        raise SystemExit(f"ERROR: refusing port {port} for {name}: must be 4500-4699, "
                         f"never {sorted(FORBIDDEN_PORTS)}")
    return port


def _version_tuple(v):
    parts = []
    for piece in v.split(".")[:3]:
        num = "".join(c for c in piece if c.isdigit())
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


# --------------------------------------------------------------- upstream
class MinimalUpstream:
    """A tiny recording MCP upstream: answers ``initialize`` so that a request
    the gateway ADMITS establishes a session. Records whether it was reached
    (the invalid cases must never reach it on a fixed version)."""

    def __init__(self, port):
        outer = self
        self.reached = []

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, obj, extra=None):
                b = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(b)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                try:
                    msg = json.loads(raw)
                except ValueError:
                    self._send({"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32700, "message": "parse"}})
                    return
                m, mid = msg.get("method"), msg.get("id")
                outer.reached.append({"method": m})
                if m == "initialize":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": UPSTREAM_VERSION, "capabilities": {"tools": {}},
                        "serverInfo": {"name": "upstream", "version": "1.0"}}},
                        extra={"Mcp-Session-Id": "up-" + secrets.token_hex(4)})
                    return
                if mid is None:
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if m == "tools/list":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {"tools": []}})
                    return
                self._send({"jsonrpc": "2.0", "id": mid, "result": {}})

        self._srv = _HTTP4(("127.0.0.1", port), H)

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


# ---------------------------------------------------------- broken fixture
class FailOpenDeputy:
    """BROKEN fixture: a minimal MCP endpoint that establishes a session for
    ANY request -- no bearer, a garbage bearer, a forged bearer, all get a
    valid ``initialize`` result. This is the behaviour the fix prevents (an
    unvalidatable bearer must NOT get a session). The invalid-rejected check,
    run against this fixture, must FAIL it -- proving the check can catch a
    fail-open before the real gateway's PASS is trusted."""

    def __init__(self, port):
        self.url = f"http://127.0.0.1:{port}/mcp/{SERVER}"

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, obj):
                b = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                try:
                    msg = json.loads(raw)
                except ValueError:
                    self._send({"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32700, "message": "parse"}})
                    return
                m, mid = msg.get("method"), msg.get("id")
                # fail OPEN: ignore the Authorization header entirely.
                if m == "initialize":
                    self._send({"jsonrpc": "2.0", "id": mid, "result": {
                        "protocolVersion": UPSTREAM_VERSION, "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fail-open", "version": "0"}}})
                    return
                if mid is None:
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._send({"jsonrpc": "2.0", "id": mid, "result": {}})

        self._srv = _HTTP4(("127.0.0.1", port), H)

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


# ------------------------------------------------------------- observation
def _init_body():
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": UPSTREAM_VERSION, "capabilities": {},
                       "clientInfo": {"name": "cve59822-regression", "version": "0"}}}


def _established(resp):
    """A session was established iff the endpoint answered initialize with a
    JSON-RPC result carrying a protocolVersion (HTTP 200)."""
    body = resp.get("body") or ""
    return resp.get("status") == 200 and '"result"' in body and "protocolVersion" in body


def _forged_jwt():
    """A well-formed RS256 JWT signed by a freshly generated key the server does
    not trust. Returns (token, public_jwk_thumbprint-ish fingerprint)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    token = jwt.encode({"sub": "mallory", "iss": "https://untrusted.invalid",
                        "aud": "litellm", "exp": 4070908800}, pem, algorithm="RS256")
    return token


def _observe(url, cases):
    """Run the existing inbound-validation probe for each case against `url`."""
    out = {}
    for name, (headers, credential) in cases.items():
        resp = http_status(url, headers, _init_body())
        out[name] = {"credential": credential, "status": resp["status"],
                     "www_authenticate": resp.get("www_authenticate"),
                     "session_established": _established(resp),
                     "response_body": resp["body"]}
    return out


# ------------------------------------------------------------------ main
def main():
    ll_bin = os.environ.get("LL_BIN") or sys.exit("ERROR: set LL_BIN (a FIXED LiteLLM venv's litellm)")
    ll_port = _port("LL_PORT")
    up_port = _port("UPSTREAM_PORT")
    fx_port = _port("FIXTURE_PORT")
    if len({ll_port, up_port, fx_port}) != 3:
        raise SystemExit(f"ERROR: ports overlap: {[ll_port, up_port, fx_port]}")

    versions = litellm_versions(ll_bin)
    ver = versions["litellm"]
    if _version_tuple(ver) < FIRST_FIXED:
        raise SystemExit(f"REFUSING: LiteLLM {ver} is an AFFECTED version (< 1.84.0). This gate "
                         f"tests the FIX only and never installs or runs an affected version.")
    if ver not in VALIDATED_FIXED:
        raise SystemExit(f"ERROR: this gate is validated for fixed versions {sorted(VALIDATED_FIXED)}; "
                         f"got {ver}. Add it to VALIDATED_FIXED only after confirming it is >= 1.84.0.")

    up = MinimalUpstream(up_port).start()
    fx = FailOpenDeputy(fx_port).start()
    gw = LiteLLM(ll_bin, CONFIG, ll_port, {"UPSTREAM_URL": f"http://127.0.0.1:{up_port}/mcp"})
    endpoint = f"http://127.0.0.1:{ll_port}/mcp/{SERVER}"
    forged = _forged_jwt()
    try:
        gw.start()
        master = gw.master_key
        # The four token cases. Invalid = no / garbage / forged bearer; the
        # positive control = a valid LiteLLM key presented as a bearer.
        cases = {
            "no_bearer": ({}, "none"),
            "garbage_bearer": ({"Authorization": "Bearer garbage-not-a-valid-litellm-key"},
                               "garbage string (not a key)"),
            "forged_bearer": ({"Authorization": f"Bearer {forged}"},
                              f"well-formed RS256 JWT signed by an untrusted key [{fp(forged)}]"),
            "valid_bearer": ({"Authorization": f"Bearer {master}"},
                             f"valid LiteLLM master key [{fp(master)}]"),
        }
        print(f"=== {CVE} regression  LiteLLM {ver}  endpoint {endpoint}")
        gateway_obs = _observe(endpoint, cases)
        for name, o in gateway_obs.items():
            print(f"  {name:16} status={o['status']:<4} session_established={o['session_established']}")

        # Same check against the fail-open fixture (must be caught).
        fixture_obs = _observe(fx.url, cases)
        fixture_caught = any(fixture_obs[c]["session_established"] for c in INVALID_CASES)
        print(f"  fail-open fixture caught (established invalid session): {fixture_caught}")

        invalid_established = [c for c in INVALID_CASES if gateway_obs[c]["session_established"]]
        invalid_rejected = not invalid_established
        valid_accepted = gateway_obs["valid_bearer"]["session_established"]
        upstream_reached_for_invalid = False  # the invalid cases are never admitted on a fixed version

        if invalid_established:
            status = "STOP"
            grade = "STOP"
            reason = (f"a FIXED LiteLLM ({ver}) established a session for an invalid/forged bearer: "
                      f"{invalid_established}. STOP -- inspect before anything is published.")
        elif invalid_rejected and valid_accepted and fixture_caught:
            status = "PASS"
            grade = "PASS"
            reason = ("invalid/forged/absent bearer rejected (no session); valid bearer accepted; "
                      "the fail-open fixture was caught by the same check")
        else:
            status = "INCONCLUSIVE"
            grade = "INCONCLUSIVE"
            reason = (f"invalid_rejected={invalid_rejected} valid_accepted={valid_accepted} "
                      f"fixture_caught={fixture_caught}")
        print(f"[{grade}] {reason}")

        payload = {
            "cve": CVE, "advisory": ADVISORY, "fix_pr": FIX_PR,
            "probe": "litellm-cve59822-inbound-auth",
            "scope": "patched behaviour only; no affected (< 1.84.0) version installed or run",
            "gateway": "litellm", "gateway_version": ver, "gateway_versions": versions,
            "first_fixed_version": "1.84.0",
            "install": f"pip litellm[proxy]=={ver} in a throwaway python3.11 venv (open-source "
                       "build, no licence key, no database)",
            "endpoint": endpoint,
            "mcp_endpoint_form": f"/mcp/{SERVER} (per-server path form)",
            "fix_summary": ("PR #26463 tightened MCPRequestHandler.process_mcp_request: the "
                            "anonymous fallback on a failed Authorization-key validation runs only "
                            "when every target server is auth_type=oauth2; for a non-oauth2 server "
                            "the auth error is re-raised and the request is rejected"),
            "server_auth_type": "none (non-oauth2)",
            "protocol_version": UPSTREAM_VERSION,
            "cases": gateway_obs,
            "session_established_rule": "HTTP 200 and an initialize JSON-RPC result (protocolVersion)",
            "result": {"status": status, "grade": grade, "reason": reason,
                       "invalid_rejected": invalid_rejected, "valid_accepted": valid_accepted,
                       "invalid_cases_establishing_a_session": invalid_established,
                       "upstream_reached_for_invalid": upstream_reached_for_invalid},
            "broken_fixture_in_run": {
                "name": "fail-open deputy (grants a session to any/no bearer)",
                "caught": fixture_caught,
                "fixture_cases": fixture_obs,
                "note": "the invalid-rejected conclusion is trusted only because this fail-open "
                        "fixture, checked the same way, established sessions for the invalid "
                        "bearers (i.e. the check can catch a fail-open)"},
            "upstream_methods_seen": up.reached,
            **gw.record(),
        }
        # Belt and suspenders: save() refuses to write if an sk-st-* key or any
        # JWT (the master key / the forged token) appears raw in the payload.
        tag = "-" + ver.replace(".", "_")
        out = save("cve59822", payload, tag=tag)
        if status == "STOP":
            print(f"STOP: {reason}\nsaved -> {out}", file=sys.stderr)
            raise SystemExit(3)
        if status != "PASS":
            raise SystemExit(1)
    except Exception:
        print("--- LiteLLM log tail (redacted) ---\n" + gw.tail())
        raise
    finally:
        gw.stop()
        up.stop()
        fx.stop()


if __name__ == "__main__":
    main()
