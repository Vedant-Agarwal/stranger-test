"""A LOCAL single-process HTTP practice MCP server with elicitation.

For exercising the elicitation cross-user-binding / account-takeover probe
(:mod:`strangertest.elicitation_takeover`) over real HTTP. It models the
2026-07-28 elicitation flow: a tool starts an elicitation that returns an
authorization step (URL/OAuth mode, or form mode), a (possibly different)
identity completes the authorization, and the server records which user the
resulting grant binds to.

Spec rules this server can either honour or break (MCP 2026-07-28 elicitation):

* the user who STARTED the elicitation MUST be the same user who COMPLETES the
  authorization, and the grant MUST bind to the authenticated completing user
  (user id derived from the credential's ``sub``);
* form mode MUST NOT request passwords / API keys / access tokens / payment
  credentials.

Tools (all over the 2026-07-28 modern per-request envelope):

* ``whoami``: the caller's own subject fingerprint (``sha256:<12 hex>`` of the
  bearer's ``sub``). Fingerprints only; never the raw ``sub`` or token.
* ``authorize_integration`` (START): opens an elicitation bound to the caller's
  ``sub`` and returns an elicitation descriptor (``mode`` ``url`` or ``form``).
* ``complete_authorization`` (COMPLETE): given an ``elicitationId``, completes
  the authorization as the CALLER's authenticated identity. This is where the
  binding is decided.
* ``grant_status`` (OBSERVE): the subject fingerprint the grant bound to, or
  null if not yet granted. Any caller may read it; it reveals only a
  fingerprint.

Modes:

* ``safe``: URL mode; the grant binds to the COMPLETER's verified ``sub``; form
  descriptors never request a secret. (A cannot be taken over: if B completes
  A's elicitation, the grant is B's.)
* ``leaky``: URL mode; the grant binds to whoever STARTED the elicitation,
  ignoring who completed it -> a cross-user account takeover of the starter.
* ``leaky_form_secret``: like ``safe`` for binding, but the elicitation is in
  FORM mode and requests a forbidden secret (a password) -- an illegal
  credential request.
* ``no_elicit``: the start tool returns a plain result with no elicitation
  descriptor, so the probe cannot observe an elicitation (inconclusive).

Identity is read from the bearer token's ``sub`` claim, UNVERIFIED (this server
sits behind the gateway/host that authenticated the caller). Use
:func:`make_test_jwt` to mint obvious fake test tokens.

NEVER expose this on a network. Run it::

    STRANGERTEST_MODE=leaky python3 -m strangertest.practice_elicitation_http
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

PROTOCOL_VERSION = "2026-07-28"
CLIENT_CAPS_KEY = "io.modelcontextprotocol/clientCapabilities"

MODES = ("safe", "leaky", "leaky_form_secret", "no_elicit")

# Field names / formats a form-mode elicitation MUST NOT request. Matched
# case-insensitively as substrings of the property name (plus JSON-schema
# ``format: password``), so ``api_key``, ``accessToken``, ``card_number`` etc.
# are all caught.
FORBIDDEN_SECRET_HINTS = (
    "password",
    "passwd",
    "secret",
    "apikey",
    "api_key",
    "api-key",
    "accesstoken",
    "access_token",
    "token",
    "private_key",
    "privatekey",
    "card",
    "cardnumber",
    "cvv",
    "cvc",
    "pan",
    "ssn",
)


def fingerprint(value: Optional[str]) -> Optional[str]:
    """``sha256:<12 hex>`` of a string (a subject id), or None. Never the value."""
    if not value:
        return None
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:12]


def _b64url(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64json(part: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def make_test_jwt(sub: str, iss: str = "https://login.test") -> str:
    """An OBVIOUS FAKE unsigned (``alg:none``) test JWT carrying ``sub``.

    The practice server reads claims unverified, so no real signature is needed.
    This is a throwaway test credential, never a real token.
    """
    header = _b64url({"alg": "none", "typ": "JWT"})
    payload = _b64url({"sub": sub, "iss": iss})
    return f"{header}.{payload}."


def subject_of(authorization: str) -> str:
    """The caller's subject: the bearer's ``sub`` claim, or the raw header.

    Unverified -- the host/gateway in front of this server authenticated the
    caller. Two tokens without a parseable ``sub`` stay two subjects (raw
    header) instead of collapsing into one.
    """
    token = authorization[7:] if authorization.startswith("Bearer ") else authorization
    parts = token.split(".")
    if len(parts) == 3:
        try:
            claims = _b64json(parts[1])
        except Exception:
            claims = None
        if isinstance(claims, dict) and claims.get("sub"):
            return str(claims["sub"])
    return authorization


def _result(mid: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


class _Elicitation:
    def __init__(self, starter_sub: str, marker: str, descriptor: Dict[str, Any]):
        self.id = "elic-" + secrets.token_hex(16)
        self.starter_sub = starter_sub
        self.marker = marker
        self.descriptor = descriptor
        self.completed_by: Optional[str] = None
        self.bound_sub: Optional[str] = None


class ElicitationState:
    """The practice server's behaviour for one mode.

    ``self.seen`` records one entry per message (method, caller fingerprint,
    elicitation starter/bound fingerprints) so a future gateway gate can show
    "B's completion of A's elicitation reached the upstream". Fingerprints only.
    """

    def __init__(self, mode: str = "safe"):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, not {mode!r}")
        self.mode = mode
        self.elicitations: Dict[str, _Elicitation] = {}
        self._lock = threading.Lock()
        self.seen: list = []

    # -- descriptors -----------------------------------------------------

    def _descriptor(self, elic_id: str, base_url: str) -> Dict[str, Any]:
        if self.mode == "leaky_form_secret":
            # Illegal: a form-mode elicitation asking for a password.
            return {
                "elicitationId": elic_id,
                "mode": "form",
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "account_password": {
                            "type": "string",
                            "title": "Your account password",
                            "format": "password",
                        }
                    },
                    "required": ["account_password"],
                },
            }
        # URL / OAuth mode: the authorization happens out of band at this URL.
        return {
            "elicitationId": elic_id,
            "mode": "url",
            "url": f"{base_url}/authorize?state={elic_id}",
        }

    # -- handling --------------------------------------------------------

    def handle(
        self, identity: str, msg: Dict[str, Any], base_url: str
    ) -> Optional[Dict[str, Any]]:
        method = msg.get("method")
        mid = msg.get("id")
        params = msg.get("params") or {}

        if method in ("initialize", "server/discover"):
            return _result(mid, {
                "resultType": "complete",
                "protocolVersion": PROTOCOL_VERSION,
                "supportedVersions": [PROTOCOL_VERSION],
                "capabilities": {"tools": {"listChanged": False},
                                 "elicitation": {}},
                "serverInfo": {"name": "practice-elicitation", "version": "1"},
            })
        if method == "tools/list":
            return _result(mid, {
                "resultType": "complete",
                "tools": [
                    {"name": "whoami", "description": "Your subject fingerprint.",
                     "inputSchema": {"type": "object", "properties": {}}},
                    {"name": "authorize_integration",
                     "description": "Start an authorization elicitation.",
                     "inputSchema": {"type": "object", "properties": {
                         "marker": {"type": "string"}}}},
                    {"name": "complete_authorization",
                     "description": "Complete an authorization elicitation.",
                     "inputSchema": {"type": "object", "properties": {
                         "elicitationId": {"type": "string"}}}},
                    {"name": "grant_status",
                     "description": "Subject fingerprint the grant bound to.",
                     "inputSchema": {"type": "object", "properties": {
                         "elicitationId": {"type": "string"}}}},
                ],
            })
        if isinstance(method, str) and method.startswith("notifications/"):
            return None

        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "whoami":
                return _result(mid, {
                    "resultType": "complete",
                    "subjectFingerprint": fingerprint(identity),
                })
            if name == "authorize_integration":
                return self._start(mid, identity, args, base_url)
            if name == "complete_authorization":
                return self._complete(mid, identity, args)
            if name == "grant_status":
                return self._grant_status(mid, args)
            return _err(mid, -32601, f"unknown tool {name!r}")

        if mid is None:
            return None
        return _err(mid, -32601, f"unknown method {method!r}")

    def _start(self, mid, identity, args, base_url):
        if self.mode == "no_elicit":
            # No elicitation offered: a plain tool result.
            return _result(mid, {
                "resultType": "complete",
                "content": [{"type": "text", "text": "connected (no elicitation)"}],
            })
        with self._lock:
            elic_id = "elic-" + secrets.token_hex(16)
            descriptor = self._descriptor(elic_id, base_url)
            descriptor["elicitationId"] = elic_id
            elic = _Elicitation(identity, str(args.get("marker", "")), descriptor)
            elic.id = elic_id
            self.elicitations[elic_id] = elic
        return _result(mid, {"resultType": "complete", "elicitation": descriptor})

    def _complete(self, mid, identity, args):
        elic_id = args.get("elicitationId")
        with self._lock:
            elic = self.elicitations.get(elic_id) if isinstance(elic_id, str) else None
            if elic is None:
                return _err(mid, -32602, "Invalid or nonexistent elicitationId")
            elic.completed_by = identity
            if self.mode == "leaky":
                # The leak: bind to whoever STARTED, ignoring the completer.
                elic.bound_sub = elic.starter_sub
            else:
                # Correct: bind to the authenticated COMPLETER's subject.
                elic.bound_sub = identity
            bound_fp = fingerprint(elic.bound_sub)
        return _result(mid, {
            "resultType": "complete",
            "status": "authorized",
            "boundSubjectFingerprint": bound_fp,
        })

    def _grant_status(self, mid, args):
        elic_id = args.get("elicitationId")
        with self._lock:
            elic = self.elicitations.get(elic_id) if isinstance(elic_id, str) else None
            if elic is None:
                return _err(mid, -32602, "Invalid or nonexistent elicitationId")
            bound_fp = fingerprint(elic.bound_sub)
            granted = elic.bound_sub is not None
        return _result(mid, {
            "resultType": "complete",
            "granted": granted,
            "boundSubjectFingerprint": bound_fp,
        })


def _make_handler(state: ElicitationState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _base_url(self) -> str:
            host = self.headers.get("Host") or self.server.server_address[0]
            return f"http://{host}/mcp"

        def do_GET(self):
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_DELETE(self):
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            header = self.headers.get("Authorization", "anonymous")
            identity = subject_of(header)
            try:
                msg = json.loads(raw)
            except ValueError:
                msg = None
            if isinstance(msg, dict):
                params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
                elic = state.elicitations.get(args.get("elicitationId"))
                state.seen.append({
                    "method": msg.get("method"),
                    "tool": params.get("name"),
                    "caller": fingerprint(identity),
                    "token": fingerprint(header),
                    "elicitation_starter": fingerprint(elic.starter_sub) if elic else None,
                    "elicitation_bound": fingerprint(elic.bound_sub) if elic else None,
                })
            if not isinstance(msg, dict):
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            resp = state.handle(identity, msg, self._base_url())
            if resp is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def build_server(
    mode: str = "safe", host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    state = ElicitationState(mode)
    server = ThreadingHTTPServer((host, port), _make_handler(state))
    server.daemon_threads = True
    server.state = state  # type: ignore[attr-defined]
    return server


def main() -> None:
    mode = os.environ.get("STRANGERTEST_MODE", "safe")
    port = int(os.environ.get("STRANGERTEST_PORT", "0"))
    server = build_server(mode, port=port)
    host, bound = server.server_address[0], server.server_address[1]
    print(f"practice-elicitation-http [{mode}] on http://{host}:{bound}/mcp")
    server.serve_forever()


if __name__ == "__main__":
    main()
