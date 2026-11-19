"""A LOCAL single-process HTTP practice MCP server with state handles.

For exercising the state-handle hijacking probe (:mod:`strangertest.statehandle`)
over real HTTP. It is the broken + safe fixture pair the probe's grading needs.

Two tools:

* ``open_state`` takes a ``marker`` and mints a server-side piece of state
  owned by the caller, returning a server-minted **handle** in
  ``structuredContent.handle``.
* ``read_state`` takes a ``handle`` and returns the marker stored in the state
  it references.

Identity is the ``Authorization`` header, or with ``identity_from="jwt"`` the
bearer's ``(orig_iss or iss, sub)`` claims (read, NOT verified: this server
sits behind the gateway under test), so a token a gateway exchanges afresh on
every request still names the same user.

Modes:

* ``leaky`` — ``read_state`` returns the stored marker for ANY existing handle,
  ignoring who is asking. Possession of the handle is treated as authentication,
  so B replaying A's handle reaches A's state. THE ATTACK SUCCEEDS.
* ``safe`` — ``read_state`` binds each handle to the user who minted it (its
  owner, taken from the authenticated identity). A caller who is not the owner
  is refused exactly like an unknown handle. B replaying A's handle is refused.
* ``accept_forged`` — safe ownership on known handles, but an UNKNOWN handle
  returns an empty success instead of a refusal (the forged-handle control then
  fails, so the probe must not report OK).
* ``break_own_read`` — ``read_state`` never returns the marker, even to the
  owner (the observer is blind; A's positive control fails).
* ``no_handle`` — ``open_state`` returns success but mints no handle (there is
  no state-handle feature to attack).

Refusals are returned as tool-level results with ``isError: true`` (the
idiomatic MCP way a tool reports failure), which the probe reads as a refusal.

NEVER expose this on a network. Run it:

    STRANGERTEST_MODE=leaky STRANGERTEST_PORT=4601 \\
        python3 -m strangertest.practice_statehandle_http
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
MODES = ("leaky", "safe", "accept_forged", "break_own_read", "no_handle", "collapse")
FORBIDDEN_PORTS = {8790, 4444, 4000}


def _result(mid: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _text_result(text: str, *, is_error: bool = False) -> Dict[str, Any]:
    out: Dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        out["isError"] = True
    return out


def _b64json(part: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def token_claims(authorization: str) -> Optional[Dict[str, Any]]:
    """The claims of a ``Bearer <JWT>`` header, unverified; None if not a JWT."""
    token = authorization[7:] if authorization.startswith("Bearer ") else authorization
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        claims = _b64json(parts[1])
    except Exception:
        return None
    return claims if isinstance(claims, dict) else None


def identity_from_jwt(authorization: str) -> str:
    """``jwt:<orig_iss or iss>|<sub>`` from the bearer's claims; the raw header
    when there is no JWT with a ``sub`` (so two unparseable tokens stay two
    identities instead of collapsing into one)."""
    claims = token_claims(authorization)
    if not claims or not claims.get("sub"):
        return authorization
    return f"jwt:{claims.get('orig_iss') or claims.get('iss')}|{claims['sub']}"


class StateHandleStore:
    """The server's state and mode behaviour (no I/O; the handler calls in)."""

    def __init__(self, mode: str = "leaky", identity_from: str = "header"):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, not {mode!r}")
        if identity_from not in ("header", "jwt"):
            raise ValueError(f"identity_from must be 'header' or 'jwt', not {identity_from!r}")
        self.mode = mode
        self.identity_from = identity_from
        # handle -> {"owner": identity, "marker": marker}
        self.handles: Dict[str, Dict[str, str]] = {}
        self._lock = threading.Lock()
        # One record per message, for a gateway gate to inspect later. Only
        # fingerprints of identity/handle are kept, never a raw token/handle.
        self.seen: list = []

    def reset(self, mode: str, **kwargs: Any) -> None:
        """Switch mode in place, dropping all state (mirrors the tasks fixture:
        a restart on the same port would strand a gateway's keep-alive
        connections on the old handler)."""
        kwargs.setdefault("identity_from", self.identity_from)
        with self._lock:
            self.__init__(mode, **kwargs)  # type: ignore[misc]

    # -- tool handlers ---------------------------------------------------

    def _open_state(self, identity: str, marker: str) -> Dict[str, Any]:
        if self.mode == "no_handle":
            # No state-handle feature: a plain acknowledgement, no handle.
            return _text_result("opened (no handle)")
        handle = "sh-" + secrets.token_hex(16)
        with self._lock:
            self.handles[handle] = {"owner": identity, "marker": marker}
        return {
            "content": [{"type": "text", "text": "state opened"}],
            "structuredContent": {"handle": handle},
        }

    def _read_state(self, identity: str, handle: Any) -> Dict[str, Any]:
        with self._lock:
            state = self.handles.get(handle) if isinstance(handle, str) else None
            if state is None:
                # Unknown/forged handle.
                if self.mode == "accept_forged":
                    # Sloppy: pretend it is fine (the forged-handle control fails).
                    return _text_result("")
                return _text_result("unknown handle", is_error=True)
            if self.mode == "break_own_read":
                # A blind observer: never returns the marker, even to the owner.
                return _text_result("state read (contents withheld)")
            if self.mode in ("leaky", "collapse"):
                # Possession is treated as authentication: owner ignored.
                # "collapse" additionally reports one shared principal via whoami
                # (see _whoami): A and B look like the same user to the server.
                return self._state_body(state)
            # safe / accept_forged: bind the handle to its owner.
            if state["owner"] != identity:
                # A foreign handle is answered exactly like an unknown one.
                return _text_result("unknown handle", is_error=True)
            return self._state_body(state)

    def _whoami(self, identity: str) -> Dict[str, Any]:
        """Report the principal the server thinks the caller is, as a fingerprint.

        In every mode but ``collapse`` this is per-identity (distinct callers get
        distinct principals). In ``collapse`` it is a single shared value for all
        callers — the identity-collapse / shared-session shape, where a handle
        replay reaching another caller's state is NOT a cross-user access gain.
        """
        if self.mode == "collapse":
            principal = "shared-principal"
        else:
            principal = "sha256:" + hashlib.sha256(identity.encode()).hexdigest()[:12]
        return {
            "content": [{"type": "text", "text": principal}],
            "structuredContent": {"principal": principal},
        }

    @staticmethod
    def _state_body(state: Dict[str, str]) -> Dict[str, Any]:
        marker = state["marker"]
        return {
            "content": [{"type": "text", "text": marker}],
            "structuredContent": {"marker": marker},
        }

    # -- JSON-RPC dispatch ----------------------------------------------

    def handle(self, identity: str, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = msg.get("method")
        mid = msg.get("id")
        params = msg.get("params") or {}

        if method == "initialize":
            return _result(mid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "practice-statehandle", "version": "1"},
            })
        if isinstance(method, str) and method.startswith("notifications/"):
            return None
        if method == "tools/list":
            return _result(mid, {"tools": [
                {"name": "open_state",
                 "description": "Open server-side state; returns a handle.",
                 "inputSchema": {"type": "object",
                                 "properties": {"marker": {"type": "string"}}}},
                {"name": "read_state",
                 "description": "Read state back through a handle.",
                 "inputSchema": {"type": "object",
                                 "properties": {"handle": {"type": "string"}}}},
                {"name": "whoami",
                 "description": "Report the caller's principal (a distinctness signal).",
                 "inputSchema": {"type": "object", "properties": {}}},
            ]})
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "open_state":
                return _result(mid, self._open_state(identity, str(args.get("marker", ""))))
            if name == "read_state":
                return _result(mid, self._read_state(identity, args.get("handle")))
            if name == "whoami":
                return _result(mid, self._whoami(identity))
            return _err(mid, -32601, f"unknown tool {name!r}")

        if mid is None:
            return None
        return _err(mid, -32601, f"unknown method {method!r}")


def _make_handler(store: StateHandleStore):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

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
            identity = (identity_from_jwt(header) if store.identity_from == "jwt"
                        else header)
            try:
                msg = json.loads(raw)
            except ValueError:
                msg = None
            if isinstance(msg, dict):
                params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
                store.seen.append({
                    "method": msg.get("method"),
                    "tool": params.get("name"),
                    "identity": "sha256:" + hashlib.sha256(identity.encode()).hexdigest()[:12],
                    "token": "sha256:" + hashlib.sha256(header.encode()).hexdigest()[:12],
                    # Fingerprint of the handle a read names, so a gate can tell
                    # "B's read of A's handle reached the server".
                    "handle": ("sha256:" + hashlib.sha256(args["handle"].encode()).hexdigest()[:12]
                               if isinstance(args.get("handle"), str) else None),
                })
            if not isinstance(msg, dict):
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            resp = store.handle(identity, msg)
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
    mode: str,
    host: str = "127.0.0.1",
    port: int = 0,
    identity_from: str = "header",
) -> ThreadingHTTPServer:
    store = StateHandleStore(mode, identity_from=identity_from)
    server = ThreadingHTTPServer((host, port), _make_handler(store))
    server.daemon_threads = True
    server.store = store  # type: ignore[attr-defined]
    return server


def main() -> None:
    mode = os.environ.get("STRANGERTEST_MODE", "leaky")
    port = int(os.environ.get("STRANGERTEST_PORT", "0"))
    if port in FORBIDDEN_PORTS:
        raise SystemExit(f"ERROR: refusing reserved port {port}")
    server = build_server(mode, port=port)
    host, bound = server.server_address[0], server.server_address[1]
    print(f"practice-statehandle-http [{mode}] on http://{host}:{bound}/mcp")
    server.serve_forever()


if __name__ == "__main__":
    main()
