"""Real transports for talking to an MCP server.

Currently: :class:`StdioTransport`, which launches a server as a subprocess and
exchanges newline-delimited JSON-RPC messages over its stdin/stdout. Each
``StdioTransport`` is one connection; to act as two identities, open two.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urlsplit

from .mcp_client import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    LISTEN_ACK_METHOD,
    LISTEN_EVENT_METHODS,
    MCP_METHOD_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    MCP_NAME_HEADER,
    NAME_BEARING_METHODS,
    PROTOCOL_VERSION_META_KEY,
    ListenStream,
    Transport,
)

import re as _re

# A header value that is plain visible ASCII (and not already the base64
# sentinel) rides as-is; anything else is wrapped the way the reference SDK
# encodes a non-ASCII Mcp-Name.
_HEADER_SAFE = _re.compile(r"^[\x20-\x7E]*$")
_B64_SENTINEL = _re.compile(r"^=\?base64\?.*\?=$")


# The tasks extension (SEP-2663) makes tasks/* name-bearing: Mcp-Name mirrors
# params.taskId. Pass this as ``HTTPTransport(name_bearing_methods=...)``.
# Without it a gateway that validates routing headers refuses every tasks/*
# request as malformed (agentgateway 1.7.0: -32020 "invalid MCP routing
# header: Mcp-Name"), a refusal that is not an authorization decision.
TASK_NAME_BEARING_METHODS: Dict[str, str] = {
    "tasks/get": "taskId",
    "tasks/update": "taskId",
    "tasks/cancel": "taskId",
}


def _encode_header_value(value: str) -> str:
    if _HEADER_SAFE.fullmatch(value) and value == value.strip() and not _B64_SENTINEL.fullmatch(value):
        return value
    import base64

    return "=?base64?" + base64.b64encode(value.encode("utf-8")).decode("ascii") + "?="

__all__ = [
    "StdioTransport",
    "HTTPTransport",
    "HTTPTransportError",
    "HTTPListenStream",
]


class StdioTransportError(RuntimeError):
    pass


class StdioTransport(Transport):
    def __init__(
        self,
        command: List[str],
        *,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
    ):
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        self._proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=full_env,
            cwd=cwd,
        )

    def _write(self, message: Dict[str, Any]) -> None:
        if self._proc.stdin is None:
            raise StdioTransportError("server stdin is closed")
        self._proc.stdin.write(json.dumps(message) + "\n")
        self._proc.stdin.flush()

    def _read_message(self) -> Dict[str, Any]:
        if self._proc.stdout is None:
            raise StdioTransportError("server stdout is closed")
        line = self._proc.stdout.readline()
        if not line:
            raise StdioTransportError("server closed the connection")
        return json.loads(line)

    def request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        self._write(message)
        want = message.get("id")
        # Read until the response that matches our request id, skipping any
        # server-initiated notifications or log lines.
        while True:
            msg = self._read_message()
            if msg.get("id") == want and ("result" in msg or "error" in msg):
                return msg

    def notify(self, message: Dict[str, Any]) -> None:
        self._write(message)

    def close(self) -> None:
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass
        for stream in (self._proc.stdin, self._proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass


class HTTPTransportError(RuntimeError):
    pass


class HTTPTransport(Transport):
    """Talks to an MCP server over Streamable HTTP (JSON or SSE responses).

    Each request is an HTTP POST of a JSON-RPC message. Extra headers (such as
    ``Authorization: Bearer <token>``) are sent on every request — that is how a
    caller acts as one identity. An ``Mcp-Session-Id`` the server returns is
    remembered and sent on later requests. Standard library only.
    """

    def __init__(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
        modern: bool = False,
        declared_version: str = "2026-07-28",
        client_info: Optional[Dict[str, Any]] = None,
        client_capabilities: Optional[Dict[str, Any]] = None,
        name_bearing_methods: Optional[Dict[str, str]] = None,
    ):
        """``name_bearing_methods`` adds methods (method -> params key) whose
        param is mirrored into the ``Mcp-Name`` header in modern mode, on top
        of the core ones (tools/call, prompts/get, resources/read), e.g.
        :data:`TASK_NAME_BEARING_METHODS`. Default: core methods only. A core
        method cannot be redefined."""
        extra = dict(name_bearing_methods or {})
        clash = {m: k for m, k in extra.items()
                 if m in NAME_BEARING_METHODS and NAME_BEARING_METHODS[m] != k}
        if clash:
            raise ValueError(f"name_bearing_methods cannot redefine core methods: {clash}")
        self._name_bearing = {**NAME_BEARING_METHODS, **extra}
        self._url = url
        self._base_headers = dict(headers or {})
        self._timeout = timeout
        self._session_id: Optional[str] = None
        # Modern (2026-07-28) mode: no initialize handshake, no session; every
        # request carries the per-request envelope. We emulate the handshake
        # locally so the MCPClient flow is unchanged, then send real calls
        # (tools/call, subscriptions/listen) as modern envelopes.
        self._modern = modern
        self._declared_version = declared_version
        self._client_info = client_info
        self._client_capabilities = client_capabilities if client_capabilities is not None else {}

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        headers.update(self._base_headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    def _modern_meta(self) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            PROTOCOL_VERSION_META_KEY: self._declared_version,
            CLIENT_CAPABILITIES_META_KEY: self._client_capabilities,
        }
        if self._client_info is not None:
            meta[CLIENT_INFO_META_KEY] = self._client_info
        return meta

    def _modern_envelope(
        self, message: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """Return a copy of ``message`` carrying the per-request ``_meta`` envelope,
        plus the routing headers the modern transport validates."""
        method = message.get("method")
        params = dict(message.get("params") or {})
        meta = dict(params.get("_meta") or {})
        meta.update(self._modern_meta())
        params["_meta"] = meta
        wrapped = dict(message)
        wrapped["params"] = params
        headers = {
            MCP_PROTOCOL_VERSION_HEADER: self._declared_version,
            MCP_METHOD_HEADER: method or "",
        }
        name_key = self._name_bearing.get(method or "")
        if name_key is not None:
            value = params.get(name_key)
            if isinstance(value, str):
                headers[MCP_NAME_HEADER] = _encode_header_value(value)
        return wrapped, headers

    def _post(self, message: Dict[str, Any], extra_headers: Optional[Dict[str, str]] = None):
        data = json.dumps(message).encode("utf-8")
        headers = self._headers()
        if extra_headers:
            headers.update(extra_headers)
        request = urllib.request.Request(
            self._url, data=data, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                session_id = resp.headers.get("Mcp-Session-Id")
                if session_id:
                    self._session_id = session_id
                content_type = resp.headers.get("Content-Type", "")
                body = resp.read().decode("utf-8")
                return content_type, body
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise HTTPTransportError(f"HTTP {exc.code} from {self._url}: {detail}")
        except urllib.error.URLError as exc:
            raise HTTPTransportError(f"could not reach {self._url}: {exc.reason}")

    def request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        want = message.get("id")
        if self._modern:
            if message.get("method") == "initialize":
                # The modern era has no initialize handshake: synthesize the
                # result locally so the client's version/capabilities flow is
                # unchanged, without a nonexistent round trip.
                return {
                    "jsonrpc": "2.0",
                    "id": want,
                    "result": {
                        "protocolVersion": self._declared_version,
                        "capabilities": {},
                        "serverInfo": {"name": "modern", "version": "0"},
                    },
                }
            wrapped, extra = self._modern_envelope(message)
            content_type, body = self._post(wrapped, extra)
        else:
            content_type, body = self._post(message)
        response: Optional[Dict[str, Any]] = None
        for parsed in self._iter_messages(content_type, body):
            if parsed.get("id") == want and ("result" in parsed or "error" in parsed):
                response = parsed
        if response is None:
            raise HTTPTransportError(f"no response matching id {want!r} from {self._url}")
        return response

    def notify(self, message: Dict[str, Any]) -> None:
        if self._modern:
            # The 2026-07-28 core defines no client-to-server notifications over
            # HTTP; dropping notifications/initialized matches the spec.
            return
        self._post(message)

    def open_listen(
        self,
        listen_request: Dict[str, Any],
        *,
        protocol_version: Optional[str] = None,
        ack_timeout: float = 10.0,
    ) -> ListenStream:
        """Open the listen stream as a long-lived SSE POST and wait for the ack.

        ``subscriptions/listen`` is not a request/response call: the response
        *is* the stream. We send it on its own HTTP connection (so the
        transport's ordinary request path is untouched) and hand back a
        :class:`HTTPListenStream` positioned just after the server's ack frame.
        """
        headers = self._headers()
        request = listen_request
        if self._modern:
            request, extra = self._modern_envelope(listen_request)
            headers.update(extra)
        elif protocol_version:
            headers[MCP_PROTOCOL_VERSION_HEADER] = protocol_version
        return HTTPListenStream(
            self._url,
            headers,
            request,
            ack_timeout=ack_timeout,
            connect_timeout=self._timeout,
        )

    @staticmethod
    def _iter_messages(content_type: str, body: str) -> Iterator[Dict[str, Any]]:
        # Real servers frame SSE with CRLF (event: message\r\ndata: ...\r\n\r\n);
        # normalize so frame/line splitting works regardless of line endings.
        text = body.replace("\r\n", "\n").strip()
        if not text:
            return
        if "text/event-stream" in content_type:
            for block in text.split("\n\n"):
                payload = "\n".join(
                    line[len("data:"):].lstrip()
                    for line in block.splitlines()
                    if line.startswith("data:")
                )
                if not payload:
                    continue
                try:
                    yield json.loads(payload)
                except ValueError:
                    continue
        else:
            obj = json.loads(text)
            if isinstance(obj, list):
                for item in obj:
                    yield item
            else:
                yield obj


# Sentinels distinguishing "nothing arrived within the timeout" (idle) from
# "the server closed the stream" (eof), neither of which is a frame.
_IDLE = object()
_EOF = object()


class HTTPListenStream(ListenStream):
    """A live ``subscriptions/listen`` stream read off a long-lived SSE POST.

    The 2026-07-28 stream is: the server's ack frame
    (``notifications/subscriptions/acknowledged``), then change-notification
    frames as they happen, then — on a graceful close only — the JSON-RPC
    *result* for the listen request. We read frames incrementally with
    ``http.client`` (which decodes chunked transfer-encoding for us) and use a
    per-read socket timeout to tell "no events yet" from "connection dropped".

    Any deviation from that contract — a non-200 status, a non-SSE body, no ack,
    an error frame, or a drop before the ack — raises
    :class:`HTTPTransportError`, so the probe can report *inconclusive* rather
    than mistake a broken stream for "no notifications".
    """

    def __init__(
        self,
        url: str,
        headers: Dict[str, str],
        listen_request: Dict[str, Any],
        *,
        ack_timeout: float,
        connect_timeout: float,
    ):
        parts = urlsplit(url)
        host = parts.hostname or "127.0.0.1"
        https = parts.scheme == "https"
        port = parts.port or (443 if https else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        self._request_id = listen_request.get("id")
        self._buf = b""
        self._closed = False
        try:
            if https:
                context = ssl.create_default_context()
                self._conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                    host, port, timeout=connect_timeout, context=context
                )
            else:
                self._conn = http.client.HTTPConnection(
                    host, port, timeout=connect_timeout
                )
            body = json.dumps(listen_request).encode("utf-8")
            send_headers = dict(headers)
            send_headers.setdefault("Content-Type", "application/json")
            send_headers.setdefault("Accept", "application/json, text/event-stream")
            self._conn.request("POST", path, body=body, headers=send_headers)
            self._resp = self._conn.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            self.close()
            raise HTTPTransportError(f"could not open subscriptions/listen on {url}: {exc}")

        if self._resp.status != 200:
            detail = self._resp.read(500).decode("utf-8", "replace")
            self.close()
            raise HTTPTransportError(
                f"subscriptions/listen returned HTTP {self._resp.status}: {detail}"
            )
        content_type = self._resp.getheader("Content-Type", "") or ""
        if "text/event-stream" not in content_type.lower():
            detail = self._resp.read(500).decode("utf-8", "replace")
            self.close()
            raise HTTPTransportError(
                f"subscriptions/listen did not return an SSE stream "
                f"(Content-Type {content_type!r}); body: {detail!r}"
            )
        self.honored = self._await_ack(ack_timeout)

    # -- reading ---------------------------------------------------------

    def _read_some(self, timeout: float) -> Optional[bytes]:
        """Pull the next available bytes. ``None`` = idle (timed out); ``b""`` = EOF."""
        sock = self._conn.sock
        if sock is not None:
            sock.settimeout(max(timeout, 0.0))
        try:
            return self._resp.read1(4096)
        except (socket.timeout, TimeoutError):
            return None
        except (OSError, http.client.HTTPException):
            return b""

    def _next_frame(self, timeout: float) -> Any:
        """Next JSON-RPC frame as a dict, or ``_IDLE`` / ``_EOF``.

        SSE frames are separated by a blank line; within a frame we keep only
        the ``data:`` payload, so comment/keepalive lines and empty priming
        frames are skipped transparently.
        """
        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            frame = self._take_buffered_frame()
            if frame is not None:
                parsed = self._parse_frame(frame)
                if parsed is not None:
                    return parsed
                continue  # keepalive / priming / unparseable: keep reading
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _IDLE
            chunk = self._read_some(remaining)
            if chunk is None:
                return _IDLE
            if chunk == b"":
                # Flush any trailing buffered frame before declaring EOF.
                frame = self._take_buffered_frame(final=True)
                if frame is not None:
                    parsed = self._parse_frame(frame)
                    if parsed is not None:
                        return parsed
                return _EOF
            self._buf += chunk.replace(b"\r\n", b"\n")

    def _take_buffered_frame(self, final: bool = False) -> Optional[bytes]:
        sep = self._buf.find(b"\n\n")
        if sep >= 0:
            frame = self._buf[:sep]
            self._buf = self._buf[sep + 2:]
            return frame
        if final and self._buf.strip():
            frame = self._buf
            self._buf = b""
            return frame
        return None

    @staticmethod
    def _parse_frame(frame: bytes) -> Optional[Dict[str, Any]]:
        data_lines = [
            line[len(b"data:"):].lstrip()
            for line in frame.split(b"\n")
            if line.startswith(b"data:")
        ]
        if not data_lines:
            return None
        payload = b"\n".join(data_lines).strip()
        if not payload:
            return None
        try:
            obj = json.loads(payload)
        except ValueError:
            return None
        return obj if isinstance(obj, dict) else None

    def _await_ack(self, timeout: float) -> Dict[str, Any]:
        frame = self._next_frame(timeout)
        if frame is _IDLE:
            self.close()
            raise HTTPTransportError(
                "timed out waiting for the subscriptions/listen acknowledgment"
            )
        if frame is _EOF:
            self.close()
            raise HTTPTransportError(
                "subscriptions/listen stream closed before acknowledgment"
            )
        if "error" in frame:
            self.close()
            raise HTTPTransportError(
                f"subscriptions/listen returned an error: {frame['error']}"
            )
        if frame.get("method") != LISTEN_ACK_METHOD:
            self.close()
            raise HTTPTransportError(
                f"first subscriptions/listen frame was not an acknowledgment: {frame!r}"
            )
        params = frame.get("params") or {}
        honored = params.get("notifications")
        return honored if isinstance(honored, dict) else {}

    def drain_events(self, idle_timeout: float) -> List[Dict[str, Any]]:
        """Event frames pushed on the stream, up to an ``idle_timeout`` gap.

        Stops at the first idle gap, at EOF, or when the server sends the
        graceful-close result. Only change-notification frames are returned;
        the ack and any keepalives are not events.
        """
        events: List[Dict[str, Any]] = []
        while True:
            frame = self._next_frame(idle_timeout)
            if frame is _IDLE or frame is _EOF:
                break
            if "result" in frame or "error" in frame:
                break  # the graceful-close result (or a late error) ends the stream
            if frame.get("method") in LISTEN_EVENT_METHODS:
                events.append(frame)
        return events

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        resp = getattr(self, "_resp", None)
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
        conn = getattr(self, "_conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
