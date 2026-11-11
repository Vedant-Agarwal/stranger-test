"""A small MCP (Model Context Protocol) client over JSON-RPC 2.0.

Stranger Test connects to an MCP server, performs the ``initialize`` handshake,
and can then list tools/resources and call a tool. The protocol logic here is
transport-agnostic: a :class:`Transport` supplies ``request``/``notify``, so the
same client works over stdio, HTTP, or an in-memory fake in tests.

Nothing in this module reaches the network on its own. Choosing and connecting
to a target is gated by :mod:`strangertest.guard`; this module only speaks the
protocol once a transport has been handed to it.
"""

from __future__ import annotations

import itertools
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Sequence

JSONRPC_VERSION = "2.0"
# The protocol version the client advertises. 2026-07-28 introduced the
# subscriptions/listen stream that the XID-13 subscription-leak probe needs; we
# still interoperate with older 2025-06-18 servers.
MCP_PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_PROTOCOL_VERSIONS = ("2026-07-28", "2025-06-18")
# subscriptions/listen exists only on 2026-07-28 (SEP-2575). On earlier
# versions the subscription path was resources/subscribe + unsolicited
# notifications, which this client does not speak; the probe reports those
# connections inconclusive rather than guessing.
LISTEN_PROTOCOL_VERSION = "2026-07-28"

# The notification methods that ride a subscriptions/listen stream at
# 2026-07-28, straight from the spec's event vocabulary.
LISTEN_ACK_METHOD = "notifications/subscriptions/acknowledged"
LISTEN_EVENT_METHODS = frozenset(
    {
        "notifications/resources/updated",
        "notifications/resources/list_changed",
        "notifications/tools/list_changed",
        "notifications/prompts/list_changed",
    }
)
# The _meta key every listen-stream frame carries; its value is the listen
# request's JSON-RPC id.
SUBSCRIPTION_ID_META_KEY = "io.modelcontextprotocol/subscriptionId"

# --- the 2026-07-28 "modern" per-request envelope (SEP-2575) ---------------
# The modern era has no initialize handshake and no session: each request is a
# self-contained POST carrying its protocol version and the client's
# capabilities in params._meta, with matching routing headers. These wire
# strings come straight from the reference SDK (mcp_types / mcp.shared.inbound).
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
MCP_PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version"
MCP_METHOD_HEADER = "Mcp-Method"
MCP_NAME_HEADER = "Mcp-Name"
# method -> the params key whose value is mirrored in the Mcp-Name header.
NAME_BEARING_METHODS = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}

__all__ = [
    "JSONRPCError",
    "ListenNotSupportedError",
    "ListenStream",
    "Transport",
    "MCPClient",
    "MCP_PROTOCOL_VERSION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "LISTEN_PROTOCOL_VERSION",
    "LISTEN_ACK_METHOD",
    "LISTEN_EVENT_METHODS",
    "SUBSCRIPTION_ID_META_KEY",
    "build_request",
    "build_notification",
    "parse_result",
]


class JSONRPCError(Exception):
    """A JSON-RPC error object returned by the server."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data


class ListenNotSupportedError(RuntimeError):
    """The negotiated protocol version has no subscriptions/listen stream.

    Raised before any stream is opened when the server negotiated a version
    older than 2026-07-28. The subscription-leak probe turns this into an
    *inconclusive* result (not "no leak"): the probe could not observe this
    server's subscription channel at all, so it makes no claim about it.
    """

    def __init__(self, negotiated_version: Optional[str]):
        self.negotiated_version = negotiated_version
        super().__init__(
            f"subscriptions/listen requires protocol version "
            f"{LISTEN_PROTOCOL_VERSION!r}; the server negotiated "
            f"{negotiated_version!r}. The pre-2026 resources/subscribe path is "
            f"not implemented by this client."
        )


class ListenStream(ABC):
    """One open ``subscriptions/listen`` stream: the server's ack, then events.

    A transport that can carry a server-pushed stream returns one of these from
    :meth:`Transport.open_listen`. Opening it has already waited for the
    server's acknowledgment, so :attr:`honored` — the subset of the requested
    filter the server agreed to deliver — is in hand. :meth:`drain_events` then
    reads whatever the server has pushed, up to an idle gap. There is no replay:
    a change made before the stream was open and acknowledged is never
    delivered, which is why the probe opens the stream *before* identity A acts.
    """

    honored: Dict[str, Any] = {}

    @abstractmethod
    def drain_events(self, idle_timeout: float) -> List[Dict[str, Any]]:
        """Return event frames pushed so far, stopping after ``idle_timeout``
        seconds with nothing new (or when the server closes the stream)."""

    def close(self) -> None:  # optional for subclasses to override
        pass

    def __enter__(self) -> "ListenStream":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def build_request(
    request_id: Any, method: str, params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    msg: Dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "id": request_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def build_notification(
    method: str, params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    msg: Dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def parse_result(response: Dict[str, Any]) -> Any:
    """Return the ``result`` from a JSON-RPC response, or raise JSONRPCError."""
    if response.get("error") is not None:
        err = response["error"]
        raise JSONRPCError(err.get("code", 0), err.get("message", ""), err.get("data"))
    if "result" not in response:
        raise JSONRPCError(0, f"Response has neither result nor error: {response!r}")
    return response["result"]


class Transport(ABC):
    """How an :class:`MCPClient` moves messages to and from a server."""

    @abstractmethod
    def request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Send a request message and return the parsed response message."""

    @abstractmethod
    def notify(self, message: Dict[str, Any]) -> None:
        """Send a notification message; no response is expected."""

    def close(self) -> None:  # optional for subclasses to override
        pass

    def open_listen(
        self,
        listen_request: Dict[str, Any],
        *,
        protocol_version: Optional[str] = None,
        ack_timeout: float = 10.0,
    ) -> ListenStream:
        """Open a ``subscriptions/listen`` stream and wait for the server's ack.

        Transports that can carry a server-pushed stream override this. The
        default raises, so the subscription-leak probe reports *inconclusive*
        for a transport that cannot observe the subscription channel.
        """
        raise NotImplementedError(
            "this transport does not support subscriptions/listen streams"
        )


class MCPClient:
    """Speaks MCP over a given transport.

    Call :meth:`initialize` once, then :meth:`list_tools`, :meth:`call_tool`,
    :meth:`list_resources`, :meth:`read_resource`.
    """

    def __init__(
        self,
        transport: Transport,
        *,
        client_name: str = "stranger-test",
        client_version: str = "0.0.0",
    ):
        self._transport = transport
        self._ids = itertools.count(1)
        self._client_name = client_name
        self._client_version = client_version
        self.initialized = False
        self.protocol_version: Optional[str] = None
        self.server_info: Optional[Dict[str, Any]] = None
        self.server_capabilities: Optional[Dict[str, Any]] = None

    def _call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        message = build_request(next(self._ids), method, params)
        response = self._transport.request(message)
        return parse_result(response)

    def initialize(self) -> Dict[str, Any]:
        result = self._call(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": self._client_name,
                    "version": self._client_version,
                },
            },
        )
        self.server_info = result.get("serverInfo")
        self.server_capabilities = result.get("capabilities")
        self.protocol_version = result.get("protocolVersion") or MCP_PROTOCOL_VERSION
        self._transport.notify(build_notification("notifications/initialized"))
        self.initialized = True
        return result

    def list_tools(self) -> List[Dict[str, Any]]:
        return self._call("tools/list").get("tools", [])

    def call_tool(
        self, name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return self._call("tools/call", {"name": name, "arguments": arguments or {}})

    def list_resources(self) -> List[Dict[str, Any]]:
        return self._call("resources/list").get("resources", [])

    def read_resource(self, uri: str) -> Dict[str, Any]:
        return self._call("resources/read", {"uri": uri})

    def listen(
        self,
        *,
        resource_subscriptions: Sequence[str] = (),
        tools_list_changed: bool = False,
        prompts_list_changed: bool = False,
        resources_list_changed: bool = False,
        ack_timeout: float = 10.0,
    ) -> ListenStream:
        """Open a ``subscriptions/listen`` stream (2026-07-28 only).

        Returns once the server has acknowledged the subscription, so the
        returned stream's ``honored`` filter is already populated. Raises
        :class:`ListenNotSupportedError` if the negotiated version predates
        2026-07-28, before any network call.
        """
        if isinstance(resource_subscriptions, str):
            raise TypeError(
                "resource_subscriptions takes a sequence of URIs, not a bare string"
            )
        if self.protocol_version != LISTEN_PROTOCOL_VERSION:
            raise ListenNotSupportedError(self.protocol_version)
        notifications: Dict[str, Any] = {}
        if tools_list_changed:
            notifications["toolsListChanged"] = True
        if prompts_list_changed:
            notifications["promptsListChanged"] = True
        if resources_list_changed:
            notifications["resourcesListChanged"] = True
        if resource_subscriptions:
            notifications["resourceSubscriptions"] = list(resource_subscriptions)
        request = build_request(
            f"listen-{next(self._ids)}",
            "subscriptions/listen",
            {"notifications": notifications},
        )
        return self._transport.open_listen(
            request,
            protocol_version=self.protocol_version,
            ack_timeout=ack_timeout,
        )

    def close(self) -> None:
        self._transport.close()
