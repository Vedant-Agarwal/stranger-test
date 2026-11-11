import unittest

from strangertest.mcp_client import (
    JSONRPCError,
    MCPClient,
    Transport,
    build_notification,
    build_request,
    parse_result,
)


class FakeTransport(Transport):
    """A transport that returns canned results keyed by method name.

    A canned value that is already a full JSON-RPC response (has ``result`` or
    ``error``) is returned as-is; anything else is wrapped as a ``result``.
    """

    def __init__(self, responses):
        self.responses = responses
        self.requests = []
        self.notifications = []

    def request(self, message):
        self.requests.append(message)
        payload = self.responses[message["method"]]
        if isinstance(payload, dict) and ("result" in payload or "error" in payload):
            resp = dict(payload)
            resp["jsonrpc"] = "2.0"
            resp["id"] = message.get("id")
            return resp
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": payload}

    def notify(self, message):
        self.notifications.append(message)


class BuildMessageTests(unittest.TestCase):
    def test_request_shape(self):
        msg = build_request(7, "tools/list")
        self.assertEqual(msg["jsonrpc"], "2.0")
        self.assertEqual(msg["id"], 7)
        self.assertEqual(msg["method"], "tools/list")
        self.assertNotIn("params", msg)

    def test_request_with_params(self):
        msg = build_request(1, "tools/call", {"name": "x"})
        self.assertEqual(msg["params"], {"name": "x"})

    def test_notification_has_no_id(self):
        msg = build_notification("notifications/initialized")
        self.assertNotIn("id", msg)
        self.assertEqual(msg["method"], "notifications/initialized")


class ParseResultTests(unittest.TestCase):
    def test_returns_result(self):
        self.assertEqual(parse_result({"result": {"ok": True}}), {"ok": True})

    def test_raises_on_error(self):
        with self.assertRaises(JSONRPCError) as ctx:
            parse_result({"error": {"code": -32601, "message": "Method not found"}})
        self.assertEqual(ctx.exception.code, -32601)

    def test_raises_when_neither(self):
        with self.assertRaises(JSONRPCError):
            parse_result({"jsonrpc": "2.0", "id": 1})


class MCPClientTests(unittest.TestCase):
    def _client(self, responses):
        transport = FakeTransport(responses)
        return MCPClient(transport), transport

    def test_initialize_handshake(self):
        client, transport = self._client(
            {
                "initialize": {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": "demo", "version": "1.0"},
                    "capabilities": {"tools": {}},
                }
            }
        )
        result = client.initialize()
        self.assertTrue(client.initialized)
        self.assertEqual(client.server_info, {"name": "demo", "version": "1.0"})
        self.assertEqual(result["protocolVersion"], "2025-06-18")
        # The initialize request carried our client info and protocol version.
        req = transport.requests[0]
        self.assertEqual(req["method"], "initialize")
        self.assertEqual(req["params"]["clientInfo"]["name"], "stranger-test")
        self.assertIn("protocolVersion", req["params"])
        # And we sent the initialized notification afterwards.
        self.assertEqual(
            transport.notifications[0]["method"], "notifications/initialized"
        )

    def test_list_tools(self):
        client, _ = self._client(
            {"tools/list": {"tools": [{"name": "a"}, {"name": "b"}]}}
        )
        self.assertEqual([t["name"] for t in client.list_tools()], ["a", "b"])

    def test_list_tools_defaults_empty(self):
        client, _ = self._client({"tools/list": {}})
        self.assertEqual(client.list_tools(), [])

    def test_call_tool_builds_params(self):
        client, transport = self._client({"tools/call": {"content": []}})
        client.call_tool("search", {"q": "hi"})
        req = transport.requests[0]
        self.assertEqual(req["method"], "tools/call")
        self.assertEqual(req["params"], {"name": "search", "arguments": {"q": "hi"}})

    def test_call_tool_defaults_empty_arguments(self):
        client, transport = self._client({"tools/call": {"content": []}})
        client.call_tool("ping")
        self.assertEqual(transport.requests[0]["params"]["arguments"], {})

    def test_read_resource(self):
        client, transport = self._client(
            {"resources/read": {"contents": [{"uri": "mem://x", "text": "hi"}]}}
        )
        out = client.read_resource("mem://x")
        self.assertEqual(out["contents"][0]["text"], "hi")
        self.assertEqual(transport.requests[0]["params"], {"uri": "mem://x"})

    def test_server_error_propagates(self):
        client, _ = self._client(
            {"tools/list": {"error": {"code": -32000, "message": "boom"}}}
        )
        with self.assertRaises(JSONRPCError):
            client.list_tools()

    def test_ids_increment(self):
        client, transport = self._client(
            {"tools/list": {"tools": []}, "resources/list": {"resources": []}}
        )
        client.list_tools()
        client.list_resources()
        self.assertEqual(transport.requests[0]["id"], 1)
        self.assertEqual(transport.requests[1]["id"], 2)


if __name__ == "__main__":
    unittest.main()
