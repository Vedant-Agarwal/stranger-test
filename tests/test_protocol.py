import unittest

from strangertest.mcp_client import MCP_PROTOCOL_VERSION, MCPClient, Transport


class _OneShotTransport(Transport):
    def __init__(self, server_version):
        self.server_version = server_version
        self.requests = []

    def request(self, message):
        self.requests.append(message)
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "protocolVersion": self.server_version,
                "serverInfo": {"name": "x"},
                "capabilities": {},
            },
        }

    def notify(self, message):
        pass


class ProtocolVersionTests(unittest.TestCase):
    def test_client_advertises_2026_07_28(self):
        self.assertEqual(MCP_PROTOCOL_VERSION, "2026-07-28")
        transport = _OneShotTransport("2026-07-28")
        MCPClient(transport).initialize()
        self.assertEqual(
            transport.requests[0]["params"]["protocolVersion"], "2026-07-28"
        )

    def test_records_server_negotiated_version(self):
        transport = _OneShotTransport("2025-06-18")
        client = MCPClient(transport)
        client.initialize()
        self.assertEqual(client.protocol_version, "2025-06-18")


if __name__ == "__main__":
    unittest.main()
