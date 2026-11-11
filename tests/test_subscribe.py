import unittest

from strangertest.mcp_client import ListenStream, MCPClient, Transport
from strangertest.probe import Identity, ProbeError
from strangertest.subscribe import SubscriptionReport, run_subscription_probe

A_URI = "note://alice/secret"


def _result(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


class _InProcessStream(ListenStream):
    """A fake listen stream: events the server fans out land straight in it."""

    def __init__(self, honored):
        self.honored = honored
        self._inbox = []

    def deliver(self, frame):
        self._inbox.append(frame)

    def drain_events(self, idle_timeout):
        out = self._inbox[:]
        self._inbox.clear()
        return out


class NotifyingServer:
    """In-process server shared by all identities.

    Leaky mode delivers one identity's resource update to ANY subscriber of that
    URI; safe mode delivers only to the resource's owner. Streams are opened
    before any change, mirroring the real no-replay channel.
    """

    def __init__(self, leaky, protocol_version="2026-07-28"):
        self.leaky = leaky
        self.protocol_version = protocol_version
        self.subs = []  # (identity_id, uris, stream)
        self.owner = {}  # uri -> identity_id

    def handle(self, transport, msg):
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            return _result(mid, {
                "protocolVersion": self.protocol_version,
                "serverInfo": {"name": "notify"},
                "capabilities": {"resources": {}},
            })
        if method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            if name == "set_resource":
                uri = args["uri"]
                self.owner.setdefault(uri, transport.identity_id)
                self._fanout(uri)
                return _result(mid, {"content": [{"type": "text", "text": "ok"}]})
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": f"unknown tool {name}"}}
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"unknown method {method}"}}

    def open_listen(self, transport, listen_request):
        notifications = (listen_request.get("params") or {}).get("notifications") or {}
        uris = list(notifications.get("resourceSubscriptions") or [])
        honored = {"resourceSubscriptions": uris} if uris else {}
        stream = _InProcessStream(honored)
        self.subs.append((transport.identity_id, set(uris), stream))
        return stream

    def _fanout(self, uri):
        owner = self.owner.get(uri)
        frame = {"jsonrpc": "2.0", "method": "notifications/resources/updated",
                 "params": {"uri": uri}}
        for identity_id, uris, stream in self.subs:
            if uri not in uris:
                continue
            if self.leaky or identity_id == owner:
                stream.deliver(dict(frame))


class NotifyingTransport(Transport):
    def __init__(self, server, identity_id):
        self.server = server
        self.identity_id = identity_id

    def request(self, message):
        return self.server.handle(self, message)

    def notify(self, message):
        pass

    def open_listen(self, listen_request, *, protocol_version=None, ack_timeout=10.0):
        return self.server.open_listen(self, listen_request)


def _identity(server, identity_id, label):
    return Identity(
        label=label,
        connect=lambda: MCPClient(NotifyingTransport(server, identity_id)),
    )


def _change(client):
    client.call_tool("set_resource", {"uri": A_URI, "value": "x"})


class SubscriptionProbeTests(unittest.TestCase):
    def test_leak_on_shared_subscription(self):
        server = NotifyingServer(leaky=True)
        report = run_subscription_probe(
            "http://localhost/practice",
            _identity(server, "alice", "A"),
            _identity(server, "bob", "B"),
            resource_uri=A_URI,
            change=_change,
        )
        self.assertIsInstance(report, SubscriptionReport)
        self.assertTrue(report.leaked)
        self.assertIn("LEAK", report.summary())
        self.assertEqual(
            report.to_dict()["failure_class"],
            "cross-identity subscription/notification leak",
        )

    def test_no_leak_when_scoped(self):
        server = NotifyingServer(leaky=False)
        report = run_subscription_probe(
            "http://localhost/practice",
            _identity(server, "alice", "A"),
            _identity(server, "bob", "B"),
            resource_uri=A_URI,
            change=_change,
        )
        self.assertFalse(report.leaked)
        self.assertIn("OK", report.summary())
        self.assertNotIn("failure_class", report.to_dict())

    def test_pre_2026_server_is_inconclusive(self):
        # subscriptions/listen does not exist before 2026-07-28; the probe must
        # say inconclusive, never "no leak".
        server = NotifyingServer(leaky=True, protocol_version="2025-06-18")
        with self.assertRaises(ProbeError):
            run_subscription_probe(
                "http://localhost/practice",
                _identity(server, "alice", "A"),
                _identity(server, "bob", "B"),
                resource_uri=A_URI,
                change=_change,
            )

    def test_authorization_enforced_before_connecting(self):
        def must_not_connect():
            raise AssertionError("connected before authorization passed")

        blocked = Identity(label="X", connect=must_not_connect)
        with self.assertRaises(Exception):
            run_subscription_probe(
                "https://mcp.example.com/",
                blocked,
                blocked,
                resource_uri=A_URI,
                change=_change,
            )


if __name__ == "__main__":
    unittest.main()
