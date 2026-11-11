import threading
import unittest
from contextlib import contextmanager

from strangertest.mcp_client import MCPClient
from strangertest.practice_http import build_server
from strangertest.probe import Identity, ProbeError
from strangertest.subscribe import run_subscription_probe
from strangertest.transports import HTTPTransport

A_URI = "note://alice/secret"
B_URI = "note://bob/own"


@contextmanager
def running_server(mode, fail_listen=False):
    server = build_server(mode, fail_listen=fail_listen)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.shutdown()
        server.server_close()


def _identity(url, token, label):
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {token}"})
        ),
    )


def _change(uri):
    return lambda client: client.call_tool("set_resource", {"uri": uri, "value": "x"})


class SubscriptionOverHTTPTests(unittest.TestCase):
    def test_positive_control_owner_sees_own_update(self):
        # If this fails, the observer is broken and any "no leak" is meaningless.
        # No replay: open and acknowledge the stream BEFORE the change.
        for mode in ("leaky", "safe"):
            with running_server(mode) as url:
                client = MCPClient(
                    HTTPTransport(url, headers={"Authorization": "Bearer bob"})
                )
                client.initialize()
                with client.listen(resource_subscriptions=[B_URI]) as stream:
                    self.assertEqual(stream.honored.get("resourceSubscriptions"), [B_URI])
                    client.call_tool("set_resource", {"uri": B_URI, "value": "x"})
                    events = stream.drain_events(idle_timeout=2.0)
                self.assertTrue(
                    any(
                        e.get("params", {}).get("uri") == B_URI
                        for e in events
                    ),
                    f"owner did not receive its own update in {mode} mode: {events!r}",
                )
                client.close()

    def test_leak_detected_over_http(self):
        with running_server("leaky") as url:
            report = run_subscription_probe(
                url,
                _identity(url, "alice", "A"),
                _identity(url, "bob", "B"),
                resource_uri=A_URI,
                change=_change(A_URI),
            )
        self.assertTrue(report.leaked)
        self.assertIn("LEAK", report.summary())

    def test_listen_failure_is_inconclusive(self):
        # A broken/unexpected listen must NOT be reported as "no leak".
        with running_server("leaky", fail_listen=True) as url:
            with self.assertRaises(ProbeError):
                run_subscription_probe(
                    url,
                    _identity(url, "alice", "A"),
                    _identity(url, "bob", "B"),
                    resource_uri=A_URI,
                    change=_change(A_URI),
                )

    def test_no_leak_when_scoped_over_http(self):
        with running_server("safe") as url:
            report = run_subscription_probe(
                url,
                _identity(url, "alice", "A"),
                _identity(url, "bob", "B"),
                resource_uri=A_URI,
                change=_change(A_URI),
            )
        self.assertFalse(report.leaked)
        self.assertIn("OK", report.summary())


if __name__ == "__main__":
    unittest.main()
