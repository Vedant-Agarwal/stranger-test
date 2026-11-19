"""Loopback tests for the subscriptions/listen notification-leak probe.

Real HTTP servers on 127.0.0.1, ports 4600-4699 only (never 4000/4444/8790).
Every server is shut down and every listen stream closed before the test ends.
Fingerprints only: the report carries a sha256 marker fingerprint, never the
raw resource URI.
"""

import socket
import threading
import unittest
from contextlib import contextmanager

from strangertest.mcp_client import MCPClient
from strangertest.practice_subscriptions_http import build_server
from strangertest.probe import Identity
from strangertest.subscriptions_leak import (
    INCONCLUSIVE,
    LEAK,
    OK,
    run_subscriptions_leak_probe,
)
from strangertest.transports import HTTPTransport

A_URI = "note://alice/private-secret"
B_URI = "note://bob/own-note"

PORT_LOW, PORT_HIGH = 4600, 4699


def _free_port() -> int:
    """A free TCP port on 127.0.0.1 within the allowed 4600-4699 window."""
    for port in range(PORT_LOW, PORT_HIGH + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port available in 4600-4699")


@contextmanager
def running_server(mode, fail_listen=False):
    server = build_server(mode, host="127.0.0.1", port=_free_port(), fail_listen=fail_listen)
    port = server.server_address[1]
    assert PORT_LOW <= port <= PORT_HIGH, f"port {port} outside 4600-4699"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
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


def _set(uri, value):
    def _change(client):
        client.call_tool("set_resource", {"uri": uri, "value": value})

    return _change


def _run(url, *, b_own=True):
    return run_subscriptions_leak_probe(
        url,
        _identity(url, "alice", "A"),
        _identity(url, "bob", "B"),
        resource_uri=A_URI,
        change=_set(A_URI, "a-value"),
        b_own_uri=B_URI if b_own else None,
        b_change=_set(B_URI, "b-value") if b_own else None,
        idle_timeout=2.0,
    )


class SubscriptionsLeakOverHTTP(unittest.TestCase):
    def test_positive_control_owner_sees_own_update(self):
        # If the observer cannot even see an owner's own update, every "no leak"
        # would be meaningless. Open and acknowledge BEFORE the change (no replay).
        for mode in ("leaky", "safe"):
            with running_server(mode) as url:
                client = MCPClient(
                    HTTPTransport(url, headers={"Authorization": "Bearer alice"})
                )
                client.initialize()
                with client.listen(resource_subscriptions=[A_URI]) as stream:
                    client.call_tool("set_resource", {"uri": A_URI, "value": "x"})
                    events = stream.drain_events(idle_timeout=2.0)
                client.close()
                self.assertTrue(
                    any(e.get("params", {}).get("uri") == A_URI for e in events),
                    f"owner did not receive its own update in {mode} mode: {events!r}",
                )

    def test_leaky_is_leak(self):
        with running_server("leaky") as url:
            report = _run(url)
        self.assertEqual(report.grade, LEAK)
        self.assertTrue(report.leaked)
        self.assertIn("LEAK", report.summary())
        self.assertEqual(
            report.to_dict()["failure_class"],
            "cross-identity subscription/notification delivery leak",
        )
        self.assertTrue(report.controls.get("a_own_stream_fires"))
        # Fingerprints only: the raw URI never appears in the report payload.
        self.assertNotIn(A_URI, repr(report.to_dict()))
        self.assertTrue(report.marker_fingerprint.startswith("sha256:"))

    def test_safe_is_ok_with_broken_control_first(self):
        # REQUIRED: a broken fixture must FAIL the control in the SAME run,
        # before any OK is trusted. The mute server fires no notifications, so
        # A's own-stream control fails -> INCONCLUSIVE.
        with running_server("mute") as url:
            broken = _run(url)
        self.assertEqual(broken.grade, INCONCLUSIVE)
        self.assertFalse(broken.controls.get("a_own_stream_fires"))
        self.assertIn("INCONCLUSIVE", broken.summary())

        # Only now, with the control shown to catch a dead server, trust OK.
        with running_server("safe") as url:
            report = _run(url)
        self.assertEqual(report.grade, OK)
        self.assertFalse(report.leaked)
        self.assertIn("OK", report.summary())
        self.assertNotIn("failure_class", report.to_dict())
        self.assertTrue(report.controls.get("a_own_stream_fires"))
        self.assertTrue(report.controls.get("b_own_stream_alive"))

    def test_fail_listen_is_inconclusive(self):
        # A listen that returns a JSON error instead of a stream must NOT be
        # read as "no leak".
        with running_server("leaky", fail_listen=True) as url:
            report = _run(url)
        self.assertEqual(report.grade, INCONCLUSIVE)
        self.assertFalse(report.leaked)

    def test_authorization_enforced_before_connecting(self):
        def must_not_connect():
            raise AssertionError("connected before authorization passed")

        blocked = Identity(label="X", connect=must_not_connect)
        with self.assertRaises(Exception):
            run_subscriptions_leak_probe(
                "https://mcp.example.com/",
                blocked,
                blocked,
                resource_uri=A_URI,
                change=_set(A_URI, "x"),
            )


if __name__ == "__main__":
    unittest.main()


class SubscriptionsIdentityCollapse(unittest.TestCase):
    """A cross-stream delivery is a LEAK only when A and B are distinct
    principals; a collapsing server grades OBSERVATION, not LEAK."""

    def test_collapse_is_observation_not_leak(self):
        from strangertest.subscriptions_leak import OBSERVATION
        with running_server("collapse") as url:
            report = _run(url)
        self.assertEqual(report.grade, OBSERVATION, report.detail)
        self.assertFalse(report.leaked)
        self.assertIn("COLLAPSED", report.controls["identities"])
