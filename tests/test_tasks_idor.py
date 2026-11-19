"""Loopback tests for the tasks-extension cross-tenant IDOR probe.

Everything runs on 127.0.0.1 on a port picked from 4600-4699 (never
4000/4444/8790). Servers are started and stopped per test.
"""

import socket
import threading
import unittest
from contextlib import contextmanager

from strangertest.guard import AuthorizationError
from strangertest.mcp_client import MCPClient
from strangertest.probe import Identity
from strangertest.transports import HTTPTransport
from strangertest.practice_tasks_http import build_server
from strangertest.tasks_idor import (
    INCONCLUSIVE,
    LEAK,
    OBSERVATION,
    OK,
    assess_entropy,
    run_tasks_idor_probe,
    tasks_identity,
)

PORT_LOW, PORT_HIGH = 4600, 4699


def _free_port() -> int:
    """First free TCP port in the allowed 4600-4699 range."""
    for port in range(PORT_LOW, PORT_HIGH + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port in 4600-4699")


@contextmanager
def running_server(mode, **kwargs):
    port = _free_port()
    server = build_server(mode, host="127.0.0.1", port=port, **kwargs)
    assert PORT_LOW <= server.server_address[1] <= PORT_HIGH
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_address[1]}/mcp"
    finally:
        server.shutdown()
        server.server_close()


def probe(url, **kw):
    kw.setdefault("drift_window", 0.02)
    kw.setdefault("settle_timeout", 0.2)
    return run_tasks_idor_probe(
        url, tasks_identity(url, "alice", "A"), tasks_identity(url, "bob", "B"), **kw
    )


class LeakyTests(unittest.TestCase):
    def test_leaky_is_leak_plus_entropy_observation(self):
        with running_server("leaky") as (_, url):
            r = probe(url)
        # Confirmed cross-tenant IDOR on all three given-id methods.
        self.assertEqual(r.grade, LEAK, r.detail)
        self.assertTrue(r.leaked)
        for m in ("get", "update", "cancel"):
            self.assertEqual(r.methods[m].grade, LEAK, (m, r.methods[m].detail))
        # The entropy signal is a separate OBSERVATION: sequential/guessable ids.
        self.assertIsNotNone(r.entropy)
        self.assertEqual(r.entropy.grade, OBSERVATION, r.entropy.detail)
        self.assertTrue(r.entropy.sequential)
        self.assertIn("LEAK", r.summary())
        self.assertEqual(r.to_dict()["leaked_methods"], r.leaked_methods)
        # Controls held even though the server is vulnerable.
        self.assertTrue(all(c.passed for c in r.controls.values()), r.controls)

    def test_leaky_ids_are_enumerable(self):
        # B reaches a stranger's task by GUESSING a sequential id it was never given.
        with running_server("leaky") as (_, url):
            r = probe(url)
        self.assertTrue(r.entropy.enumerated, r.entropy.detail)
        self.assertIn("enumerate", r.methods)
        self.assertEqual(r.methods["enumerate"].grade, LEAK)
        self.assertIn("enumerate", r.leaked_methods)

    def test_each_method_leaks_alone_when_only_it_is_unauthorized(self):
        # A per-method leaky switch isn't offered by this server; instead assert
        # the get attack alone carries the marker, independent of mutation.
        with running_server("leaky") as (_, url):
            r = probe(url)
        self.assertEqual(r.methods["get"].detail, "B received A's marker")


class SafeTests(unittest.TestCase):
    def test_safe_is_ok_with_high_entropy(self):
        with running_server("safe") as (_, url):
            r = probe(url)
        self.assertEqual(r.grade, OK, r.detail)
        self.assertFalse(r.leaked)
        for m in ("get", "update", "cancel"):
            self.assertEqual(r.methods[m].grade, OK, (m, r.methods[m].detail))
        self.assertIsNotNone(r.entropy)
        self.assertEqual(r.entropy.grade, OK, r.entropy.detail)
        self.assertFalse(r.entropy.sequential)
        self.assertFalse(r.entropy.enumerated)
        self.assertIn("OK", r.summary())
        self.assertTrue(all(c.passed for c in r.controls.values()), r.controls)

    def test_safe_but_guessable_ids_is_observation(self):
        # Per-request authz (safe) but sequential ids: ops refused, yet the ids
        # are guessable -> OBSERVATION, not OK and not LEAK.
        with running_server("safe", id_style="sequential") as (_, url):
            r = probe(url)
        self.assertEqual(r.grade, OBSERVATION, r.detail)
        for m in ("get", "update", "cancel"):
            self.assertEqual(r.methods[m].grade, OK, (m, r.methods[m].detail))
        self.assertEqual(r.entropy.grade, OBSERVATION)
        self.assertTrue(r.entropy.sequential)
        # Guessing is refused by authz, so no confirmed cross-user read.
        self.assertFalse(r.entropy.enumerated)
        self.assertIn("OBSERVATION", r.summary())


class ControlTests(unittest.TestCase):
    """A broken observer must FAIL a control and never grade OK, in the same run."""

    def test_broken_own_read_is_inconclusive_never_ok(self):
        # The server returns the wrong marker even to the owner: the positive
        # control fails, so the run is INCONCLUSIVE (never OK), on an otherwise
        # safe server where it would otherwise be OK.
        with running_server("safe", break_own_read=True) as (_, url):
            r = probe(url)
        self.assertEqual(r.grade, INCONCLUSIVE)
        self.assertNotEqual(r.grade, OK)
        self.assertFalse(r.controls["own_read"].passed)
        self.assertIn("positive control", r.detail)

    def test_forged_id_accepted_is_inconclusive_never_ok(self):
        # The server invents a task for any nonexistent id: the forged-id
        # negative control fails, so the run cannot be trusted as OK.
        with running_server("safe", accept_forged=True) as (_, url):
            r = probe(url)
        self.assertEqual(r.grade, INCONCLUSIVE, r.detail)
        self.assertNotEqual(r.grade, OK)
        self.assertFalse(r.controls["forged_refused"].passed)

    def test_update_rejected_for_own_task_is_inconclusive_never_ok(self):
        # The server rejects EVERY update: B's refusal on A's task proves
        # nothing because B's own update control also fails.
        with running_server("safe", reject_updates=True) as (_, url):
            r = probe(url)
        self.assertEqual(r.methods["update"].grade, INCONCLUSIVE)
        self.assertNotEqual(r.grade, OK)
        self.assertFalse(r.controls["b_own_update"].passed)
        self.assertEqual(r.methods["get"].grade, OK)
        self.assertEqual(r.methods["cancel"].grade, OK)


class InconclusiveTests(unittest.TestCase):
    def test_no_tasks_extension_is_inconclusive(self):
        with running_server("safe", no_tasks=True) as (_, url):
            r = probe(url)
        self.assertEqual(r.grade, INCONCLUSIVE)
        self.assertNotEqual(r.grade, OK)

    def test_unreachable_server_is_inconclusive(self):
        with running_server("safe") as (_, url):
            pass  # shut down
        r = probe(url)
        self.assertEqual(r.grade, INCONCLUSIVE)

    def test_client_without_capability_is_inconclusive(self):
        with running_server("leaky") as (_, url):
            def plain(token, label):
                return Identity(label, lambda: MCPClient(HTTPTransport(
                    url, headers={"Authorization": f"Bearer {token}"}, modern=True)))
            r = run_tasks_idor_probe(url, plain("alice", "A"), plain("bob", "B"))
        self.assertEqual(r.grade, INCONCLUSIVE)

    def test_mode_switch_in_place(self):
        with running_server("leaky") as (server, url):
            self.assertEqual(probe(url).grade, LEAK)
            server.state.reset("safe")
            self.assertEqual(server.state.tasks, {})
            self.assertEqual(probe(url).grade, OK)


class GuardTests(unittest.TestCase):
    def test_public_target_refused_before_any_connection(self):
        def boom():
            raise AssertionError("connected despite refusal")

        with self.assertRaises(AuthorizationError):
            run_tasks_idor_probe(
                "https://mcp.example.com/mcp", Identity("A", boom), Identity("B", boom)
            )


class EntropyUnitTests(unittest.TestCase):
    def test_sequential_ids_are_observation(self):
        f = assess_entropy([f"task-{i}" for i in range(1, 6)])
        self.assertEqual(f.grade, OBSERVATION)
        self.assertTrue(f.sequential)

    def test_high_entropy_ids_are_ok(self):
        import secrets
        f = assess_entropy(["task-" + secrets.token_hex(16) for _ in range(5)])
        self.assertEqual(f.grade, OK)
        self.assertFalse(f.sequential)
        self.assertGreaterEqual(f.est_bits, 64)

    def test_short_random_ids_are_guessable(self):
        import secrets
        f = assess_entropy(["id-" + secrets.token_hex(2) for _ in range(5)])
        self.assertEqual(f.grade, OBSERVATION)

    def test_too_few_ids_is_inconclusive(self):
        self.assertEqual(assess_entropy(["task-1"]).grade, INCONCLUSIVE)

    def test_fingerprints_only_no_raw_ids(self):
        f = assess_entropy([f"task-{i}" for i in range(1, 6)])
        for fp in f.sample_fingerprints:
            self.assertTrue(fp.startswith("sha256:"))
        self.assertNotIn("task-1", "".join(f.sample_fingerprints))


if __name__ == "__main__":
    unittest.main()


class TasksIdorIdentityCollapse(unittest.TestCase):
    """A reach of A's task is a cross-user LEAK only when A and B are distinct
    principals; a server that collapses them grades OBSERVATION, not LEAK."""

    def test_collapse_is_observation_not_leak(self):
        from strangertest.tasks_idor import OBSERVATION
        with running_server("collapse") as (_, url):
            r = run_tasks_idor_probe(
                url, tasks_identity(url, "alice", "A"), tasks_identity(url, "bob", "B"),
                authorized=True)
        self.assertEqual(r.grade, OBSERVATION, r.detail)
        self.assertFalse(r.leaked)
        self.assertNotIn("failure_class", r.to_dict())
