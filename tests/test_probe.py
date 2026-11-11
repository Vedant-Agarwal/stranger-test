import unittest

from strangertest.guard import AuthorizationError
from strangertest.mcp_client import MCPClient, Transport
from strangertest.probe import (
    FAILURE_CLASS,
    Identity,
    ProbeError,
    ProbePlan,
    ProbeReport,
    new_marker,
    run_probe,
)


class MemoryServer:
    """A tiny in-memory key/value MCP server for tests.

    With ``shared=True`` every identity reads and writes the same store (a
    leaking, confused-deputy server). With ``shared=False`` each identity gets
    its own store (a correctly-isolated server).
    """

    def __init__(self, shared: bool, plant_errors: bool = False):
        self.shared = shared
        self.plant_errors = plant_errors
        self._stores = {}

    def _store(self, identity_id):
        namespace = "shared" if self.shared else identity_id
        return self._stores.setdefault(namespace, {})

    def handle(self, identity_id, message):
        method = message["method"]
        if method == "initialize":
            return {"result": {"protocolVersion": "2025-06-18",
                               "serverInfo": {"name": "memory"},
                               "capabilities": {"tools": {}}}}
        if method == "tools/list":
            return {"result": {"tools": [{"name": "kv_set"}, {"name": "kv_get"}]}}
        if method == "tools/call":
            params = message["params"]
            name = params["name"]
            args = params.get("arguments", {})
            store = self._store(identity_id)
            if name == "kv_set":
                if self.plant_errors:
                    return {"result": {"isError": True, "content": [
                        {"type": "text", "text": "unexpected keyword argument"}]}}
                store[args["key"]] = args["value"]
                return {"result": {"content": [{"type": "text", "text": "ok"}]}}
            if name == "kv_get":
                value = store.get(args["key"], "")
                return {"result": {"content": [{"type": "text", "text": value}]}}
            return {"error": {"code": -32601, "message": f"unknown tool {name}"}}
        return {"error": {"code": -32601, "message": f"unknown method {method}"}}


class MemoryTransport(Transport):
    def __init__(self, server: MemoryServer, identity_id: str):
        self.server = server
        self.identity_id = identity_id

    def request(self, message):
        resp = self.server.handle(self.identity_id, message)
        resp["jsonrpc"] = "2.0"
        resp["id"] = message.get("id")
        return resp

    def notify(self, message):
        pass


def identity(server, identity_id, label):
    return Identity(label=label, connect=lambda: MCPClient(MemoryTransport(server, identity_id)))


KV_PLAN = ProbePlan.key_value("kv_set", "kv_get", "secret")


class MarkerTests(unittest.TestCase):
    def test_markers_are_unique(self):
        self.assertNotEqual(new_marker(), new_marker())

    def test_marker_prefix(self):
        self.assertTrue(new_marker().startswith("st-marker-"))


class ProbeTests(unittest.TestCase):
    def test_detects_leak_on_shared_server(self):
        server = MemoryServer(shared=True)
        report = run_probe(
            "http://localhost:9000/mcp",
            identity(server, "alice", "A"),
            identity(server, "bob", "B"),
            KV_PLAN,
        )
        self.assertIsInstance(report, ProbeReport)
        self.assertTrue(report.leaked)
        self.assertIn("LEAK", report.summary())
        self.assertEqual(report.to_dict()["failure_class"], FAILURE_CLASS)

    def test_no_leak_on_isolated_server(self):
        server = MemoryServer(shared=False)
        report = run_probe(
            "http://localhost:9000/mcp",
            identity(server, "alice", "A"),
            identity(server, "bob", "B"),
            KV_PLAN,
        )
        self.assertFalse(report.leaked)
        self.assertIn("OK", report.summary())
        self.assertNotIn("failure_class", report.to_dict())

    def test_marker_recorded_in_report(self):
        server = MemoryServer(shared=True)
        report = run_probe(
            "http://localhost:9000/mcp",
            identity(server, "alice", "A"),
            identity(server, "bob", "B"),
            KV_PLAN,
        )
        self.assertTrue(report.marker.startswith("st-marker-"))

    def test_failed_plant_is_inconclusive_not_clean(self):
        # A plant that returns a tool-level error must not be reported as "no
        # leak" (a vector-DB server's argument-name mismatch first bit us here).
        server = MemoryServer(shared=True, plant_errors=True)
        reader_must_not_run = Identity(
            label="B",
            connect=lambda: (_ for _ in ()).throw(AssertionError("B connected after a failed plant")),
        )
        with self.assertRaises(ProbeError) as ctx:
            run_probe(
                "http://localhost:9000/mcp",
                identity(server, "alice", "A"),
                reader_must_not_run,
                KV_PLAN,
            )
        self.assertIn("inconclusive", str(ctx.exception))

    def test_authorization_is_enforced_before_connecting(self):
        def must_not_connect():
            raise AssertionError("probe connected before authorization passed")

        blocked = Identity(label="X", connect=must_not_connect)
        with self.assertRaises(AuthorizationError):
            run_probe(
                "https://mcp.example.com/",
                blocked,
                blocked,
                KV_PLAN,
            )

    def test_authorized_public_target_runs(self):
        server = MemoryServer(shared=False)
        report = run_probe(
            "https://mcp.example.com/",
            identity(server, "alice", "A"),
            identity(server, "bob", "B"),
            KV_PLAN,
            authorized=True,
            authorization_note="owner Jane Doe, email 2026-11-09",
        )
        self.assertIn("Jane Doe", report.authorization)
        self.assertFalse(report.leaked)


if __name__ == "__main__":
    unittest.main()
