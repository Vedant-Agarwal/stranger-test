import threading
import unittest
from contextlib import contextmanager

from strangertest.guard import AuthorizationError
from strangertest.handle import (
    INCONCLUSIVE,
    LEAK,
    OK,
    run_handle_probe,
    tasks_identity,
    _contains_exact,
)
from strangertest.mcp_client import JSONRPCError
from strangertest.practice_handle_http import build_server


@contextmanager
def running_server(mode, **kwargs):
    server = build_server(mode, **kwargs)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    finally:
        server.shutdown()
        server.server_close()


def probe(url, **kw):
    # Short windows: the practice server settles in ~50ms.
    kw.setdefault("drift_window", 0.02)
    kw.setdefault("settle_timeout", 0.2)
    return run_handle_probe(
        url, tasks_identity(url, "alice", "A"), tasks_identity(url, "bob", "B"), **kw
    )


class LeakyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._ctx = running_server("leaky")
        cls.url = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def test_all_methods_leak(self):
        r = probe(self.url)
        self.assertEqual(r.grade, LEAK)
        self.assertTrue(r.leaked)
        self.assertEqual(sorted(r.leaked_methods), ["cancel", "get", "update"])
        self.assertIn("LEAK", r.summary())
        self.assertEqual(r.to_dict()["leaked_methods"], r.leaked_methods)

    def test_each_method_leaks_alone(self):
        for method in ("get", "update", "cancel"):
            with running_server("leaky", leaky_methods=[method]) as url:
                r = probe(url)
            self.assertEqual(r.grade, LEAK, method)
            self.assertEqual(r.leaked_methods, [method])
            for other, res in r.methods.items():
                if other != method:
                    self.assertEqual(res.grade, OK, (method, other))


class SafeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._servers = [running_server("safe"), running_server("oracle")]
        cls.safe_url, cls.oracle_url = [c.__enter__() for c in cls._servers]

    @classmethod
    def tearDownClass(cls):
        for c in cls._servers:
            c.__exit__(None, None, None)

    def test_safe_passes(self):
        r = probe(self.safe_url)
        self.assertEqual(r.grade, OK, r.detail)
        self.assertFalse(r.leaked)
        self.assertEqual(r.observations, [])
        self.assertIn("OK", r.summary())

    def test_existence_oracle_is_observation_not_leak(self):
        r = probe(self.oracle_url)
        self.assertEqual(r.grade, OK)
        self.assertTrue(any("existence oracle" in o for o in r.observations))


class InconclusiveTests(unittest.TestCase):
    def test_no_tasks_extension(self):
        with running_server("safe", no_tasks=True) as url:
            r = probe(url)
        self.assertEqual(r.grade, INCONCLUSIVE)
        self.assertNotEqual(r.grade, OK)

    def test_unreachable_server_is_inconclusive(self):
        with running_server("safe") as url:
            pass  # server is now shut down
        r = probe(url)
        self.assertEqual(r.grade, INCONCLUSIVE)

    def test_client_without_capability_is_inconclusive(self):
        from strangertest.mcp_client import MCPClient
        from strangertest.probe import Identity
        from strangertest.transports import HTTPTransport

        with running_server("leaky") as url:
            def plain(token, label):
                return Identity(label, lambda: MCPClient(HTTPTransport(
                    url, headers={"Authorization": f"Bearer {token}"}, modern=True)))
            r = run_handle_probe(url, plain("alice", "A"), plain("bob", "B"))
        self.assertEqual(r.grade, INCONCLUSIVE)

    def test_tasks_requests_carry_mcp_name(self):
        # SEP-2663: Mcp-Name mirrors taskId on tasks/*. A server that enforces
        # it must still let the probe reach a real verdict.
        with running_server("safe", require_name_header=True) as url:
            r = probe(url)
        self.assertEqual(r.grade, OK, r.detail)
        with running_server("leaky", require_name_header=True) as url:
            r = probe(url)
        self.assertEqual(r.grade, LEAK, r.detail)

    def test_malformed_request_refusal_is_inconclusive_never_ok(self):
        # A refusal of a malformed request (here: no Mcp-Name on tasks/*,
        # -32020) is not an authorization decision and must never grade OK.
        from strangertest.mcp_client import MCPClient
        from strangertest.probe import Identity
        from strangertest.handle import CLIENT_CAPABILITIES_WITH_TASKS
        from strangertest.transports import HTTPTransport

        with running_server("safe", require_name_header=True) as url:
            def plain(token, label):
                return Identity(label, lambda: MCPClient(HTTPTransport(
                    url, headers={"Authorization": f"Bearer {token}"}, modern=True,
                    client_capabilities=CLIENT_CAPABILITIES_WITH_TASKS)))
            r = run_handle_probe(url, plain("alice", "A"), plain("bob", "B"),
                                 drift_window=0.02, settle_timeout=0.2)
        self.assertEqual(r.grade, INCONCLUSIVE)
        self.assertNotEqual(r.methods.get("get", None) and r.methods["get"].grade, OK)

    def test_mode_switch_in_place_takes_effect(self):
        # A gate swaps leaky -> safe on the SAME server (a restart on the same
        # port leaves a gateway's keep-alive connections on the old state).
        server = build_server("leaky")
        thread = threading.Thread(
            target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            self.assertEqual(probe(url).grade, LEAK)
            server.state.reset("safe")
            self.assertEqual(server.state.tasks, {})
            self.assertEqual(probe(url).grade, OK)
        finally:
            server.shutdown()
            server.server_close()

    def test_broken_observer_is_inconclusive_not_ok(self):
        # A server whose tasks/get never returns A's marker must not yield OK.
        fake = _FakeServer(break_marker=True)
        r = _fake_probe(fake)
        self.assertEqual(r.grade, INCONCLUSIVE)
        self.assertIn("positive control", r.detail)

    def test_ack_without_observable_change_is_inconclusive(self):
        fake = _FakeServer(ack_only=True)
        r = _fake_probe(fake, settle_timeout=0.1, drift_window=0.01)
        self.assertEqual(r.methods["update"].grade, INCONCLUSIVE)
        self.assertEqual(r.methods["cancel"].grade, INCONCLUSIVE)
        self.assertEqual(r.grade, INCONCLUSIVE)
        for m in ("update", "cancel"):
            self.assertTrue(
                any(f"tasks/{m}" in o and "acknowledged" in o for o in r.observations),
                (m, r.observations),
            )


class ControlTests(unittest.TestCase):
    def test_update_rejected_for_own_task_is_inconclusive_never_ok(self):
        # The server rejects EVERY update as malformed, so B's refusal on A's
        # task proves nothing: B's own update control fails too.
        with running_server("safe", reject_updates=True) as url:
            r = probe(url)
        self.assertEqual(r.methods["update"].grade, INCONCLUSIVE)
        self.assertIn("control", r.methods["update"].detail)
        self.assertNotEqual(r.grade, OK)
        self.assertEqual(r.methods["get"].grade, OK)
        self.assertEqual(r.methods["cancel"].grade, OK)

    def test_own_cancel_failure_is_inconclusive_never_ok(self):
        fake = _FakeServer(own_cancel_fails=True)
        r = _fake_probe(fake)
        self.assertEqual(r.methods["cancel"].grade, INCONCLUSIVE)
        self.assertIn("control", r.methods["cancel"].detail)
        self.assertNotEqual(r.grade, OK)


class DriftTests(unittest.TestCase):
    def test_self_progressing_task_is_inconclusive_not_leak(self):
        with running_server("safe", drift=True) as url:
            r = probe(url, drift_window=0.02)
        self.assertNotEqual(r.grade, LEAK)
        self.assertEqual(r.grade, INCONCLUSIVE)
        for m in ("update", "cancel"):
            self.assertEqual(r.methods[m].grade, INCONCLUSIVE, m)
            self.assertIn("unstable", r.methods[m].detail)

    def test_stable_task_passes_drift_check(self):
        with running_server("safe") as url:
            r = probe(url)
        self.assertEqual(r.grade, OK, r.detail)


class LeakDefinitionTests(unittest.TestCase):
    def test_cosmetic_change_is_observation_not_leak(self):
        # B's update/cancel only touches A's statusMessage: not a leak.
        fake = _FakeServer(foreign_effect="message")
        r = _fake_probe(fake, settle_timeout=0.05, drift_window=0.01)
        self.assertNotEqual(r.grade, LEAK)
        for m in ("update", "cancel"):
            self.assertNotEqual(r.methods[m].grade, LEAK, m)
            self.assertTrue(
                any(f"tasks/{m}" in o and "statusMessage" in o for o in r.observations),
                (m, r.observations),
            )

    def test_cancel_leaks_only_when_cancelled(self):
        fake = _FakeServer(foreign_effect="cancel")
        r = _fake_probe(fake, settle_timeout=0.05, drift_window=0.01)
        self.assertEqual(r.methods["cancel"].grade, LEAK)
        self.assertEqual(r.methods["update"].grade, INCONCLUSIVE)

    def test_update_leaks_when_input_requests_change(self):
        fake = _FakeServer(foreign_effect="requests")
        r = _fake_probe(fake, settle_timeout=0.05, drift_window=0.01)
        self.assertEqual(r.methods["update"].grade, LEAK)

    def test_update_leaks_when_status_leaves_input_required(self):
        fake = _FakeServer(foreign_effect="update")
        r = _fake_probe(fake, settle_timeout=0.05, drift_window=0.01)
        self.assertEqual(r.methods["update"].grade, LEAK)


class GuardTests(unittest.TestCase):
    def test_public_target_refused_before_any_connection(self):
        def boom():
            raise AssertionError("connected despite refusal")

        from strangertest.probe import Identity

        with self.assertRaises(AuthorizationError):
            run_handle_probe(
                "https://mcp.example.com/mcp",
                Identity("A", boom),
                Identity("B", boom),
            )


class ClientCallContractTests(unittest.TestCase):
    """handle.py reaches MCPClient._call through the single helper _rpc()."""

    def test_mcpclient_still_has_call(self):
        from strangertest.mcp_client import MCPClient

        self.assertTrue(
            callable(getattr(MCPClient, "_call", None)),
            "MCPClient._call is gone or renamed: strangertest/handle.py _rpc() "
            "depends on it. Update _rpc() (the only caller) to the new request "
            "method, or give MCPClient a public generic request method.",
        )

    def test_rpc_fails_readably_without_call(self):
        from strangertest.handle import _rpc

        class NoCall:
            pass

        with self.assertRaises(RuntimeError) as cm:
            _rpc(NoCall(), "tasks/get", {})
        self.assertIn("MCPClient._call", str(cm.exception))


class ExactMatchTests(unittest.TestCase):
    def test_exact_leaf_only(self):
        self.assertTrue(_contains_exact({"a": [{"t": "m1"}]}, "m1"))
        self.assertFalse(_contains_exact({"a": "xm1x"}, "m1"))
        self.assertFalse(_contains_exact({"m1": 1}, "m1"))


# -- in-memory fake client for paths HTTP can't easily produce -----------

class _FakeServer:
    def __init__(self, break_marker=False, ack_only=False, own_cancel_fails=False,
                 foreign_effect=None):
        self.foreign_effect = foreign_effect
        self.own_cancel_fails = own_cancel_fails
        self.break_marker = break_marker
        self.ack_only = ack_only
        self.tasks = {}


class _FakeClient:
    def __init__(self, server, who):
        self.s, self.who = server, who

    def initialize(self):
        return {}

    def close(self):
        pass

    def call_tool(self, name, arguments):
        tid = f"t{len(self.s.tasks)}"
        self.s.tasks[tid] = {"owner": self.who, "kind": arguments["kind"],
                             "marker": arguments["marker"],
                             "status": {"input": "input_required"}.get(
                                 arguments["kind"], "working")}
        return {"resultType": "task", "taskId": tid, "status": "working"}

    def _call(self, method, params):
        t = self.s.tasks.get(params["taskId"])
        if t is None or t["owner"] != self.who:
            raise JSONRPCError(-32602, "Invalid or nonexistent taskId")
        if method == "tasks/get":
            if t["kind"] == "complete":
                text = "other" if self.s.break_marker else t["marker"]
                return {"resultType": "complete", "status": "completed",
                        "result": {"content": [{"type": "text", "text": text}]}}
            out = {"resultType": "complete", "status": t["status"]}
            if t["status"] == "input_required":
                out["inputRequests"] = t.get("reqs") or {"q1": {}}
            if t.get("msg"):
                out["statusMessage"] = t["msg"]
            return out
        if method == "tasks/update" and t["status"] == "input_required":
            t["status"] = "completed"
        if method == "tasks/cancel":
            if self.s.own_cancel_fails:
                raise JSONRPCError(-32603, "cancel broke")
            t["status"] = "cancelled"
        return {"resultType": "complete"}


def _fake_probe(server, **kw):
    from strangertest.probe import Identity

    class AckClient(_FakeClient):
        # B's update/cancel on A's task is acknowledged but changes nothing.
        def _call(self, method, params):
            t = self.s.tasks.get(params["taskId"])
            foreign = (method in ("tasks/update", "tasks/cancel")
                       and t is not None and t["owner"] != self.who)
            if foreign and self.s.foreign_effect:
                eff = self.s.foreign_effect
                if eff == "message":
                    t["msg"] = "touched"
                elif eff == "cancel" and method == "tasks/cancel":
                    t["status"] = "cancelled"
                elif eff == "requests" and method == "tasks/update":
                    t["reqs"] = {"q2": {}}
                elif eff == "update" and method == "tasks/update":
                    t["status"] = "completed"
                return {"resultType": "complete"}
            if self.s.ack_only and foreign:
                return {"resultType": "complete"}
            return super()._call(method, params)

    return run_handle_probe(
        "http://127.0.0.1:1/mcp",
        Identity("A", lambda: AckClient(server, "A")),
        Identity("B", lambda: AckClient(server, "B")),
        **kw,
    )


if __name__ == "__main__":
    unittest.main()


# ------------------------------------------- identity from the token's claims
import base64 as _b64
import itertools as _it
import json as _json

from strangertest.handle import CLIENT_CAPABILITIES_WITH_TASKS, TasksHTTPTransport
from strangertest.mcp_client import MCPClient
from strangertest.probe import Identity

_counter = _it.count()


def _jwt(claims):
    """An unsigned JWT-shaped token (the practice server only reads claims)."""
    enc = lambda d: _b64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


class _RotatingTransport(TasksHTTPTransport):
    """A fresh token on EVERY request, same principal: what an upstream sees
    behind a gateway that exchanges the user's token per request."""

    def __init__(self, url, sub, iss="https://local-as.test", **kw):
        super().__init__(url, modern=True, client_capabilities=CLIENT_CAPABILITIES_WITH_TASKS, **kw)
        self._sub, self._iss = sub, iss

    def _headers(self):
        h = super()._headers()
        h["Authorization"] = "Bearer " + _jwt(
            {"iss": self._iss, "sub": self._sub, "n": next(_counter)})
        return h


def rotating(url, sub, label):
    return Identity(label=label, connect=lambda: MCPClient(_RotatingTransport(url, sub)))


def rprobe(url):
    return run_handle_probe(url, rotating(url, "alice", "A"), rotating(url, "bob", "B"),
                            drift_window=0.02, settle_timeout=0.2)


class JwtIdentityTests(unittest.TestCase):
    """identity_from="jwt": the caller is (orig_iss or iss, sub) from the bearer's
    claims, so a per-request exchanged token still names the same user."""

    def test_safe_with_rotating_tokens_is_ok(self):
        with running_server("safe", identity_from="jwt") as url:
            self.assertEqual(rprobe(url).grade, OK)

    def test_leaky_with_rotating_tokens_leaks(self):
        with running_server("leaky", identity_from="jwt") as url:
            self.assertEqual(rprobe(url).grade, LEAK)

    def test_header_identity_cannot_follow_rotating_tokens(self):
        # Why the option exists: keyed on the raw header, A cannot reach its
        # own task, so the probe must not say OK.
        with running_server("safe") as url:
            self.assertNotEqual(rprobe(url).grade, OK)

    def test_same_sub_other_issuer_is_another_user(self):
        from strangertest.practice_handle_http import identity_from_jwt
        a = identity_from_jwt("Bearer " + _jwt({"iss": "https://x.test", "sub": "alice"}))
        b = identity_from_jwt("Bearer " + _jwt({"iss": "https://y.test", "sub": "alice"}))
        c = identity_from_jwt("Bearer " + _jwt({"iss": "https://z.test", "sub": "alice",
                                                "orig_iss": "https://x.test"}))
        self.assertNotEqual(a, b)
        self.assertEqual(a, c)  # exchanged token: identity is the original provider

    def test_unparseable_bearer_falls_back_to_header(self):
        # Two different garbage tokens must stay two identities (collapsing
        # them would make a false LEAK).
        from strangertest.practice_handle_http import identity_from_jwt
        self.assertNotEqual(identity_from_jwt("Bearer junk-1"), identity_from_jwt("Bearer junk-2"))
        self.assertEqual(identity_from_jwt("Bearer junk-1"), "Bearer junk-1")
        self.assertNotEqual(identity_from_jwt("Bearer " + _jwt({"iss": "i"})),
                            identity_from_jwt("Bearer " + _jwt({"iss": "i", "x": 1})))

    def test_reset_keeps_identity_mode(self):
        server = build_server("leaky", identity_from="jwt")
        try:
            server.state.reset("safe")
            self.assertEqual(server.state.identity_from, "jwt")
        finally:
            server.server_close()

    def test_seen_records_token_fingerprint_and_claims(self):
        server = build_server("safe", identity_from="jwt")
        t = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        t.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            rprobe(url)
            s = [x for x in server.state.seen if x["method"] == "tools/call"][0]
            self.assertTrue(s["token"].startswith("sha256:"))
            self.assertEqual(s["claims"]["sub"], "alice")
            self.assertNotIn("eyJ", _json.dumps(server.state.seen))
        finally:
            server.shutdown()
            server.server_close()


# --------------------------------------- Mcp-Name option on the base transport
class NameBearingOptionTests(unittest.TestCase):
    """HTTPTransport(name_bearing_methods=...) is the public way to mirror a
    param into Mcp-Name for extension methods; the default is unchanged."""

    def envelope_headers(self, transport, method, params):
        return transport._modern_envelope(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})[1]

    def test_option_mirrors_task_id(self):
        from strangertest.transports import HTTPTransport, TASK_NAME_BEARING_METHODS
        t = HTTPTransport("http://127.0.0.1:1/mcp", modern=True,
                          name_bearing_methods=TASK_NAME_BEARING_METHODS)
        for m in ("tasks/get", "tasks/update", "tasks/cancel"):
            self.assertEqual(self.envelope_headers(t, m, {"taskId": "task-1"})["Mcp-Name"],
                             "task-1")
        # core name-bearing methods still work alongside
        self.assertEqual(self.envelope_headers(t, "tools/call", {"name": "x"})["Mcp-Name"], "x")

    def test_default_is_unchanged(self):
        from strangertest.transports import HTTPTransport
        t = HTTPTransport("http://127.0.0.1:1/mcp", modern=True)
        self.assertNotIn("Mcp-Name", self.envelope_headers(t, "tasks/get", {"taskId": "t"}))
        self.assertEqual(self.envelope_headers(t, "tools/call", {"name": "x"})["Mcp-Name"], "x")

    def test_option_cannot_redefine_a_core_method(self):
        from strangertest.transports import HTTPTransport
        with self.assertRaises(ValueError):
            HTTPTransport("http://127.0.0.1:1/mcp", modern=True,
                          name_bearing_methods={"tools/call": "other"})

    def test_option_reaches_a_strict_server(self):
        from strangertest.transports import HTTPTransport, TASK_NAME_BEARING_METHODS

        def ident(url, token, label):
            return Identity(label, lambda: MCPClient(HTTPTransport(
                url, headers={"Authorization": f"Bearer {token}"}, modern=True,
                client_capabilities=CLIENT_CAPABILITIES_WITH_TASKS,
                name_bearing_methods=TASK_NAME_BEARING_METHODS)))

        with running_server("safe", require_name_header=True) as url:
            r = run_handle_probe(url, ident(url, "alice", "A"), ident(url, "bob", "B"),
                                 drift_window=0.02, settle_timeout=0.2)
        self.assertEqual(r.grade, OK, r.detail)

    def test_tasks_transport_is_the_base_transport_configured(self):
        from strangertest.handle import TASK_NAME_BEARING_METHODS as H
        from strangertest.transports import HTTPTransport, TASK_NAME_BEARING_METHODS
        self.assertIs(H, TASK_NAME_BEARING_METHODS)
        self.assertIs(TasksHTTPTransport._modern_envelope, HTTPTransport._modern_envelope)
