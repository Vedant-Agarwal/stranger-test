"""Tests for the universal scan adapter (strangertest.scan.adapter).

Every target here is a LOCAL server on 127.0.0.1, ports 4600-4699: the shipped
``practice_http`` server plus a small configurable MCP server defined in-test
that exercises the auth / session / cache / OAuth-metadata paths the practice
server does not. Nothing reaches the network.
"""

import json
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from strangertest.practice_http import build_server
from strangertest.scan import TargetProfile, fingerprint_secret, profile_target

PORT_RANGE = range(4600, 4700)


def _bind_in_range(make_server):
    """Bind a ThreadingHTTPServer on the first free port in 4600-4699."""
    for port in PORT_RANGE:
        try:
            return make_server(port), port
        except OSError:
            continue
    raise RuntimeError("no free port in 4600-4699")


@contextmanager
def _serving(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()


@contextmanager
def _practice_http():
    server, port = _bind_in_range(lambda p: build_server("safe", port=p))
    with _serving(server):
        yield f"http://127.0.0.1:{port}/mcp"


# --- a configurable in-test MCP server -------------------------------------


def _make_feature_handler(opts):
    issued_session = "srv-session-abcdef012345"

    def result(mid, res):
        return {"jsonrpc": "2.0", "id": mid, "result": res}

    def err(mid, code, message):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}

    def dispatch(msg):
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            return result(mid, {
                "protocolVersion": "2026-07-28",
                "serverInfo": {"name": "feature-srv", "version": "9.9"},
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            })
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            return result(mid, {"tools": [{"name": "alpha"}, {"name": "beta"}]})
        if method == "resources/list":
            return result(mid, {"resources": [{"uri": "note://doc/1"}]})
        if method == "resources/read":
            return result(mid, {
                "resultType": "complete",
                "contents": [{"uri": "note://doc/1", "mimeType": "text/plain", "text": "hi"}],
                "cacheScope": "private",
                "ttlMs": 60000,
            })
        if method == "prompts/list":
            return result(mid, {"prompts": [{"name": "greet"}]})
        if mid is None:
            return None
        return err(mid, -32601, f"unknown method {method}")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            if opts.get("oauth") and self.path == "/.well-known/oauth-authorization-server":
                body = json.dumps({
                    "issuer": "http://127.0.0.1/",
                    "grant_types_supported": [
                        "authorization_code",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ],
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            if opts.get("require_auth") and not self.headers.get("Authorization"):
                body = b""
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Bearer realm="mcp"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            try:
                msg = json.loads(raw)
            except ValueError:
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            resp = dispatch(msg)
            if resp is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if msg.get("method") == "initialize" and opts.get("issue_session"):
                self.send_header("Mcp-Session-Id", issued_session)
            inbound = self.headers.get("Mcp-Session-Id")
            if inbound and opts.get("echo_session"):
                self.send_header("Mcp-Session-Id", inbound)
            self.end_headers()
            self.wfile.write(body)

    return Handler


@contextmanager
def _feature_server(**opts):
    server, port = _bind_in_range(
        lambda p: ThreadingHTTPServer(("127.0.0.1", p), _make_feature_handler(opts))
    )
    server.daemon_threads = True
    with _serving(server):
        yield f"http://127.0.0.1:{port}/mcp"


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_shape(self):
        fp = fingerprint_secret("super-secret-token")
        self.assertTrue(fp.startswith("sha256:"))
        self.assertEqual(len(fp), len("sha256:") + 12)
        self.assertEqual(fp, fingerprint_secret("super-secret-token"))


class LoopbackGuardTests(unittest.TestCase):
    def test_nonloopback_rejected_by_default(self):
        with self.assertRaises(ValueError):
            profile_target("https://mcp.example.com/")

    def test_unreadable_host_rejected(self):
        with self.assertRaises(ValueError):
            profile_target("not a url")


class PracticeServerProfileTests(unittest.TestCase):
    def test_profiles_practice_http(self):
        with _practice_http() as url:
            profile = profile_target(url, timeout=5.0)
        self.assertIsInstance(profile, TargetProfile)
        self.assertTrue(profile.reachable)
        self.assertEqual(profile.transport, "streamable-http")
        self.assertEqual(profile.protocol_version, "2026-07-28")
        self.assertEqual(profile.server_info.get("name"), "practice-http")
        self.assertEqual(
            sorted(profile.capabilities["tools"]),
            ["get_resource", "set_resource", "whoami"],
        )
        self.assertEqual(profile.capabilities["counts"]["tools"], 3)
        # practice_http never issues a session id but ignores session entirely.
        self.assertFalse(profile.session["issues_session_id"])
        self.assertTrue(profile.session["accepts_forged_session_id"])
        # It does not require auth.
        self.assertIs(profile.auth["required"], False)


class FeatureServerProfileTests(unittest.TestCase):
    def test_session_cache_and_caps(self):
        with _feature_server(issue_session=True, echo_session=True) as url:
            profile = profile_target(url, bearer="tok-123456", timeout=5.0)
        self.assertTrue(profile.reachable)
        self.assertEqual(profile.transport, "streamable-http")
        self.assertEqual(profile.server_info.get("name"), "feature-srv")
        self.assertEqual(sorted(profile.capabilities["tools"]), ["alpha", "beta"])
        self.assertEqual(profile.capabilities["resources"], ["note://doc/1"])
        self.assertEqual(profile.capabilities["prompts"], ["greet"])
        # session
        self.assertTrue(profile.session["issues_session_id"])
        self.assertTrue(profile.session["echoes_inbound_session_id"])
        self.assertTrue(profile.session["accepts_forged_session_id"])
        # cache
        self.assertTrue(profile.cache["advertises_cachescope"])
        self.assertTrue(profile.cache["forces_private"])
        self.assertEqual(profile.cache["ttl_ms"], 60000)
        # bearer recorded only as a fingerprint
        self.assertEqual(profile.fingerprints["bearer"], fingerprint_secret("tok-123456"))
        self.assertNotIn("tok-123456", json.dumps(profile.fingerprints))
        self.assertEqual(
            profile.fingerprints["server_session_id"],
            fingerprint_secret("srv-session-abcdef012345"),
        )

    def test_auth_required_fingerprinted(self):
        with _feature_server(require_auth=True) as url:
            profile = profile_target(url, bearer="let-me-in-999999", timeout=5.0)
        # Authenticated connect works; unauthenticated probe sees the 401.
        self.assertTrue(profile.reachable)
        self.assertIs(profile.auth["required"], True)
        self.assertEqual(profile.auth["scheme"], "Bearer")
        self.assertIn("realm", profile.auth["www_authenticate"])
        # No raw Authorization value anywhere in the recorded headers.
        self.assertNotIn("let-me-in-999999", json.dumps(profile.headers))

    def test_oauth_metadata_and_token_exchange_hint(self):
        with _feature_server(oauth=True) as url:
            profile = profile_target(url, timeout=5.0)
        meta = profile.auth["oauth_metadata"]
        self.assertIn("authorization_server", meta)
        self.assertTrue(profile.auth["token_exchange_hint"])


class UnreachableTargetTests(unittest.TestCase):
    def test_unreachable_loopback_returns_partial_profile(self):
        # A closed port on loopback: must not raise, must mark unreachable.
        profile = profile_target("http://127.0.0.1:4699/closed", timeout=1.0)
        self.assertIsInstance(profile, TargetProfile)
        self.assertFalse(profile.reachable)
        self.assertEqual(profile.transport, "unknown")
        self.assertTrue(profile.errors)


if __name__ == "__main__":
    unittest.main()
