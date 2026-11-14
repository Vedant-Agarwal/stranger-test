import io
import json
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from strangertest.cli import main
from strangertest.transports import HTTPTransport


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the test output quiet
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            message = json.loads(raw)
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return
        token = self.headers.get("Authorization", "")
        response = self.server.handle_rpc(token, message)
        if response is None:
            self.send_response(202)
            self.end_headers()
            return
        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Mcp-Session-Id", "test-session")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeHTTPServer(ThreadingHTTPServer):
    def __init__(self, mode):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mode = mode
        self.stores = {}

    def _store(self, token):
        namespace = "shared" if self.mode == "leaky" else token
        return self.stores.setdefault(namespace, {})

    def handle_rpc(self, token, message):
        method = message.get("method")
        mid = message.get("id")
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "fake-http"},
                "capabilities": {"tools": {}},
            }}
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "tools": [{"name": "kv_set"}, {"name": "kv_get"}]
            }}
        if method == "tools/call":
            params = message.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            store = self._store(token)
            if name == "kv_set":
                store[args["key"]] = args["value"]
                return {"jsonrpc": "2.0", "id": mid,
                        "result": {"content": [{"type": "text", "text": "ok"}]}}
            if name == "kv_get":
                value = store.get(args["key"], "")
                return {"jsonrpc": "2.0", "id": mid,
                        "result": {"content": [{"type": "text", "text": value}]}}
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": f"unknown tool {name}"}}
        if mid is None:
            return None
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"unknown method {method}"}}


@contextmanager
def running_server(mode):
    server = FakeHTTPServer(mode)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.shutdown()
        server.server_close()


class IterMessagesTests(unittest.TestCase):
    def test_parses_sse(self):
        raw = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n'
        msgs = list(HTTPTransport._iter_messages("text/event-stream", raw))
        self.assertEqual(msgs[0]["result"], {"ok": True})

    def test_parses_json_object(self):
        msgs = list(HTTPTransport._iter_messages("application/json", '{"id":1,"result":2}'))
        self.assertEqual(msgs[0]["result"], 2)

    def test_parses_json_batch(self):
        raw = '[{"id":1,"result":1},{"id":2,"result":2}]'
        msgs = list(HTTPTransport._iter_messages("application/json", raw))
        self.assertEqual([m["id"] for m in msgs], [1, 2])


class ScanOverHTTPTests(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_leak_detected_against_shared_server(self):
        with running_server("leaky") as url:
            code, out = self._run([
                "scan", url, "--token-a", "AAA", "--token-b", "BBB",
                "--plant-tool", "kv_set", "--read-tool", "kv_get",
            ])
        self.assertEqual(code, 1)
        self.assertIn("LEAK", out)

    def test_anonymous_reader_still_leaks(self):
        with running_server("leaky") as url:
            code, out = self._run([
                "scan", url, "--token-a", "AAA",
                "--plant-tool", "kv_set", "--read-tool", "kv_get",
            ])
        self.assertEqual(code, 1)

    def test_no_leak_against_isolated_server(self):
        with running_server("safe") as url:
            code, out = self._run([
                "scan", url, "--token-a", "AAA", "--token-b", "BBB",
                "--plant-tool", "kv_set", "--read-tool", "kv_get",
            ])
        self.assertEqual(code, 0)
        self.assertIn("OK", out)

    def test_public_target_refused_without_authorization(self):
        # Guard refuses before any network call is made: authorization
        # refusal is exit 3 (usage/authorization), not 2.
        code, _ = self._run([
            "scan", "https://mcp.example.com/mcp", "--token-a", "AAA",
            "--plant-tool", "kv_set", "--read-tool", "kv_get",
        ])
        self.assertEqual(code, 3)

    def test_refusal_names_the_authorized_flag(self):
        # The refusal message on the command line names the --authorized flag
        # (the guard keeps the Python `authorized=True` wording for libraries).
        from contextlib import redirect_stderr
        err = io.StringIO()
        with redirect_stderr(err):
            code = main([
                "scan", "https://mcp.example.com/mcp", "--token-a", "AAA",
                "--plant-tool", "kv_set", "--read-tool", "kv_get",
            ])
        self.assertEqual(code, 3)
        self.assertIn("--authorized", err.getvalue())
        self.assertIn("re-run", err.getvalue())

    def test_transport_error_is_inconclusive(self):
        # Nothing could be observed (connection refused on a closed local
        # port) -> INCONCLUSIVE, exit 2.
        code, _ = self._run([
            "scan", "http://127.0.0.1:1/mcp", "--token-a", "AAA",
            "--plant-tool", "kv_set", "--read-tool", "kv_get",
        ])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
