"""Gate: the agent-memory probe against the REAL LangGraph SQLite Store.

A thin HTTP shim exposes the LangGraph-shaped endpoints the probe uses, but the
Store operations call the genuine ``langgraph.store.sqlite.SqliteStore``. The
shim itself is a correct per-user app: a caller may only touch a Store namespace
whose first segment is their own identity. So any cross-user read comes from the
store's own namespace matching, not from this code.

Run it once per installed store version, in a SEPARATE environment:

    pip install "langgraph-checkpoint-sqlite==3.1.0"   -> expect LEAK  (CVE-2026-71433)
    pip install "langgraph-checkpoint-sqlite==3.1.1"   -> expect OK    (fixed)

Identities are prefix siblings: ``tok-ali`` (id ``ali``) and ``tok-alice``
(id ``alice``). ``alice`` saves a secret in her namespace; ``ali`` searches his
own namespace ``("ali",)``. A store that matches the prefix as a string returns
alice's item to ali.

    LANGGRAPH_STORE_DB=<path.sqlite> ST_GATE_PORT=4660 \
        <venv>/bin/python integration/langgraph/real_store_gate.py

Exit 0 LEAK, 5 OK/isolated, 2 could not run. The runner compares the two.
"""

import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from strangertest.agent_memory import run_agent_memory_probe  # noqa: E402

FORBIDDEN_PORTS = {4000, 4444, 8790}
TOKENS = {"tok-alice": "alice", "tok-ali": "ali"}


def _identity(auth):
    token = (auth or "")
    token = token[len("Bearer "):] if token.startswith("Bearer ") else ""
    return TOKENS.get(token)


def make_handler(store):
    threads = {}
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, status, payload=None):
            body = b"" if payload is None else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw) if raw else {}

        def _ns_ok(self, who, namespace):
            return bool(namespace) and namespace[0] == who   # own-namespace only

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

        def do_PUT(self):
            self._route("PUT")

        def _route(self, method):
            u = urlparse(self.path)
            parts = [p for p in u.path.split("/") if p]
            if method == "GET" and parts == ["ok"]:
                return self._send(200, {"ok": True})
            who = _identity(self.headers.get("Authorization"))
            if who is None:
                return self._send(401, {"detail": "unknown token"})
            try:
                body = self._body() if method in ("POST", "PUT") else {}
            except ValueError:
                return self._send(422, {"detail": "bad json"})
            if parts and parts[0] == "threads":
                return self._threads(method, parts[1:], who, body)
            if parts and parts[0] == "store":
                return self._store(method, parts[1:], who, body, parse_qs(u.query))
            self._send(404, {"detail": "not found"})

        def _threads(self, method, rest, who, body):
            if method == "POST" and not rest:
                tid = "t-%d" % (len(threads) + 1)
                with lock:
                    threads[tid] = {"owner": who, "metadata": body.get("metadata") or {}, "values": {}}
                return self._send(200, {"thread_id": tid, "metadata": threads[tid]["metadata"]})
            if method == "POST" and rest == ["search"]:
                return self._send(200, [{"thread_id": t, "metadata": v["metadata"]}
                                        for t, v in threads.items() if v["owner"] == who])
            if len(rest) >= 1:
                t = threads.get(rest[0])
                if not t or t["owner"] != who:
                    return self._send(404, {"detail": "not found"})
                if method == "GET" and len(rest) == 1:
                    return self._send(200, {"thread_id": rest[0], "metadata": t["metadata"]})
                if method == "GET" and rest[1:] == ["state"]:
                    return self._send(200, {"values": t["values"]})
                if method == "GET" and rest[1:] == ["history"]:
                    return self._send(200, [{"values": t["values"]}] if t["values"] else [])
                if method == "POST" and rest[1:] == ["runs", "wait"]:
                    inp = dict(body.get("input") or {})
                    ns = (who, "memories")
                    key = str(inp.get("key"))
                    if inp.get("action") == "save":
                        store.put(ns, key, {"text": inp.get("value")})
                        inp["result"] = "saved"
                    else:
                        item = store.get(ns, key)
                        inp["result"] = item.value.get("text") if item else None
                    inp["whoami"] = who
                    t["values"] = inp
                    return self._send(200, inp)
            self._send(404, {"detail": "not found"})

        def _store(self, method, rest, who, body, query):
            if method == "PUT" and rest == ["items"]:
                ns = tuple(body.get("namespace") or ())
                if not self._ns_ok(who, ns):
                    return self._send(403, {"detail": "not your namespace"})
                store.put(ns, str(body.get("key")), dict(body.get("value") or {}))
                return self._send(204)
            if method == "GET" and rest == ["items"]:
                ns = tuple(p for p in (query.get("namespace") or [""])[0].split(".") if p)
                if not self._ns_ok(who, ns):
                    return self._send(403, {"detail": "not your namespace"})
                item = store.get(ns, (query.get("key") or [""])[0])
                if item is None:
                    return self._send(404, {"detail": "not found"})
                return self._send(200, {"namespace": list(ns), "key": item.key, "value": item.value})
            if method == "POST" and rest == ["items", "search"]:
                prefix = tuple(body.get("namespace_prefix") or ())
                if not self._ns_ok(who, prefix):
                    return self._send(403, {"detail": "not your namespace"})
                # The real store decides what this prefix matches.
                hits = store.search(prefix, limit=int(body.get("limit") or 100))
                return self._send(200, {"items": [{"namespace": list(i.namespace), "key": i.key,
                                                    "value": i.value} for i in hits]})
            if method == "POST" and rest == ["namespaces"]:
                return self._send(200, {"namespaces": []})
            self._send(404, {"detail": "not found"})

    return H


def main():
    db = os.environ.get("LANGGRAPH_STORE_DB")
    if not db:
        print("REFUSING: LANGGRAPH_STORE_DB not set", file=sys.stderr)
        return 2
    port = int(os.environ.get("ST_GATE_PORT", "4660"))
    if not (4600 <= port <= 4699) or port in FORBIDDEN_PORTS:
        print(f"REFUSING: port {port} outside 4600-4699 or reserved", file=sys.stderr)
        return 2
    try:
        from langgraph.store.sqlite import SqliteStore
    except Exception as exc:
        print(f"REFUSING: langgraph sqlite store not importable: {exc}", file=sys.stderr)
        return 2
    import importlib.metadata as m
    version = m.version("langgraph-checkpoint-sqlite")
    with socket.socket() as s:
        s.bind(("127.0.0.1", port))
    cm = SqliteStore.from_conn_string(db)
    with cm as store:
        try:
            store.setup()
        except Exception:
            pass
        server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(store))
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{port}"
        try:
            report = run_agent_memory_probe(
                base, "tok-alice", "tok-ali",
                namespace_a=["alice"], namespace_b=["ali"],
                assistant_id="memory",
                save_input={"action": "save", "key": "st-probe", "value": "{marker}"},
                recall_input={"action": "recall", "key": "st-probe"},
                whoami_field="whoami", authorized=True)
        finally:
            server.shutdown()
            server.server_close()
    out = report.to_dict()
    out["store_version"] = version
    own = next((p for p in out["paths"] if p["name"] == "store_search_own_prefix"), {})
    print(f"store {version}: grade={out['grade']}  own-namespace path={own.get('outcome')}")
    print(json.dumps({"store_version": version, "grade": out["grade"],
                      "paths": {p["name"]: p["outcome"] for p in out["paths"]}}, indent=2))
    scratch = os.environ.get("ST_GATE_SCRATCH")
    if scratch and os.path.isdir(scratch):
        with open(os.path.join(scratch, f"real-store-{version}.json"), "w") as fh:
            json.dump(out, fh, indent=2)
    return 0 if out["grade"] == "LEAK" else (5 if out["grade"] == "OK" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
