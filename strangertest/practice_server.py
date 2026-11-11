"""A deliberately-insecure LOCAL practice MCP server.

Its only purpose is to give Stranger Test a known target on your own machine:
in the default "leaky" mode it ignores which identity is connected and keeps
one shared key/value store, so a marker planted by one identity is readable by
another — a cross-identity confused-deputy leak. In "safe" mode it namespaces
every key by identity, so there is no leak.

NEVER expose this on a network. It stores unauthenticated data by design.

It speaks newline-delimited JSON-RPC over stdin/stdout and is configured by
environment variables:

* ``STRANGERTEST_MODE``     -- "leaky" (default) or "safe"
* ``STRANGERTEST_IDENTITY`` -- the identity this connection authenticates as
* ``STRANGERTEST_STORE``    -- path to a shared JSON file used as the backing store
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

MODE = os.environ.get("STRANGERTEST_MODE", "leaky")
IDENTITY = os.environ.get("STRANGERTEST_IDENTITY", "anonymous")
STORE_PATH = os.environ.get("STRANGERTEST_STORE")


def _load() -> Dict[str, Any]:
    if not STORE_PATH or not os.path.exists(STORE_PATH):
        return {}
    try:
        with open(STORE_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(data: Dict[str, Any]) -> None:
    if STORE_PATH:
        with open(STORE_PATH, "w") as f:
            json.dump(data, f)


def _key(key: str) -> str:
    # The bug lives here: "leaky" uses a global key (identity ignored); "safe"
    # scopes the key to the connected identity.
    if MODE == "safe":
        return f"{IDENTITY}:{key}"
    return key


def _ok(mid: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def handle(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        return _ok(mid, {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "practice", "version": "0.0.0"},
            "capabilities": {"tools": {}},
        })
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _ok(mid, {"tools": [{"name": "kv_set"}, {"name": "kv_get"}]})
    if method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})
        data = _load()
        if name == "kv_set":
            data[_key(args.get("key"))] = args.get("value")
            _save(data)
            return _ok(mid, {"content": [{"type": "text", "text": "ok"}]})
        if name == "kv_get":
            value = data.get(_key(args.get("key")), "")
            return _ok(mid, {"content": [{"type": "text", "text": value}]})
        return _err(mid, -32601, f"unknown tool {name}")
    if mid is None:
        return None  # an unknown notification; nothing to answer
    return _err(mid, -32601, f"unknown method {method}")


def main() -> None:
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        response = handle(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
