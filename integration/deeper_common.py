"""Shared bits for the deeper-scenario drivers (xid10_deeper_*.py).

Ports: every port a deeper driver binds or names must be 4600-4699 and never
4000, 4444 or 8790. Saved runs go to integration/runs/<gateway>-<name>-<ts>.json
and are refused if anything JWT-shaped (or a LiteLLM key) is in them.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any, Callable, Dict
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from login_faults_harness import FORBIDDEN_PORTS, fp, port_46xx  # noqa: E402

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_SK_RE = re.compile(r"sk-[A-Za-z0-9_-]{8,}")

DEEPER_MODES = ("login_faults", "concurrent")


def redact(text) -> str:
    return _SK_RE.sub("sk-<redacted>", _JWT_RE.sub(lambda m: fp(m.group(0)), str(text)))


def env_port(name: str) -> int:
    raw = os.environ.get(name)
    if not raw:
        raise SystemExit(f"ERROR: refusing to start: set {name} explicitly")
    return port_46xx(int(raw), name)


def url_port(name: str) -> str:
    url = os.environ.get(name) or ""
    u = urlparse(url)
    if u.hostname != "127.0.0.1" or not u.port:
        raise SystemExit(f"ERROR: refusing to start: {name} must be http://127.0.0.1:<46xx>")
    port_46xx(u.port, name)
    return url.rstrip("/")


def save_run(gateway: str, name: str, payload: Dict[str, Any]) -> str:
    runs = os.environ.get("DEEPER_RUNS_DIR") or os.path.join(_HERE, "runs")
    os.makedirs(runs, exist_ok=True)
    out = os.path.join(runs, f"{gateway}-{name}-{int(time.time())}.json")
    text = json.dumps(payload, indent=2, default=str)
    if _JWT_RE.search(text) or _SK_RE.search(text):
        raise SystemExit("refusing to save: a token or key is in the run")
    with open(out, "w") as f:
        f.write(text)
    print(f"saved run -> {out}")
    return out


def mcp_call(client_fn: Callable[[float], Any], tool: str, nonce: str, timeout: float) -> Dict[str, Any]:
    """One tools/call with ``nonce``; never raises. ``succeeded`` is True only for
    a result that is not ``isError``."""
    t0 = time.monotonic()
    c = None
    try:
        c = client_fn(timeout)
        c.initialize()
        r = c.call_tool(tool, {"nonce": nonce})
        ok = not (isinstance(r, dict) and r.get("isError"))
        return {"succeeded": ok, "detail": redact(json.dumps(r))[:400],
                "elapsed_s": round(time.monotonic() - t0, 2)}
    except Exception as e:  # noqa: BLE001  -- a refusal is data here
        return {"succeeded": False, "detail": redact(f"{type(e).__name__}: {e}")[:400],
                "elapsed_s": round(time.monotonic() - t0, 2)}
    finally:
        if c is not None:
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass


def fault_modes_from_env():
    from strangertest.login_faults import FAULT_MODES
    raw = os.environ.get("FAULT_MODES", "").strip()
    if not raw:
        return FAULT_MODES
    modes = tuple(raw.split(","))
    bad = [m for m in modes if m not in FAULT_MODES]
    if bad:
        raise SystemExit(f"unknown FAULT_MODES {bad}; known: {FAULT_MODES}")
    return modes


__all__ = ["DEEPER_MODES", "FORBIDDEN_PORTS", "env_port", "url_port", "save_run", "mcp_call",
           "redact", "fp", "fault_modes_from_env"]
