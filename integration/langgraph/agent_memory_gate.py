"""Gate: the agent-memory probe against a REAL local LangGraph dev server.

Starts ``langgraph dev`` on 127.0.0.1 with the sample app in ``app/`` (a no-LLM
agent with long-term memory) in leaky and then safe mode, runs
``strangertest.agent_memory`` against each as two identities, and always stops
the server. LangGraph lives in a separate environment; this script and the probe
use the standard library only.

Required:
  LANGGRAPH_BIN       path to the ``langgraph`` CLI (``pip install "langgraph-cli[inmem]"``)
  ST_GATE_SCRATCH     an existing directory for server logs and saved runs
Optional:
  ST_GATE_PORT_BASE   first of two loopback ports in 4600-4699 (default 4640)

Exit: 0 when the leaky app grades LEAK and the safe app grades OK, 1 otherwise,
2 when the gate could not run.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from strangertest.agent_memory import LEAK, OK, run_agent_memory_probe  # noqa: E402

FORBIDDEN_PORTS = {4000, 4444, 8790}
TOKENS = ("tok-alice", "tok-bob")
AGENT = {
    "assistant_id": "memory",
    "save_input": {"action": "save", "key": "st-probe", "value": "{marker}"},
    "recall_input": {"action": "recall", "key": "st-probe"},
    "whoami_field": "whoami",
    "namespace_a": ["alice", "notes"],
}


def _ready(base: str) -> bool:
    try:
        with urllib.request.urlopen(base + "/ok", timeout=2) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


def run_mode(mode: str, port: int, langgraph_bin: str, scratch: str) -> dict:
    if not (4600 <= port <= 4699) or port in FORBIDDEN_PORTS:
        raise SystemExit(f"REFUSING: port {port} is outside 4600-4699 or reserved")
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", port))        # fails loudly if already in use
    env = dict(os.environ, ST_SPIKE_MODE=mode, LANGSMITH_TRACING="false",
               LANGCHAIN_TRACING_V2="false")
    log = open(os.path.join(scratch, f"langgraph-{mode}.log"), "w")
    proc = subprocess.Popen(
        [langgraph_bin, "dev", "--host", "127.0.0.1", "--port", str(port),
         "--no-browser", "--no-reload", "--config", "langgraph.json"],
        cwd=os.path.join(HERE, "app"), env=env, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(120):
            if proc.poll() is not None:
                raise RuntimeError(f"the server exited early; see {log.name}")
            if _ready(base):
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("the server never became ready")
        report = run_agent_memory_probe(base, TOKENS[0], TOKENS[1], authorized=True, **AGENT)
        return report.to_dict()
    finally:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=10)
        log.close()


def main() -> int:
    langgraph_bin = os.environ.get("LANGGRAPH_BIN")
    scratch = os.environ.get("ST_GATE_SCRATCH")
    if not langgraph_bin or not os.path.exists(langgraph_bin):
        print("REFUSING: LANGGRAPH_BIN is not set or does not exist", file=sys.stderr)
        return 2
    if not scratch or not os.path.isdir(scratch):
        print("REFUSING: ST_GATE_SCRATCH is not set or is not a directory", file=sys.stderr)
        return 2
    base_port = int(os.environ.get("ST_GATE_PORT_BASE", "4640"))
    version = subprocess.run([langgraph_bin, "--version"], capture_output=True, text=True).stdout.strip()
    results = {}
    for offset, mode in enumerate(("leaky", "safe")):
        try:
            results[mode] = run_mode(mode, base_port + offset, langgraph_bin, scratch)
        except Exception as exc:  # the gate could not run this mode
            print(f"[{mode}] could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        results[mode]["target"] = f"langgraph dev ({mode} sample app)"
        print(f"[{mode}] {results[mode]['grade']}: {results[mode]['detail']}")
        for path in results[mode]["paths"]:
            print(f"    {path['outcome']:<14} {path['name']}")
    out = os.path.join(scratch, "langgraph-agent-memory.json")
    with open(out, "w") as handle:
        json.dump({"gate": "agent-memory", "server": version, "results": results}, handle, indent=2)
    print(f"saved: {out}")
    held = results["leaky"]["grade"] == LEAK and results["safe"]["grade"] == OK
    print("GATE " + ("PASSED" if held else "FAILED") + ": leaky -> "
          f"{results['leaky']['grade']}, safe -> {results['safe']['grade']}")
    return 0 if held else 1


if __name__ == "__main__":
    raise SystemExit(main())
