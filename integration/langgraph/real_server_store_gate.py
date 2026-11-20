"""Gate: the agent-memory probe through a REAL LangGraph server on a real store.

Starts ``langgraph dev`` on 127.0.0.1 with the sample app in safe mode (owner
filter for threads, own-namespace check for the Store) and with the server's
Store replaced by LangGraph's own SQLite or Postgres store (``app/store.py``,
via ``app/langgraph.store.json``). The two identities are prefix siblings,
``alice`` and ``ali``. Nothing in the path is a stand-in: requests go through
the LangGraph server, its auth handlers and the real store.

Run it once per installed store version, each in its own environment that has
both the dev server and the store:

    pip install "langgraph-cli[inmem]" "langgraph-checkpoint-sqlite==3.1.0"   -> expect LEAK
    pip install "langgraph-cli[inmem]" "langgraph-checkpoint-sqlite==3.1.1"   -> expect OK

    LANGGRAPH_BIN=<env>/bin/langgraph ST_GATE_SCRATCH=<dir> ST_GATE_PORT=4645 \
        python3 integration/langgraph/real_server_store_gate.py

For Postgres, install ``langgraph-checkpoint-postgres`` (3.1.0 / 3.1.1),
``psycopg[binary]`` and ``psycopg-pool`` instead, and add
``ST_STORE_KIND=postgres ST_PG_URI=postgresql://user@127.0.0.1:<port>/<db>``.
The gate refuses a database that already has tables: use an empty one you own.

Exit 0 when the run completed (read the grade in the output), 2 when it could
not run. The server is always stopped.
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

from strangertest.agent_memory import run_agent_memory_probe  # noqa: E402

FORBIDDEN_PORTS = {4000, 4444, 8790}


def _ready(base):
    try:
        with urllib.request.urlopen(base + "/ok", timeout=2) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


def main():
    langgraph_bin = os.environ.get("LANGGRAPH_BIN")
    scratch = os.environ.get("ST_GATE_SCRATCH")
    if not langgraph_bin or not os.path.exists(langgraph_bin):
        print("REFUSING: LANGGRAPH_BIN is not set or does not exist", file=sys.stderr)
        return 2
    if not scratch or not os.path.isdir(scratch):
        print("REFUSING: ST_GATE_SCRATCH is not set or is not a directory", file=sys.stderr)
        return 2
    port = int(os.environ.get("ST_GATE_PORT", "4645"))
    if not (4600 <= port <= 4699) or port in FORBIDDEN_PORTS:
        print(f"REFUSING: port {port} is outside 4600-4699 or reserved", file=sys.stderr)
        return 2
    with socket.socket() as check:
        check.bind(("127.0.0.1", port))

    kind = os.environ.get("ST_STORE_KIND", "sqlite")
    if kind not in ("sqlite", "postgres"):
        print("REFUSING: ST_STORE_KIND must be sqlite or postgres", file=sys.stderr)
        return 2
    package = f"langgraph-checkpoint-{kind}"
    env_python = os.path.join(os.path.dirname(langgraph_bin), "python")
    version = subprocess.run(
        [env_python, "-c",
         "import importlib.metadata as m;"
         f"print(m.version('{package}'), m.version('langgraph'), m.version('langgraph-api'))"],
        capture_output=True, text=True).stdout.split()
    if len(version) != 3:
        print("REFUSING: could not read package versions from the server environment", file=sys.stderr)
        return 2
    store_version, langgraph_version, api_version = version
    tag = f"{kind}-{store_version}"

    env = dict(os.environ, ST_SPIKE_MODE="safe",
               LANGSMITH_TRACING="false", LANGCHAIN_TRACING_V2="false")
    if kind == "postgres":
        uri = os.environ.get("ST_PG_URI", "")
        if not uri.startswith("postgresql://"):
            print("REFUSING: ST_PG_URI must be a postgresql:// URI", file=sys.stderr)
            return 2
        # Never touch a database that already holds anything.
        tables = subprocess.run(
            [env_python, "-c",
             "import sys, psycopg;"
             "c = psycopg.connect(sys.argv[1]);"
             "print(c.execute(\"select count(*) from information_schema.tables "
             "where table_schema not in ('pg_catalog', 'information_schema')\").fetchone()[0])",
             uri], capture_output=True, text=True)
        if tables.returncode != 0 or tables.stdout.strip() != "0":
            print("REFUSING: the Postgres database is not reachable or not empty "
                  f"({(tables.stdout or tables.stderr).strip()[:120]})", file=sys.stderr)
            return 2
        env["ST_STORE_URI"] = uri
    else:
        database = os.path.join(scratch, f"server-store-{store_version}.sqlite")
        for leftover in (database, database + "-wal", database + "-shm"):
            if os.path.exists(leftover):
                os.remove(leftover)
        env["ST_STORE_DB"] = database
    log = open(os.path.join(scratch, f"server-store-{tag}.log"), "w")
    proc = subprocess.Popen(
        [langgraph_bin, "dev", "--host", "127.0.0.1", "--port", str(port),
         "--no-browser", "--no-reload", "--config", "langgraph.store.json"],
        cwd=os.path.join(HERE, "app"), env=env, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(120):
            if proc.poll() is not None:
                print(f"could not run: the server exited early; see {log.name}", file=sys.stderr)
                return 2
            if _ready(base):
                break
            time.sleep(0.5)
        else:
            print("could not run: the server never became ready", file=sys.stderr)
            return 2
        report = run_agent_memory_probe(
            base, "tok-alice", "tok-ali",
            namespace_a=["alice"], namespace_b=["ali"],
            assistant_id="memory",
            save_input={"action": "save", "key": "st-probe", "value": "{marker}"},
            recall_input={"action": "recall", "key": "st-probe"},
            whoami_field="whoami", authorized=True)
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

    with open(log.name) as handle:
        used_custom_store = "Using custom store" in handle.read()
    out = report.to_dict()
    out.update({"target": f"langgraph dev (safe sample app, {kind} store)",
                "store_kind": kind, "store_version": store_version, "langgraph_version": langgraph_version,
                "langgraph_api_version": api_version,
                "server_log_confirms_custom_store": used_custom_store})
    with open(os.path.join(scratch, f"server-store-{tag}.json"), "w") as handle:
        json.dump(out, handle, indent=2)
    print(f"langgraph {langgraph_version}, langgraph-api {api_version}, "
          f"{package} {store_version}; custom store in use: {used_custom_store}")
    print(f"grade: {out['grade']} - {out['detail']}")
    for path in out["paths"]:
        print(f"    {path['outcome']:<14} {path['name']}")
    if not used_custom_store:
        print(f"WARNING: the server log does not show the {kind} store in use; "
              "this run says nothing about that store.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
