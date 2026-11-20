"""Reproduction: CVE-2026-71433 (GHSA-47pj-3jcm-6whg), LangGraph SQLite/Postgres
store namespace-prefix matching crosses segment boundaries. Affected
langgraph-checkpoint-sqlite < 3.1.1; fixed in 3.1.1.

Run with the package installed in a SEPARATE environment, e.g.:
    pip install "langgraph-checkpoint-sqlite==3.1.0"  -> exits 7 (cross-user read)
    pip install "langgraph-checkpoint-sqlite==3.1.1"  -> exits 0 (isolated)

This is a STORE-LEVEL reproduction. The shipped agent-memory probe tests the
application authorization layer; to catch this store-level bug end-to-end the
probe must use two prefix-sibling identities (attacker id is a string prefix of
the victim id) searching their OWN allowed namespace. That path is not wired yet.
"""
import sys, importlib.metadata as m
try:
    from langgraph.store.sqlite import SqliteStore
except Exception as e:
    print("IMPORT-FAIL", e); sys.exit(2)
ver = m.version("langgraph-checkpoint-sqlite")
try:
    cm = SqliteStore.from_conn_string(":memory:")
except Exception as e:
    print("CTOR-FAIL", e); sys.exit(2)
with cm as store:
    try: store.setup()
    except Exception: pass
    # Three users whose ids share a leading string but are DIFFERENT segments.
    store.put(("alice",), "k", {"text": "ALICE-SECRET"})
    store.put(("alice-evil",), "k", {"text": "EVIL-SECRET"})
    store.put(("alicent",), "k", {"text": "ALICENT-SECRET"})
    hits = store.search(("alice",))
    names = sorted({".".join(i.namespace) for i in hits})
    texts = sorted({i.value.get("text") for i in hits})
    print(f"version={ver}")
    print(f"alice searched prefix ('alice',) -> namespaces {names}")
    foreign = [t for t in texts if t not in (None, "ALICE-SECRET")]
    if foreign:
        print(f"CROSS-USER READ: alice also saw {foreign}"); sys.exit(7)
    print("ISOLATED: alice saw only her own item"); sys.exit(0)
