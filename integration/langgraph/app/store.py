"""A custom Store for the sample app: LangGraph's own SQLite or Postgres store.

Used only by ``langgraph.store.json`` so that the dev server keeps long-term
memory in a real LangGraph store (the stores the namespace-boundary advisories
were about) instead of its default in-memory store.

- ``ST_STORE_URI`` set (a ``postgresql://`` URI): ``AsyncPostgresStore``.
- otherwise ``ST_STORE_DB`` (a file path): ``AsyncSqliteStore``.
"""
import os
from contextlib import asynccontextmanager


@asynccontextmanager
async def create_store():
    uri = os.environ.get("ST_STORE_URI")
    if uri:
        from langgraph.store.postgres.aio import AsyncPostgresStore
        context = AsyncPostgresStore.from_conn_string(uri)
    else:
        from langgraph.store.sqlite.aio import AsyncSqliteStore
        context = AsyncSqliteStore.from_conn_string(os.environ["ST_STORE_DB"])
    async with context as store:
        await store.setup()
        yield store
