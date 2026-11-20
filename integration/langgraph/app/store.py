"""A custom Store for the sample app: LangGraph's own SQLite store.

Used only by ``langgraph.sqlite.json`` so that the dev server keeps long-term
memory in ``langgraph.store.sqlite`` (the store the namespace-boundary
advisories were about) instead of its default in-memory store. The database
path comes from ``ST_STORE_DB``.
"""
import os
from contextlib import asynccontextmanager

from langgraph.store.sqlite.aio import AsyncSqliteStore


@asynccontextmanager
async def create_store():
    async with AsyncSqliteStore.from_conn_string(os.environ["ST_STORE_DB"]) as store:
        await store.setup()
        yield store
