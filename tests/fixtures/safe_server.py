"""Fixture: an identity-scoped MCP server. Parsed by tests, never imported.

The same shapes as ``leaky_server.py``, but every handler scopes what it
touches to the caller.
"""

import sqlite3

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("safe-notes")

NOTES = {}
DB_PATH = "notes.db"


def _caller(ctx: Context) -> str:
    return ctx.request_context.request.state.user_id


def _scoped(ctx: Context, key: str) -> str:
    return f"{_caller(ctx)}:{key}"


@mcp.tool()
def save_note(key: str, value: str, ctx: Context) -> str:
    NOTES[(ctx.request_context.request.state.user_id, key)] = value
    return "ok"


@mcp.tool()
def read_note(key: str, ctx: Context) -> str:
    # Identity is only referenced inside the helper.
    return NOTES.get(_scoped(ctx, key), "")


@mcp.tool()
async def search_notes(text: str, ctx: Context) -> list:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT body FROM notes WHERE owner_id = ? AND body LIKE ?",
        (_caller(ctx), text),
    ).fetchall()
    return [r[0] for r in rows]
