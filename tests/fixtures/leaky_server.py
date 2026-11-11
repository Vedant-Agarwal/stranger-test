"""Fixture: a deliberately leaky MCP server. Parsed by tests, never imported.

Every handler reaches one shared store and none of them looks at who is
calling, so a note saved by one caller is readable by any other.
"""

import json
import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("leaky-notes")

NOTES = {}
DB_PATH = "notes.db"
HELP_TOPICS = {"usage": "call save_note then read_note"}


def _load_archive():
    with open("archive.json") as f:
        return json.load(f)


@mcp.tool()
def save_note(key: str, value: str) -> str:
    """Save a note."""
    NOTES[key] = value
    return "ok"


@mcp.tool()
def read_note(key: str) -> str:
    """Read a note back."""
    return NOTES.get(key, "")


@mcp.tool(name="search_notes")
async def search(text: str) -> list:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT body FROM notes WHERE body LIKE ?", (text,)).fetchall()
    return [r[0] for r in rows]


@mcp.tool()
def read_archive() -> dict:
    # State is only reached through a helper in this file.
    return _load_archive()


@mcp.tool()
def add(a: int, b: int) -> int:
    """Pure: no state, so not a candidate."""
    return a + b


@mcp.tool()
def help_topic(name: str) -> str:
    """Reads a constant table nothing mutates: not shared state."""
    return HELP_TOPICS.get(name, "")
