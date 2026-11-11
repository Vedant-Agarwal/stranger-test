"""Fixture: a low-level SDK dispatcher. Parsed by tests, never imported.

One ``call_tool`` function serves several tools; the detector should judge
each ``if name == ...`` branch on its own.
"""

from mcp.server import Server

server = Server("lowlevel")


class Backend:
    def __init__(self, db):
        self.db = db
        self.items = {}

    def register(self):
        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            if name == "put_item_shared":
                self.items[arguments["key"]] = arguments["value"]
                return []
            elif name == "get_rows":
                return self.db.session.execute("SELECT * FROM rows").fetchall()
            elif name == "get_my_rows":
                return self.db.session.execute(
                    "SELECT * FROM rows WHERE tenant_id = ?", (arguments["tenant_id"],)
                ).fetchall()
            elif name == "ping":
                return []
            raise ValueError(name)
