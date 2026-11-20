"""Spike auth for a local LangGraph dev server. Two fixed test users.

ST_SPIKE_MODE=leaky : authenticates callers but adds NO resource authorization
                      (the framework default when no @auth.on handler exists).
ST_SPIKE_MODE=safe  : owner filter on threads/runs, and Store access limited to
                      namespaces that start with the caller's own identity.
"""
import os
from langgraph_sdk import Auth

MODE = os.environ.get("ST_SPIKE_MODE", "leaky")
TOKENS = {"tok-alice": "alice", "tok-bob": "bob"}

auth = Auth()


@auth.authenticate
async def authenticate(authorization: str | None) -> Auth.types.MinimalUserDict:
    token = (authorization or "").removeprefix("Bearer ").strip()
    user = TOKENS.get(token)
    if user is None:
        raise Auth.exceptions.HTTPException(status_code=401, detail="unknown token")
    return {"identity": user}


if MODE == "safe":

    @auth.on
    async def owner_only(ctx: Auth.types.AuthContext, value: dict):
        owner = {"owner": ctx.user.identity}
        value.setdefault("metadata", {}).update(owner)
        return owner

    @auth.on.store()
    async def own_namespace_only(ctx: Auth.types.AuthContext, value: dict):
        namespace = tuple(value.get("namespace") or ())
        if not namespace or namespace[0] != ctx.user.identity:
            raise Auth.exceptions.HTTPException(status_code=403, detail="not your namespace")
