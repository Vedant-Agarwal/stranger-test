"""A no-LLM 'agent' with long-term memory, for the isolation spike.

input: {"action": "save", "key": k, "value": v}  or  {"action": "recall", "key": k}
leaky: one shared namespace for every user.  safe: namespace starts with the user.
"""
import os
from typing import Optional, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.store.base import BaseStore

MODE = os.environ.get("ST_SPIKE_MODE", "leaky")


class State(TypedDict, total=False):
    action: str
    key: str
    value: Optional[str]
    result: Optional[str]
    whoami: Optional[str]


async def memory_node(state: State, config: RunnableConfig, *, store: BaseStore) -> State:
    user = (config.get("configurable") or {}).get("langgraph_auth_user_id") or "anonymous"
    namespace = ("memories",) if MODE == "leaky" else (user, "memories")
    if state.get("action") == "save":
        await store.aput(namespace, state["key"], {"text": state.get("value")})
        return {"result": "saved", "whoami": user}
    item = await store.aget(namespace, state["key"])
    return {"result": (item.value.get("text") if item else None), "whoami": user}


builder = StateGraph(State)
builder.add_node("memory", memory_node)
builder.add_edge(START, "memory")
builder.add_edge("memory", END)
graph = builder.compile()
