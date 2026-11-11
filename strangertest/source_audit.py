"""Static source triage for MCP servers (Python only, for now).

Where :mod:`strangertest.probe` tests a *running* server, this module only
*reads source code*. It never imports, executes, or connects to anything: each
file is parsed with :mod:`ast` and inspected as a tree.

The pattern it looks for, stated precisely:

    A **tool handler** whose code **touches stored or shared state** and in
    which **no caller identity is referenced**.

* A *tool handler* is a function decorated with ``@<x>.tool`` /
  ``@<x>.resource`` (FastMCP style), a function registered through
  ``add_tool(fn)`` / ``from_function(fn)`` / ``tool(fn)``, or one branch
  (``if name == "..."``) of a low-level ``@<x>.call_tool()`` dispatcher.
* *Touches state* means: a storage-style call (``.execute*``, ``.find_one``,
  ``.write_text`` ...), file I/O (``open``, ``json.dump`` ...), a call on an
  object named like a store (``db``, ``cache``, ``repo`` ...), a shared
  module-level container, or ``self.<attr>[...]`` instance state.
* *References caller identity* means: any identifier or short string in the
  handler mentions a user / token / session / tenant / owner / account / auth
  style word (see ``IDENTITY_TOKENS``).

Both checks follow calls into helper functions **in the same file** (a few
levels deep) and stop there.

This is coarse, **LOW-confidence triage**, not ground truth. A hit is a place
worth reading, not a vulnerability. Known blind spots:

* A server that only ever serves one user (most stdio servers) has no second
  identity to leak to; a hit there is a non-issue. ``network_hints`` on the
  survey says whether the tree mentions a network transport at all.
* Identity enforced in another module, in middleware, or by the database
  (row-level security) is invisible here, so the handler is flagged anyway.
* The word match is shallow: a handler that mentions ``token`` for an unrelated
  reason is cleared, and a ``user_id`` that is accepted but trusted blindly from
  the caller (which is itself the bug) is cleared too.
* Only the stored-state half of the failure class is covered. A server that
  forwards every caller's request upstream with one shared credential holds no
  local state and is not flagged.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

__all__ = [
    "PATTERN",
    "CONFIDENCE",
    "Handler",
    "SurveyReport",
    "audit_source",
    "audit_file",
    "survey",
]

PATTERN = "tool handler touches stored/shared state but references no caller identity"
CONFIDENCE = "low"

# Words that, as one part of an identifier (``user_id`` -> user, id), count as a
# reference to who is calling.
IDENTITY_TOKENS = frozenset({
    "user", "userid", "username", "uid", "owner", "ownerid", "tenant",
    "tenantid", "token", "session", "sessionid", "account", "accountid",
    "org", "orgid", "organization", "organisation", "principal", "subject",
    "identity", "caller", "auth", "authed", "authenticated", "authorization",
    "authorize", "authorized", "credential", "credentials", "bearer", "jwt",
    "claims", "workspace", "member", "actor", "apikey", "oauth", "login",
})
IDENTITY_PAIRS = frozenset({("client", "id"), ("api", "key"), ("access", "key")})

# Method names that read or write a datastore whatever they are called on.
STORAGE_METHODS = frozenset({
    "execute", "executemany", "executescript", "fetchone", "fetchall",
    "fetchmany", "fetchrow", "fetchval", "commit", "query", "find_one",
    "insert_one", "insert_many", "update_one", "update_many", "delete_one",
    "delete_many", "replace_one", "aggregate", "hget", "hset", "hgetall",
    "lpush", "rpush", "lrange", "sadd", "smembers", "zadd", "upsert",
    "put_item", "get_item", "add_documents", "similarity_search",
    "read_text", "write_text", "read_bytes", "write_bytes",
})
WRITE_METHODS = frozenset({
    "executemany", "executescript", "commit", "insert_one", "insert_many",
    "update_one", "update_many", "delete_one", "delete_many", "replace_one",
    "hset", "lpush", "rpush", "sadd", "zadd", "upsert", "put_item",
    "add_documents", "write_text", "write_bytes", "dump",
})
# An object named with one of these words is treated as a store.
STORE_TOKENS = frozenset({
    "db", "database", "store", "storage", "repo", "repository", "cache",
    "redis", "mongo", "collection", "table", "conn", "connection", "cursor",
    "cur", "memory", "memories", "kv", "vault", "bucket", "datastore",
    "driver", "connector", "sqlite", "duckdb", "postgres", "qdrant", "chroma",
    "neo4j",
})
MUTATORS = frozenset({
    "append", "appendleft", "add", "extend", "insert", "pop", "popitem",
    "remove", "discard", "clear", "update", "setdefault",
})
SERIALIZERS = frozenset({"json", "pickle", "yaml", "toml", "shelve", "sqlite3"})
SERIALIZER_CALLS = frozenset({"load", "dump", "open", "connect"})
CONTAINER_FACTORIES = frozenset({
    "dict", "list", "set", "defaultdict", "OrderedDict", "deque", "Counter",
})

SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__",
    "site-packages", "build", "dist", ".tox", ".mypy_cache",
})
TEST_DIRS = frozenset({"tests", "test"})
MAX_FILE_BYTES = 2_000_000
HELPER_DEPTH = 3

_NETWORK_RE = re.compile(
    r"streamable[-_]http|\bsse\b|SseServerTransport|uvicorn|starlette|fastapi"
    r"|aiohttp\.web|transport\s*=\s*[\"'](?:http|sse)",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SQL_WRITE_RE = re.compile(r"^\s*(insert|update|delete|replace|drop|create)\b", re.IGNORECASE)

_FuncDef = (ast.FunctionDef, ast.AsyncFunctionDef)


def _tokens(identifier: str) -> List[str]:
    return [t.lower() for t in _TOKEN_RE.findall(identifier)]


def _is_identity(tokens: Sequence[str]) -> bool:
    if any(t in IDENTITY_TOKENS for t in tokens):
        return True
    return any(pair in IDENTITY_PAIRS for pair in zip(tokens, tokens[1:]))


@dataclass
class Handler:
    """One tool handler and what the detector saw in it."""

    file: str
    line: int
    tool: str
    kind: str  # "tool" | "resource" | "dispatch-branch" | "dispatcher"
    state_signals: List[str] = field(default_factory=list)
    identity_refs: List[str] = field(default_factory=list)
    writes: bool = False

    @property
    def touches_state(self) -> bool:
        return bool(self.state_signals)

    @property
    def flagged(self) -> bool:
        return self.touches_state and not self.identity_refs

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "tool": self.tool,
            "kind": self.kind,
            "access": "write" if self.writes else "read",
            "state_signals": self.state_signals,
            "identity_refs": self.identity_refs,
            "flagged": self.flagged,
            "confidence": CONFIDENCE if self.flagged else None,
        }


@dataclass
class SurveyReport:
    root: str
    files_scanned: int = 0
    handlers: List[Handler] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)
    network_hints: List[str] = field(default_factory=list)

    @property
    def findings(self) -> List[Handler]:
        return [h for h in self.handlers if h.flagged]

    def counts(self) -> Dict[str, int]:
        return {
            "files_scanned": self.files_scanned,
            "files_with_handlers": len({h.file for h in self.handlers}),
            "handlers": len(self.handlers),
            "handlers_touching_state": sum(1 for h in self.handlers if h.touches_state),
            "flagged": len(self.findings),
            "parse_errors": len(self.parse_errors),
        }

    def to_dict(self, include_all: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "root": self.root,
            "pattern": PATTERN,
            "confidence": CONFIDENCE,
            "counts": self.counts(),
            "network_transport_hint": bool(self.network_hints),
            "network_hint_files": self.network_hints,
            "parse_errors": self.parse_errors,
            "findings": [h.to_dict() for h in self.findings],
        }
        if include_all:
            data["handlers"] = [h.to_dict() for h in self.handlers]
        return data

    def summary(self) -> str:
        c = self.counts()
        lines = [
            f"Surveyed {self.root}: {c['files_scanned']} Python file(s), "
            f"{c['handlers']} tool handler(s) in {c['files_with_handlers']} file(s).",
            f"{c['handlers_touching_state']} touch stored/shared state; "
            f"{c['flagged']} of those reference no caller identity.",
            "Network transport mentioned: "
            + ("yes" if self.network_hints else "no (may be single-user stdio only)")
            + ".",
        ]
        if c["parse_errors"]:
            lines.append(
                f"{c['parse_errors']} file(s) could not be parsed and were skipped "
                "(run under a Python at least as new as the code being read)."
            )
        for h in self.findings:
            lines.append(
                f"  CANDIDATE [{CONFIDENCE}] {h.file}:{h.line} {h.kind} {h.tool!r} "
                f"({'write' if h.writes else 'read'}) — " + ", ".join(h.state_signals[:4])
                + (" ..." if len(h.state_signals) > 4 else "")
            )
        lines.append(
            "These are low-confidence triage hits to read by hand, not confirmed leaks."
        )
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Module-level facts
# --------------------------------------------------------------------------


def _container_emptiness(value: Optional[ast.AST]) -> Optional[bool]:
    """None if ``value`` is not a mutable container; else whether it starts empty."""
    if isinstance(value, ast.Dict):
        return not value.keys
    if isinstance(value, (ast.List, ast.Set)):
        return not value.elts
    if isinstance(value, ast.Call):
        func = value.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name in CONTAINER_FACTORIES:
            return True
    return None


class _Module:
    def __init__(self, tree: ast.Module) -> None:
        self.functions: Dict[str, ast.AST] = {}
        for node in ast.walk(tree):
            if isinstance(node, _FuncDef):
                self.functions.setdefault(node.name, node)
        # One level of plain aliasing: ``find_tool = find``.
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                target = node.targets[0]
                if isinstance(target, ast.Name) and node.value.id in self.functions:
                    self.functions.setdefault(target.id, self.functions[node.value.id])

        containers: Dict[str, bool] = {}
        for stmt in tree.body:
            targets: List[ast.AST] = []
            value: Optional[ast.AST] = None
            if isinstance(stmt, ast.Assign):
                targets, value = list(stmt.targets), stmt.value
            elif isinstance(stmt, ast.AnnAssign):
                targets, value = [stmt.target], stmt.value
            empty = _container_emptiness(value)
            if empty is None:
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    containers[target.id] = empty

        mutated: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                mutated.update(node.names)
            elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
                if isinstance(node.value, ast.Name):
                    mutated.add(node.value.id)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in MUTATORS and isinstance(node.func.value, ast.Name):
                    mutated.add(node.func.value.id)
        # A container counts as shared state if it starts empty (it exists to be
        # filled) or something in the file mutates it. A populated, never-mutated
        # literal is just a constant table.
        self.shared_globals: Set[str] = {
            name for name, empty in containers.items() if empty or name in mutated
        }


# --------------------------------------------------------------------------
# Handler discovery
# --------------------------------------------------------------------------

_DECORATOR_KINDS = {
    "tool": "tool",
    "resource": "resource",
    "read_resource": "resource",
    "call_tool": "dispatcher",
}


def _decorator_info(dec: ast.AST) -> Optional[Tuple[str, Optional[str]]]:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        attr = target.attr
    elif isinstance(target, ast.Name):
        attr = target.id
    else:
        return None
    kind = _DECORATOR_KINDS.get(attr)
    if kind is None:
        return None
    name: Optional[str] = None
    if isinstance(dec, ast.Call):
        for kw in dec.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                name = kw.value.value
        if name is None and dec.args:
            first = dec.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                name = first.value
    return kind, name


def _dispatch_branches(func: ast.AST) -> List[Tuple[str, int, List[ast.stmt]]]:
    """Split a ``call_tool(name, arguments)`` dispatcher into per-tool branches."""
    params = [a.arg for a in func.args.args if a.arg not in ("self", "cls")]  # type: ignore[attr-defined]
    if not params:
        return []
    name_param = params[0]
    branches: List[Tuple[str, int, List[ast.stmt]]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.If):
            test = node.test
            if (
                isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and test.left.id == name_param
                and len(test.ops) == 1
                and isinstance(test.ops[0], ast.Eq)
                and isinstance(test.comparators[0], ast.Constant)
                and isinstance(test.comparators[0].value, str)
            ):
                branches.append((test.comparators[0].value, node.lineno, node.body))
        elif hasattr(ast, "Match") and isinstance(node, ast.Match):  # Python 3.10+
            if isinstance(node.subject, ast.Name) and node.subject.id == name_param:
                for case in node.cases:
                    pat = case.pattern
                    if (
                        isinstance(pat, ast.MatchValue)
                        and isinstance(pat.value, ast.Constant)
                        and isinstance(pat.value.value, str)
                    ):
                        branches.append((pat.value.value, pat.lineno, case.body))
    return branches


def _registered_functions(tree: ast.Module, mod: _Module) -> Iterator[ast.AST]:
    """Functions passed to ``add_tool(fn)`` / ``from_function(fn)`` / ``tool(fn)``."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in ("add_tool", "from_function", "tool") or not node.args:
            continue
        arg = node.args[0]
        name = arg.id if isinstance(arg, ast.Name) else getattr(arg, "attr", None)
        if name in mod.functions:
            yield mod.functions[name]


# --------------------------------------------------------------------------
# Scanning one handler
# --------------------------------------------------------------------------


def _chain_names(node: ast.AST) -> List[str]:
    """Identifier parts of a receiver expression such as ``self.db.notes``."""
    names: List[str] = []
    while True:
        if isinstance(node, ast.Attribute):
            names.append(node.attr)
            node = node.value
        elif isinstance(node, (ast.Subscript, ast.Call)):
            node = node.value if isinstance(node, ast.Subscript) else node.func
        elif isinstance(node, ast.Name):
            names.append(node.id)
            break
        else:
            break
    names.reverse()
    return names


def _body_without_docstring(func: ast.AST) -> List[ast.stmt]:
    body = list(func.body)  # type: ignore[attr-defined]
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return body


class _Scan:
    def __init__(self, mod: _Module) -> None:
        self.mod = mod
        self.state: List[str] = []
        self.identity: List[str] = []
        self.writes = False
        self.calls: Set[str] = set()
        self._weak: Set[int] = set()  # nodes where "session" means a DB/MCP session
        self._seen_state: Set[str] = set()
        self._seen_identity: Set[str] = set()

    # -- recording ---------------------------------------------------------

    def _state(self, kind: str, detail: str, line: int, write: bool = False) -> None:
        self.writes = self.writes or write
        key = f"{kind}:{detail}"
        if key not in self._seen_state:
            self._seen_state.add(key)
            self.state.append(f"{kind} {detail} (line {line})")

    def _ident(self, text: str, weak: bool = False) -> None:
        tokens = _tokens(text)
        if weak:
            tokens = [t for t in tokens if t != "session"]
        if _is_identity(tokens) and text not in self._seen_identity:
            self._seen_identity.add(text)
            self.identity.append(text)

    # -- walking -----------------------------------------------------------

    def scan_function(self, func: ast.AST, skip: Optional[Set[int]] = None) -> None:
        self.walk(func.args, skip)  # type: ignore[attr-defined]
        for stmt in _body_without_docstring(func):
            self.walk(stmt, skip)

    def walk(self, node: ast.AST, skip: Optional[Set[int]] = None) -> None:
        if skip and id(node) in skip:
            return
        self.visit(node)
        for child in ast.iter_child_nodes(node):
            self.walk(child, skip)

    def _mark_weak(self, node: ast.AST) -> None:
        while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call, ast.Name)):
            self._weak.add(id(node))
            if isinstance(node, ast.Attribute):
                node = node.value
            elif isinstance(node, ast.Subscript):
                node = node.value
            elif isinstance(node, ast.Call):
                node = node.func
            else:
                break

    def visit(self, node: ast.AST) -> None:
        line = getattr(node, "lineno", 0)
        weak = id(node) in self._weak

        if isinstance(node, ast.Call):
            self._visit_call(node, line)
        elif isinstance(node, ast.Subscript):
            write = isinstance(node.ctx, (ast.Store, ast.Del))
            base = node.value
            if isinstance(base, ast.Name) and base.id in self.mod.shared_globals:
                self._state("global_state", base.id, line, write)
            elif isinstance(base, ast.Attribute):
                chain = _chain_names(base)
                if chain and chain[0] in ("self", "cls"):
                    self._state("instance_state", ".".join(chain), line, write)
        elif isinstance(node, ast.Name):
            if node.id in self.mod.shared_globals:
                self._state("global_state", node.id, line)
            self._ident(node.id, weak)
        elif isinstance(node, ast.Attribute):
            # ``ctx.session`` is the MCP transport session, not who is calling.
            base = node.value
            if node.attr == "session" and (
                (isinstance(base, ast.Name) and base.id in ("ctx", "context", "request_context"))
                or (isinstance(base, ast.Attribute) and base.attr == "request_context")
            ):
                weak = True
            self._ident(node.attr, weak)
        elif isinstance(node, ast.arg):
            self._ident(node.arg)
        elif isinstance(node, ast.keyword):
            if node.arg:
                self._ident(node.arg)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
            if len(text) <= 400:
                for word in _WORD_RE.findall(text):
                    self._ident(word)
                if _SQL_WRITE_RE.match(text):
                    self.writes = True

    def _visit_call(self, node: ast.Call, line: int) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            self.calls.add(func.id)
            if func.id == "open":
                mode = ""
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                self._state("file_io", "open()", line, any(c in mode for c in "wax+"))
            return
        if not isinstance(func, ast.Attribute):
            return

        method = func.attr
        chain = _chain_names(func.value)
        receiver = ".".join(chain) or "<expr>"
        if chain and chain[0] in ("self", "cls") and len(chain) == 1:
            self.calls.add(method)

        chain_tokens = {t for name in chain for t in _tokens(name)}
        if method in STORAGE_METHODS or method.startswith("execute_"):
            self._mark_weak(func.value)
            self._state("storage_call", f"{receiver}.{method}()", line, method in WRITE_METHODS)
        elif chain and chain[-1] in SERIALIZERS and method in SERIALIZER_CALLS:
            self._state("file_io", f"{receiver}.{method}()", line, method == "dump")
        elif chain_tokens & STORE_TOKENS:
            self._mark_weak(func.value)
            write = method in MUTATORS or _tokens(method)[:1] in (
                ["set"], ["save"], ["put"], ["add"], ["create"], ["delete"],
                ["remove"], ["write"], ["insert"], ["update"], ["store"],
            )
            self._state("store_object", f"{receiver}.{method}()", line, write)
        elif method in MUTATORS and chain:
            if chain[0] in ("self", "cls") and len(chain) > 1:
                self._state("instance_state", f"{receiver}.{method}()", line, True)
            elif len(chain) == 1 and chain[0] in self.mod.shared_globals:
                self._state("global_state", f"{receiver}.{method}()", line, True)


def _analyse(
    mod: _Module,
    func: ast.AST,
    skip: Optional[Set[int]] = None,
) -> _Scan:
    scan = _Scan(mod)
    scan.scan_function(func, skip)
    visited: Set[str] = {func.name}  # type: ignore[attr-defined]
    for _ in range(HELPER_DEPTH):
        todo = sorted(n for n in scan.calls if n in mod.functions and n not in visited)
        if not todo:
            break
        for name in todo:
            visited.add(name)
            scan.scan_function(mod.functions[name])
    return scan


def audit_source(source: str, filename: str = "<source>") -> List[Handler]:
    """Find tool handlers in one file's source and describe each.

    Raises :class:`SyntaxError` if the source does not parse. A file that never
    mentions ``mcp`` is assumed not to be an MCP server and yields nothing.
    """
    if "mcp" not in source.lower():
        return []
    tree = ast.parse(source, filename=filename)
    mod = _Module(tree)

    found: List[Tuple[ast.AST, str, Optional[str]]] = []
    seen: Set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, _FuncDef):
            continue
        for dec in node.decorator_list:
            info = _decorator_info(dec)
            if info is not None and id(node) not in seen:
                seen.add(id(node))
                found.append((node, info[0], info[1]))
    for node in _registered_functions(tree, mod):
        if id(node) not in seen:
            seen.add(id(node))
            found.append((node, "tool", None))

    handlers: List[Handler] = []

    def emit(tool: str, kind: str, line: int, scan: _Scan) -> None:
        handlers.append(Handler(
            file=filename, line=line, tool=tool, kind=kind,
            state_signals=scan.state, identity_refs=scan.identity, writes=scan.writes,
        ))

    for func, kind, override in found:
        name = override or func.name  # type: ignore[attr-defined]
        branches = _dispatch_branches(func) if kind == "dispatcher" else []
        if not branches:
            emit(name, kind, func.lineno, _analyse(mod, func))  # type: ignore[attr-defined]
            continue
        # Each branch is scanned together with the dispatcher's shared code (an
        # auth check or a store load before the branches applies to all of them)
        # but without the other branches.
        for tool, line, body in branches:
            skip = {id(stmt) for _, _, other in branches if other is not body for stmt in other}
            emit(tool, "dispatch-branch", line, _analyse(mod, func, skip))

    handlers.sort(key=lambda h: h.line)
    return handlers


def audit_file(path: str, display: Optional[str] = None) -> List[Handler]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return audit_source(f.read(), display or path)


def _is_test_file(name: str) -> bool:
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def _python_files(root: str, include_tests: bool) -> Iterable[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and (include_tests or d not in TEST_DIRS)
        )
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            if not include_tests and _is_test_file(name):
                continue
            yield os.path.join(dirpath, name)


def survey(path: str, include_tests: bool = False) -> SurveyReport:
    """Run the detector over every Python file under ``path``.

    Reads files only. Raises :class:`FileNotFoundError` if ``path`` is missing.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    report = SurveyReport(root=path)
    base = path if os.path.isdir(path) else os.path.dirname(path)
    for file_path in _python_files(path, include_tests):
        display = os.path.relpath(file_path, base) if base else file_path
        try:
            if os.path.getsize(file_path) > MAX_FILE_BYTES:
                continue
            with open(file_path, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except OSError as exc:
            report.parse_errors.append(f"{display}: {exc}")
            continue
        report.files_scanned += 1
        if _NETWORK_RE.search(source):
            report.network_hints.append(display)
        try:
            report.handlers.extend(audit_source(source, display))
        except (SyntaxError, ValueError, RecursionError) as exc:
            report.parse_errors.append(f"{display}: {type(exc).__name__}: {exc}")
    return report
