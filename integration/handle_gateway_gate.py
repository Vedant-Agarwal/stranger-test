"""TASK-HANDLE gate: the saved-reference (task handle) probe through a REAL gateway.

Puts the practice task server (strangertest/practice_handle_http.py) behind a
third-party MCP gateway and asks two questions, in order:

1. ``HANDLE_STAGE=trial`` - does the gateway forward the MCP tasks extension at
   all? One honest trial: a tools/call that the upstream answers with
   ``resultType: "task"``, then tasks/get, tasks/update and tasks/cancel on the
   returned taskId. Records the request/response pairs (tokens as sha256
   fingerprints only) and what reached the upstream (method, whether the tasks
   capability was in ``_meta``, protocol version).
2. ``HANDLE_STAGE=probe`` - only for a gateway that forwards tasks: run
   :func:`strangertest.handle.run_handle_probe` as two distinct users A and B,
   each authenticated by the gateway's own inbound JWT validation, with the
   practice server in ``HANDLE_UPSTREAM_MODE`` (``safe`` or ``leaky``).

Gateways (``HANDLE_GATEWAY``):

* ``agentgateway`` - the official v1.7.0 binary (``AGW_BIN``), run by this
  driver on a port-substituted copy of ``integration/agentgateway/handle-*.yaml``
  (``HANDLE_AGW_CONFIG``: ``token-exchange`` (RFC 8693 delegation, the
  compliant config), ``per-user`` (default; backendAuth.passthrough, which
  forwards the user's own token: a token-passthrough config) or
  ``shared-credential`` (backendAuth.key, one static credential for all users).
* ``contextforge`` - ContextForge 1.1.1 (``mcpgateway`` importable in this
  Python), run by this driver from ``CF_HOME`` (a dir with a bootstrapped
  ``.env``/``mcp.db``) on ``HANDLE_GW_PORT``.

PORTS. Every port is REQUIRED and explicit (no defaults): ``HANDLE_AS_PORT``,
``HANDLE_GW_PORT``, ``HANDLE_UPSTREAM_PORT`` and, for agentgateway,
``HANDLE_AGW_ADMIN_PORT``. Each must be inside ``HANDLE_PORT_BLOCK``
(default ``4200-4299``) and never 8790 or 4444 (other people's services). The
driver runs its OWN local AS (integration/local_as.py) on ``HANDLE_AS_PORT``.
Everything binds 127.0.0.1. The saved run records every URL and port used.

This is NOT a unittest; it is an operator-driven gate (needs pyjwt[crypto]).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import jwt  # noqa: F401
    from local_as import LocalAS
except Exception as exc:  # pragma: no cover
    # A results-checking script that cannot run must not look like a pass.
    print(f"ERROR: cannot run: needs pyjwt[crypto] + local_as ({exc})", file=sys.stderr)
    sys.exit(2)

from strangertest.handle import (  # noqa: E402
    CLIENT_CAPABILITIES_WITH_TASKS,
    TaskPlan,
    TasksHTTPTransport,
    run_handle_probe,
)
from strangertest.mcp_client import JSONRPCError, MCPClient  # noqa: E402
from strangertest.practice_handle_http import build_server, identity_from_jwt  # noqa: E402
from strangertest.probe import Identity  # noqa: E402
from strangertest.transports import HTTPTransport  # noqa: E402

AS_ISSUER = "https://local-as.test"
FORBIDDEN_PORTS = {8790, 4444}
COSAI = "3.2.7 / 3.2.12"
AGW_VARIANTS = ("token-exchange", "per-user", "shared-credential")
ACTOR_CLIENT = "handle-agent"
EXCHANGE_AUDIENCE = "https://upstream.test/mcp"
# backendAuth.key is a documented agentgateway option (cited in every
# shared-credential run's source_evidence).
BACKENDAUTH_KEY_DOCS = [
    "agentgateway docs, 'Static keys and passthrough' (standalone, latest): "
    "https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/"
    "backend-authn/key/ - 'Static key (key) sends a value that you configure, either "
    "inline or from a file on disk.'",
    "agentgateway v1.7.0 generated config reference schema/config.md: "
    "<BackendPolicies>.backendAuth.key (with .file), next to backendAuth.passthrough "
    "('Forward the validated incoming JWT to the backend.')",
    "agentgateway v1.7.0 crates/agentgateway/src/http/auth/mod.rs BackendAuthKind::Key: "
    "'Send a configured secret value, or a value computed from the request, to the backend.'",
    "agentgateway v1.7.0 examples/llm-telemetry/tracing/phoenix.yaml: backendAuth: key: "
    "$GEMINI_API_KEY",
]
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _fp(t):
    return "sha256:" + hashlib.sha256(t.encode()).hexdigest()[:12] if t else t


def redact(obj):
    """JSON-encode-safe copy of ``obj`` with every JWT-shaped string fingerprinted."""
    text = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    out = _JWT_RE.sub(lambda m: _fp(m.group(0)), text)
    return out if isinstance(obj, str) else json.loads(out)


# ------------------------------------------------------------------ ports
def required_scratch():
    """HANDLE_SCRATCH is required (it holds the AS key and run copies): no fallback."""
    path = os.environ.get("HANDLE_SCRATCH")
    if not path:
        sys.exit("REFUSING: HANDLE_SCRATCH is not set (no temp-dir fallback)")
    if not os.path.isdir(path):
        sys.exit(f"REFUSING: HANDLE_SCRATCH={path} is not an existing directory")
    return path


def _port_block():
    raw = os.environ.get("HANDLE_PORT_BLOCK", "4200-4299")
    lo, hi = (int(x) for x in raw.split("-", 1))
    return lo, hi


def required_port(name):
    """Read an explicit port; refuse defaults, forbidden ports and out-of-block ports."""
    raw = os.environ.get(name)
    if not raw:
        sys.exit(f"REFUSING: {name} is not set (every port must be explicit)")
    port = int(raw)
    lo, hi = _port_block()
    if port in FORBIDDEN_PORTS:
        sys.exit(f"REFUSING: {name}={port} is a forbidden port ({sorted(FORBIDDEN_PORTS)})")
    if not lo <= port <= hi:
        sys.exit(f"REFUSING: {name}={port} is outside the port block {lo}-{hi}")
    return port


def _port_free(port):
    # SO_REUSEADDR like the servers themselves: TIME_WAIT from a previous run
    # is not "in use"; a live listener still is.
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        s.listen(1)
        return True
    except OSError:
        return False
    finally:
        s.close()


def _wait_port(port, proc=None, timeout=90, tail=lambda: ""):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError("process exited early:\n" + tail())
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError(f"port {port} never opened:\n" + tail())


class _Proc:
    """A child process whose output is kept in memory, printed only redacted."""

    def __init__(self, argv, cwd, env=None):
        self.argv = argv
        self.lines = []
        self.proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, bufsize=1)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))

    def tail(self, n=30):
        return "\n".join(redact(l) for l in self.lines[-n:])

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)


# ------------------------------------------------------------ agentgateway
class AgentGateway:
    name = "agentgateway"

    def __init__(self, ports, as_url):
        self.ports = ports
        self.as_url = as_url
        self.bin = os.environ.get("AGW_BIN") or sys.exit("REFUSING: AGW_BIN not set")
        variant = os.environ.get("HANDLE_AGW_CONFIG", "per-user")
        if variant not in AGW_VARIANTS:
            sys.exit(f"REFUSING: HANDLE_AGW_CONFIG must be one of {AGW_VARIANTS}")
        self.variant = variant
        self.config_path = os.path.join(_HERE, "agentgateway", f"handle-{variant}.yaml")
        with open(self.config_path) as f:
            self.config_template = f.read()
        text = self.config_template
        for key, val in (("GW_PORT", ports["gateway"]), ("ADMIN_PORT", ports["agw_admin"]),
                         ("AS_PORT", ports["as"]), ("UPSTREAM_PORT", ports["upstream"])):
            text = text.replace("{{" + key + "}}", str(val))
        if "{{" in text:
            sys.exit("REFUSING: unsubstituted placeholder left in the agentgateway config")
        for bad in FORBIDDEN_PORTS:
            if re.search(rf"\b{bad}\b", text):
                sys.exit(f"REFUSING: the substituted config mentions forbidden port {bad}")
        self.config_text = text
        self.url = f"http://127.0.0.1:{ports['gateway']}/mcp"
        self.proc = None
        self.version = json.loads(subprocess.check_output([self.bin, "--version"]).decode())
        self.upstream_auth = {
            "token-exchange": ("token exchange: backendAuth.oauthTokenExchange swaps the "
                               "validated user JWT (subject) and the agent's x-actor-token "
                               "(actor) at the local AS for a token with aud="
                               f"{EXCHANGE_AUDIENCE} and act=the agent"),
            "per-user": ("per-user passthrough: backendAuth.passthrough forwards the "
                         "validated user JWT unchanged (a token-passthrough config)"),
            "shared-credential": ("shared: backendAuth.key sends ONE static credential "
                                  "for every user"),
        }[variant]
        # The practice server keys callers on the raw Authorization header,
        # except behind token exchange, where every request may carry a freshly
        # exchanged token: there it keys on the token's (orig_iss or iss, sub).
        self.upstream_identity_from = "jwt" if variant == "token-exchange" else "header"

    def start(self):
        scratch = required_scratch()
        # agentgateway writes a generated session key into its config file on
        # startup: run from a throwaway copy, never the repo file.
        self._tmp = tempfile.mkdtemp(prefix="handle-agw-", dir=scratch)
        run_cfg = os.path.join(self._tmp, "config.yaml")
        with open(run_cfg, "w") as f:
            f.write(self.config_text)
        self.proc = _Proc([self.bin, "-f", run_cfg], cwd=self._tmp)
        _wait_port(self.ports["gateway"], self.proc.proc, 30, self.proc.tail)
        print(f"agentgateway {self.version.get('version')} up @ {self.url} "
              f"(pid {self.proc.proc.pid}, config {self.variant})")

    def token_for(self, as_, sub):
        return as_.issue_user_token(sub, audience="agentgateway-api")

    def extra_headers(self, as_):
        """Headers every client request carries besides the user's bearer."""
        if self.variant == "token-exchange":
            return {"x-actor-token": as_.issue_client_token(ACTOR_CLIENT)}
        return {}

    def upstream_identity(self, sub, token):
        """The identity the practice server will key this user on."""
        if self.variant == "token-exchange":
            return _fp(f"jwt:{AS_ISSUER}|{sub}")
        return _fp(f"Bearer {token}")

    def tool_name(self, client):
        return "start_job"

    def stop(self):
        if self.proc:
            self.proc.stop()
        if getattr(self, "_tmp", None):
            shutil.rmtree(self._tmp, ignore_errors=True)

    def record(self):
        return {
            "gateway_version_full": self.version,
            "gateway_config_path": os.path.relpath(self.config_path, _REPO),
            "gateway_config_template_sha256": hashlib.sha256(
                self.config_template.encode()).hexdigest(),
            # Static credential values (backendAuth.key) as fingerprints only.
            "gateway_config_run": re.sub(
                r'(value:\s*")([^"]+)(")',
                lambda m: m.group(1) + _fp(m.group(2)) + m.group(3), self.config_text),
            "upstream_auth": self.upstream_auth,
            "upstream_identity_from": self.upstream_identity_from,
            "backendauth_key_documented": BACKENDAUTH_KEY_DOCS,
            "source_evidence": [
                "agentgateway v1.7.0 crates/agentgateway/src/mcp/session.rs:736-756: "
                "GetTask/UpdateTask/CancelTask requests are parsed, authorized only by the "
                "configured static mcpAuthorization policy (authorize_task_request, "
                "session.rs:256-280: ResourceType::Task(target, taskId) against CEL rules), "
                "then sent to the upstream (send_single). No binding of a taskId to the "
                "user who created it.",
                "handler.rs:205-237: taskIds in CreateTaskResult/GetTaskResult are "
                "rewritten to '<target>+<id>' only when there is no default target "
                "(multiplexing); with one target they pass through unchanged.",
                "streamablehttp.rs:428-441: tasks/* are name-bearing; the Mcp-Name header "
                "must equal params.taskId, else -32020 'invalid MCP routing header'.",
            ],
        }


# ------------------------------------------------------------ ContextForge
class ContextForge:
    name = "contextforge"

    def __init__(self, ports, as_url):
        self.ports = ports
        self.as_url = as_url
        self.home = os.environ.get("CF_HOME") or sys.exit("REFUSING: CF_HOME not set")
        self.base = f"http://127.0.0.1:{ports['gateway']}"
        self.url = None
        self.proc = None
        self.version = None
        self.upstream_auth = "none configured on the registered gateway (trial only)"

    def _env(self):
        env = dict(os.environ)
        with open(os.path.join(self.home, ".env")) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k] = v
        env["HOST"] = "127.0.0.1"
        env["PORT"] = str(self.ports["gateway"])  # explicit; never CF's 4444 default
        return env

    def start(self):
        env = self._env()
        os.environ.update({k: v for k, v in env.items() if k not in os.environ})
        self.proc = _Proc([sys.executable, "-m", "mcpgateway"], cwd=self.home, env=env)
        _wait_port(self.ports["gateway"], self.proc.proc, 120, self.proc.tail)
        print(f"ContextForge up @ {self.base} (pid {self.proc.proc.pid})")

    def admin_token(self):
        out = subprocess.check_output(
            [sys.executable, "-m", "mcpgateway.utils.create_jwt_token",
             "-u", "admin@example.com", "--admin", "-e", "600"],
            cwd=self.home, env=self._env(), stderr=subprocess.DEVNULL)
        return out.decode().strip().splitlines()[-1]

    def api(self, method, path, tok, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            return e.code, {"_error": e.read().decode("utf-8", "replace")[:500]}

    def register(self, upstream_url):
        tok = self.admin_token()
        st, ver = self.api("GET", "/version", tok)
        self.version = (ver or {}).get("app", {}).get("version") if isinstance(ver, dict) else None
        # Our own disposable CF copy: drop earlier registrations of this
        # upstream URL (CF refuses a duplicate URL in the public scope).
        st, gws = self.api("GET", "/v1/gateways", tok)
        allg = gws if isinstance(gws, list) else (gws.get("data", []) if isinstance(gws, dict) else [])
        port = str(self.ports["upstream"])
        for g in allg:
            if str(g.get("name", "")).startswith("handle-") and f":{port}/" in str(g.get("url")):
                self.api("DELETE", f"/v1/gateways/{g['id']}", tok)
        gw = {"name": f"handle-{int(time.time())}", "url": upstream_url,
              "transport": "STREAMABLEHTTP", "visibility": "public"}
        st, resp = self.api("POST", "/v1/gateways", tok, gw)
        print(f"register gateway -> HTTP {st} {redact(json.dumps(resp))[:300]}")
        if st >= 300:
            raise RuntimeError("ContextForge refused the gateway registration")
        gid = resp.get("id")
        mine = []
        for _ in range(15):
            st, tools = self.api("GET", "/v1/tools", tok)
            allt = tools if isinstance(tools, list) else tools.get("data", [])
            mine = [t for t in allt if gid in (t.get("gatewayId"), t.get("gateway_id"))]
            if mine:
                break
            time.sleep(2)
        if not mine:
            raise RuntimeError("ContextForge discovered no tools from the practice server")
        st, srv = self.api("POST", "/v1/servers", tok, {"server": {
            "name": f"handle-vs-{int(time.time())}", "visibility": "public",
            "associated_tools": [mine[0]["id"]]}})
        print(f"create virtual server -> HTTP {st}")
        if st >= 300:
            raise RuntimeError(f"virtual server: {srv}")
        self.url = f"{self.base}/servers/{srv['id']}/mcp"
        self._tool = mine[0].get("name")
        self._admin = tok
        print(f"ContextForge {self.version}: gateway={gid} server={srv['id']} tool={self._tool}")

    variant = None
    upstream_identity_from = "header"

    def extra_headers(self, as_):
        return {}

    def upstream_identity(self, sub, token):
        return _fp(f"Bearer {token}")

    def token_for(self, as_, sub):
        # Trial stage only: the platform admin JWT (CF's own login), so the
        # trial isolates "does it forward tasks", not inbound auth.
        return self._admin

    def tool_name(self, client):
        return self._tool

    def stop(self):
        if self.proc:
            self.proc.stop()

    def record(self):
        return {
            "cf_home": "<scratch>", "upstream_auth": self.upstream_auth,
            "source_evidence": [
                "mcp-contextforge-gateway 1.1.1 mcpgateway/transports/"
                "streamablehttp_transport.py:4030-4040: the MCP server registers handlers "
                "for server/discover, tools/list, tools/call, prompts/*, resources/*, "
                "completion/complete, logging/setLevel only; no tasks/get, tasks/update "
                "or tasks/cancel handler, so the SDK answers -32601.",
                "streamablehttp_transport.py:2104-2130: tools/call returns a "
                "types.CallToolResult (normal mode converts the upstream ToolResult; "
                "direct_proxy returns the raw CallToolResult); no CreateTaskResult path.",
                "No reference to 'io.modelcontextprotocol/tasks', 'tasks/get' or "
                "'CreateTaskResult' anywhere under mcpgateway/ (grep); the only "
                "'tasks/get'/'tasks/cancel' strings are the A2A protocol routes "
                "(main.py:10455-10530, services/a2a_protocol.py:40-42), not MCP.",
            ],
        }


# ------------------------------------------------------------------ trial
def _try(fn):
    try:
        return {"result": redact(fn())}
    except JSONRPCError as e:
        return {"error": {"code": e.code, "message": redact(str(e.message))}}
    except Exception as e:  # noqa: BLE001
        return {"transport_failure": redact(str(e))[:400]}


def trial(gw, as_, upstream_state):
    """One honest forwarding trial (no probe, one identity)."""
    tok = gw.token_for(as_, "alice")
    client = MCPClient(TasksHTTPTransport(gw.url, headers={"Authorization": f"Bearer {tok}",
                                                           **gw.extra_headers(as_)},
                                     modern=True,
                                     client_capabilities=CLIENT_CAPABILITIES_WITH_TASKS))
    steps = []
    client.initialize()  # synthesized locally by the modern transport
    tools = _try(lambda: client.list_tools())
    steps.append({"request": "tools/list", "response": tools})
    tool = gw.tool_name(client)
    created = _try(lambda: client.call_tool(tool, {"marker": "st-trial-marker", "kind": "complete"}))
    steps.append({"request": f"tools/call {tool} kind=complete (tasks extension declared)",
                  "response": created})
    task_id = None
    res = created.get("result")
    if isinstance(res, dict) and res.get("resultType") == "task":
        task_id = res.get("taskId")
    probe_id = task_id or "st-trial-no-task"
    time.sleep(0.2)
    for method, params in (
        ("tasks/get", {"taskId": probe_id}),
        ("tasks/update", {"taskId": probe_id, "inputResponses": {"q1": {"value": "x"}}}),
        ("tasks/cancel", {"taskId": probe_id}),
    ):
        steps.append({"request": f"{method} {probe_id if task_id else '(no taskId was returned; placeholder id)'}",
                      "response": _try(lambda: client._call(method, params))})
    seen = list(upstream_state.seen)
    forwards = {
        "create_task_result_passed_through": task_id is not None,
        "tasks_get_reached_upstream": any(s["method"] == "tasks/get" for s in seen),
        "tasks_update_reached_upstream": any(s["method"] == "tasks/update" for s in seen),
        "tasks_cancel_reached_upstream": any(s["method"] == "tasks/cancel" for s in seen),
        "tasks_capability_in_upstream_meta_on_tools_call": any(
            s["method"] == "tools/call" and s["tasks_ext_declared"] for s in seen),
    }
    # Did the trial complete? Every call must have produced a server answer
    # (a JSON-RPC result or error, also inside an HTTP error body), and the
    # gateway must have actually reached the upstream with tools/call -
    # otherwise "does not forward" could not be told from "could not run".
    def answered(resp):
        if "result" in resp or "error" in resp:
            return True
        body = resp.get("transport_failure", "")
        return '"jsonrpc"' in body and ('"error"' in body or '"result"' in body)

    problems = [f"no server answer to {st['request'].split(' ', 1)[0]}: "
                f"{json.dumps(st['response'])[:200]}"
                for st in steps if not answered(st["response"])]
    if "result" not in created:
        problems.append("tools/call did not return a result")
    if not any(s["method"] == "tools/call" for s in seen):
        problems.append("the upstream never received tools/call through the gateway")
    return {"steps": steps, "upstream_seen": seen, "forwarding": forwards,
            "completed": not problems, "problems": problems}


# ------------------------------------------------------------------ main
def main():
    gateway = os.environ.get("HANDLE_GATEWAY") or sys.exit("REFUSING: HANDLE_GATEWAY not set")
    stage = os.environ.get("HANDLE_STAGE", "trial")
    up_mode = os.environ.get("HANDLE_UPSTREAM_MODE", "safe")
    scratch = required_scratch()
    ports = {"as": required_port("HANDLE_AS_PORT"),
             "gateway": required_port("HANDLE_GW_PORT"),
             "upstream": required_port("HANDLE_UPSTREAM_PORT")}
    if gateway == "agentgateway":
        ports["agw_admin"] = required_port("HANDLE_AGW_ADMIN_PORT")
    if len(set(ports.values())) != len(ports):
        sys.exit(f"REFUSING: ports must be distinct: {ports}")
    for name, port in ports.items():
        if not _port_free(port):
            sys.exit(f"REFUSING: port {port} ({name}) is already in use")
    as_url = f"http://127.0.0.1:{ports['as']}"
    upstream_url = f"http://127.0.0.1:{ports['upstream']}/mcp"
    print(f"=== handle gate: {gateway} stage={stage} upstream={up_mode} ports={ports} ===")

    as_ = LocalAS(issuer=AS_ISSUER, key_path=os.path.join(scratch, "handle_as_key.pem"))
    as_srv = as_.serve(port=ports["as"])
    threading.Thread(target=as_srv.serve_forever, daemon=True).start()
    # Probe stage: the broken fixture (leaky) FIRST, then the requested mode,
    # both behind the SAME running gateway process; the practice server's mode
    # is switched IN PLACE between them (TasksState.reset). OK is allowed only
    # if the fixture leaked.
    modes = [up_mode] if stage == "trial" else (
        ["leaky"] if up_mode == "leaky" else ["leaky", up_mode])
    upstream = None

    def start_upstream(mode):
        srv = build_server(mode, port=ports["upstream"],
                           identity_from=gw.upstream_identity_from)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    gw = AgentGateway(ports, as_url) if gateway == "agentgateway" else ContextForge(ports, as_url)
    base = {
        "probe": "handle", "stage": stage, "gateway": gateway,
        "cosai": COSAI,
        "ports": ports, "as_url": as_url, "upstream_url": upstream_url,
        "client_transport": "strangertest.handle.TasksHTTPTransport (HTTPTransport modern=True "
                            "+ Mcp-Name=taskId on tasks/*), MCP 2026-07-28, tasks "
                            "extension declared in _meta clientCapabilities",
    }
    results = {}
    try:
        upstream = start_upstream(modes[0])
        gw.start()
        if gateway == "contextforge":
            gw.register(upstream_url)
        base["gateway_url"] = gw.url
        base["gateway_version"] = (gw.version.get("version") if isinstance(gw.version, dict)
                                   else gw.version)
        base["gateway_pid"] = gw.proc.proc.pid if gw.proc else None
        base.update(gw.record())
        for i, mode in enumerate(modes):
            if i:
                # Switch the SAME server's mode in place. Restarting it on the
                # same port is wrong: the gateway's pooled keep-alive
                # connections keep reaching the old server's handler threads
                # (observed: a "safe" run answered entirely by the old leaky
                # state, with the new server seeing zero requests).
                upstream.state.reset(mode)
            out = dict(base, upstream=f"strangertest.practice_handle_http mode={mode}",
                       upstream_mode=mode)
            if stage == "trial":
                out["trial"] = trial(gw, as_, upstream.state)
                fwd = out["trial"]["forwarding"]
                steps = {st["request"].split(" ", 1)[0]: st["response"]
                         for st in out["trial"]["steps"]}
                out["methods"] = {}
                for m in ("get", "update", "cancel"):
                    reached = fwd[f"tasks_{m}_reached_upstream"]
                    resp = steps.get(f"tasks/{m}", {})
                    out["methods"][m] = {
                        "grade": None if (reached and fwd["create_task_result_passed_through"])
                        else "INCONCLUSIVE",
                        "detail": (f"tasks/{m} reached the upstream" if reached else
                                   f"tasks/{m} never reached the upstream; gateway answered "
                                   f"{json.dumps(resp)[:200]}"),
                    }
                out["observations"] = [
                    f"{k}: {v}" for k, v in fwd.items()]
                out["controls"] = {
                    "single_identity_trial": "one user, own task only; no A/B probe run",
                    "upstream_supports_tasks_directly": (
                        "the same practice server returns CreateTaskResult and serves "
                        "tasks/* when called directly (tests/test_handle.py)"),
                }
                if all(fwd.values()):
                    out["grade"] = None
                    out["grade_note"] = ("trial only: the gateway forwards the tasks "
                                         "extension; run HANDLE_STAGE=probe for a grade")
                else:
                    out["grade"] = "INCONCLUSIVE"
                    out["reason"] = ("the gateway does not forward the MCP tasks extension: "
                                     + ", ".join(k for k, v in fwd.items() if not v)
                                     + " (see trial.steps / trial.upstream_seen)")
                print(json.dumps(fwd, indent=2))
                for st in out["trial"]["steps"]:
                    print(f"  {st['request']}\n    -> {json.dumps(st['response'])[:400]}")
            else:
                out.update(run_probe(gw, as_, upstream, mode))
            out["upstream_protocol_versions_seen"] = sorted(
                {str(x.get("protocol_header")) for x in upstream.state.seen})
            out["upstream_meta_protocol_versions_seen"] = sorted(
                {str(x.get("meta_protocol")) for x in upstream.state.seen})
            results[mode] = out
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {redact(str(e))}")
        if gw.proc:
            print("--- gateway log tail (redacted) ---\n" + gw.proc.tail())
        raise
    finally:
        gw.stop()
        if upstream is not None:
            upstream.shutdown(); upstream.server_close()
        as_srv.shutdown(); as_srv.server_close()

    problems = {mode: [] for mode in results}
    for mode, out in results.items():
        if stage == "trial" and not out["trial"]["completed"]:
            problems[mode] += [f"trial could not complete: {p}" for p in out["trial"]["problems"]]
            out["grade"] = "INCONCLUSIVE"
            out["reason"] = "the trial could not complete: " + "; ".join(out["trial"]["problems"])
        tx = out.get("token_exchange_at_upstream")
        if stage == "probe" and tx is not None and not tx.get("observed"):
            problems[mode].append(f"[{mode}] token exchange not observed at the upstream: "
                                  f"{tx}")
        if stage == "probe" and out.get("probe_grade_unattributable") is not None:
            problems[mode].append(f"[{mode}] the upstream received no tools/call: "
                                  "cannot observe")
    if stage == "probe":
        fixture = results["leaky"]
        detected = fixture.get("probe_grade") == "LEAK"
        for mode, out in results.items():
            out["controls"] = {
                "in_probe": ("strangertest.handle positive controls passed or the method "
                             "would be INCONCLUSIVE: A reads its own three tasks (marker "
                             "exact-match), B starts/reads/updates/cancels its OWN tasks "
                             "through the same gateway, drift check on A's task before B "
                             "acts, nonexistent-taskId comparison"),
                "broken_fixture_through_same_gateway": {
                    "upstream_mode": "leaky", "probe_grade": fixture.get("probe_grade"),
                    "detected": detected, "gateway_pid": base.get("gateway_pid")},
                "distinct_inbound_users": True,
            }
            out["grade"] = out["probe_grade"]
            if not detected:
                problems[mode].append(
                    f"the leaky fixture was not LEAK (got {fixture.get('probe_grade')}) "
                    "through the same gateway")
            if mode != "leaky" and out["grade"] == "OK" and not detected:
                out["grade"] = "INCONCLUSIVE"
                out["reason"] = ("the broken (leaky) fixture was not reported LEAK through "
                                 "the same gateway, so OK is not allowed")

    # What the grade is ABOUT. A shared-credential run is a deployment we
    # configured, not the gateway's default per-user path: its LEAK stays a
    # LEAK but must not count toward the gateway's own verdict.
    variant = gw.variant if gateway == "agentgateway" else None
    for mode, out in results.items():
        out["agw_config"] = variant
        if gateway == "contextforge":
            out["grade_subject"] = ("gateway: ContextForge 1.1.1 (default settings, "
                                    "STREAMABLEHTTP gateway) in front of the practice "
                                    f"task server ({mode})")
            out["counts_toward_gateway_verdict"] = True
        elif variant == "shared-credential":
            out["grade_subject"] = ("deployment: agentgateway 1.7.0 configured by us with "
                                    "backendAuth.key (one static upstream credential for "
                                    "all users), a documented option: configuration risk")
            out["counts_toward_gateway_verdict"] = False
        elif variant == "token-exchange":
            out["grade_subject"] = ("gateway path: agentgateway 1.7.0 configured by us with "
                                    "jwtAuth + backendAuth.oauthTokenExchange (RFC 8693 "
                                    "delegation, the compliant config) in front of the "
                                    f"practice task server ({mode})")
            out["counts_toward_gateway_verdict"] = True
        else:
            out["grade_subject"] = ("gateway path: agentgateway 1.7.0 configured by us with "
                                    "jwtAuth + backendAuth.passthrough (per-user upstream "
                                    f"identity) in front of the practice task server ({mode})")
            # Per-user, but it forwards the user's own token: the CoSAI
            # no-token-passthrough rule is broken by the config itself.
            out["counts_toward_gateway_verdict"] = False
            out["violates_no_token_passthrough"] = True
        out["run_valid"] = not problems[mode]
        out["run_problems"] = problems[mode]

    runs_dir = os.path.join(_HERE, "runs")
    os.makedirs(runs_dir, exist_ok=True)
    tag = (f"-{gw.variant}" if gateway == "agentgateway" else "")
    stamp = int(time.time())
    for mode, out in results.items():
        path = os.path.join(runs_dir, f"{gateway}-handle-{stage}{tag}-{mode}-{stamp}.json")
        with open(path, "w") as f:
            json.dump(redact(out), f, indent=2)
        print(f"[{mode}] grade={out.get('grade')} run_valid={out['run_valid']} "
              f"saved run -> {path}")
    bad = [p for ps in problems.values() for p in ps]
    for p in dict.fromkeys(bad):
        print(f"ERROR: {p}", file=sys.stderr)
    if bad:
        sys.exit(1)


def run_probe(gw, as_, upstream, up_mode):
    tokens = {"A": gw.token_for(as_, "alice"), "B": gw.token_for(as_, "bob")}
    if tokens["A"] == tokens["B"]:
        # Same inbound credential = same user: a "leak" would be meaningless.
        sys.exit("REFUSING: A and B would present the same inbound credential")

    extra = gw.extra_headers(as_)

    def ident(label):
        return Identity(label=label, connect=lambda: MCPClient(TasksHTTPTransport(
            gw.url, headers={"Authorization": f"Bearer {tokens[label]}", **extra},
            modern=True, client_capabilities=CLIENT_CAPABILITIES_WITH_TASKS)))

    plan = TaskPlan(tool=gw.tool_name(None))
    report = run_handle_probe(gw.url, ident("A"), ident("B"), plan=plan,
                              ready_timeout=10.0, settle_timeout=1.5, drift_window=0.5)
    print(report.summary())
    d = report.to_dict()
    seen = upstream.state.seen
    ids = sorted({s["identity"] for s in seen if s["method"] == "tools/call"})
    subs = {"A": "alice", "B": "bob"}
    fp = {k: gw.upstream_identity(subs[k], v) for k, v in tokens.items()}
    inbound_fp = {k: _fp(f"Bearer {v}") for k, v in tokens.items()}
    exchange = None
    if getattr(gw, "variant", None) == "token-exchange":
        # Was the token at the upstream really an exchanged one? Never the
        # user's own token; aud = the upstream; act = the agent.
        calls = [x for x in seen if x["method"] == "tools/call" or
                 str(x["method"]).startswith("tasks/")]
        claims = [x.get("claims") or {} for x in calls]
        exchange = {
            "upstream_calls_checked": len(calls),
            "user_token_reached_upstream": any(
                x.get("token") in inbound_fp.values() for x in calls),
            "all_aud_is_upstream": all(c.get("aud") in (EXCHANGE_AUDIENCE, [EXCHANGE_AUDIENCE])
                                       for c in claims) and bool(claims),
            "all_act_is_agent": all(c.get("act_sub") == ACTOR_CLIENT for c in claims)
                                and bool(claims),
            "subjects_at_upstream": sorted({str(c.get("sub")) for c in claims}),
            "distinct_tokens_at_upstream": len({x.get("token") for x in calls}),
        }
        exchange["observed"] = (not exchange["user_token_reached_upstream"]
                                and exchange["all_aud_is_upstream"]
                                and exchange["all_act_is_agent"])
    upstream_ids_of = {k: (v in ids) for k, v in fp.items()}
    distinct = len(ids) >= 2
    observations = list(d["observations"])
    if not ids:
        # Answers came from somewhere other than this upstream (in this mode):
        # nothing here can be attributed to it.
        return {"probe_grade": "INCONCLUSIVE",
                "reason": "the upstream in this mode received no tools/call: the "
                          "responses did not come from it",
                "detail": d["detail"], "probe_grade_unattributable": d["grade"],
                "methods": d["methods"], "observations": observations}
    if not distinct:
        observations.append(
            "the upstream saw ONE caller identity for A and B (one shared credential): the "
            "upstream cannot tell A from B, so its per-owner check cannot apply")
    # Who enforced: if B was refused, was B's request even forwarded upstream?
    enforcement = {}
    up_a, up_b = fp["A"], fp["B"]
    if not distinct and ids:
        up_a = up_b = ids[0]  # one shared upstream identity
    for m in ("get", "update", "cancel"):
        r = d["methods"].get(m, {})
        # B's request naming a task A created: did the gateway forward it?
        foreign = [s for s in seen if s["method"] == f"tasks/{m}"
                   and s["identity"] == up_b and s.get("task_owner") == up_a]
        if distinct:
            forwarded = bool(foreign)
            who = ("upstream (B's request on A's task reached it as B; the gateway "
                   "added no check)" if forwarded and r.get("grade") == "OK" else
                   "gateway (B's request on A's task never reached the upstream)"
                   if not forwarded and r.get("grade") == "OK" else
                   "nobody (B's request reached the upstream as B and was served)"
                   if r.get("grade") == "LEAK" else "not determined")
        else:
            forwarded = None  # B is indistinguishable from A at the upstream
            who = ("nobody: the upstream received B's request under the shared "
                   "credential, indistinguishable from A" if r.get("grade") == "LEAK"
                   else "not determined")
        enforcement[m] = {"grade": r.get("grade"), "detail": r.get("detail"),
                          "b_request_on_a_task_reached_upstream_as_b": forwarded,
                          "enforced_by": who}
    return {
        "probe_grade": d["grade"], "detail": d["detail"], "summary": report.summary(),
        "methods": d["methods"], "per_method": enforcement,
        "leaked_methods": d.get("leaked_methods", []),
        "observations": observations,
        "identity_fingerprints": {"A_inbound": inbound_fp["A"], "B_inbound": inbound_fp["B"],
                                  "A_upstream": fp["A"], "B_upstream": fp["B"]},
        "token_exchange_at_upstream": exchange,
        "upstream_identities_on_tools_call": ids,
        "upstream_saw_inbound_token_as_identity": upstream_ids_of,
        "upstream_distinguishes_users": distinct,
        "upstream_methods_seen": [(s["method"], s["identity"], s.get("task_owner"),
                                   s["tasks_ext_declared"]) for s in seen],
    }


if __name__ == "__main__":
    main()
