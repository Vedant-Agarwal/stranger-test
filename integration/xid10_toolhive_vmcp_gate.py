"""XID-10 same-user-credentials gate against ToolHive's Virtual MCP (vMCP).

The companion to :mod:`integration.xid10_toolhive_gate` (the standalone `thv run`
proxy). This drives the CVE-2026-110195-class same-user-credentials probe through
a ToolHive **vMCP** server (`thv vmcp serve`), because vMCP is where ToolHive's
token-exchange cache lives in source
(`pkg/vmcp/cache/cache.go`: key `{backend}:{hash(subject_token)}:{audience}`).

vMCP aggregates a ToolHive GROUP, so the lifecycle needs a shared HOME:
  1. create a group,
  2. register the recording upstream as a remote backend workload in it
     (`thv run <url> --group`),
  3. `thv vmcp serve --config <inline token-exchange config>`.

incomingAuth MUST be oidc: with `anonymous`, vMCP has no identity and the
exchange fails ("identity has no token"). So the caller presents a user JWT,
vMCP validates it (oidc, loopback AS allowed via jwksAllowPrivateIp +
insecureAllowHttp), and exchanges it per backend.

OBSERVATION recorded by this gate: on the `thv vmcp serve` path, ToolHive
re-exchanges on every request (a fresh backend session per request), so the
source-level token cache is NOT exercised in this mode — each read mints a
distinct upstream token even for the same credential. The same-user-credentials
probe therefore grades OK with cache_hit_observed=False ("caching not observed in
this run"). This is an observation of this deployment mode, NOT a bug: the
Kubernetes operator deployment (where backend sessions may persist) was NOT
tested here. subjectProviderName (exchange a stored upstream token) is NOT run —
it requires ToolHive's embedded authorization server.

Ports: AS_BASE, UPSTREAM_PORT, BACKEND_PORT, VMCP_PORT required, 4600-4699,
never 4000/4444/8790. Tokens as sha256 fingerprints only; secrets never.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlencode, urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import jwt  # noqa: F401
    from local_as import LocalAS  # noqa: F401
except Exception as exc:  # pragma: no cover
    print(f"ERROR: cannot run the vMCP gate: needs pyjwt[crypto] ({exc})", file=sys.stderr)
    sys.exit(2)

from xid10_litellm_gate import Recorder, fp, redact, _get, as_issue, UPSTREAM_AUD, _JWT_RE  # noqa: E402
from xid10_toolhive_gate import thv_version, PINNED_VERSION, USER_AUD, CLIENT_ID, save_checked  # noqa: E402
from strangertest.credcache import (  # noqa: E402
    Credential, run_same_user_credentials_probe, FAIL, OK, INCONCLUSIVE,
)
from strangertest.delegate import UpstreamCall, make_nonce  # noqa: E402
from strangertest.mcp_client import MCPClient  # noqa: E402
from strangertest.transports import HTTPTransport  # noqa: E402

FORBIDDEN_PORTS = {4000, 4444, 8790}
PORT_RANGE = range(4600, 4700)
GROUP = "xid10vmcp"


def _port(name):
    raw = os.environ.get(name)
    if not raw:
        raise SystemExit(f"ERROR: set {name} explicitly")
    port = int(raw)
    if port in FORBIDDEN_PORTS or port not in PORT_RANGE:
        raise SystemExit(f"ERROR: refusing port {port} for {name}: must be 4600-4699")
    return port


def require_endpoints():
    as_base = os.environ.get("AS_BASE") or ""
    u = urlparse(as_base)
    if u.hostname != "127.0.0.1" or not u.port:
        raise SystemExit("ERROR: AS_BASE must be http://127.0.0.1:<46xx>")
    os.environ["_AS_PORT"] = str(u.port)
    ports = {"as": _port("_AS_PORT"), "upstream": _port("UPSTREAM_PORT"),
             "backend": _port("BACKEND_PORT"), "vmcp": _port("VMCP_PORT")}
    used = list(ports.values())
    if len(set(used)) != len(used):
        raise SystemExit(f"ERROR: ports overlap: {used}")
    return as_base.rstrip("/"), ports


class VMCP:
    """A ToolHive vMCP server over a one-backend group, with inline RFC 8693
    token-exchange outgoing auth. Shared isolated HOME for the whole lifecycle."""

    def __init__(self, thv_bin, as_base, ports):
        self.bin = thv_bin
        self.as_base = as_base
        self.ports = ports
        self.client_secret = os.environ.get("TH_CLIENT_SECRET") or secrets.token_hex(16)
        self.name = GROUP + "-" + secrets.token_hex(2)
        self.url = f"http://127.0.0.1:{ports['vmcp']}/mcp"
        self._tmp = tempfile.mkdtemp(prefix="xid10-vmcp-")
        self._serve = None
        self.serve_lines = []
        self.config_text = None

    def _env(self):
        return dict(os.environ, HOME=self._tmp,
                    XDG_CONFIG_HOME=os.path.join(self._tmp, "cfg"),
                    XDG_DATA_HOME=os.path.join(self._tmp, "data"),
                    XDG_STATE_HOME=os.path.join(self._tmp, "state"),
                    XDG_CACHE_HOME=os.path.join(self._tmp, "cache"))

    def _thv(self, *args, timeout=90):
        p = subprocess.run([self.bin, *args], env=self._env(), capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")

    def _config(self):
        return f"""name: {self.name}
groupRef: {GROUP}
incomingAuth:
  type: oidc
  oidc:
    issuer: https://local-as.test
    clientId: vmcp
    audience: {USER_AUD}
    jwksUrl: {self.as_base}/jwks
    jwksAllowPrivateIp: true
    insecureAllowHttp: true
outgoingAuth:
  source: inline
  backends:
    notes:
      type: token_exchange
      tokenExchange:
        tokenUrl: {self.as_base}/token
        audience: {UPSTREAM_AUD}
        clientId: {CLIENT_ID}
        clientSecret: {self.client_secret}
        scopes:
          - read:notes
        subjectTokenType: access_token
aggregation:
  conflictResolution: prefix
  conflictResolutionConfig:
    prefixFormat: "{{workload}}_"
backends:
  - name: notes
    url: http://127.0.0.1:{self.ports['backend']}
    transport: streamable-http
"""

    def start(self, timeout=90):
        rc, out = self._thv("group", "create", GROUP)
        rc, out = self._thv("run", f"http://127.0.0.1:{self.ports['upstream']}", "--name", "notes",
                            "--group", GROUP, "--transport", "streamable-http",
                            "--proxy-port", str(self.ports["backend"]), "--host", "127.0.0.1")
        if rc != 0:
            raise RuntimeError("backend registration failed:\n" + redact(out))
        time.sleep(3)
        self.config_text = self._config()
        cfg = os.path.join(self._tmp, "vmcp.yaml")
        with open(cfg, "w") as f:
            f.write(self.config_text)
        rc, out = self._thv("vmcp", "validate", "--config", cfg)
        if rc != 0:
            raise RuntimeError("vmcp validate failed:\n" + redact(out))
        self._serve = subprocess.Popen(
            [self.bin, "vmcp", "serve", "--config", cfg, "--port", str(self.ports["vmcp"]),
             "--host", "127.0.0.1"], env=self._env(), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1)
        import threading
        threading.Thread(target=self._pump, daemon=True).start()
        probe = as_issue(self.as_base, "readyprobe", aud=USER_AUD)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._serve.poll() is not None:
                raise RuntimeError("vmcp serve exited:\n" + self.tail())
            try:
                c = MCPClient(HTTPTransport(self.url, headers={"Authorization": f"Bearer {probe}"},
                                           modern=True))
                c.initialize()
                if c.list_tools():
                    try:
                        c.close()
                    except Exception:  # noqa: BLE001
                        pass
                    return self
            except Exception:  # noqa: BLE001
                pass
            time.sleep(1)
        raise RuntimeError("vMCP did not become ready:\n" + self.tail())

    def _pump(self):
        for line in self._serve.stdout:
            self.serve_lines.append(line.rstrip("\n"))

    def tail(self, n=40):
        return "\n".join(redact(l) for l in self.serve_lines[-n:])

    def client(self, token):
        return MCPClient(HTTPTransport(self.url, headers={"Authorization": f"Bearer {token}"},
                                       modern=True))

    def discover_tool(self, token):
        c = self.client(token)
        try:
            c.initialize()
            tools = c.list_tools()
        finally:
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass
        if not tools:
            raise SystemExit("no tools discovered through vMCP")
        return tools[0]["name"]

    def stop(self):
        if self._serve and self._serve.poll() is None:
            self._serve.terminate()
            try:
                self._serve.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._serve.kill()
        subprocess.run(["/usr/bin/pkill", "-f", f"vmcp serve --config {self._tmp}"],
                       capture_output=True)
        self._thv("stop", "notes")
        self._thv("rm", "notes")
        subprocess.run(["/usr/bin/pkill", "-f", f"proxy-port {self.ports['backend']}"],
                       capture_output=True)
        shutil.rmtree(self._tmp, ignore_errors=True)

    def record(self):
        rec = re.sub(re.escape(self.client_secret), "<client-secret>", self.config_text or "")
        return {"vmcp_config": rec,
                "vmcp_config_sha256": hashlib.sha256((self.config_text or "").encode()).hexdigest(),
                "client_secret": fp(self.client_secret), "serve_log_tail": self.tail(30)}


def granted_exchanges(as_base, subject_fp=None):
    rows = [e for e in _get(f"{as_base}/exchanges") if e.get("outcome") == "granted"]
    if subject_fp is not None:
        rows = [e for e in rows if e.get("subject_fp") == subject_fp]
    return len(rows)


def reexchange_evidence(gw, up, as_base, tool):
    """One credential, three reads: record exchanges per read and the distinct
    upstream tokens, to show the per-request re-exchange (no cache) on serve."""
    tok = as_issue(as_base, "evidence-user", aud=USER_AUD)
    sfp = "sha256:" + hashlib.sha256(tok.encode()).hexdigest()[:12]
    per_read = []
    c = gw.client(tok)
    try:
        c.initialize()
        for i in range(3):
            n = make_nonce(f"ev{i}")
            before = granted_exchanges(as_base, sfp)
            c.call_tool(tool, {"nonce": n})
            after = granted_exchanges(as_base, sfp)
            calls = up.by_nonce(n)
            per_read.append({"read": i, "exchanges_for_this_credential": after - before,
                             "upstream_token": (calls[-1].get("authorization") if calls else None)})
    finally:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass
    toks = [r["upstream_token"] for r in per_read if r["upstream_token"]]
    return {"per_read": per_read,
            "exchanges_per_read": [r["exchanges_for_this_credential"] for r in per_read],
            "distinct_upstream_tokens": len(set(toks)) == len(toks) and len(toks) > 1,
            "all_tokens_distinct_for_same_credential": len(set(toks)) == len(toks)}


def main():
    as_base, ports = require_endpoints()
    thv_bin = os.environ.get("THV_BIN") or sys.exit("ERROR: set THV_BIN")
    ver = thv_version(thv_bin)
    if ver.get("version") != PINNED_VERSION:
        raise SystemExit(f"ERROR: ToolHive {ver.get('version')} != pinned {PINNED_VERSION}")
    print(f"=== vMCP same-user-credentials  ToolHive {ver.get('version')} ===")
    up = Recorder(ports["upstream"], _get(f"{as_base}/jwks")).start()
    gw = VMCP(thv_bin, as_base, ports)
    base = {"gateway": "toolhive", "gateway_label": "Stacklok ToolHive (vMCP)",
            "gateway_version": ver.get("version"), "gateway_versions": ver,
            "gateway_mode": "vMCP (thv vmcp serve)",
            "install": f"release binary thv v{PINNED_VERSION} (Apache-2.0), sha256-verified, loopback only",
            "incoming_auth": "oidc (vMCP requires an authenticated identity to exchange; anonymous "
                             "incoming has no token to exchange). Loopback AS allowed via "
                             "jwksAllowPrivateIp + insecureAllowHttp.",
            "endpoints": {"as_base": as_base, **ports}}
    try:
        gw.start()
        base.update(gw.record())
        print(f"vMCP up @ {gw.url}")
        tool = gw.discover_tool(as_issue(as_base, "alice", aud=USER_AUD))
        print(f"tool via vMCP: {tool}")

        # Per-request re-exchange evidence (observation).
        evidence = reexchange_evidence(gw, up, as_base, tool)
        print(f"re-exchange evidence: exchanges_per_read={evidence['exchanges_per_read']} "
              f"all_tokens_distinct={evidence['all_tokens_distinct_for_same_credential']}")

        # The same-user-credentials probe.
        user = "alice"
        cred1 = as_issue(as_base, user, scope="read:notes", aud=USER_AUD)
        cred2 = as_issue(as_base, user, scope="read:notes", aud=USER_AUD)
        if cred1 == cred2:
            raise SystemExit("the two credentials are byte-identical; aborting")

        def upstream_calls():
            return [UpstreamCall(nonce=r.get("nonce"), token=r.get("authorization"),
                                 audience=UPSTREAM_AUD, scope=None, subject=None,
                                 issuer="local-as.test", parsed=True, method="tools/call")
                    for r in up.requests if r.get("method") == "tools/call"]

        def read_resource(token, nonce):
            c = gw.client(token)
            try:
                c.initialize()
                return c.call_tool(tool, {"nonce": nonce})
            finally:
                try:
                    c.close()
                except Exception:  # noqa: BLE001
                    pass

        report = run_same_user_credentials_probe(
            target=gw.url, upstream_target=f"http://127.0.0.1:{ports['upstream']}/mcp", user=user,
            cred1=Credential("session", cred1), cred2=Credential("apitoken", cred2),
            read_resource=read_resource, uri_for=lambda n: n, upstream_calls=upstream_calls,
            fresh_cache=lambda: None,  # serve path keeps no exchange cache to reset
            expire_cache=None, exchange_attempts=lambda: granted_exchanges(as_base),
            authorized=True, authorization_note="localhost ToolHive vMCP CVE-2026-110195-class check")
        print("cold control:", report.cold_control.grade, "-", report.cold_control.detail)
        print("warm test:   ", report.warm.grade, "-", report.warm.detail)
        print("cache hit observed:", report.observations.get("cache_hit_observed"))
        print("VERDICT:", report.summary())

        save_checked("vmcp-same-user-credentials", {
            **base, "probe": "same-user-credentials", "cve": "CVE-2026-110195",
            "method": ("two inbound login JWTs for one user (alice), same scope; vMCP validates the "
                       "caller (oidc) and exchanges per backend; recording upstream ties each read "
                       "to its nonce; the AS mints a distinct upstream token per exchange so reuse "
                       "is visible"),
            "user": user, "credentials": {"cred1": "session JWT", "cred2": "api-token JWT (same user)"},
            "cold_control": report.cold_control.to_dict(), "warm": report.warm.to_dict(),
            "grade": report.grade, "vulnerable": report.vulnerable,
            "observations": report.observations,
            "cache_observation": (
                "on `thv vmcp serve`, each request re-exchanged (a fresh backend session per "
                "request), so the source-level token cache "
                "(pkg/vmcp/cache/cache.go: {backend}:{hash(subject_token)}:{audience}) was NOT "
                "exercised in this mode — every read minted a distinct upstream token, even for the "
                "same credential. This is an observation of this deployment mode, not a bug."),
            "reexchange_evidence": evidence,
            "kubernetes_operator_not_tested": (
                "the Kubernetes operator deployment, where backend sessions may persist and the "
                "token cache may apply, was NOT tested here"),
            "subject_provider_name": (
                "NOT run — the subjectProviderName (exchange a stored upstream token) sub-mode "
                "requires ToolHive's embedded authorization server, which was not stood up"),
            "scope_and_privilege": ("both credentials carried the same scope (read:notes); this "
                                    "shows token handling across credentials, not privilege escalation"),
            "summary": report.summary()})
    except Exception:
        print("--- vMCP serve log tail (redacted) ---\n" + gw.tail())
        raise
    finally:
        gw.stop()
        up.stop()


if __name__ == "__main__":
    main()
