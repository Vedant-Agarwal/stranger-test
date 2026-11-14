"""ContextForge gate setup through the supported admin API, not the database.

The gate module needs pyjwt[crypto] and integration/local_as.py; under the
stdlib-only test run these tests are skipped. Run them with a venv that has it:
    <venv>/bin/python -m unittest tests.test_cf_provider_api
"""

import importlib
import os
import sys
import unittest

_INTEGRATION = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "integration")
try:
    import jwt  # noqa: F401
    if _INTEGRATION not in sys.path:
        sys.path.insert(0, _INTEGRATION)
    gate = importlib.import_module("xid10_contextforge_gate")
except Exception:  # pragma: no cover - dependency missing
    gate = None


class FakeCF:
    """Records every call; answers like ContextForge 1.1.1's admin API."""

    def __init__(self, providers=(), api=True, users=None, roles=None, teams=()):
        self.providers = {p: {"id": p} for p in providers}
        self.api = api
        self.users = dict(users or {})
        self.roles = {e: list(r) for e, r in (roles or {}).items()}
        self.teams = list(teams)
        self.calls = []

    def __call__(self, method, path, tok, body=None):
        self.calls.append((method, path, body))
        prov = "/auth/sso/admin/providers"
        if path.startswith(prov):
            if not self.api:
                return 404, {"_error": '{"detail":"Not Found"}'}
            pid = path[len(prov) + 1:]
            if method == "GET" and not pid:
                return 200, list(self.providers.values())
            if method == "POST":
                if body["id"] in self.providers:
                    return 409, {}
                self.providers[body["id"]] = {**body, "is_enabled": True}
                return 200, {"id": body["id"]}
            if method == "PUT":
                if pid not in self.providers:
                    return 404, {}
                self.providers[pid] = {"id": pid, **body}
                return 200, {"id": pid}
            if method == "GET":
                return (200, self.providers[pid]) if pid in self.providers else (404, {})
        if path == "/rbac/roles":
            return 200, [{"id": "r-viewer", "name": "viewer"}, {"id": "r-dev", "name": "developer"}]
        if path.startswith("/teams/?"):
            return 200, {"teams": self.teams, "total": len(self.teams)}
        if path == "/teams/" and method == "POST":
            self.teams.append({"id": "t1", "name": body["name"]})
            return 201, {"id": "t1"}
        if path.startswith("/teams/") and path.endswith("/members"):
            return 201, {}
        if path.startswith("/auth/email/admin/users/"):
            email = path.rsplit("/", 1)[1].replace("%40", "@")
            if email not in self.users:
                return 404, {}
            if method == "PATCH":
                self.users[email].update(body)
            return 200, self.users[email]
        if path.startswith("/rbac/users/"):
            email = path.split("/")[3].replace("%40", "@")
            if method == "GET":
                return 200, self.roles.get(email, [])
            self.roles.setdefault(email, []).append(
                {"role_id": body["role_id"], "scope_id": body["scope_id"], "is_active": True})
            return 200, {}
        return 500, {"_error": f"unexpected {method} {path}"}


@unittest.skipIf(gate is None, "needs pyjwt[crypto] (integration/xid10_contextforge_gate.py)")
class ProviderApiTests(unittest.TestCase):
    def run_with(self, fake, fn, *a, **kw):
        orig = gate.cf
        gate.cf = fake
        try:
            return fn(*a, **kw)
        finally:
            gate.cf = orig

    def test_first_run_creates_with_post(self):
        fake = FakeCF()
        self.run_with(fake, gate.upsert_provider, "local-as", "https://local-as.test",
                      "http://127.0.0.1:1", tok="t")
        posts = [c for c in fake.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 1)
        body = posts[0][2]
        self.assertEqual(body["id"], "local-as")
        self.assertEqual(body["client_secret"], "unused")
        self.assertNotIn("client_secret_encrypted", body)
        self.assertEqual(body["issuer"], "https://local-as.test")
        self.assertEqual(body["jwks_uri"], "http://127.0.0.1:1/jwks")
        self.assertIs(body["trusted_for_api_auth"], True)
        self.assertEqual(body["api_audience"], "mcpgateway-api")
        self.assertFalse(any(c[0] == "PUT" for c in fake.calls))

    def test_repeat_run_updates_with_put_and_keeps_audience(self):
        fake = FakeCF(providers=["provx"])
        self.run_with(fake, gate.upsert_provider, "provx", "https://provx.test",
                      "http://127.0.0.1:1", "/jwks/provx", tok="t")
        puts = [c for c in fake.calls if c[0] == "PUT"]
        self.assertEqual([c[1] for c in puts], ["/auth/sso/admin/providers/provx"])
        self.assertIs(puts[0][2]["trusted_for_api_auth"], True)
        self.assertEqual(puts[0][2]["api_audience"], "mcpgateway-api")
        self.assertIs(puts[0][2]["is_enabled"], True)
        self.assertFalse(any(c[0] == "POST" for c in fake.calls))

    def test_missing_api_is_a_clear_error(self):
        fake = FakeCF(api=False)
        with self.assertRaises(SystemExit) as cm:
            self.run_with(fake, gate.upsert_provider, "local-as", "https://local-as.test",
                          "http://127.0.0.1:1", tok="t")
        self.assertIn("SSO_ENABLED=true", str(cm.exception))
        self.assertIn("1.1.1", str(cm.exception))

    def test_read_back_mismatch_fails(self):
        fake = FakeCF()
        orig_put = fake.__call__

        def drops_audience(method, path, tok, body=None):
            st, resp = orig_put(method, path, tok, body)
            if method == "GET" and path.endswith("/local-as"):
                resp = {**resp, "api_audience": None}
            return st, resp
        with self.assertRaises(SystemExit):
            self.run_with(drops_audience, gate.upsert_provider, "local-as",
                          "https://local-as.test", "http://127.0.0.1:1", tok="t")

    def test_rate_limited_provider_call_waits_and_retries(self):
        fake = FakeCF()
        inner = fake.__call__
        hits = []

        def limited_once(method, path, tok, body=None):
            if method == "POST" and not hits:
                hits.append(1)
                return 429, {"_error": '{"error":"Rate limit exceeded","reset_in_seconds":0}'}
            return inner(method, path, tok, body)
        orig_sleep = gate.time.sleep
        gate.time.sleep = lambda s: None
        try:
            self.run_with(limited_once, gate.upsert_provider, "provx", "https://provx.test",
                          "http://127.0.0.1:1", "/jwks/provx", tok="t")
        finally:
            gate.time.sleep = orig_sleep
        self.assertIn("provx", fake.providers)

    def test_tool_access_via_api(self):
        fake = FakeCF(users={"alice@local-as.test": {"is_admin": False,
                                                     "auth_provider": "local-as"}})
        self.run_with(fake, gate.ensure_tool_access,
                      ["alice@local-as.test", "ghost@local-as.test"], tok="t")
        self.assertIn(("POST", "/teams/", {"name": "xid10-team", "slug": "xid10-team",
                                          "description": "XID-10 gate",
                                          "visibility": "private"}), fake.calls)
        grants = [c for c in fake.calls if c[0] == "POST" and c[1].startswith("/rbac/users/")]
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0][2], {"role_id": "r-dev", "scope": "team", "scope_id": "t1"})
        # never PATCHes a user who is not admin; never touches the unprovisioned one
        self.assertFalse(any(c[0] == "PATCH" for c in fake.calls))
        self.assertFalse(any("ghost" in c[1] and c[0] == "POST" for c in fake.calls))

    def test_tool_access_is_idempotent_and_demotes_admin(self):
        fake = FakeCF(users={"a@x.test": {"is_admin": True}},
                      roles={"a@x.test": [{"role_id": "r-dev", "scope_id": "t1"}]},
                      teams=[{"id": "t1", "name": "xid10-team"}])
        self.run_with(fake, gate.ensure_tool_access, ["a@x.test"], tok="t")
        self.assertFalse(any(c[0] == "POST" and c[1] in ("/teams/",) for c in fake.calls))
        self.assertFalse(any(c[0] == "POST" and c[1].startswith("/rbac/") for c in fake.calls))
        self.assertIn(("PATCH", "/auth/email/admin/users/a%40x.test", {"is_admin": False}),
                      fake.calls)

    def test_user_provider_lookup_via_api(self):
        fake = FakeCF(users={"carol@provy.test": {"auth_provider": "provy"}})
        self.assertEqual(self.run_with(fake, gate.cf_user_provider, "carol@provy.test",
                                       tok="t"), "provy")
        self.assertIsNone(self.run_with(fake, gate.cf_user_provider, "nobody@x.test", tok="t"))

    def test_reserved_domain_membership_falls_back_to_database_only(self):
        fake = FakeCF(users={"alice@local-as.test": {"is_admin": False}})
        inner = fake.__call__

        def rejects_test_domain(method, path, tok, body=None):
            if method == "POST" and path.endswith("/members"):
                return 422, {"_error": "value is not a valid email address: The part after "
                                       "the @-sign is a special-use or reserved name"}
            return inner(method, path, tok, body)
        added = []
        orig = gate._add_member_db
        gate._add_member_db = lambda team, email: added.append((team, email))
        try:
            self.run_with(rejects_test_domain, gate.ensure_tool_access,
                          ["alice@local-as.test"], tok="t")
        finally:
            gate._add_member_db = orig
        self.assertEqual(added, [("t1", "alice@local-as.test")])
        # the role grant still goes through the API
        self.assertTrue(any(c[0] == "POST" and c[1].startswith("/rbac/users/")
                            for c in fake.calls))

    def test_other_membership_errors_are_not_masked(self):
        fake = FakeCF(users={"a@x.test": {"is_admin": False}})
        inner = fake.__call__

        def fails(method, path, tok, body=None):
            if method == "POST" and path.endswith("/members"):
                return 403, {"_error": "denied"}
            return inner(method, path, tok, body)
        with self.assertRaises(SystemExit):
            self.run_with(fails, gate.ensure_tool_access, ["a@x.test"], tok="t")

    def test_only_database_write_left_is_team_membership(self):
        with open(os.path.join(_INTEGRATION, "xid10_contextforge_gate.py")) as f:
            src = f.read()
        self.assertEqual(src.count("SessionLocal()"), 1)
        db_imports = [l.strip() for l in src.splitlines() if "from mcpgateway.db import" in l]
        self.assertEqual(db_imports,
                         ["from mcpgateway.db import EmailTeamMember, SessionLocal"])


if __name__ == "__main__":
    unittest.main()
