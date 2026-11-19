"""Client authentication and act_from_client in integration/local_as.py.

The pure helpers run under the stdlib-only test run; the LocalAS tests need
pyjwt[crypto] + cryptography and are skipped without them.
"""

import base64
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from urllib.parse import quote_plus, urlencode

_INTEGRATION = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "integration")
if _INTEGRATION not in sys.path:
    sys.path.insert(0, _INTEGRATION)
import local_as  # noqa: E402

GRANT = local_as.TOKEN_EXCHANGE_GRANT
TARGET = "https://upstream.test/mcp"
CLIENTS = {"gw": "s3cret", "other": "x"}


def basic(cid, secret):
    raw = f"{quote_plus(cid)}:{quote_plus(secret)}".encode()
    return "Basic " + base64.b64encode(raw).decode()


class ParseClientAuthTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(local_as.parse_client_auth({}, basic("gw", "s3:c ret")),
                         ("client_secret_basic", "gw", "s3:c ret"))

    def test_post(self):
        self.assertEqual(local_as.parse_client_auth({"client_id": "gw", "client_secret": "s"}, None),
                         ("client_secret_post", "gw", "s"))

    def test_client_id_only(self):
        self.assertEqual(local_as.parse_client_auth({"client_id": "gw"}, None),
                         ("client_id_only", "gw", None))

    def test_none(self):
        self.assertEqual(local_as.parse_client_auth({}, None), (None, None, None))
        self.assertEqual(local_as.parse_client_auth({}, "Bearer abc"), (None, None, None))

    def test_both_methods_is_multiple(self):
        m, cid, sec = local_as.parse_client_auth({"client_secret": "s"}, basic("gw", "s3cret"))
        self.assertEqual((m, sec), ("multiple", None))

    def test_malformed_basic(self):
        self.assertEqual(local_as.parse_client_auth({}, "Basic !!!"),
                         ("client_secret_basic", None, None))

    def test_check_client(self):
        self.assertIsNone(local_as.check_client("client_secret_post", "gw", "s3cret", {}))
        self.assertTrue(local_as.check_client("client_secret_post", "gw", "s3cret", CLIENTS))
        self.assertTrue(local_as.check_client("client_secret_basic", "gw", "s3cret", CLIENTS))
        self.assertFalse(local_as.check_client("client_secret_post", "gw", "wrong", CLIENTS))
        self.assertFalse(local_as.check_client("client_secret_post", "nobody", "x", CLIENTS))
        self.assertFalse(local_as.check_client("client_id_only", "gw", None, CLIENTS))
        self.assertFalse(local_as.check_client("multiple", "gw", None, CLIENTS))
        self.assertFalse(local_as.check_client(None, None, None, CLIENTS))


@unittest.skipIf(local_as.jwt is None, "needs pyjwt[crypto] + cryptography")
class LocalASClientAuthTests(unittest.TestCase):
    def mk(self, **kw):
        return local_as.LocalAS(**kw)

    def ex(self, as_, *, actor=False, params=None, authorization=None):
        user = as_.issue_user_token("alice")
        p = {"grant_type": GRANT, "subject_token": user, "audience": TARGET,
             "scope": "read:notes", **(params or {})}
        if actor:
            p["actor_token"] = as_.issue_client_token("agent-client")
        out = as_.token_exchange(p, authorization=authorization)
        return as_.validate(out["access_token"], audience=TARGET), out, as_.exchanges[-1]

    # -- resource_access roles (opt-in) -------------------------------------
    def test_resource_access_claim_opt_in(self):
        as_ = self.mk()
        # default: the claim is absent (existing tokens are unchanged)
        self.assertNotIn("resource_access", as_.validate(as_.issue_user_token("alice")))
        # opt-in: a Keycloak-style resource_access claim is carried verbatim
        ra = {"svc1": {"roles": ["tool:read_note", "tool:other"]}}
        claims = as_.validate(as_.issue_user_token("alice", resource_access=ra))
        self.assertEqual(claims.get("resource_access"), ra)

    def test_issue_endpoint_ra_param(self):
        as_ = self.mk()
        srv = as_.serve(port=0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        try:
            ra = {"svc1": {"roles": ["tool:read_note"]}}
            q = urlencode({"sub": "alice", "ra": json.dumps(ra)})
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/issue?{q}", timeout=5) as r:
                tok = json.loads(r.read())["access_token"]
            self.assertEqual(as_.validate(tok).get("resource_access"), ra)
            # bad JSON in ra -> HTTP 400
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/issue?ra=not-json", timeout=5)
            self.assertEqual(cm.exception.code, 400)
        finally:
            srv.shutdown()
            srv.server_close()

    # -- default mode: exactly as before ------------------------------------
    def test_default_mode_unchanged(self):
        as_ = self.mk()
        self.assertEqual((as_.client_auth, as_.act_from_client, as_.clients), ("none", False, {}))
        # no credentials: same claims and response shape as before
        claims, out, rec = self.ex(as_)
        self.assertNotIn("act", claims)
        self.assertEqual(set(out), {"access_token", "issued_token_type", "token_type",
                                    "expires_in", "scope"})
        self.assertEqual(claims["sub"], "alice")
        self.assertEqual(rec["outcome"], "granted")
        # any credentials, even nonsense, are not checked and change nothing
        for kw in ({"params": {"client_id": "x", "client_secret": "y"}},
                   {"authorization": basic("x", "y")}, {"params": {"client_id": "x"}}):
            claims, _, rec = self.ex(as_, **kw)
            self.assertNotIn("act", claims)
            self.assertEqual(rec["outcome"], "granted")
            self.assertIsNone(rec["client_valid"])
        # actor_token still gives act, as before
        claims, _, rec = self.ex(as_, actor=True)
        self.assertEqual(claims["act"], {"sub": "agent-client"})
        self.assertEqual(rec["act_source"], "actor_token")

    def test_default_records_old_keys(self):
        as_ = self.mk()
        _, _, rec = self.ex(as_)
        for k in ("time", "subject_fp", "requested_scope", "requested_audience", "actor_present",
                  "subject_iss", "subject_sub", "subject_scope", "subject_key", "outcome",
                  "issued_fp", "issued_scope", "issued_audience", "seq"):
            self.assertIn(k, rec)

    # -- logging --------------------------------------------------------------
    def test_logs_method_and_validity_never_secret(self):
        as_ = self.mk(clients=CLIENTS)
        _, _, rec = self.ex(as_, authorization=basic("gw", "s3cret"))
        self.assertEqual((rec["client_auth_method"], rec["client_id"], rec["client_valid"]),
                         ("client_secret_basic", "gw", True))
        _, _, rec = self.ex(as_, params={"client_id": "gw", "client_secret": "nope"})
        self.assertEqual((rec["client_auth_method"], rec["client_valid"]),
                         ("client_secret_post", False))
        _, _, rec = self.ex(as_)
        self.assertEqual((rec["client_auth_method"], rec["client_valid"]), (None, False))
        dump = json.dumps(as_.exchanges)
        for secret in ("s3cret", "nope"):
            self.assertNotIn(secret, dump)

    # -- optional / strict ----------------------------------------------------
    def test_wrong_secret_rejected(self):
        for mode in ("optional", "strict"):
            as_ = self.mk(clients=CLIENTS, client_auth=mode)
            for kw in ({"params": {"client_id": "gw", "client_secret": "wrong"}},
                       {"authorization": basic("gw", "wrong")},
                       {"authorization": basic("nobody", "s3cret")}):
                with self.assertRaises(local_as.ClientAuthError, msg=(mode, kw)):
                    self.ex(as_, **kw)
                self.assertTrue(as_.exchanges[-1]["outcome"].startswith("refused: invalid_client"))

    def test_strict_requires_credentials(self):
        as_ = self.mk(clients=CLIENTS, client_auth="strict")
        for kw in ({}, {"params": {"client_id": "gw"}}):
            with self.assertRaises(local_as.ClientAuthError):
                self.ex(as_, **kw)
        claims, _, rec = self.ex(as_, params={"client_id": "gw", "client_secret": "s3cret"})
        self.assertEqual(rec["outcome"], "granted")

    def test_optional_allows_none_but_not_bad(self):
        as_ = self.mk(clients=CLIENTS, client_auth="optional")
        _, _, rec = self.ex(as_)
        self.assertEqual(rec["outcome"], "granted")
        with self.assertRaises(local_as.ClientAuthError):
            self.ex(as_, params={"client_id": "gw"})  # id with no secret is not valid

    def test_both_methods_rejected_when_checked(self):
        as_ = self.mk(clients=CLIENTS, client_auth="optional")
        with self.assertRaises(local_as.ClientAuthError):
            self.ex(as_, params={"client_secret": "s3cret"}, authorization=basic("gw", "s3cret"))

    # -- act_from_client ------------------------------------------------------
    def test_act_from_client(self):
        as_ = self.mk(clients=CLIENTS, act_from_client=True)
        claims, _, rec = self.ex(as_, authorization=basic("gw", "s3cret"))
        self.assertEqual(claims["act"], {"sub": "gw"})
        self.assertEqual(rec["act_source"], "client_auth")
        claims, _, rec = self.ex(as_, params={"client_id": "gw", "client_secret": "s3cret"})
        self.assertEqual(claims["act"], {"sub": "gw"})

    def test_act_from_client_needs_valid_credentials(self):
        as_ = self.mk(clients=CLIENTS, act_from_client=True)  # client_auth none: not refused
        for kw in ({}, {"params": {"client_id": "gw"}},
                   {"params": {"client_id": "gw", "client_secret": "wrong"}}):
            claims, _, rec = self.ex(as_, **kw)
            self.assertNotIn("act", claims, kw)
            self.assertIsNone(rec["act_source"])

    def test_actor_token_wins_over_client(self):
        as_ = self.mk(clients=CLIENTS, act_from_client=True)
        claims, _, rec = self.ex(as_, actor=True, authorization=basic("gw", "s3cret"))
        self.assertEqual(claims["act"], {"sub": "agent-client"})
        self.assertEqual(rec["act_source"], "actor_token")

    def test_act_from_client_off_by_default_even_with_clients(self):
        as_ = self.mk(clients=CLIENTS)
        claims, _, _ = self.ex(as_, authorization=basic("gw", "s3cret"))
        self.assertNotIn("act", claims)

    def test_bad_construction(self):
        with self.assertRaises(ValueError):
            self.mk(client_auth="strict")
        with self.assertRaises(ValueError):
            self.mk(act_from_client=True)
        with self.assertRaises(ValueError):
            self.mk(clients=CLIENTS, client_auth="maybe")

    # -- over HTTP ------------------------------------------------------------
    def test_http_basic_and_401(self):
        as_ = self.mk(clients=CLIENTS, client_auth="strict", act_from_client=True)
        srv = as_.serve(port=0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            body = urlencode({"grant_type": GRANT, "subject_token": as_.issue_user_token("alice"),
                              "audience": TARGET}).encode()

            def post(auth):
                h = {"Content-Type": "application/x-www-form-urlencoded"}
                if auth:
                    h["Authorization"] = auth
                req = urllib.request.Request(f"{url}/token", data=body, headers=h, method="POST")
                return urllib.request.urlopen(req, timeout=5)

            with post(basic("gw", "s3cret")) as r:
                tok = json.loads(r.read())["access_token"]
            self.assertEqual(as_.validate(tok, audience=TARGET)["act"], {"sub": "gw"})
            for auth in (basic("gw", "wrong"), None):
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    post(auth)
                self.assertEqual(cm.exception.code, 401)
                self.assertEqual(json.loads(cm.exception.read())["error"], "invalid_client")
            with urllib.request.urlopen(f"{url}/.well-known/openid-configuration") as r:
                oc = json.loads(r.read())
            self.assertEqual((oc["x_client_auth"], oc["x_act_from_client"], oc["x_clients"]),
                             ("strict", True, ["gw", "other"]))
            self.assertNotIn("s3cret", json.dumps(oc))
            with urllib.request.urlopen(f"{url}/exchanges") as r:
                self.assertNotIn("s3cret", r.read().decode())
        finally:
            srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    unittest.main()
