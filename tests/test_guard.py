import unittest

from strangertest.guard import (
    Authorization,
    AuthorizationError,
    authorize,
    extract_host,
    is_local_target,
)


class ExtractHostTests(unittest.TestCase):
    def test_full_url(self):
        self.assertEqual(extract_host("http://localhost:8080/mcp"), "localhost")

    def test_host_and_port(self):
        self.assertEqual(extract_host("127.0.0.1:3000"), "127.0.0.1")

    def test_ipv6(self):
        self.assertEqual(extract_host("http://[::1]:9000"), "::1")

    def test_uppercase_is_lowercased(self):
        self.assertEqual(extract_host("HTTPS://MCP.Example.COM/"), "mcp.example.com")

    def test_empty_or_none(self):
        self.assertIsNone(extract_host(""))
        self.assertIsNone(extract_host("   "))
        self.assertIsNone(extract_host(None))


class LocalTargetTests(unittest.TestCase):
    def test_localhost_name(self):
        self.assertTrue(is_local_target("localhost"))

    def test_loopback_v4_range(self):
        self.assertTrue(is_local_target("127.0.0.1"))
        self.assertTrue(is_local_target("127.5.5.5"))

    def test_loopback_v6(self):
        self.assertTrue(is_local_target("::1"))

    def test_dev_tlds(self):
        self.assertTrue(is_local_target("api.localhost"))
        self.assertTrue(is_local_target("mcp.test"))

    def test_public_hosts(self):
        self.assertFalse(is_local_target("example.com"))
        self.assertFalse(is_local_target("1.2.3.4"))
        self.assertFalse(is_local_target(""))
        self.assertFalse(is_local_target(None))


class AuthorizeTests(unittest.TestCase):
    def test_local_target_allowed(self):
        decision = authorize("http://localhost:8080/mcp")
        self.assertIsInstance(decision, Authorization)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.host, "localhost")

    def test_dev_tld_allowed(self):
        self.assertTrue(authorize("http://api.test/mcp").allowed)

    def test_public_target_refused(self):
        with self.assertRaises(AuthorizationError):
            authorize("https://mcp.example.com/")

    def test_authorized_flag_without_note_refused(self):
        with self.assertRaises(AuthorizationError):
            authorize("https://mcp.example.com/", authorized=True)
        with self.assertRaises(AuthorizationError):
            authorize("https://mcp.example.com/", authorized=True, authorization_note="   ")

    def test_note_without_flag_refused(self):
        with self.assertRaises(AuthorizationError):
            authorize("https://mcp.example.com/", authorization_note="owner said ok")

    def test_explicit_authorization_allowed(self):
        decision = authorize(
            "https://mcp.example.com/",
            authorized=True,
            authorization_note="owner Jane Doe, email 2026-11-09",
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.host, "mcp.example.com")
        self.assertIn("Jane Doe", decision.reason)

    def test_unreadable_target_refused(self):
        with self.assertRaises(AuthorizationError):
            authorize("")


if __name__ == "__main__":
    unittest.main()
