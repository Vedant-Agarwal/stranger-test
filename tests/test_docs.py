"""The docs name every setting a gate refuses to start without."""

import os
import re
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(_ROOT, rel)) as f:
        return f.read()


class ThinPortBaseDocumentedTests(unittest.TestCase):
    def test_thin_gate_requires_it(self):
        self.assertIn('raise SystemExit("ERROR: refusing to start: set THIN_PORT_BASE',
                      _read("integration/xid10_thin_deputy_gate.py"))

    def test_readme_documents_it(self):
        text = _read("README.md")
        self.assertIn("THIN_PORT_BASE", text)
        # the four ports it pins, and that it is required
        self.assertRegex(text, r"(?s)THIN_PORT_BASE=N.{0,200}N\+3")
        self.assertRegex(text, r"(?is)THIN_PORT_BASE.{0,400}(required|refuses)")

    def test_gate_guides_document_it(self):
        for rel in ("integration/CONTEXTFORGE_GATE.md", "integration/AGENTGATEWAY_GATE.md"):
            text = _read(rel)
            self.assertIn("THIN_PORT_BASE", text, rel)
            self.assertIn("FIXTURE_PORT", text, rel)


if __name__ == "__main__":
    unittest.main()
