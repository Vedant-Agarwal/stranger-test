"""The one-command MCP scanner.

``strangertest.scan`` profiles any MCP server/gateway by URL and grades the
profile into findings. This package holds three cooperating layers that share
the dataclasses in :mod:`strangertest.scan.model`:

* the **adapter** (:mod:`strangertest.scan.adapter`) connects to a target and
  returns a :class:`~strangertest.scan.model.TargetProfile` — safe, read-only;
* the **check catalog** turns a profile into
  :class:`~strangertest.scan.model.ScanFinding` records (sibling-owned);
* the **CLI/report** renders those findings (sibling-owned).

Only the adapter and the shared model live here so far.
"""

from .model import ScanFinding, TargetProfile  # noqa: F401
from .adapter import fingerprint_secret, profile_target  # noqa: F401

__all__ = [
    "TargetProfile",
    "ScanFinding",
    "profile_target",
    "fingerprint_secret",
]
