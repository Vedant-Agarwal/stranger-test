"""Authorization guard for Stranger Test.

Stranger Test checks an MCP server for cross-identity / delegated-authority
confused-deputy leaks: it acts as identity A, then checks what identity B or an
anonymous client can reach. Running it against a server you do not own or are
not authorized to test can itself be an unauthorized-access offense, so this
guard is the first thing every run passes through.

Policy (default-deny):

* Local development hosts -- loopback addresses, and names ending in
  ``.localhost`` or ``.test`` -- are always allowed. You are testing your own
  machine.
* Any other target is refused UNLESS the caller passes explicit authorization
  (``authorized=True`` together with a non-empty ``authorization_note`` that
  records who permitted the test).

This is a deliberate speed bump, not a security control: its job is to make sure
a stranger's server is never probed by accident. There is intentionally no flag
that authorizes "everything" and no way to sweep a range of hosts. One target,
one authorization.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

__all__ = [
    "Authorization",
    "AuthorizationError",
    "authorize",
    "is_local_target",
    "extract_host",
]


class AuthorizationError(Exception):
    """Raised when a target may not be tested under the current authorization."""


@dataclass(frozen=True)
class Authorization:
    """The record of a passed authorization check."""

    target: str
    host: str
    allowed: bool
    reason: str


def extract_host(target: Optional[str]) -> Optional[str]:
    """Return the lowercase hostname of ``target``, or ``None`` if unreadable.

    Accepts a full URL (``http://host:port/path``) or a bare ``host`` /
    ``host:port``.
    """
    if target is None:
        return None
    t = target.strip()
    if not t:
        return None
    # Ensure urlparse sees a netloc even when no scheme is given.
    if "://" not in t:
        t = "//" + t
    host = urlparse(t).hostname
    if not host:
        return None
    return host.lower()


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_local_target(host: Optional[str]) -> bool:
    """True if ``host`` is a local development host (loopback / .localhost / .test)."""
    if not host:
        return False
    host = host.lower()
    if host == "localhost":
        return True
    if host.endswith(".localhost") or host.endswith(".test"):
        return True
    return _is_loopback(host)


def authorize(
    target: str,
    *,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> Authorization:
    """Decide whether ``target`` may be tested; return an Authorization or raise.

    Local development hosts are always allowed. Every other target is refused
    unless ``authorized`` is True AND ``authorization_note`` records who
    permitted the test.
    """
    host = extract_host(target)
    if host is None:
        raise AuthorizationError(
            f"Could not read a hostname from target {target!r}. Give a host or "
            f"URL, e.g. 'http://localhost:8080' or 'https://mcp.example.com/'."
        )

    if is_local_target(host):
        return Authorization(
            target=target,
            host=host,
            allowed=True,
            reason=f"local development host ({host})",
        )

    note = (authorization_note or "").strip()
    if authorized and note:
        return Authorization(
            target=target,
            host=host,
            allowed=True,
            reason=f"explicit authorization: {note}",
        )

    raise AuthorizationError(
        f"Refusing to test {host}. Stranger Test only runs against local "
        f"development hosts or targets you are explicitly authorized to test. "
        f"If you own this server or have written permission, re-run with "
        f"explicit authorization (authorized=True) and a note recording who "
        f"authorized it."
    )
