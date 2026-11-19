"""LOCAL practice deputy for the same-user-credentials cache probe (XID-10).

A single in-process deputy that models a gateway doing RFC 8693 token exchange
and caching the exchanged upstream token. It is the broken/correct **fixture**
for :func:`strangertest.credcache.run_same_user_credentials_probe`: the probe
drives it as two credentials of one user and inspects what reached the owned
upstream.

Everything is in-process and deterministic — no network, no clock dependence.
The "exchanged token" is a toy opaque string ``ut~<user>~<scope+scope>~<serial>``
(deliberately **not** JWT-shaped) so the upstream can read back the subject and
scope, and so a cache *hit* reuses a byte-identical token (same fingerprint).

Cache modes
-----------
* ``user_only``              BROKEN — cache keyed on (user, audience) only, so two
                             credentials of the same user collide. The token (and
                             its scope) minted for the first is served to the
                             second. **Must FAIL.**
* ``user_plus_credential``   SAFE — cache keyed on (user, audience, credential),
                             so each credential exchanges its own token.
* ``no_cache``               SAFE — never caches; always exchanges.
* ``static_token``           The deputy mints one fixed token for everyone
                             (no per-subject exchange). The probe's cold control
                             must then refuse to grade — INCONCLUSIVE, not FAIL.
* ``content_cache_user``     Caches the upstream *response* keyed on (user,
                             audience) and serves a warm caller locally **without
                             forwarding** — so the owned upstream never sees the
                             second credential's call. The probe must not call
                             this OK (it cannot observe the token): INCONCLUSIVE.
* ``scope_from_user_cache``  Mints a fresh token per credential (distinct
                             fingerprint) but reads the *scope* from a user-keyed
                             cache, so the second credential's fresh token carries
                             the first's scope. **Must FAIL** by scope escalation.

NEVER expose this on a network; it has no authentication of its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit
import itertools
import threading

from .delegate import UpstreamCall

MODES = (
    "user_only",
    "user_plus_credential",
    "no_cache",
    "static_token",
    "content_cache_user",
    "scope_from_user_cache",
)

_STATIC_TOKEN = "ut~STATIC~read~0"  # one fixed token for every caller


@dataclass(frozen=True)
class CredSpec:
    """A credential the deputy knows: which user it belongs to and its scope."""

    user: str
    scope: FrozenSet[str]


def mint(user: str, scope: FrozenSet[str], serial: int) -> str:
    """A fresh exchanged token for (user, scope); a new serial each exchange."""
    joined = "+".join(sorted(scope)) if scope else "-"
    return f"ut~{user}~{joined}~{serial}"


def parse_token(token: Optional[str]) -> Tuple[Optional[str], Optional[FrozenSet[str]], bool]:
    """Read (user, scope, parsed) back out of an exchanged token string."""
    if not token or not isinstance(token, str):
        return None, None, False
    parts = token.split("~")
    if len(parts) != 4 or parts[0] != "ut":
        return None, None, False
    user = parts[1]
    scope = frozenset() if parts[2] == "-" else frozenset(parts[2].split("+"))
    return user, scope, True


def nonce_from_uri(uri: str) -> Optional[str]:
    vals = parse_qs(urlsplit(uri).query).get("nonce")
    return vals[0] if vals else None


class PracticeDeputy:
    """In-process token-exchanging, token-caching deputy fixture."""

    def __init__(
        self,
        mode: str,
        credentials: Dict[str, CredSpec],
        *,
        audience: str = "https://upstream.localhost/mcp",
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        self.mode = mode
        self.credentials = dict(credentials)
        self.audience = audience
        self._serial = itertools.count(1)
        self.exchanges = 0  # cumulative count of real mints (not cache hits)
        self._token_cache: Dict[Tuple, str] = {}
        self._scope_cache: Dict[Tuple, FrozenSet[str]] = {}
        self._content_cache: Dict[Tuple, Dict[str, Any]] = {}
        self._expired = False
        self._lock = threading.Lock()
        self.recorded: List[UpstreamCall] = []

    # --- probe callbacks -------------------------------------------------
    def reset_cache(self) -> None:
        """Cold cache: forget every cached token/scope/content."""
        with self._lock:
            self._token_cache.clear()
            self._scope_cache.clear()
            self._content_cache.clear()
            self._expired = False

    def expire_all(self) -> None:
        """Force every cached entry to be treated as expired on the next read."""
        with self._lock:
            self._expired = True

    def recorded_calls(self) -> List[UpstreamCall]:
        with self._lock:
            return list(self.recorded)

    def exchange_count(self) -> int:
        """Cumulative number of real token-exchange mints (cache hits excluded)."""
        with self._lock:
            return self.exchanges

    def read_resource(self, token: str, uri: str) -> Dict[str, Any]:
        """Drive one ``resources/read`` through the deputy as inbound ``token``.

        Raises ``KeyError`` for an unregistered credential (surfaced by the probe
        as a setup failure), mirroring a gateway that cannot exchange.
        """
        spec = self.credentials.get(token)
        if spec is None:
            raise KeyError(f"unknown inbound credential {token!r}")
        nonce = nonce_from_uri(uri)

        if self.mode == "content_cache_user":
            return self._serve_content_cache(spec, token, uri, nonce)

        exchanged = self._exchange(spec, token)
        return self._forward(exchanged, nonce, uri)

    # --- internals -------------------------------------------------------
    def _mint_fresh(self, spec: CredSpec, scope: Optional[FrozenSet[str]] = None) -> str:
        with self._lock:
            serial = next(self._serial)
            self.exchanges += 1
        return mint(spec.user, spec.scope if scope is None else scope, serial)

    def _exchange(self, spec: CredSpec, token: str) -> str:
        """Return the (possibly cached) exchanged upstream token for this read."""
        if self.mode == "static_token":
            return _STATIC_TOKEN
        if self.mode == "no_cache":
            return self._mint_fresh(spec)

        with self._lock:
            expired = self._expired
        if self.mode in ("user_only", "user_plus_credential"):
            if self.mode == "user_only":
                key = (spec.user, self.audience)
            else:
                key = (spec.user, self.audience, token)
            with self._lock:
                hit = None if expired else self._token_cache.get(key)
            if hit is not None:
                return hit
            fresh = self._mint_fresh(spec)
            with self._lock:
                self._token_cache[key] = fresh
            return fresh
        if self.mode == "scope_from_user_cache":
            # Fresh token every time (distinct fingerprint), but the *scope* is
            # cached per user — so the second credential's fresh token carries
            # the first credential's scope.
            skey = (spec.user, self.audience)
            with self._lock:
                scope = None if expired else self._scope_cache.get(skey)
                if scope is None:
                    scope = spec.scope
                    self._scope_cache[skey] = scope
            return self._mint_fresh(spec, scope=scope)
        raise AssertionError(f"unreachable mode {self.mode!r}")  # pragma: no cover

    def _forward(self, exchanged: str, nonce: Optional[str], uri: str) -> Dict[str, Any]:
        """Send the exchanged token to the owned upstream and record the call."""
        user, scope, parsed = parse_token(exchanged)
        with self._lock:
            self.recorded.append(
                UpstreamCall(
                    nonce=nonce,
                    subject=user,
                    actor=None,
                    audience=self.audience,
                    scope=sorted(scope) if scope is not None else None,
                    token=exchanged,
                    issuer="practice-as",
                    parsed=parsed,
                    method="resources/read",
                )
            )
        return {
            "contents": [
                {"uri": uri, "mimeType": "text/plain", "text": f"served to {user}"}
            ]
        }

    def _serve_content_cache(
        self, spec: CredSpec, token: str, uri: str, nonce: Optional[str]
    ) -> Dict[str, Any]:
        """Cache the upstream response per (user, audience); serve warm locally."""
        key = (spec.user, self.audience)
        with self._lock:
            expired = self._expired
            cached = None if expired else self._content_cache.get(key)
        if cached is not None:
            # Served locally — the owned upstream is NOT called for this read.
            return {"contents": [{"uri": uri, "mimeType": "text/plain", "text": cached["text"]}]}
        exchanged = self._mint_fresh(spec)
        resp = self._forward(exchanged, nonce, uri)
        with self._lock:
            self._content_cache[key] = {"text": resp["contents"][0]["text"]}
        return resp
