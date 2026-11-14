"""The private-cached-results probe (CoSAI MCP Security v2.0, 3.2.7).

MCP 2026-07-28 results of ``resources/read`` carry ``cacheScope`` ("public" or
"private") and ``ttlMs``. A "private" result "MUST NOT be shared across
authorization contexts"; a "public" one may be served by any shared cache to any
user. This probe grades two separate things:

1. **Labelling** (is the origin honest?). The origin is read directly as A and
   as B. Same URI, different content, labelled "public" -> LEAK (private data
   mislabelled as shareable). "private" with differing content is correct (OK).
   A missing ``cacheScope`` is only an OBSERVATION ("unlabelled"); the spec
   states no default, so it is never graded as a confirmed leak.
2. **Honouring** (does the cache obey a "private" label?). A reads R through the
   cache, then reads it again. If the origin's call count did not rise, caching
   was observed (the positive control). Then B reads the identical R. If B gets
   A's content, the cache shared a private result -> LEAK. If no caching was
   observed, the verdict is INCONCLUSIVE, never OK.

Content is compared by exact equality of the ``(uri, text)`` pairs in
``contents``, never by substring search. The probe also records whether the
cache passed ``cacheScope`` and ``ttlMs`` through unchanged (observation only).

Grades are ``LEAK``, ``OK`` or ``INCONCLUSIVE``. A setup that stops the probe
observing A's first read raises :class:`~strangertest.probe.ProbeError`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .guard import authorize
from .mcp_client import MCPClient
from .probe import Identity, ProbeError

__all__ = ["CacheScopeReport", "Verdict", "run_cachescope_probe", "LEAK", "OK", "INCONCLUSIVE"]

LEAK = "LEAK"
OK = "OK"
INCONCLUSIVE = "INCONCLUSIVE"

FAILURE_CLASS = "private result served across authorization contexts (cache scope)"
LABEL_FAILURE_CLASS = "user-specific result labelled cacheScope=public"

Content = Tuple[Tuple[Any, Any], ...]


@dataclass
class Verdict:
    grade: str
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {"grade": self.grade, "detail": self.detail}


@dataclass
class _Read:
    content: Content
    cache_scope: Any
    ttl_ms: Any
    has_scope: bool
    has_ttl: bool


def _content(result: Any) -> Content:
    contents = result.get("contents") if isinstance(result, dict) else None
    if not isinstance(contents, list) or not contents:
        raise ValueError("result has no contents list")
    pairs = []
    for item in contents:
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            raise ValueError("contents item has no text")
        pairs.append((item.get("uri"), item["text"]))
    return tuple(pairs)


def _read(client: MCPClient, uri: str) -> _Read:
    result = client.read_resource(uri)
    return _Read(
        content=_content(result),
        cache_scope=result.get("cacheScope"),
        ttl_ms=result.get("ttlMs"),
        has_scope="cacheScope" in result,
        has_ttl="ttlMs" in result,
    )


@dataclass
class CacheScopeReport:
    target: str
    upstream_target: str
    authorization: str
    identity_a: str
    identity_b: str
    uri: str
    labelling: Verdict
    honouring: Verdict
    observations: Dict[str, Any] = field(default_factory=dict)

    @property
    def leaked(self) -> bool:
        return LEAK in (self.labelling.grade, self.honouring.grade)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "probe": "cachescope",
            "target": self.target,
            "upstream_target": self.upstream_target,
            "authorization": self.authorization,
            "identity_a": self.identity_a,
            "identity_b": self.identity_b,
            "uri": self.uri,
            "labelling": self.labelling.to_dict(),
            "honouring": self.honouring.to_dict(),
            "observations": dict(self.observations),
            "leaked": self.leaked,
        }
        classes = []
        if self.labelling.grade == LEAK:
            classes.append(LABEL_FAILURE_CLASS)
        if self.honouring.grade == LEAK:
            classes.append(FAILURE_CLASS)
        if classes:
            data["failure_class"] = classes
        return data

    def summary(self) -> str:
        return (
            f"labelling: {self.labelling.grade} - {self.labelling.detail}\n"
            f"honouring: {self.honouring.grade} - {self.honouring.detail}"
        )


def _valid_ttl(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _grade_labelling(
    direct_a: _Read, direct_b: _Read, stable: bool, obs: Dict[str, Any]
) -> Verdict:
    if not stable:
        return Verdict(
            INCONCLUSIVE,
            "origin content is unstable: an identity's own two reads differ, so "
            "a difference between A and B proves nothing about identity",
        )
    if direct_a.cache_scope != direct_b.cache_scope or (
        direct_a.has_scope != direct_b.has_scope
    ):
        return Verdict(
            INCONCLUSIVE,
            "origin returned different cacheScope values to A and B; "
            "no single label to grade",
        )
    differs = direct_a.content != direct_b.content
    obs["content_differs_per_identity"] = differs
    if not direct_a.has_scope:
        obs["unlabelled"] = True
    if not differs:
        return Verdict(
            INCONCLUSIVE,
            "resource is not identity-specific: content is identical for A and "
            "B, so there is nothing to mislabel or leak"
            + ("" if direct_a.has_scope else " (observation: cacheScope is "
               "missing, which the spec requires)"),
        )
    if not direct_a.has_scope:
        return Verdict(
            INCONCLUSIVE,
            "OBSERVATION unlabelled: cacheScope is missing on a result whose "
            "content differs per identity; not safe to cache, but the spec "
            "gives no default so this is not graded as a confirmed leak",
        )
    scope = direct_a.cache_scope
    if scope not in ("public", "private"):
        return Verdict(INCONCLUSIVE, f"cacheScope {scope!r} is not public or private")
    if scope == "public":
        return Verdict(
            LEAK,
            "origin returns different content to A and B for the same request "
            "but labels it cacheScope=public",
        )
    return Verdict(OK, "content differs per identity and is labelled private")


def run_cachescope_probe(
    target: str,
    upstream_target: str,
    identity_a: Identity,
    identity_b: Identity,
    *,
    direct_a: Identity,
    direct_b: Identity,
    uri: str,
    upstream_calls: Callable[[], int],
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> CacheScopeReport:
    """Run the labelling and honouring checks for ``resources/read`` of ``uri``.

    ``identity_a`` / ``identity_b`` connect through the cache under test
    (``target``). ``direct_a`` / ``direct_b`` connect to the origin
    (``upstream_target``) with the same credentials. ``upstream_calls`` returns
    the origin's served-read count (the caching control). Both targets pass the
    authorization guard first.
    """
    decision = authorize(
        target, authorized=authorized, authorization_note=authorization_note
    )
    authorize(
        upstream_target, authorized=authorized, authorization_note=authorization_note
    )

    clients: List[MCPClient] = []

    def connect(identity: Identity) -> MCPClient:
        client = identity.connect()
        clients.append(client)
        client.initialize()
        return client

    obs: Dict[str, Any] = {}
    try:
        client_a = connect(identity_a)
        client_b = connect(identity_b)
        try:
            c0 = upstream_calls()
            a1 = _read(client_a, uri)  # step 1
            c1 = upstream_calls()
            a2 = _read(client_a, uri)  # step 2: caching control
            c2 = upstream_calls()
        except Exception as exc:
            raise ProbeError(
                f"could not read {uri!r} as {identity_a.label!r} through the "
                f"cache: {exc}. The probe is inconclusive."
            )
        b_read: Optional[_Read] = None
        b_error: Optional[str] = None
        try:
            b_read = _read(client_b, uri)  # step 3
        except Exception as exc:
            b_error = str(exc)
        try:
            origin_a = connect(direct_a)
            origin_b = connect(direct_b)
            da = _read(origin_a, uri)
            da2 = _read(origin_a, uri)
            db = _read(origin_b, uri)
            db2 = _read(origin_b, uri)
        except Exception as exc:
            raise ProbeError(
                f"could not read {uri!r} directly from the origin: {exc}. "
                f"The probe is inconclusive (not 'no leak')."
            )
    finally:
        for c in clients:
            try:
                c.close()
            except Exception:
                pass

    obs["origin_cache_scope"] = da.cache_scope if da.has_scope else None
    obs["origin_ttl_ms"] = da.ttl_ms if da.has_ttl else None
    obs["origin_ttl_valid"] = (not da.has_ttl) or _valid_ttl(da.ttl_ms)
    obs["origin_calls_step1"] = c1 - c0
    obs["origin_calls_step2"] = c2 - c1
    obs["caching_observed"] = c2 == c1 and a2.content == a1.content
    # Pass-through: compare what the cache returned to A with what the origin
    # returned to A. Observation only.
    obs["hints_passed_through"] = (
        a1.has_scope == da.has_scope
        and a1.cache_scope == da.cache_scope
        and a1.has_ttl == da.has_ttl
        and a1.ttl_ms == da.ttl_ms
    )

    if b_read is None:
        obs["b_received"] = "error"
    elif da.content != db.content and b_read.content == da.content:
        obs["b_received"] = "a"
    elif b_read.content == db.content:
        obs["b_received"] = "own"
    else:
        obs["b_received"] = "other"
    stable = da.content == da2.content and db.content == db2.content
    obs["origin_stable"] = stable
    labelling = _grade_labelling(da, db, stable, obs)
    honouring = _grade_honouring(a1, a2, b_read, b_error, da, db, c1, c2, stable, obs)

    return CacheScopeReport(
        target=decision.target,
        upstream_target=upstream_target,
        authorization=decision.reason,
        identity_a=identity_a.label,
        identity_b=identity_b.label,
        uri=uri,
        labelling=labelling,
        honouring=honouring,
        observations=obs,
    )


def _grade_honouring(
    a1: _Read,
    a2: _Read,
    b_read: Optional[_Read],
    b_error: Optional[str],
    da: _Read,
    db: _Read,
    c1: int,
    c2: int,
    stable: bool,
    obs: Dict[str, Any],
) -> Verdict:
    if not stable:
        return Verdict(
            INCONCLUSIVE,
            "origin content is unstable: an identity's own two reads differ",
        )
    if da.content == db.content:
        return Verdict(
            INCONCLUSIVE,
            "A's and B's content are identical at the origin; nothing "
            "identity-specific to leak",
        )
    if not da.has_scope or da.cache_scope != "private":
        return Verdict(
            INCONCLUSIVE,
            f"origin label is {da.cache_scope if da.has_scope else 'missing'}, not "
            f"private: sharing is permitted or unspecified; see the labelling verdict",
        )
    if b_read is None:
        return Verdict(
            INCONCLUSIVE, f"B's read through the cache failed: {b_error}"
        )
    # Leak first: B received A's origin content for a private, identity-specific
    # resource. This holds whether or not the caching control was observed.
    if b_read.content == da.content:
        return Verdict(
            LEAK,
            "B received A's private content for the identical request"
            + ("" if obs.get("caching_observed") else
               " (caching was not observed by the control, but the content "
               "was still shared)"),
        )
    # Controls only gate OK.
    if a2.content != a1.content:
        return Verdict(
            INCONCLUSIVE, "A's repeat read returned different content; unstable control"
        )
    if c2 != c1:
        return Verdict(
            INCONCLUSIVE,
            "no caching observed: the origin served A's repeat read, so the "
            "cache never stored the result and honouring was not exercised",
        )
    if a1.content != da.content:
        return Verdict(
            INCONCLUSIVE, "A's content through the cache differs from A's direct content"
        )
    if b_read.content == db.content:
        return Verdict(
            OK, "caching observed, and B received B's own content, not A's"
        )
    return Verdict(INCONCLUSIVE, "B received content matching neither A nor B's origin content")
