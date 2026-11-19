"""Two users at the same time (XID-10, deeper).

The delegation probe drives A, then B, then A, one at a time. This probe fires
many interleaved A and B calls AT ONCE (``pairs`` of them, default 50) and checks
that no call is served as the other identity.

Each user owns a marker the upstream returns only to a token for that user (the
upstream keys its "note" on the token's (issuer, subject), never on the request
arguments). Each request carries its own nonce, so every upstream call is tied
to the request that caused it.

Grades:

* FAIL ``cross_identity_response`` -- a response carries the OTHER user's marker.
* FAIL ``wrong_subject_upstream`` -- an upstream call with a request's nonce carries
  another identity than that request's caller.
* INCONCLUSIVE -- an upstream call that cannot be tied to a request, an unparseable
  token, a request that errored or did not get its own marker, a request with no
  upstream call, or the broken fixture not shown to behave as required.
* OBSERVATION ``serialized`` -- nothing wrong seen, but the upstream never saw two
  calls in flight at once: the gateway serialized them, so concurrency was not
  actually exercised. Never OK.
* OK ``isolated`` -- every request got its own marker and reached the upstream as its
  own caller, at least two upstream calls overlapped, and in this run the leaky
  fixture FAILED this probe while PASSING the one-at-a-time probe.

Ways this could lie, and the unit test that pins each (tests/test_concurrency.py):

False LEAK
  C1 one marker a substring of the other -> markers are fixed-length random hex
     with distinct prefixes; checked at construction.
                               test_markers_must_not_overlap
  C2 discovery (tools/list) on the gateway's own credential -> only tools/call and
     resources/read with a known nonce are graded.
                               test_discovery_traffic_is_not_graded
  C3 a gateway retry delivering the same nonce twice -> duplicates are fine as long
     as each carries the right identity.
                               test_duplicate_nonce_same_identity_is_not_a_leak
  C4 an error response (rate limit, 5xx) that carries no marker -> not a leak; it
     only blocks OK.           test_error_response_is_inconclusive_not_fail
  C5 the same user arriving on a different token (cache refresh) -> identity is
     (issuer, subject), not the token.
                               test_same_user_new_token_is_not_a_leak
False OK
  C6 the gateway serialized every call -> OBSERVATION serialized, never OK.
                               test_serialized_is_observation_not_ok
  C7 the nonce stripped, so calls cannot be tied -> INCONCLUSIVE.
                               test_nonce_stripped_is_inconclusive
  C8 a request that reached nothing upstream (answered locally / from a cache)
     -> INCONCLUSIVE.          test_request_without_upstream_call_is_inconclusive
  C9 the leaky fixture not shown to FAIL concurrently and PASS serially in this
     run -> INCONCLUSIVE.      test_fixture_not_proven_blocks_ok
  C10 an unparseable token at the upstream -> INCONCLUSIVE.
                               test_unparsed_upstream_token_is_inconclusive
  C11 a seen leak with failing controls -> stays FAIL.
                               test_seen_leak_not_downgraded_by_controls
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .delegate import make_nonce
from .guard import authorize
from .probe import Identity

GRADE_FAIL = "FAIL"
GRADE_OK = "OK"
GRADE_INCONCLUSIVE = "INCONCLUSIVE"
GRADE_OBSERVATION = "OBSERVATION"
_GRADED = ("tools/call", "resources/read")


def make_markers(labels=("A", "B")) -> Dict[str, str]:
    """One marker per label: ``mk<label>-<24 hex>``; none is a substring of another."""
    out = {lab: f"mk{lab}-{secrets.token_hex(12)}" for lab in labels}
    check_markers(out)
    return out


def check_markers(markers: Dict[str, str]) -> None:
    vals = list(markers.values())
    for i, a in enumerate(vals):
        for j, b in enumerate(vals):
            if i != j and a in b:
                raise ValueError("markers overlap: one is a substring of another")


def grade_concurrent(
    *,
    requests: List[Dict[str, Any]],
    upstream_calls: List[Dict[str, Any]],
    markers: Dict[str, str],
    identities: Dict[str, Tuple[Optional[str], str]],
    max_inflight: int,
    fixture: Optional[Dict[str, Any]],
) -> Tuple[str, str, str]:
    """Grade one concurrent run.

    ``requests``: one dict per client request: ``label`` (A/B), ``nonce``,
    ``text`` (the response text, or None), ``error`` (None if a result came back).
    ``upstream_calls``: graded upstream calls: ``method``, ``nonce``, ``parsed``,
    ``issuer``, ``subject``. ``identities``: label -> (issuer, subject) expected.
    ``fixture``: the in-run fixture result (``practice_concurrency_http.
    run_concurrency_fixture``); OK needs ``proven`` True: the racy deputy FAILED
    this probe, PASSED the one-at-a-time probe, and the safe deputy did not FAIL.
    """
    by_nonce: Dict[str, Dict[str, Any]] = {r["nonce"]: r for r in requests}
    # --- observed leaks first ---------------------------------------------
    crossed = []
    for r in requests:
        text = r.get("text") or ""
        for other, mk in markers.items():
            if other != r["label"] and mk in text:
                crossed.append((r["label"], other, r["nonce"]))
    if crossed:
        return (GRADE_FAIL, "cross_identity_response",
                f"{len(crossed)} response(s) carried the other user's marker "
                f"(first: {crossed[0][0]}'s request got {crossed[0][1]}'s marker)")
    graded = [c for c in upstream_calls if c.get("method") in _GRADED]
    wrong = []
    for c in graded:
        req = by_nonce.get(c.get("nonce"))
        if req is None or not c.get("parsed"):
            continue
        want = identities[req["label"]]
        iss, sub = want
        if c.get("subject") != sub or (iss is not None and c.get("issuer") != iss):
            wrong.append((req["label"], c.get("issuer"), c.get("subject")))
    if wrong:
        return (GRADE_FAIL, "wrong_subject_upstream",
                f"{len(wrong)} upstream call(s) carried another identity than their request's "
                f"caller (first: {wrong[0][0]}'s request arrived as ({wrong[0][1]}, {wrong[0][2]}))")
    # --- nothing wrong seen; can we say it is right? ----------------------
    unattributed = [c for c in graded if c.get("nonce") not in by_nonce]
    if unattributed:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                f"{len(unattributed)} upstream call(s) carried no known nonce and cannot be "
                "tied to a request")
    unparsed = [c for c in graded if not c.get("parsed")]
    if unparsed:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                f"{len(unparsed)} upstream call(s) carried a token the upstream could not read")
    errored = [r for r in requests if r.get("error")]
    if errored:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                f"{len(errored)} of {len(requests)} request(s) errored "
                f"(first: {str(errored[0]['error'])[:120]})")
    no_own = [r for r in requests if markers[r["label"]] not in (r.get("text") or "")]
    if no_own:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                f"{len(no_own)} of {len(requests)} response(s) did not carry their own marker")
    reached = {c.get("nonce") for c in graded}
    missing = [r for r in requests if r["nonce"] not in reached]
    if missing:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                f"{len(missing)} of {len(requests)} request(s) made no upstream call")
    if max_inflight < 2:
        return (GRADE_OBSERVATION, "serialized",
                "every request was served correctly, but the upstream never saw two calls in "
                "flight at once: the gateway serialized them, so concurrency was not exercised")
    if not fixture or fixture.get("proven") is not True:
        return (GRADE_INCONCLUSIVE, "inconclusive",
                "the leaky fixture was not shown, in this run, to FAIL this probe while "
                "passing the one-at-a-time probe")
    return (GRADE_OK, "isolated",
            f"{len(requests)} interleaved requests each got only their own marker and reached "
            f"the upstream as their own caller; up to {max_inflight} upstream calls overlapped")


@dataclass
class ConcurrentResult:
    grade: str
    label: str
    reason: str
    pairs: int
    max_inflight: int
    requests: List[Dict[str, Any]] = field(default_factory=list)
    upstream_calls: List[Dict[str, Any]] = field(default_factory=list)
    timing: Dict[str, Any] = field(default_factory=dict)
    target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"probe": "concurrent_identities", "grade": self.grade, "label": self.label,
                "reason": self.reason, "pairs": self.pairs, "max_inflight": self.max_inflight,
                "target": self.target, "timing": self.timing,
                "requests": self.requests, "upstream_calls": self.upstream_calls}

    def summary(self) -> str:
        return f"[{self.grade}] concurrent identities: {self.label} -- {self.reason}"


def run_concurrent_probe(
    target: str,
    identity_a: Identity,
    identity_b: Identity,
    *,
    upstream,
    trigger: Callable[[Any, str], Any],
    markers: Dict[str, str],
    identities: Dict[str, Tuple[Optional[str], str]],
    pairs: int = 50,
    fixture: Optional[Dict[str, Any]] = None,
    settle_seconds: float = 1.0,
    redact: Callable[[Any], str] = str,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> ConcurrentResult:
    """Fire ``pairs`` A and ``pairs`` B calls at once and grade them.

    Every request connects as its identity and initializes BEFORE a shared
    barrier; then all fire ``trigger(client, nonce)`` together. ``upstream`` is a
    :class:`MockUpstream` that records ``nonce`` and exposes ``max_inflight``
    (the most graded calls it held at once)."""
    decision = authorize(target, authorized=authorized, authorization_note=authorization_note)
    check_markers(markers)
    jobs = [("A" if i % 2 == 0 else "B") for i in range(2 * pairs)]
    reqs: List[Dict[str, Any]] = [{"label": lab, "nonce": make_nonce(f"c{lab}"), "text": None,
                                   "error": None} for lab in jobs]
    barrier = threading.Barrier(len(reqs))
    start = len(upstream.calls)
    if hasattr(upstream, "reset_inflight"):
        upstream.reset_inflight()

    def text_of(result) -> str:
        if not isinstance(result, dict):
            return str(result)
        parts = []
        for item in result.get("content") or result.get("contents") or []:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        if result.get("isError"):
            raise RuntimeError("tool error result: " + " ".join(parts)[:200])
        return " ".join(parts)

    def worker(r):
        client = None
        try:
            ident = identity_a if r["label"] == "A" else identity_b
            client = ident.connect()
            client.initialize()
        except Exception as exc:  # noqa: BLE001
            r["error"] = redact(f"connect: {type(exc).__name__}: {exc}")[:300]
            try:
                barrier.wait(timeout=120)
            except threading.BrokenBarrierError:
                pass
            return
        try:
            try:
                barrier.wait(timeout=120)
            except threading.BrokenBarrierError:
                pass
            r["t_sent"] = time.monotonic()
            r["text"] = redact(text_of(trigger(client, r["nonce"])))[:400]
        except Exception as exc:  # noqa: BLE001
            r["error"] = redact(f"{type(exc).__name__}: {exc}")[:300]
        finally:
            r["t_done"] = time.monotonic()
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass

    threads = [threading.Thread(target=worker, args=(r,), daemon=True) for r in reqs]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=300)
    wall = time.monotonic() - t0
    if settle_seconds:
        time.sleep(settle_seconds)
    calls = [{"method": c.method, "nonce": c.nonce, "parsed": c.parsed, "issuer": c.issuer,
              "subject": c.subject, "actor": c.actor,
              "token": _fp(c.token)} for c in upstream.calls[start:] if c.method in _GRADED]
    max_inflight = int(getattr(upstream, "max_inflight", 0))
    grade, label, reason = grade_concurrent(
        requests=reqs, upstream_calls=calls, markers=markers, identities=identities,
        max_inflight=max_inflight, fixture=fixture)
    sent = [r["t_sent"] for r in reqs if "t_sent" in r]
    timing = {"wall_seconds": round(wall, 2),
              "send_spread_seconds": round(max(sent) - min(sent), 3) if sent else None}
    for r in reqs:
        r.pop("t_sent", None)
        r.pop("t_done", None)
    return ConcurrentResult(grade=grade, label=label, reason=reason, pairs=pairs,
                            max_inflight=max_inflight, requests=reqs, upstream_calls=calls,
                            timing=timing, target=decision.target)


def _fp(token: Optional[str]) -> Optional[str]:
    import hashlib
    if not token:
        return None
    if str(token).startswith("sha256:"):
        return token
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()[:12]


class InflightMixin:
    """Mixed into an upstream: counts graded calls held at once (``max_inflight``)
    and holds each for ``hold_seconds`` so overlap is observable. Off by default
    (hold 0): an upstream that does not opt in behaves exactly as before."""

    hold_seconds: float = 0.0

    def _inflight_init(self):
        self._inflight_lock = threading.Lock()
        self.inflight = 0
        self.max_inflight = 0

    def reset_inflight(self):
        with self._inflight_lock:
            self.max_inflight = self.inflight

    def enter(self):
        with self._inflight_lock:
            self.inflight += 1
            self.max_inflight = max(self.max_inflight, self.inflight)
        if self.hold_seconds:
            time.sleep(self.hold_seconds)

    def leave(self):
        with self._inflight_lock:
            self.inflight -= 1
