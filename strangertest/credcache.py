"""The same-user-credentials token-exchange cache probe (XID-10, cache-key class).

When a gateway exchanges a caller's *inbound* credential for an upstream token
(RFC 8693 token exchange / on-behalf-of) and **caches** the exchanged token, the
cache key must include the specific inbound credential. If it keys only on
``(gateway, user, audience)`` and omits the credential, two credentials of the
**same user** collide — for example a broad interactive **session JWT** and a
restricted **API token**. The upstream token minted for the first is then served
to the second, so the second caller reaches the upstream carrying *more
authority than its own credential holds*.

This is the class of **CVE-2026-110195** (IBM ContextForge MCP Gateway, affected
1.0.0–1.0.11, fixed in 1.1.0 by adding the inbound ``subject_token`` to the
token-exchange cache key). Our existing delegation probe (:mod:`strangertest.delegate`)
drives **two different users**; this one drives **one user, two credentials**, so
it catches a leak that per-user isolation alone would miss.

How it observes
---------------
The probe owns an upstream it controls (as the delegation probe does) and drives
the deputy as credential 1 (broad) then credential 2 (narrow). Both legs are the
same user; only the credential differs. Every leg carries a per-request nonce so
each upstream call can be tied to the request that caused it.

* **Cold-cache control (positive control).** With a cold cache, credential 1 and
  credential 2 are each driven on their own. The upstream must see a *distinct*
  token per credential. If it does not — e.g. the deputy mints one static token
  for everyone — then a later "same token" in the warm test is not a cache
  collision, and the probe refuses to call it a leak (INCONCLUSIVE).
* **Warm-cache test.** With a cold cache, credential 1 is driven (populating the
  cache) and then credential 2 (a warm hit). The probe inspects the upstream call
  tied to credential 2's request:

  - **FAIL** — credential 2's call carried the token minted for credential 1
    (identical fingerprint), or a scope that only credential 1 holds. The cached
    token was reused across two credentials of the same user.
  - **OK** — credential 2's call carried its own distinct token and only its own
    scope: a fresh exchange happened, so the cache key includes the credential.
  - **INCONCLUSIVE** — the cold control did not establish per-credential
    distinctness, or credential 2's call never reached the upstream, so there is
    nothing to grade (never reported as OK).
* **Expired-cache observation.** After the cached entry expires, credential 2 is
  driven once more; whether it then gets its own token is recorded as an
  observation (it confirms a *cache-key* collision within the TTL rather than a
  permanent conflation). Observation only — never changes the grade.

Grades are ``FAIL``, ``OK`` and ``INCONCLUSIVE``. Tokens are only ever recorded
as ``sha256:`` fingerprints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import secrets

from .guard import authorize
from .delegate import UpstreamCall, token_fingerprint
from .probe import ProbeError

__all__ = [
    "Credential",
    "Verdict",
    "CredentialCacheReport",
    "run_same_user_credentials_probe",
    "FAIL",
    "OK",
    "INCONCLUSIVE",
]

FAIL = "FAIL"
OK = "OK"
INCONCLUSIVE = "INCONCLUSIVE"

FAILURE_CLASS = (
    "cached upstream token reused across two credentials of the same user "
    "(token-exchange cache key)"
)


@dataclass
class Credential:
    """One inbound credential for a user.

    ``label`` names it (e.g. ``"session"``); ``token`` is the inbound bearer the
    deputy exchanges (the RFC 8693 subject token). Two credentials of the same
    user share the user but differ in ``token`` and, usually, in the upstream
    scope they are entitled to.
    """

    label: str
    token: str


@dataclass
class Verdict:
    grade: str
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {"grade": self.grade, "detail": self.detail}


def _scope_set(value: Any) -> set:
    """Normalize a scope claim (list, space-delimited string, or None) to a set."""
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(v) for v in value if v is not None}
    text = str(value).strip()
    return set(text.split()) if text else set()


def _nonce(tag: str) -> str:
    return f"stcc-{tag}-{secrets.token_hex(6)}"


@dataclass
class CredentialCacheReport:
    target: str
    upstream_target: str
    authorization: str
    user: str
    cred1_label: str
    cred2_label: str
    cold_control: Verdict
    warm: Verdict
    observations: Dict[str, Any] = field(default_factory=dict)

    @property
    def vulnerable(self) -> bool:
        return self.warm.grade == FAIL

    @property
    def grade(self) -> str:
        return self.warm.grade

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "probe": "same-user-credentials",
            "target": self.target,
            "upstream_target": self.upstream_target,
            "authorization": self.authorization,
            "user": self.user,
            "cred1_label": self.cred1_label,
            "cred2_label": self.cred2_label,
            "cold_control": self.cold_control.to_dict(),
            "warm": self.warm.to_dict(),
            "grade": self.grade,
            "vulnerable": self.vulnerable,
            "observations": dict(self.observations),
        }
        if self.vulnerable:
            data["failure_class"] = FAILURE_CLASS
        return data

    def summary(self) -> str:
        if self.grade == FAIL:
            return (
                f"FAIL: credential {self.cred2_label!r} reached the upstream with "
                f"authority minted for credential {self.cred1_label!r} (same user "
                f"{self.user!r}) — {self.warm.detail}. {FAILURE_CLASS}."
            )
        if self.grade == OK:
            return (
                f"OK: credential {self.cred2_label!r} reached the upstream with its "
                f"own distinct token and scope, not credential {self.cred1_label!r}'s."
            )
        return f"INCONCLUSIVE: {self.warm.detail}"


def _call_fp(call: Optional[UpstreamCall]) -> Optional[str]:
    if call is None or call.token is None:
        return None
    tok = str(call.token)
    return tok if tok.startswith("sha256:") else token_fingerprint(tok)


def _grade_cold(
    c1: Optional[UpstreamCall], c2: Optional[UpstreamCall], obs: Dict[str, Any]
) -> Verdict:
    """The positive control: each credential must mint its own distinct token."""
    if c1 is None or c2 is None:
        which = "credential 1" if c1 is None else "credential 2"
        return Verdict(
            INCONCLUSIVE,
            f"no cold-cache upstream call was observed for {which}; the observer "
            f"could not see a per-credential token, so a warm match cannot be graded",
        )
    if not c1.parsed or not c2.parsed:
        return Verdict(
            INCONCLUSIVE,
            "a cold-cache upstream token could not be parsed; the observer cannot "
            "read the delegated credential",
        )
    f1, f2 = _call_fp(c1), _call_fp(c2)
    if f1 is None or f2 is None:
        return Verdict(
            INCONCLUSIVE,
            "a cold-cache upstream call carried no token to fingerprint",
        )
    if f1 == f2:
        return Verdict(
            INCONCLUSIVE,
            "both credentials received the SAME upstream token on a cold cache: "
            "the deputy does not mint a per-credential token at all, so a warm "
            "match is not evidence of a cache-key collision",
        )
    obs["cold_cred1_token"] = f1
    obs["cold_cred2_token"] = f2
    obs["cold_cred1_scope"] = sorted(_scope_set(c1.scope))
    obs["cold_cred2_scope"] = sorted(_scope_set(c2.scope))
    return Verdict(
        OK,
        "each credential minted its own distinct upstream token on a cold cache "
        "(positive control passed)",
    )


def _grade_warm(
    cold: Verdict,
    populate: Optional[UpstreamCall],
    cred2_warm: Optional[UpstreamCall],
    cred1_cold: Optional[UpstreamCall],
    cred2_cold: Optional[UpstreamCall],
    cache_hit_observed: bool,
    obs: Dict[str, Any],
) -> Verdict:
    if cold.grade != OK:
        return Verdict(
            INCONCLUSIVE,
            f"cold-cache control did not establish distinct per-credential tokens, "
            f"so a warm match proves nothing: {cold.detail}",
        )
    # False-OK guard: the populate leg (credential 1, warm run) must have reached
    # the upstream, or the cache was never warmed and the test is meaningless.
    if populate is None:
        return Verdict(
            INCONCLUSIVE,
            "credential 1's warm populate call did not reach the upstream, so the "
            "cache was never warmed; the test is inconclusive",
        )
    pop_fp = _call_fp(populate)
    obs["warm_populate_token"] = pop_fp
    # False-OK guard: credential 2's warm call must have reached the upstream, or
    # the deputy served it some other way and there is nothing to grade.
    if cred2_warm is None:
        return Verdict(
            INCONCLUSIVE,
            "no upstream call tied to credential 2's warm request was observed "
            "(the deputy did not forward it); cannot grade — not reported as OK",
        )
    if not cred2_warm.parsed:
        return Verdict(
            INCONCLUSIVE,
            "credential 2's warm upstream token could not be parsed; cannot grade",
        )
    w_fp = _call_fp(cred2_warm)
    obs["warm_cred2_token"] = w_fp
    # Leak by token reuse: credential 2 carried the exact token minted for
    # credential 1 in this warm run.
    if w_fp is not None and pop_fp is not None and w_fp == pop_fp:
        return Verdict(
            FAIL,
            "credential 2's upstream call carried the token minted for credential 1 "
            "(identical fingerprint): the cached exchanged token was reused across "
            "two credentials of the same user",
        )
    # Leak by scope escalation: distinct token, but it grants a scope that only
    # credential 1 holds (and credential 2 does not).
    warm_scope = _scope_set(cred2_warm.scope)
    legit = _scope_set(cred2_cold.scope) if cred2_cold is not None else set()
    broad = _scope_set(cred1_cold.scope) if cred1_cold is not None else set()
    escalated = (warm_scope - legit) & broad
    if escalated:
        obs["warm_cred2_scope"] = sorted(warm_scope)
        return Verdict(
            FAIL,
            f"credential 2's upstream call carried scope(s) {sorted(escalated)} that "
            f"only credential 1 holds and credential 2 does not: cached authority "
            f"reused across credentials of the same user",
        )
    # OK only when positively observed: a distinct token and no escalated scope.
    if w_fp is not None and w_fp != pop_fp and warm_scope <= legit:
        obs["warm_cred2_scope"] = sorted(warm_scope)
        # The same-credential repeat control decides how strong a claim we make:
        # a cache hit on credential 1 proves the gateway caches at all, so a
        # distinct token for credential 2 means the cache is keyed per credential.
        # Without a cache hit we only observed no reuse, not why.
        if cache_hit_observed:
            detail = "no cross-credential reuse; the gateway caches per credential"
        else:
            detail = "no cross-credential reuse; caching not observed in this run"
        return Verdict(OK, detail)
    return Verdict(
        INCONCLUSIVE,
        "credential 2's warm token/scope could not be resolved against the cold "
        "controls; not reported as OK",
    )


def run_same_user_credentials_probe(
    *,
    target: str,
    upstream_target: str,
    user: str,
    cred1: Credential,
    cred2: Credential,
    read_resource: Callable[[str, str], Any],
    uri_for: Callable[[str], str],
    upstream_calls: Callable[[], List[UpstreamCall]],
    fresh_cache: Callable[[], None],
    expire_cache: Optional[Callable[[], None]] = None,
    exchange_attempts: Optional[Callable[[], int]] = None,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> CredentialCacheReport:
    """Drive the same-user-credentials cache probe against ``target``.

    ``cred1`` (broad) and ``cred2`` (narrow) are two credentials of one ``user``.
    ``read_resource(token, uri)`` drives one ``resources/read`` through the deputy
    as the given inbound credential bearer and must raise on failure.
    ``uri_for(nonce)`` builds a resource URI carrying the nonce. ``upstream_calls``
    returns every :class:`~strangertest.delegate.UpstreamCall` the owned upstream
    has recorded (each tagged with its ``nonce``). ``fresh_cache`` resets the
    deputy's token-exchange cache to cold; ``expire_cache`` (optional) forces
    cached entries to expire for the observation.

    Both ``target`` and ``upstream_target`` pass the authorization guard first.
    """
    decision = authorize(
        target, authorized=authorized, authorization_note=authorization_note
    )
    authorize(
        upstream_target, authorized=authorized, authorization_note=authorization_note
    )

    def call_for(nonce: str) -> Optional[UpstreamCall]:
        hits = [c for c in upstream_calls() if c.nonce == nonce]
        return hits[-1] if hits else None

    def drive(cred: Credential, tag: str) -> str:
        nonce = _nonce(tag)
        try:
            read_resource(cred.token, uri_for(nonce))
        except Exception as exc:  # noqa: BLE001 — surfaced as a probe-setup failure
            raise ProbeError(
                f"could not drive a read as credential {cred.label!r} "
                f"({tag}): {exc}. The probe is inconclusive."
            )
        return nonce

    obs: Dict[str, Any] = {"user": user}

    # --- Cold-cache control: each credential alone, fresh cache each time. ---
    fresh_cache()
    cold1 = call_for(drive(cred1, "cold1"))
    fresh_cache()
    cold2 = call_for(drive(cred2, "cold2"))
    cold = _grade_cold(cold1, cold2, obs)

    # --- Warm-cache test: credential 1 populates, repeats (same credential
    # twice in a row, the caching control), then credential 2 hits warm. ---
    fresh_cache()
    populate = call_for(drive(cred1, "warm1"))
    ex_before = exchange_attempts() if exchange_attempts is not None else None
    repeat = call_for(drive(cred1, "warm1b"))  # credential 1, twice in a row
    ex_after = exchange_attempts() if exchange_attempts is not None else None
    # Cache hit: the repeat triggered no new exchange AND carried the same token.
    cache_hit = bool(
        exchange_attempts is not None
        and ex_before is not None
        and ex_after == ex_before
        and repeat is not None
        and populate is not None
        and _call_fp(repeat) == _call_fp(populate)
    )
    obs["warm_repeat_token"] = _call_fp(repeat)
    obs["cache_hit_observed"] = cache_hit
    if ex_before is not None:
        obs["exchange_attempts_after_populate"] = ex_before
        obs["exchange_attempts_after_repeat"] = ex_after
    cred2_warm = call_for(drive(cred2, "warm2"))
    warm = _grade_warm(cold, populate, cred2_warm, cold1, cold2, cache_hit, obs)

    # --- Expired-cache observation (never changes the grade). ---
    if expire_cache is not None:
        try:
            expire_cache()
            after = call_for(drive(cred2, "expired"))
            after_fp = _call_fp(after)
            pop_fp = _call_fp(populate)
            obs["after_expiry_cred2_token"] = after_fp
            obs["after_expiry_distinct_from_cred1"] = (
                after_fp is not None and after_fp != pop_fp
            )
        except ProbeError as exc:
            obs["after_expiry_error"] = str(exc)

    return CredentialCacheReport(
        target=decision.target,
        upstream_target=upstream_target,
        authorization=decision.reason,
        user=user,
        cred1_label=cred1.label,
        cred2_label=cred2.label,
        cold_control=cold,
        warm=warm,
        observations=obs,
    )
