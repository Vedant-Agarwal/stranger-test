"""The elicitation cross-user-binding / account-takeover probe.

Identity A starts an elicitation (a ``tools/call`` that returns an elicitation
descriptor -- URL/OAuth mode or form mode). Identity B, authenticated as B,
completes the authorization step. Does the resulting grant bind to A (the user
who STARTED) although B completed it? If so, B has taken over A's grant: a
**cross-user elicitation binding / account-takeover leak**. Separately: does the
server request a forbidden secret (password / API key / access token / payment
credential) in FORM mode?

MCP 2026-07-28 elicitation says a server MUST ensure the user who started the
elicitation is the same user who completes the authorization, MUST bind the
elicitation/grant to the authenticated completing user (id derived from the
credential's ``sub``), and MUST NOT use form mode to request such secrets.

Same "A acts, B acts, observe the binding" shape as the other probes:
connections come from :class:`~strangertest.probe.Identity` objects and the
server-specific steps (start / complete / observe / whoami) are injected through
an :class:`ElicitationPlan`, so the engine stays server-agnostic and testable.

Grading (never OK for something not observed):

* Positive controls first, every OK backed by a control that would have failed
  if the observer were broken:
  - ``whoami`` for A and B must return distinct subject fingerprints, else
    INCONCLUSIVE (the probe cannot tell the two identities apart).
  - Happy path: A starts and A completes -> the grant MUST bind to A. If it does
    not, the binding is not observable here -> INCONCLUSIVE.
  - B starts and B completes -> the grant MUST bind to B. Proves a correct
    completer-binding is observable and differs from A's.
* Attack: A starts, B completes.
  - grant binds to A (the starter) -> LEAK (B took over A's grant).
  - grant binds to B (the completer) -> OK.
  - B was refused and nothing bound to A -> OK.
  - could not observe a binding -> INCONCLUSIVE.
* Form-secret: any elicitation descriptor seen in ``form`` mode that requests a
  forbidden secret -> LEAK (``forbidden-secret`` failure). URL mode, or a form
  with no secret, is OK for this check.
* Server offers no elicitation (start returns no descriptor): INCONCLUSIVE.

Fingerprints only: the probe compares ``sha256:`` subject fingerprints the
server returns, never a raw ``sub``, token or secret.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .guard import authorize
from .mcp_client import MCPClient
from .probe import Identity, new_marker

try:  # defaults reuse the practice server's helpers when it is importable
    from .practice_elicitation_http import FORBIDDEN_SECRET_HINTS
except Exception:  # pragma: no cover - the probe is usable without the practice server
    FORBIDDEN_SECRET_HINTS = (
        "password", "passwd", "secret", "apikey", "api_key", "api-key",
        "accesstoken", "access_token", "token", "private_key", "privatekey",
        "card", "cardnumber", "cvv", "cvc", "pan", "ssn",
    )

__all__ = [
    "LEAK",
    "OK",
    "INCONCLUSIVE",
    "ElicitationPlan",
    "CheckResult",
    "ElicitationReport",
    "forbidden_secret_field",
    "run_elicitation_takeover_probe",
]

LEAK = "LEAK"
OK = "OK"
INCONCLUSIVE = "INCONCLUSIVE"

FAILURE_CLASS = "cross-user elicitation binding / account-takeover leak"
SECRET_FAILURE_CLASS = "forbidden-secret request in form-mode elicitation"


def _text_of(result: Any) -> str:
    import json

    return json.dumps(result, default=str)


def forbidden_secret_field(descriptor: Any) -> Optional[str]:
    """The name of a forbidden-secret field a FORM-mode descriptor requests, else None.

    A property is forbidden if its name contains a secret hint
    (case-insensitive) or its JSON-schema ``format`` is ``password``. URL-mode
    (or non-form) descriptors never match.
    """
    if not isinstance(descriptor, dict):
        return None
    if descriptor.get("mode") != "form":
        return None
    schema = descriptor.get("requestedSchema")
    if not isinstance(schema, dict):
        return None
    props = schema.get("properties")
    if not isinstance(props, dict):
        return None
    for name, spec in props.items():
        lname = str(name).lower()
        if any(hint in lname for hint in FORBIDDEN_SECRET_HINTS):
            return str(name)
        if isinstance(spec, dict) and str(spec.get("format", "")).lower() == "password":
            return str(name)
    return None


@dataclass
class ElicitationPlan:
    """How to drive one server's elicitation flow.

    Defaults match :mod:`strangertest.practice_elicitation_http`. For another
    server, supply callables that speak its tool names / shapes. Every callable
    gets a connected, initialized :class:`MCPClient`.

    * ``start(client, marker)`` -> the ``tools/call`` result of starting an
      elicitation.
    * ``parse_descriptor(result)`` -> the elicitation descriptor dict (with an
      ``elicitationId`` and a ``mode``), or None if the server offered none.
    * ``complete(client, descriptor)`` -> the result/outcome of completing the
      authorization as ``client``'s identity.
    * ``observe_binding(client, descriptor)`` -> the subject FINGERPRINT the
      grant bound to (``sha256:...``), or None if nothing is bound.
    * ``whoami(client)`` -> ``client``'s own subject fingerprint.
    """

    start_tool: str = "authorize_integration"
    complete_tool: str = "complete_authorization"
    status_tool: str = "grant_status"
    whoami_tool: str = "whoami"

    start: Callable[[MCPClient, str], Any] = None  # type: ignore[assignment]
    parse_descriptor: Callable[[Any], Optional[Dict[str, Any]]] = None  # type: ignore[assignment]
    complete: Callable[[MCPClient, Dict[str, Any]], Any] = None  # type: ignore[assignment]
    observe_binding: Callable[[MCPClient, Dict[str, Any]], Optional[str]] = None  # type: ignore[assignment]
    whoami: Callable[[MCPClient], Optional[str]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.start is None:
            self.start = lambda c, marker: c.call_tool(
                self.start_tool, {"marker": marker}
            )
        if self.parse_descriptor is None:
            self.parse_descriptor = _default_parse_descriptor
        if self.complete is None:
            self.complete = lambda c, d: c.call_tool(
                self.complete_tool, {"elicitationId": d.get("elicitationId")}
            )
        if self.observe_binding is None:
            self.observe_binding = lambda c, d: _read_binding(
                c.call_tool(self.status_tool, {"elicitationId": d.get("elicitationId")})
            )
        if self.whoami is None:
            self.whoami = lambda c: _read_fp(
                c.call_tool(self.whoami_tool, {}), "subjectFingerprint"
            )


def _default_parse_descriptor(result: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(result, dict):
        return None
    desc = result.get("elicitation")
    if isinstance(desc, dict) and desc.get("elicitationId") and desc.get("mode"):
        return desc
    return None


def _read_fp(result: Any, key: str) -> Optional[str]:
    if isinstance(result, dict):
        value = result.get(key)
        if isinstance(value, str) and value.startswith("sha256:"):
            return value
    return None


def _read_binding(result: Any) -> Optional[str]:
    if isinstance(result, dict) and not result.get("granted", True):
        return None
    return _read_fp(result, "boundSubjectFingerprint")


@dataclass
class CheckResult:
    name: str
    grade: str
    detail: str


@dataclass
class ElicitationReport:
    target: str
    authorization: str
    identity_a: str
    identity_b: str
    grade: str
    detail: str
    checks: Dict[str, CheckResult] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)
    fingerprints: Dict[str, Optional[str]] = field(default_factory=dict)

    @property
    def leaked(self) -> bool:
        return self.grade == LEAK

    @property
    def leaked_checks(self) -> List[str]:
        return [n for n, r in self.checks.items() if r.grade == LEAK]

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "probe": "elicitation_takeover",
            "target": self.target,
            "authorization": self.authorization,
            "identity_a": self.identity_a,
            "identity_b": self.identity_b,
            "grade": self.grade,
            "detail": self.detail,
            "checks": {
                n: {"grade": r.grade, "detail": r.detail}
                for n, r in self.checks.items()
            },
            "observations": list(self.observations),
            # Fingerprints only (sha256:...), never a raw subject or token.
            "fingerprints": dict(self.fingerprints),
        }
        if self.leaked:
            if self.checks.get("binding") and self.checks["binding"].grade == LEAK:
                data["failure_class"] = FAILURE_CLASS
            else:
                data["failure_class"] = SECRET_FAILURE_CLASS
            data["leaked_checks"] = self.leaked_checks
        return data

    def summary(self) -> str:
        if self.grade == LEAK:
            if self.checks.get("binding") and self.checks["binding"].grade == LEAK:
                return (
                    f"LEAK: identity {self.identity_b!r} completed an elicitation "
                    f"that identity {self.identity_a!r} started, and the grant "
                    f"bound to {self.identity_a!r} -- {FAILURE_CLASS}."
                )
            return (
                f"LEAK: the server requested a forbidden secret in a form-mode "
                f"elicitation -- {SECRET_FAILURE_CLASS}."
            )
        if self.grade == OK:
            return (
                f"OK: the grant bound to the verified completing user and no "
                f"forbidden secret was requested in form mode."
            )
        return f"INCONCLUSIVE: {self.detail}"


class _Inconclusive(Exception):
    pass


def _safe_close(client: Optional[MCPClient]) -> None:
    if client is None:
        return
    try:
        client.close()
    except Exception:
        pass


def run_elicitation_takeover_probe(
    target: str,
    identity_a: Identity,
    identity_b: Identity,
    *,
    plan: Optional[ElicitationPlan] = None,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> ElicitationReport:
    """A starts an elicitation, B completes it; grade whose grant it bound to."""
    decision = authorize(
        target, authorized=authorized, authorization_note=authorization_note
    )
    plan = plan or ElicitationPlan()

    checks: Dict[str, CheckResult] = {}
    observations: List[str] = []
    fingerprints: Dict[str, Optional[str]] = {}

    def report(grade: str, detail: str) -> ElicitationReport:
        return ElicitationReport(
            target=decision.target,
            authorization=decision.reason,
            identity_a=identity_a.label,
            identity_b=identity_b.label,
            grade=grade,
            detail=detail,
            checks=checks,
            observations=observations,
            fingerprints=fingerprints,
        )

    client_a = identity_a.connect()
    client_b: Optional[MCPClient] = None
    secret_found: Optional[str] = None

    def note_secret(descriptor: Optional[Dict[str, Any]]) -> None:
        nonlocal secret_found
        if secret_found is None and descriptor is not None:
            field_name = forbidden_secret_field(descriptor)
            if field_name is not None:
                secret_found = field_name

    try:
        try:
            client_a.initialize()
            client_b = identity_b.connect()
            client_b.initialize()

            # --- identities must be observable and distinct ---
            a_fp = plan.whoami(client_a)
            b_fp = plan.whoami(client_b)
            fingerprints["identity_a"] = a_fp
            fingerprints["identity_b"] = b_fp
            if a_fp is None or b_fp is None:
                raise _Inconclusive(
                    "could not read a subject fingerprint for A and/or B "
                    "(whoami); cannot grade binding"
                )
            if a_fp == b_fp:
                raise _Inconclusive(
                    "A and B have the same subject fingerprint; they are "
                    "indistinguishable, so a binding cannot be attributed"
                )

            # --- does the server elicit at all? ---
            started = plan.start(client_a, new_marker())
            desc_pc = plan.parse_descriptor(started)
            if desc_pc is None:
                raise _Inconclusive(
                    "the start tool returned no elicitation descriptor: the "
                    "server does not elicit (or the plan's tool is wrong)"
                )
            note_secret(desc_pc)

            # --- control 1 (happy path): A starts, A completes -> binds to A ---
            plan.complete(client_a, desc_pc)
            bound_aa = plan.observe_binding(client_a, desc_pc)
            if bound_aa != a_fp:
                raise _Inconclusive(
                    "happy-path control failed: A-starts/A-completes did not "
                    f"bind to A (observed {bound_aa!r}, expected A's {a_fp!r}); "
                    "the binding is not observable here"
                )

            # --- control 2: B starts, B completes -> binds to B ---
            started_bb = plan.start(client_b, new_marker())
            desc_bb = plan.parse_descriptor(started_bb)
            if desc_bb is None:
                raise _Inconclusive(
                    "control failed: the start tool stopped returning an "
                    "elicitation descriptor for B"
                )
            note_secret(desc_bb)
            plan.complete(client_b, desc_bb)
            bound_bb = plan.observe_binding(client_b, desc_bb)
            if bound_bb != b_fp:
                raise _Inconclusive(
                    "control failed: B-starts/B-completes did not bind to B "
                    f"(observed {bound_bb!r}, expected B's {b_fp!r})"
                )
        except _Inconclusive as exc:
            return report(INCONCLUSIVE, str(exc))
        except Exception as exc:
            return report(INCONCLUSIVE, f"could not set up the probe: {exc}")

        # --- attack: A starts, B completes ---
        binding_grade = INCONCLUSIVE
        binding_detail = ""
        try:
            started_attack = plan.start(client_a, new_marker())
            desc_attack = plan.parse_descriptor(started_attack)
            if desc_attack is None:
                binding_detail = "A's attack start returned no elicitation descriptor"
            else:
                note_secret(desc_attack)
                complete_failed = False
                try:
                    plan.complete(client_b, desc_attack)
                except Exception as exc:
                    # A completion that raised (e.g. transport/JSON-RPC error)
                    # means B was refused: a refusal, not a leak.
                    complete_failed = True
                    observations.append(f"B's completion raised: {exc}")
                bound_attack = plan.observe_binding(client_a, desc_attack)
                fingerprints["attack_bound"] = bound_attack
                if bound_attack == a_fp:
                    binding_grade = LEAK
                    binding_detail = (
                        "B completed the elicitation A started, and the grant "
                        "bound to A (the starter): account takeover"
                    )
                elif bound_attack == b_fp:
                    binding_grade = OK
                    binding_detail = "the grant bound to B, the completing user"
                elif bound_attack is None:
                    if complete_failed:
                        binding_grade = OK
                        binding_detail = "B was refused; nothing bound to A"
                    else:
                        binding_detail = (
                            "B's completion was acknowledged but no binding is "
                            "observable; neither takeover nor a clean refusal"
                        )
                else:
                    binding_detail = (
                        f"the grant bound to an unrecognised subject "
                        f"{bound_attack!r} (not A or B)"
                    )
        except Exception as exc:
            binding_detail = f"could not run the attack: {exc}"
        checks["binding"] = CheckResult("binding", binding_grade, binding_detail)

        # --- form-mode forbidden-secret check ---
        if secret_found is not None:
            checks["form_secret"] = CheckResult(
                "form_secret", LEAK,
                f"a form-mode elicitation requested a forbidden secret field "
                f"{secret_found!r} (password/API key/token/payment credential)",
            )
        else:
            checks["form_secret"] = CheckResult(
                "form_secret", OK,
                "no forbidden secret requested in form mode "
                "(URL mode, or a form with no secret field)",
            )
    finally:
        _safe_close(client_a)
        _safe_close(client_b)

    grades = {r.grade for r in checks.values()}
    if LEAK in grades:
        overall = LEAK
        detail = "; ".join(
            f"{n}: {r.detail}" for n, r in checks.items() if r.grade == LEAK
        )
    elif grades == {OK}:
        overall = OK
        detail = "grant bound to the completing user; no forbidden secret in form mode"
    else:
        overall = INCONCLUSIVE
        detail = "; ".join(
            f"{n}: {r.detail}" for n, r in checks.items() if r.grade != OK
        )
    return report(overall, detail)
