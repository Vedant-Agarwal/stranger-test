"""Renderers for the one-command scanner: human, JSON and SARIF.

Stdlib only. Colour is used only when writing to a TTY. No renderer ever prints
a raw token, key or session id — only the fingerprints the adapter put in the
profile; a defensive scrub drops any ``authorization`` header value that slips
through.

Exit codes (owned here, applied by the CLI):
    0  no RISK finding
    1  at least one RISK finding
    2  target unreachable / scan error  (set by the CLI, not from findings)
"""

from __future__ import annotations

import io
import json
import sys
from typing import Any, Dict, List, Optional, Sequence

from .model import GRADES, SEVERITIES, field_of, to_plain

__all__ = [
    "render",
    "human_report",
    "json_report",
    "sarif_report",
    "exit_code",
    "EXIT_OK",
    "EXIT_RISK",
    "EXIT_ERROR",
]

EXIT_OK = 0
EXIT_RISK = 1
EXIT_ERROR = 2

# Grades in display order, with the glyph/label shown in the human report.
_GRADE_LABEL = {
    "RISK": "RISK",
    "OBSERVATION": "OBSERVATION",
    "OK": "OK",
    "INCONCLUSIVE": "INCONCLUSIVE",
}

# ANSI colours, only emitted to a TTY.
_ANSI = {
    "RISK": "\033[31m",       # red
    "OBSERVATION": "\033[33m",  # yellow
    "OK": "\033[32m",         # green
    "INCONCLUSIVE": "\033[90m",  # grey
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

_SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def exit_code(findings: Sequence[Any]) -> int:
    """0 if no finding is graded RISK, else 1. (Unreachable/error is exit 2,
    set by the CLI before it ever renders.)"""
    for f in findings or ():
        if field_of(f, "grade") == "RISK":
            return EXIT_RISK
    return EXIT_OK


def _scrub_headers(headers: Any) -> Dict[str, Any]:
    """Return headers with any sensitive value redacted. Defensive only — the
    profile should carry response headers, which do not hold the caller's
    bearer, but we never want to be the thing that prints one."""
    out: Dict[str, Any] = {}
    if not isinstance(headers, dict):
        return out
    for k, v in headers.items():
        if str(k).lower() in _SENSITIVE_HEADERS:
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


def _grouped(findings: Sequence[Any]) -> Dict[str, List[Any]]:
    groups: Dict[str, List[Any]] = {g: [] for g in GRADES}
    for f in findings or ():
        grade = field_of(f, "grade", "INCONCLUSIVE")
        groups.setdefault(grade, []).append(f)
    # Within a group, sort by severity (worst first) for a stable, skimmable order.
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    for g in groups:
        groups[g].sort(key=lambda f: sev_rank.get(field_of(f, "severity_hint", "info"), 99))
    return groups


def _counts(findings: Sequence[Any]) -> Dict[str, int]:
    counts = {g: 0 for g in GRADES}
    for f in findings or ():
        grade = field_of(f, "grade", "INCONCLUSIVE")
        counts[grade] = counts.get(grade, 0) + 1
    return counts


def _verdict_line(profile: Any, findings: Sequence[Any]) -> str:
    if not field_of(profile, "reachable", False):
        return "VERDICT: target unreachable — nothing could be observed."
    counts = _counts(findings)
    risk = counts.get("RISK", 0)
    if risk:
        return (
            f"VERDICT: {risk} risk signal{'s' if risk != 1 else ''} to review "
            f"(not a confirmed leak — see the footer)."
        )
    inconclusive = counts.get("INCONCLUSIVE", 0)
    tail = (
        f" {inconclusive} check{'s' if inconclusive != 1 else ''} inconclusive."
        if inconclusive
        else ""
    )
    return f"VERDICT: no risk signals in this pass.{tail}"


# --------------------------------------------------------------------------- #
# human
# --------------------------------------------------------------------------- #

def human_report(profile: Any, findings: Sequence[Any], *, color: bool = False) -> str:
    def c(text: str, key: str) -> str:
        if not color:
            return text
        return f"{_ANSI.get(key, '')}{text}{_ANSI['reset']}"

    out = io.StringIO()
    w = out.write

    url = field_of(profile, "url", "?")
    reachable = field_of(profile, "reachable", False)

    w(c("stranger-test scan", "bold") + f"  {url}\n")
    w("=" * min(72, max(24, len(url) + 19)) + "\n")

    if not reachable:
        errors = field_of(profile, "errors", []) or []
        w(c("UNREACHABLE", "RISK") + ": the server could not be profiled.\n")
        for e in errors:
            w(f"  - {e}\n")
        w("\n" + _verdict_line(profile, findings) + "\n")
        return out.getvalue()

    # --- server summary ---
    server_info = field_of(profile, "server_info", {}) or {}
    name = server_info.get("name") if isinstance(server_info, dict) else None
    version = server_info.get("version") if isinstance(server_info, dict) else None
    auth = field_of(profile, "auth", None)
    cache = field_of(profile, "cache", None)
    session = field_of(profile, "session", None)

    w(c("Server", "bold") + "\n")
    srv = f"{name} {version}".strip() if (name or version) else "(no serverInfo)"
    w(f"  name            {srv}\n")
    w(f"  transport       {field_of(profile, 'transport') or '?'}\n")
    w(f"  protocol        {field_of(profile, 'protocol_version') or '?'}\n")
    caps = field_of(profile, "capabilities", {}) or {}
    if isinstance(caps, dict) and caps:
        w(f"  capabilities    {', '.join(sorted(caps.keys()))}\n")
    if auth is not None:
        required = field_of(auth, "required", False)
        scheme = field_of(auth, "scheme") or "none"
        w(f"  auth            {'required' if required else 'not required'} ({scheme})\n")
    if session is not None and field_of(session, "issues_session_id", False):
        w("  session         issues Mcp-Session-Id\n")
    if cache is not None and field_of(cache, "advertises_cachescope", False):
        priv = "private" if field_of(cache, "forces_private", False) else "shared"
        w(f"  cache-scope     advertised ({priv})\n")
    w("\n")

    # --- findings grouped by grade ---
    groups = _grouped(findings)
    counts = _counts(findings)
    summary_bits = [f"{counts[g]} {_GRADE_LABEL[g].lower()}" for g in GRADES if counts[g]]
    w(c("Findings", "bold") + f"  ({', '.join(summary_bits) or 'none'})\n")

    any_printed = False
    for grade in GRADES:
        items = groups.get(grade) or []
        if not items:
            continue
        any_printed = True
        w("\n" + c(_GRADE_LABEL[grade], grade) + "\n")
        for f in items:
            sev = field_of(f, "severity_hint", "info")
            check_id = field_of(f, "check_id", "?")
            title = field_of(f, "title", "")
            w(f"  [{sev:<6}] {c(check_id, grade)}  {title}\n")
            rationale = field_of(f, "rationale", "")
            if rationale:
                w(f"           {c(rationale, 'dim')}\n")
            rec = field_of(f, "recommendation", "")
            if rec:
                w(f"           {c('fix: ' + rec, 'dim')}\n")
            try:
                from ..deep_tests import CONFIRM_FOR_CHECK
                tid = CONFIRM_FOR_CHECK.get(check_id)
            except Exception:
                tid = None
            if tid:
                w(f"           {c('confirm: stranger-test confirm ' + tid + ' ' + str(url), 'dim')}\n")
    if not any_printed:
        w("  (no findings)\n")

    # --- verdict + footer ---
    w("\n" + c(_verdict_line(profile, findings), "bold") + "\n")
    w(c(
        "to confirm the auth-leak classes, run the lab deep-check.",
        "dim",
    ) + "\n")
    return out.getvalue()


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #

def json_report(profile: Any, findings: Sequence[Any]) -> str:
    """``{profile, findings}`` as JSON. Fingerprints only — a defensive scrub
    redacts any sensitive header value that slipped into the profile."""
    profile_d = to_plain(profile)
    if isinstance(profile_d, dict) and "headers" in profile_d:
        profile_d["headers"] = _scrub_headers(profile_d.get("headers"))
    payload = {
        "profile": profile_d,
        "findings": [to_plain(f) for f in (findings or ())],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


# --------------------------------------------------------------------------- #
# SARIF 2.1.0
# --------------------------------------------------------------------------- #

# grade/severity -> SARIF result level (none | note | warning | error).
def _sarif_level(grade: str, severity: str) -> str:
    if grade == "RISK":
        return "error" if severity == "high" else "warning"
    if grade == "OBSERVATION":
        return "warning" if severity in ("high", "medium") else "note"
    if grade == "INCONCLUSIVE":
        return "note"
    return "none"  # OK


def sarif_report(profile: Any, findings: Sequence[Any], *, version: str = "0.0.2") -> str:
    """A SARIF 2.1.0 log — a drop-in for CI code-scanning uploads.

    One rule per distinct ``check_id``; one result per finding, located at the
    scanned URL. ``note``/``none`` levels keep OK and inconclusive findings in
    the log without failing a build.
    """
    url = field_of(profile, "url", "")

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings or ():
        check_id = field_of(f, "check_id", "UNKNOWN")
        title = field_of(f, "title", check_id)
        grade = field_of(f, "grade", "INCONCLUSIVE")
        severity = field_of(f, "severity_hint", "info")
        rationale = field_of(f, "rationale", "") or title
        recommendation = field_of(f, "recommendation", "")
        evidence = field_of(f, "evidence", {}) or {}

        if check_id not in rules:
            rules[check_id] = {
                "id": check_id,
                "name": check_id.replace("-", "_"),
                "shortDescription": {"text": title},
                "fullDescription": {"text": rationale},
                "defaultConfiguration": {"level": _sarif_level(grade, severity)},
                "properties": {"grade": grade, "severity_hint": severity},
            }
            if recommendation:
                rules[check_id]["help"] = {"text": recommendation}

        message = rationale
        if recommendation:
            message = f"{rationale}\nRecommendation: {recommendation}"

        results.append(
            {
                "ruleId": check_id,
                "level": _sarif_level(grade, severity),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": url or "mcp://target"}
                        }
                    }
                ],
                "properties": {
                    "grade": grade,
                    "severity_hint": severity,
                    "evidence": to_plain(evidence),
                },
            }
        )

    log = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "stranger-test",
                        "informationUri": "https://github.com/strangertest-labs/stranger-test",
                        "version": version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "reachable": bool(field_of(profile, "reachable", False)),
                    "scanned_url": url,
                },
            }
        ],
    }
    return json.dumps(log, indent=2)


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #

def render(
    profile: Any,
    findings: Sequence[Any],
    *,
    fmt: str = "human",
    stream: Optional[Any] = None,
    color: Optional[bool] = None,
) -> int:
    """Write the chosen format to ``stream`` (default stdout) and return the
    finding-based exit code (0 or 1). The CLI handles exit 2 (unreachable/error)
    on its own before calling here."""
    stream = stream if stream is not None else sys.stdout
    if fmt == "json":
        stream.write(json_report(profile, findings) + "\n")
    elif fmt == "sarif":
        stream.write(sarif_report(profile, findings) + "\n")
    else:
        if color is None:
            color = bool(getattr(stream, "isatty", lambda: False)())
        stream.write(human_report(profile, findings, color=color))
    return exit_code(findings)
