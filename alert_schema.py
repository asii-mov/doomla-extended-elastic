"""Alert dataclass + cross-surface normalisation.

Two surfaces feed this eval:

- `logs-endpoint.alerts-*` — raw Elastic Defend prevention/detection
  alerts. Nested ECS layout. `event.severity` is numeric (0-100).
- `.alerts-security.alerts-*` — Detection Engine rollup. Mixed layout
  where most `kibana.alert.*` fields are dotted top-level keys but the
  core ECS fields (`file.path`, `process.executable`, `container.*`)
  remain nested. `kibana.alert.severity` is the string form
  (low/medium/high/critical).

`normalize()` collapses both into the same `Alert` shape so downstream
consumers (the in-loop wrapper in Phase 4, the scorer in Phase 5) don't
need to know which surface a hit came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

SEVERITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Cutoffs match Elastic's default rule severity buckets.
_NUMERIC_SEVERITY_BUCKETS: list[tuple[int, str]] = [
    (74, "critical"),
    (48, "high"),
    (22, "medium"),
    (0, "low"),
]

# Syslog-style severity strings (RFC 5424) map onto Elastic's 4-level scale.
_SYSLOG_SEVERITY_MAP: dict[str, str] = {
    "debug": "low",
    "informational": "low",
    "notice": "low",
    "warning": "medium",
    "error": "high",
    "critical": "critical",
    "alert": "critical",
    "emergency": "critical",
}


def _coerce_severity(value: Any) -> str:
    """Return one of low/medium/high/critical for any reasonable input."""
    if value is None:
        return "low"
    if isinstance(value, (int, float)):
        n = int(value)
        for cutoff, label in _NUMERIC_SEVERITY_BUCKETS:
            if n >= cutoff:
                return label
        return "low"
    s = str(value).strip().lower()
    if s in SEVERITY_RANK:
        return s
    if s in _SYSLOG_SEVERITY_MAP:
        return _SYSLOG_SEVERITY_MAP[s]
    return "low"


@dataclass
class Alert:
    """One normalised alert spanning both raw and rollup surfaces."""

    timestamp: datetime | None
    surface: str  # "raw" or "rollup"
    severity: str  # low | medium | high | critical
    severity_rank: int  # 1..4
    event_type: str  # "denied" | "allowed" | "unknown"
    event_code: str
    rule_name: str
    mitre_tactic: list[str] = field(default_factory=list)
    mitre_technique: list[str] = field(default_factory=list)
    container_id: str | None = None
    container_name: str | None = None
    process_name: str | None = None
    process_command_line: str | None = None
    dedup_key: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


def _dotted_get(d: dict, dotted: str, default: Any = None) -> Any:
    """Look up `dotted` tolerating ES's mixed flat/nested storage.

    The Detection Engine rollup index stores most `kibana.alert.*` fields
    as flat dotted keys; the raw datastream uses fully nested objects;
    some fields exist in a hybrid shape (a flat prefix whose value is a
    nested object). We try progressively shorter flat prefixes — for
    `a.b.c.d` we attempt the full flat key, then `a.b.c` (descend `d`),
    then `a.b` (descend `c.d`), and so on — falling through to a fully
    nested walk if nothing flat matches.
    """
    if dotted in d:
        return d[dotted]
    parts = dotted.split(".")
    for split in range(len(parts) - 1, 0, -1):
        flat = ".".join(parts[:split])
        if flat in d:
            cur: Any = d[flat]
            for part in parts[split:]:
                if not isinstance(cur, dict) or part not in cur:
                    cur = None
                    break
                cur = cur[part]
            if cur is not None:
                return cur
    cur = d
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _extract_mitre(source: dict) -> tuple[list[str], list[str]]:
    """Pull MITRE tactic and technique names out of a hit, surface-agnostic."""
    tactics: list[str] = []
    techniques: list[str] = []

    threats: Iterable[dict] = _dotted_get(source, "kibana.alert.rule.threat") or []
    if isinstance(threats, dict):
        threats = [threats]
    for t in threats:
        if not isinstance(t, dict):
            continue
        tactic = (t.get("tactic") or {}).get("name")
        if tactic:
            tactics.append(tactic)
        for tech in t.get("technique") or []:
            if isinstance(tech, dict) and tech.get("name"):
                techniques.append(tech["name"])

    # Raw Defend alerts sometimes carry threat.* inline at the top level.
    inline_tactic = _dotted_get(source, "threat.tactic.name")
    if inline_tactic and inline_tactic not in tactics:
        tactics.append(inline_tactic)
    inline_tech = _dotted_get(source, "threat.technique.name")
    if inline_tech and inline_tech not in techniques:
        techniques.append(inline_tech)

    return tactics, techniques


def _infer_event_type(source: dict) -> str:
    """Best-effort classification of denied vs allowed."""
    # Defend explicitly marks prevention outcomes via these fields.
    if _dotted_get(source, "file.Ext.quarantine_result") is True:
        return "denied"

    action = _dotted_get(source, "event.action")
    if isinstance(action, list):
        action_str = " ".join(str(a) for a in action).lower()
    else:
        action_str = str(action or "").lower()
    if any(k in action_str for k in ("block", "deny", "denied", "prevent", "kill", "quarantine")):
        return "denied"
    if any(k in action_str for k in ("allow", "execution_detected", "creation")):
        return "allowed"

    # Detection-rule rollup: original_event.action carries the same info.
    orig_action = _dotted_get(source, "kibana.alert.original_event.action")
    if orig_action:
        oa = str(orig_action).lower()
        if any(k in oa for k in ("block", "deny", "prevent", "kill")):
            return "denied"

    return "unknown"


def normalize(hit: dict, *, surface: str | None = None) -> Alert:
    """Normalise one ES `_search` hit into an Alert.

    `surface` may be passed explicitly; if omitted it is inferred from
    `_index` (`logs-endpoint.alerts-*` → raw, anything else → rollup).
    """
    if surface is None:
        idx = hit.get("_index", "")
        surface = "raw" if idx.startswith("logs-endpoint.alerts") else "rollup"
    source: dict[str, Any] = hit.get("_source") or {}

    timestamp = _parse_ts(source.get("@timestamp"))

    if surface == "rollup":
        severity_raw = _dotted_get(source, "kibana.alert.severity") \
            or _dotted_get(source, "event.severity")
    else:
        severity_raw = _dotted_get(source, "event.severity") \
            or _dotted_get(source, "kibana.alert.severity")
    severity = _coerce_severity(severity_raw)

    rule_name = (
        _dotted_get(source, "kibana.alert.rule.name")
        or _dotted_get(source, "rule.name")
        or ""
    )

    event_code = _dotted_get(source, "event.code") or ""
    tactics, techniques = _extract_mitre(source)
    event_type = _infer_event_type(source)

    container_id = _dotted_get(source, "container.id")
    container_name = _dotted_get(source, "container.name")
    process_name = (
        _dotted_get(source, "process.name")
        or _dotted_get(source, "process.executable")
    )
    process_command_line = _dotted_get(source, "process.command_line")
    if not process_command_line:
        args = _dotted_get(source, "process.args")
        if isinstance(args, list) and args:
            process_command_line = " ".join(str(a) for a in args)

    # Dedup key: the rollup links back to the raw event via
    # kibana.alert.original_event.id. Prefer that so a rollup hit "absorbs"
    # the matching raw hit; fall back to the document's own _id.
    dedup_key = (
        _dotted_get(source, "kibana.alert.original_event.id")
        or hit.get("_id")
        or ""
    )

    return Alert(
        timestamp=timestamp,
        surface=surface,
        severity=severity,
        severity_rank=SEVERITY_RANK[severity],
        event_type=event_type,
        event_code=str(event_code),
        rule_name=str(rule_name),
        mitre_tactic=tactics,
        mitre_technique=techniques,
        container_id=container_id,
        container_name=container_name,
        process_name=process_name,
        process_command_line=process_command_line,
        dedup_key=str(dedup_key),
        raw=source,
    )
