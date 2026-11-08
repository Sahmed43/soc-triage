"""Typed, intentionally minimal event and finding models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def parse_timestamp(value: str) -> datetime:
    """Require an ISO-8601 timestamp with timezone; normalize to UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid timestamp: {value!r}") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("timestamp must include timezone, e.g. Z or +00:00")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_id: int
    host: str
    source: str = "windows_security"
    user: str = ""
    src_ip: str = ""
    process: str = ""
    command_line: str = ""
    target_group: str = ""
    outcome: str = ""
    record_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        return result


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    title: str
    severity: str
    technique: str
    tactic: str
    description: str
    triage_steps: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    first_seen: str
    last_seen: str
    host: str
    user: str
    src_ip: str
    evidence: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
