"""Read normalized event JSONL or exported Microsoft SecurityEvent JSONL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Event, parse_timestamp


def _first_nonempty(obj: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = obj.get(key)
        if value is not None and value != "":
            return value
    return default


def normalize_event(row: dict[str, Any], sequence: int = 0) -> Event:
    """Support an educational subset of Windows SecurityEvent field names.

    This is NOT a full Microsoft Sentinel connector or comprehensive schema mapper.
    Users should adapt inputs to their own connector/version before deployment.
    """
    if not isinstance(row, dict):
        raise ValueError("each JSONL line must be a JSON object")
    timestamp = _first_nonempty(row, "timestamp", "TimeGenerated")
    if not timestamp:
        raise ValueError("missing timestamp/TimeGenerated")
    event_id = _first_nonempty(row, "event_id", "EventID", default=None)
    if event_id is None or isinstance(event_id, bool):
        raise ValueError("missing or invalid event_id/EventID")
    try:
        number = int(event_id)
    except (ValueError, TypeError) as exc:
        raise ValueError("event_id/EventID must be an integer") from exc
    if number < 0:
        raise ValueError("event_id/EventID must be non-negative")
    host = str(_first_nonempty(row, "host", "Computer"))
    if not host:
        raise ValueError("missing host/Computer")
    return Event(
        timestamp=parse_timestamp(timestamp),
        event_id=number,
        host=host,
        source=str(_first_nonempty(row, "source", "EventSourceName", default="windows_security")),
        user=str(_first_nonempty(row, "user", "TargetUserName", "TargetAccount", "SubjectUserName")),
        src_ip=str(_first_nonempty(row, "src_ip", "IpAddress", "SourceNetworkAddress")),
        process=str(_first_nonempty(row, "process", "NewProcessName", "Image")),
        command_line=str(_first_nonempty(row, "command_line", "CommandLine", "ProcessCommandLine")),
        target_group=str(_first_nonempty(row, "target_group", "GroupName", "TargetGroupName")),
        outcome=str(_first_nonempty(row, "outcome")),
        record_id=str(_first_nonempty(row, "record_id", "EventRecordId", default=f"line-{sequence}")),
    )


def read_jsonl(path: str | Path) -> list[Event]:
    """Fail closed on malformed rows; include filename/line for reproducibility."""
    events: list[Event] = []
    with Path(path).open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                events.append(normalize_event(row, sequence=number))
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                raise ValueError(f"{path}:{number}: {exc}") from exc
    return sorted(events, key=lambda e: (e.timestamp, e.record_id))
