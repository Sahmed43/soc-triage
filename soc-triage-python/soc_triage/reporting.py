"""Export triage evidence and customer-style situational awareness reports."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Event, Finding


def build_report(events: list[Event], findings: list[Finding]) -> dict[str, Any]:
    return {
        "project": "SOC Triage Lab",
        "classification": "SYNTHETIC TRAINING DATA ONLY" if events else "NO DATA",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "total_events": len(events),
        "event_sources": dict(sorted(Counter(e.source for e in events).items())),
        "event_ids": {str(k): v for k, v in sorted(Counter(e.event_id for e in events).items())},
        "total_findings": len(findings),
        "severity_counts": {s: sum(f.severity == s for f in findings) for s in ("critical", "high", "medium", "low")},
        "findings": [f.to_dict() for f in findings],
        "disclaimer": "Heuristic detections require analyst validation; findings are not proof of compromise.",
    }


def _md(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("`", "\\`")


def to_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# SOC Situational Awareness Report",
        "",
        f"**Generated (UTC):** {_md(report['generated_at_utc'])}",
        f"**Data type:** {_md(report['classification'])}",
        f"**Events analyzed:** {report['total_events']}",
        f"**Findings:** {report['total_findings']}",
        "",
        "## Executive summary",
        "",
        "Severity distribution: " + ", ".join(f"{key}: {value}" for key, value in report["severity_counts"].items()) + ".",
        "All alerts are hypotheses requiring analyst investigation; no actions are taken automatically.",
        "",
        "## Visibility and ingestion coverage",
        "",
        "| Event source | Records |",
        "| --- | ---: |",
    ]
    for source, count in report["event_sources"].items():
        lines.append(f"| {_md(source)} | {count} |")
    lines += ["", "## Findings and analyst triage", ""]
    if not report["findings"]:
        lines += ["No rules fired in the submitted events. This does not establish that the environment is secure.", ""]
    for index, f in enumerate(report["findings"], start=1):
        lines += [
            f"### {index}. {_md(f['title'])} ({_md(f['id'])})",
            "",
            f"**Severity:** {_md(f['severity']).upper()}  ",
            f"**MITRE ATT&CK:** {_md(f['technique'])} — {_md(f['tactic'])}  ",
            f"**Detected window:** {_md(f['first_seen'])} to {_md(f['last_seen'])}  ",
            f"**Context:** host={_md(f['host'])}, user={_md(f['user'])}, src_ip={_md(f['src_ip'])}",
            "",
            _md(f["description"]),
            "",
            "**Evidence (truncated to 30 records per finding):**",
            "",
            "| UTC timestamp | Event ID | Host | User | Source IP | Record |",
            "| --- | ---: | --- | --- | --- | --- |",
        ]
        for e in f["evidence"]:
            lines.append("| " + " | ".join(_md(e[key]) for key in ("timestamp", "event_id", "host", "user", "src_ip", "record_id")) + " |")
        lines += ["", "**Recommended investigation:**", ""]
        lines.extend(f"- {_md(step)}" for step in f["triage_steps"])
        lines += ["", "**Response options (require analyst authorization):**", ""]
        lines.extend(f"- {_md(step)}" for step in f["recommended_actions"])
        lines.append("")
    lines += [
        "## Operational follow-up",
        "",
        "Review data-source coverage, tune noisy rules against approved activities, and document disposition in the casebook.",
        "Maintain the evidence trail and obtain approval before containment or remediation.",
        "",
        f"> {_md(report['disclaimer'])}",
        "",
    ]
    return "\n".join(lines)


def write_json(report: dict[str, Any], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_markdown(report: dict[str, Any], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(to_markdown(report), encoding="utf-8")
