"""Defensive heuristics over normalized Windows event data.

Alerts mean 'review this behavior', not a confirmed compromise. Rules are
intentionally transparent and deterministic so they can be explained in an interview.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import timedelta
from typing import Any

from .models import Event, Finding

DEFAULT_RULES: dict[str, dict[str, int]] = {
    "brute_force": {"threshold": 5, "window_minutes": 10},
    "password_spray": {"unique_user_threshold": 5, "window_minutes": 15},
    "success_after_failures": {"threshold": 5, "window_minutes": 10},
}

# -enc, -encodedcommand and common abbreviation forms: heuristic, not proof.
ENCODED_POWERSHELL = re.compile(r"(?i)(?:^|\s)-(?:enc(?:odedcommand)?|e(?:ncodedc(?:ommand)?)?)\b")
PRIVILEGED_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _evidence(event: Event) -> dict[str, Any]:
    return {
        "timestamp": event.to_dict()["timestamp"],
        "record_id": event.record_id,
        "event_id": event.event_id,
        "host": event.host,
        "user": event.user,
        "src_ip": event.src_ip,
        "process": event.process,
        "command_line": event.command_line[:500],
        "target_group": event.target_group,
    }


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    technique: str,
    tactic: str,
    description: str,
    steps: tuple[str, ...],
    actions: tuple[str, ...],
    events: list[Event],
) -> Finding:
    ordered = sorted(events, key=lambda e: (e.timestamp, e.record_id))
    ids = ",".join(f"{e.host}:{e.record_id}:{e.event_id}" for e in ordered)
    digest = hashlib.sha256(f"{rule_id}|{ids}".encode()).hexdigest()[:12]
    focus = ordered[-1]
    return Finding(
        id=f"SOC-{digest}",
        rule_id=rule_id,
        title=title,
        severity=severity,
        technique=technique,
        tactic=tactic,
        description=description,
        triage_steps=steps,
        recommended_actions=actions,
        first_seen=ordered[0].to_dict()["timestamp"],
        last_seen=ordered[-1].to_dict()["timestamp"],
        host=focus.host,
        user=focus.user,
        src_ip=focus.src_ip,
        evidence=tuple(_evidence(e) for e in ordered[:30]),
    )


def _first_threshold_window(
    events: list[Event], minutes: int, threshold: int, unique_users: bool = False
) -> list[Event]:
    """Find the first sorted sliding-window matching the specified threshold."""
    left = 0
    for right, event in enumerate(events):
        while event.timestamp - events[left].timestamp > timedelta(minutes=minutes):
            left += 1
        window = events[left : right + 1]
        measure = len({e.user.casefold() for e in window if e.user}) if unique_users else len(window)
        if measure >= threshold:
            return window
    return []


def _config_for(rule_id: str, config: dict[str, Any]) -> dict[str, int]:
    defaults = DEFAULT_RULES[rule_id]
    options = config.get(rule_id, {})
    if not isinstance(options, dict):
        raise ValueError(f"{rule_id} configuration must be an object")
    combined = dict(defaults)
    combined.update(options)
    for key, value in combined.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 100000:
            raise ValueError(f"{rule_id}.{key} must be a positive integer <= 100000")
    return combined


def detect(events: list[Event], config: dict[str, Any] | None = None) -> list[Finding]:
    """Run five alert patterns; no network calls or automated containment."""
    config = config if config is not None else DEFAULT_RULES
    bf = _config_for("brute_force", config)
    spray = _config_for("password_spray", config)
    post = _config_for("success_after_failures", config)
    ordered = sorted(events, key=lambda e: (e.timestamp, e.record_id))
    findings: list[Finding] = []

    failures: dict[tuple[str, str], list[Event]] = defaultdict(list)
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in ordered:
        if event.event_id == 4625 and event.src_ip and event.user and event.outcome.lower() != "success":
            failures[(event.src_ip, event.user.casefold())].append(event)
            by_ip[event.src_ip].append(event)

    for (ip, user), group in sorted(failures.items()):
        window = _first_threshold_window(group, bf["window_minutes"], bf["threshold"])
        if window:
            findings.append(_finding(
                "AUTH-001", "Repeated failed authentication", "medium", "T1110.001", "Credential Access",
                f"At least {bf['threshold']} failed logons for {user} from {ip} in {bf['window_minutes']} minutes.",
                ("Verify account and source IP ownership.", "Look for successes, MFA events, and other affected accounts.", "Compare activity with maintenance windows and user reports."),
                ("Escalate suspected unauthorized access to the incident owner.", "Apply account protection or source blocking only with approval."),
                window,
            ))

    for ip, group in sorted(by_ip.items()):
        window = _first_threshold_window(group, spray["window_minutes"], spray["unique_user_threshold"], True)
        if window:
            findings.append(_finding(
                "AUTH-002", "Possible password spraying", "high", "T1110.003", "Credential Access",
                f"Failures for at least {spray['unique_user_threshold']} distinct users from {ip} within {spray['window_minutes']} minutes.",
                ("Review affected accounts and IP reputation within authorized systems.", "Check for any related successful logins.", "Assess whether a shared proxy or misconfigured app explains the pattern."),
                ("Notify the identity response team if suspicious.", "Consider targeted identity controls subject to change approval."),
                window,
            ))

    seen_success: set[tuple[str, str]] = set()
    for event in ordered:
        if event.event_id != 4624 or not event.src_ip or not event.user:
            continue
        key = (event.src_ip, event.user.casefold())
        if key in seen_success:
            continue
        candidates = [
            f for f in failures.get(key, [])
            if timedelta(0) <= event.timestamp - f.timestamp <= timedelta(minutes=post["window_minutes"])
        ]
        if len(candidates) >= post["threshold"]:
            window = candidates[-post["threshold"] :] + [event]
            findings.append(_finding(
                "AUTH-003", "Successful logon following repeated failures", "high", "T1110", "Credential Access",
                f"Successful authentication followed {len(candidates)} recent failures for {event.user} from {event.src_ip}.",
                ("Verify that the authentication was authorized.", "Correlate session activity and endpoint alerts after the logon.", "Confirm whether an expected password reset occurred."),
                ("Escalate confirmed suspicious access for session revocation review.", "Preserve relevant logs and obtain approval before containment."),
                window,
            ))
            seen_success.add(key)

    for event in ordered:
        text = f"{event.process} {event.command_line}".lower()
        if event.event_id in {1, 4688, 4104} and ("powershell" in text or "pwsh" in text) and ENCODED_POWERSHELL.search(event.command_line):
            findings.append(_finding(
                "PROC-001", "PowerShell with encoded command argument", "high", "T1059.001", "Execution",
                "Potentially suspicious PowerShell encoded-command invocation (may be legitimate administration).",
                ("Review the complete process tree and execution context.", "Check the command content in an isolated analysis environment.", "Correlate with endpoint alerts and authorized scripts."),
                ("Escalate confirmed unauthorized execution for endpoint containment review.", "Preserve process, script, and host evidence."),
                [event],
            ))

        if event.event_id in {4728, 4732, 4756} and event.target_group.strip().casefold() in PRIVILEGED_GROUPS:
            findings.append(_finding(
                "ID-001", "Privileged group membership modification", "high", "T1098.007", "Persistence",
                f"Membership changed for the privileged group {event.target_group!r}.",
                ("Confirm change ticket, approver, and identity of the operator.", "Identify the member added using the full original security event.", "Review follow-on authentications and privilege use."),
                ("Revert unauthorized access only under the approved incident process.", "Preserve audit data and escalate to the identity owner."),
                [event],
            ))

        if event.event_id == 1102:
            findings.append(_finding(
                "LOG-001", "Windows security event log cleared", "high", "T1070.001", "Defense Evasion",
                "A Windows security audit log clear event was recorded; verify whether maintenance was authorized.",
                ("Validate the event against approved maintenance activity.", "Check adjacent hosts, EDR telemetry, and alternate log sources.", "Identify the operator and preceding actions."),
                ("Preserve available off-host logs.", "Escalate if the audit trail was deliberately removed."),
                [event],
            ))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen, f.rule_id, f.id))
