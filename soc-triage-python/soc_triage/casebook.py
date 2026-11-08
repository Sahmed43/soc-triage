"""Local SQLite incident-tracking demonstration, not an enterprise SOAR platform."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding

STATUSES = ("new", "triaging", "investigating", "contained", "resolved", "false_positive")


def _connect(path: str | Path) -> sqlite3.Connection:
    location = Path(path)
    location.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(location)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("""CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, title TEXT NOT NULL,
        severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new',
        analyst TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
    )""")
    return connection


def register(path: str | Path, findings: list[Finding]) -> int:
    """Insert new cases without overwriting analysts' statuses or notes."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect(path) as db:
        before = db.total_changes
        for f in findings:
            db.execute(
                "INSERT OR IGNORE INTO cases (id, rule_id, title, severity, updated_at) VALUES (?, ?, ?, ?, ?)",
                (f.id, f.rule_id, f.title, f.severity, now),
            )
        db.commit()
        return db.total_changes - before


def list_cases(path: str | Path) -> list[dict[str, str]]:
    with _connect(path) as db:
        rows = db.execute("SELECT * FROM cases ORDER BY updated_at DESC, id").fetchall()
    return [dict(row) for row in rows]


def update_case(path: str | Path, case_id: str, status: str, note: str = "", analyst: str = "") -> bool:
    if status not in STATUSES:
        raise ValueError(f"status must be one of: {', '.join(STATUSES)}")
    now = datetime.now(timezone.utc).isoformat()
    with _connect(path) as db:
        row = db.execute("SELECT notes, analyst FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            return False
        notes = row["notes"]
        if note:
            notes = (notes + "\n" if notes else "") + f"[{now}] {note}"
        db.execute(
            "UPDATE cases SET status = ?, notes = ?, analyst = ?, updated_at = ? WHERE id = ?",
            (status, notes, analyst or row["analyst"], now, case_id),
        )
        db.commit()
    return True
