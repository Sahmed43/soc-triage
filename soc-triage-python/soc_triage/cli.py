"""Command-line interface for offline SOC triage exercises."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .casebook import STATUSES, list_cases, register, update_case
from .detection import detect
from .ingest import read_jsonl
from .reporting import build_report, write_json, write_markdown


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="soc-triage",
        description="SOC detection engineering lab (offline, read-only event analysis).",
    )
    commands = ap.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Analyze JSONL events and generate SOC reports")
    scan.add_argument("--input", required=True, type=Path, help="Normalized/SecurityEvent JSONL export")
    scan.add_argument("--json", type=Path, help="Output JSON findings report")
    scan.add_argument("--markdown", type=Path, help="Output Markdown SOC situation report")
    scan.add_argument("--db", type=Path, help="Optional SQLite casebook path")
    scan.add_argument("--config", type=Path, help="Optional detection threshold configuration JSON")
    cases = commands.add_parser("cases", help="List local incident cases")
    cases.add_argument("--db", required=True, type=Path)
    update = commands.add_parser("update", help="Update an incident case status and analyst notes")
    update.add_argument("--db", required=True, type=Path)
    update.add_argument("--id", required=True)
    update.add_argument("--status", choices=STATUSES, required=True)
    update.add_argument("--note", default="")
    update.add_argument("--analyst", default="")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "scan":
            config = json.loads(args.config.read_text(encoding="utf-8")) if args.config else None
            if config is not None and not isinstance(config, dict):
                raise ValueError("configuration must be a JSON object")
            events = read_jsonl(args.input)
            findings = detect(events, config)
            report = build_report(events, findings)
            if args.json:
                write_json(report, args.json)
            if args.markdown:
                write_markdown(report, args.markdown)
            new = register(args.db, findings) if args.db else None
            print(f"Analyzed {len(events)} events; created {len(findings)} findings.")
            for f in findings:
                print(f"  {f.id}  {f.severity.upper():6}  {f.technique:10}  {f.title}")
            if new is not None:
                print(f"Added {new} new case(s) to {args.db}.")
            if not args.json and not args.markdown:
                print("Use --json and/or --markdown to save reports.")
            return 0
        if args.command == "cases":
            cases = list_cases(args.db)
            print(f"{len(cases)} case(s)")
            for case in cases:
                print(f"  {case['id']}  {case['severity']:6}  {case['status']:14}  {case['title']}")
            return 0
        if args.command == "update":
            if not update_case(args.db, args.id, args.status, args.note, args.analyst):
                print(f"Case not found: {args.id}", file=sys.stderr)
                return 1
            print(f"Updated {args.id} -> {args.status}")
            return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
