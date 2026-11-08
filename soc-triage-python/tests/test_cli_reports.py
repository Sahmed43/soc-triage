import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from soc_triage.cli import main
from soc_triage.reporting import build_report, to_markdown

ROOT = Path(__file__).resolve().parents[1]


class CliAndReportTests(unittest.TestCase):
    def test_end_to_end_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            j, m, db = root / "results.json", root / "results.md", root / "cases.sqlite"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(["scan", "--input", str(ROOT / "sample_data/events.jsonl"),
                               "--json", str(j), "--markdown", str(m), "--db", str(db)])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(j.read_text())["total_findings"], 6)
            self.assertIn("SOC Situational Awareness Report", m.read_text())
            self.assertTrue(db.exists())

    def test_cli_missing_file_returns_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            result = main(["scan", "--input", "/nothing/soc-events.jsonl"])
        self.assertEqual(result, 2)

    def test_cli_update_unknown_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(["update", "--db", str(Path(tmp)/"cases.sqlite"), "--id", "SOC-none", "--status", "resolved"])
            self.assertEqual(code, 1)

    def test_zero_findings_report_caveat(self):
        report = build_report([], [])
        self.assertEqual(report["total_findings"], 0)
        self.assertIn("does not establish", to_markdown(report))

    def test_markdown_escapes_untrusted_source(self):
        report = build_report([], [])
        report["event_sources"] = {"host|a": 1}
        self.assertIn("host\\|a", to_markdown(report))


if __name__ == "__main__":
    unittest.main()
