import tempfile
import unittest
from pathlib import Path

from soc_triage.casebook import list_cases, register, update_case
from soc_triage.detection import detect
from soc_triage.ingest import read_jsonl

ROOT = Path(__file__).resolve().parents[1]


class CasebookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "triage.sqlite"
        self.findings = detect(read_jsonl(ROOT / "sample_data/events.jsonl"))

    def test_insert_and_list(self):
        self.assertEqual(register(self.db, self.findings), 6)
        self.assertEqual(len(list_cases(self.db)), 6)
        self.assertTrue(all(c["status"] == "new" for c in list_cases(self.db)))

    def test_rescan_preserves_analyst_notes(self):
        register(self.db, self.findings)
        finding_id = self.findings[0].id
        self.assertTrue(update_case(self.db, finding_id, "investigating", "Approved test", "analyst-a"))
        self.assertEqual(register(self.db, self.findings), 0)
        record = next(c for c in list_cases(self.db) if c["id"] == finding_id)
        self.assertEqual(record["status"], "investigating")
        self.assertIn("Approved test", record["notes"])
        self.assertEqual(record["analyst"], "analyst-a")

    def test_missing_case_not_found(self):
        self.assertFalse(update_case(self.db, "SOC-missing", "resolved"))

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            update_case(self.db, "SOC-missing", "destroyed")


if __name__ == "__main__":
    unittest.main()
