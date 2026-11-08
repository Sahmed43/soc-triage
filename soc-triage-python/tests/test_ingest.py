import json
import tempfile
import unittest
from pathlib import Path

from soc_triage.ingest import normalize_event, read_jsonl
from soc_triage.models import parse_timestamp


class IngestTests(unittest.TestCase):
    def test_timezone_normalization(self):
        dt = parse_timestamp("2026-10-15T16:00:00-04:00")
        self.assertEqual(dt.isoformat(), "2026-10-15T20:00:00+00:00")

    def test_naive_time_rejected(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            parse_timestamp("2026-10-15T16:00:00")

    def test_bad_time_rejected(self):
        with self.assertRaises(ValueError):
            parse_timestamp("not-a-date")

    def test_normalized_event(self):
        ev = normalize_event({"timestamp": "2026-10-15T20:00:00Z", "event_id": 4625, "host": "dc-1", "user": "alex"}, 10)
        self.assertEqual(ev.event_id, 4625)
        self.assertEqual(ev.record_id, "line-10")

    def test_sentinel_mapping(self):
        ev = normalize_event({"TimeGenerated": "2026-10-15T20:00:00Z", "EventID": "4625", "Computer": "dc-1", "TargetUserName": "alex", "IpAddress": "192.0.2.5", "EventRecordId": "43"})
        self.assertEqual((ev.user, ev.src_ip, ev.record_id), ("alex", "192.0.2.5", "43"))

    def test_missing_event_id(self):
        with self.assertRaisesRegex(ValueError, "event_id"):
            normalize_event({"timestamp": "2026-10-15T20:00:00Z", "host": "dc-1"})

    def test_non_object_jsonl_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('[]\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r":1:"):
                read_jsonl(path)

    def test_reports_bad_line_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('{"timestamp":"2026-10-15T20:00:00Z","event_id":4625,"host":"dc-1"}\nnot-json\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r":2:"):
                read_jsonl(path)

    def test_sorted_by_event_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            values = [{"timestamp": "2026-10-15T20:01:00Z", "event_id": 4625, "host": "a"},
                      {"timestamp": "2026-10-15T20:00:00Z", "event_id": 4624, "host": "a"}]
            path.write_text("".join(json.dumps(v) + "\n" for v in values), encoding="utf-8")
            self.assertEqual([e.event_id for e in read_jsonl(path)], [4624, 4625])


if __name__ == "__main__":
    unittest.main()
