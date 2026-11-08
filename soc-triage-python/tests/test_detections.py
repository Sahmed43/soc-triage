import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_triage.detection import detect
from soc_triage.ingest import read_jsonl
from soc_triage.models import Event

ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 10, 15, 20, 0, tzinfo=timezone.utc)


def event(minute, event_id, user="a", ip="192.0.2.5", **kwargs):
    return Event(timestamp=BASE + timedelta(minutes=minute), event_id=event_id, host="dc-1",
                 user=user, src_ip=ip, record_id=str(minute) + ":" + str(event_id), **kwargs)


class DetectionTests(unittest.TestCase):
    def test_demo_has_all_six_rules(self):
        findings = detect(read_jsonl(ROOT / "sample_data/events.jsonl"))
        self.assertEqual({f.rule_id for f in findings},
                         {"AUTH-001", "AUTH-002", "AUTH-003", "PROC-001", "ID-001", "LOG-001"})
        self.assertEqual(len(findings), 6)

    def test_stable_ids_on_same_input(self):
        events = read_jsonl(ROOT / "sample_data/events.jsonl")
        self.assertEqual([f.id for f in detect(events)], [f.id for f in detect(events)])

    def test_no_findings_for_normal_login(self):
        self.assertEqual(detect([event(0, 4624)]), [])

    def test_no_false_brute_force_when_events_spaced_out(self):
        self.assertFalse(any(f.rule_id == "AUTH-001" for f in detect([event(i * 30, 4625) for i in range(5)])))

    def test_brute_force_at_boundary(self):
        findings = detect([event(i * 2, 4625) for i in range(6)])
        self.assertIn("AUTH-001", {f.rule_id for f in findings})

    def test_success_after_failures(self):
        events = [event(i, 4625) for i in range(5)] + [event(6, 4624)]
        self.assertIn("AUTH-003", {f.rule_id for f in detect(events)})

    def test_success_before_failures_not_flagged(self):
        events = [event(0, 4624)] + [event(i, 4625) for i in range(1, 6)]
        self.assertNotIn("AUTH-003", {f.rule_id for f in detect(events)})

    def test_password_spray_distinct_user_required(self):
        events = [event(i, 4625, user="same-user") for i in range(5)]
        self.assertNotIn("AUTH-002", {f.rule_id for f in detect(events)})

    def test_password_spray_five_users(self):
        events = [event(i, 4625, user=f"user-{i}") for i in range(5)]
        self.assertIn("AUTH-002", {f.rule_id for f in detect(events)})

    def test_encoded_powershell(self):
        proc = event(0, 4688, process="powershell.exe", command_line="powershell.exe -EncodedCommand AAAA")
        self.assertIn("PROC-001", {f.rule_id for f in detect([proc])})

    def test_benign_powershell_not_flagged(self):
        proc = event(0, 4688, process="powershell.exe", command_line="powershell.exe Get-Date")
        self.assertNotIn("PROC-001", {f.rule_id for f in detect([proc])})

    def test_only_sensitive_groups_flagged(self):
        events = [event(0, 4732, target_group="Developers"), event(1, 4732, target_group="Administrators")]
        self.assertEqual([f.rule_id for f in detect(events)], ["ID-001"])

    def test_security_log_cleared(self):
        self.assertEqual(detect([event(0, 1102)])[0].technique, "T1070.001")

    def test_custom_threshold(self):
        findings = detect([event(i, 4625) for i in range(3)], {"brute_force": {"threshold": 3}})
        self.assertIn("AUTH-001", {f.rule_id for f in findings})

    def test_bad_threshold_rejected(self):
        with self.assertRaises(ValueError):
            detect([], {"brute_force": {"threshold": 0}})

    def test_sorted_by_severity(self):
        findings = detect(read_jsonl(ROOT / "sample_data/events.jsonl"))
        self.assertEqual(findings[-1].severity, "medium")
        self.assertTrue(all(f.severity == "high" for f in findings[:-1]))


if __name__ == "__main__":
    unittest.main()
