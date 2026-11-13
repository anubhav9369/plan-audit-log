"""Tests for plan_audit_log — 9 tests, stdlib only."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plan_audit_log import (  # noqa: E402
    check_log,
    entry_hash,
    filter_entries,
    read_log,
    summarise,
    timeline,
    verify_chain,
    GENESIS,
)

DAY44 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_entry(seq, prev_hash, **overrides):
    entry = {
        "seq": seq,
        "ts": f"2026-11-13T09:0{seq}:00Z",
        "actor": "anubhav9369",
        "action": "plan_approved",
        "plan": "weekly-report",
        "version": 1,
        "detail": f"entry {seq}",
        "prev_hash": prev_hash,
    }
    entry.update(overrides)
    entry["hash"] = entry_hash(entry)
    return entry


def make_chain(n=3):
    entries, prev = [], GENESIS
    for seq in range(1, n + 1):
        entry = make_entry(seq, prev)
        entries.append(entry)
        prev = entry["hash"]
    return entries


def write_log(entries, raw_lines=None):
    path = tempfile.NamedTemporaryFile(
        "w", suffix=".jsonl", delete=False).name
    with open(path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
        for line in (raw_lines or []):
            f.write(line + "\n")
    return path


class TestPlanAuditLog(unittest.TestCase):
    def test_valid_chain_verifies_clean(self):
        self.assertEqual(verify_chain(make_chain(3)), [])

    def test_tampered_entry_is_detected(self):
        entries = make_chain(3)
        entries[1]["detail"] = "rewritten after the fact"
        problems = verify_chain(entries)
        self.assertTrue(any("hash mismatch" in p for p in problems))

    def test_missing_sequence_number_is_detected(self):
        entries = make_chain(4)
        del entries[2]
        problems = verify_chain(entries)
        self.assertTrue(any("gap" in p for p in problems))

    def test_duplicate_sequence_number_is_detected(self):
        entries = make_chain(3)
        entries[2]["seq"] = 2
        problems = verify_chain(entries)
        self.assertTrue(any("duplicate" in p for p in problems))

    def test_wrong_prev_hash_is_detected(self):
        entries = make_chain(3)
        entries[1]["prev_hash"] = "0" * 64
        problems = verify_chain(entries)
        self.assertTrue(any("prev_hash" in p for p in problems))

    def test_malformed_line_is_reported_not_dropped(self):
        path = write_log(make_chain(2), raw_lines=["{not json"])
        entries, errors = read_log(path)
        self.assertEqual(len(entries), 2)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["line"], 3)

    def test_timeline_renders_in_order(self):
        lines = timeline(make_chain(2))
        self.assertEqual(len(lines), 2)
        self.assertIn("plan approved weekly-report v1", lines[0])
        self.assertIn("2026-11-13T09:01:00Z", lines[0])

    def test_summarise_counts_by_action_actor_and_plan(self):
        summary = summarise(make_chain(3))
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_action"], {"plan_approved": 3})
        self.assertEqual(summary["by_actor"], {"anubhav9369": 3})
        self.assertEqual(summary["first_ts"], "2026-11-13T09:01:00Z")

    def test_example_logs_check_as_expected(self):
        clean = check_log(os.path.join(DAY44, "examples", "audit.jsonl"))
        self.assertEqual(clean["verdict"], "clean")
        self.assertEqual(clean["entries"], 6)
        broken = check_log(os.path.join(DAY44, "examples", "broken.jsonl"))
        self.assertEqual(broken["verdict"], "broken")
        self.assertTrue(any("hash mismatch" in p for p in broken["problems"]))
        self.assertTrue(any("gap" in p for p in broken["problems"]))
        entries, _ = read_log(os.path.join(DAY44, "examples", "audit.jsonl"))
        approved = filter_entries(entries, action="plan_approved")
        self.assertEqual(len(approved), 1)
        self.assertEqual(approved[0]["detail"],
                         "approved with the email step gated")


if __name__ == "__main__":
    unittest.main()
