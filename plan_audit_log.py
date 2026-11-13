"""plan_audit_log — read and verify the append-only audit log of an InspectablePlan.

Every step of the trustworthy-agentic-ai pipeline writes one JSON line per
event: plan created, explained, risk-scanned, approved, refined,
policy-checked. Each entry carries a sequence number and a hash chain
(sha256 over the entry plus the previous entry's hash), so a later edit,
deletion or reordering is detectable instead of silently believed.

Entry shape (one JSON object per line):

    {"seq": 1, "ts": "2026-11-13T09:00:00Z", "actor": "anubhav9369",
     "action": "plan_created", "plan": "weekly-report", "version": 1,
     "detail": "goal-driven plan generated from 'summarise the week'",
     "prev_hash": "GENESIS",
     "hash": "<sha256 of the entry without its hash field>"}

Rules the verifier enforces:

* a malformed line is reported, never silently skipped;
* sequence numbers start at 1 and rise by exactly 1 — a gap means a
  deleted entry, a duplicate means a replayed one;
* each entry's prev_hash must equal the previous entry's hash
  ("GENESIS" for the first);
* the stored hash must match a recomputation — a tampered entry fails;
* timestamps must not run backwards.

Usage:

    python3 plan_audit_log.py examples/audit.jsonl
    python3 plan_audit_log.py examples/audit.jsonl --json
    python3 plan_audit_log.py examples/broken.jsonl --verify-only

Exit codes: 0 chain clean, 1 chain problems found, 2 malformed lines.
"""

import argparse
import hashlib
import json
import sys
from collections import Counter

GENESIS = "GENESIS"
REQUIRED_FIELDS = ("seq", "ts", "actor", "action", "plan", "version",
                   "prev_hash", "hash")


def entry_hash(entry):
    """sha256 of the entry's canonical JSON, excluding its own hash."""
    payload = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def read_log(path):
    """Parse a JSONL audit log.

    Returns (entries, errors). A blank line is ignored; a line that is
    not valid JSON, or is missing a required field, becomes an error
    entry {"line": n, "error": ...} instead of vanishing.
    """
    entries, errors = [], []
    with open(path, "r", encoding="utf-8") as f:
        for n, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append({"line": n, "error": f"invalid JSON: {exc}"})
                continue
            if not isinstance(entry, dict):
                errors.append({"line": n, "error": "entry is not a JSON object"})
                continue
            missing = [f for f in REQUIRED_FIELDS if f not in entry]
            if missing:
                errors.append({"line": n,
                               "error": f"missing fields: {', '.join(missing)}"})
                continue
            entries.append(entry)
    return entries, errors


def verify_chain(entries):
    """Check sequence, hash linkage and timestamp order.

    Returns a list of problem strings; empty means the chain is clean.
    """
    problems = []
    if not entries:
        return ["log is empty"]
    expected_seq = 1
    prev_hash = GENESIS
    prev_ts = None
    for entry in entries:
        seq = entry["seq"]
        if seq != expected_seq:
            problems.append(
                f"seq {seq}: expected {expected_seq} "
                f"({'gap — an entry is missing' if seq > expected_seq else 'duplicate or out of order'})")
        expected_seq = seq + 1
        if entry["prev_hash"] != prev_hash:
            problems.append(
                f"seq {seq}: prev_hash does not match the previous entry's hash")
        if entry["hash"] != entry_hash(entry):
            problems.append(
                f"seq {seq}: hash mismatch — the entry was changed after it was written")
        if prev_ts is not None and entry["ts"] < prev_ts:
            problems.append(
                f"seq {seq}: timestamp {entry['ts']} runs before {prev_ts}")
        prev_hash = entry["hash"]
        prev_ts = entry["ts"]
    return problems


def timeline(entries):
    """One human-readable line per entry, in log order."""
    lines = []
    for e in entries:
        line = (f"{e['ts']} — {e['actor']} {e['action'].replace('_', ' ')} "
                f"{e['plan']} v{e['version']}")
        if e.get("detail"):
            line += f" ({e['detail']})"
        lines.append(line)
    return lines


def summarise(entries):
    """Counts and span of the log, as a plain dict."""
    return {
        "total": len(entries),
        "by_action": dict(Counter(e["action"] for e in entries)),
        "by_actor": dict(Counter(e["actor"] for e in entries)),
        "by_plan": dict(Counter(e["plan"] for e in entries)),
        "first_ts": entries[0]["ts"] if entries else None,
        "last_ts": entries[-1]["ts"] if entries else None,
    }


def filter_entries(entries, plan=None, actor=None, action=None):
    """Keep only entries matching every filter given."""
    kept = entries
    if plan is not None:
        kept = [e for e in kept if e["plan"] == plan]
    if actor is not None:
        kept = [e for e in kept if e["actor"] == actor]
    if action is not None:
        kept = [e for e in kept if e["action"] == action]
    return kept


def check_log(path):
    """Full check of one log file: read it, verify the chain, summarise."""
    entries, errors = read_log(path)
    problems = verify_chain(entries)
    return {
        "file": path,
        "entries": len(entries),
        "malformed_lines": errors,
        "problems": problems,
        "verdict": "clean" if not errors and not problems else (
            "malformed" if errors else "broken"),
        "summary": summarise(entries),
        "timeline": timeline(entries),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify an InspectablePlan audit log.")
    parser.add_argument("logfile", help="JSONL audit log to check")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("--verify-only", action="store_true",
                        help="print only the verdict and any problems")
    args = parser.parse_args(argv)

    report = check_log(args.logfile)
    if args.json:
        print(json.dumps(report, indent=2))
    elif args.verify_only:
        print(f"verdict: {report['verdict']} "
              f"({report['entries']} entries)")
        for problem in report["problems"]:
            print(f"  ! {problem}")
        for error in report["malformed_lines"]:
            print(f"  ! line {error['line']}: {error['error']}")
    else:
        print(f"{report['file']}: {report['entries']} entries, "
              f"verdict {report['verdict']}")
        for line in report["timeline"]:
            print(f"  {line}")
        for problem in report["problems"]:
            print(f"  ! {problem}")
        for error in report["malformed_lines"]:
            print(f"  ! line {error['line']}: {error['error']}")
    if report["malformed_lines"]:
        return 2
    return 0 if not report["problems"] else 1


if __name__ == "__main__":
    sys.exit(main())
