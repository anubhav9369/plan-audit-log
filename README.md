# plan-audit-log

A plan is only trustworthy if its history can be believed. This is the
record half: read and verify the append-only audit log of an
InspectablePlan — every event the pipeline writes (created, explained,
risk-scanned, approved, refined, policy-checked) — and prove that no
entry was edited, deleted or reordered after the fact.

Part of the trustworthy-agentic-ai prototype for **BRJP26100123 —
Building Trustworthy AI Systems through Explainability and
Human-in-the-Loop Control**. Companion repos:
[trustworthy-agentic-ai](https://github.com/anubhav9369/trustworthy-agentic-ai)
(the InspectablePlan schema),
[plan-explainer](https://github.com/anubhav9369/plan-explainer)
(plain-language rendering + review checklist),
[plan-diff](https://github.com/anubhav9369/plan-diff)
(what changed between two plan versions),
[plan-risk-scan](https://github.com/anubhav9369/plan-risk-scan)
(what needs a human's attention before approval),
[plan-approve](https://github.com/anubhav9369/plan-approve)
(the human decision point),
[plan-refine](https://github.com/anubhav9369/plan-refine)
(applying the human's requested changes), and
[plan-policy-check](https://github.com/anubhav9369/plan-policy-check)
(validating a plan against a policy pack).

## The rules

| Rule | What it stops |
| --- | --- |
| A malformed line is reported, never silently skipped | A log that looks clean because a bad line was dropped |
| Sequence numbers start at 1 and rise by exactly 1 | A deleted entry passing as "nothing happened" |
| Each entry's `prev_hash` must match the previous entry's hash | Entries reordered or spliced in from another log |
| The stored hash must match a recomputation | An entry edited after it was written |
| Timestamps must not run backwards | A log re-assembled out of order |

Each entry is one JSON line with `seq`, `ts`, `actor`, `action`,
`plan`, `version`, `detail`, `prev_hash` and `hash` — the hash is a
sha256 of the entry's canonical JSON (without the hash itself) chained
to the previous entry, `GENESIS` for the first.

## Usage

```bash
python3 plan_audit_log.py examples/audit.jsonl
```

The example log is clean: 6 entries from plan creation to refinement,
verdict `clean`, exit 0.

```bash
python3 plan_audit_log.py examples/broken.jsonl --verify-only
```

The broken log fails three ways: entry 3 was edited after it was
written (hash mismatch), entry 5 is missing (sequence gap), and the
hash chain breaks at entry 6. Verdict `broken`, exit 1. Exit codes:
0 clean, 1 chain problems, 2 malformed lines. `--json` prints the full
report (verdict, problems, summary, timeline) as JSON.

Python API:

```python
from plan_audit_log import check_log, filter_entries

report = check_log("examples/audit.jsonl")
report["verdict"]  # "clean" | "broken" | "malformed"
entries, errors = read_log("examples/audit.jsonl")
approved = filter_entries(entries, action="plan_approved")
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

9 tests, all passing.
