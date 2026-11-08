"""Summarize an irctest junit XML file: totals, per-file counts, and failures."""

import collections
import re
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
per_file = collections.defaultdict(collections.Counter)
totals = collections.Counter()
failures = []
skip_reasons = collections.Counter()
for case in root.iter("testcase"):
    module = case.get("classname", "").split(".")[-2] if "." in case.get("classname", "") else "?"
    status = "passed"
    for child in case:
        if child.tag in ("failure", "error"):
            status = "failed" if child.tag == "failure" else "error"
            text = (child.get("message") or child.text or "").strip().splitlines()
            failures.append((module, case.get("name"), text[0][:200] if text else ""))
        elif child.tag == "skipped":
            status = "skipped"
            reason = child.get("message") or ""
            reason = re.sub(r"\s+", " ", reason)[:90]
            skip_reasons[reason] += 1
    per_file[module][status] += 1
    totals[status] += 1

print("TOTAL", dict(totals))
print()
print(f"{'file':32} pass fail err skip")
for module, c in sorted(per_file.items()):
    print(f"{module:32} {c['passed']:4} {c['failed']:4} {c['error']:3} {c['skipped']:4}")
print()
print("TOP SKIP REASONS")
for reason, n in skip_reasons.most_common(15):
    print(f"{n:4}  {reason}")
print()
print("FAILURES")
for module, name, msg in failures:
    print(f"{module}::{name} | {msg}")
