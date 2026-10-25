"""Checks a rule file against a test file annotated in Semgrep's style.

A comment "ruleid: X" means the next code line must be flagged by rule X; "ok: X" means it must not be.
Used by tests/test_engine.py (semgrep --test does not handle this repo's layout).
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


def check(rules: Path, target: Path) -> tuple[list[str], list[str]]:
    """Returns (missed, false_alarms): annotated lines that weren't flagged, and lines flagged that shouldn't be."""
    lines = target.read_text().splitlines()
    expected, ok = set(), set()
    for i, line in enumerate(lines):
        m = re.search(r"//\s*(ruleid|ok):\s*([\w-]+)", line)
        if not m:
            continue
        nxt = next(j for j in range(i + 1, len(lines)) if lines[j].strip() and not lines[j].strip().startswith("//"))
        (expected if m.group(1) == "ruleid" else ok).add((m.group(2), nxt + 1))
    out = subprocess.run(["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check",
                          "--no-git-ignore", "--config", str(rules), str(target)], capture_output=True, text=True, timeout=300)
    data = json.loads(out.stdout)
    # Any error fails the check: a rule that doesn't parse finds nothing, which would make every
    # "ok:" line pass for the wrong reason.
    if data.get("errors"):
        raise AssertionError(f"semgrep reported errors for {rules.name} on {target.name}: "
                             f"{[(e.get('type'), str(e.get('message', ''))[:200]) for e in data['errors'][:3]]}")
    found = {(r["check_id"].rsplit(".", 1)[-1], r["start"]["line"]) for r in data["results"]}
    missed = sorted(f"{rule} (line {line})" for rule, line in expected - found)
    false_alarms = sorted(f"{rule} (line {line})" for rule, line in found & ok)
    unexpected = sorted(f"{rule} (line {line}, not annotated)" for rule, line in found - expected - ok)
    return missed, false_alarms + unexpected
