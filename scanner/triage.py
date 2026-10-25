"""Step 4: triage - pick representative findings and attach a small window of code to each.

Keeps the LLM input small: a few examples per rule (more for security, fewer for smells),
~20 lines of context each, and an overall character budget. Every rule found is kept: examples
that don't fit the budget are marked sent_to_ai=False and still appear in the report.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from scanner.ingest import UnpackedApk

CONTEXT_BEFORE = 10
CONTEXT_AFTER = 10
MAX_FLAGGED_SPAN = 8  # multi-line matches (e.g. a whole method) are trimmed to this many lines
MAX_LINE_CHARS = 200
MAX_OTHER_LOCATIONS = 10
CHAR_BUDGET = 40_000  # ~10k tokens of code context in total

EXAMPLES_PER_RULE = {"secret": 5, "security": 4, "bug": 3, "smell": 2}
CATEGORY_ORDER = {"secret": 0, "security": 1, "bug": 2, "smell": 3}
SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}

CLASS_RE = re.compile(r"\b(?:class|interface|enum)\s+(\w+)")
METHOD_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)*"
    r"(?:<[^>]+>\s+)?[\w.$<>\[\], ?]+\s+([\w$]+)\s*\([^;{]*\)\s*(?:throws\s+[\w.$, ]+)?\s*\{\s*$"
)
NOT_METHOD_NAMES = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "else"}


def triage(unpacked: UnpackedApk, scan_result: dict, char_budget: int = CHAR_BUDGET) -> dict:
    jadx_root = unpacked.sources_dir.parent
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in scan_result["findings"]:
        groups[f["rule_id"]].append(f)

    # Most important rules first, so if we run out of budget it's the smells that get cut.
    ordered_rules = sorted(groups, key=lambda r: _priority(groups[r][0]) + (-len(groups[r]),))

    items, omitted, used = [], [], 0
    for rule_id in ordered_rules:
        findings = groups[rule_id]
        limit = EXAMPLES_PER_RULE.get(findings[0]["category"], 2)
        examples = _pick_examples(findings, limit)
        others = [f"{f['file']}:{f['line']}" for f in findings if f not in examples]

        for i, f in enumerate(examples):
            item = _build_item(jadx_root, f, CONTEXT_BEFORE, CONTEXT_AFTER)
            if used + len(item["context"]) > char_budget:
                # Retry with a much smaller window before leaving this one out of the AI prompt.
                item = _build_item(jadx_root, f, 3, 3)
            if used + len(item["context"]) > char_budget:
                # Still reported and counted - it just gets the policy's wording instead of the AI's.
                omitted.append(f"{f['file']}:{f['line']} ({rule_id})")
                item["context"] = ""
                item["sent_to_ai"] = False
            else:
                item["sent_to_ai"] = True
            used += len(item["context"])
            if i == 0:
                # The first example carries the rule-wide picture for the report.
                item["occurrences"] = len(findings)
                item["other_locations"] = others[:MAX_OTHER_LOCATIONS]
                item["more_locations"] = max(0, len(others) - MAX_OTHER_LOCATIONS)
            items.append(item)

    for n, item in enumerate(items, 1):
        item["id"] = f"F{n}"

    return {
        "items": items,
        "summary": {
            "findings_total": len(scan_result["findings"]),
            "rules": len(groups),
            "items_with_context": len(items),
            "omitted_for_budget": omitted,
            "context_chars": used,
            "approx_tokens": used // 4,
        },
    }


def _priority(f: dict) -> tuple:
    return (CATEGORY_ORDER.get(f["category"], 9), SEVERITY_ORDER.get(f["tool_severity"], 9))


def _pick_examples(findings: list[dict], limit: int) -> list[dict]:
    """Prefer examples from different files - 3 hits in 3 files say more than 3 in one."""
    picked, seen_files = [], set()
    for f in findings:
        if f["file"] not in seen_files:
            picked.append(f)
            seen_files.add(f["file"])
        if len(picked) == limit:
            return picked
    for f in findings:
        if f not in picked:
            picked.append(f)
            if len(picked) == limit:
                break
    return picked


def _build_item(jadx_root: Path, f: dict, before: int, after: int) -> dict:
    lines = list(_read_lines(str(jadx_root / f["file"])))
    start = f["line"]
    end = min(f.get("end_line") or start, start + MAX_FLAGGED_SPAN - 1)

    if f["category"] == "secret":
        lines = _mask_secret(lines, f)

    lo, hi = max(1, start - before), min(len(lines), end + after)
    width = len(str(hi))
    context = "\n".join(
        f"{'>>' if start <= n <= end else '  '}{n:>{width}} | {_clip(lines[n - 1])}" for n in range(lo, hi + 1)
    )

    item = {
        "rule_id": f["rule_id"],
        "category": f["category"],
        "tool": f["tool"],
        "tool_severity": f["tool_severity"],
        "message": f["message"],
        "file": f["file"],
        "line": f["line"],
        "context": context,
    }
    if f["file"].endswith(".java"):
        item["class"], item["method"] = _enclosing(lines, start)
    extra = {k: v for k, v in f.get("extra", {}).items() if k not in ("secret_sha256", "secret_length")}
    if extra:
        item["extra"] = extra
    return item


@lru_cache(maxsize=256)
def _read_lines(path: str) -> tuple[str, ...]:
    try:
        return tuple(Path(path).read_text(errors="ignore").splitlines())
    except OSError:
        return ()


def _clip(line: str) -> str:
    line = line.rstrip()
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + " …"


def _mask_secret(lines: list[str], f: dict) -> list[str]:
    """Replace the secret with a placeholder by matching its hash, so it never leaves the machine."""
    extra = f.get("extra", {})
    digest, length = extra.get("secret_sha256"), extra.get("secret_length", 0)
    first, last = f["line"], f.get("end_line") or f["line"]
    lines = list(lines)
    placeholder = f"<SECRET HIDDEN: {extra.get('secret_preview', '')}>"

    for n in range(first, min(last, len(lines)) + 1):
        text, masked = lines[n - 1], False
        if digest and length and first == last:
            for i in range(len(text) - length + 1):
                if hashlib.sha256(text[i:i + length].encode()).hexdigest() == digest:
                    lines[n - 1] = text[:i] + placeholder + text[i + length:]
                    masked = True
                    break
        if not masked:
            # Couldn't locate it exactly (e.g. a multi-line private key): hide the whole line.
            indent = text[: len(text) - len(text.lstrip())]
            lines[n - 1] = f"{indent}<LINE HIDDEN: contains a secret>"
    return lines


def _enclosing(lines: list[str], line: int) -> tuple[str | None, str | None]:
    """Walk upwards, skipping blocks that already closed, to find the class/method we're inside."""
    cls = method = None
    balance = 0
    for n in range(min(line, len(lines)) - 1, 0, -1):
        text = lines[n - 1]
        balance += text.count("}") - text.count("{")
        if balance >= 0:
            continue  # this line doesn't open a block that encloses us
        balance = 0
        if method is None and cls is None:
            m = METHOD_RE.match(text)
            if m and m.group(1) not in NOT_METHOD_NAMES:
                method = m.group(1)
        if (m := CLASS_RE.search(text)) and not text.lstrip().startswith(("//", "*", "/*")):
            cls = m.group(1)
            break
    return cls, method


if __name__ == "__main__":
    import argparse
    import json

    from scanner.ingest import load_unpacked, unpack_apk
    from scanner.mapper import build_map
    from scanner.scan import run_static_scan

    parser = argparse.ArgumentParser(description="Triage static-scan findings and attach code context.")
    parser.add_argument("target", help="path to an .apk, or a folder from an earlier run (skips jadx)")
    parser.add_argument("--json", action="store_true", help="print the full triage result as JSON")
    args = parser.parse_args()

    target = Path(args.target)
    unpacked = load_unpacked(target) if target.is_dir() else unpack_apk(target)
    result = triage(unpacked, run_static_scan(unpacked, build_map(unpacked)))

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps(result["summary"], indent=2))
        for item in result["items"]:
            where = ".".join(x for x in (item.get("class"), item.get("method")) if x)
            count = f"  ({item['occurrences']} total)" if "occurrences" in item else ""
            print(f"\n=== {item['id']} [{item['category']}] {item['rule_id']}{count}")
            print(f"    {item['file']}:{item['line']}" + (f"  in {where}" if where else ""))
            print(item["context"])
    print(f"\n# decompiled folder: {unpacked.work_dir}")
