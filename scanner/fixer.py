"""The "Bug fixing" ($50) and "Code improvement" ($150) tiers: fix issues in the customer's source code, and
keep a fix only when a re-scan proves it.

- fix:     Critical and Warning issues.
- improve: the same plus Smells, a structure review (scanner/structure.py: deterministic measurements,
           AI refactoring suggestions that are NOT applied) and a pull-request package.

For each (rule, file) group the AI proposes exact find-and-replace edits. An edit is kept only if:
  1. every "find" text occurs exactly once in the current file (no guessing where it goes),
  2. re-scanning the edited file shows that rule gone from it,
  3. no other rule got more findings in that file (no new problems), and
  4. the file still parses (Semgrep reports no syntax error), and
  5. no non-private method or constructor was removed or changed, and no first constructor was added
     (scanner/structure.breaking_changes), since that would break other files we cannot compile here.
Otherwise the AI gets one more try with the scanner's feedback, then the issue is marked
"needs a manual fix". Leaked secrets are never "fixed" by editing code: the key has already shipped
and must be revoked, so they are reported as manual actions.

The project is not compiled (there is no Android SDK here); the report says so.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import shutil
import time
import zipfile
from collections import Counter
from dataclasses import replace
from pathlib import Path

from scanner.ai import LLMError, ProviderConfig, call_llm, get_config, language_note, parse_json
from scanner.policy import POLICY_VERSION, RULES, standard
from scanner.source import WEB_SUFFIXES
from scanner.structure import breaking_changes, js_breaking_changes, kotlin_breaking_changes
from scanner.source import (fingerprint, git_apply_check, manifest_findings, project_files, scan_source,
                            semgrep_files)

FIX_SEVERITIES = ("critical", "warning")
TIERS = {"fix": {"name": "Bug fixing", "severities": FIX_SEVERITIES},
         "improve": {"name": "Code improvement", "severities": ("critical", "warning", "smell")}}
MAX_STRUCTURE_SUGGESTIONS = 6
MAX_FILE_CHARS = 60_000
MAX_ATTEMPTS = 2  # fixes the scanner rejected, per issue
MAX_AI_ERRORS = 3  # broken or failed AI replies, per issue (these don't use up an attempt)
MAX_GROUPS = int(os.environ.get("FIX_MAX_ISSUES", 25))

SYSTEM_PROMPT = """You fix one security or reliability problem in one source file of an Android app (Java or Kotlin)
or a web app (JavaScript or TypeScript, possibly React/Next.js).

Return ONLY a JSON object:
{"edits": [{"find": "<exact text copied from the file>", "replace": "<new text>"}],
 "summary": "<one or two plain-English sentences: what you changed and why it is safe now>"}

Rules:
- "find" must be copied character for character from the file (including indentation) and must occur
  exactly once in it. Include enough surrounding lines to make it unique. Keep each edit small.
- Fix every listed occurrence of the problem in this file, and nothing else. Do not reformat, rename, or
  touch unrelated code. Keep the app's behaviour the same except for removing the problem.
- Use only the language's standard library and what the file already imports (no new npm packages or
  Android libraries); add any import lines you need as separate edits.
- Do not change, remove or add constructors, do not change the signature of any non-private method, and do
  not remove or rename anything a JavaScript/TypeScript file exports: other files use them. Add private
  helpers (or non-exported functions) instead if you need them.
- The code must still compile: Java 8 syntax for .java files, idiomatic Kotlin for .kt files, and for
  .js/.ts/.jsx/.tsx files keep the file's style (module syntax, TypeScript types, framework conventions).
- In web code, prefer safe built-ins: textContent instead of innerHTML, JSON.parse instead of eval, https://
  URLs, checking event.origin in message listeners, and never logging or storing secrets in the browser.
- If the fix changes data the app has already stored (for example a different hash or key format, or a
  database column), or changes something users notice (where files are saved, a feature that stops
  working), end the summary with "Note: " and what the developer must check or migrate.
- If the problem cannot be fixed safely without knowing more about the app, return {"edits": [], "summary": "<why>"}.
"""


def plan(findings: list[dict], severities: tuple[str, ...] = FIX_SEVERITIES) -> tuple[list[dict], list[dict], list[dict]]:
    """Split findings into (groups to fix, manual actions, out of scope for this tier)."""
    groups: dict[tuple[str, str], dict] = {}
    manual, later = [], []
    for f in sorted(findings, key=lambda f: (f["file"], f["line"])):
        if f["policy_rule"] == "secret":
            manual.append(f)
        elif f["severity"] not in severities:
            later.append(f)
        else:
            g = groups.setdefault((f["policy_rule"], f["file"]), {"rule_id": f["policy_rule"], "file": f["file"],
                                                                  "severity": f["severity"], "findings": []})
            g["findings"].append(f)
    order = {"critical": 0, "warning": 1, "smell": 2}
    ordered = sorted(groups.values(), key=lambda g: (order[g["severity"]], g["file"], g["rule_id"]))
    return ordered, manual, later


def fix_project(original_root: Path, work_dir: Path, progress=lambda message, done, total: None,
                cfg: ProviderConfig | None = None, tier: str = "fix", language: str | None = None) -> dict:
    """Fix a copy of the project in work_dir/fixed. Writes fixes.patch and fixed-source.zip next to it
    (and, for the improve tier, pr-description.md and commit-message.txt)."""
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}")
    started = time.monotonic()
    cfg = cfg or get_config()
    if cfg.response_format == "json_schema":
        cfg = replace(cfg, response_format="json_object")  # the schema belongs to the report prompt

    progress("Scanning your source code", 0, 1)
    before = scan_source(original_root)
    groups, manual, later = plan(before.findings, TIERS[tier]["severities"])
    skipped_for_limit = groups[MAX_GROUPS:]
    groups = groups[:MAX_GROUPS]

    fixed_root = work_dir / "fixed"
    if fixed_root.exists():
        shutil.rmtree(fixed_root)
    shutil.copytree(original_root, fixed_root, symlinks=False)

    results = []
    for n, group in enumerate(groups, 1):
        rule = RULES.get(group["rule_id"])
        progress(f"Fixing {n} of {len(groups)}: {rule.title if rule else group['rule_id']}", n - 1, len(groups))
        results.append(_fix_group(group, fixed_root, cfg, language))
    for group in skipped_for_limit:
        results.append(_result(group, "needs_manual_fix", f"More than {MAX_GROUPS} issues; this one was not attempted."))

    structure = None
    if tier == "improve":
        progress("Reviewing the code's structure", len(groups), len(groups))
        structure = _structure_review(fixed_root, cfg, language)

    progress("Re-scanning the fixed project", len(groups), len(groups))
    after = scan_source(fixed_root)
    patch_text = _patch(original_root, fixed_root)
    patch_path = work_dir / "fixes.patch"
    patch_path.write_text(patch_text)
    applies, apply_log = git_apply_check(original_root, patch_path) if patch_text else (True, "")
    zip_path = work_dir / "fixed-source.zip"
    _zip(fixed_root, zip_path)

    fixed = sum(1 for r in results if r["status"] == "fixed")
    model = cfg.model
    result = {
        "kind": "fix", "target": "source", "project": original_root.name,
        "tier": tier, "tier_name": TIERS[tier]["name"],
        "summary": {
            "attempted": len(results), "fixed": fixed,
            "partly_fixed": sum(1 for r in results if r["status"] == "partly_fixed"),
            "needs_manual_fix": sum(1 for r in results if r["status"] == "needs_manual_fix"),
            "manual_actions": len(manual), "not_in_this_tier": len(later),
        },
        "before": {"counts": _counts(before.findings), "fingerprint": fingerprint(before.findings)},
        "after": {"counts": _counts(after.findings), "fingerprint": fingerprint(after.findings),
                  "new_problems": _new_problems(before.findings, after.findings)},
        "fixes": results,
        "manual_actions": [_manual(f) for f in manual],
        "not_in_this_tier": [{"rule_id": f["policy_rule"], "title": f["title"], "file": f["file"], "line": f["line"]}
                             for f in later],
        "coverage": _coverage(before, before.errors + after.errors),
        "verification": {"rescanned": True, "syntax_checked": True, "interface_checked": True, "compiled": False,
                         "patch_applies_cleanly": applies, "patch_check_log": "" if applies else apply_log,
                         "patch_sha256": hashlib.sha256(patch_text.encode()).hexdigest()},
        "ai": {"provider": cfg.name, "model": model},
        "policy_version": POLICY_VERSION,
        "seconds": round(time.monotonic() - started, 1),
        "disclaimer": ("Each change was re-scanned with the same rules and checked for syntax errors, and the patch "
                       "was checked to apply cleanly to the code you uploaded. The project was not compiled or "
                       "tested here: build it and run your tests before releasing. Review every change; the AI "
                       "wrote the edits and the scanner only proves the listed problems are gone."),
    }
    if structure is not None:
        result["structure"] = structure
        result["pull_request"] = _pull_request(result, work_dir)
    return result


# ---------------------------------------------------------------- improve tier: structure and PR

STRUCTURE_PROMPT = """You review the structure of one method or function (Java or Kotlin) in an Android app and suggest how to improve it.
Do NOT rewrite the whole method. Return ONLY a JSON object:
{"steps": ["<short, concrete refactoring step>", ...], "sketch": "<a short sketch of the new shape in the same language, max 25 lines>",
 "risk": "<one sentence: what could break and what to test>"}
Keep behaviour identical. Use plain English a non-expert developer can follow. Standard library only."""


def _structure_review(root: Path, cfg: ProviderConfig, language: str | None = None) -> dict:
    from scanner.structure import MAX_METHOD_LINES, MAX_PARAMETERS, measure, measure_kotlin

    java = [p.relative_to(root).as_posix() for p in project_files(root, ".java")]
    kotlin = [p.relative_to(root).as_posix() for p in project_files(root, ".kt")]
    issues = measure(root, java) + measure_kotlin(root, kotlin)
    for issue in issues[:MAX_STRUCTURE_SUGGESTIONS]:
        text = (root / issue["file"]).read_text(errors="replace").splitlines()
        code = "\n".join(text[issue["line"] - 1:issue["end_line"]])
        user = (f"File: {issue['file']}\nMethod: {issue['method']} ({issue['lines']} lines, {issue['parameters']} parameters)\n"
                f"Problem: {issue['title']} ({issue['source']}: {issue['limit']}). {issue['why']}\n\n{code[:20000]}")
        try:
            content, _ = call_llm([{"role": "system", "content": STRUCTURE_PROMPT + language_note(language)},
                                   {"role": "user", "content": user}], cfg)
            data = parse_json(content)
            issue["suggestion"] = {
                "steps": [str(s)[:300] for s in (data.get("steps") or [])][:8],
                "sketch": str(data.get("sketch") or "")[:3000],
                "risk": str(data.get("risk") or "")[:400],
                "applied": False,
            }
        except (LLMError, ValueError, json.JSONDecodeError) as e:
            issue["suggestion"] = {"steps": [], "sketch": "", "risk": "", "applied": False,
                                   "error": f"No suggestion: the AI service failed ({str(e)[:120]})."}
    for issue in issues[MAX_STRUCTURE_SUGGESTIONS:]:
        issue["suggestion"] = None
    return {"issues": issues, "limits": {"method_lines": MAX_METHOD_LINES, "parameters": MAX_PARAMETERS},
            "note": ("Measured with SonarSource's default limits. Suggestions are written by the AI and are not applied: "
                     "a restructure can only be proven safe by compiling the app and running its tests.")}


def _pull_request(result: dict, work_dir: Path) -> dict:
    """A ready-to-use PR description and commit message (written next to the patch)."""
    sm, b, a = result["summary"], result["before"]["counts"], result["after"]["counts"]
    title = f"Fix {sm['fixed']} security and code-quality issues (VibeGuard)"
    lines = [f"## Summary", "",
             f"Automated fixes from a VibeGuard {result['tier_name']} run. Every change below was re-scanned with "
             f"the same rules (OWASP MASVS v2 / CWE, policy {result['policy_version']}) and kept only when the problem was gone, "
             "no new problem appeared and the file still parsed.", "",
             "| | Before | After |", "|---|---|---|",
             f"| Critical | {b['critical']} | {a['critical']} |", f"| Warnings | {b['warning']} | {a['warning']} |",
             f"| Smells | {b['smell']} | {a['smell']} |", "", "## Changes", ""]
    for f in result["fixes"]:
        mark = {"fixed": "[x]", "partly_fixed": "[~]", "needs_manual_fix": "[ ]"}[f["status"]]
        std = f" ({f['standard']['cwe']})" if f.get("standard") else ""
        lines.append(f"- {mark} **{f['title']}**{std}: `{f['file']}`" + (f": {f['summary']}" if f["summary"] else "")
                     + ("" if f["status"] == "fixed" else f" _Not fixed: {f['reason']}_"))
    notes = [f for f in result["fixes"] if "Note:" in f["summary"]]
    if notes:
        lines += ["", "## Data migration", ""] + [f"- `{f['file']}`: {f['summary'][f['summary'].index('Note:'):]}" for f in notes]
    if result["manual_actions"]:
        lines += ["", "## To do by hand", ""] + [f"- [ ] **{m['title']}** in `{m['file']}` line {m['line']}: {m['action']}"
                                                for m in result["manual_actions"]]
    structure = result.get("structure", {}).get("issues", [])
    if structure:
        lines += ["", "## Structure review (suggestions, not part of this PR)", ""] + [
            f"- `{s['file']}` `{s['method']}()`: {s['title'].lower()} ({s['lines']} lines, {s['parameters']} parameters; "
            f"{s['source']})" for s in structure]
    lines += ["", "## Before merging", "",
              "- [ ] Build the app and run the tests (this run checked syntax and re-scanned, but did not compile)",
              "- [ ] Review each change", "- [ ] Handle the data migration notes above" if notes else "",
              "", f"Before fingerprint `{result['before']['fingerprint']}` → after `{result['after']['fingerprint']}` · "
              f"patch sha256 `{result['verification']['patch_sha256'][:16]}`"]
    body = "\n".join(l for l in lines if l is not None)
    commit = (f"{title}\n\n" + "\n".join(f"- {f['title']} ({f['file']})" for f in result["fixes"] if f["status"] != "needs_manual_fix")
              + f"\n\nVerified by re-scan (policy {result['policy_version']}); not compiled.\n")
    (work_dir / "pr-description.md").write_text(f"# {title}\n\n{body}\n")
    (work_dir / "commit-message.txt").write_text(commit)
    branch = "vibeguard/code-improvement"
    return {"title": title, "body": body, "branch": branch,
            "commands": [f"git checkout -b {branch}", "git apply fixes.patch", "git add -A",
                         "git commit -F commit-message.txt", f"git push -u origin {branch}",
                         "# then open a pull request and paste pr-description.md"]}


# ---------------------------------------------------------------- one group

def _fix_group(group: dict, root: Path, cfg: ProviderConfig, language: str | None = None) -> dict:
    path = root / group["file"]
    original = path.read_text(errors="replace")
    if len(original) > MAX_FILE_CHARS:
        return _result(group, "needs_manual_fix", "The file is too large to fix automatically.")
    before_counts, before_parse = _scan_one(path, root)
    target_before = before_counts.get(group["rule_id"], 0)
    if target_before == 0:
        return _result(group, "fixed", "Already gone after an earlier fix in the same file.", attempts=0)

    feedback, last_reason, summary = None, "", ""
    attempt, ai_errors = 0, 0
    while attempt < MAX_ATTEMPTS:
        attempt += 1
        current = path.read_text(errors="replace")
        try:
            reply = _ask(group, current, feedback, cfg, language)
        except LLMError as e:
            ai_errors += 1
            last_reason = f"The AI service failed: {str(e)[:200]}"
            if not e.retryable or ai_errors >= MAX_AI_ERRORS:
                break
            attempt -= 1  # a broken reply is not a rejected fix; ask again
            continue
        summary = reply["summary"]
        if not reply["edits"]:
            last_reason = summary or "The AI could not find a safe fix."
            break
        patched, problem = _apply_edits(current, reply["edits"])
        if problem:
            feedback, last_reason = problem, problem
            continue
        broken = (breaking_changes(current, patched) if path.suffix == ".java"
                  else kotlin_breaking_changes(current, patched) if path.suffix == ".kt"
                  else js_breaking_changes(current, patched) if path.suffix in WEB_SUFFIXES else [])
        if broken:
            feedback = last_reason = ("The edit changes how other files use this class, which would stop them compiling: "
                                      + "; ".join(broken[:3]) + ". Keep every constructor and non-private method signature unchanged.")
            continue
        path.write_text(patched)
        after_counts, after_parse = _scan_one(path, root)
        verdict = _judge(group["rule_id"], target_before, before_counts, after_counts, before_parse, after_parse)
        if verdict is None or verdict == "partly":
            status = "fixed" if verdict is None else "partly_fixed"
            if status == "partly_fixed" and attempt < MAX_ATTEMPTS:
                feedback = (f"{after_counts.get(group['rule_id'], 0)} of {target_before} occurrences are still found "
                            "by the scanner. Fix all of them.")
                continue  # keep the partial fix in the file and ask again for the rest
            return _result(group, status, "", summary, _diff(group["file"], original, patched),
                           attempt, after_counts.get(group["rule_id"], 0))
        path.write_text(current)  # reject: put the file back exactly as it was
        feedback, last_reason = verdict, verdict
    final = path.read_text(errors="replace")
    if final != original:  # an earlier partial fix is kept
        remaining = _scan_one(path, root)[0].get(group["rule_id"], 0)
        return _result(group, "partly_fixed", last_reason, summary, _diff(group["file"], original, final),
                       MAX_ATTEMPTS, remaining)
    return _result(group, "needs_manual_fix", last_reason or "No verified fix was found.", summary, attempts=MAX_ATTEMPTS)


def _ask(group: dict, text: str, feedback: str | None, cfg: ProviderConfig, language: str | None = None) -> dict:
    rule = RULES.get(group["rule_id"])
    lines = text.splitlines()
    occurrences = "\n".join(
        f"- line {f['line']}: {lines[f['line'] - 1].strip() if 0 < f['line'] <= len(lines) else ''}"
        for f in group["findings"])
    user = (f"File: {group['file']}\n"
            f"Problem: {rule.title if rule else group['rule_id']} ({group['rule_id']}, {standard(rule)['cwe'] if rule else ''})\n"
            f"Why it matters: {rule.risk if rule else ''}\n"
            f"How to fix: {rule.fix if rule else ''}\n"
            f"Where the scanner found it (original line numbers):\n{occurrences}\n")
    if feedback:
        user += f"\nYour previous edit was rejected: {feedback}\nTry again.\n"
    user += f"\n----- {Path(group['file']).name} -----\n{text}"
    content, usage = call_llm([{"role": "system", "content": SYSTEM_PROMPT + language_note(language)},
                               {"role": "user", "content": user}], cfg)
    try:
        data = parse_json(content)
    except (ValueError, json.JSONDecodeError) as e:
        cut = " (cut off: it ran out of tokens)" if usage.get("finish_reason") == "length" else ""
        raise LLMError(f"the AI's reply was not valid JSON{cut}: {e}") from None
    edits = [e for e in data.get("edits") or [] if isinstance(e, dict) and isinstance(e.get("find"), str)
             and isinstance(e.get("replace"), str)]
    return {"edits": edits, "summary": str(data.get("summary") or "").strip()[:600]}


def _apply_edits(text: str, edits: list[dict]) -> tuple[str, str | None]:
    for edit in edits:
        find = edit["find"]
        if not find:
            return text, "An edit had an empty 'find' text."
        count = text.count(find)
        if count != 1:
            where = "does not occur" if count == 0 else f"occurs {count} times"
            return text, f"The 'find' text {where} in the file: {find[:120]!r}. Copy it exactly and make it unique."
        text = text.replace(find, edit["replace"], 1)
    return text, None


def _scan_one(path: Path, root: Path) -> tuple[Counter, bool]:
    if path.name == "AndroidManifest.xml":
        found = manifest_findings(path, root)
        return Counter(f.rule_id for f in found), any(f.rule_id == "manifest-unreadable" for f in found)
    found, parse_errors = semgrep_files([path], root)
    return Counter(f.rule_id for f in found), bool(parse_errors)


def _judge(rule_id: str, target_before: int, before: Counter, after: Counter, parse_before: bool,
           parse_after: bool) -> str | None:
    """None = fully fixed; 'partly' = fewer but not zero; otherwise the reason to reject."""
    if parse_after and not parse_before:
        return "The edited file no longer parses (syntax error)."
    new = [r for r in after if r != rule_id and after[r] > before.get(r, 0)]
    if new:
        return f"The edit introduced a new problem the scanner flags: {', '.join(sorted(new))}."
    left = after.get(rule_id, 0)
    if left == 0:
        return None
    if left < target_before:
        return "partly"
    return "The scanner still finds the problem after the edit."


# ---------------------------------------------------------------- output

def _result(group: dict, status: str, reason: str, summary: str = "", diff: str = "", attempts: int = 0,
            remaining: int | None = None) -> dict:
    rule = RULES.get(group["rule_id"])
    return {
        "rule_id": group["rule_id"], "title": rule.title if rule else group["rule_id"], "severity": group["severity"],
        "standard": standard(rule) if rule else None, "file": group["file"],
        "lines": [f["line"] for f in group["findings"]], "occurrences_before": len(group["findings"]),
        "occurrences_after": len(group["findings"]) if remaining is None and status == "needs_manual_fix" else (remaining or 0),
        "status": status, "reason": reason, "summary": summary, "diff": diff, "attempts": attempts,
        "how_to_fix": rule.fix if rule else "",
    }


def _manual(f: dict) -> dict:
    return {"rule_id": f["policy_rule"], "title": f["title"], "file": f["file"], "line": f["line"],
            "what": f.get("message", ""),
            "action": ("Revoke this key in the provider's dashboard and create a new one: it is already inside copies "
                       "of your app, so editing the code does not make it secret again. Then load the new key from "
                       "your server at runtime (or, for keys that are meant to be public, restrict them by app "
                       "signature) instead of writing it into the code.")}


def _diff(rel: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        f"a/{rel}", f"b/{rel}"))


def _patch(original_root: Path, fixed_root: Path) -> str:
    parts = []
    for path in sorted(p for p in fixed_root.rglob("*") if p.is_file()):
        rel = path.relative_to(fixed_root).as_posix()
        old_path = original_root / rel
        new = (path.read_text(errors="replace")
               if path.suffix in (".java", ".xml", ".kt", ".gradle", *WEB_SUFFIXES) else None)
        if new is None or not old_path.is_file():
            continue
        old = old_path.read_text(errors="replace")
        if old != new:
            parts.append(f"diff --git a/{rel} b/{rel}\n" + _diff(rel, old, new))
    return "".join(parts)


def _zip(root: Path, dest: Path) -> None:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            z.write(path, f"{root.name}/{path.relative_to(root).as_posix()}")


def _coverage(scan, tool_errors: list[str]) -> dict:
    return {"java_files": len(scan.java_files), "kotlin_files": len(scan.kotlin_files), "manifests": scan.manifests,
            "web_files": len(scan.web_files), "not_checked": scan.not_checked, "tool_errors": tool_errors}


def _counts(findings: list[dict]) -> dict:
    c = Counter(f["severity"] for f in findings)
    return {"critical": c.get("critical", 0), "warning": c.get("warning", 0), "smell": c.get("smell", 0)}


def _new_problems(before: list[dict], after: list[dict]) -> list[str]:
    b = Counter((f["policy_rule"], f["file"]) for f in before)
    a = Counter((f["policy_rule"], f["file"]) for f in after)
    return sorted(f"{rule} in {file}" for (rule, file), n in a.items() if n > b.get((rule, file), 0))


def preview(root: Path) -> dict:
    """The free result for an uploaded project: what was found and what each tier would work on."""
    from scanner.structure import measure, measure_kotlin

    scan = scan_source(root)
    groups, manual, later = plan(scan.findings)
    improve_groups, _, _ = plan(scan.findings, TIERS["improve"]["severities"])
    structure = measure(root, scan.java_files) + measure_kotlin(root, scan.kotlin_files)
    by_rule: dict[str, dict] = {}
    for f in scan.findings:
        item = by_rule.setdefault(f["policy_rule"], {"rule_id": f["policy_rule"], "title": f["title"],
                                                     "severity": f["severity"], "occurrences": 0, "files": set()})
        item["occurrences"] += 1
        item["files"].add(f["file"])
    order = {"critical": 0, "warning": 1, "smell": 2}
    issues = sorted(by_rule.values(), key=lambda i: (order[i["severity"]], -i["occurrences"], i["rule_id"]))
    for i in issues:
        i["files"] = len(i["files"])
        i["fixable"] = i["severity"] in FIX_SEVERITIES and i["rule_id"] != "secret"
        i["standard"] = standard(RULES[i["rule_id"]]) if i["rule_id"] in RULES else None
    return {
        "locked": True, "target": "source", "project": root.name,
        "counts": _counts(scan.findings), "result_fingerprint": fingerprint(scan.findings),
        "fixable_issues": len(groups), "fixable_occurrences": sum(len(g["findings"]) for g in groups),
        "manual_actions": len(manual), "not_in_this_tier": len(later), "issues": issues,
        "improve": {"fixable_issues": len(improve_groups), "smell_issues": len(improve_groups) - len(groups),
                    "structure_issues": len(structure),
                    "structure": [{k: s[k] for k in ("rule_id", "title", "file", "method", "lines", "parameters", "source")}
                                  for s in structure]},
        "coverage": _coverage(scan, scan.errors),
        "scan": {"apk_name": root.name, "policy_version": POLICY_VERSION},
    }


__all__ = ["fix_project", "plan", "preview", "project_files"]
