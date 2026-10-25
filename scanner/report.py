"""Step 6: report - merge map, scan, triage and AI output into one plain-English report.

build_report() returns JSON-ready data grouped by severity; render_text() turns it into readable text.

Which issues are found (severities, locations, order, fingerprint) comes only from the scanners and the
severity policy, so it is identical on every run. The AI adds wording, a false-alarm opinion per issue,
and a separate, uncounted list of suggestions. Issues it judges false alarms everywhere it looked are
moved out of the counts into their own list (report["false_alarms"]), so the counts can be lower with AI.
"""

from __future__ import annotations

import hashlib
import json
import textwrap
from collections import defaultdict

from scanner.ai import normalize
from scanner.policy import POLICY_VERSION, rule_for, standard

GROUPS = (
    ("critical", "Critical", "Fix before you release"),
    ("warning", "Warning", "Fix soon"),
    ("smell", "Smell", "Clean up when you can"),
)
SEVERITY_RANK = {"critical": 0, "warning": 1, "smell": 2}
KIND_RANK = {"secret": 0, "security": 1, "bug": 2, "smell": 3}
KIND_LABELS = {"secret": "Leaked secret", "security": "Security", "logic": "Logic bug",
               "bug": "Likely bug", "smell": "Code quality"}

DISCLAIMER = (
    "This is an automated scan of the app's decompiled code. Issues and their severity come from fixed "
    "scanner rules, so the same app always gets the same result; the plain-English wording and the "
    "'AI suggestions' section are written by an AI and can be wrong. The scan can miss problems and can "
    "raise false alarms, so treat it as a starting point for review, not a guarantee that the app is safe."
)


WEB_DISCLAIMER = DISCLAIMER.replace(
    "an automated scan of the app's decompiled code", "an automated scan of the code this website sends to "
    "browsers and of its server responses").replace("the same app always", "the same site always")


def build_report(app_map: dict, scan_result: dict, triaged: dict, ai_result: dict | None, meta: dict) -> dict:
    warnings = list(meta.pop("warnings", []))
    target = meta.pop("target", "android")
    if ai_result is None:
        # AI off or unavailable: same issues and severities, with the policy's fixed wording.
        ai_result, _ = normalize({}, triaged)
        ai_result["llm"] = None
    else:
        warnings += ai_result.get("warnings", [])

    items = {item["id"]: item for item in triaged["items"]}
    explained = {f["id"]: f for f in ai_result["findings"]}

    issues = _merge_by_rule(items, explained)
    issues.sort(key=lambda i: (SEVERITY_RANK[i["severity"]], KIND_RANK.get(i["kind"], 9),
                               -i["occurrences"], i["rule_id"], _first_location(i)))
    for n, issue in enumerate(issues, 1):
        issue["id"] = f"I{n}"

    suggestions = [_suggestion(b, items) for b in ai_result.get("logic_bugs", [])]
    for n, s in enumerate(suggestions, 1):
        s["id"] = f"S{n}"

    # Issues the AI judged false alarms in every place it saw are listed on their own and not counted.
    # The fingerprint still covers every issue the scanners found, so it does not depend on the AI.
    false_alarms = [i for i in issues if is_false_alarm(i)]
    counted = [i for i in issues if not is_false_alarm(i)]
    groups = {key: [i for i in counted if i["severity"] == key] for key, _, _ in GROUPS}
    summary = ai_result["app_summary"]
    return {
        "target": target,
        "app": {
            "package_name": app_map["package_name"],
            "one_liner": summary["one_liner"] or (f"Website {app_map['package_name']}" if target == "web"
                                                  else f"Android app {app_map['package_name']}"),
            "what_it_does": summary["what_it_does"],
            "how_it_works": summary["how_it_works"],
            "personal_data": summary["personal_data"],
            "talks_to": summary["talks_to"],
            "permissions": app_map["permissions"],
            "libraries": [{"name": lib["name"], "purpose": lib["category"]}
                          for lib in app_map["libraries"] if lib["category"] != "core"],
            "unencrypted_servers": sorted({e["host"] for e in app_map["endpoints"] if e["in_app_code"] and e["insecure"]}),
        },
        "counts": {key: len(groups[key]) for key, _, _ in GROUPS},
        "result_fingerprint": result_fingerprint(issues),
        "issues": {key: groups[key] for key, _, _ in GROUPS},
        "false_alarms": false_alarms,
        "ai_suggestions": suggestions,
        "ai_review": {
            "likely_false_alarms": len(false_alarms),
            "scanner_counts": {key: sum(1 for i in issues if i["severity"] == key) for key, _, _ in GROUPS},
            "suggestions": len(suggestions),
        },
        "scan": {
            **meta,
            "policy_version": POLICY_VERSION,
            "ai": ai_result.get("llm"),
            "raw_findings": scan_result["counts"],
            "findings_explained": len(items),
            "tool_errors": scan_result["errors"],
            "apk_signature": scan_result.get("signature"),
            "app_code_files": app_map["app_code"]["java_files"],
            "total_code_files": app_map["stats"]["total_java_files"],
        },
        "warnings": warnings,
        "disclaimer": WEB_DISCLAIMER if target == "web" else DISCLAIMER,
    }


def result_fingerprint(issues: list[dict]) -> str:
    """Hash of everything the AI cannot influence. Two scans with the same fingerprint found
    exactly the same issues, at the same severities, in the same places."""
    core = [(i["rule_id"], i["severity"], i["occurrences"],
             [(loc["file"], loc["line"]) for loc in i["locations"]],
             list(i["more_locations"]), i["more_locations_count"]) for i in issues]
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()[:16]


def _merge_by_rule(items: dict, explained: dict) -> list[dict]:
    """Triage sends a few examples per rule; the report shows each rule once with all its places."""
    by_rule: dict[str, list[str]] = defaultdict(list)
    for fid, item in items.items():
        by_rule[item["rule_id"]].append(fid)

    issues = []
    for rule_id, fids in by_rule.items():
        first = items[fids[0]]  # carries occurrences / other_locations
        rule = rule_for(first)
        lead = explained[fids[0]]
        issue = {
            "severity": rule.severity,
            "rule_id": rule_id,
            "title": rule.title,
            "explanation": lead["explanation"],
            "fix": lead["fix"],
            "kind": first["category"],
            "kind_label": KIND_LABELS.get(first["category"], first["category"]),
            "standard": standard(rule),
            "found_by": f"{first['tool']} ({rule_id})",
            "explained_by": lead["explained_by"],
            "ai_review": _ai_review([explained[f] for f in fids]),
            "occurrences": first.get("occurrences", len(fids)),
            "locations": [_location(items[f]) for f in fids],
            "more_locations": first.get("other_locations", []),
            "more_locations_count": len(first.get("other_locations", [])) + first.get("more_locations", 0),
            "finding_ids": fids,
        }
        if preview := first.get("extra", {}).get("secret_preview"):
            issue["secret_preview"] = preview
        issues.append(issue)
    return issues


def is_false_alarm(issue: dict) -> bool:
    return (issue.get("ai_review") or {}).get("verdict") == "likely_false_alarm"


def _ai_review(examples: list[dict]) -> dict | None:
    """The AI's opinion on the examples it saw. "likely_false_alarm" (every example) moves the issue out of the
    counts into the report's false_alarms list; "partly_false_alarm" is shown next to a counted issue."""
    reviewed = [e for e in examples if e["explained_by"] == "ai"]
    if not reviewed:
        return None
    alarms = [e for e in reviewed if e["verdict"] == "likely_false_alarm"]
    if len(alarms) == len(reviewed):
        return {"verdict": "likely_false_alarm", "reason": alarms[0]["verdict_reason"]}
    if alarms:
        return {"verdict": "partly_false_alarm", "reason": alarms[0]["verdict_reason"]}
    return {"verdict": "confirmed", "reason": ""}


def _suggestion(bug: dict, items: dict) -> dict:
    source = items.get(bug.get("seen_in"))
    return {
        "suggested_severity": bug["severity"],
        "title": bug["title"],
        "explanation": bug["explanation"],
        "fix": bug["fix"],
        "confidence": bug["confidence"],
        "kind_label": KIND_LABELS["logic"],
        "found_by": "AI code review (not verified)",
        "locations": [_location(source)] if source else [],
    }


def _location(item: dict) -> dict:
    where = ".".join(x for x in (item.get("class"), item.get("method")) if x)
    return {"file": item["file"], "line": item["line"], "in": where or None}


def _first_location(issue: dict) -> tuple[str, int]:
    loc = issue["locations"][0] if issue["locations"] else {"file": "", "line": 0}
    return loc["file"], loc["line"]


# ------------------------------------------------------------------------------ text rendering

WIDTH = 88
ICONS = {"critical": "🔴", "warning": "🟠", "smell": "🟡"}
VERDICT_TEXT = {
    "likely_false_alarm": "AI review: probably a false alarm here",
    "partly_false_alarm": "AI review: some of these places are probably false alarms",
}


def render_text(report: dict) -> str:
    app, counts = report["app"], report["counts"]
    out: list[str] = []

    def para(text: str, indent: str = "") -> None:
        if text:
            out.append(textwrap.fill(text, WIDTH, initial_indent=indent, subsequent_indent=indent))

    def bullets(title: str, rows: list[str]) -> None:
        if rows:
            out.extend(["", title])
            for row in rows:
                out.append(textwrap.fill(row, WIDTH, initial_indent="  • ", subsequent_indent="    "))

    rule = "═" * WIDTH
    kind = "WEBSITE" if report.get("target") == "web" else "APP"
    out += [rule, f" {kind} SCAN REPORT · {app['package_name']}", rule]
    para(app["one_liner"])
    out += ["", "At a glance: " + " · ".join([
        f"{counts['critical']} critical", f"{counts['warning']} warnings", f"{counts['smell']} smells"])
        + f"   (result fingerprint {report['result_fingerprint']})"]
    if report.get("false_alarms"):
        fa = len(report["false_alarms"])
        out.append(f"Not counted: {fa} probable false alarm{'s' if fa != 1 else ''} (listed at the end)")
    if not report["scan"].get("ai"):
        out += ["", "AI explanations were not used for this report: the issues and severities are the same as",
                "with AI, and the descriptions are the scanner policy's standard wording."]

    if app["what_it_does"]:
        out += ["", "WHAT THIS APP DOES"]
        para(app["what_it_does"], "  ")
    bullets("HOW IT WORKS", app["how_it_works"])
    bullets("PERSONAL DATA IT CAN ACCESS", app["personal_data"])
    bullets("WHO IT TALKS TO", app["talks_to"])

    n = 0

    def issue_block(issue: dict) -> None:
        nonlocal n
        n += 1
        out.append("")
        out.append(textwrap.fill(f"{n}. {issue['title']}", WIDTH, subsequent_indent="   "))
        para(issue["explanation"], "   ")
        if issue.get("secret_preview"):
            out.append(f"   Secret (shortened): {issue['secret_preview']}")
        if issue["fix"]:
            out.append(textwrap.fill(f"How to fix: {issue['fix']}", WIDTH, initial_indent="   ",
                                     subsequent_indent="   "))
        review = issue["ai_review"]
        if review and review["verdict"] in VERDICT_TEXT:
            counted = "not counted above" if review["verdict"] == "likely_false_alarm" else \
                "still counted until a person checks it"
            out.append(textwrap.fill(f"{VERDICT_TEXT[review['verdict']]}: {review['reason']} ({counted})", WIDTH,
                                     initial_indent="   ", subsequent_indent="   "))
        out.append(f"   Where: {_where(issue)}")
        std = issue["standard"]
        out.append(f"   {issue['kind_label']} · {std['control']}" + (f" · {std['cwe']}" if std["cwe"] else "")
                   + f" · found by {issue['found_by']}")

    for key, label, advice in GROUPS:
        issues = report["issues"][key]
        out += ["", "─" * WIDTH, f"{ICONS[key]} {label.upper()} - {advice} ({len(issues)})", "─" * WIDTH]
        if not issues:
            out.append("  Nothing found.")
        for issue in issues:
            issue_block(issue)

    false_alarms = report.get("false_alarms") or []
    if false_alarms:
        out += ["", "─" * WIDTH, f"🔕 PROBABLY FALSE ALARMS - not counted above ({len(false_alarms)})", "─" * WIDTH]
        para("The scanner rules flagged these, but the AI read the code and judged them safe. Check them once "
             "before you ignore them.", "  ")
        for issue in false_alarms:
            issue_block(issue)

    suggestions = report["ai_suggestions"]
    if suggestions:
        out += ["", "─" * WIDTH, f"💡 AI SUGGESTIONS - not verified, not counted above ({len(suggestions)})", "─" * WIDTH]
        for s in suggestions:
            where = "; ".join(f"{loc['file'].removeprefix('sources/')}:{loc['line']}" for loc in s["locations"])
            out.append("")
            out.append(textwrap.fill(f"• {s['title']} (AI rates it {s['suggested_severity']}, confidence "
                                     f"{s['confidence']})", WIDTH, subsequent_indent="  "))
            para(s["explanation"], "  ")
            if s["fix"]:
                para(f"How to fix: {s['fix']}", "  ")
            if where:
                out.append(f"  Where: {where}")

    scan = report["scan"]
    out += ["", "═" * WIDTH, "ABOUT THIS SCAN"]
    ai = scan.get("ai")
    details = [
        (f"Website: {scan.get('url')}" if report.get("target") == "web" else f"File: {scan.get('apk_name') or '?'}")
        + (f" (sha256 {scan['apk_sha256'][:16]}…)" if scan.get("apk_sha256") else ""),
        (f"Found {scan['raw_findings']['total']} raw findings in {scan['app_code_files']:,} captured scripts and "
         f"the server's responses; {scan['findings_explained']} examples explained." if report.get("target") == "web" else
         f"Found {scan['raw_findings']['total']} raw findings in {scan['app_code_files']:,} of the app's own code "
         f"files ({scan['total_code_files']:,} including libraries); {scan['findings_explained']} examples explained."),
        f"Engine {scan.get('engine_version', '?')} · severity policy {scan['policy_version']} "
        f"({'OWASP ASVS 4.0' if report.get('target') == 'web' else 'OWASP MASVS v2'}, CWE)"
        + (f" · {_versions(scan['tool_versions'])}" if scan.get("tool_versions") else ""),
        f"Explained by: {ai['model']} via {ai['provider']}" if ai else "Explained by: scanner policy text (no AI)",
        f"Took {scan.get('seconds_total', '?')}s",
    ]
    if scan.get("apk_signature"):
        details.insert(1, _signature_line(scan["apk_signature"]))
    out += ["  " + d for d in details]
    for w in report["warnings"] + [f"tool error: {e}" for e in scan["tool_errors"]]:
        out.append(textwrap.fill(f"Note: {w}", WIDTH, initial_indent="  ", subsequent_indent="    "))
    out.append("")
    para(report["disclaimer"], "  ")
    return "\n".join(out)


def _signature_line(sig: dict) -> str:
    if not sig["verified"]:
        return f"Signature: NOT valid ({sig['checked_by']})"
    signer = sig["signers"][0] if sig["signers"] else {}
    return (f"Signature: valid, schemes {'+'.join(sig['schemes'])} · {signer.get('key_algorithm', '?')} "
            f"{signer.get('key_bits', '?')}-bit · certificate sha256 {signer.get('sha256', '?')[:16]}… ({sig['checked_by']})")


def _versions(tools: dict) -> str:
    return ", ".join(f"{name} {version}" for name, version in tools.items())


def _where(issue: dict) -> str:
    if not issue["locations"]:
        return "(see explanation)"
    parts = []
    for loc in issue["locations"][:3]:
        short = loc["file"].removeprefix("sources/")
        parts.append(f"{short}:{loc['line']}" + (f" ({loc['in']})" if loc["in"] else ""))
    text = "; ".join(parts)
    hidden = len(issue["locations"]) - 3
    more = issue["more_locations_count"] + max(0, hidden)
    return text + (f"; and {more} more place{'s' if more != 1 else ''}" if more else "")
