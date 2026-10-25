"""The paid report as one self-contained HTML file (download), in English or German.

The page is written in English and, for German, every fixed sentence is looked up in the same dictionary the
browser uses (scanner/i18n_de.py): first as an exact sentence, then against the patterns. Text that is not in
the dictionary (file paths, code, AI-written text in another language) is left as it is, as on the website.
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from functools import lru_cache

from scanner.report import GROUPS

ICONS = {"critical": "🔴", "warning": "🟠", "smell": "🟡"}
SEVERITY_LABEL = {"critical": "Critical", "warning": "Warning", "smell": "Smell"}
REVIEW_TEXT = {
    "likely_false_alarm": "AI review: probably a false alarm here:",
    "partly_false_alarm": "AI review: some of these places are probably false alarms:",
}
LANGUAGES = ("en", "de")


@lru_cache(maxsize=1)
def _german() -> tuple[dict, list, list]:
    from scanner import i18n_de

    patterns = []
    for pattern, to in i18n_de.PATTERNS:
        try:
            patterns.append((re.compile(pattern, re.S), to))
        except re.error:  # written for the browser's RegExp; skip one Python can't read
            continue
    return i18n_de.exact(), patterns, i18n_de.TERMS


def german(text: str) -> str:
    """Same lookup as translate() in static/i18n.js."""
    exact, patterns, terms = _german()
    key = " ".join(text.split())
    if not key or not re.search(r"[A-Za-z]", key):
        return text
    if key in exact:
        return exact[key]

    def part(value: str | None) -> str:
        if value is None:
            return ""
        if value in exact:
            return exact[value]
        for en, de in terms:
            value = value.replace(en, de)
        return value

    for regex, to in patterns:
        m = regex.fullmatch(key)
        if m:
            return re.sub(r"\$(\d)", lambda g: part(m.group(int(g.group(1)))), to)
    return text


def render_html(report: dict, language: str = "en", paid_plan: str | None = None) -> str:
    de = language == "de"
    t = german if de else (lambda s: s)

    def e(text) -> str:
        return html.escape(str(text), quote=True)

    def te(text) -> str:
        return e(t(text))

    app, counts, scan = report["app"], report["counts"], report["scan"]
    web = report.get("target") == "web"
    false_alarms = report.get("false_alarms") or []
    scanned = scan.get("url") if web else (scan.get("apk_name") or app["package_name"])
    out: list[str] = []
    w = out.append

    # ---- header and counts
    w(f'<header><p class="eyebrow">{te("Website scan" if web else "App scan")} · {e(scanned)}</p>')
    w(f"<h1>{te(app['one_liner'])}</h1><p class=\"where\">{e(app['package_name'])}</p>")
    w('<div class="glance">')
    for key, label in (("critical", "Critical"), ("warning", "Warnings"), ("smell", "Code smells")):
        w(f'<div class="tile {key}"><div class="n">{counts[key]}</div><div class="l">{te(label)}</div></div>')
    w("</div>")
    if false_alarms:
        n = len(false_alarms)
        w(f'<p class="muted">{te("Not counted: 1 probable false alarm (listed below the issues)" if n == 1 else f"Not counted: {n} probable false alarms (listed below the issues)")}</p>')
    fingerprint = report["result_fingerprint"]
    w(f'<p class="meta">{te(f"Result fingerprint {fingerprint} · the same app always gives the same issues and fingerprint")}</p>')
    if not scan.get("ai"):
        w(f'<p class="banner"><strong>{te("AI explanations were not used for this report.")}</strong> '
          f'{te("The issues and their severity are exactly the same as with AI - they come from fixed scanner rules. The descriptions below are the rules' standard wording instead of explanations written for your code.")}</p>')
    w("</header>")

    # ---- how it works
    if app.get("what_it_does") or app.get("how_it_works"):
        w(f'<section class="card"><h2>{te("How this website works" if web else "How this app works")}</h2>')
        if app.get("what_it_does"):
            w(f"<p>{te(app['what_it_does'])}</p>")
        for title, items in (("What it does, step by step", app.get("how_it_works")),
                             ("Personal data it can access", app.get("personal_data")),
                             ("Who it talks to", app.get("talks_to"))):
            if items:
                w(f"<h3>{te(title)}</h3><ul>" + "".join(f"<li>{te(x)}</li>" for x in items) + "</ul>")
        w("</section>")

    # ---- issues
    def issue_card(issue: dict) -> None:
        sev = issue["severity"]
        w(f'<article class="issue {sev}"><div class="title"><h4>{te(issue["title"])}</h4>'
          f'<span class="sev {sev}">{te(SEVERITY_LABEL[sev])}</span></div>')
        w(f"<p>{te(issue['explanation'])}</p>")
        if issue.get("secret_preview"):
            w(f'<p class="meta">{te("Secret (shortened):")} <code>{e(issue["secret_preview"])}</code></p>')
        if issue.get("fix"):
            w(f'<div class="fix"><strong>{te("How to fix")}</strong><p>{te(issue["fix"])}</p></div>')
        review = issue.get("ai_review") or {}
        if review.get("verdict") in REVIEW_TEXT:
            note = "Not counted." if review["verdict"] == "likely_false_alarm" else "Still counted until a person checks it."
            w(f'<p class="review"><strong>{te(REVIEW_TEXT[review["verdict"]])}</strong> {te(review.get("reason") or "")} '
              f'<span class="muted">{te(note)}</span></p>')
        std = issue["standard"]  # one sentence, built as the website builds it, so the same pattern translates it
        meta = " · ".join(x for x in (issue["kind_label"], std.get("control"), std.get("cwe"),
                                      f"found by {issue['found_by']}") if x)
        if issue["occurrences"] > 1:
            meta += f" · {issue['occurrences']} places"
        w(f'<p class="meta">{te(meta)}</p>')
        where = [f"{loc['file'].removeprefix('sources/')}:{loc['line']}" + (f" ({loc['in']})" if loc.get("in") else "")
                 for loc in issue["locations"]]
        more = issue.get("more_locations_count", 0)
        if where:
            w(f'<details open><summary>{te("Where in the code")}</summary><ul class="where">'
              + "".join(f"<li>{e(x)}</li>" for x in where)
              + (f"<li>{te(f'and {more} more place' + ('s' if more != 1 else ''))}</li>" if more else "")
              + "</ul></details>")
        w("</article>")

    for key, label, advice in GROUPS:
        issues = report["issues"][key]
        w(f'<section><div class="group-head"><h2>{ICONS[key]} {te(label)}</h2>'
          f'<span class="muted">{te(advice)} · {len(issues)}</span></div>')
        if not issues:
            w(f'<p class="muted">{te("Nothing found.")}</p>')
        for issue in issues:
            issue_card(issue)
        w("</section>")

    if false_alarms:
        w(f'<section><div class="group-head"><h2>{te("🔕 Probably false alarms")}</h2>'
          f'<span class="muted">{te(f"Not counted above · {len(false_alarms)}")}</span></div>'
          f'<p class="muted">{te("The scanner rules flagged these, but the AI read the code and judged them safe. Check them once before you ignore them.")}</p>')
        for issue in false_alarms:
            issue_card(issue)
        w("</section>")

    suggestions = report.get("ai_suggestions") or []
    if suggestions:
        w(f'<section><div class="group-head"><h2>{te("💡 AI suggestions")}</h2>'
          f'<span class="muted">{te(f"Not verified · not counted above · {len(suggestions)}")}</span></div>'
          f'<p class="muted">{te("Possible problems the AI noticed while reading the code. No scanner rule confirms them, so check them before acting.")}</p>')
        for s in suggestions:
            where = ", ".join(f"{loc['file'].removeprefix('sources/')}:{loc['line']}" for loc in s["locations"])
            w(f'<article class="issue suggestion"><h4>{te(s["title"])}</h4><p>{te(s["explanation"])}</p>')
            if s.get("fix"):
                w(f'<div class="fix"><strong>{te("Possible fix")}</strong><p>{te(s["fix"])}</p></div>')
            meta = f"{s['found_by']} · AI rates it {s['suggested_severity']} · confidence {s['confidence']}"
            w(f'<p class="meta">{te(meta + (" · " + where if where else ""))}</p></article>')
        w("</section>")

    # ---- about the scan
    raw = (scan.get("raw_findings") or {}).get("total", "?")
    w(f'<section class="card about"><h2>{te("About this scan")}</h2><ul>')
    w(f"<li>{te('Website' if web else 'File')}: {e(scanned)}"
      + (f" (sha256 {e(scan['apk_sha256'][:16])}…)" if scan.get("apk_sha256") else "") + "</li>")
    if scan.get("scanned_at"):
        w(f"<li>{te('Scanned at')}: {e(scan['scanned_at'])}</li>")
    w(f"<li>{te('Raw findings')}: {e(raw)}</li>")
    if scan.get("ai"):
        w(f"<li>{te('Explained by')}: {e(scan['ai'].get('model'))} ({e(scan['ai'].get('provider'))})</li>")
    else:
        w(f"<li>{te('Explained by')}: {te('scanner rule text (no AI)')}</li>")
    w(f"<li>{te('Engine')} {e(scan.get('engine_version', '?'))} · {te('severity policy')} {e(scan.get('policy_version'))} "
      f"({'OWASP ASVS 4.0' if web else 'OWASP MASVS v2'}, CWE)</li>")
    if scan.get("tool_versions"):
        w(f"<li>{te('Tools')}: {e(', '.join(f'{k} {v}' for k, v in scan['tool_versions'].items()))}</li>")
    sig = scan.get("apk_signature")
    if sig:
        w(f"<li>{te('Signature')}: {te('valid' if sig.get('verified') else 'not valid')} ({e(sig.get('checked_by'))})</li>")
    w("</ul>")
    for note in report.get("warnings") or []:
        w(f'<p class="muted">{te("Note:")} {te(note)}</p>')
    w(f'<p class="muted">{te(report["disclaimer"])}</p></section>')

    made = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    w(f'<footer>{te("Report downloaded from VibeGuard")} · {e(made)}'
      + (f" · {e(t(paid_plan))}" if paid_plan else "") + "</footer>")

    title = f"VibeGuard · {t('Security report')} · {app['package_name']}"
    return (f'<!doctype html>\n<html lang="{"de" if de else "en"}">\n<head>\n<meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">\n<title>{e(title)}</title>\n'
            f"<style>{CSS}</style>\n</head>\n<body>\n<main>\n"
            f'<p class="brand">VibeGuard · {te("Security report")}</p>\n' + "\n".join(out) + "\n</main>\n</body>\n</html>\n")


CSS = """
:root { --bg: #f5f7fc; --card: #fff; --text: #0d1222; --muted: #5a6277; --border: #e3e7f0; --code-bg: #f3f5fb;
  --accent: #1f4fe0; --accent-soft: #e9efff; --critical: #d0342c; --critical-bg: #fde9e8; --warning: #b36b00; --warning-bg: #fff3dc;
  --smell: #5b50d6; --smell-bg: #eeecff; color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; background: radial-gradient(rgba(31,79,224,.08) 1px, transparent 1.2px) 0 0 / 22px 22px, var(--bg); color: var(--text);
  font: 15px/1.55 Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
h1, h2, h4 { font-family: "Inter Tight", Inter, -apple-system, "Segoe UI", sans-serif; letter-spacing: -.02em; }
main { max-width: 860px; margin: 0 auto; padding: 28px 16px 48px; }
.brand { font: 600 12px ui-monospace, Menlo, monospace; text-transform: uppercase; letter-spacing: .08em; color: var(--accent); margin: 0 0 18px; }
header, .card { background: var(--card); border: 1px solid var(--border); border-radius: 20px; padding: 22px 24px; margin-bottom: 18px;
  box-shadow: 0 1px 2px rgba(13,18,34,.04), 0 10px 30px rgba(31,79,224,.07); }
h1 { font-size: 26px; line-height: 1.2; margin: 8px 0 4px; font-weight: 800; } h2 { font-size: 18px; margin: 0; } h3 { font-size: 14px; margin: 16px 0 6px; }
h4 { font-size: 15px; margin: 0; }
.eyebrow, .muted, .meta { color: var(--muted); font-size: 13px; } .eyebrow { margin: 0; }
.where, .meta, code { font-family: ui-monospace, Menlo, monospace; font-size: 12.5px; overflow-wrap: anywhere; }
.where { color: var(--muted); margin: 0 0 14px; padding-left: 18px; }
.glance { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 14px 0; }
.tile { border: 1px solid var(--border); border-radius: 16px; padding: 14px 16px; }
.tile.critical { background: var(--critical-bg); border-color: transparent; }
.tile.warning { background: var(--warning-bg); border-color: transparent; }
.tile.smell { background: var(--smell-bg); border-color: transparent; }
.tile .n { font-size: 28px; font-weight: 800; line-height: 1; } .tile .l { font-size: 11.5px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin-top: 6px; }
.tile.critical .n { color: var(--critical); } .tile.warning .n { color: var(--warning); } .tile.smell .n { color: var(--smell); }
.banner { background: var(--warning-bg); border-radius: 10px; padding: 10px 12px; font-size: 13.5px; }
.group-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap; margin: 26px 0 10px; }
.issue { background: var(--card); border: 1px solid var(--border); border-left: 4px solid var(--border); border-radius: 16px; padding: 16px 18px; margin: 0 0 12px; break-inside: avoid; }
.issue.critical { border-left-color: var(--critical); } .issue.warning { border-left-color: var(--warning); } .issue.smell { border-left-color: var(--smell); }
.issue.suggestion { border-left-color: var(--accent); }
.title { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }
.sev { font: 600 11px Inter, -apple-system, sans-serif; border-radius: 999px; padding: 3px 9px; white-space: nowrap; }
.sev.critical { color: var(--critical); background: var(--critical-bg); } .sev.warning { color: var(--warning); background: var(--warning-bg); }
.sev.smell { color: var(--smell); background: var(--smell-bg); }
.fix { background: var(--accent-soft); border-radius: 12px; padding: 10px 12px; margin: 10px 0; font-size: 14px; } .fix p { margin: 4px 0 0; }
.review { background: var(--warning-bg); border-radius: 10px; padding: 8px 12px; font-size: 13.5px; }
details summary { cursor: pointer; color: var(--muted); font-size: 13px; }
.about ul { padding-left: 18px; font-size: 13.5px; }
footer { color: var(--muted); font-size: 12px; text-align: center; margin-top: 28px; }
@media print { body { background: #fff; } main { padding: 0; } header, .card, .issue { border-color: #ccc; } }
@media (max-width: 520px) { .glance { gap: 6px; } .tile { padding: 10px; } .tile .n { font-size: 22px; } }
"""
