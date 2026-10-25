"""Runs every step: ingest -> map -> scan -> triage -> AI -> report."""

from __future__ import annotations

import copy
import hashlib
import os
import re
import subprocess
import time
from functools import lru_cache
from datetime import datetime, timezone
from pathlib import Path

from scanner.ai import LLMError, explain
from scanner.ingest import IngestError, load_unpacked, unpack_apk
from scanner.mapper import build_map
from scanner.rea import rea_available, rea_version
from scanner.rea_ingest import unpack_with_rea
from scanner.report import build_report
from scanner.scan import run_static_scan
from scanner.signing import APKSIG_VERSION
from scanner.triage import triage

# Bump when a code change can change which issues are found (rules have their own POLICY_VERSION).
ENGINE_VERSION = "0.4.0"
RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "android.yml"


def run_pipeline(target: str | Path, use_ai: bool = True, keep_files: bool = False,
                 apk_name: str | None = None, engine: str | None = None) -> dict:
    """Scan an .apk (or a folder from an earlier run) and return the report dict.

    engine is rea, jadx or auto; None uses APK_ENGINE. The decompiled code is deleted afterwards
    unless keep_files is set or a folder was passed in.
    """
    return finish_report(scan_apk(target, keep_files, apk_name, engine), use_ai)


def run_web_pipeline(url: str, use_ai: bool = True, keep_files: bool = False) -> dict:
    """Scan a website the person controls (see scanner/web.py for the safety checks)."""
    return finish_report(scan_web(url, keep_files), use_ai)


def scan_apk(target: str | Path, keep_files: bool = False, apk_name: str | None = None,
             engine: str | None = None) -> dict:
    """Every step that decides the findings. Returns the JSON-ready state finish_report() needs, so
    the AI step can run later (for example after payment) on exactly the same findings."""
    target = Path(target)
    started = time.monotonic()
    timings: dict[str, float] = {}

    def timed(name: str, fn, *args):
        t = time.monotonic()
        result = fn(*args)
        timings[name] = round(time.monotonic() - t, 1)
        return result

    reused = target.is_dir()
    engine_notes: list[str] = []
    unpacked = load_unpacked(target) if reused else timed("decompile", _unpack, target, engine_notes, engine)
    try:
        app_map = timed("map", build_map, unpacked)
        scan_result = timed("scan", run_static_scan, unpacked, app_map)
        triaged = timed("triage", triage, unpacked, scan_result)
        meta = {
            "apk_name": apk_name or target.name,
            "apk_sha256": _sha256(target) if target.is_file() else None,
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "seconds_by_step": timings,
            "engine_version": ENGINE_VERSION,
            "rules_sha256": hashlib.sha256(RULES_FILE.read_bytes()).hexdigest()[:16],
            "tool_versions": tool_versions(),
            "reverse_engineering": unpacked.provenance,
            "warnings": engine_notes + unpacked.warnings,
        }
        if keep_files or reused:
            meta["decompiled_folder"] = str(unpacked.work_dir)
        return {"target": "android", "app_map": app_map, "scan_result": scan_result, "triaged": triaged,
                "meta": meta, "scan_seconds": round(time.monotonic() - started, 1)}
    finally:
        if not keep_files and not reused:
            unpacked.cleanup()


def scan_web(url: str, keep_files: bool = False) -> dict:
    from scanner.web import WEB_RULES_FILE, scan_website

    started = time.monotonic()
    unpacked, web_map, scan_result = scan_website(url)
    timings = {"capture_and_scan": round(time.monotonic() - started, 1)}
    try:
        t = time.monotonic()
        triaged = triage(unpacked, scan_result)
        timings["triage"] = round(time.monotonic() - t, 1)
        meta = {
            "url": unpacked.provenance["final_url"],
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "seconds_by_step": timings,
            "engine_version": ENGINE_VERSION,
            "rules_sha256": hashlib.sha256(WEB_RULES_FILE.read_bytes()).hexdigest()[:16],
            "tool_versions": tool_versions(),
            "reverse_engineering": unpacked.provenance,
            "warnings": list(unpacked.warnings),
        }
        if keep_files:
            meta["decompiled_folder"] = str(unpacked.work_dir)
        return {"target": "web", "app_map": web_map, "scan_result": scan_result, "triaged": triaged,
                "meta": meta, "scan_seconds": round(time.monotonic() - started, 1)}
    finally:
        if not keep_files:
            unpacked.cleanup()


def finish_report(state: dict, use_ai: bool = True, language: str | None = None) -> dict:
    """AI wording (optional) + the report. Never changes which issues are found or their severity."""
    state = copy.deepcopy(state)  # build_report edits meta; a stored state must stay reusable
    meta, target = state["meta"], state["target"]
    ai_seconds = 0.0
    ai_result = None
    if use_ai:
        t = time.monotonic()
        try:
            ai_result = explain(state["app_map"], state["triaged"], target=target, language=language)
        except LLMError as e:
            meta["warnings"].append(f"AI explanations unavailable, showing the scanner policy's standard text instead: {e}")
        ai_seconds = round(time.monotonic() - t, 1)
        meta["seconds_by_step"]["ai"] = ai_seconds
    meta["seconds_total"] = round(state["scan_seconds"] + ai_seconds, 1)
    if target == "web":
        meta["target"] = "web"
    return build_report(state["app_map"], state["scan_result"], state["triaged"], ai_result, meta)


ENGINES = ("rea", "jadx", "auto")


def selected_engine(choice: str | None = None) -> str:
    """The engine for one scan: the caller's choice, else APK_ENGINE (default auto: REA when installed)."""
    choice = (choice or os.environ.get("APK_ENGINE", "auto")).strip().lower()
    if choice not in ENGINES:
        raise ValueError(f"engine must be rea, jadx or auto (got {choice!r})")
    if choice == "auto":
        return "rea" if rea_available() else "jadx"
    return choice


def _unpack(target: Path, notes: list[str], engine: str | None = None):
    if selected_engine(engine) == "rea":
        try:
            return unpack_with_rea(target)
        except IngestError as e:
            # A broken or oversized APK for REA still gets a full scan with the whole-app jadx engine.
            notes.append(f"Reverse-engineered with the fast engine (jadx) instead of the deep engine ({e}). Results are "
                         "complete, but line numbers differ from deep-engine scans of the same app.")
    return unpack_apk(target)


@lru_cache(maxsize=1)
def tool_versions() -> dict[str, str]:
    """Recorded in every report: a different tool version can legitimately change the findings."""
    versions = {}
    for name, cmd in (("jadx", ["jadx", "--version"]), ("semgrep", ["semgrep", "--version"]),
                      ("gitleaks", ["gitleaks", "version"])):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
            match = re.search(r"\d+\.\d+\.\d+", out)
            versions[name] = match.group(0) if match else "unknown"
        except (OSError, subprocess.SubprocessError):
            versions[name] = "unknown"
    if rea_available():
        versions["rea"] = rea_version()
    versions["apksig"] = APKSIG_VERSION
    return versions


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    import argparse
    import json

    from scanner.report import render_text

    parser = argparse.ArgumentParser(description="Scan an APK and print a plain-English report.")
    parser.add_argument("target", help="path to an .apk, a folder from an earlier run, or a website URL")
    parser.add_argument("--json", action="store_true", help="print the JSON report instead of text")
    parser.add_argument("--no-ai", action="store_true", help="skip the LLM; use scanner wording only")
    parser.add_argument("--keep", action="store_true", help="keep the decompiled code folder")
    parser.add_argument("--out", help="also save the JSON report to this file")
    args = parser.parse_args()

    if args.target.startswith(("http://", "https://")):
        report = run_web_pipeline(args.target, use_ai=not args.no_ai, keep_files=args.keep)
    else:
        report = run_pipeline(args.target, use_ai=not args.no_ai, keep_files=args.keep)
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2) if args.json else render_text(report))
