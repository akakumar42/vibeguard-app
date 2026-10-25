"""Step 1 (REA engine): reverse-engineer an APK with REA instead of a whole-app jadx run.

REA is the reverse-engineering layer:
  - package facts and the decoded manifest come from REA's `inspect_android_package` Evidence,
  - the class inventory (all classes, app and libraries) from `search_android_classes`,
  - the app's OWN code is decompiled method by method with `inspect_android_class` and
    `inspect_android_method`; library code is only counted, never decompiled,
  - Flutter apps are detected with `identify_flutter_build`.

Every method's source is written to sources/<package>/<Class>.java so the same bug engine (Semgrep,
Gitleaks, manifest checks) runs on it unchanged. Static initializers come back as smali and go into
<Class>.smali next to it, so secrets assigned there are still scanned.

XML resources (network security config, strings, library version files) are decoded with
`jadx --no-src` (resources only), because REA's resource decoder needs apktool and returns only
the manifest and strings.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scanner.ingest import IngestError, UnpackedApk, parse_manifest
from scanner.mapper import KNOWN_LIBRARIES, _app_prefixes, _under
from scanner.rea import ReaError, ReaSession, rea_version

REA_WORKERS = int(os.environ.get("REA_WORKERS", 3))  # each worker is a JVM with a ~2 GB heap
# Above this many app classes (e.g. heavily obfuscated apps) method-by-method is too slow; the
# pipeline falls back to the whole-app jadx engine.
REA_MAX_CLASSES = int(os.environ.get("REA_MAX_CLASSES", 1500))
JADX_TIMEOUT_SECONDS = 600
log = logging.getLogger("vibeguard.rea")


class TooLargeForRea(IngestError):
    pass


JADX_FILL_TIMEOUT = int(os.environ.get("JADX_FILL_TIMEOUT", 900))


def unpack_with_rea(apk_path: str | Path, jadx_bin: str = "jadx") -> UnpackedApk:
    apk = Path(apk_path).expanduser().resolve()
    if not apk.is_file():
        raise IngestError(f"APK not found: {apk}")
    work_dir = Path(tempfile.mkdtemp(prefix="vibeguard-"))
    out_dir = work_dir / "rea"
    sources_dir, resources_dir = out_dir / "sources", out_dir / "resources"
    sources_dir.mkdir(parents=True)
    started = time.monotonic()

    # Resources only - runs in parallel with REA.
    res_job = _start_resource_decode(jadx_bin, apk, out_dir)
    try:
        with ReaSession() as rea:
            pkg = rea.call("inspect_android_package", {"path": str(apk), "detail": "complete"})
            facts = pkg["normalized_result"]
            manifest_text = (facts.get("manifest") or {}).get("text") or ""
            inventory = rea.call("search_android_classes", {"path": str(apk), "query": ""})["normalized_result"]
            flutter = rea.call("identify_flutter_build", {"path": str(apk)})["normalized_result"]

        all_classes = list(dict.fromkeys(inventory.get("matches", [])))
        package_counts = _package_counts(all_classes)
        package_name = facts.get("package_name")
        app_prefixes = _app_prefixes(package_name, package_counts)
        app_classes = _app_classes(all_classes, app_prefixes)
        if len(app_classes) > REA_MAX_CLASSES:
            raise TooLargeForRea(f"{len(app_classes)} app classes is more than REA_MAX_CLASSES={REA_MAX_CLASSES}")

        decompiled = _decompile_classes(apk, app_classes)
        _write_sources(sources_dir, decompiled)
        # Methods REA could not decompile one by one: decompile their whole classes with jadx instead.
        rea_failed: dict[str, int] = defaultdict(int)
        for n, c in decompiled.items():
            rea_failed[_outer(n)] += sum(1 for m in c["methods"] if m["status"] == "failed")
        rea_failed = {cls: n for cls, n in rea_failed.items() if n}
        gap = _fill_gaps(jadx_bin, apk, decompiled, sources_dir, work_dir / "jadx-fill") if rea_failed else {}

        _finish_resource_decode(res_job)
        resources_dir.mkdir(exist_ok=True)
        manifest_path = resources_dir / "AndroidManifest.xml"
        if manifest_text:
            manifest_path.write_text(manifest_text)  # REA's decoded manifest is the one we analyse
        if not manifest_path.is_file():
            raise IngestError("The deep engine returned no manifest and the resource decode produced none")
        manifest_package, permissions = parse_manifest(manifest_path)
    except (ReaError, KeyError, OSError) as e:
        _kill(res_job)
        shutil.rmtree(work_dir, ignore_errors=True)
        raise IngestError(f"The deep engine could not analyse this APK: {e}") from e
    except IngestError:
        _kill(res_job)
        shutil.rmtree(work_dir, ignore_errors=True)
        raise

    methods = [m for c in decompiled.values() for m in c["methods"]]
    filled = gap.get("filled", {})  # outer class -> methods jadx still could not decompile
    still_missing = {cls: (filled[cls] if cls in filled else n) for cls, n in rea_failed.items()}
    still_missing = {cls: n for cls, n in still_missing.items() if n}
    provenance = {
        "engine": "rea",
        "rea_version": rea_version(),
        "decompiler": f"{facts['engine']['name']} {facts['engine']['version']}",
        "decompiler_sha256": facts["engine"].get("artifact_sha256"),
        "package_evidence_id": pkg.get("evidence_id"),
        "classes_total": len(all_classes),
        "app_classes_decompiled": len(decompiled),
        "methods_decompiled": sum(1 for m in methods if m["status"] == "java"),
        "methods_as_smali": sum(1 for m in methods if m["status"] == "smali"),
        "methods_total": len(methods),
        "methods_failed": sum(1 for m in methods if m["status"] == "failed"),
        "classes_completed_with_jadx": sorted(filled),
        "methods_not_decompiled": sum(still_missing.values()),
        "classes_not_fully_decompiled": sorted(still_missing),
        "flutter_detected": bool(flutter.get("flutter_detected")),
        "seconds": round(time.monotonic() - started, 1),
    }
    warnings = []
    if provenance["flutter_detected"]:
        warnings.append("This is a Flutter app: most of its logic is compiled Dart code, which this scan "
                        "cannot read, so only the Android parts were checked.")
    provenance["coverage"] = _coverage_summary(provenance)
    warnings += _coverage_notes(provenance, gap.get("error"))

    (work_dir / "engine.json").write_text(json.dumps(
        {"package_counts": package_counts, "provenance": provenance, "warnings": warnings}, indent=1))
    return UnpackedApk(
        apk_path=apk,
        work_dir=work_dir,
        sources_dir=sources_dir,
        resources_dir=resources_dir,
        manifest_path=manifest_path,
        package_name=manifest_package or package_name,
        permissions=permissions,
        package_counts=package_counts,
        provenance=provenance,
        warnings=warnings,
    )


# ------------------------------------------------------------------------------ closing the gaps with jadx

def _fill_gaps(jadx_bin: str, apk: Path, decompiled: dict[str, dict], sources_dir: Path, out: Path) -> dict:
    """Decompile the app with jadx (code only) and, for each file REA left incomplete, use jadx's files for the
    same classes instead, when they leave fewer methods out. REA's file is then removed, so no code is
    scanned twice. Returns {"filled": {class: methods jadx could not decompile either}} or {"error": reason}."""
    try:
        subprocess.run([jadx_bin, "--no-res", "--output-dir", str(out), str(apk)], capture_output=True, text=True,
                       timeout=JADX_FILL_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as e:
        return {"error": f"the fast engine could not run ({e})"}
    jadx_sources = out / "sources"
    groups: dict[str, list[str]] = defaultdict(list)  # REA output file (outer name) -> classes in it
    for name in decompiled:
        groups[_outer(name)].append(name)
    filled: dict[str, int] = {}
    for outer, members in sorted(groups.items()):
        rea_missing = sum(1 for n in members for m in decompiled[n]["methods"] if m["status"] == "failed")
        if not rea_missing:
            continue
        files = [_jadx_file(jadx_sources, n) for n in members]
        if any(f is None for f in files):
            continue  # jadx has no file for one of these classes; keep REA's
        files = sorted(set(files))
        # jadx writes this comment in place of a method body it could not decompile.
        jadx_missing = sum(f.read_text(errors="replace").count("Method dump skipped") for f in files)
        if jadx_missing >= rea_missing:
            continue  # REA's version is at least as complete; keep it
        rea_file = sources_dir / _rel_path(outer)
        rea_file.unlink(missing_ok=True)
        rea_file.with_suffix(".smali").unlink(missing_ok=True)
        for f in files:
            dest = sources_dir / f.relative_to(jadx_sources)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, dest)
            dest.with_suffix(".smali").unlink(missing_ok=True)
        filled[outer] = jadx_missing
    shutil.rmtree(out, ignore_errors=True)
    return {"filled": filled}


def _rel_path(outer: str) -> Path:
    pkg, _, simple = outer.rpartition(".")
    return Path(*pkg.split("."), f"{simple}.java") if pkg else Path(f"{simple}.java")


def _jadx_file(jadx_sources: Path, name: str) -> Path | None:
    """The jadx file that holds a class: "a.B$c$d" may be its own file (Kotlin's ComposableSingletons$XKt) or
    nested in B$c.java / B.java; "a.B.AnonymousClass1" (an inner-class alias) lives in B.java."""
    parts = name.split(".")
    first = next((i for i, p in enumerate(parts) if p[:1].isupper()), len(parts) - 1)
    package, top = parts[:first], parts[first]
    candidate = top
    while True:
        path = jadx_sources.joinpath(*package, f"{candidate}.java")
        if path.is_file():
            return path
        if "$" not in candidate:
            return None
        candidate = candidate.rsplit("$", 1)[0]


def _coverage_summary(p: dict) -> str:
    """One line for the report's technical footer."""
    total, failed, missing = p["methods_total"], p["methods_failed"], p["methods_not_decompiled"]
    via_jadx = failed - missing if p["classes_completed_with_jadx"] else 0
    head = f"All {total:,} methods checked" if not missing else f"{total - missing:,} of {total:,} methods checked"
    return head + (f" ({via_jadx} completed with the fast engine)" if via_jadx else "")


def _coverage_notes(p: dict, gap_error: str | None) -> list[str]:
    """A note for the top of the report, only when some code really was not checked."""
    total, missing = p["methods_total"], p["methods_not_decompiled"]
    pct = lambda n: f"{100 * n / total:.1f}%" if total else "?"  # noqa: E731
    notes = []
    if missing:
        names = [c.rsplit(".", 1)[-1] for c in p["classes_not_fully_decompiled"]]
        shown = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
        why = f" ({gap_error})" if gap_error else ""
        notes.append(f"{missing} of {total:,} methods ({pct(missing)}) could not be decompiled{why} and were not "
                     f"checked, in {len(names)} class{'es' if len(names) != 1 else ''}: {shown}.")
    return notes


# ------------------------------------------------------------------------------ class inventory

def _outer(name: str) -> str:
    return name.split("$", 1)[0]


def _package_counts(class_names: list[str]) -> Counter:
    """Top-level classes per package - the same unit as jadx's one .java file per class."""
    counts: Counter = Counter()
    for name in {_outer(n) for n in class_names}:
        counts[name.rpartition(".")[0]] += 1
    return counts


def _app_classes(class_names: list[str], app_prefixes: list[str]) -> list[str]:
    def is_app(name: str) -> bool:
        pkg = name.rpartition(".")[0]
        if app_prefixes:
            return any(_under(pkg, p) for p in app_prefixes)
        return not any(_under(pkg, p) for p in KNOWN_LIBRARIES)

    # Compiler-made helper classes ($$ExternalSynthetic...) hold no code the developer wrote.
    return sorted(n for n in class_names if is_app(n) and "$$ExternalSynthetic" not in n)


# ------------------------------------------------------------------------------ decompilation

def _decompile_classes(apk: Path, class_names: list[str]) -> dict[str, dict]:
    """Decompile every method of every class, across REA_WORKERS sessions. The result does not
    depend on scheduling: each class is processed independently and assembled in sorted order."""
    workers = max(1, min(REA_WORKERS, len(class_names) // 25 + 1))
    chunks = [class_names[i::workers] for i in range(workers)]
    results: dict[str, dict] = {}
    lock = threading.Lock()

    done = [0]
    started = time.monotonic()

    def run(chunk: list[str]) -> None:
        with ReaSession() as rea:
            for name in chunk:
                classes = _decompile_class_tree(rea, apk, name)
                with lock:
                    results.update(classes)
                    done[0] += 1
                    if done[0] % 25 == 0:
                        methods = sum(len(c["methods"]) for c in results.values())
                        log.info("REA: %d/%d classes, %d methods, %.0fs", done[0], len(class_names), methods,
                                 time.monotonic() - started)

    with ThreadPoolExecutor(workers) as pool:
        for future in [pool.submit(run, c) for c in chunks if c]:
            future.result()
    return dict(sorted(results.items()))


def _decompile_class_tree(rea: ReaSession, apk: Path, name: str, depth: int = 0) -> dict[str, dict]:
    try:
        inv = rea.call("inspect_android_class", {"path": str(apk), "class_name": name})["normalized_result"]
    except ReaError:
        return {}
    cls = {"name": name, "fields": inv.get("fields", []), "methods": []}
    for m in inv.get("methods", []):
        cls["methods"].append(_decompile_method(rea, apk, name, m))
    found = {name: cls}
    for inner in inv.get("inner_classes", []) if depth < 5 else []:
        inner_name = inner.get("name") if isinstance(inner, dict) else str(inner)
        if inner_name and "$$ExternalSynthetic" not in inner_name:
            found.update(_decompile_class_tree(rea, apk, inner_name, depth + 1))
    return found


def _decompile_method(rea: ReaSession, apk: Path, class_name: str, m: dict) -> dict:
    entry = {"name": m.get("name"), "signature": m.get("reported_signature", m.get("name")), "status": "failed", "text": ""}
    try:
        r = rea.call("inspect_android_method", {"path": str(apk), "class_name": class_name,
                                                "method_name": m["name"], "overload_index": m.get("overload_index", 0)})
    except (ReaError, KeyError):
        return entry
    nr = r["normalized_result"]
    text = (nr.get("source") or {}).get("text") or ""
    if nr.get("body_status") == "not_available":
        entry["status"] = "no_body"  # abstract / native: nothing to scan
    elif nr.get("representation") == "java" and not nr.get("fell_back"):
        entry["status"] = "java"
    else:
        entry["status"] = "smali"
    entry["text"] = text
    entry["evidence_id"] = r.get("evidence_id")
    return entry


# ------------------------------------------------------------------------------ writing sources

def _write_sources(sources_dir: Path, classes: dict[str, dict]) -> None:
    """One .java file per top-level class with its methods (and inner classes) in REA's order."""
    by_file: dict[str, list[dict]] = defaultdict(list)
    for name, cls in classes.items():
        by_file[_outer(name)].append(cls)

    for outer, members in sorted(by_file.items()):
        pkg, _, simple = outer.rpartition(".")
        folder = sources_dir.joinpath(*pkg.split(".")) if pkg else sources_dir
        folder.mkdir(parents=True, exist_ok=True)
        java = [f"package {pkg};", "", "// Reconstructed method by method by the VibeGuard deep engine.", ""] if pkg else []
        smali = []
        for cls in members:
            label = cls["name"].rpartition(".")[2]
            header = label.rsplit("$", 1)[-1] if "$" in label else label
            java.append(f"// class {cls['name']}")
            java.append(f"class {header} {{")
            for f in cls["fields"]:
                java.append(f"    {f.get('reported_type', 'Object')} {f.get('name', '_')};")
            for m in cls["methods"]:
                if m["status"] == "java" and m["text"].strip():
                    java.append("")
                    java.extend(m["text"].rstrip("\n").splitlines())
                elif m["status"] == "smali" and m["text"].strip():
                    smali += [f"# {cls['name']}.{m['signature']}", m["text"].rstrip("\n"), ""]
                elif m["status"] == "failed":
                    java.append(f"    // The deep engine could not decompile {m['signature']}")
            java += ["}", ""]
        (folder / f"{simple}.java").write_text("\n".join(java))
        if smali:
            (folder / f"{simple}.smali").write_text("\n".join(smali))


# ------------------------------------------------------------------------------ resources (jadx --no-src)

def _start_resource_decode(jadx_bin: str, apk: Path, out_dir: Path) -> subprocess.Popen | None:
    if shutil.which(jadx_bin) is None:
        return None
    return subprocess.Popen([jadx_bin, "--no-src", "--output-dir", str(out_dir), str(apk)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _finish_resource_decode(job: subprocess.Popen | None) -> None:
    if job is None:
        return
    try:
        job.wait(timeout=JADX_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        job.kill()


def _kill(job: subprocess.Popen | None) -> None:
    if job is not None and job.poll() is None:
        job.kill()
