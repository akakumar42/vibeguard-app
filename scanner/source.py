"""Scanning an uploaded Android source project (a .zip) with the same rules as the APK scan.

Used by the "Bug fixing" tier: the APK scan finds problems in the decompiled app, but fixes have to be
made in the developer's own source code, so the source is scanned directly.

Java files are checked with rules/android.yml and Kotlin files with rules/android-kotlin.yml (same rule
ids, so the same severity policy); JavaScript/TypeScript files (web apps) with rules/web.yml, the rules the
website scan uses. Gradle .kts build scripts are listed but not checked.
"""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from scanner.ingest import UnpackedApk
from scanner.policy import rule_for
from scanner.scan import RULES_FILE, Finding, ScanError, _check_manifest, _run, run_gitleaks

KOTLIN_RULES_FILE = RULES_FILE.parent / "android-kotlin.yml"
WEB_RULES_FILE = RULES_FILE.parent / "web.yml"
WEB_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
MAX_WEB_FILE_BYTES = 1024 * 1024  # anything bigger is a bundle or generated file, not hand-written code

MAX_ZIP_BYTES = 50 * 1024 * 1024
MAX_UNPACKED_BYTES = 300 * 1024 * 1024
MAX_FILES = 20_000
# Folders that hold generated or downloaded code, not the developer's own.
SKIP_DIRS = {"build", ".gradle", ".idea", ".git", "node_modules", ".cxx", ".externalNativeBuild", "generated",
             "intermediates", "__MACOSX",
             # web build output and tool caches
             ".next", ".nuxt", ".svelte-kit", ".vercel", ".netlify", ".turbo", ".expo", "dist", "out", "coverage",
             ".cache", ".parcel-cache", "bower_components"}


# Never unpacked or stored: signing keys and local secrets have nothing to scan and must not leave the
# developer's machine. (Leaked keys *inside code* are still found by the secret scan.)
SENSITIVE_SUFFIXES = (".jks", ".keystore", ".p12", ".pfx", ".pem", ".key", ".der", ".p8", ".mobileprovision")
SENSITIVE_NAMES = {"local.properties", "keystore.properties", "signing.properties", "secrets.properties",
                   "gradle.properties.local", "credentials.json", "service-account.json"}


def is_sensitive(name: str) -> bool:
    base = name.rsplit("/", 1)[-1].lower()
    return base.endswith(SENSITIVE_SUFFIXES) or base in SENSITIVE_NAMES or base == ".env" or base.startswith(".env.")


class SourceError(Exception):
    """The upload is not a usable source project."""


@dataclass
class SourceScan:
    root: Path
    findings: list[dict]
    java_files: list[str]
    kotlin_files: list[str]
    manifests: list[str]
    not_checked: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    web_files: list[str] = field(default_factory=list)


def unpack_source_zip(zip_path: Path, dest: Path) -> tuple[Path, list[str]]:
    """Extract safely: no absolute paths, no '..', no symlinks, and size/count limits (zip bombs).
    Returns (project root, sensitive files that were left out)."""
    if zip_path.stat().st_size > MAX_ZIP_BYTES:
        raise SourceError(f"The zip is larger than {MAX_ZIP_BYTES // (1024 * 1024)} MB.")
    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        raise SourceError("This file is not a valid .zip archive.") from None
    with archive:
        members = archive.infolist()
        if len(members) > MAX_FILES:
            raise SourceError(f"The zip has more than {MAX_FILES:,} files. Leave out build folders and try again.")
        if sum(m.file_size for m in members) > MAX_UNPACKED_BYTES:
            raise SourceError("The zip is too large once unpacked. Leave out build folders and try again.")
        dest.mkdir(parents=True, exist_ok=True)
        root = dest.resolve()
        skipped: list[str] = []
        for m in members:
            name = m.filename.replace("\\", "/")
            parts = [p for p in name.split("/") if p not in ("", ".")]
            if name.startswith("/") or ".." in parts or (parts and ":" in parts[0]):
                raise SourceError(f"The zip contains an unsafe path: {name[:120]}")
            if stat.S_ISLNK(m.external_attr >> 16):
                continue  # symlinks could point outside the project
            if not parts or any(p in SKIP_DIRS for p in parts[:-1]):
                continue
            if not m.is_dir() and is_sensitive(name):
                skipped.append("/".join(parts))
                continue
            target = (root / Path(*parts)).resolve()
            if root not in target.parents:
                raise SourceError(f"The zip contains an unsafe path: {name[:120]}")
            if m.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(m) as src, target.open("wb") as out:
                out.write(src.read())
    project = _project_root(root)
    prefix = project.relative_to(root).as_posix()
    left_out = sorted(s[len(prefix) + 1:] if prefix != "." and s.startswith(prefix + "/") else s for s in skipped)
    return project, left_out


def _project_root(root: Path) -> Path:
    """Zips made by 'compress folder' wrap everything in one top folder; use it as the root."""
    entries = [p for p in root.iterdir() if not p.name.startswith(".")]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return root


def project_files(root: Path, suffix: str) -> list[Path]:
    return sorted(p for p in root.rglob(f"*{suffix}")
                  if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]))


def web_files(root: Path) -> list[Path]:
    """Hand-written JavaScript/TypeScript: no minified bundles, type declarations or huge generated files."""
    files = []
    for suffix in WEB_SUFFIXES:
        for p in project_files(root, suffix):
            if p.name.endswith((".min.js", ".d.ts", ".bundle.js")) or p.stat().st_size > MAX_WEB_FILE_BYTES:
                continue
            files.append(p)
    return sorted(files)


def scan_source(root: Path, gitleaks: bool = True) -> SourceScan:
    java = project_files(root, ".java")
    kotlin = project_files(root, ".kt")
    scripts = project_files(root, ".kts")
    manifests = [p for p in project_files(root, ".xml") if p.name == "AndroidManifest.xml"]
    web = web_files(root)
    if not java and not kotlin and not manifests and not web:
        raise SourceError("No supported source code found. VibeGuard checks Android projects (.java, .kt, "
                          "AndroidManifest.xml) and web projects (.js, .jsx, .ts, .tsx).")
    web_only = bool(web) and not (java or kotlin or manifests)

    findings: list[Finding] = []
    errors: list[str] = []
    code_findings, parse_errors = semgrep_files(java + kotlin + web, root)
    findings += code_findings
    for manifest in manifests:
        findings += manifest_findings(manifest, root)
    if gitleaks:
        try:
            with tempfile.TemporaryDirectory(prefix="vibeguard-gitleaks-") as tmp:
                secrets = run_gitleaks(root, [root], Path(tmp) / "gitleaks.json")
            if web:
                # Same handling as the website scan: a Supabase anon key is public by design, a service_role key
                # is an admin key; secrets in a web project are web secrets (OWASP ASVS).
                from scanner.web import _classify_secrets
                secrets = _classify_secrets(secrets)
                if web_only:
                    for f in secrets:
                        f.extra["target"] = "web"
            findings += secrets
        except ScanError as e:
            errors.append(f"gitleaks: {e}")

    rel = lambda p: p.relative_to(root).as_posix()  # noqa: E731
    return SourceScan(root, [_with_policy(f) for f in findings], [rel(p) for p in java], [rel(p) for p in kotlin],
                      [rel(p) for p in manifests], [rel(p) for p in scripts], parse_errors, errors,
                      [rel(p) for p in web])


def semgrep_files(files: list[Path], root: Path) -> tuple[list[Finding], list[str]]:
    """Semgrep over the given files. Also returns files it could not parse, so a fix that breaks the
    code's syntax is caught."""
    if not files:
        return [], []
    configs = []
    if any(f.suffix == ".java" for f in files):
        configs += ["--config", str(RULES_FILE)]
    if any(f.suffix == ".kt" for f in files):
        configs += ["--config", str(KOTLIN_RULES_FILE)]
    if any(f.suffix in WEB_SUFFIXES for f in files):
        configs += ["--config", str(WEB_RULES_FILE)]
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check", "--no-git-ignore",
           "--max-target-bytes=5000000", "--timeout=20", *configs] + [str(f) for f in files]
    result = _run(cmd)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ScanError(f"semgrep exit {result.returncode}: {(result.stderr or result.stdout)[-500:]}") from None
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        findings.append(Finding(
            tool="semgrep", rule_id=r["check_id"].rsplit(".", 1)[-1],
            category=extra.get("metadata", {}).get("category", "security"),
            file=Path(r["path"]).resolve().relative_to(root.resolve()).as_posix(),
            line=r["start"]["line"], end_line=r["end"]["line"], message=extra.get("message", ""),
            tool_severity=extra.get("severity", "INFO")))
    errors = data.get("errors", [])
    # A rule that fails to load finds nothing at all; never let that pass as "no problems".
    rule_errors = [e for e in errors if "Rule" in str(e.get("type", "")) or "InvalidRule" in str(e.get("type", ""))]
    if rule_errors:
        raise ScanError(f"a scanner rule failed to load: {str(rule_errors[0].get('message', ''))[:300]}")
    parse_errors = sorted({Path(e["path"]).resolve().relative_to(root.resolve()).as_posix()
                           for e in errors if e.get("path") and "Syntax" in str(e.get("type", ""))})
    return findings, parse_errors


def manifest_findings(manifest: Path, root: Path) -> list[Finding]:
    # The APK manifest check reads paths relative to sources_dir.parent and resources from <dir>/res.
    view = UnpackedApk(apk_path=manifest, work_dir=root, sources_dir=root / "_", resources_dir=manifest.parent,
                       manifest_path=manifest, package_name=None)
    try:
        return _check_manifest(view)
    except Exception as e:  # noqa: BLE001 - a broken manifest is reported, not fatal
        return [Finding("manifest", "manifest-unreadable", "bug", manifest.relative_to(root).as_posix(), 1,
                        f"AndroidManifest.xml could not be read: {e}", "WARNING")]


def _with_policy(f: Finding) -> dict:
    d = f.to_dict()
    rule = rule_for(d)
    d["severity"] = rule.severity
    d["title"] = rule.title
    d["policy_rule"] = "secret" if d["category"] == "secret" else d["rule_id"]
    return d


def fingerprint(findings: list[dict]) -> str:
    rows = sorted((f["policy_rule"], f["severity"], f["file"], f["line"]) for f in findings)
    return hashlib.sha256(json.dumps(rows).encode()).hexdigest()[:16]


def git_apply_check(original_root: Path, patch: Path) -> tuple[bool, str]:
    """Prove the delivered patch applies cleanly to the code the customer uploaded."""
    try:
        r = subprocess.run(["git", "apply", "--check", "--verbose", str(patch)], cwd=original_root,
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    return r.returncode == 0, (r.stderr or r.stdout)[-500:]
