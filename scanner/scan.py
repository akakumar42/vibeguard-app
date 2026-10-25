"""Step 3: static scan - Semgrep + Gitleaks over the app's own code, plus manifest and signature checks."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path

from scanner.ingest import ANDROID_NS, UnpackedApk

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "android.yml"
SCAN_TIMEOUT_SECONDS = 600
# Old Android versions lack protections like scoped storage and HTTPS-by-default.
MIN_SAFE_TARGET_SDK = 30


@dataclass
class Finding:
    tool: str  # semgrep | gitleaks | manifest | apksig
    rule_id: str
    category: str  # security | secret | bug | smell
    file: str  # relative to the jadx output folder, e.g. sources/org/foo/Bar.java
    line: int
    message: str
    tool_severity: str  # the tool's own rating; the AI layer re-rates later
    end_line: int | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def run_static_scan(unpacked: UnpackedApk, app_map: dict) -> dict:
    jadx_root = unpacked.sources_dir.parent
    app_dirs = [Path(d) for d in app_map["app_code"]["source_dirs"]]

    from scanner import signing

    findings: list[Finding] = []
    errors: list[str] = []
    signature: dict | None = None

    def check_signature() -> list[Finding]:
        nonlocal signature
        if not unpacked.apk_path.is_file():
            return []  # a folder from an earlier run has no .apk to check
        sig = signing.read_signature(unpacked.apk_path)
        signature = signing.summary(sig)
        return signing.signature_findings(sig)

    for name, scanner in (
        ("semgrep", lambda: _run_semgrep(app_dirs, jadx_root)),
        ("gitleaks", lambda: _run_gitleaks(unpacked, app_dirs, jadx_root)),
        ("manifest", lambda: _check_manifest(unpacked)),
        ("signature", check_signature),
    ):
        try:
            findings += scanner()
        except ScanError as e:
            errors.append(f"{name}: {e}")

    findings = _dedupe(findings)
    by_category: dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1

    return {
        "findings": [f.to_dict() for f in findings],
        "counts": {"total": len(findings), **by_category},
        "errors": errors,
        "signature": signature,
    }


class ScanError(Exception):
    pass


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    if shutil.which(cmd[0]) is None:
        raise ScanError(f"'{cmd[0]}' is not installed (brew install {cmd[0]})")
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise ScanError(f"timed out after {SCAN_TIMEOUT_SECONDS}s")


# ------------------------------------------------------------------------------ Semgrep

def _run_semgrep(app_dirs: list[Path], jadx_root: Path, rules_file: Path = RULES_FILE) -> list[Finding]:
    # Extra rulesets, e.g. SEMGREP_EXTRA_CONFIGS="p/java,p/secrets" (registry rules need internet).
    configs = [str(rules_file)] + [c.strip() for c in os.environ.get("SEMGREP_EXTRA_CONFIGS", "").split(",") if c.strip()]
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check",
           "--max-target-bytes=5000000", "--timeout=20"]
    for c in configs:
        cmd += ["--config", c]
    result = _run(cmd + [str(d) for d in app_dirs])

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ScanError(f"exit {result.returncode}: {(result.stderr or result.stdout)[-1000:]}")

    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        findings.append(Finding(
            tool="semgrep",
            rule_id=r["check_id"].rsplit(".", 1)[-1],
            category=meta.get("category", "security"),
            file=_relative(r["path"], jadx_root),
            line=r["start"]["line"],
            end_line=r["end"]["line"],
            message=extra.get("message", ""),
            tool_severity=extra.get("severity", "INFO"),
            extra={k: v for k, v in meta.items() if k in ("cwe", "owasp")},
        ))
    return findings


# ------------------------------------------------------------------------------ Gitleaks

def _run_gitleaks(unpacked: UnpackedApk, app_dirs: list[Path], jadx_root: Path) -> list[Finding]:
    # Secrets inside bundled libraries are almost always test fixtures or public keys;
    # keep the app's own code plus resources/ (strings.xml, assets) where real keys live.
    return run_gitleaks(jadx_root, list(app_dirs) + [unpacked.resources_dir], unpacked.work_dir / "gitleaks.json")


def run_gitleaks(jadx_root: Path, scope_dirs: list[Path], report: Path) -> list[Finding]:
    """Gitleaks over jadx_root, keeping leaks under scope_dirs. Paths are reported relative to jadx_root."""
    result = _run(["gitleaks", "dir", str(jadx_root), "--report-format", "json", "--report-path", str(report),
                   "--no-banner", "--exit-code", "0", "--log-level", "error", "--max-target-megabytes", "5"])
    if not report.is_file():
        raise ScanError(f"exit {result.returncode}: {(result.stderr or result.stdout)[-1000:]}")
    leaks = json.loads(report.read_text() or "[]")
    scope = [d.resolve() for d in scope_dirs]
    findings = []
    for leak in leaks:
        path = Path(leak["File"]).resolve()
        if not any(path.is_relative_to(s) for s in scope):
            continue
        findings.append(Finding(
            tool="gitleaks",
            rule_id=leak["RuleID"],
            category="secret",
            file=_relative(str(path), jadx_root),
            line=leak["StartLine"],
            end_line=leak.get("EndLine"),
            message=f"Possible hardcoded secret: {leak.get('Description', leak['RuleID'])}",
            tool_severity="ERROR",
            # Never pass the full secret downstream (it ends up in an LLM prompt and the report).
            # The hash lets triage find and mask the secret in code context without storing it.
            extra={
                "secret_preview": _redact(leak.get("Secret", "")),
                "secret_sha256": hashlib.sha256(leak.get("Secret", "").encode()).hexdigest(),
                "secret_length": len(leak.get("Secret", "")),
                "entropy": round(leak.get("Entropy", 0), 2),
                **_jwt_claims(leak.get("Secret", "")),
            },
        ))
    return findings


def _jwt_claims(token: str) -> dict:
    """Only the non-secret 'role' and 'iss' claims of a JWT, e.g. to tell Supabase's public anon key
    from its admin service_role key."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {f"jwt_{k}": str(payload[k]) for k in ("role", "iss") if k in payload}


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}…{secret[-2:]} ({len(secret)} chars)"


# ------------------------------------------------------------------------------ Manifest

def _check_manifest(unpacked: UnpackedApk) -> list[Finding]:
    path = unpacked.manifest_path
    rel = _relative(str(path), unpacked.sources_dir.parent)
    lines = path.read_text(errors="ignore").splitlines()
    root = ET.parse(path).getroot()
    app = root.find("application")
    findings: list[Finding] = []

    def line_of(*needles: str) -> int:
        for i, text in enumerate(lines, 1):
            if all(n in text for n in needles):
                return i
        return 1

    def add(rule_id: str, category: str, severity: str, message: str, line: int) -> None:
        findings.append(Finding("manifest", rule_id, category, rel, line, message, severity))

    def attr(el: ET.Element | None, name: str) -> str | None:
        return None if el is None else el.get(f"{ANDROID_NS}{name}")

    if attr(app, "debuggable") == "true":
        add("debuggable", "security", "ERROR",
            "The app was shipped in debug mode: anyone with a USB cable can inspect its memory and data.",
            line_of('android:debuggable="true"'))
    if attr(app, "allowBackup") == "true":
        add("allow-backup", "security", "INFO",
            "App data can be copied off the phone with a backup tool, including any saved logins.",
            line_of('android:allowBackup="true"'))
    if attr(app, "usesCleartextTraffic") == "true":
        add("cleartext-traffic", "security", "WARNING",
            "The app is allowed to use unencrypted http:// connections that others on the network can read.",
            line_of('android:usesCleartextTraffic="true"'))

    sdk = root.find("uses-sdk")
    target = attr(sdk, "targetSdkVersion")
    if target and target.isdigit() and int(target) < MIN_SAFE_TARGET_SDK:
        add("old-target-sdk", "security", "WARNING",
            f"The app targets Android API {target}, so it opts out of newer Android privacy and security protections.",
            line_of("targetSdkVersion"))

    findings += _check_network_security_config(unpacked, attr(app, "networkSecurityConfig"))

    # Exported services/receivers/providers with no permission can be triggered by any app.
    for tag in ("service", "receiver", "provider"):
        for el in root.iter(tag):
            name = attr(el, "name") or "?"
            exported = attr(el, "exported")
            if exported is None:
                # Before Android 12 a component with an intent-filter was exported by default.
                exported = "true" if el.find("intent-filter") is not None and tag != "provider" else "false"
            if exported == "true" and not attr(el, "permission") and not _is_library_component(name):
                add(f"exported-{tag}", "security", "WARNING",
                    f"The {tag} {name.rsplit('.', 1)[-1]} can be started by any other app on the phone, with no permission check.",
                    line_of(f'android:name="{name}"'))
    return findings


def _check_network_security_config(unpacked: UnpackedApk, ref: str | None) -> list[Finding]:
    if not ref or not ref.startswith("@xml/"):
        return []
    path = unpacked.resources_dir / "res" / "xml" / f"{ref[5:]}.xml"
    if not path.is_file():
        return []
    rel = _relative(str(path), unpacked.sources_dir.parent)
    text = path.read_text(errors="ignore")
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        if 'cleartextTrafficPermitted="true"' in line:
            findings.append(Finding("manifest", "nsc-cleartext", "security", rel, i,
                                    "The network security config allows unencrypted http:// traffic.", "WARNING"))
        if 'src="user"' in line:
            findings.append(Finding("manifest", "nsc-user-certs", "security", rel, i,
                                    "The app trusts certificates the user installs, which makes its HTTPS traffic easy to intercept.",
                                    "WARNING"))
    return findings


def _is_library_component(name: str) -> bool:
    # Components merged in from AndroidX/Google libraries are reviewed upstream and are mostly noise here.
    return name.startswith(("androidx.", "com.google.android.gms.", "com.google.firebase."))


# ------------------------------------------------------------------------------ helpers

def _relative(path: str, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        return path


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, unique = set(), []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    order = {"secret": 0, "security": 1, "bug": 2, "smell": 3}
    return sorted(unique, key=lambda f: (order.get(f.category, 9), f.file, f.line))


if __name__ == "__main__":
    import argparse
    from collections import Counter

    from scanner.ingest import load_unpacked, unpack_apk
    from scanner.mapper import build_map

    parser = argparse.ArgumentParser(description="Static scan of an APK with Semgrep + Gitleaks.")
    parser.add_argument("target", help="path to an .apk, or a folder from an earlier run (skips jadx)")
    parser.add_argument("--json", action="store_true", help="print every finding as JSON")
    args = parser.parse_args()

    target = Path(args.target)
    unpacked = load_unpacked(target) if target.is_dir() else unpack_apk(target)
    result = run_static_scan(unpacked, build_map(unpacked))

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"counts: {result['counts']}")
        for err in result["errors"]:
            print(f"ERROR {err}")
        print("\nby rule:")
        for (cat, rule), n in Counter((f["category"], f["rule_id"]) for f in result["findings"]).most_common():
            print(f"  {n:4}  {cat:8}  {rule}")
        print("\nfirst finding per rule:")
        shown = set()
        for f in result["findings"]:
            if f["rule_id"] not in shown:
                shown.add(f["rule_id"])
                print(f"  [{f['category']}] {f['rule_id']}  {f['file']}:{f['line']}\n      {f['message']}")
    print(f"\n# decompiled folder: {unpacked.work_dir}")
