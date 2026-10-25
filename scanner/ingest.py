"""Step 1: ingest + unpack an APK with jadx and read its manifest."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
PERMISSION_TAGS = ("uses-permission", "uses-permission-sdk-23")
JADX_TIMEOUT_SECONDS = 600


class IngestError(Exception):
    """Raised when an APK can't be decompiled or its manifest can't be read."""


@dataclass
class UnpackedApk:
    apk_path: Path
    work_dir: Path  # temp folder holding everything; delete with cleanup()
    sources_dir: Path  # decompiled Java/Kotlin-as-Java source
    resources_dir: Path
    manifest_path: Path
    package_name: str | None
    permissions: list[str] = field(default_factory=list)
    jadx_warnings: str = ""  # jadx often reports errors for a few classes but still succeeds
    # Set by the REA engine, which decompiles only the app's own code: classes per package for the
    # whole APK (libraries included), where each fact came from, and notes for the report.
    package_counts: Counter | None = None
    provenance: dict = field(default_factory=lambda: {"engine": "jadx"})
    warnings: list[str] = field(default_factory=list)

    def cleanup(self) -> None:
        shutil.rmtree(self.work_dir, ignore_errors=True)


def unpack_apk(apk_path: str | Path, jadx_bin: str = "jadx") -> UnpackedApk:
    apk = Path(apk_path).expanduser().resolve()
    if not apk.is_file():
        raise IngestError(f"APK not found: {apk}")
    if shutil.which(jadx_bin) is None:
        raise IngestError(f"'{jadx_bin}' is not on PATH. Install it with: brew install jadx")

    work_dir = Path(tempfile.mkdtemp(prefix="vibeguard-"))
    out_dir = work_dir / "jadx"

    try:
        result = subprocess.run(
            [jadx_bin, "--output-dir", str(out_dir), "--show-bad-code", "--no-debug-info", str(apk)],
            capture_output=True,
            text=True,
            timeout=JADX_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise IngestError(f"jadx timed out after {JADX_TIMEOUT_SECONDS}s")

    sources_dir = out_dir / "sources"
    resources_dir = out_dir / "resources"
    manifest_path = resources_dir / "AndroidManifest.xml"

    # jadx exits non-zero if *any* class fails to decompile, which is common with
    # obfuscated apps. Only treat it as fatal if nothing usable came out.
    if not manifest_path.is_file() or not sources_dir.is_dir():
        shutil.rmtree(work_dir, ignore_errors=True)
        raise IngestError(
            f"jadx failed (exit {result.returncode}):\n{(result.stderr or result.stdout)[-2000:]}"
        )

    package_name, permissions = parse_manifest(manifest_path)
    return UnpackedApk(
        apk_path=apk,
        work_dir=work_dir,
        sources_dir=sources_dir,
        resources_dir=resources_dir,
        manifest_path=manifest_path,
        package_name=package_name,
        permissions=permissions,
        jadx_warnings=result.stderr.strip() if result.returncode != 0 else "",
    )


def load_unpacked(work_dir: str | Path) -> UnpackedApk:
    """Reopen a folder produced by an earlier unpack_apk() run (handy while developing)."""
    work_dir = Path(work_dir).expanduser().resolve()
    out_dir = work_dir / "rea" if (work_dir / "rea").is_dir() else work_dir / "jadx"
    manifest_path = out_dir / "resources" / "AndroidManifest.xml"
    if not manifest_path.is_file():
        raise IngestError(f"No decompiled APK found in {work_dir}")
    package_name, permissions = parse_manifest(manifest_path)
    unpacked = UnpackedApk(
        apk_path=work_dir,
        work_dir=work_dir,
        sources_dir=out_dir / "sources",
        resources_dir=out_dir / "resources",
        manifest_path=manifest_path,
        package_name=package_name,
        permissions=permissions,
    )
    meta = work_dir / "engine.json"  # written by the REA engine
    if meta.is_file():
        saved = json.loads(meta.read_text())
        unpacked.package_counts = Counter(saved["package_counts"])
        unpacked.provenance = saved["provenance"]
        unpacked.warnings = saved["warnings"]
    return unpacked


def parse_manifest(manifest_path: Path) -> tuple[str | None, list[str]]:
    try:
        root = ET.parse(manifest_path).getroot()
    except ET.ParseError as e:
        raise IngestError(f"Could not parse AndroidManifest.xml: {e}")

    permissions = {
        el.get(f"{ANDROID_NS}name")
        for tag in PERMISSION_TAGS
        for el in root.iter(tag)
        if el.get(f"{ANDROID_NS}name")
    }
    return root.get("package"), sorted(permissions)


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        sys.exit("usage: python -m scanner.ingest path/to/app.apk")

    unpacked = unpack_apk(sys.argv[1])
    java_files = sum(1 for _ in unpacked.sources_dir.rglob("*.java"))
    print(json.dumps(
        {
            "package_name": unpacked.package_name,
            "permissions": unpacked.permissions,
            "decompiled_to": str(unpacked.work_dir),
            "java_files": java_files,
            "manifest": str(unpacked.manifest_path),
            "jadx_had_warnings": bool(unpacked.jadx_warnings),
        },
        indent=2,
    ))
