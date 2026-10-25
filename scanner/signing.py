"""APK signature check with Google's apksig library (the code behind `apksigner verify`).

REA 6.7.0 has no signature tool, so this runs for both engines straight on the uploaded .apk.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from scanner.scan import Finding, ScanError

TOOLS = Path(__file__).resolve().parent.parent / "tools" / "apksig"
APKSIG_VERSION = "9.3.3"
APKSIG_JAR = TOOLS / f"apksig-{APKSIG_VERSION}.jar"
# Google Maven publishes only a sha1; this sha256 was taken after that sha1 matched.
APKSIG_SHA256 = "562cd0a88890960d2ece48e116c61f12872222f1dcc306890799382bc019b201"
CHECKER = TOOLS / "ApkSigCheck.java"
# Where the finding points in the report: the signature is not a line of code.
LOCATION = "APK signature"
MIN_KEY_BITS = {"RSA": 2048, "EC": 256}


def apksig_available() -> bool:
    return APKSIG_JAR.is_file() and CHECKER.is_file() and shutil.which(os.environ.get("JAVA_BIN", "java")) is not None


def read_signature(apk: Path) -> dict:
    """The signing facts as reported by apksig (schemes, signer certificates, errors)."""
    if not apksig_available():
        raise ScanError(f"APK signature check needs Java and {APKSIG_JAR.name} in tools/apksig")
    if hashlib.sha256(APKSIG_JAR.read_bytes()).hexdigest() != APKSIG_SHA256:
        raise ScanError(f"{APKSIG_JAR.name} does not match its pinned checksum; download it again")
    try:
        java = os.environ.get("JAVA_BIN", "java")
        compiled = TOOLS / "classes" / "ApkSigCheck.class"
        # The Docker image compiles the checker ahead of time, so a Java runtime (no compiler) is enough there.
        cmd = ([java, "-cp", f"{APKSIG_JAR}{os.pathsep}{compiled.parent}", "ApkSigCheck", str(apk)] if compiled.is_file()
               else [java, "-cp", str(APKSIG_JAR), str(CHECKER), str(apk)])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        raise ScanError(f"APK signature check failed: {e}") from e


def signature_findings(sig: dict) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule_id: str, severity: str, message: str) -> None:
        findings.append(Finding("apksig", rule_id, "security", LOCATION, 1, message, severity))

    if not sig.get("verified"):
        errors = "; ".join(sig.get("errors", [])[:3]) or "no valid signature found"
        add("apk-signature-invalid", "ERROR", f"The APK's signature did not verify: {errors}")
        return findings
    if sig.get("v1") and not (sig.get("v2") or sig.get("v3") or sig.get("v31")):
        add("apk-signature-v1-only", "WARNING",
            "The APK is signed only with the old v1 (JAR) scheme, which does not protect the whole file (Janus, CVE-2017-13156).")
    for cert in sig.get("signers", []):
        if "CN=Android Debug" in cert.get("subject", ""):
            add("apk-debug-certificate", "WARNING", "The APK is signed with the Android Studio debug key, not a release key.")
        algo, bits = cert.get("key_algorithm", ""), cert.get("key_bits", 0)
        if algo == "DSA" or (algo in MIN_KEY_BITS and bits < MIN_KEY_BITS[algo]):
            add("apk-weak-signing-key", "WARNING", f"The signing key is {algo} {bits}-bit, below today's minimum.")
    return findings


def summary(sig: dict) -> dict:
    """What the report shows about signing, whether or not anything was flagged."""
    schemes = [s for s in ("v1", "v2", "v3", "v31", "v4") if sig.get(s)]
    return {
        "verified": bool(sig.get("verified")),
        "schemes": schemes,
        "errors": sig.get("errors", []),
        "signers": sig.get("signers", []),
        "checked_by": f"apksig {APKSIG_VERSION}",
    }
