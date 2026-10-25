"""Website scanning: REA captures what the browser downloads, then the same bug engine checks it.

  1. Safety: only http(s) URLs, never private-network addresses (so the server can't be used to
     reach internal machines), and the owner must prove control of the site (verification file).
  2. Capture: a headless Chrome opens the page; REA's `analyze_web_bundle` reads the JavaScript the
     browser received, the API endpoints in it, the libraries it uses and any public source maps,
     and `export_web_scripts` writes those scripts to disk.
  3. Checks: Semgrep (rules/web.yml) + Gitleaks on the scripts, plus fixed HTTP checks on the
     response (HTTPS, security headers, cookies, exposed .env / .git, source maps).

The output is an UnpackedApk-shaped bundle plus a map, so triage, AI and report run unchanged.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from scanner import tls
from scanner.ingest import UnpackedApk
from scanner.rea import ReaError, ReaSession, rea_available, rea_version
from scanner.scan import Finding, ScanError, _dedupe, _run_semgrep, run_gitleaks

PROJECT = Path(__file__).resolve().parent.parent
WEB_RULES_FILE = PROJECT / "rules" / "web.yml"
log = logging.getLogger("vibeguard.web")
VERIFY_PATH = "/.well-known/vibeguard-verify.txt"
SECRET_FILE = Path(os.environ.get("VERIFY_SECRET_FILE", PROJECT / ".verify-secret"))
USER_AGENT = "VibeGuard-WebScan/0.4 (authorized owner scan)"
HTTP_TIMEOUT = 15
MAX_BODY = 2 * 1024 * 1024
PAGE_LOAD_SECONDS = float(os.environ.get("WEB_PAGE_LOAD_SECONDS", 4))
# host.docker.internal is the computer running VibeGuard's Docker container (its own dev servers).
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


class WebScanError(Exception):
    """A problem the person can fix (bad URL, not verified, site unreachable)."""


class ReaCaptureError(WebScanError):
    """REA could not capture the page (it crashed or ran out of memory); the direct capture can stand in."""


class NotVerifiedError(WebScanError):
    pass


# ------------------------------------------------------------------------------ URL safety

def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise WebScanError("Please enter the website address.")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    try:
        parts.port  # raises for a non-numeric port, e.g. "javascript:alert(1)" read as host:port
    except ValueError:
        raise WebScanError("Only http:// and https:// website addresses can be scanned.")
    if parts.scheme not in ("http", "https") or not parts.hostname or "." not in parts.hostname and \
            parts.hostname not in LOCAL_HOSTS:
        raise WebScanError("Only http:// and https:// website addresses can be scanned.")
    if parts.username or parts.password:
        raise WebScanError("Please remove the username and password from the address.")
    return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path or "/", parts.query, ""))


def allow_local() -> bool:
    # On for local development; switch off on a public server.
    return os.environ.get("WEB_ALLOW_LOCAL", "true").lower() in ("1", "true", "yes", "on")


def is_local(url: str) -> bool:
    return (urlsplit(url).hostname or "") in LOCAL_HOSTS


def check_target(url: str) -> None:
    """Refuse addresses inside private networks (cloud metadata, routers, other servers)."""
    host = urlsplit(url).hostname or ""
    if host in LOCAL_HOSTS:
        if not allow_local():
            raise WebScanError("Scanning localhost is switched off on this server.")
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise WebScanError(f"The website {host} could not be found. Check the address.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified):
            raise WebScanError("This address points into a private network, which can't be scanned.")


# ------------------------------------------------------------------------------ ownership

def _verify_secret() -> bytes:
    if os.environ.get("WEB_VERIFY_SECRET"):
        return os.environ["WEB_VERIFY_SECRET"].encode()
    if not SECRET_FILE.is_file():
        SECRET_FILE.write_text(secrets.token_hex(32))
        SECRET_FILE.chmod(0o600)
    return SECRET_FILE.read_text().strip().encode()


def verification_token(url: str) -> str:
    """The same site always gets the same token, so no database is needed."""
    host = (urlsplit(normalize_url(url)).hostname or "").lower()
    return "vibeguard-verify=" + hmac.new(_verify_secret(), host.encode(), hashlib.sha256).hexdigest()[:32]


META_NAME = "vibeguard-site-verification"
_META_TAG = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR = re.compile(r"""([a-zA-Z_:-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s"'>]+)""")


def trusted_hosts() -> set[str]:
    """WEB_VERIFY_EXEMPT_HOSTS: sites the operator of this server owns or may test (comma-separated,
    "*.example.com" for subdomains). A server setting, so customers cannot add to it."""
    return {h.strip().lower() for h in os.environ.get("WEB_VERIFY_EXEMPT_HOSTS", "").split(",") if h.strip()}


def is_trusted(url: str) -> bool:
    host = (urlsplit(normalize_url(url)).hostname or "").lower()
    return any(host == t or (t.startswith("*.") and host.endswith(t[1:])) for t in trusted_hosts())


def verification_instructions(url: str) -> dict:
    url = normalize_url(url)
    parts = urlsplit(url)
    token = verification_token(url)
    return {
        "url": url,
        "token": token,
        "file_url": f"{parts.scheme}://{parts.netloc}{VERIFY_PATH}",
        "home_url": f"{parts.scheme}://{parts.netloc}/",
        "meta_tag": f'<meta name="{META_NAME}" content="{token}">',
        "meta_name": META_NAME,
        "local": is_local(url),
        "trusted": is_trusted(url),
        "instructions": "Add the meta tag to your homepage's <head>, or create a text file at file_url containing only "
                        "the token, then scan. It proves you control the site; you can remove it afterwards.",
    }


def check_ownership(url: str) -> str:
    """How the site was verified: local | trusted | meta | file. Raises NotVerifiedError otherwise."""
    if is_local(url):
        return "local"  # your own machine
    if is_trusted(url):
        return "trusted"
    info = verification_instructions(url)
    # 1. <meta name="vibeguard-site-verification" content="..."> on the homepage (like Google Search Console).
    try:
        final, status, _, body, _ = _follow(info["home_url"])
    except WebScanError:
        status, final, body = 0, "", b""
    same_site = urlsplit(final).hostname == urlsplit(info["home_url"]).hostname
    if status == 200 and same_site and _has_meta_token(body.decode("utf-8", "replace"), info["token"]):
        return "meta"
    # 2. The token file at /.well-known/vibeguard-verify.txt (no redirects, so a login page can't stand in).
    status, _, body = _fetch(info["file_url"])
    if status == 200 and info["token"] in body.decode("utf-8", "replace"):
        return "file"
    raise NotVerifiedError(f"Couldn't verify that you control this site. Add {info['meta_tag']} to your homepage, "
                           f"or put the token {info['token']} in a file at {info['file_url']}, and try again.")


def _has_meta_token(html: str, token: str) -> bool:
    for tag in _META_TAG.findall(html[:500_000]):
        attrs = {k.lower(): v.strip("\"'") for k, v in _ATTR.findall(tag)}
        if attrs.get("name", "").lower() == META_NAME and attrs.get("content", "").strip() == token:
            return True
    return False


# ------------------------------------------------------------------------------ HTTP

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=tls.CONTEXT))


def _fetch(url: str) -> tuple[int, list[tuple[str, str]], bytes]:
    """GET without following redirects. Returns (status, headers, body), status 0 if unreachable."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = _opener.open(req, timeout=HTTP_TIMEOUT)
    except urllib.error.HTTPError as e:
        resp = e
    except (urllib.error.URLError, OSError, ValueError):
        return 0, [], b""
    with resp:
        return resp.status, list(resp.headers.items()), resp.read(MAX_BODY)


def _follow(url: str, limit: int = 5) -> tuple[str, int, list[tuple[str, str]], bytes, list[str]]:
    chain = []
    for _ in range(limit):
        status, headers, body = _fetch(url)
        chain.append(f"{status} {url}")
        location = next((v for k, v in headers if k.lower() == "location"), None)
        if status in (301, 302, 303, 307, 308) and location:
            nxt = urljoin(url, location)
            check_target(nxt)
            url = nxt
            continue
        return url, status, headers, body, chain
    raise WebScanError("The website redirects too many times.")


def _redact_cookie(value: str) -> str:
    name, _, rest = value.partition("=")
    _, sep, attrs = rest.partition(";")
    return f"{name}=<hidden>{sep}{attrs}"


def http_checks(url: str, root: Path) -> tuple[list[Finding], dict]:
    """Fixed checks on the page response. Evidence goes to http/*.txt so triage can show it."""
    http_dir = root / "http"
    http_dir.mkdir(parents=True, exist_ok=True)
    final, status, headers, body, chain = _follow(url)
    if status == 0:
        raise WebScanError("The website did not respond. Check that it is online.")

    lines = [f"GET {url}"] + [f"redirect: {c}" for c in chain[:-1]] + [f"HTTP {status} {final}"]
    header_line: dict[str, int] = {}
    for name, value in headers:
        shown = _redact_cookie(value) if name.lower() == "set-cookie" else value
        lines.append(f"{name}: {shown}")
        header_line.setdefault(name.lower(), len(lines))
    (http_dir / "headers.txt").write_text("\n".join(lines) + "\n")
    rel = "http/headers.txt"
    hmap = {k.lower(): v for k, v in headers}
    findings: list[Finding] = []

    def add(rule: str, message: str, line: int = 1, file: str = rel, severity: str = "WARNING") -> None:
        findings.append(Finding("http", rule, "security", file, line, message, severity, extra={"target": "web"}))

    https = final.startswith("https://")
    local = is_local(final)
    if not https and not local:
        add("web-no-https", "The site is served over plain http://.", header_line.get("location", len(chain) + 1), severity="ERROR")
    if https and url.startswith("https://"):
        plain = "http://" + final.split("://", 1)[1]
        p_status, p_headers, _ = _fetch(plain)
        p_loc = next((v for k, v in p_headers if k.lower() == "location"), "")
        if p_status and not (p_status in (301, 302, 307, 308) and p_loc.startswith("https://")):
            add("web-no-https-redirect", f"http:// returns {p_status} instead of redirecting to https://.")
    if https and "strict-transport-security" not in hmap:
        add("web-missing-hsts", "No Strict-Transport-Security header.")
    csp = hmap.get("content-security-policy", "")
    if not csp:
        add("web-missing-csp", "No Content-Security-Policy header.")
    if "frame-ancestors" not in csp and "x-frame-options" not in hmap:
        add("web-missing-frame-protection", "Neither X-Frame-Options nor CSP frame-ancestors is set.")
    if hmap.get("x-content-type-options", "").lower() != "nosniff":
        add("web-missing-nosniff", "X-Content-Type-Options: nosniff is not set.", severity="INFO")
    for name, value in headers:
        if name.lower() != "set-cookie":
            continue
        attrs = value.lower()
        missing = [flag for flag, ok in (("Secure", "secure" in attrs or local), ("HttpOnly", "httponly" in attrs),
                                         ("SameSite", "samesite" in attrs)) if not ok]
        if missing:
            cookie = value.split("=", 1)[0]
            add("web-cookie-insecure", f"Cookie '{cookie}' is missing: {', '.join(missing)}.",
                lines.index(f"{name}: {_redact_cookie(value)}") + 1)
    server = hmap.get("server", "")
    if re.search(r"\d", server) or "x-powered-by" in hmap:
        line = header_line.get("x-powered-by") or header_line.get("server", 1)
        add("web-server-version-disclosure", "The Server / X-Powered-By header reveals software versions.", line,
            severity="INFO")

    origin = f"{urlsplit(final).scheme}://{urlsplit(final).netloc}"
    findings += _exposed_files(origin, http_dir)
    return findings, {"final_url": final, "status": status, "redirects": chain[:-1], "body": body}


def _exposed_files(origin: str, http_dir: Path) -> list[Finding]:
    findings = []
    status, headers, body = _fetch(origin + "/.env")
    text = body.decode("utf-8", "replace")
    ctype = next((v for k, v in headers if k.lower() == "content-type"), "")
    keys = re.findall(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=", text)
    if status == 200 and keys and "html" not in ctype:
        # Keep only the variable names as evidence - never the values.
        (http_dir / "exposed-env.txt").write_text(
            f"GET {origin}/.env -> {status}\n" + "\n".join(f"{k}=<hidden>" for k in keys[:50]) + "\n")
        findings.append(Finding("http", "web-exposed-env-file", "security", "http/exposed-env.txt", 1,
                                f"{origin}/.env is publicly downloadable ({len(keys)} variables).", "ERROR",
                                extra={"target": "web"}))
    status, _, body = _fetch(origin + "/.git/HEAD")
    if status == 200 and body.decode("utf-8", "replace").startswith("ref: "):
        (http_dir / "exposed-git.txt").write_text(f"GET {origin}/.git/HEAD -> {status}\n{body[:200].decode('utf-8', 'replace')}")
        findings.append(Finding("http", "web-exposed-git", "security", "http/exposed-git.txt", 1,
                                f"{origin}/.git/ is publicly downloadable.", "ERROR", extra={"target": "web"}))
    return findings


# ------------------------------------------------------------------------------ REA browser capture

def _chrome_bin() -> str:
    for candidate in (os.environ.get("CHROME_BIN"),
                      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                      "/Applications/Chromium.app/Contents/MacOS/Chromium",
                      shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chromium-browser")):
        if candidate and Path(candidate).exists():
            return candidate
    raise WebScanError("Google Chrome or Chromium is needed to scan websites (set CHROME_BIN).")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def capture_with_rea(url: str, root: Path) -> dict:
    """Open the page in headless Chrome and let REA capture and analyse what the browser received."""
    if not rea_available():
        raise ReaCaptureError("the deep engine is not installed here")
    try:
        _chrome_bin()
    except WebScanError as e:
        raise ReaCaptureError(f"no browser is available for the deep engine ({e})") from e
    port = _free_port()
    profile = Path(tempfile.mkdtemp(prefix="vibeguard-chrome-"))
    chrome = subprocess.Popen(
        [_chrome_bin(), "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
         f"--remote-debugging-port={port}", f"--user-data-dir={profile}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    endpoint = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"{endpoint}/json/version", timeout=1).read()
                break
            except OSError:
                time.sleep(0.25)
        else:
            raise WebScanError("The headless browser did not start.")
        req = urllib.request.Request(f"{endpoint}/json/new?{url}", method="PUT")
        target = json.loads(urllib.request.urlopen(req, timeout=10).read())
        time.sleep(PAGE_LOAD_SECONDS)  # let the page load its scripts

        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        notes: list[str] = []
        bundle_args = {"cdp_endpoint": endpoint, "target_id": target["id"], "allowed_origins": [origin],
                       "observation_ms": 1000, "fetch_source_maps": True}
        rea = ReaSession(heap_mb=WEB_REA_HEAP_MB, call_timeout=WEB_REA_TIMEOUT)
        try:
            bundle = rea.call("analyze_web_bundle", bundle_args)
        except ReaError as e:
            rea.close()
            if e.reason != "out_of_memory":
                raise
            # Source maps are usually the biggest part of a large bundle; capture again without them.
            rea = ReaSession(heap_mb=WEB_REA_HEAP_MB, call_timeout=WEB_REA_TIMEOUT)
            try:
                bundle = rea.call("analyze_web_bundle", {**bundle_args, "fetch_source_maps": False})
            except ReaError:
                rea.close()
                raise
            notes.append("This site's JavaScript was too large to analyse together with its source maps, so the "
                         "check for public source maps was skipped. Everything else was checked.")
        with rea:
            (root / "rea-web-bundle.json").write_text(json.dumps(bundle))
            # The script export works from a page capture that retained the script sources.
            page = rea.call("inspect_web_page", {
                "cdp_endpoint": endpoint, "target_id": target["id"], "allowed_origins": [origin],
                "observation_ms": 1000, "include_script_sources": True, "include_storage_keys": True})
            capture_path = root / "rea-web-page.json"
            capture_path.write_text(json.dumps(page))
            export_dir = root / "rea-export"
            exported = rea.call("export_web_scripts", {"capture_path": str(capture_path),
                                                       "output_directory": str(export_dir)})
            (root / "rea-web-scripts.json").write_text(json.dumps(exported))
        site_dir, files = _site_tree(export_dir, root)
        return {"bundle": bundle, "page": page, "exported": exported, "scripts_dir": site_dir, "files": files,
                "notes": notes}
    except ReaError as e:
        if e.reason == "out_of_memory":
            raise ReaCaptureError("the deep engine ran out of memory analysing this site's JavaScript") from e
        if e.reason == "timeout":
            raise ReaCaptureError("the deep engine took too long to analyse this site's JavaScript") from e
        raise ReaCaptureError(f"the deep engine could not capture the page ({e})") from e
    finally:
        chrome.kill()
        chrome.wait(timeout=10)
        shutil.rmtree(profile, ignore_errors=True)


MAX_DIRECT_SCRIPTS = 80
# A web capture should take seconds; when REA struggles, fail fast and let the direct capture take over.
WEB_REA_HEAP_MB = int(os.environ.get("REA_WEB_HEAP_MB", 2048))
WEB_REA_TIMEOUT = float(os.environ.get("REA_WEB_TIMEOUT", 90))
_SCRIPT_SRC = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_PRELOAD = re.compile(r"""<link\b(?=[^>]*\brel\s*=\s*["'](?:modulepreload|preload)["'])(?=[^>]*\bas\s*=\s*["']script["']|[^>]*modulepreload)[^>]*\bhref\s*=\s*["']([^"']+)["']""", re.I)
_INLINE = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)</script>", re.I)
_MAP_URL = re.compile(r"[#@]\s*sourceMappingURL=(\S+)\s*$")


def capture_direct(url: str, html: bytes, root: Path) -> dict:
    """Fallback capture without REA: the scripts the page links to (same site only), fetched directly.
    Scripts the page loads later, while it runs, are not seen; the report says so."""
    site_dir = root / "site"
    site_dir.mkdir(exist_ok=True)
    host = (urlsplit(url).hostname or "").lower()
    page = html.decode("utf-8", "replace")
    seen, srcs = set(), []
    for m in list(_SCRIPT_SRC.finditer(page)) + list(_PRELOAD.finditer(page)):
        absolute = urljoin(url, m.group(1).replace("&amp;", "&"))
        if absolute not in seen and (urlsplit(absolute).hostname or "").lower() == host:
            seen.add(absolute)
            srcs.append(absolute)
    findings: list[Finding] = []
    safe = lambda segs: "/".join(re.sub(r"[^A-Za-z0-9._-]+", "_", x) for x in segs if x not in ("", ".", ".."))  # noqa: E731
    host_dir = re.sub(r"[^A-Za-z0-9.-]+", "_", host) or "site"
    saved = 0
    for absolute in srcs[:MAX_DIRECT_SCRIPTS]:
        check_target(absolute)
        status, _, body = _fetch(absolute)
        if status != 200 or not body:
            continue
        path = safe(urlsplit(absolute).path.split("/")) or f"script-{saved + 1}.js"
        if not path.endswith((".js", ".mjs", ".cjs")):
            path += ".js"
        dest = site_dir / host_dir / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
        saved += 1
        text = body.decode("utf-8", "ignore")
        lines = text.splitlines()
        tail = next((l for l in reversed(lines[-5:]) if "sourceMappingURL" in l), "")
        m = _MAP_URL.search(tail.strip())
        if m and not m.group(1).startswith("data:"):
            map_url = urljoin(absolute, m.group(1))
            if (urlsplit(map_url).hostname or "").lower() == host:
                check_target(map_url)
                mstatus, _, mbody = _fetch(map_url)
                if mstatus == 200 and b'"mappings"' in mbody[:200_000]:
                    findings.append(Finding("http", "web-source-map-exposed", "security", str(dest.relative_to(root)),
                                            len(lines), f"Source map is publicly downloadable: {map_url}", "WARNING",
                                            extra={"target": "web"}))
    for n, m in enumerate(_INLINE.finditer(page), 1):
        code = m.group(1).strip()
        if code:
            dest = site_dir / host_dir / "inline" / f"inline-{n}.js"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(code)
    return {"bundle": {}, "files": {}, "scripts_dir": site_dir, "findings": findings, "mode": "direct",
            "scripts_linked": len(srcs), "scripts_fetched": saved}


# ------------------------------------------------------------------------------ scan + map

def scan_website(url: str) -> tuple[UnpackedApk, dict, dict]:
    """Capture and check one website. Returns (bundle, map, scan_result) for triage/AI/report."""
    from scanner.mapper import NOISE_HOSTS, URL_RE, URL_TRAILING_JUNK

    url = normalize_url(url)
    check_target(url)
    ownership = check_ownership(url)
    work_dir = Path(tempfile.mkdtemp(prefix="vibeguard-web-"))
    root = work_dir / "web"
    root.mkdir()
    started = time.monotonic()
    try:
        findings, http_info = http_checks(url, root)
        try:
            capture = capture_with_rea(http_info["final_url"], root)
        except ReaCaptureError as e:
            # Don't fail the scan: check the scripts the page links to directly, and say so in the report.
            log.warning("REA capture failed for %s (%s); using the direct capture", http_info["final_url"], e)
            capture = capture_direct(http_info["final_url"], http_info["body"], root)
            capture["notes"] = [f"Captured with VibeGuard's direct fetch because {e}. The {capture['scripts_fetched']} "
                                "scripts this page links to were checked; scripts it loads later while running were not."]
    except Exception:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise
    scripts_dir = capture["scripts_dir"]
    scripts_dir.mkdir(exist_ok=True)
    errors: list[str] = []
    try:
        findings += _run_semgrep([scripts_dir], root, WEB_RULES_FILE)
    except ScanError as e:
        errors.append(f"semgrep: {e}")
    try:
        findings += _classify_secrets(run_gitleaks(root, [scripts_dir], work_dir / "gitleaks.json"))
    except ScanError as e:
        errors.append(f"gitleaks: {e}")
    findings += _source_map_findings(capture["bundle"], capture["files"], root) + capture.get("findings", [])
    for f in findings:
        f.extra["target"] = "web"
    findings = _dedupe(findings)

    by_category: dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
    scan_result = {"findings": [f.to_dict() for f in findings],
                   "counts": {"total": len(findings), **by_category}, "errors": errors}

    scripts = sorted(p for p in scripts_dir.rglob("*") if p.is_file() and p.suffix in (".js", ".mjs", ".cjs", ".ts"))
    final = http_info["final_url"]
    parts = urlsplit(final)
    endpoints: dict[str, dict] = {}
    for path in scripts:
        text = path.read_text(errors="ignore")
        for m in URL_RE.finditer(text):
            u = m.group(0).rstrip(URL_TRAILING_JUNK)
            host = (urlsplit(u).hostname or "").lower()
            if not host or host in NOISE_HOSTS or "." not in host and host != "localhost":
                continue
            e = endpoints.setdefault(u, {"url": u, "host": host, "in_app_code": True, "locations": [],
                                         "insecure": u.startswith(("http://", "ws://")) and host not in LOCAL_HOSTS})
            if len(e["locations"]) < 5:
                e["locations"].append({"file": str(path.relative_to(root)), "line": text.count("\n", 0, m.start()) + 1})

    evidence = capture["bundle"]
    web_map = {
        "package_name": parts.netloc,
        "permissions": [],
        "app_code": {"packages": [f"{parts.scheme}://{parts.netloc}"], "source_dirs": [str(scripts_dir)],
                     "java_files": len(scripts)},
        "libraries": _vendors(evidence),
        "library_versions": [],
        "unrecognized_code": [],
        "endpoints": sorted(endpoints.values(), key=lambda e: (not e["insecure"], e["host"], e["url"])),
        "stats": {"total_java_files": len(scripts), "library_prefixes_found": 0},
    }
    unpacked = UnpackedApk(
        apk_path=Path(parts.netloc), work_dir=work_dir, sources_dir=scripts_dir, resources_dir=root / "http",
        manifest_path=root / "http" / "headers.txt", package_name=parts.netloc, permissions=[],
        provenance={"engine": "direct" if capture.get("mode") == "direct" else "rea", "rea_version": rea_version(),
                    "capture": "html-linked-scripts" if capture.get("mode") == "direct" else "analyze_web_bundle",
                    "bundle_evidence_id": evidence.get("evidence_id"),
                    "scripts_captured": len(scripts), "final_url": final, "ownership_verified_by": ownership,
                    "seconds": round(time.monotonic() - started, 1)},
    )
    if not scripts:
        unpacked.warnings.append("No JavaScript was captured from this page, so only the server settings were checked.")
    unpacked.warnings.extend(capture.get("notes", []))
    return unpacked, web_map, scan_result


def _classify_secrets(findings: list[Finding]) -> list[Finding]:
    """Supabase's anon key is public by design (row level security protects the data); its
    service_role key is an admin key. Everything else Gitleaks finds stays a secret."""
    kept = []
    for f in findings:
        if f.extra.get("jwt_iss") == "supabase":
            if f.extra.get("jwt_role") == "anon":
                continue
            if f.extra.get("jwt_role") == "service_role":
                f.rule_id = "supabase-service-role-key"
        kept.append(f)
    return kept


def _walk(obj, key: str):
    """Yield every value stored under `key` anywhere in REA's Evidence."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                yield v
            yield from _walk(v, key)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, key)


def _vendors(evidence: dict) -> list[dict]:
    names = set()
    for key in ("vendor_fingerprint", "vendor_fingerprints"):
        for found in _walk(evidence.get("normalized_result", {}), key):
            for v in found if isinstance(found, list) else [found]:
                name = (v.get("name") or v.get("vendor") or v.get("library")) if isinstance(v, dict) else v
                if name:
                    names.add(str(name))
    return [{"name": n, "category": "web library", "package": n, "java_files": 0} for n in sorted(names)]


def _site_tree(export_dir: Path, root: Path) -> tuple[Path, dict[str, Path]]:
    """Copy REA's exported scripts (verified against its manifest) to site/<host>/<url path>, so reports
    show readable locations. Returns the folder and script_key -> file."""
    site_dir = root / "site"
    site_dir.mkdir(exist_ok=True)
    try:
        manifest = json.loads((export_dir / "manifest.json").read_text())
    except (OSError, ValueError):
        return site_dir, {}
    files: dict[str, Path] = {}
    for n, entry in enumerate(manifest.get("scripts", []), 1):
        content, source = entry.get("content") or {}, entry.get("source") or {}
        src = export_dir / "files" / content.get("relative_path", "")
        if content.get("state") != "exported" or not src.is_file():
            continue
        if hashlib.sha256(src.read_bytes()).hexdigest() != content.get("sha256"):
            continue  # never scan bytes that don't match REA's evidence
        parts = urlsplit(entry.get("url") or "")
        host = re.sub(r"[^A-Za-z0-9.-]+", "_", parts.netloc) or "inline"
        path = parts.path.strip("/") or f"inline-{n}.js"
        path = "/".join(re.sub(r"[^A-Za-z0-9._-]+", "_", seg) for seg in path.split("/") if seg not in ("", ".", ".."))
        if not path.endswith((".js", ".mjs", ".cjs")):
            path += ".js"
        dest = site_dir / host / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        if source.get("script_key"):
            files[source["script_key"]] = dest
    return site_dir, files


def _source_map_findings(evidence: dict, files: dict[str, Path], root: Path) -> list[Finding]:
    """Scripts whose source map REA could download from the site - i.e. the original code is public."""
    findings = []
    for maps in _walk(evidence.get("normalized_result", {}), "source_maps"):
        items = maps.get("items", []) if isinstance(maps, dict) else []
        for m in items:
            if not isinstance(m, dict) or not m.get("artifact"):
                continue  # declared but not downloadable
            script = files.get(m.get("script_key"))
            line = 1
            if script and script.is_file():
                for n, text in enumerate(script.read_text(errors="ignore").splitlines(), 1):
                    if "sourceMappingURL" in text:
                        line = n
            rel = str(script.relative_to(root)) if script else "http/headers.txt"
            findings.append(Finding("rea", "web-source-map-exposed", "security", rel, line,
                                    f"Source map is publicly downloadable: {m.get('effective_url') or m.get('declared_url')}",
                                    "WARNING", extra={"target": "web"}))
    return findings
