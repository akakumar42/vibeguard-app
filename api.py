"""Step 7: HTTP API. POST /scan with an .apk upload returns the plain-English report.

Run:  uvicorn api:app --reload
Open: http://127.0.0.1:8000       (demo upload page)
Docs: http://127.0.0.1:8000/docs  (raw API)
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import tempfile
import threading
import time
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from scanner.ai import PROVIDERS, get_config, load_dotenv
from scanner.ingest import IngestError
from scanner import accounts, billing, fixer, jobs, limits
from scanner.source import SourceError, unpack_source_zip
from scanner.accounts import AuthError
from scanner.billing import BillingError
from scanner.limits import LimitError
from scanner.pipeline import ENGINE_VERSION, ENGINES, _sha256, finish_report, scan_apk, scan_web as scan_website, selected_engine
from scanner.policy import POLICY_VERSION
from scanner.rea import rea_available
from scanner.web import NotVerifiedError, WebScanError, verification_instructions
from scanner.report import render_text

load_dotenv()
log = logging.getLogger("vibeguard")

MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_MB", 150)) * 1024 * 1024
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", 2))
CHUNK = 1 << 20
STATIC_DIR = Path(__file__).resolve().parent / "static"
ZIP_MAGIC = b"PK\x03\x04"  # every APK is a ZIP file

# jadx + semgrep are CPU/memory heavy; refuse rather than queue when the box is busy.
_scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)
# Each REA scan runs several ~2 GB JVMs for ~13 minutes, so by default only one at a time.
_rea_slots = threading.BoundedSemaphore(int(os.environ.get("REA_MAX_CONCURRENT", 1)))
# Each account's current scan, so a reloaded page (or a second click) can follow it instead of failing.
# In memory: a server restart forgets running scans, which also stop on restart.
_active: dict[str, dict] = {}
_active_lock = threading.Lock()
ACTIVE_KEEP_SECONDS = 15 * 60  # how long a finished scan's report id stays available to pick up


def _scan_started(owner: str | None, kind: str, name: str, engine: str | None = None) -> None:
    if owner:
        with _active_lock:
            _active[owner] = {"kind": kind, "name": name, "engine": engine, "started": time.time(),
                              "running": True, "report_id": None, "error": None}


def _scan_finished(owner: str | None, report_id: str | None = None, error: str | None = None) -> None:
    if owner:
        with _active_lock:
            if owner in _active and _active[owner]["running"]:  # the first outcome recorded wins
                _active[owner].update(running=False, report_id=report_id, error=error, finished=time.time())


def _running_scan(owner: str | None) -> dict | None:
    with _active_lock:
        info = _active.get(owner) if owner else None
        return dict(info) if info and info["running"] else None


def _still_running_error(info: dict) -> HTTPException:
    minutes = max(1, round((time.time() - info["started"]) / 60))
    what = "deep scan" if info.get("engine") == "rea" else "scan"
    return HTTPException(409, {
        "message": f"Your {what} of {info['name']} is still running (started {minutes} minute{'s' if minutes != 1 else ''} "
                   "ago). It will show here when it's done.",
        "active": {**info, "elapsed_seconds": round(time.time() - info["started"])}})


# Bug-fixing jobs run in the background (minutes); the page polls /reports/{id} for progress.
_fix_jobs: dict[str, dict] = {}
_fix_jobs_lock = threading.Lock()
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() in ("1", "true", "yes")

app = FastAPI(
    title="VibeGuard",
    description="Upload an Android app you own or are authorized to test and get a plain-English report "
                "of how it works and what's wrong with it.",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",")],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
CLEANUP_INTERVAL_SECONDS = 3600


@app.on_event("startup")
def start_cleanup() -> None:
    """Keeps the "deleted after 24 hours" promise: expired scans, uploaded projects, sessions and codes are
    removed when the app starts and then every hour, not only when someone opens them."""
    def loop() -> None:
        while True:
            try:
                scans, other = billing.purge_expired(), accounts.purge_expired()
                if scans or other:
                    log.info("clean-up removed %d expired scans and %d expired sign-in records", scans, other)
            except Exception:  # noqa: BLE001 - never let clean-up take the app down
                log.exception("clean-up failed")
            time.sleep(CLEANUP_INTERVAL_SECONDS)
    threading.Thread(target=loop, name="vibeguard-cleanup", daemon=True).start()


@app.get("/", include_in_schema=False)
def landing_page(request: Request):
    # Links from before the landing page existed (/?report=..., /#example) still open the scanner.
    if request.query_params.get("report"):
        return RedirectResponse(f"/app?{request.url.query}", status_code=307)
    return FileResponse(STATIC_DIR / "landing.html")


@app.get("/app", include_in_schema=False)
def scanner_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict:
    tools = {name: shutil.which(name) is not None for name in ("jadx", "semgrep", "gitleaks")}
    try:
        cfg = get_config()
        keys = ("LLM_API_KEY", *PROVIDERS[cfg.name].key_envs)
        llm = {"provider": cfg.name, "model": cfg.model, "api_key_set": any(os.environ.get(k) for k in keys)}
    except Exception as e:  # bad LLM_PROVIDER etc. - report it, don't crash the health check
        llm = {"error": str(e)}
    tools["rea"] = rea_available()
    return {"ok": all(v for k, v in tools.items() if k != "rea"), "tools": tools, "apk_engine": selected_engine(),
            "apk_engines": [e for e in ("jadx", "rea") if e == "jadx" or tools["rea"]], "llm": llm,
            "paywall": billing.paywall_enabled(), "payments_mode": billing.payments_mode(), "plans": billing.public_plans(),
            "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024)}


@app.get("/limits")
def free_limits(request: Request) -> dict:
    """How many free scans the signed-in account has left today."""
    if not billing.paywall_enabled():
        return {"enabled": False}
    account = _account(request)
    base = {"enabled": True, "signed_in": bool(account), "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
            "free_scans_per_day": limits.free_scans_per_day()}
    return base | (limits.status(account["id"]) if account else {})


# ---------------------------------------------------------------- accounts (email code sign-in)

@app.get("/auth/config")
def auth_config() -> dict:
    try:
        return accounts.public_config()
    except AuthError as e:
        raise _auth_http(e)


@app.post("/auth/supabase")
def auth_supabase(request: Request, access_token: str = Form(...)) -> JSONResponse:
    """Called once by the page after Supabase sign-in (Google or email link)."""
    try:
        account, token = accounts.sign_in_with_supabase(access_token, _visitor(request))
    except AuthError as e:
        raise _auth_http(e)
    return _signed_in(request, account, token)


@app.post("/auth/start")
def auth_start(email: str = Form(...)) -> dict:
    """Send a 6-digit sign-in code. In EMAIL_MODE=demo the code is returned instead of emailed."""
    try:
        return accounts.start_sign_in(email)
    except AuthError as e:
        raise _auth_http(e)


@app.post("/auth/verify")
def auth_verify(request: Request, email: str = Form(...), code: str = Form(...)) -> JSONResponse:
    try:
        account, token = accounts.verify_code(email, code, _visitor(request))
    except AuthError as e:
        raise _auth_http(e)
    return _signed_in(request, account, token)


def _signed_in(request: Request, account: dict, token: str) -> JSONResponse:
    response = JSONResponse({"email": account["email"], **limits.status(account["id"])})
    response.set_cookie(accounts.SESSION_COOKIE, token, max_age=accounts.SESSION_TTL_SECONDS, httponly=True,
                        samesite="lax", secure=request.url.scheme == "https", path="/")
    return response


@app.get("/auth/me")
def auth_me(request: Request) -> dict:
    account = _account(request)
    if not account:
        return {"signed_in": False}
    return {"signed_in": True, "email": account["email"], **limits.status(account["id"])}


@app.post("/auth/logout")
def auth_logout(request: Request) -> JSONResponse:
    accounts.end_session(request.cookies.get(accounts.SESSION_COOKIE))
    response = JSONResponse({"signed_in": False})
    response.delete_cookie(accounts.SESSION_COOKIE, path="/")
    return response


def _auth_http(e: AuthError) -> HTTPException:
    return HTTPException(e.status, str(e), headers={"Retry-After": str(e.retry_after)} if e.retry_after else None)


def _account(request: Request) -> dict | None:
    return accounts.account_for_session(request.cookies.get(accounts.SESSION_COOKIE))


def _require_account(request: Request) -> dict | None:
    """With the paywall on, scans and reports belong to a signed-in account."""
    if not billing.paywall_enabled():
        return None
    account = _account(request)
    if not account:
        raise HTTPException(401, "Please sign in with your email to scan. It's free and takes a minute.")
    return account


@app.post("/scan")
def scan(
    request: Request,
    file: UploadFile = File(..., description="The .apk file to scan"),
    # Booleans are taken as text and parsed by _flag(): FastAPI turns a *missing* bool form field into
    # False regardless of its declared default, which would silently switch off use_ai/include_text.
    i_am_authorized: str | None = Form(
        None, description="Must be true: you confirm you own this app or have permission to test it"),
    use_ai: str | None = Form(None, description="Only when PAYWALL=off: true (default) or false to skip the AI "
                                                "explanations. With the paywall on, the paid report always has them"),
    include_text: str | None = Form(None, description="true (default) or false: also return the report as readable text"),
    engine: str | None = Form(None, description="jadx (about 1 minute), rea (slower, method-by-method evidence) "
                                                "or auto; default is the server's APK_ENGINE"),
) -> dict:
    # A plain `def` endpoint runs in FastAPI's threadpool, so a ~1 minute scan doesn't block other requests.
    authorized = _flag(i_am_authorized, "i_am_authorized", default=False)
    use_ai_flag = _flag(use_ai, "use_ai", default=True)
    include_text_flag = _flag(include_text, "include_text", default=True)
    if not authorized:  # missing or false
        raise HTTPException(403, "Scan refused: you must confirm you own this app or have permission to "
                                 "test it (i_am_authorized=true).")

    if engine and engine.strip().lower() not in ENGINES:
        raise HTTPException(400, "engine must be jadx, rea or auto.")
    if engine and engine.strip().lower() == "rea" and not rea_available():
        raise HTTPException(400, "The deep engine is not installed on this server; choose Fast · jadx.")

    account = _require_account(request)
    name = _safe_name(file.filename)
    if not name.lower().endswith(".apk"):
        raise HTTPException(415, "Please upload an Android app file ending in .apk.")

    chosen = selected_engine(engine)
    running = _running_scan(account["id"] if account else None)
    if running:
        raise _still_running_error(running)
    if chosen == "rea" and not _rea_slots.acquire(blocking=False):
        raise HTTPException(429, "A deep scan is already running and it needs most of the server's memory. "
                                 "Try again later, or choose Fast · jadx (same issues, about 1 minute).",
                            headers={"Retry-After": "600"})
    if not _scan_slots.acquire(blocking=False):
        if chosen == "rea":
            _rea_slots.release()
        raise HTTPException(429, "The scanner is busy with other apps right now. Try again in a minute.",
                            headers={"Retry-After": "60"})
    owner = account["id"] if account else None
    ip_key = _visitor(request)
    reserved = False
    finished_ok = False
    _scan_started(owner, "apk", name, chosen)
    upload_dir = Path(tempfile.mkdtemp(prefix="apk-upload-"))
    try:
        apk_path = upload_dir / name
        _save_upload(file, apk_path)
        # Same visitor, same file, same engine and rules: the findings would be identical, so reuse them.
        cache_key = f"apk:{_sha256(apk_path)}:{chosen}:{ENGINE_VERSION}:{POLICY_VERSION}"
        if owner:
            earlier = billing.find_recent_scan(owner, cache_key)
            if earlier:
                log.info("reusing stored scan for %s", name)
                finished_ok = True
                _scan_finished(owner, report_id=earlier)
                return _stored(earlier, owner, reused=True)
            limits.reserve(owner, ip_key)
            reserved = True
        log.info("scanning %s (%d bytes, ai=%s, engine=%s)", name, apk_path.stat().st_size, use_ai_flag, chosen)
        state = jobs.run(_job_key(owner), scan_apk, apk_path, apk_name=name, engine=engine)
        reserved = False  # the scan worked, so it counts
        finished_ok = True
    except LimitError as e:
        raise HTTPException(429, str(e), headers={"Retry-After": str(e.retry_after)})
    except jobs.ScanCancelled:
        raise _cancelled_http(owner)
    except IngestError as e:
        log.warning("could not decompile %s: %s", name, e)
        raise HTTPException(422, "This file couldn't be opened as an Android app. Make sure it's a "
                                 "complete, unencrypted .apk file.")
    except HTTPException:
        raise
    except Exception:
        log.exception("scan of %s failed", name)
        raise HTTPException(500, "Something went wrong while scanning this app. Please try again.")
    finally:
        if reserved:
            limits.refund(owner, ip_key)
        if not finished_ok:
            _scan_finished(owner, error="The scan stopped before it finished. Please try again.")
        _scan_slots.release()
        if chosen == "rea":
            _rea_slots.release()
        shutil.rmtree(upload_dir, ignore_errors=True)
        file.file.close()

    response = _respond(state, use_ai_flag, include_text_flag, owner, cache_key)
    _scan_finished(owner, report_id=response.get("report_id"))
    return response


@app.post("/scans/cancel")
def cancel_scan(request: Request) -> dict:
    """Stop the signed-in account's running scan and every program it started. The free scan is given back."""
    account = _account(request)
    if not account:
        raise HTTPException(401, "Please sign in.")
    stopped = jobs.cancel(_job_key(account["id"]))
    return {"cancelled": stopped}


def _job_key(owner: str | None) -> str:
    # One scan per account at a time; without the paywall there are no accounts, so each scan gets its own key.
    return owner or f"anon-{os.urandom(6).hex()}"


def _cancelled_http(owner: str | None) -> HTTPException:
    _scan_finished(owner, error="You cancelled this scan.")
    return HTTPException(409, {"message": "Scan cancelled. No free scan was used.", "cancelled": True})


@app.get("/scans/active")
def active_scan(request: Request) -> dict:
    """The signed-in account's running scan, or the report of the one that just finished."""
    account = _account(request)
    if not account:
        return {"active": None}
    with _active_lock:
        info = _active.get(account["id"])
        if info and not info["running"] and time.time() - info.get("finished", 0) > ACTIVE_KEEP_SECONDS:
            _active.pop(account["id"], None)
            info = None
        info = dict(info) if info else None
    if info:
        info["elapsed_seconds"] = round(time.time() - info["started"])
    return {"active": info}


@app.get("/web/verify")
def web_verify(url: str) -> dict:
    """The token the site owner puts at /.well-known/vibeguard-verify.txt before a website scan."""
    try:
        return verification_instructions(url)
    except WebScanError as e:
        raise HTTPException(400, str(e))


@app.post("/scan-web")
def scan_web(
    request: Request,
    url: str = Form(..., description="The website address, e.g. https://myapp.com"),
    i_am_authorized: str | None = Form(
        None, description="Must be true: you confirm you own this website or have permission to test it"),
    use_ai: str | None = Form(None, description="Only when PAYWALL=off: true (default) or false to skip the AI explanations"),
    include_text: str | None = Form(None, description="true (default) or false: also return readable text"),
) -> dict:
    authorized = _flag(i_am_authorized, "i_am_authorized", default=False)
    use_ai_flag = _flag(use_ai, "use_ai", default=True)
    include_text_flag = _flag(include_text, "include_text", default=True)
    if not authorized:
        raise HTTPException(403, "Scan refused: you must confirm you own this website or have permission to "
                                 "test it (i_am_authorized=true).")
    account = _require_account(request)
    owner = account["id"] if account else None
    running = _running_scan(owner)
    if running:
        raise _still_running_error(running)
    ip_key = _visitor(request)
    if owner:
        try:
            limits.reserve(owner, ip_key)  # websites change, so every website scan is a new scan
        except LimitError as e:
            raise HTTPException(429, str(e), headers={"Retry-After": str(e.retry_after)})
    if not _scan_slots.acquire(blocking=False):
        if owner:
            limits.refund(owner, ip_key)
        raise HTTPException(429, "The scanner is busy right now. Try again in a minute.", headers={"Retry-After": "60"})
    reserved = bool(owner)
    _scan_started(owner, "web", url[:200])
    try:
        log.info("scanning website %s (ai=%s)", url[:200], use_ai_flag)
        state = jobs.run(_job_key(owner), scan_website, url)
        reserved = False
    except jobs.ScanCancelled:
        raise _cancelled_http(owner)
    except NotVerifiedError as e:
        # The page turns this into the "prove you own this site" panel.
        raise HTTPException(403, {"message": str(e), "verify": verification_instructions(url)})
    except WebScanError as e:
        raise HTTPException(400, str(e))
    except Exception:
        log.exception("scan of %s failed", url[:200])
        raise HTTPException(500, "Something went wrong while scanning this website. Please try again.")
    finally:
        if reserved:
            limits.refund(owner, ip_key)
            _scan_finished(owner, error="The website scan stopped before it finished.")
        _scan_slots.release()
    response = _respond(state, use_ai_flag, include_text_flag, owner)
    _scan_finished(owner, report_id=response.get("report_id"))
    return response


def _respond(state: dict, use_ai: bool, include_text: bool, owner: str | None = None,
             cache_key: str | None = None) -> dict:
    if not billing.paywall_enabled():
        report = finish_report(state, use_ai)
        return {"report": report, **({"report_text": render_text(report)} if include_text else {})}
    # Free result: the full scan, shown as counts and titles. The AI runs only for a paid report.
    locked = billing.lock_report(finish_report(state, use_ai=False))
    return _stored(billing.save_scan(state, locked, owner, cache_key), owner)


def _stored(report_id: str, owner: str | None, reused: bool = False) -> dict:
    """A stored scan as the scan endpoints return it (free result, or the full report if already paid)."""
    record = billing.load_scan(report_id)
    response = {"report": record["free_report"], "report_id": report_id, "plans": billing.public_plans(),
                "payments_mode": billing.payments_mode(), "reused": reused}
    if record["paid"] and record["full_report"]:
        response.update(report=record["full_report"], paid=True)
        if record.get("kind") != "source":  # a paid source project holds a fixing result, not a scan report
            response["report_text"] = render_text(record["full_report"])
    elif record["paid"]:
        response["paid_pending"] = True  # the page opens /reports/{id}, which writes the paid report
    if owner:
        response["limits"] = limits.status(owner)
    return response


def _language(request: Request) -> str | None:
    """The page's language choice (the vg_lang cookie set by static/i18n.js); None means English."""
    lang = (request.cookies.get("vg_lang") or "").lower()
    return lang if lang in ("de",) else None


def _visitor(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    if TRUST_PROXY_HEADERS and request.headers.get("x-forwarded-for"):
        ip = request.headers["x-forwarded-for"].split(",")[0].strip()
    return limits.visitor_key(ip)


# ---------------------------------------------------------------- reports and (demo) payments

@app.get("/reports/{report_id}")
def get_report(request: Request, report_id: str, include_text: bool = True) -> dict:
    """The full report once paid (built with AI on first request, ~40 s), otherwise the free version."""
    try:
        _check_owner(request, billing.report_owner(report_id))
        record = billing.load_scan(report_id)
        if record.get("kind") == "source" and record["paid"]:
            return _fix_status(report_id, record)
        if not record["paid"]:
            return {"report": record["free_report"], "report_id": report_id, "plans": billing.public_plans(),
                    "payments_mode": billing.payments_mode()}
        language = record.get("language") or _language(request)
        report = billing.full_report(report_id, lambda state: finish_report(state, use_ai=True, language=language))
    except BillingError as e:
        raise HTTPException(404, str(e))
    return {"report": report, "report_id": report_id, "paid": True,
            **({"report_text": render_text(report)} if include_text else {})}


@app.post("/scan-source")
def scan_source_zip(
    request: Request,
    file: UploadFile = File(..., description="The Android project as a .zip (leave out build folders)"),
    i_am_authorized: str | None = Form(None, description="Must be true: you own this code or may change it"),
) -> dict:
    """Free preview for the Bug fixing tier: scan the source and show what would be fixed."""
    if not _flag(i_am_authorized, "i_am_authorized", default=False):
        raise HTTPException(403, "Scan refused: you must confirm you own this code or have permission to change it.")
    account = _require_account(request)
    running = _running_scan(account["id"] if account else None)
    if running:
        raise _still_running_error(running)
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(415, "Please upload your project as a .zip file.")
    if not _scan_slots.acquire(blocking=False):
        raise HTTPException(429, "The scanner is busy right now. Try again in a minute.", headers={"Retry-After": "60"})
    owner = account["id"] if account else None
    ip_key = _visitor(request)
    reserved = False
    report_id = billing.new_id()
    job = billing.job_dir(report_id)
    try:
        job.mkdir(parents=True, mode=0o700)
        upload = job / "upload.zip"
        _save_upload(file, upload, max_bytes=fixer_max_zip())
        cache_key = f"src:{_sha256(upload)}:{POLICY_VERSION}"
        if owner:
            earlier = billing.find_recent_scan(owner, cache_key)
            if earlier:
                shutil.rmtree(job, ignore_errors=True)
                return _stored(earlier, owner, reused=True)
            limits.reserve(owner, ip_key)
            reserved = True
        root, left_out = unpack_source_zip(upload, job / "source")
        upload.unlink()
        _scan_started(owner, "source", file.filename or "project.zip")
        preview = jobs.run(_job_key(owner), fixer.preview, root)
        _scan_finished(owner, report_id=report_id)
        preview["coverage"]["sensitive_files_left_out"] = left_out
        reserved = False
    except LimitError as e:
        shutil.rmtree(job, ignore_errors=True)
        raise HTTPException(429, str(e), headers={"Retry-After": str(e.retry_after)})
    except jobs.ScanCancelled:
        shutil.rmtree(job, ignore_errors=True)
        raise _cancelled_http(owner)
    except SourceError as e:
        shutil.rmtree(job, ignore_errors=True)
        raise HTTPException(422, str(e))
    except HTTPException:
        shutil.rmtree(job, ignore_errors=True)
        raise
    except Exception:
        shutil.rmtree(job, ignore_errors=True)
        log.exception("source scan failed")
        raise HTTPException(500, "Something went wrong while scanning this project. Please try again.")
    finally:
        if reserved:
            limits.refund(owner, ip_key)
        _scan_finished(owner, error="The source scan stopped before it finished.")  # no-op if it already finished
        _scan_slots.release()
        file.file.close()
    state = {"source_root": str(root), "job_dir": str(job)}
    billing.save_scan(state, preview, owner, cache_key, kind="source", report_id=report_id)
    return _stored(report_id, owner)


def fixer_max_zip() -> int:
    from scanner.source import MAX_ZIP_BYTES
    return MAX_ZIP_BYTES


def _fix_status(report_id: str, record: dict) -> dict:
    """A paid source job: the result if done, otherwise start it (once) and report progress."""
    base = {"report_id": report_id, "paid": True, "plans": billing.public_plans(), "payments_mode": billing.payments_mode()}
    if record["full_report"]:
        return {**base, "report": record["full_report"], "status": "done"}
    with _fix_jobs_lock:
        job = _fix_jobs.get(report_id)
        # Start when nothing is running for this report: first request, after a server restart, or to
        # retry a run that failed.
        if job is None or (job["done_flag"] and job["error"]):
            job = {"message": "Starting", "done": 0, "total": 1, "error": None, "done_flag": False}
            job["thread"] = threading.Thread(target=_run_fix_job, args=(report_id, job), daemon=True)
            _fix_jobs[report_id] = job
            job["thread"].start()
    if job["done_flag"] and not job["error"]:
        return {**base, "report": billing.load_scan(report_id)["full_report"], "status": "done"}
    return {**base, "report": record["free_report"], "status": "failed" if job["error"] else "running",
            "progress": {"message": job["message"], "done": job["done"], "total": job["total"], "error": job["error"]}}


def _run_fix_job(report_id: str, job: dict) -> None:
    def progress(message: str, done: int, total: int) -> None:
        job.update(message=message, done=done, total=total)

    try:
        billing.full_report(report_id, lambda state: fixer.fix_project(
            Path(state["source_root"]), Path(state["job_dir"]), progress=progress, tier=state.get("tier", "fix"),
            language=state.get("language")))
    except Exception as e:  # noqa: BLE001 - shown to the customer; the next request retries
        log.exception("fix job %s failed", report_id)
        job["error"] = "The fixing run stopped unexpectedly. Reload the page to try again." if not str(e) else \
            f"The fixing run stopped: {str(e)[:200]}. Reload the page to try again."
    finally:
        job["done_flag"] = True


@app.get("/reports/{report_id}/download/{what}")
def download_fix(request: Request, report_id: str, what: str) -> FileResponse:
    """The Bug fixing deliverables: fixes.patch (git apply) or the fixed project as a zip."""
    files = {"patch": ("fixes.patch", "text/x-diff"), "zip": ("fixed-source.zip", "application/zip"),
             "pr": ("pr-description.md", "text/markdown"), "commit": ("commit-message.txt", "text/plain")}
    if what not in files:
        raise HTTPException(404, "Unknown download.")
    try:
        _check_owner(request, billing.report_owner(report_id))
        record = billing.load_scan(report_id)
    except BillingError as e:
        raise HTTPException(404, str(e))
    if record.get("kind") != "source" or not record["paid"] or not record["full_report"]:
        raise HTTPException(404, "The fixes are not ready yet.")
    name, media = files[what]
    path = Path(record["state"]["job_dir"]) / name
    if not path.is_file():
        raise HTTPException(404, "The fixes are not ready yet.")
    project = re.sub(r"[^A-Za-z0-9._-]+", "_", record["free_report"].get("project") or "project")[:60]
    return FileResponse(path, media_type=media, filename=f"{project}-{name}")


@app.post("/checkout")
def checkout(request: Request, report_id: str = Form(...), plan: str = Form("report")) -> dict:
    try:
        _check_owner(request, billing.report_owner(report_id))
        return billing.create_checkout(report_id, plan)
    except BillingError as e:
        raise HTTPException(400, str(e))


@app.get("/pay/{order_id}")
def checkout_page(order_id: str) -> FileResponse:
    return FileResponse(STATIC_DIR / "pay.html")


@app.get("/orders/{order_id}")
def order_status(request: Request, order_id: str) -> dict:
    try:
        _check_owner(request, billing.order_owner(order_id))
        return billing.get_order(order_id)
    except BillingError as e:
        raise HTTPException(404, str(e))


@app.post("/orders/{order_id}/complete")
def complete_order(request: Request, order_id: str) -> dict:
    """Demo mode only: stands in for the payment provider's 'payment succeeded' webhook."""
    try:
        _check_owner(request, billing.order_owner(order_id))
        return billing.complete_demo_order(order_id, language=_language(request))
    except BillingError as e:
        raise HTTPException(400, str(e))


@app.post("/orders/{order_id}/cancel")
def cancel_order(request: Request, order_id: str) -> dict:
    try:
        _check_owner(request, billing.order_owner(order_id))
        return billing.cancel_order(order_id)
    except BillingError as e:
        raise HTTPException(400, str(e))


def _check_owner(request: Request, owner: str | None) -> None:
    """Reports and orders are visible only to the account that ran the scan. A wrong account gets the
    same answer as a missing report, so ids can't be probed."""
    if owner is None:
        return  # scanned with the paywall off
    account = _account(request)
    if not account:
        raise HTTPException(401, "Please sign in to open this report.")
    if account["id"] != owner:
        raise BillingError("No such report.")


def _flag(value: str | None, field: str, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    v = value.strip().lower()
    if v in ("true", "1", "yes", "on"):
        return True
    if v in ("false", "0", "no", "off"):
        return False
    raise HTTPException(400, f"'{field}' must be true or false.")


def _save_upload(file: UploadFile, dest: Path, max_bytes: int | None = None) -> None:
    """Stream to disk with a size cap, and check it's really a ZIP before spending a minute on it."""
    max_bytes = max_bytes or MAX_UPLOAD_BYTES
    written = 0
    with dest.open("wb") as out:
        first = file.file.read(CHUNK)
        if not first.startswith(ZIP_MAGIC):
            raise HTTPException(415, "This file isn't a valid .apk or .zip (both are ZIP archives).")
        chunk = first
        while chunk:
            written += len(chunk)
            if written > max_bytes:
                raise HTTPException(413, f"The file is too big. The limit is {max_bytes // (1024 * 1024)} MB.")
            out.write(chunk)
            chunk = file.file.read(CHUNK)


def _safe_name(filename: str | None) -> str:
    # Keep only the base name and harmless characters - it's used as a path and shown in the report.
    base = Path(filename or "upload.apk").name
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._") or "upload.apk"
    return cleaned[:100]
