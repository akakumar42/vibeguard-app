"""Cancellable scans: each scan runs in its own child process and process group.

A scan starts several other programs (jadx, REA's Node and Java workers, Semgrep, Gitleaks, a headless
browser). Running the scan in a child process that leads its own process group means cancelling can stop
all of them at once with one signal, and nothing keeps using memory after the user pressed Cancel.
"""

from __future__ import annotations

import multiprocessing
import os
import queue
import signal
import threading
import time
import traceback

_ctx = multiprocessing.get_context("spawn")  # a fresh interpreter: no locks or threads copied from the server
_running: dict[str, dict] = {}  # job key -> {"process", "cancelled"}
_lock = threading.Lock()


class ScanCancelled(Exception):
    """The user cancelled the scan."""


class ScanCrashed(Exception):
    """The scan process ended without a result."""


def run(key: str, fn, *args, **kwargs):
    """Run fn(*args, **kwargs) in a child process and return its result. cancel(key) stops it.
    Exceptions raised in the child are raised here again (with their original type when possible)."""
    results = _ctx.Queue()
    process = _ctx.Process(target=_child, args=(results, fn, args, kwargs), daemon=True)
    with _lock:
        if key in _running:
            raise RuntimeError(f"a job is already running for {key}")
        _running[key] = job = {"process": process, "cancelled": False}
    try:
        process.start()
        while True:
            try:
                kind, payload = results.get(timeout=0.5)
                break
            except queue.Empty:
                if job["cancelled"]:
                    raise ScanCancelled()
                if not process.is_alive():
                    raise ScanCancelled() if job["cancelled"] else ScanCrashed("the scan process stopped unexpectedly")
        process.join(timeout=10)
        if kind == "ok":
            return payload
        exc_type, message, details = payload
        if isinstance(exc_type, type) and issubclass(exc_type, Exception):
            try:
                raise exc_type(message)
            except TypeError:  # exception classes with other constructor arguments
                pass
        raise ScanCrashed(f"{message}\n{details}")
    finally:
        _stop(process)
        with _lock:
            _running.pop(key, None)


def cancel(key: str) -> bool:
    """Stop the job and every program it started. Returns False if nothing was running for key."""
    with _lock:
        job = _running.get(key)
        if not job:
            return False
        job["cancelled"] = True
    _stop(job["process"])
    return True


def is_running(key: str) -> bool:
    with _lock:
        return key in _running


def _stop(process) -> None:
    if process.pid is None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)  # the child leads its own group, so this reaches its subprocesses too
        except (ProcessLookupError, PermissionError):
            return
        deadline = time.monotonic() + 3
        while process.is_alive() and time.monotonic() < deadline:
            time.sleep(0.1)
        if not process.is_alive():
            return


def _child(results, fn, args, kwargs) -> None:
    os.setpgrp()  # lead a new process group: cancel() signals the whole group
    try:
        results.put(("ok", fn(*args, **kwargs)))
    except BaseException as e:  # noqa: BLE001 - every failure must reach the parent
        results.put(("error", (type(e), str(e), traceback.format_exc()[-2000:])))


def sleep_then(seconds: float, start_helper: bool = False) -> str:
    """Test helper: optionally starts a helper program (like jadx would), then sleeps."""
    if start_helper:
        import subprocess
        helper = subprocess.Popen(["sleep", "120"])
        with open(os.environ["JOBS_TEST_PIDFILE"], "w") as f:
            f.write(str(helper.pid))
    time.sleep(float(seconds))  # the API test passes it in place of a URL, as text
    return "finished"
