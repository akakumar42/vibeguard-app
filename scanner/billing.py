"""Paywall: the free scan shows counts and issue titles; payment unlocks the full report.

The scan runs once. Its findings are stored, and paying only adds the AI wording and the details,
so the paid report always has the same issues and fingerprint as the free one.

PAYMENTS_MODE=demo (the only mode so far) is a stand-in checkout for demos: no card details are
collected and no money moves. A real provider replaces create_checkout() and marks orders paid from
its webhook (for Stripe: a Checkout Session with metadata.order_id, then checkout.session.completed).
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import threading
import time
from pathlib import Path

DATA_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
# Stored scans include snippets of the customer's code, so they are deleted after this long.
REPORT_TTL_SECONDS = int(os.environ.get("REPORT_TTL_HOURS", 24)) * 3600
CURRENCY = "USD"
PLANS = {
    "report": {"name": "Bug report", "price_cents": 900, "available": True, "needs": "scan",
               "includes": "Where every issue is, plain-English explanations, how to fix each one, AI suggestions"},
    "fix": {"name": "Bug fixing", "price_cents": 5000, "available": True, "needs": "source",
            "includes": "Fixes for every critical issue and warning in your source code, re-scanned to prove they are gone"},
    "improve": {"name": "Code improvement", "price_cents": 15000, "available": True, "needs": "source",
                "includes": "Everything in Bug fixing, plus code smells fixed, a structure review with refactoring plans, "
                            "and a ready-to-open pull request"},
}
_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


class BillingError(Exception):
    """Unknown report/order, or an action that is not allowed in its current state."""


def payments_mode() -> str:
    return os.environ.get("PAYMENTS_MODE", "demo").strip().lower()


def paywall_enabled() -> bool:
    return os.environ.get("PAYWALL", "on").strip().lower() not in ("off", "0", "false", "no")


def public_plans() -> list[dict]:
    return [{"id": key, **plan, "currency": CURRENCY} for key, plan in PLANS.items()]


# ---------------------------------------------------------------- stored scans

def save_scan(state: dict, free_report: dict, owner: str | None = None, cache_key: str | None = None,
              kind: str = "scan", report_id: str | None = None) -> str:
    """owner is the account id; cache_key identifies the input (file hash + engine + versions).
    kind is "scan" (an app or website) or "source" (a source project for the Bug fixing tier)."""
    report_id = report_id or new_id()
    _write("reports", report_id, {"created": time.time(), "paid": False, "state": state, "owner": owner, "kind": kind,
                                  "cache_key": cache_key, "free_report": free_report, "full_report": None})
    return report_id


def new_id() -> str:
    return secrets.token_urlsafe(18)


def job_dir(report_id: str) -> Path:
    """Where a source job keeps the uploaded project and the fixes (deleted with the report)."""
    _path("reports", report_id)  # validates the id
    return DATA_DIR / "jobs" / report_id


def find_recent_scan(owner: str, cache_key: str) -> str | None:
    """The same visitor's stored scan of the same input, if it hasn't expired. Only their own: another
    visitor uploading the same app must not see a report someone else paid for."""
    newest, newest_id = 0.0, None
    for path in (DATA_DIR / "reports").glob("*.json"):
        try:
            record = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if (record.get("owner") == owner and record.get("cache_key") == cache_key
                and time.time() - record["created"] <= REPORT_TTL_SECONDS and record["created"] > newest):
            newest, newest_id = record["created"], path.stem
    return newest_id


def load_scan(report_id: str) -> dict:
    record = _read("reports", report_id)
    if time.time() - record["created"] > REPORT_TTL_SECONDS:
        _delete_scan(report_id)
        raise BillingError("This report has expired. Please scan again.")
    return record


def _delete_scan(report_id: str) -> None:
    _path("reports", report_id).unlink(missing_ok=True)
    shutil.rmtree(DATA_DIR / "jobs" / report_id, ignore_errors=True)  # uploaded source code, fixes


def full_report(report_id: str, build) -> dict:
    """The paid report, built once by build(state) and then served from storage."""
    with _lock_for(report_id):
        record = load_scan(report_id)
        if not record["paid"]:
            raise BillingError("This report has not been paid for.")
        if record["full_report"] is None:
            record["full_report"] = build(record["state"])
            _write("reports", report_id, record)
        return record["full_report"]


def lock_report(report: dict) -> dict:
    """What the free scan shows: how many issues and what they are, but not where or how to fix them."""
    scan = report["scan"]
    return {
        "locked": True,
        "target": report.get("target", "android"),
        "app": {"package_name": report["app"]["package_name"], "one_liner": report["app"]["one_liner"]},
        "counts": report["counts"],
        "result_fingerprint": report["result_fingerprint"],
        "issues": {group: [{k: issue[k] for k in ("id", "rule_id", "title", "severity", "kind", "occurrences", "standard")}
                           for issue in issues] for group, issues in report["issues"].items()},
        "scan": {k: scan[k] for k in ("apk_name", "apk_sha256", "url", "scanned_at", "seconds_total", "engine_version",
                                      "policy_version", "tool_versions") if k in scan}
                | {"reverse_engineering": {k: (scan.get("reverse_engineering") or {}).get(k) for k in ("engine", "coverage")}},
        "warnings": report["warnings"],
        "disclaimer": report["disclaimer"],
    }


# ---------------------------------------------------------------- orders

def create_checkout(report_id: str, plan: str) -> dict:
    if plan not in PLANS:
        raise BillingError(f"Unknown plan {plan!r}.")
    if not PLANS[plan]["available"]:
        raise BillingError(f"{PLANS[plan]['name']} is coming soon.")
    record = load_scan(report_id)
    kind = record.get("kind", "scan")
    if PLANS[plan]["needs"] != kind:
        raise BillingError("Bug fixing works on your source code: upload it on the \"Fix my code\" tab."
                           if plan == "fix" else "This plan is for app and website scans.")
    if record["paid"]:
        return {"already_paid": True, "report_url": f"/app?report={report_id}"}
    if payments_mode() != "demo":
        raise BillingError(f"PAYMENTS_MODE={payments_mode()!r} is not supported yet; use demo.")
    order_id = "ord_" + secrets.token_urlsafe(12)
    report = record["free_report"]
    _write("orders", order_id, {
        "id": order_id, "report_id": report_id, "plan": plan, "plan_name": PLANS[plan]["name"],
        "price_cents": PLANS[plan]["price_cents"], "currency": CURRENCY, "status": "open", "mode": "demo",
        "created": time.time(),
        "scanned": report["scan"].get("apk_name") or report["scan"].get("url"),
        "counts": report["counts"], "result_fingerprint": report["result_fingerprint"],
    })
    return {"order_id": order_id, "checkout_url": f"/pay/{order_id}"}


def report_owner(report_id: str) -> str | None:
    return load_scan(report_id).get("owner")


def order_owner(order_id: str) -> str | None:
    return report_owner(_read("orders", order_id)["report_id"])


def get_order(order_id: str) -> dict:
    order = _read("orders", order_id)
    return {k: v for k, v in order.items() if k != "report_id"} | {"report_url": f"/app?report={order['report_id']}"}


def complete_demo_order(order_id: str, language: str | None = None) -> dict:
    """What a payment provider's webhook does once the money has arrived."""
    if payments_mode() != "demo":
        raise BillingError("Demo payments are switched off on this server.")
    with _lock_for(order_id):
        order = _read("orders", order_id)
        if order["status"] == "cancelled":
            raise BillingError("This order was cancelled. Start a new checkout from the report.")
        if order["status"] != "paid":
            with _lock_for(order["report_id"]):
                record = load_scan(order["report_id"])
                record["paid"] = True
                record["order_id"] = order_id
                record["paid_plan"] = order["plan"]
                record["language"] = language  # the paid report and fixes are written in this language
                if record.get("kind") == "source":
                    record["state"]["tier"] = order["plan"]  # how much the fixing run does
                    record["state"]["language"] = language
                _write("reports", order["report_id"], record)
            order.update(status="paid", paid_at=time.time())
            _write("orders", order_id, order)
    return get_order(order_id)


def cancel_order(order_id: str) -> dict:
    with _lock_for(order_id):
        order = _read("orders", order_id)
        if order["status"] == "open":
            order["status"] = "cancelled"
            _write("orders", order_id, order)
    return get_order(order_id)


# ---------------------------------------------------------------- storage

def _path(kind: str, item_id: str) -> Path:
    if not item_id or len(item_id) > 64 or not set(item_id) <= _ID_CHARS:
        raise BillingError("Unknown id.")
    return DATA_DIR / kind / f"{item_id}.json"


def _read(kind: str, item_id: str) -> dict:
    path = _path(kind, item_id)
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise BillingError(f"No such {kind[:-1]}.") from None


def _write(kind: str, item_id: str, data: dict) -> None:
    path = _path(kind, item_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.chmod(0o600)
    tmp.replace(path)


def _lock_for(key: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def purge_expired() -> int:
    """Delete stored scans (and their uploaded projects) past their lifetime. Orders are kept as the
    payment record. Called by api.py when the app starts and then every hour."""
    removed = 0
    for path in (DATA_DIR / "reports").glob("*.json"):
        try:
            if time.time() - json.loads(path.read_text())["created"] > REPORT_TTL_SECONDS:
                _delete_scan(path.stem)
                removed += 1
        except (OSError, ValueError, KeyError):
            continue
    return removed
