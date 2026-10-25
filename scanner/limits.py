"""Free-tier limits: a daily number of free scans per verified account, plus a higher cap per network.

The account limit is the real one (see scanner/accounts.py). The per-IP cap stops one person from
multiplying their free scans with many email addresses. IP addresses are stored only as a keyed hash.
A scan is reserved before it starts, so parallel requests can't overshoot the limit, and refunded if it
fails. Rescanning an app the visitor already scanned returns the stored result and costs nothing
(see billing.find_recent_scan), since the same file always gives the same findings.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timedelta, timezone

from scanner import billing
from scanner.web import _verify_secret

_lock = threading.Lock()


class LimitError(Exception):
    def __init__(self, message: str, retry_after: int):
        super().__init__(message)
        self.retry_after = retry_after


def free_scans_per_day() -> int:
    return int(os.environ.get("FREE_SCANS_PER_DAY", 5))


def unlimited_emails() -> set[str]:
    """UNLIMITED_ACCOUNTS: comma-separated emails with no free-scan limits (the operator, testers).
    A server setting, so customers cannot add themselves."""
    from scanner.accounts import AuthError, normalize_email

    emails = set()
    for raw in os.environ.get("UNLIMITED_ACCOUNTS", "").split(","):
        if raw.strip():
            try:
                emails.add(normalize_email(raw))
            except AuthError:
                continue
    return emails


def is_unlimited(account_id: str) -> bool:
    from scanner import accounts

    for email in unlimited_emails():
        account = accounts._read("accounts", accounts._key("email", email))
        if account and account.get("id") == account_id:
            return True
    return False


def free_scans_per_ip_per_day() -> int:
    return int(os.environ.get("FREE_SCANS_PER_IP_PER_DAY", 15))


def visitor_key(ip: str) -> str:
    return hmac.new(_verify_secret(), f"visitor:{ip}".encode(), hashlib.sha256).hexdigest()[:24]


def status(account_id: str) -> dict:
    if is_unlimited(account_id):
        return {"free_scans_per_day": None, "used_today": 0, "left_today": None, "unlimited": True,
                "resets_in_seconds": _seconds_to_reset()}
    limit = free_scans_per_day()
    with _lock:
        used = _load(_today()).get(f"acct:{account_id}", 0)
    return {"free_scans_per_day": limit, "used_today": used, "left_today": max(0, limit - used),
            "resets_in_seconds": _seconds_to_reset()}


def reserve(account_id: str, ip_key: str) -> None:
    if is_unlimited(account_id):
        return  # not counted, so refund() has nothing to give back either
    hours = max(1, round(_seconds_to_reset() / 3600))
    resets = f"They reset in about {hours} hour{'s' if hours != 1 else ''}. Results you already scanned stay available."
    with _lock:
        day = _today()
        usage = _load(day)
        acct, ip = f"acct:{account_id}", f"ip:{ip_key}"
        if usage.get(acct, 0) >= free_scans_per_day():
            raise LimitError(f"You have used your {free_scans_per_day()} free scans for today. {resets}", _seconds_to_reset())
        if usage.get(ip, 0) >= free_scans_per_ip_per_day():
            raise LimitError(f"This network has used its {free_scans_per_ip_per_day()} free scans for today. {resets}",
                             _seconds_to_reset())
        usage[acct] = usage.get(acct, 0) + 1
        usage[ip] = usage.get(ip, 0) + 1
        _save(day, usage)


def refund(account_id: str, ip_key: str) -> None:
    """A scan that failed (bad file, unreachable site, server error) does not count."""
    if is_unlimited(account_id):
        return
    with _lock:
        day = _today()
        usage = _load(day)
        for key in (f"acct:{account_id}", f"ip:{ip_key}"):
            if usage.get(key, 0) > 0:
                usage[key] -= 1
        _save(day, usage)


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _seconds_to_reset() -> int:
    now = datetime.now(timezone.utc)
    midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int((midnight - now).total_seconds())


def _path(day: str):
    return billing.DATA_DIR / "usage" / f"{day}.json"


def _load(day: str) -> dict:
    try:
        return json.loads(_path(day).read_text())
    except (FileNotFoundError, ValueError):
        return {}


def _save(day: str, usage: dict) -> None:
    path = _path(day)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(usage))
    tmp.chmod(0o600)
    tmp.replace(path)
    for old in path.parent.glob("*.json"):  # yesterday's counts are no longer needed
        if old.name < f"{(datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%d')}.json":
            old.unlink(missing_ok=True)
