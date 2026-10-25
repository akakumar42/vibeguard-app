"""Accounts with a verified email.

Two ways in, chosen by AUTH_MODE:
- supabase (default when SUPABASE_URL is set): Google or an emailed link through Supabase Auth. The page
  sends Supabase's access token once to /auth/supabase; we check it with Supabase and start our own session.
- local: passwordless sign-in with a 6-digit code sent by this server.
Either way the account is keyed by the normalized email, so limits, reports and payments don't change.

Free scans are counted per account, so switching networks or using a VPN no longer gives more.
A cap on new accounts per IP address and per-IP scan limits (scanner/limits.py) make throwaway
addresses expensive too.

EMAIL_MODE=demo (default when SMTP_HOST is not set) sends nothing: the code is returned to the page and
shown in a clearly labelled demo inbox. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD and EMAIL_FROM
to email real codes.

Stored: accounts by a hash of the email, codes and session tokens only as keyed hashes, so a copy of
data/ cannot be used to sign in.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import threading
import time
import urllib.error
import urllib.request
from email.message import EmailMessage

from scanner import billing, tls
from scanner.web import _verify_secret

CODE_TTL_SECONDS = 10 * 60
CODE_MAX_ATTEMPTS = 5
RESEND_AFTER_SECONDS = 60
CODES_PER_EMAIL_PER_HOUR = 5
SESSION_TTL_SECONDS = 30 * 24 * 3600
SESSION_COOKIE = "vibeguard_session"
# Well-known throwaway inbox services; a real deployment would use a maintained list.
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
    "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "dispostable.com", "maildrop.cc",
    "throwawaymail.com", "fakeinbox.com", "mintemail.com", "emailondeck.com", "mohmal.com",
}
_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
_lock = threading.Lock()


class AuthError(Exception):
    def __init__(self, message: str, status: int = 400, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def auth_mode() -> str:
    default = "supabase" if os.environ.get("SUPABASE_URL") else "local"
    mode = os.environ.get("AUTH_MODE", default).strip().lower()
    if mode == "supabase" and not (os.environ.get("SUPABASE_URL") and os.environ.get("SUPABASE_ANON_KEY")):
        raise AuthError("AUTH_MODE=supabase needs SUPABASE_URL and SUPABASE_ANON_KEY in .env", 500)
    return mode


def public_config() -> dict:
    """What the page needs to show the right sign-in. The anon key is public by design."""
    mode = auth_mode()
    config = {"mode": mode}
    if mode == "supabase":
        wanted = [p.strip() for p in os.environ.get("SUPABASE_PROVIDERS", "google,email").split(",") if p.strip()]
        enabled = _enabled_providers()
        config |= {"supabase_url": os.environ["SUPABASE_URL"].rstrip("/"), "supabase_anon_key": os.environ["SUPABASE_ANON_KEY"],
                   # Only offer what the Supabase project has switched on, so no button leads to an error.
                   "providers": [p for p in wanted if enabled is None or enabled.get(p)]}
    else:
        config["email_mode"] = email_mode()
    return config


_providers_cache: tuple[float, dict | None] = (0.0, None)


def _enabled_providers() -> dict | None:
    """Supabase's own list of enabled sign-in methods, cached for a minute (None if unreachable)."""
    global _providers_cache
    if time.time() - _providers_cache[0] < 60:
        return _providers_cache[1]
    request = urllib.request.Request(os.environ["SUPABASE_URL"].rstrip("/") + "/auth/v1/settings",
                                     headers={"apikey": os.environ["SUPABASE_ANON_KEY"]})
    try:
        with urllib.request.urlopen(request, timeout=5, context=tls.CONTEXT) as response:
            enabled = json.loads(response.read()).get("external") or None
    except (OSError, ValueError):
        enabled = None
    _providers_cache = (time.time(), enabled)
    return enabled


def email_mode() -> str:
    default = "smtp" if os.environ.get("SMTP_HOST") else "demo"
    return os.environ.get("EMAIL_MODE", default).strip().lower()


def accounts_per_ip_per_day() -> int:
    return int(os.environ.get("ACCOUNTS_PER_IP_PER_DAY", 3))


def normalize_email(raw: str) -> str:
    """One account per real inbox: lower-case, no '+tag', and no dots for Gmail (Gmail ignores them)."""
    email = (raw or "").strip().lower()
    if len(email) > 254 or not _EMAIL.match(email):
        raise AuthError("Please enter a valid email address.")
    local, domain = email.rsplit("@", 1)
    if domain in DISPOSABLE_DOMAINS:
        raise AuthError("Please use your own email address, not a temporary inbox.")
    local = local.split("+", 1)[0]
    if domain in ("gmail.com", "googlemail.com"):
        local, domain = local.replace(".", ""), "gmail.com"
    if not local:
        raise AuthError("Please enter a valid email address.")
    return f"{local}@{domain}"


# ---------------------------------------------------------------- sign-in codes

def start_sign_in(raw_email: str) -> dict:
    """Create a code for this email and send it (or, in demo mode, return it)."""
    _require_mode("local")
    email = normalize_email(raw_email)
    key = _key("email", email)
    now = time.time()
    with _lock:
        record = _read("codes", key) or {"sent": []}
        recent = [t for t in record["sent"] if now - t < 3600]
        if recent and now - recent[-1] < RESEND_AFTER_SECONDS:
            wait = int(RESEND_AFTER_SECONDS - (now - recent[-1])) + 1
            raise AuthError(f"A code was just sent. You can ask for a new one in {wait} seconds.", 429, wait)
        if len(recent) >= CODES_PER_EMAIL_PER_HOUR:
            raise AuthError("Too many codes were requested for this email. Try again in an hour.", 429, 3600)
        code = f"{secrets.randbelow(1_000_000):06d}"
        _write("codes", key, {"code": _key("code", f"{email}:{code}"), "expires": now + CODE_TTL_SECONDS,
                              "attempts": 0, "sent": recent + [now]})
    if email_mode() == "demo":
        return {"email": email, "mode": "demo", "demo_code": code, "expires_in": CODE_TTL_SECONDS}
    _send_code(raw_email.strip(), code)
    return {"email": email, "mode": "email", "expires_in": CODE_TTL_SECONDS}


def verify_code(raw_email: str, code: str, ip_key: str) -> tuple[dict, str]:
    """Check the code; returns (account, session token). Creates the account on first sign-in."""
    _require_mode("local")
    email = normalize_email(raw_email)
    key = _key("email", email)
    code = re.sub(r"\D", "", code or "")
    with _lock:
        record = _read("codes", key)
        if not record or not record.get("code") or time.time() > record["expires"]:
            raise AuthError("This code has expired. Ask for a new one.")
        if record["attempts"] >= CODE_MAX_ATTEMPTS:
            raise AuthError("Too many wrong codes. Ask for a new one.", 429)
        if not hmac.compare_digest(record["code"], _key("code", f"{email}:{code}")):
            record["attempts"] += 1
            _write("codes", key, record)
            left = CODE_MAX_ATTEMPTS - record["attempts"]
            raise AuthError(f"That code is not right. {left} tr{'ies' if left != 1 else 'y'} left." if left
                            else "Too many wrong codes. Ask for a new one.")
        account = _get_or_create_account(key, email, ip_key, "email-code")
        record["code"] = None  # a code works once
        _write("codes", key, record)
    return account, _new_session(key)


def sign_in_with_supabase(access_token: str, ip_key: str) -> tuple[dict, str]:
    """Exchange a Supabase access token for our session. Supabase itself confirms the token (works for
    both its old shared-secret and its newer signing keys, and notices revoked sessions)."""
    _require_mode("supabase")
    user = _supabase_user(access_token)
    if not user.get("email") or not (user.get("email_confirmed_at") or user.get("confirmed_at")):
        raise AuthError("Your email address isn't confirmed yet. Use the link in the email Supabase sent you.", 403)
    email = normalize_email(user["email"])
    key = _key("email", email)
    provider = (user.get("app_metadata") or {}).get("provider", "supabase")
    with _lock:
        account = _get_or_create_account(key, email, ip_key, provider)
        account["supabase_id"] = user.get("id")
        _write("accounts", key, account)
    return account, _new_session(key)


def _supabase_user(access_token: str) -> dict:
    if not access_token or len(access_token) > 4096:
        raise AuthError("Sign-in failed. Please try again.", 401)
    request = urllib.request.Request(
        os.environ["SUPABASE_URL"].rstrip("/") + "/auth/v1/user",
        headers={"Authorization": f"Bearer {access_token}", "apikey": os.environ["SUPABASE_ANON_KEY"]})
    try:
        with urllib.request.urlopen(request, timeout=10, context=tls.CONTEXT) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise AuthError("Your sign-in has expired. Please sign in again.", 401) from e
        raise AuthError("Supabase sign-in is not reachable right now. Please try again.", 503) from e
    except (OSError, ValueError) as e:
        raise AuthError("Supabase sign-in is not reachable right now. Please try again.", 503) from e


def _get_or_create_account(key: str, email: str, ip_key: str, method: str) -> dict:
    """Caller holds _lock."""
    account = _read("accounts", key)
    if account is None:
        _count_new_account(ip_key)
        account = {"id": "acct_" + secrets.token_urlsafe(12), "email": email, "created": time.time()}
    account["last_sign_in"] = time.time()
    account["last_method"] = method
    _write("accounts", key, account)
    return account


def _new_session(account_key: str) -> str:
    token = secrets.token_urlsafe(32)
    _write("sessions", _key("session", token), {"account_key": account_key, "expires": time.time() + SESSION_TTL_SECONDS})
    return token


def _require_mode(mode: str) -> None:
    # In supabase mode the local code sign-in is off, so nobody can skip Google by using it.
    if auth_mode() != mode:
        raise AuthError(f"This sign-in method is switched off on this server (AUTH_MODE={auth_mode()}).", 404)


def _count_new_account(ip_key: str) -> None:
    """At most ACCOUNTS_PER_IP_PER_DAY new accounts from one network a day (caller holds _lock)."""
    day = time.strftime("%Y-%m-%d", time.gmtime())
    usage = _read("signups", day) or {}
    if usage.get(ip_key, 0) >= accounts_per_ip_per_day():
        raise AuthError("Too many new accounts were created from this network today. Sign in with an "
                        "existing account, or try again tomorrow.", 429, 3600)
    usage[ip_key] = usage.get(ip_key, 0) + 1
    _write("signups", day, usage)


# ---------------------------------------------------------------- sessions

def account_for_session(token: str | None) -> dict | None:
    if not token or len(token) > 100:
        return None
    session = _read("sessions", _key("session", token))
    if not session or time.time() > session["expires"]:
        return None
    return _read("accounts", session["account_key"])


def purge_expired() -> int:
    """Delete expired sessions, sign-in codes older than a day and new-account counts older than two days."""
    removed, now = 0, time.time()
    for kind, too_old in (("sessions", lambda d: now > d.get("expires", 0)),
                          ("codes", lambda d: now - max(d.get("sent") or [0]) > 86400)):
        for path in (billing.DATA_DIR / kind).glob("*.json"):
            try:
                if too_old(json.loads(path.read_text())):
                    path.unlink()
                    removed += 1
            except (OSError, ValueError):
                continue
    cutoff = time.strftime("%Y-%m-%d", time.gmtime(now - 2 * 86400))
    for path in (billing.DATA_DIR / "signups").glob("*.json"):
        if path.stem < cutoff:
            path.unlink(missing_ok=True)
            removed += 1
    return removed


def end_session(token: str | None) -> None:
    if token and len(token) <= 100:
        (billing.DATA_DIR / "sessions" / f"{_key('session', token)}.json").unlink(missing_ok=True)


# ---------------------------------------------------------------- helpers

def _send_code(to: str, code: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"Your VibeGuard sign-in code: {code}"
    msg["From"] = os.environ.get("EMAIL_FROM", os.environ.get("SMTP_USER", "no-reply@localhost"))
    msg["To"] = to
    msg.set_content(f"Your sign-in code is {code}\n\nIt works once and expires in 10 minutes. "
                    "If you didn't ask for it, you can ignore this email.\n")
    try:
        with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", 587)), timeout=20) as smtp:
            smtp.starttls()
            if os.environ.get("SMTP_USER"):
                smtp.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException, KeyError) as e:
        raise AuthError("We couldn't send the email right now. Please try again in a minute.", 503) from e


def _key(kind: str, value: str) -> str:
    return hmac.new(_verify_secret(), f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:40]


def _read(kind: str, item_id: str) -> dict | None:
    try:
        return json.loads((billing.DATA_DIR / kind / f"{item_id}.json").read_text())
    except (FileNotFoundError, ValueError):
        return None


def _write(kind: str, item_id: str, data: dict) -> None:
    path = billing.DATA_DIR / kind / f"{item_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.chmod(0o600)
    tmp.replace(path)
