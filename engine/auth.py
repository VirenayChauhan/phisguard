"""Secure local account authentication for PhishGuard.

Passwords are never stored directly. The database keeps a Werkzeug password
hash, a normalized Indian mobile number, an optional Gmail address, and the
account's username. Login
sessions are random bearer tokens whose hashes are stored server-side.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from engine import store

SESSION_TTL_SECONDS = int(os.environ.get("AUTH_SESSION_TTL_SECONDS", "28800"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("AUTH_LOGIN_WINDOW_SECONDS", "900"))
LOGIN_MAX_FAILURES = int(os.environ.get("AUTH_LOGIN_MAX_FAILURES", "10"))
RECOVERY_MAX_FAILURES = int(os.environ.get("AUTH_RECOVERY_MAX_FAILURES", "5"))
USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,31}$")
INDIAN_MOBILE_RE = re.compile(r"^[6-9]\d{9}$")
GMAIL_RE = re.compile(r"^[a-z0-9][a-z0-9.!#$%&'*+/=?^_`{|}~-]{0,63}@(?:gmail\.com|googlemail\.com)$")
RECOVERY_QUESTIONS = (
    "What is your favorite game?",
    "What is your favorite flower?",
    "What is your favorite hobby?",
    "What city were you born in?",
    "What was your first pet's name?",
)


class AuthError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def normalize_username(username: str) -> str:
    if not isinstance(username, str):
        raise AuthError("Enter a valid username.", 400)
    value = (username or "").strip().lower()
    if not USERNAME_RE.fullmatch(value):
        raise AuthError(
            "Username must start with a letter and contain 3–32 letters, numbers, or underscores.",
            400,
        )
    return value


def normalize_mobile(mobile: str) -> str:
    if not isinstance(mobile, str):
        raise AuthError("Enter a valid 10-digit Indian mobile number.", 400)
    value = re.sub(r"[\s()-]", "", (mobile or "").strip())
    if value.startswith("+91"):
        value = value[3:]
    elif value.startswith("91") and len(value) == 12:
        value = value[2:]
    if not INDIAN_MOBILE_RE.fullmatch(value):
        raise AuthError("Enter a valid 10-digit Indian mobile number.", 400)
    return "+91" + value


def normalize_gmail(email: str, required: bool = True) -> str:
    if not isinstance(email, str):
        email = ""
    value = email.strip().lower()
    if not value and not required:
        return ""
    if not GMAIL_RE.fullmatch(value):
        raise AuthError("Enter a valid Gmail address, for example name@gmail.com.", 400)
    return value


def validate_password(password: str) -> str:
    if not isinstance(password, str):
        raise AuthError("Enter a valid password.", 400)
    if len(password or "") < 8:
        raise AuthError("Password must be at least 8 characters.", 400)
    if len(password) > 128:
        raise AuthError("Password must be 128 characters or fewer.", 400)
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise AuthError("Password must contain at least one letter and one number.", 400)
    return password


def normalize_recovery_question(question: str) -> str:
    if not isinstance(question, str) or question not in RECOVERY_QUESTIONS:
        raise AuthError("Choose a valid password recovery question.", 400)
    return question


def normalize_recovery_answer(answer: str) -> str:
    if not isinstance(answer, str):
        raise AuthError("Enter an answer for your password recovery question.", 400)
    value = " ".join(answer.strip().lower().split())
    if len(value) < 2:
        raise AuthError("Recovery answer must be at least 2 characters.", 400)
    if len(value) > 128:
        raise AuthError("Recovery answer must be 128 characters or fewer.", 400)
    return value


def normalize_display_name(display_name: str) -> str:
    if not isinstance(display_name, str):
        display_name = ""
    value = " ".join(display_name.strip().split())
    if len(value) > 60:
        raise AuthError("Display name must be 60 characters or fewer.", 400)
    return value


def normalize_avatar_initials(initials: str) -> str:
    if not isinstance(initials, str):
        initials = ""
    value = initials.strip().upper()
    if value and not re.fullmatch(r"[A-Z0-9]{1,2}", value):
        raise AuthError("Avatar initials must be 1–2 letters or numbers.", 400)
    return value


def _value(account, name: str, default=None):
    if isinstance(account, dict):
        return account.get(name, default)
    try:
        return account[name]
    except (IndexError, KeyError):
        return default


def _default_initials(display_name: str, username: str) -> str:
    words = (display_name or username or "?").split()
    if len(words) > 1:
        return (words[0][0] + words[1][0]).upper()
    return (words[0][:2] or "?").upper()


def _device_label(user_agent: str) -> str:
    ua = (user_agent or "")[:500]
    if "Edg/" in ua:
        browser = "Microsoft Edge"
    elif "Chrome/" in ua:
        browser = "Google Chrome"
    elif "Firefox/" in ua:
        browser = "Firefox"
    elif "Safari/" in ua and "Chrome/" not in ua:
        browser = "Safari"
    else:
        browser = "Browser"
    if "Windows" in ua:
        system = "Windows"
    elif "Android" in ua:
        system = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        system = "iOS"
    elif "Mac OS X" in ua:
        system = "macOS"
    elif "Linux" in ua:
        system = "Linux"
    else:
        system = "Unknown device"
    return f"{browser} on {system}"


def _public_user(account) -> dict:
    username = _value(account, "username", "")
    display_name = _value(account, "display_name") or username
    return {
        "username": username,
        "display_name": display_name,
        "avatar_initials": _value(account, "avatar_initials") or _default_initials(display_name, username),
        "mobile": _value(account, "mobile", ""),
        "email": _value(account, "email") or "",
        "email_verified": bool(_value(account, "email_verified_at")),
        "created_at": _value(account, "created_at", ""),
        "last_login_at": _value(account, "last_login_at", ""),
        "password_changed_at": _value(account, "password_changed_at") or _value(account, "created_at", ""),
        "has_recovery_question": bool(_value(account, "recovery_answer_hash")),
        "notifications": {
            "security": bool(_value(account, "notify_security", 1)),
            "email": bool(_value(account, "notify_monthly_summary", 0)),
            "push_scan": bool(_value(account, "notify_push_scan", 1)),
            "tips": bool(_value(account, "notify_tips", 1)),
        },
    }


def _create_session(account, request_ip: str = "", user_agent: str = "") -> tuple[dict, str]:
    now = _now()
    store.mark_auth_account_login(account["user_id"], _iso(now))
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    store.create_login_session(
        token_hash, account["user_id"], account["username"],
        _iso(now), _iso(now + timedelta(seconds=SESSION_TTL_SECONDS)),
        request_ip, (user_agent or "")[:500], _device_label(user_agent),
    )
    return _public_user(account), raw_token


def register_account(username: str, password: str, mobile: str,
                     email: str = "", recovery_question: str = "",
                     recovery_answer: str = "", request_ip: str = "",
                     user_agent: str = "", monthly_summary: bool = False) -> tuple[dict, str]:
    username = normalize_username(username)
    password = validate_password(password)
    mobile = normalize_mobile(mobile)
    email = normalize_gmail(email, required=False)
    monthly_summary = monthly_summary is True
    if monthly_summary and not email:
        raise AuthError("Add a Gmail address to receive monthly flagged-site summaries.", 400)
    recovery_question = normalize_recovery_question(recovery_question)
    recovery_answer = normalize_recovery_answer(recovery_answer)
    if store.get_auth_account(username):
        raise AuthError("That username is already registered. Please log in.", 409)
    if email and store.get_auth_account_by_email(email):
        raise AuthError("That Gmail address is already linked to another account.", 409)

    created_at = _iso(_now())
    account = {
        "user_id": secrets.token_urlsafe(18),
        "username": username,
        "password_hash": generate_password_hash(password),
        "mobile": mobile,
        "email": email,
        "display_name": "",
        "avatar_initials": "",
        "password_changed_at": created_at,
        "recovery_question": recovery_question,
        "recovery_answer_hash": generate_password_hash(recovery_answer),
        "notify_security": 1,
        "notify_email": 1,
        "notify_monthly_summary": int(monthly_summary),
        "notify_tips": 1,
        "created_at": created_at,
    }
    try:
        store.create_auth_account(
            account["user_id"], account["username"], account["password_hash"],
            account["mobile"], created_at, account["email"],
            account["display_name"], account["avatar_initials"], created_at,
            account["recovery_question"], account["recovery_answer_hash"],
            bool(account["notify_monthly_summary"]),
        )
    except sqlite3.IntegrityError as exc:
        raise AuthError("That username is already registered. Please log in.", 409) from exc
    return _create_session(account, request_ip, user_agent)


def login_account(username: str, password: str, request_ip: str,
                  user_agent: str = "") -> tuple[dict, str]:
    username = normalize_username(username)
    if not isinstance(password, str):
        password = ""
    request_ip = request_ip or "unknown"
    since = _iso(_now() - timedelta(seconds=LOGIN_WINDOW_SECONDS))
    if store.count_recent_failed_logins(username, request_ip, since) >= LOGIN_MAX_FAILURES:
        raise AuthError("Too many failed login attempts. Please try again later.", 429)

    account = store.get_auth_account(username)
    if not account or not check_password_hash(account["password_hash"], password or ""):
        store.record_login_attempt(
            secrets.token_urlsafe(12), username, request_ip, _iso(_now()), False
        )
        raise AuthError("Invalid username or password.", 401)

    store.record_login_attempt(
        secrets.token_urlsafe(12), username, request_ip, _iso(_now()), True
    )
    return _create_session(account, request_ip, user_agent)


OTP_TTL_SECONDS = 600
OTP_MAX_REQUESTS = 3
OTP_GLOBAL_MAX_PER_DAY = 100
OTP_MAX_ATTEMPTS = 5


def issue_email_otp(email: str, purpose: str, request_ip: str = "") -> tuple[str, str]:
    """Create a short-lived, one-use email code with bounded online guessing."""
    email = normalize_gmail(email)
    if purpose not in {"verify_email", "password_reset"}:
        raise AuthError("Invalid email-code purpose.", 400)
    now = _now()
    since = _iso(now - timedelta(minutes=15))
    request_ip = request_ip or "unknown"
    if store.count_recent_otp_requests(email, request_ip, since) >= OTP_MAX_REQUESTS:
        raise AuthError("Too many email codes requested. Please try again later.", 429)
    if store.count_otp_requests_since(_iso(now - timedelta(days=1))) >= OTP_GLOBAL_MAX_PER_DAY:
        raise AuthError("Email code delivery has reached its daily safety limit.", 429)
    code = f"{secrets.randbelow(1_000_000):06d}"
    challenge_id = secrets.token_urlsafe(24)
    store.invalidate_otp_challenges(email, purpose, _iso(now))
    store.create_otp_challenge(
        challenge_id, email, generate_password_hash(code, method="scrypt"),
        now.isoformat(timespec="microseconds"),
        (now + timedelta(seconds=OTP_TTL_SECONDS)).isoformat(timespec="microseconds"),
        request_ip, purpose,
    )
    return challenge_id, code


def verify_email_otp(email: str, purpose: str, code: str) -> str:
    email = normalize_gmail(email)
    if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code):
        raise AuthError("The email code is invalid or expired.", 400)
    challenge = store.latest_otp_challenge(email, purpose)
    now = _now()
    if (not challenge or challenge["used_at"]
            or challenge["expires_at"] <= now.isoformat(timespec="microseconds")
            or int(challenge["attempts"] or 0) >= OTP_MAX_ATTEMPTS):
        raise AuthError("The email code is invalid or expired.", 400)
    attempts = store.increment_otp_attempts(challenge["challenge_id"], OTP_MAX_ATTEMPTS)
    if attempts > OTP_MAX_ATTEMPTS or not check_password_hash(challenge["code_hash"], code):
        raise AuthError("The email code is invalid or expired.", 400)
    if not store.mark_otp_used(challenge["challenge_id"], _iso(now)):
        raise AuthError("The email code is invalid or expired.", 400)
    return email


def verify_account_email(username: str, code: str) -> dict:
    username = normalize_username(username)
    account = store.get_auth_account(username)
    if not account or not account["email"]:
        raise AuthError("Add a Gmail address before verifying it.", 400)
    email = verify_email_otp(account["email"], "verify_email", code)
    store.mark_auth_email_verified(account["user_id"], _iso(_now()))
    return _public_user(store.get_auth_account(username))


def reset_password_with_email_otp(username: str, code: str, new_password: str,
                                  request_ip: str = "", user_agent: str = "") -> tuple[dict, str]:
    username = normalize_username(username)
    new_password = validate_password(new_password)
    account = store.get_auth_account(username)
    if not account or not account["email"] or not _value(account, "email_verified_at"):
        raise AuthError("The email code is invalid or expired.", 400)
    if check_password_hash(account["password_hash"], new_password):
        raise AuthError("New password must be different from the current password.", 400)
    verify_email_otp(account["email"], "password_reset", code)
    changed_at = _iso(_now())
    store.update_auth_password(account["user_id"], generate_password_hash(new_password), changed_at)
    store.revoke_user_login_sessions(account["user_id"], changed_at)
    updated = store.get_auth_account(username)
    return _create_session(updated, request_ip, user_agent)


def get_recovery_question(username: str) -> str:
    """Return the non-secret recovery question for the password reset screen."""
    username = normalize_username(username)
    account = store.get_auth_account(username)
    if not account or not _value(account, "recovery_answer_hash"):
        raise AuthError("No recovery question is set for this account.", 404)
    return _value(account, "recovery_question", "")


def reset_password(username: str, recovery_answer: str, new_password: str,
                   request_ip: str = "", user_agent: str = "") -> tuple[dict, str]:
    """Reset a password after a rate-limited recovery-answer check."""
    username = normalize_username(username)
    request_ip = request_ip or "unknown"
    since = _iso(_now() - timedelta(seconds=LOGIN_WINDOW_SECONDS))
    if store.count_recent_recovery_attempts(username, request_ip, since) >= RECOVERY_MAX_FAILURES:
        raise AuthError("Too many recovery attempts. Please try again later.", 429)

    account = store.get_auth_account(username)
    answer = normalize_recovery_answer(recovery_answer)
    valid = bool(
        account and _value(account, "recovery_answer_hash") and
        check_password_hash(account["recovery_answer_hash"], answer)
    )
    store.record_recovery_attempt(
        secrets.token_urlsafe(12), username, request_ip, _iso(_now()), valid
    )
    if not valid:
        raise AuthError("The recovery answer is incorrect.", 401)

    new_password = validate_password(new_password)
    if check_password_hash(account["password_hash"], new_password):
        raise AuthError("New password must be different from the current password.", 400)
    changed_at = _iso(_now())
    store.update_auth_password(account["user_id"], generate_password_hash(new_password), changed_at)
    store.revoke_user_login_sessions(account["user_id"], changed_at)
    updated = store.get_auth_account(username)
    return _create_session(updated, request_ip, user_agent)


def update_recovery_question(username: str, current_password: str,
                             recovery_question: str, recovery_answer: str) -> dict:
    """Set or replace the recovery question from an authenticated session."""
    username = normalize_username(username)
    account = store.get_auth_account(username)
    if not account or not isinstance(current_password, str) or not check_password_hash(
        account["password_hash"], current_password
    ):
        raise AuthError("Current password is incorrect.", 401)
    question = normalize_recovery_question(recovery_question)
    answer = normalize_recovery_answer(recovery_answer)
    store.update_auth_recovery(account["user_id"], question, generate_password_hash(answer))
    return _public_user(store.get_auth_account(username))


def change_password(username: str, current_password: str,
                    new_password: str, request_ip: str = "",
                    user_agent: str = "") -> tuple[dict, str]:
    username = normalize_username(username)
    account = store.get_auth_account(username)
    if not account or not isinstance(current_password, str) or not check_password_hash(
        account["password_hash"], current_password
    ):
        raise AuthError("Current password is incorrect.", 401)
    new_password = validate_password(new_password)
    if check_password_hash(account["password_hash"], new_password):
        raise AuthError("New password must be different from the current password.", 400)

    changed_at = _iso(_now())
    store.update_auth_password(account["user_id"], generate_password_hash(new_password), changed_at)
    store.revoke_user_login_sessions(account["user_id"], _iso(_now()))
    updated = store.get_auth_account(username)
    return _create_session(updated, request_ip, user_agent)


def change_mobile(username: str, current_password: str, mobile: str) -> dict:
    username = normalize_username(username)
    account = store.get_auth_account(username)
    if not account or not isinstance(current_password, str) or not check_password_hash(
        account["password_hash"], current_password
    ):
        raise AuthError("Current password is incorrect.", 401)
    mobile = normalize_mobile(mobile)
    if mobile == account["mobile"]:
        raise AuthError("Enter a different mobile number.", 400)
    store.update_auth_mobile(account["user_id"], mobile)
    return _public_user(store.get_auth_account(username))


def change_gmail(username: str, current_password: str, email: str) -> dict:
    username = normalize_username(username)
    account = store.get_auth_account(username)
    if not account or not isinstance(current_password, str) or not check_password_hash(
        account["password_hash"], current_password
    ):
        raise AuthError("Current password is incorrect.", 401)
    email = normalize_gmail(email)
    if email == (account["email"] or ""):
        raise AuthError("Enter a different Gmail address.", 400)
    existing = store.get_auth_account_by_email(email)
    if existing and existing["user_id"] != account["user_id"]:
        raise AuthError("That Gmail address is already linked to another account.", 409)
    try:
        store.update_auth_email(account["user_id"], email)
    except sqlite3.IntegrityError as exc:
        raise AuthError("That Gmail address is already linked to another account.", 409) from exc
    return _public_user(store.get_auth_account(username))


def update_profile(username: str, current_password: str,
                   display_name: str, avatar_initials: str) -> dict:
    username = normalize_username(username)
    account = store.get_auth_account(username)
    if not account or not isinstance(current_password, str) or not check_password_hash(
        account["password_hash"], current_password
    ):
        raise AuthError("Current password is incorrect.", 401)
    display_name = normalize_display_name(display_name)
    avatar_initials = normalize_avatar_initials(avatar_initials)
    store.update_auth_profile(account["user_id"], display_name, avatar_initials)
    return _public_user(store.get_auth_account(username))


def update_preferences(username: str, preferences: dict) -> dict:
    username = normalize_username(username)
    account = store.get_auth_account(username)
    if not account:
        raise AuthError("Account not found.", 404)
    requested_email = preferences.get("email", bool(_value(account, "notify_monthly_summary", 0)))
    if requested_email is True and not _value(account, "email"):
        raise AuthError("Add a Gmail address before enabling monthly summaries.", 400)
    values = {
        "security": bool(preferences.get("security", _value(account, "notify_security", 1))),
        "email": requested_email is True,
        "tips": bool(preferences.get("tips", _value(account, "notify_tips", 1))),
        "push_scan": bool(preferences.get("push_scan", _value(account, "notify_push_scan", 1))),
    }
    store.update_auth_preferences(
        account["user_id"], values["security"], values["email"], values["tips"],
        values["push_scan"],
    )
    return _public_user(store.get_auth_account(username))


def login_history(username: str) -> list[dict]:
    account = store.get_auth_account(normalize_username(username))
    if not account:
        raise AuthError("Account not found.", 404)
    current_time = _iso(_now())
    return [
        {
            "login_at": row["created_at"],
            "device": row["device_label"] or _device_label(row["user_agent"]),
            "ip_address": row["ip_address"] or "Unknown IP",
            "active": not row["revoked_at"] and row["expires_at"] > current_time,
            "signed_out_at": row["revoked_at"] or "",
        }
        for row in store.list_login_history(account["user_id"])
    ]


def export_data(username: str) -> dict:
    account = store.get_auth_account(normalize_username(username))
    if not account:
        raise AuthError("Account not found.", 404)
    def row_dict(row):
        return {key: row[key] for key in row.keys()}
    return {
        "exported_at": _iso(_now()),
        "profile": _public_user(account),
        "login_history": [row_dict(row) for row in store.list_login_history(account["user_id"], 100)],
        "help_questions": [row_dict(row) for row in store.list_user_assistant_requests(account["username"])],
        "reported_items": [row_dict(row) for row in store.list_user_reports(account["username"])],
    }


def delete_account(username: str, current_password: str) -> None:
    username = normalize_username(username)
    account = store.get_auth_account(username)
    if not account or not isinstance(current_password, str) or not check_password_hash(
        account["password_hash"], current_password
    ):
        raise AuthError("Current password is incorrect.", 401)
    store.delete_auth_account(account["user_id"], username)


def clear_data(username: str, current_password: str) -> None:
    username = normalize_username(username)
    account = store.get_auth_account(username)
    if not account or not isinstance(current_password, str) or not check_password_hash(
        account["password_hash"], current_password
    ):
        raise AuthError("Current password is incorrect.", 401)
    store.clear_user_activity(username)


def current_user(raw_token: str | None) -> dict | None:
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    row = store.get_login_session(token_hash, _iso(_now()))
    if not row:
        return None
    account = store.get_auth_account(row["username"])
    return _public_user(account) if account else None


def revoke(raw_token: str | None) -> None:
    if raw_token:
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        store.revoke_login_session(token_hash, _iso(_now()))
